/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package etcd3

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"k8s.io/klog/v2"
)

const (
	compactRevKey = "compact_rev_key"
)

var (
	endpointsMapMu sync.Mutex
	endpointsMap   map[string]*compactor
)

func init() {
	endpointsMap = make(map[string]*compactor)
}

// StartCompactor starts a compactor in the background to compact old version of keys that's not needed.
// By default, we save the most recent 5 minutes data and compact versions > 5minutes ago.
// It should be enough for slow watchers and to tolerate burst.
// TODO: We might keep a longer history (12h) in the future once storage API can take advantage of past version of keys.
func StartCompactor(client *clientv3.Client, compactInterval time.Duration) Compactor {
	endpointsMapMu.Lock()
	defer endpointsMapMu.Unlock()

	// In one process, we can have only one compactor for one cluster.
	// Currently we rely on endpoints to differentiate clusters.
	for _, ep := range client.Endpoints() {
		if c, ok := endpointsMap[ep]; ok {
			klog.V(4).Infof("compactor already exists for endpoints %v", client.Endpoints())
			return c
		}
	}
	c := newCompactor(client, compactInterval)
	for _, ep := range client.Endpoints() {
		endpointsMap[ep] = c
	}
	return c
}

func newCompactor(client *clientv3.Client, compactInterval time.Duration) *compactor {
	ctx, cancel := context.WithCancel(context.Background())
	c := &compactor{
		client:   client,
		interval: compactInterval,
		cancel:   cancel,
	}
	c.cond = sync.NewCond(&c.mux)
	for _, ep := range client.Endpoints() {
		endpointsMap[ep] = c
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.runCompactLoop(ctx)
	}()
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.runWatchLoop(ctx)
	}()
	return c
}

type Compactor interface {
	Stop()
	Interval() time.Duration
	UpdateMinInterval(interval time.Duration)
	WaitCompaction(context.Context, uint64) (uint64, error)
}

type compactor struct {
	client *clientv3.Client
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mux             sync.Mutex
	cond            *sync.Cond
	compactRevision uint64
	interval        time.Duration
	stopped         bool
}

func (c *compactor) Stop() {
	c.cancel()
	c.client.Close()
	c.wg.Wait()
	func() {
		c.mux.Lock()
		defer c.mux.Unlock()
		c.stopped = true
		c.cond.Signal()
	}()
	func() {
		endpointsMapMu.Lock()
		defer endpointsMapMu.Unlock()
		for _, ep := range c.client.Endpoints() {
			delete(endpointsMap, ep)
		}
	}()
}

func (c *compactor) Interval() time.Duration {
	c.mux.Lock()
	defer c.mux.Unlock()
	return c.interval
}

func (c *compactor) UpdateMinInterval(interval time.Duration) {
	if interval <= 0 {
		return
	}
	c.mux.Lock()
	defer c.mux.Unlock()
	c.interval = min(c.interval, interval)
}

func (c *compactor) WaitCompaction(ctx context.Context, rev uint64) (uint64, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		// TODO: Not wake up everyone
		c.cond.Signal()
	}()
	c.mux.Lock()
	defer c.mux.Unlock()
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		if c.compactRevision >= rev || c.stopped {
			break
		}
		c.cond.Wait()
	}
	return c.compactRevision, nil
}

func (c *compactor) updateCompactRevision(rev uint64) {
	c.mux.Lock()
	defer c.mux.Unlock()
	if rev > c.compactRevision {
		c.compactRevision = rev
		c.cond.Broadcast()
	}
}

// compactor periodically compacts historical versions of keys in etcd.
// It will compact keys with versions older than given interval.
// In other words, after compaction, it will only contain keys set during last interval.
// Any API call for the older versions of keys will return error.
// Interval is the time interval between each compaction. The first compaction happens after "interval".
func (c *compactor) runCompactLoop(ctx context.Context) {
	// Technical definitions:
	// We have a special key in etcd defined as *compactRevKey*.
	// compactRevKey's value will be set to the string of last compacted revision.
	// compactRevKey's version will be used as logical time for comparison. THe version is referred as compact time.
	// Initially, because the key doesn't exist, the compact time (version) is 0.
	//
	// Algorithm:
	// - Compare to see if (local compact_time) = (remote compact_time).
	// - If yes, increment both local and remote compact_time, and do a compaction.
	// - If not, set local to remote compact_time.
	//
	// Technical details/insights:
	//
	// The protocol here is lease based. If one compactor CAS successfully, the others would know it when they fail in
	// CAS later and would try again in 5 minutes. If an APIServer crashed, another one would "take over" the lease.
	//
	// For example, in the following diagram, we have a compactor C1 doing compaction in t1, t2. Another compactor C2
	// at t1' (t1 < t1' < t2) would CAS fail, set its known oldRev to rev at t1', and try again in t2' (t2' > t2).
	// If C1 crashed and wouldn't compact at t2, C2 would CAS successfully at t2'.
	//
	//                 oldRev(t2)     curRev(t2)
	//                                  +
	//   oldRev        curRev           |
	//     +             +              |
	//     |             |              |
	//     |             |    t1'       |     t2'
	// +---v-------------v----^---------v------^---->
	//     t0           t1             t2
	//
	// We have the guarantees:
	// - in normal cases, the interval is 5 minutes.
	// - in failover, the interval is >5m and <10m
	//
	// FAQ:
	// - What if time is not accurate? We don't care as long as someone did the compaction. Atomicity is ensured using
	//   etcd API.
	// - What happened under heavy load scenarios? Initially, each apiserver will do only one compaction
	//   every 5 minutes. This is very unlikely affecting or affected w.r.t. server load.

	var previousVersion int64
	var previousRev int64
	var compactRev uint64
	var err error
	for {
		select {
		case <-time.After(c.Interval()):
		case <-ctx.Done():
			return
		}

		previousVersion, previousRev, compactRev, err = compact(ctx, c.client, previousVersion, previousRev)
		if err != nil {
			klog.Errorf("etcd: endpoint (%v) compact failed: %v", c.client.Endpoints(), err)
			continue
		}
		c.updateCompactRevision(compactRev)
	}
}

// compact compacts etcd store and returns current rev.
// It will return the current compact time and global revision if no error occurred.
// Note that CAS fail will not incur any error.
func compact(ctx context.Context, client *clientv3.Client, expectVersion, rev int64) (currentVersion, currentRev int64, compactRev uint64, err error) {
	resp, err := client.KV.Txn(ctx).If(
		clientv3.Compare(clientv3.Version(compactRevKey), "=", expectVersion),
	).Then(
		clientv3.OpPut(compactRevKey, strconv.FormatInt(rev, 10)), // Expect side effect: increment Version
	).Else(
		clientv3.OpGet(compactRevKey),
	).Commit()
	if err != nil {
		return expectVersion, rev, 0, err
	}

	currentRev = resp.Header.Revision

	if !resp.Succeeded {
		currentVersion = resp.Responses[0].GetResponseRange().Kvs[0].Version
		compactRev, err = strconv.ParseUint(string(resp.Responses[0].GetResponseRange().Kvs[0].Value), 10, 64)
		if err != nil {
			return currentVersion, currentRev, 0, nil
		}
		return currentVersion, currentRev, compactRev, nil
	}
	currentVersion = expectVersion + 1

	if rev == 0 {
		// We don't compact on bootstrap.
		return currentVersion, currentRev, 0, nil
	}
	if _, err = client.Compact(ctx, rev); err != nil {
		return currentVersion, currentRev, 0, err
	}
	klog.V(4).Infof("etcd: compacted rev (%d), endpoints (%v)", rev, client.Endpoints())
	return currentVersion, currentRev, uint64(rev), nil
}

func (c *compactor) runWatchLoop(ctx context.Context) {
	for {
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return
		}
		compactRev, currentRev, err := c.getCompactRev(ctx)
		if err != nil {
			klog.Errorf("etcd: endpoint (%v): %v", c.client.Endpoints(), err)
			continue
		}
		if compactRev != 0 {
			c.updateCompactRevision(compactRev)
		}
		watch := c.client.Watch(ctx, compactRevKey, clientv3.WithRev(currentRev))
		for resp := range watch {
			compactRev, err := c.fromWatchResponse(resp)
			if err != nil {
				klog.Errorf("etcd: endpoint (%v): %v", c.client.Endpoints(), err)
				continue
			}
			if compactRev != 0 {
				c.updateCompactRevision(compactRev)
			}
		}
	}
}

func (c *compactor) getCompactRev(ctx context.Context) (compactRev uint64, currentRev int64, err error) {
	resp, err := c.client.Get(ctx, compactRevKey)
	if err != nil {
		return compactRev, currentRev, fmt.Errorf("get %q failed: %v", compactRevKey, err)
	}
	if len(resp.Kvs) != 0 {
		compactRev, err = strconv.ParseUint(string(resp.Kvs[0].Value), 10, 64)
		if err != nil {
			return compactRev, currentRev, fmt.Errorf("failed to parse compact revision: %v", err)
		}
	}
	if resp.Header == nil {
		return compactRev, currentRev, fmt.Errorf("empty response header")
	}
	currentRev = resp.Header.Revision
	return compactRev, currentRev, nil
}

func (c *compactor) fromWatchResponse(resp clientv3.WatchResponse) (compactRev uint64, err error) {
	if resp.Err() != nil {
		return compactRev, resp.Err()
	}
	if len(resp.Events) == 0 {
		return compactRev, nil
	}
	lastEvent := resp.Events[len(resp.Events)-1]
	compactRev, err = strconv.ParseUint(string(lastEvent.Kv.Value), 10, 64)
	if err != nil {
		return compactRev, fmt.Errorf("failed to parse compact revision: %v", err)
	}
	return compactRev, nil
}

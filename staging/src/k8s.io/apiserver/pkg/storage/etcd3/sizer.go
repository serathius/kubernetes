/*
Copyright 2025 The Kubernetes Authors.

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
	"sync"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

const sizerRefreshInterval = time.Minute

type getKeysFunc func(context.Context) ([]*mvccpb.KeyValue, error)

func newSizeCache(getKeys getKeysFunc) *sizeCache {
	sizer := &sizeCache{
		getKeys: getKeys,
		stop:    make(chan struct{}),
		perKey:  make(map[string]sizeRevision),
	}
	sizer.wg.Add(1)
	go func() {
		defer sizer.wg.Done()
		sizer.run()
	}()
	return sizer
}

// sizeCache efficiently estimates the average object size based on the last observed state of individual keys.
// By plugging sizeCache into GetList and Watch functions, a fairly accurate estimate of object sizes can be maintained
// without additional requests to the underlying storage.
// To handle potential out-of-order or incomplete data, it uses a per-key revision to identify the newer state.
// This approach may lead to key leakage if delete events are not observed, thus we run a background goroutine to periodically cleanup keys if needed.
type sizeCache struct {
	getKeys getKeysFunc
	stop    chan struct{}
	wg      sync.WaitGroup

	lock           sync.Mutex
	perKey         map[string]sizeRevision
	lastKeyCleanup time.Time
}

type sizeRevision struct {
	sizeBytes int64
	revision  int64
}

// AverageObjectSize returns the average size of objects observed by cache.
// To prevent leakage and staleness, the caller should provide the current list of keys.
// To avoid allocating dedicated slice, kvs argument should be set to results of Range request with clientv3.WithKeysOnly().
func (ss *sizeCache) AverageObjectSize(kvs []*mvccpb.KeyValue) int64 {
	ss.lock.Lock()
	defer ss.lock.Unlock()

	totalSize := ss.sizeKeysAndCleanOthers(kvs)

	if len(ss.perKey) == 0 {
		return 0
	}
	return totalSize / int64(len(ss.perKey))
}

func (ss *sizeCache) Close() {
	close(ss.stop)
	ss.wg.Wait()
}

func (ss *sizeCache) run() {
	err := wait.PollUntilContextCancel(wait.ContextForChannel(ss.stop), sizerRefreshInterval, false, func(ctx context.Context) (done bool, err error) {
		ss.cleanKeysIfNeeded(ctx)
		return false, nil
	})
	if err != nil {
		klog.InfoS("Sizer exiting")
	}
}

func (ss *sizeCache) cleanKeysIfNeeded(ctx context.Context) {
	ss.lock.Lock()
	defer ss.lock.Unlock()
	if time.Since(ss.lastKeyCleanup) < sizerRefreshInterval {
		return
	}
	keys, err := ss.getKeys(ctx)
	if err != nil {
		klog.InfoS("Error getting keys", "err", err)
	}
	ss.sizeKeysAndCleanOthers(keys)
}

func (ss *sizeCache) sizeKeysAndCleanOthers(keysOnly []*mvccpb.KeyValue) (totalSize int64) {
	newKeys := make(map[string]sizeRevision, len(keysOnly))
	for _, kvs := range keysOnly {
		key := string(kvs.Key)
		keySizeRevision, ok := ss.perKey[key]
		if !ok {
			continue
		}
		newKeys[key] = keySizeRevision
		totalSize += keySizeRevision.sizeBytes
	}
	ss.perKey = newKeys
	ss.lastKeyCleanup = time.Now()
	return totalSize
}

func (ss *sizeCache) AddOrUpdate(key string, revision, size int64) {
	ss.lock.Lock()
	defer ss.lock.Unlock()

	keySizeRevision := ss.perKey[key]
	if keySizeRevision.revision >= revision {
		return
	}

	ss.perKey[key] = sizeRevision{
		sizeBytes: size,
		revision:  revision,
	}
}

func (ss *sizeCache) Delete(key string, revision int64) {
	ss.lock.Lock()
	defer ss.lock.Unlock()

	keySizeRevision := ss.perKey[key]
	if keySizeRevision.revision >= revision {
		return
	}

	delete(ss.perKey, key)
}

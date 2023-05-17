/*
Copyright 2022 The Kubernetes Authors.

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

package etcd

import (
	"context"
	"fmt"

	clientv3 "go.etcd.io/etcd/client/v3"

	"k8s.io/apiserver/pkg/storage"
)

const (
	compactRevKey = "compact_rev_key"
)

type Client struct {
	etcdClient *clientv3.Client
}

func NewClient(c *clientv3.Client) storage.MvccKVClient {
	return Client{c}
}

func (c Client) Get(ctx context.Context, key string) (kv *storage.KV, headerRev int64, err error) {
	resp, err := c.etcdClient.KV.Get(ctx, key)
	// always return headerRV
	headerRev = resp.Header.Revision
	// only return value when we have a KV returned
	if len(resp.Kvs) != 0 {
		kv = &storage.KV{
			Key:   resp.Kvs[0].Key,
			Value: resp.Kvs[0].Value,
			RV:    resp.Kvs[0].ModRevision,
		}
		return
	}
	// else return zero values and the error if it exists
	return
}

func (c Client) List(ctx context.Context, key string, opts []clientv3.OpOption) (kvs []*storage.KV, hasMore bool, count int64, headerRev int64, err error) {
	resp, err := c.etcdClient.KV.Get(ctx, key, opts...)
	if err != nil {
		return
	}
	kvs = make([]*storage.KV, len(resp.Kvs))
	hasMore = resp.More
	count = resp.Count
	for i, kv := range resp.Kvs {
		kvs[i] = &storage.KV{
			Key:   kv.Key,
			Value: kv.Value,
			RV:    kv.ModRevision,
		}
	}
	headerRev = resp.Header.Revision
	return
}

func (c Client) Count(ctx context.Context, key string) (count int64, err error) {
	resp, err := c.etcdClient.KV.Get(ctx, key, clientv3.WithRange(clientv3.GetPrefixRangeEnd(key)), clientv3.WithCountOnly())
	if err != nil {
		return
	}
	count = resp.Count
	return
}

func (c Client) OptimisticCreate(ctx context.Context, key string, data []byte, ttl int64) (headerRev int64, err error) {
	opts, err := c.ttlOpts(ctx, ttl)
	if err != nil {
		return
	}
	resp, err := c.etcdClient.KV.Txn(ctx).If(
		notFound(key),
	).Then(
		clientv3.OpPut(key, string(data), opts...),
	).Commit()
	if err != nil {
		return
	}
	headerRev = resp.Header.Revision
	if !resp.Succeeded {
		err = storage.NewKeyExistsError(key, 0)
	}
	return
}

func (c Client) OptimisticUpdate(ctx context.Context, key string, newData []byte, ttl int64, expectedRV int64) (kv *storage.KV, succeeded bool, txnRV int64, err error) {
	opts, err := c.ttlOpts(ctx, ttl)
	if err != nil {
		return
	}
	txnResp, err := c.etcdClient.KV.Txn(ctx).If(
		clientv3.Compare(clientv3.ModRevision(key), "=", expectedRV),
	).Then(
		clientv3.OpPut(key, string(newData), opts...),
	).Else(
		clientv3.OpGet(key),
	).Commit()
	succeeded = txnResp.Succeeded
	if !txnResp.Succeeded {
		getResp := (*clientv3.GetResponse)(txnResp.Responses[0].GetResponseRange())
		if len(getResp.Kvs) > 0 {
			kv = &storage.KV{
				Key:   getResp.Kvs[0].Key,
				Value: getResp.Kvs[0].Value,
				RV:    getResp.Kvs[0].ModRevision,
			}
		}
	} else {
		txnRV = txnResp.Header.Revision
	}
	return
}

func (c Client) OptimisticDelete(ctx context.Context, key string, expectedRV int64) (bool, *storage.KV, error) {
	resp, err := c.etcdClient.KV.Txn(ctx).If(
		clientv3.Compare(clientv3.ModRevision(key), "=", expectedRV),
	).Then(
		clientv3.OpDelete(key),
	).Else(
		clientv3.OpGet(key),
	).Commit()
	if err != nil {
		return false, nil, err
	}
	succeeded := resp.Succeeded
	if !succeeded {
		getResp := (*clientv3.GetResponse)(resp.Responses[0].GetResponseRange())
		if len(getResp.Kvs) > 0 {
			return succeeded, &storage.KV{
				Key:   getResp.Kvs[0].Key,
				Value: getResp.Kvs[0].Value,
				RV:    getResp.Kvs[0].ModRevision,
			}, nil
		}
	}
	return succeeded, nil, nil
}

func (c Client) Compact(ctx context.Context, rev int64) (headerRev int64, err error) {
	//resp, err := c.etcdClient.KV.Txn(ctx).If(
	//	clientv3.Compare(clientv3.Version(compactRevKey), "=", t),
	//).Then(
	//	clientv3.OpPut(compactRevKey, strconv.FormatInt(rev, 10)), // Expect side effect: increment Version
	//).Else(
	//	clientv3.OpGet(compactRevKey),
	//).Commit()
	//if err != nil {
	//	return t, rev, err
	//}
	//
	//curRev = resp.Header.Revision
	//
	//if !resp.Succeeded {
	//	curTime := resp.Responses[0].GetResponseRange().Kvs[0].Version
	//	return curTime, curRev, nil
	//}
	//curTime = t + 1
	//
	//if rev == 0 {
	//	// We don't compact on bootstrap.
	//	return curTime, curRev, nil
	//}
	//
	resp, err := c.etcdClient.Compact(ctx, rev)
	if err != nil {
		return 0, err
	}
	return resp.Header.Revision, nil
}

func (c Client) GrantLease(ctx context.Context, ttl int64) (leaseID int64, err error) {
	return
}

func (c Client) Watch(ctx context.Context, key string, startRV int64, withPrefix bool, withProgressNotify bool, errCh chan<- error) <-chan *storage.Event {
	opts := []clientv3.OpOption{clientv3.WithRev(startRV + 1), clientv3.WithPrevKV()}
	if withPrefix {
		opts = append(opts, clientv3.WithPrefix())
	}
	if withProgressNotify {
		opts = append(opts, clientv3.WithProgressNotify())
	}
	retCh := make(chan *storage.Event, 1)
	wch := c.etcdClient.Watch(ctx, key, opts...)
	go func(ch clientv3.WatchChan) {
		for wres := range wch {
			if err := wres.Err(); err != nil {
				errCh <- err
				return
			}
			if wres.IsProgressNotify() {
				retCh <- progressNotifyEvent(wres.Header.GetRevision())
				continue
			}
			for _, e := range wres.Events {
				evt, err := parseEvent(e)
				if err != nil {
					errCh <- err
					return
				}
				retCh <- evt
			}
		}

	}(wch)
	return retCh
}

func progressNotifyEvent(rev int64) *storage.Event {
	return &storage.Event{
		RV:               rev,
		IsProgressNotify: true,
	}
}

func parseEvent(e *clientv3.Event) (*storage.Event, error) {
	if !e.IsCreate() && e.PrevKv == nil {
		// If the previous value is nil, error. One example of how this is possible is if the previous value has been compacted already.
		return nil, fmt.Errorf("etcd event received with PrevKv=nil (key=%q, modRevision=%d, type=%s)", string(e.Kv.Key), e.Kv.ModRevision, e.Type.String())

	}
	ret := &storage.Event{
		Key:       string(e.Kv.Key),
		Value:     e.Kv.Value,
		RV:        e.Kv.ModRevision,
		IsDeleted: e.Type == clientv3.EventTypeDelete,
		IsCreated: e.IsCreate(),
	}
	if e.PrevKv != nil {
		ret.PrevValue = e.PrevKv.Value
	}
	return ret, nil
}

// ttlOpts returns client options based on given ttl.
// ttl: if ttl is non-zero, it will attach the key to a lease with ttl of roughly the same length
func (c *Client) ttlOpts(ctx context.Context, ttl int64) ([]clientv3.OpOption, error) {
	if ttl == 0 {
		return nil, nil
	}
	// TODO: Fix
	return []clientv3.OpOption{clientv3.WithLease(0)}, nil
}

func notFound(key string) clientv3.Cmp {
	return clientv3.Compare(clientv3.ModRevision(key), "=", 0)
}

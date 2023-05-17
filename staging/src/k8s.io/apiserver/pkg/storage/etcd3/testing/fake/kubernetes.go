package fake

import (
	"context"
	"sync"

	clientv3 "go.etcd.io/etcd/client/v3"

	"k8s.io/apiserver/pkg/storage"
)

func NewEtcdFake() storage.MvccKVClient {
	return &mvccFake{etcdState: etcdState{
		Revision:  1,
		KeyValues: map[string]ValueRevision{},
		KeyLeases: map[string]int64{},
		Leases:    map[int64]EtcdLease{},
	}}
}

type mvccFake struct {
	mux sync.RWMutex
	etcdState
}

func (f *mvccFake) Get(ctx context.Context, key string) (kv *storage.KV, headerRev int64, err error) {
	f.mux.RLock()
	defer f.mux.RUnlock()
	var resp EtcdResponse
	_, resp = f.etcdState.step(getRequest(key))
	if len(resp.Txn.Results[0].KVs) == 0 {
		return nil, resp.Revision, nil
	}
	kvs := resp.Txn.Results[0].KVs
	return &storage.KV{
		Key:   []byte(kvs[0].Key),
		Value: []byte(kvs[0].Value.Value),
		RV:    kvs[0].ModRevision,
	}, resp.Revision, nil
}

func (f *mvccFake) List(ctx context.Context, key string, opts []clientv3.OpOption) (kvs []*storage.KV, hasMore bool, count int64, headerRev int64, err error) {
	f.mux.RLock()
	defer f.mux.RUnlock()
	var resp EtcdResponse
	// TODO: Transfer opts into arguments
	_, resp = f.etcdState.step(rangeRequest(key, true, 0))
	for _, kv := range resp.Txn.Results[0].KVs {
		kvs = append(kvs, &storage.KV{
			Key:   []byte(kv.Key),
			Value: []byte(kv.Value.Value),
			RV:    kv.ModRevision,
		})
	}
	return kvs, resp.Txn.Results[0].Count > int64(len(resp.Txn.Results[0].KVs)), resp.Txn.Results[0].Count, resp.Revision, nil
}

func (f *mvccFake) Count(ctx context.Context, key string) (count int64, err error) {
	f.mux.RLock()
	defer f.mux.RUnlock()
	var resp EtcdResponse
	_, resp = f.etcdState.step(rangeRequest(key, true, 0))
	return resp.Txn.Results[0].Count, nil
}

func (f *mvccFake) OptimisticCreate(ctx context.Context, key string, data []byte, ttl int64) (headerRev int64, err error) {
	f.mux.Lock()
	defer f.mux.Unlock()
	var resp EtcdResponse
	// TODO: Handle TTL
	request := txnRequest([]EtcdCondition{{Key: key, ExpectedRevision: 0}}, []EtcdOperation{{Type: Put, Key: key, Value: ValueOrHash{Value: string(data)}}}, nil)
	f.etcdState, resp = f.etcdState.step(request)
	if resp.Txn.Failure {
		return resp.Revision, storage.NewKeyExistsError(key, resp.Revision)
	}
	return resp.Revision, nil
}

func (f *mvccFake) OptimisticUpdate(ctx context.Context, key string, newData []byte, ttl int64, expectedRV int64) (kv *storage.KV, succeeded bool, txnRV int64, err error) {
	f.mux.Lock()
	defer f.mux.Unlock()
	var resp EtcdResponse
	// TODO: Handle TTL
	request := txnRequest([]EtcdCondition{{Key: key, ExpectedRevision: expectedRV}}, []EtcdOperation{{Type: Put, Key: key, Value: ValueOrHash{Value: string(newData)}}}, []EtcdOperation{{Type: Range, Key: key}})
	f.etcdState, resp = f.etcdState.step(request)
	succeeded = !resp.Txn.Failure
	if !succeeded && len(resp.Txn.Results[0].KVs) == 1 {
		result := resp.Txn.Results[0].KVs[0]
		kv = &storage.KV{
			Key:   []byte(result.Key),
			Value: []byte(result.Value.Value),
			RV:    result.ModRevision,
		}
	}
	return kv, succeeded, resp.Revision, nil
}

func (f *mvccFake) OptimisticDelete(ctx context.Context, key string, expectedRV int64) (succeeded bool, kv *storage.KV, err error) {
	f.mux.Lock()
	defer f.mux.Unlock()
	var resp EtcdResponse
	request := txnRequest([]EtcdCondition{{Key: key, ExpectedRevision: expectedRV}}, []EtcdOperation{{Type: Delete, Key: key}}, []EtcdOperation{{Type: Range, Key: key}})
	f.etcdState, resp = f.etcdState.step(request)
	succeeded = !resp.Txn.Failure
	if !succeeded && len(resp.Txn.Results[0].KVs) == 1 {
		result := resp.Txn.Results[0].KVs[0]
		kv = &storage.KV{
			Key:   []byte(result.Key),
			Value: []byte(result.Value.Value),
			RV:    result.ModRevision,
		}
	}
	return succeeded, kv, nil
}

func (f *mvccFake) Compact(ctx context.Context, rev int64) (curRev int64, err error) {
	f.mux.RLock()
	defer f.mux.RUnlock()
	return f.Revision, nil
}

func (f *mvccFake) GrantLease(ctx context.Context, ttl int64) (leaseID int64, err error) {
	//TODO implement me
	panic("implement me")
}

func (f *mvccFake) Watch(ctx context.Context, key string, startRV int64, withPrefix bool, withProgressNotify bool, errCh chan<- error) <-chan *storage.Event {
	//TODO implement me
	respCh := make(chan *storage.Event)
	go func() {
		select {
		case <-ctx.Done():
			close(respCh)
		}
	}()
	return respCh
}

var _ storage.MvccKVClient = (*mvccFake)(nil)

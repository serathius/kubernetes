/*
Copyright The Kubernetes Authors.

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

package robustness

import (
	"context"
	"strconv"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

const maxIndexerSnapshots = 64

// StaleRead simulates cache sync lag: every read behaves as if the cache were
// empty and the last-synced RV is "1".
type StaleRead struct{}

func (StaleRead) ApplyCache() bool { return true }

// StaleSnapshot serves informer cache reads from a previously recorded snapshot
// of the same resource's indexer rather than returning an empty cache.
// Revision comparisons occur strictly within this single resource's snapshot
// history; ResourceVersions of different resources are never compared.
type StaleSnapshot struct {
	// StepsBack chooses how many recorded snapshots behind the latest snapshot
	// to serve (default 1 when AtRevision is nil and StepsBack <= 0).
	StepsBack int

	// AtRevision, if non-nil and returning a non-empty revision string for this
	// resource, selects the newest recorded snapshot whose RV <= AtRevision().
	AtRevision func() string

	// PinFirst keeps the snapshot chosen on the first active hit pinned until
	// the rule stops matching, preventing the stale view from drifting forward.
	PinFirst bool

	// SpoofFreshRV, when true, reports the real indexer's current
	// LastStoreSyncResourceVersion while still serving objects from the older
	// snapshot (for testing controller guards independently of KEP-5647).
	SpoofFreshRV bool
}

// ApplyCacheSnapshot implements CacheSnapshotFault.
func (s StaleSnapshot) ApplyCacheSnapshot() *StaleSnapshot {
	cp := s
	return &cp
}

type indexerSnapshot struct {
	rv      string
	indexer cache.Indexer
}

// FaultInjectingIndexer wraps cache.Indexer and intercepts every read path the
// generated listers use, including the namespace index. It also retains a ring
// buffer of deep-copied per-resource snapshots to support StaleSnapshot faults.
type FaultInjectingIndexer struct {
	cache.Indexer
	ctx      context.Context // bounds BlockingFault actions
	registry *FaultRegistry
	name     string // plural resource name, e.g. "pods"

	snapMu    sync.RWMutex
	snapshots []indexerSnapshot
	pinned    *indexerSnapshot
}

// NewFaultInjectingIndexer creates a wrapped cache.Indexer hooked to the registry.
func NewFaultInjectingIndexer(ctx context.Context, realIndexer cache.Indexer, registry *FaultRegistry, name string) cache.Indexer {
	fi := &FaultInjectingIndexer{
		Indexer:  realIndexer,
		ctx:      ctx,
		registry: registry,
		name:     name,
	}
	fi.RecordSnapshot()
	return fi
}

// RecordSnapshot captures a deep-copied snapshot of the underlying indexer at
// its current single-resource revision.
func (i *FaultInjectingIndexer) RecordSnapshot() {
	if i == nil || i.Indexer == nil {
		return
	}
	indexers := i.Indexer.GetIndexers()
	cloneIndexers := make(cache.Indexers, len(indexers))
	for k, fn := range indexers {
		cloneIndexers[k] = fn
	}
	clone := cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, cloneIndexers)
	var maxObjRV uint64
	for _, item := range i.Indexer.List() {
		cp := item
		if ro, ok := item.(runtime.Object); ok {
			cp = ro.DeepCopyObject()
		}
		if acc, err := meta.Accessor(cp); err == nil {
			if rv, err := strconv.ParseUint(acc.GetResourceVersion(), 10, 64); err == nil && rv > maxObjRV {
				maxObjRV = rv
			}
		}
		_ = clone.Add(cp)
	}
	rv := i.Indexer.LastStoreSyncResourceVersion()
	if rv == "" && maxObjRV > 0 {
		rv = strconv.FormatUint(maxObjRV, 10)
	}

	i.snapMu.Lock()
	defer i.snapMu.Unlock()
	if len(i.snapshots) >= maxIndexerSnapshots {
		copy(i.snapshots, i.snapshots[1:])
		i.snapshots = i.snapshots[:maxIndexerSnapshots-1]
	}
	i.snapshots = append(i.snapshots, indexerSnapshot{rv: rv, indexer: clone})
}

// SnapshotCount returns the number of single-resource snapshots currently retained.
func (i *FaultInjectingIndexer) SnapshotCount() int {
	i.snapMu.RLock()
	defer i.snapMu.RUnlock()
	return len(i.snapshots)
}

func (i *FaultInjectingIndexer) Add(obj interface{}) error {
	err := i.Indexer.Add(obj)
	if err == nil {
		i.RecordSnapshot()
	}
	return err
}

func (i *FaultInjectingIndexer) Update(obj interface{}) error {
	err := i.Indexer.Update(obj)
	if err == nil {
		i.RecordSnapshot()
	}
	return err
}

func (i *FaultInjectingIndexer) Delete(obj interface{}) error {
	err := i.Indexer.Delete(obj)
	if err == nil {
		i.RecordSnapshot()
	}
	return err
}

func (i *FaultInjectingIndexer) Replace(list []interface{}, resourceVersion string) error {
	err := i.Indexer.Replace(list, resourceVersion)
	if err == nil {
		i.RecordSnapshot()
	}
	return err
}

func (i *FaultInjectingIndexer) selectSnapshot(req *StaleSnapshot) *indexerSnapshot {
	i.snapMu.Lock()
	defer i.snapMu.Unlock()
	if len(i.snapshots) == 0 {
		return nil
	}
	if req.PinFirst && i.pinned != nil {
		return i.pinned
	}
	var chosen indexerSnapshot
	if req.AtRevision != nil {
		if targetStr := req.AtRevision(); targetStr != "" {
			targetRV, targetErr := strconv.ParseUint(targetStr, 10, 64)
			found := false
			for idx := len(i.snapshots) - 1; idx >= 0; idx-- {
				s := i.snapshots[idx]
				if s.rv == targetStr {
					chosen = s
					found = true
					break
				}
				if targetErr == nil {
					if snapRV, err := strconv.ParseUint(s.rv, 10, 64); err == nil && snapRV <= targetRV {
						chosen = s
						found = true
						break
					}
				}
			}
			if !found {
				chosen = i.snapshots[0]
			}
			if req.PinFirst {
				cp := chosen
				i.pinned = &cp
			}
			return &chosen
		}
	}
	back := req.StepsBack
	if back <= 0 {
		back = 1
	}
	idx := len(i.snapshots) - 1 - back
	if idx < 0 {
		idx = 0
	}
	chosen = i.snapshots[idx]
	if req.PinFirst {
		cp := chosen
		i.pinned = &cp
	}
	return &chosen
}

func (i *FaultInjectingIndexer) resolve(op, key string) (staleEmpty bool, snap *indexerSnapshot, snapReq *StaleSnapshot) {
	staleEmpty, snapReq = i.registry.ResolveCacheSnapshot(i.ctx, CacheFacts{Cache: i.name, Op: op, Key: key})
	if snapReq != nil {
		snap = i.selectSnapshot(snapReq)
	} else {
		i.snapMu.Lock()
		i.pinned = nil
		i.snapMu.Unlock()
	}
	return staleEmpty, snap, snapReq
}

func (i *FaultInjectingIndexer) GetByKey(key string) (interface{}, bool, error) {
	staleEmpty, snap, _ := i.resolve("get", key)
	if staleEmpty {
		return nil, false, nil
	}
	if snap != nil {
		return snap.indexer.GetByKey(key)
	}
	return i.Indexer.GetByKey(key)
}

func (i *FaultInjectingIndexer) Get(obj interface{}) (interface{}, bool, error) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		return nil, false, err
	}
	return i.GetByKey(key)
}

func (i *FaultInjectingIndexer) List() []interface{} {
	staleEmpty, snap, _ := i.resolve("list", "")
	if staleEmpty {
		return nil
	}
	if snap != nil {
		return snap.indexer.List()
	}
	return i.Indexer.List()
}

func (i *FaultInjectingIndexer) ListKeys() []string {
	staleEmpty, snap, _ := i.resolve("list-keys", "")
	if staleEmpty {
		return nil
	}
	if snap != nil {
		return snap.indexer.ListKeys()
	}
	return i.Indexer.ListKeys()
}

// Index backs cache.ListAllByNamespace, i.e. every namespaced lister.
func (i *FaultInjectingIndexer) Index(indexName string, obj interface{}) ([]interface{}, error) {
	staleEmpty, snap, _ := i.resolve("index", indexName)
	if staleEmpty {
		return nil, nil
	}
	if snap != nil {
		return snap.indexer.Index(indexName, obj)
	}
	return i.Indexer.Index(indexName, obj)
}

func (i *FaultInjectingIndexer) IndexKeys(indexName, indexedValue string) ([]string, error) {
	staleEmpty, snap, _ := i.resolve("index-keys", indexName+"/"+indexedValue)
	if staleEmpty {
		return nil, nil
	}
	if snap != nil {
		return snap.indexer.IndexKeys(indexName, indexedValue)
	}
	return i.Indexer.IndexKeys(indexName, indexedValue)
}

func (i *FaultInjectingIndexer) ListIndexFuncValues(indexName string) []string {
	staleEmpty, snap, _ := i.resolve("index-values", indexName)
	if staleEmpty {
		return nil
	}
	if snap != nil {
		return snap.indexer.ListIndexFuncValues(indexName)
	}
	return i.Indexer.ListIndexFuncValues(indexName)
}

func (i *FaultInjectingIndexer) ByIndex(indexName, indexedValue string) ([]interface{}, error) {
	staleEmpty, snap, _ := i.resolve("by-index", indexName+"/"+indexedValue)
	if staleEmpty {
		return nil, nil
	}
	if snap != nil {
		return snap.indexer.ByIndex(indexName, indexedValue)
	}
	return i.Indexer.ByIndex(indexName, indexedValue)
}

func (i *FaultInjectingIndexer) LastStoreSyncResourceVersion() string {
	staleEmpty, snap, snapReq := i.resolve("last-sync-rv", "")
	if staleEmpty {
		return "1"
	}
	if snap != nil {
		if snapReq != nil && snapReq.SpoofFreshRV {
			return i.Indexer.LastStoreSyncResourceVersion()
		}
		if snap.rv != "" {
			return snap.rv
		}
		return "1"
	}
	return i.Indexer.LastStoreSyncResourceVersion()
}

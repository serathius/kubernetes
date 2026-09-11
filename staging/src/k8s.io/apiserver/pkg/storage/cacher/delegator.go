/*
Copyright 2015 The Kubernetes Authors.

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

package cacher

import (
	"context"
	stderrors "errors"
	"sync"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/cacher/consistency"
	"k8s.io/apiserver/pkg/storage/cacher/delegator"
	"k8s.io/apiserver/pkg/storage/cacher/metrics"
	"k8s.io/apiserver/pkg/storage/cacher/store"
	storagemetrics "k8s.io/apiserver/pkg/storage/metrics"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/klog/v2"
)

func NewCacheDelegator(cacher *Cacher, storage storage.Interface) *CacheDelegator {
	d := &CacheDelegator{
		cacher:  cacher,
		storage: storage,
		stopCh:  make(chan struct{}),
	}
	if utilfeature.DefaultFeatureGate.Enabled(features.DetectCacheInconsistency) || consistency.PanicOnCacheInconsistency {
		d.checker = consistency.NewChecker(cacher.resourcePrefix, cacher.groupResource, cacher.newListFunc, cacher, storage)
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.checker.Run(d.stopCh)
		}()
	}
	return d
}

type CacheDelegator struct {
	cacher  *Cacher
	storage storage.Interface
	checker *consistency.Checker

	wg       sync.WaitGroup
	stopOnce sync.Once
	stopCh   chan struct{}
}

var _ storage.Interface = (*CacheDelegator)(nil)

func (c *CacheDelegator) Versioner() storage.Versioner {
	return c.storage.Versioner()
}

func (c *CacheDelegator) Create(ctx context.Context, key string, obj, out runtime.Object, ttl uint64) error {
	return c.storage.Create(ctx, key, obj, out, ttl)
}

func (c *CacheDelegator) GetCurrentResourceVersion(ctx context.Context) (uint64, error) {
	return c.storage.GetCurrentResourceVersion(ctx)
}

func (c *CacheDelegator) EnableResourceSizeEstimation(keys storage.KeysFunc) error {
	return c.storage.EnableResourceSizeEstimation(keys)
}

func (c *CacheDelegator) Delete(ctx context.Context, key string, out runtime.Object, preconditions *storage.Preconditions, validateDeletion storage.ValidateObjectFunc, cachedExistingObject runtime.Object, opts storage.DeleteOptions) error {
	// Ignore the suggestion and try to pass down the current version of the object
	// read from cache.
	if elem, exists, err := c.cacher.watchCache.storage.GetByKey(key); err != nil {
		klog.Errorf("GetByKey returned error: %v", err)
	} else if exists {
		// DeepCopy the object since we modify resource version when serializing the
		// current object.
		currObj := elem.(*store.Element).Object.DeepCopyObject()
		return c.storage.Delete(ctx, key, out, preconditions, validateDeletion, currObj, opts)
	}
	// If we couldn't get the object, fallback to no-suggestion.
	return c.storage.Delete(ctx, key, out, preconditions, validateDeletion, nil, opts)
}

func (c *CacheDelegator) Watch(ctx context.Context, key string, opts storage.ListOptions) (watch.Interface, error) {
	// if the watch-list feature wasn't set and the resourceVersion is unset
	// ensure that the rv from which the watch is being served, is the latest
	// one. "latest" is ensured by serving the watch from
	// the underlying storage.
	//
	// it should never happen due to our validation but let's just be super-safe here
	// and disable sendingInitialEvents when the feature wasn't enabled
	if !utilfeature.DefaultFeatureGate.Enabled(features.WatchList) && opts.SendInitialEvents != nil {
		opts.SendInitialEvents = nil
	}
	return c.cacher.Watch(ctx, key, opts)
}

func (c *CacheDelegator) Get(ctx context.Context, key string, opts storage.GetOptions, objPtr runtime.Object) error {
	if opts.ResourceVersion == "" {
		// If resourceVersion is not specified, serve it from underlying
		// storage (for backward compatibility).
		return c.storage.Get(ctx, key, opts, objPtr)
	}

	if !c.cacher.Ready() {
		// If Cache is not initialized, delegator Get requests to storage
		// as described in https://kep.k8s.io/4568
		return c.storage.Get(ctx, key, opts, objPtr)
	}
	// If resourceVersion is specified, serve it from cache.
	// It's guaranteed that the returned value is at least that
	// fresh as the given resourceVersion.
	if _, err := c.cacher.versioner.ParseResourceVersion(opts.ResourceVersion); err != nil {
		return err
	}
	return c.cacher.Get(ctx, key, opts, objPtr)
}

func (c *CacheDelegator) GetList(ctx context.Context, key string, opts storage.ListOptions, listObj runtime.Object) error {
	_, _, err := storage.ValidateListOptions(c.cacher.resourcePrefix, c.cacher.versioner, opts)
	if err != nil {
		return err
	}
	result, err := delegator.ShouldDelegateList(opts, c.cacher)
	if err != nil {
		return err
	}
	if result.ShouldDelegate {
		return c.storage.GetList(ctx, key, opts, listObj)
	}

	if _, err := c.cacher.versioner.ParseResourceVersion(opts.ResourceVersion); err != nil {
		return err
	}

	if !c.cacher.Ready() && shouldDelegateListOnNotReadyCache(opts) {
		// If Cacher is not initialized, delegator List requests to storage
		// as described in https://kep.k8s.io/4568
		return c.storage.GetList(ctx, key, opts, listObj)
	}
	err = c.cacher.GetList(ctx, key, opts, listObj)
	success := "true"
	fallback := "false"
	if err != nil {
		if errors.IsResourceExpired(err) && utilfeature.DefaultFeatureGate.Enabled(features.ListFromCacheSnapshot) {
			return c.storage.GetList(ctx, key, opts, listObj)
		}
		if result.ConsistentRead {
			// IsTooLargeResourceVersion occurs when the requested RV is higher than cache's current RV
			// and cache hasn't caught up within the timeout period.
			if storage.IsTooLargeResourceVersion(err) {
				if utilfeature.DefaultFeatureGate.Enabled(features.ConsistentListFromCacheSkipTimeoutFallback) {
					fallback = "skipped"
					err = errors.NewTooManyRequests(err.Error(), resourceVersionTooHighRetrySeconds)
				} else {
					fallback = "true"
					err = c.storage.GetList(ctx, key, opts, listObj)
				}
			}
			if err != nil {
				success = "false"
			}
			metrics.ConsistentReadTotal.WithLabelValues(c.cacher.groupResource.Group, c.cacher.groupResource.Resource, success, fallback).Add(1)
		}
		return err
	}
	if result.ConsistentRead {
		metrics.ConsistentReadTotal.WithLabelValues(c.cacher.groupResource.Group, c.cacher.groupResource.Resource, success, fallback).Add(1)
	}
	return nil
}

func shouldDelegateListOnNotReadyCache(opts storage.ListOptions) bool {
	pred := opts.Predicate
	noLabelSelector := pred.Label == nil || pred.Label.Empty()
	noFieldSelector := pred.Field == nil || pred.Field.Empty()
	hasLimit := pred.Limit > 0
	return noLabelSelector && noFieldSelector && hasLimit
}

func (c *CacheDelegator) GuaranteedUpdate(ctx context.Context, key string, destination runtime.Object, ignoreNotFound bool, preconditions *storage.Preconditions, tryUpdate storage.UpdateFunc, cachedExistingObject runtime.Object) (err error) {
	return c.GuaranteedUpdateRetry(ctx, key, destination, ignoreNotFound, preconditions, tryUpdate, cachedExistingObject, true)
}

func (c *CacheDelegator) GuaranteedUpdateRetry(ctx context.Context, key string, destination runtime.Object, ignoreNotFound bool, preconditions *storage.Preconditions, tryUpdate storage.UpdateFunc, cachedExistingObject runtime.Object, retry bool) (err error) {
	attempts := 0
	defer func() {
		if attempts > 0 {
			status := storagemetrics.StatusSuccess
			if err != nil {
				if storage.IsConflict(err) {
					status = storagemetrics.StatusConflict
				} else {
					status = storagemetrics.StatusError
				}
			}
			storagemetrics.RecordStorageUpdateAttempts(c.cacher.groupResource, storagemetrics.StorageBackendWatchCache, status, attempts)
		}
	}()

	var currObj runtime.Object
	var currObjectRV uint64

	if elem, exists, err := c.cacher.watchCache.storage.GetByKey(key); err != nil {
		klog.Errorf("GetByKey returned error: %v", err)
	} else if exists {
		currObj = elem.(*store.Element).Object.DeepCopyObject()
		currObjectRV, err = c.cacher.versioner.ObjectResourceVersion(currObj)
		if err != nil {
			return err
		}
	}

	for {
		attempts++
		err = c.storage.GuaranteedUpdateRetry(ctx, key, destination, ignoreNotFound, preconditions, tryUpdate, currObj, false)
		if err == nil {
			return nil
		}
		if !storage.IsConflict(err) {
			return err
		}
		storagemetrics.RecordStorageUpdateConflict(c.cacher.groupResource, storagemetrics.StorageBackendWatchCache)
		if !retry {
			return err
		}

		var storageErr *storage.StorageError
		if !stderrors.As(err, &storageErr) || storageErr.ResourceVersion <= 0 {
			return err
		}

		elem, exists, _, err := c.cacher.watchCache.WaitUntilFreshAndGet(ctx, uint64(storageErr.ResourceVersion), key)
		if err != nil {
			return err
		}
		if !exists || currObjectRV == 0 {
			currObj = nil
		} else {
			newObject := elem.(*store.Element).Object
			newObjectRV, err := c.cacher.versioner.ObjectResourceVersion(newObject)
			if err != nil {
				return err
			}
			if newObjectRV <= currObjectRV {
				currObj = nil
			} else {
				currObj = newObject.DeepCopyObject()
				currObjectRV = newObjectRV
			}
		}
	}
}

func (c *CacheDelegator) Stats(ctx context.Context) (storage.Stats, error) {
	return c.storage.Stats(ctx)
}

func (c *CacheDelegator) ReadinessCheck() error {
	if !c.cacher.Ready() {
		return storage.ErrStorageNotReady
	}
	return nil
}

func (c *CacheDelegator) RequestWatchProgress(ctx context.Context) error {
	return c.storage.RequestWatchProgress(ctx)
}

func (c *CacheDelegator) CompactRevision() int64 {
	if c.cacher.compactor == nil {
		return c.storage.CompactRevision()
	}
	return c.cacher.compactor.Revision()
}

func (c *CacheDelegator) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	c.wg.Wait()
}

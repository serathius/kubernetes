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
cachertesting "k8s.io/apiserver/pkg/storage/cacher/testing"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"


	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/rand"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/apis/example"
	examplev1 "k8s.io/apiserver/pkg/apis/example/v1"
	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/storage"
	storagetesting "k8s.io/apiserver/pkg/storage/testing"
	"k8s.io/apiserver/pkg/storage/value/encrypt/identity"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/klog/v2"
)

func init() {
	metav1.AddToGroupVersion(cachertesting.Scheme, metav1.SchemeGroupVersion)
	utilruntime.Must(example.AddToScheme(cachertesting.Scheme))
	utilruntime.Must(examplev1.AddToScheme(cachertesting.Scheme))
}


func checkStorageInvariants(ctx context.Context, t *testing.T, key string) {
	// No-op function since cacher simply passes object creation to the underlying storage.
}

func TestCreate(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestCreate(ctx, t, cacher, checkStorageInvariants)
}

func TestCreateWithTTL(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestCreateWithTTL(ctx, t, cacher)
}

func TestCreateWithKeyExist(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestCreateWithKeyExist(ctx, t, cacher)
}

func TestGet(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestGet(ctx, t, cacher)
}

func TestUnconditionalDelete(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestUnconditionalDelete(ctx, t, cacher)
}

func TestConditionalDelete(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestConditionalDelete(ctx, t, cacher)
}

func TestDeleteWithSuggestion(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestDeleteWithSuggestion(ctx, t, cacher)
}

func TestDeleteWithSuggestionAndConflict(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestDeleteWithSuggestionAndConflict(ctx, t, cacher)
}

func TestDeleteWithSuggestionOfDeletedObject(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestDeleteWithSuggestionOfDeletedObject(ctx, t, cacher)
}

func TestValidateDeletionWithSuggestion(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestValidateDeletionWithSuggestion(ctx, t, cacher)
}

func TestValidateDeletionWithOnlySuggestionValid(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestValidateDeletionWithOnlySuggestionValid(ctx, t, cacher)
}

func TestDeleteWithConflict(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestDeleteWithConflict(ctx, t, cacher)
}

func TestPreconditionalDeleteWithSuggestion(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestPreconditionalDeleteWithSuggestion(ctx, t, cacher)
}

func TestPreconditionalDeleteWithSuggestionPass(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestPreconditionalDeleteWithOnlySuggestionPass(ctx, t, cacher)
}

func TestListPaging(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestListPaging(ctx, t, cacher)
}

func TestLists(t *testing.T) {
	for _, consistentRead := range []bool{true, false} {
		for _, listFromCacheSnapshot := range []bool{true, false} {
			t.Run(fmt.Sprintf("ConsistentListFromCache=%v,ListFromCacheSnapshot=%v", consistentRead, listFromCacheSnapshot), func(t *testing.T) {
				featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.ListFromCacheSnapshot, listFromCacheSnapshot)
				if !consistentRead {
					featuregatetesting.SetFeatureGateEmulationVersionDuringTest(t, utilfeature.DefaultFeatureGate, version.MustParse("1.33"))
					featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.ConsistentListFromCache, false)
				}
				t.Run("List", func(t *testing.T) {
					t.Parallel()
					ctx, cacher, server, terminate := SetupCacher(t)
					t.Cleanup(terminate)
					storagetesting.RunTestList(ctx, t, cacher, compactStore(cacher, server.V3Client.Client), true, server.V3Client.Kubernetes.(*storagetesting.KubernetesRecorder))
				})

				t.Run("ConsistentList", func(t *testing.T) {
					t.Parallel()
					ctx, cacher, server, terminate := SetupCacher(t)
					t.Cleanup(terminate)
					storagetesting.RunTestConsistentList(ctx, t, cacher, increaseRVFunc(server.V3Client.Client), true, consistentRead, listFromCacheSnapshot)
				})

				t.Run("GetListNonRecursive", func(t *testing.T) {
					t.Parallel()
					ctx, cacher, server, terminate := SetupCacher(t)
					t.Cleanup(terminate)
					storagetesting.RunTestGetListNonRecursive(ctx, t, increaseRVFunc(server.V3Client.Client), cacher)
				})
			})
		}
	}
}

func TestCompactRevision(t *testing.T) {
	// Test requires store to observe extenal changes to compaction revision, requiring dedicated watch on compact key which is enabled by ListFromCacheSnapshot.
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.ListFromCacheSnapshot, true)
	ctx, cacher, server, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestCompactRevision(ctx, t, cacher, increaseRVFunc(server.V3Client.Client), compactStore(cacher, server.V3Client.Client))
}

func TestMarkConsistent(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.ListFromCacheSnapshot, true)
	ctx, cacher, server, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	recorder := server.V3Client.Kubernetes.(*storagetesting.KubernetesRecorder)

	t.Log("New cache collects snapshots, list skips etcd")
	resourceVersion1 := createObject(t, ctx, cacher)
	etcdRequests := etcdListRequests(t, ctx, cacher, recorder, storage.ListOptions{
		Predicate:            storage.Everything,
		ResourceVersionMatch: metav1.ResourceVersionMatchExact,
		ResourceVersion:      resourceVersion1,
		Recursive:            true,
	})
	if len(etcdRequests) != 0 {
		t.Errorf("Expected no requests to etcd, got: %+v", etcdRequests)
	}
	if cacher.cacher.watchCache.snapshots.Len() != 2 {
		t.Errorf("Expected cache %d snapshots, got: %d", 2, cacher.cacher.watchCache.snapshots.Len())
	}

	t.Log("Inconsistent cache clears old snapshots, list hits etcd")
	cacher.cacher.MarkConsistent(false)
	etcdRequests = etcdListRequests(t, ctx, cacher, recorder, storage.ListOptions{
		Predicate:            storage.Everything,
		ResourceVersionMatch: metav1.ResourceVersionMatchExact,
		ResourceVersion:      resourceVersion1,
		Recursive:            true,
	})
	if len(etcdRequests) != 1 {
		t.Errorf("Expected request to etcd, got: %+v", etcdRequests)
	}
	if cacher.cacher.watchCache.snapshots.Len() != 0 {
		t.Errorf("Expected cache %d snapshots, got: %d", 0, cacher.cacher.watchCache.snapshots.Len())
	}

	t.Log("Inconsistent cache doesn't collect new snapshot, list hits etcd")
	resourceVersion2 := createObject(t, ctx, cacher)
	etcdRequests = etcdListRequests(t, ctx, cacher, recorder, storage.ListOptions{
		Predicate:            storage.Everything,
		ResourceVersionMatch: metav1.ResourceVersionMatchExact,
		ResourceVersion:      resourceVersion2,
		Recursive:            true,
	})
	if len(etcdRequests) != 1 {
		t.Errorf("Expected request to etcd, got: %+v", etcdRequests)
	}
	if cacher.cacher.watchCache.snapshots.Len() != 0 {
		t.Errorf("Expected cache %d snapshots, got: %d", 0, cacher.cacher.watchCache.snapshots.Len())
	}

	t.Log("Marking cache consistent allows it to collect new snapshots, list skips etcd")
	cacher.cacher.MarkConsistent(true)
	resourceVersion3 := createObject(t, ctx, cacher)
	etcdRequests = etcdListRequests(t, ctx, cacher, recorder, storage.ListOptions{
		Predicate:            storage.Everything,
		ResourceVersionMatch: metav1.ResourceVersionMatchExact,
		ResourceVersion:      resourceVersion3,
		Recursive:            true,
	})
	if len(etcdRequests) != 0 {
		t.Errorf("Expected no requests to etcd, got: %+v", etcdRequests)
	}
	if cacher.cacher.watchCache.snapshots.Len() != 1 {
		t.Errorf("Expected cache %d snapshots, got: %d", 1, cacher.cacher.watchCache.snapshots.Len())
	}
}

func createObject(t *testing.T, ctx context.Context, store storage.Interface) string {
	var out example.Pod
	pod := &example.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: rand.String(10)}}
	err := store.Create(ctx, cachertesting.ComputePodKey(pod), pod, &out, 0)
	if err != nil {
		t.Fatal(err)
	}
	return out.ResourceVersion
}

func etcdListRequests(t *testing.T, ctx context.Context, store storage.Interface, recorder *storagetesting.KubernetesRecorder, opts storage.ListOptions) []storagetesting.RecordedList {
	key := rand.String(10)
	listCtx := context.WithValue(ctx, storagetesting.RecorderContextKey, key)
	listOut := &example.PodList{}
	if err := store.GetList(listCtx, "/pods/", opts, listOut); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	return recorder.ListRequestForKey(key)
}

func TestGetListRecursivePrefix(t *testing.T) {
	ctx, store, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestGetListRecursivePrefix(ctx, t, store)
}

func checkStorageCalls(t *testing.T, pageSize, estimatedProcessedObjects uint64) {
	// No-op function for now, since cacher passes pagination calls to underlying storage.
}

func TestListContinuation(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestListContinuation(ctx, t, cacher, checkStorageCalls)
}

func TestListPaginationRareObject(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestListPaginationRareObject(ctx, t, cacher, checkStorageCalls)
}

func TestListContinuationWithFilter(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestListContinuationWithFilter(ctx, t, cacher, checkStorageCalls)
}

func TestListInconsistentContinuation(t *testing.T) {
	// TODO(#109831): Enable use of this by setting compaction.
}

func TestListResourceVersionMatch(t *testing.T) {
	// TODO(#109831): Enable use of this test and run it.
}

func TestNamespaceScopedList(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t, cachertesting.WithNodeNameAndNamespaceIndex)
	t.Cleanup(terminate)
	storagetesting.RunTestNamespaceScopedList(ctx, t, cacher)
}

func TestGuaranteedUpdate(t *testing.T) {
	// TODO(#109831): Enable use of this test and run it.
}

func TestGuaranteedUpdateWithTTL(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestGuaranteedUpdateWithTTL(ctx, t, cacher)
}

func TestGuaranteedUpdateChecksStoredData(t *testing.T) {
	// TODO(#109831): Enable use of this test and run it.
}

func TestGuaranteedUpdateWithConflict(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestGuaranteedUpdateWithConflict(ctx, t, cacher)
}

func TestGuaranteedUpdateWithSuggestionAndConflict(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestGuaranteedUpdateWithSuggestionAndConflict(ctx, t, cacher)
}

func TestTransformationFailure(t *testing.T) {
	// TODO(#109831): Enable use of this test and run it.
}

func TestStats(t *testing.T) {
	for _, sizeBasedListCostEstimate := range []bool{true, false} {
		t.Run(fmt.Sprintf("SizeBasedListCostEstimate=%v", sizeBasedListCostEstimate), func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.SizeBasedListCostEstimate, sizeBasedListCostEstimate)
			ctx, cacher, _, terminate := SetupCacher(t)
			t.Cleanup(terminate)
			storagetesting.RunTestStats(ctx, t, cacher, cachertesting.Codecs.LegacyCodec(examplev1.SchemeGroupVersion), identity.NewEncryptCheckTransformer(), sizeBasedListCostEstimate)
		})
	}
}
func TestKeySchema(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestKeySchema(ctx, t, cacher)
}

func TestWatch(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestWatch(ctx, t, cacher)
}

func TestWatchFromZero(t *testing.T) {
	ctx, cacher, server, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestWatchFromZero(ctx, t, cacher, compactWatch(cacher, server.V3Client.Client))
}

func TestDeleteTriggerWatch(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestDeleteTriggerWatch(ctx, t, cacher)
}

func TestWatchFromNonZero(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestWatchFromNonZero(ctx, t, cacher)
}

func TestDelayedWatchDelivery(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestDelayedWatchDelivery(ctx, t, cacher)
}

func TestWatchError(t *testing.T) {
	// TODO(#109831): Enable use of this test and run it.
}

func TestWatchContextCancel(t *testing.T) {
	// TODO(#109831): Enable use of this test and run it.
}

func TestWatcherTimeout(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestWatcherTimeout(ctx, t, cacher)
}

func TestWatchDeleteEventObjectHaveLatestRV(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestWatchDeleteEventObjectHaveLatestRV(ctx, t, cacher)
}

func TestWatchInitializationSignal(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestWatchInitializationSignal(ctx, t, cacher)
}

func TestClusterScopedWatch(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t, cachertesting.WithClusterScopedKeyFunc, cachertesting.WithNodeNameAndNamespaceIndex)
	t.Cleanup(terminate)
	storagetesting.RunTestClusterScopedWatch(ctx, t, cacher)
}

func TestNamespaceScopedWatch(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t, cachertesting.WithNodeNameAndNamespaceIndex)
	t.Cleanup(terminate)
	storagetesting.RunTestNamespaceScopedWatch(ctx, t, cacher)
}

func TestWatchDispatchBookmarkEvents(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestWatchDispatchBookmarkEvents(ctx, t, cacher, true)
}

func TestWatchBookmarksWithCorrectResourceVersion(t *testing.T) {
	ctx, cacher, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunTestOptionalWatchBookmarksWithCorrectResourceVersion(ctx, t, cacher)
}

func TestSendInitialEventsBackwardCompatibility(t *testing.T) {
	ctx, store, _, terminate := SetupCacher(t)
	t.Cleanup(terminate)
	storagetesting.RunSendInitialEventsBackwardCompatibility(ctx, t, store)
}

func TestWatchSemantics(t *testing.T) {
	store, terminate := SetupCacherWithEtcdAndCreateWrapper(t)
	t.Cleanup(terminate)
	storagetesting.RunWatchSemantics(context.TODO(), t, store)
}

func TestWatchSemanticInitialEventsExtended(t *testing.T) {
	store, terminate := SetupCacherWithEtcdAndCreateWrapper(t)
	t.Cleanup(terminate)
	storagetesting.RunWatchSemanticInitialEventsExtended(context.TODO(), t, store)
}

func TestWatchListMatchSingle(t *testing.T) {
	store, terminate := SetupCacherWithEtcdAndCreateWrapper(t)
	t.Cleanup(terminate)
	storagetesting.RunWatchListMatchSingle(context.TODO(), t, store)
}

// ===================================================
// Test-setup related function are following.
// ===================================================


func SetupCacherWithEtcdAndCreateWrapper(t *testing.T, opts ...cachertesting.SetupOption) (storage.Interface, cachertesting.TearDownFunc) {
	_, cacher, _, tearDown := SetupCacher(t, opts...)

	if !utilfeature.DefaultFeatureGate.Enabled(features.ResilientWatchCacheInitialization) {
		if err := cacher.cacher.ready.wait(context.TODO()); err != nil {
			t.Fatalf("unexpected error waiting for the cache to be ready")
		}
	}
	return &createWrapper{CacheDelegator: cacher}, tearDown
}

type createWrapper struct {
	*CacheDelegator
}

func (c *createWrapper) Create(ctx context.Context, key string, obj, out runtime.Object, ttl uint64) error {
	if err := c.CacheDelegator.Create(ctx, key, obj, out, ttl); err != nil {
		return err
	}
	return wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, wait.ForeverTestTimeout, true, func(ctx context.Context) (bool, error) {
		currentObj := c.CacheDelegator.cacher.newFunc()
		err := c.CacheDelegator.Get(ctx, key, storage.GetOptions{ResourceVersion: "0"}, currentObj)
		if err != nil {
			if storage.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		if !apiequality.Semantic.DeepEqual(currentObj, out) {
			return false, nil
		}
		return true, nil
	})
}

func BenchmarkStoreCreateList(b *testing.B) {
	klog.SetLogger(logr.Discard())
	storeOptions := []struct {
		name         string
		btreeEnabled bool
	}{
		{
			name:         "Btree",
			btreeEnabled: true,
		},
		{
			name:         "Map",
			btreeEnabled: false,
		},
	}
	for _, store := range storeOptions {
		b.Run(fmt.Sprintf("Store=%s", store.name), func(b *testing.B) {
			featuregatetesting.SetFeatureGateDuringTest(b, utilfeature.DefaultFeatureGate, features.BtreeWatchCache, store.btreeEnabled)
			for _, rvm := range []metav1.ResourceVersionMatch{metav1.ResourceVersionMatchNotOlderThan, metav1.ResourceVersionMatchExact} {
				b.Run(fmt.Sprintf("RV=%s", rvm), func(b *testing.B) {
					for _, useIndex := range []bool{true, false} {
						b.Run(fmt.Sprintf("Indexed=%v", useIndex), func(b *testing.B) {
							opts := []cachertesting.SetupOption{}
							if useIndex {
								opts = append(opts, cachertesting.WithNodeNameAndNamespaceIndex)
							}
							ctx, cacher, _, terminate := SetupCacher(b, opts...)
							b.Cleanup(terminate)
							storagetesting.RunBenchmarkStoreListCreate(ctx, b, cacher, rvm)
						})
					}
				})
			}
		})
	}
}

func BenchmarkStoreList(b *testing.B) {
	klog.SetLogger(logr.Discard())
	// Based on https://github.com/kubernetes/community/blob/master/sig-scalability/configs-and-limits/thresholds.md
	dimensions := []struct {
		namespaceCount       int
		podPerNamespaceCount int
		nodeCount            int
	}{
		{
			namespaceCount:       10_000,
			podPerNamespaceCount: 15,
			nodeCount:            5_000,
		},
		{
			namespaceCount:       50,
			podPerNamespaceCount: 3_000,
			nodeCount:            5_000,
		},
		{
			namespaceCount:       100,
			podPerNamespaceCount: 1_100,
			nodeCount:            1000,
		},
	}
	for _, dims := range dimensions {
		b.Run(fmt.Sprintf("Namespaces=%d/Pods=%d/Nodes=%d", dims.namespaceCount, dims.namespaceCount*dims.podPerNamespaceCount, dims.nodeCount), func(b *testing.B) {
			data := storagetesting.PrepareBenchchmarkData(dims.namespaceCount, dims.podPerNamespaceCount, dims.nodeCount)
			storeOptions := []struct {
				name         string
				btreeEnabled bool
			}{
				{
					name:         "Btree",
					btreeEnabled: true,
				},
				{
					name:         "Map",
					btreeEnabled: false,
				},
			}
			for _, store := range storeOptions {
				b.Run(fmt.Sprintf("Store=%s", store.name), func(b *testing.B) {
					featuregatetesting.SetFeatureGateDuringTest(b, utilfeature.DefaultFeatureGate, features.BtreeWatchCache, store.btreeEnabled)
					ctx, cacher, _, terminate := SetupCacher(b, cachertesting.WithNodeNameAndNamespaceIndex)
					b.Cleanup(terminate)
					var out example.Pod
					for _, pod := range data.Pods {
						err := cacher.Create(ctx, cachertesting.ComputePodKey(pod), pod, &out, 0)
						if err != nil {
							b.Fatal(err)
						}
					}
					for _, useIndex := range []bool{true, false} {
						b.Run(fmt.Sprintf("Indexed=%v", useIndex), func(b *testing.B) {
							storagetesting.RunBenchmarkStoreList(ctx, b, cacher, data, useIndex)
						})
					}
				})
			}
		})
	}
}

func BenchmarkStoreStats(b *testing.B) {
	klog.SetLogger(logr.Discard())
	data := storagetesting.PrepareBenchchmarkData(50, 3_000, 5_000)
	ctx, cacher, _, terminate := SetupCacher(b)
	b.Cleanup(terminate)
	var out example.Pod
	for _, pod := range data.Pods {
		err := cacher.Create(ctx, cachertesting.ComputePodKey(pod), pod, &out, 0)
		if err != nil {
			b.Fatal(err)
		}
	}
	storagetesting.RunBenchmarkStoreStats(ctx, b, cacher)
}

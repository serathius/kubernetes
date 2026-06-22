/*
Copyright 2024 The Kubernetes Authors.

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

package testing

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	stdruntime "runtime"
	slices "slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/clock"
	"sigs.k8s.io/yaml"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/storage"
	etcd3metrics "k8s.io/apiserver/pkg/storage/etcd3/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

//go:embed testdata/exemplar_pod.yaml
var exemplarPodYAML []byte

var globalUpdateCounter atomic.Uint64

type scope string

var (
	cluster   scope = "Cluster"
	node      scope = "Node"
	namespace scope = "Namespace"
)

const (
	loadNone               = "None"
	loadWatcher            = "Watcher"
	loadLister             = "Lister"
	loadListerExactRV      = "ListerExactRV"
	loadListerNotOlderThan = "ListerNotOlderThan"
	loadWatchList          = "WatchList"
	trafficDeleteCreate    = "DeleteCreate"
	trafficPatch           = "Patch"
)

func RunBenchmarkWriteThroughput(ctx context.Context, b *testing.B, store storage.Interface, data BenchmarkData, hasIndex bool, tracker *WatchLatencyTracker, compactFn func(context.Context, uint64) error) {
	if os.Getenv("ETCD_DATA_PRESEEDED") != "true" {
		require.NoError(b, PrecreateBenchmarkPods(ctx, store, data))
		if compactFn != nil {
			rv, err := store.GetCurrentResourceVersion(ctx)
			if err != nil {
				panic(fmt.Sprintf("Failed to get current resource version for seeding compaction: %v", err))
			}
			if rv > 0 {
				if err := compactFn(ctx, rv); err != nil && !strings.Contains(err.Error(), "compacted") {
					panic(fmt.Sprintf("Failed to compact etcd to revision %d after database seeding: %v", rv, err))
				}
			}
		}
	}
	require.NoError(b, waitForConsistent(ctx, store))

	for _, trafficType := range []string{trafficDeleteCreate, trafficPatch} {
		b.Run(fmt.Sprintf("Traffic=%s", trafficType), func(b *testing.B) {
			parallelismOptions := []int{25}
			if pStr := os.Getenv("BENCHMARK_PARALLELISM"); pStr != "" {
				if parsed, err := strconv.Atoi(pStr); err == nil {
					parallelismOptions = []int{parsed}
				}
			}
			for _, parallelism := range parallelismOptions {
				b.Run(fmt.Sprintf("Parallelism=%d", parallelism), func(b *testing.B) {
					loadTypes := []string{loadNone, loadWatcher, loadLister, loadListerExactRV, loadListerNotOlderThan, loadWatchList}
					for _, loadType := range loadTypes {
						useIndexOptions := []bool{false}
						if hasIndex && loadType != loadNone {
							useIndexOptions = []bool{false, true}
						}
						for _, readIndexed := range useIndexOptions {
							b.Run(fmt.Sprintf("Background=%s/UseIndex=%v", loadType, readIndexed), func(b *testing.B) {
								if compactFn != nil {
									rv, err := store.GetCurrentResourceVersion(ctx)
									if err != nil {
										panic(fmt.Sprintf("Failed to get current resource version for compaction: %v", err))
									}
									if rv > 0 {
										if err := compactFn(ctx, rv); err != nil && !strings.Contains(err.Error(), "compacted") {
											panic(fmt.Sprintf("Failed to compact etcd to revision %d before benchmark: %v", rv, err))
										}
									}
								}
								require.NoError(b, waitForConsistent(ctx, store))
								stdruntime.GC()
								b.SetParallelism(parallelism)
								if tracker != nil {
									rv, _ := store.GetCurrentResourceVersion(ctx)
									tracker.Reset(rv, time.Now())
								}
								runBenchmarkWriteThroughput(ctx, b, store, data, trafficType, loadType, readIndexed, tracker)
							})
						}
					}
				})
			}
		})
	}
}

func runBenchmarkWriteThroughput(ctx context.Context, b *testing.B, store storage.Interface, data BenchmarkData, trafficType string, loadType string, readIndexed bool, tracker *WatchLatencyTracker) {
	stopBackgroundLoadCh := make(chan struct{})
	var workersWg sync.WaitGroup
	var stopOnce sync.Once
	stopBackgroundLoad := func() {
		stopOnce.Do(func() {
			close(stopBackgroundLoadCh)
			workersWg.Wait()
		})
	}
	defer stopBackgroundLoad()

	var writes atomic.Uint64
	var watchEvents atomic.Uint64
	var listCalls atomic.Uint64
	var listObjects atomic.Uint64
	var index atomic.Uint64
	var latestRV atomic.Pointer[string]
	initialRV := "0"
	latestRV.Store(&initialRV)

	// Determine trackers
	var writeTracker *WatchLatencyTracker  // Tracker used to record writes (sets annotation)
	var clientTracker *WatchLatencyTracker // Tracker used by background watchers (client-side latency)
	startRVStr := ""

	if tracker != nil {
		writeTracker = tracker
		if loadType == loadWatcher {
			// Cacher case with background watchers: we need a separate client tracker
			clientTracker = NewWatchLatencyTracker(clock.RealClock{})
			// Reset the clientTracker with current RV
			rv, _ := store.GetCurrentResourceVersion(ctx)
			clientTracker.Reset(rv, time.Now())
			startRVStr = strconv.FormatUint(rv, 10)
		}
	} else if loadType == loadWatcher {
		// Etcd3 case with background watchers: one tracker does both recording writes and client tracking
		clientTracker = NewWatchLatencyTracker(clock.RealClock{})
		writeTracker = clientTracker
		// Reset the clientTracker with current RV
		rv, _ := store.GetCurrentResourceVersion(ctx)
		clientTracker.Reset(rv, time.Now())
		startRVStr = strconv.FormatUint(rv, 10)
	}

	listerCount := 10
	if countStr := os.Getenv("BENCHMARK_LISTER_COUNT"); countStr != "" {
		if parsed, err := strconv.Atoi(countStr); err == nil {
			listerCount = parsed
		}
	}

	switch loadType {
	case loadNone:
	case loadWatcher:
		watcherCount := 10
		if countStr := os.Getenv("BENCHMARK_WATCHER_COUNT"); countStr != "" {
			if parsed, err := strconv.Atoi(countStr); err == nil {
				watcherCount = parsed
			}
		}
		startBackgroundWatchers(ctx, store, data, watcherCount, readIndexed, &workersWg, stopBackgroundLoadCh, &watchEvents, clientTracker, startRVStr)
	case loadLister:
		startBackgroundListers(ctx, store, data, listerCount, readIndexed, &workersWg, stopBackgroundLoadCh, &listCalls, &listObjects, "", &latestRV)
	case loadListerExactRV:
		startBackgroundListers(ctx, store, data, listerCount, readIndexed, &workersWg, stopBackgroundLoadCh, &listCalls, &listObjects, metav1.ResourceVersionMatchExact, &latestRV)
	case loadListerNotOlderThan:
		startBackgroundListers(ctx, store, data, listerCount, readIndexed, &workersWg, stopBackgroundLoadCh, &listCalls, &listObjects, metav1.ResourceVersionMatchNotOlderThan, &latestRV)
	case loadWatchList:
		startBackgroundWatchListers(ctx, store, data, listerCount, readIndexed, &workersWg, stopBackgroundLoadCh, &listCalls, &listObjects)
	default:
		panic(fmt.Sprintf("Unknown load type: %s", loadType))
	}
	writes.Store(0)
	watchEvents.Store(0)
	listCalls.Store(0)
	listObjects.Store(0)

	etcd3metrics.Register()
	statsBefore := getEtcdRequestStats()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := int(index.Add(1)) % len(data.PodKeys)
			writes.Add(runTraffic(ctx, b, store, data, trafficType, i, &latestRV, writeTracker))
		}
	})
	b.StopTimer()
	elapsedSeconds := b.Elapsed().Seconds()
	rv := ""
	if rvPtr := latestRV.Load(); rvPtr != nil {
		rv = *rvPtr
	}
	require.NoError(b, waitForResourceVersion(ctx, store, rv))
	if rv != "" && rv != "0" {
		targetRVVal, err := strconv.ParseUint(rv, 10, 64)
		if err == nil {
			if clientTracker != nil && (loadType != loadWatcher || !readIndexed) {
				if err := clientTracker.WaitForResourceVersion(targetRVVal, 30*time.Second); err != nil {
					b.Fatalf("Timed out waiting for client watchers to consume target RV %d: %v", targetRVVal, err)
				}
			} else if tracker != nil {
				if err := tracker.WaitForResourceVersion(targetRVVal, 30*time.Second); err != nil {
					b.Fatalf("Timed out waiting for cacher reflector to consume target RV %d: %v", targetRVVal, err)
				}
			}
		}
	}
	b.ReportMetric(float64(writes.Load())/elapsedSeconds, "writes/s")

	statsAfter := getEtcdRequestStats()

	stopBackgroundLoad()

	switch loadType {
	case loadWatcher:
		b.ReportMetric(float64(watchEvents.Load())/elapsedSeconds, "watch-events/s")
	case loadLister, loadListerExactRV, loadListerNotOlderThan, loadWatchList:
		b.ReportMetric(float64(listCalls.Load())/elapsedSeconds, "list-calls/s")
		b.ReportMetric(float64(listObjects.Load())/elapsedSeconds, "list-objs/s")
	}

	// Report cacher internal watchCache latency if available
	if tracker != nil {
		if p99 := tracker.GetP99Latency(); p99 > 0 {
			b.ReportMetric(p99.Seconds(), "watch-cache-latency-p99-s")
		}
	}
	// Report client-observed watch latency if available
	if clientTracker != nil {
		if p99 := clientTracker.GetP99Latency(); p99 > 0 {
			b.ReportMetric(p99.Seconds(), "watch-latency-p99-s")
		}
	}

	numWrites := writes.Load()

	if numWrites > 0 {
		creates := statsAfter.create - statsBefore.create
		deletes := statsAfter.delete - statsBefore.delete
		updates := statsAfter.update - statsBefore.update
		gets := statsAfter.get - statsBefore.get
		totalReqs := creates + deletes + updates + gets

		b.ReportMetric(float64(creates)/float64(numWrites), "etcd-creates/write-cycle")
		b.ReportMetric(float64(deletes)/float64(numWrites), "etcd-deletes/write-cycle")
		b.ReportMetric(float64(updates)/float64(numWrites), "etcd-updates/write-cycle")
		b.ReportMetric(float64(gets)/float64(numWrites), "etcd-gets/write-cycle")
		b.ReportMetric(float64(totalReqs)/float64(numWrites), "etcd-total-reqs/write-cycle")
	}
}

func waitForConsistent(ctx context.Context, store storage.Interface) error {
	rvVal, err := store.GetCurrentResourceVersion(ctx)
	if err != nil {
		return fmt.Errorf("unexpected error getting resource version: %w", err)
	}
	rv := strconv.FormatUint(rvVal, 10)

	listOut := &corev1.PodList{}
	err = store.GetList(ctx, "/pods/", storage.ListOptions{
		ResourceVersion:      rv,
		ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		Recursive:            true,
		Predicate: storage.SelectionPredicate{
			Label: labels.Everything(),
			Field: fields.Everything(),
			Limit: 1,
		},
	}, listOut)
	if err != nil {
		return fmt.Errorf("unexpected error waiting for consistency: %w", err)
	}
	return nil
}

func waitForResourceVersion(ctx context.Context, store storage.Interface, rv string) error {
	if rv == "0" || rv == "" {
		return nil
	}
	var err error
	for range 10 {
		listOut := &corev1.PodList{}
		err = store.GetList(ctx, "/pods/", storage.ListOptions{
			ResourceVersion:      rv,
			ResourceVersionMatch: metav1.ResourceVersionMatchExact,
			Recursive:            true,
			Predicate: storage.SelectionPredicate{
				Label: labels.Everything(),
				Field: fields.Everything(),
				Limit: 1,
			},
		}, listOut)
		if err == nil {
			return nil
		}
		if !strings.Contains(err.Error(), "Too large resource version") {
			return fmt.Errorf("unexpected error waiting for consistency at rv %s: %w", rv, err)
		}
	}
	return fmt.Errorf("timed out waiting for consistency at rv %s: %w", rv, err)
}

func runTraffic(ctx context.Context, b *testing.B, store storage.Interface, data BenchmarkData, trafficType string, index int, latestRV *atomic.Pointer[string], tracker *WatchLatencyTracker) (writes uint64) {
	var podOut *corev1.Pod
	rvOnly := os.Getenv("BENCHMARK_OPTIMISTIC_RV_ONLY") == "true"
	switch trafficType {
	case trafficDeleteCreate:
		var cachedObj runtime.Object
		if len(data.PodResourceVersions) > 0 {
			if rvPtr := data.PodResourceVersions[index].Load(); rvPtr != nil && *rvPtr != "" && *rvPtr != "0" {
				if rvOnly {
					cachedObj = &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:            data.Pods[index].Name,
							Namespace:       data.Pods[index].Namespace,
							ResourceVersion: *rvPtr,
						},
					}
				} else {
					pod := data.Pods[index].DeepCopy()
					pod.ResourceVersion = *rvPtr
					cachedObj = pod
				}
			}
		}
		podOut = &corev1.Pod{}
		err := store.Delete(ctx, data.PodKeys[index], podOut, nil, storage.ValidateAllObjectFunc, cachedObj, storage.DeleteOptions{})
		if err == nil {
			writes += 1
		} else if !storage.IsNotFound(err) {
			panic(fmt.Sprintf("Unexpected error on Delete %q: %v", data.PodKeys[index], err))
		}
		var pod *corev1.Pod
		if rvOnly {
			pod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      data.Pods[index].Name,
					Namespace: data.Pods[index].Namespace,
				},
			}
		} else {
			pod = data.Pods[index].DeepCopy()
		}
		if tracker != nil {
			tracker.RecordWrite(pod)
		}
		podOut = &corev1.Pod{}
		err = store.Create(ctx, data.PodKeys[index], pod, podOut, 0)
		if err == nil {
			writes += 1
			latestRV.Store(&podOut.ResourceVersion)
			if len(data.PodResourceVersions) > 0 {
				data.PodResourceVersions[index].Store(&podOut.ResourceVersion)
			}
		} else if !storage.IsExist(err) {
			panic(fmt.Sprintf("Unexpected error on Create %q: %v", data.PodKeys[index], err))
		}
	case trafficPatch:
		var cachedObj runtime.Object
		if len(data.PodResourceVersions) > 0 {
			if rvPtr := data.PodResourceVersions[index].Load(); rvPtr != nil && *rvPtr != "" && *rvPtr != "0" {
				if rvOnly {
					cachedObj = &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:            data.Pods[index].Name,
							Namespace:       data.Pods[index].Namespace,
							ResourceVersion: *rvPtr,
						},
					}
				} else {
					pod := data.Pods[index].DeepCopy()
					pod.ResourceVersion = *rvPtr
					cachedObj = pod
				}
			}
		}
		podOut = &corev1.Pod{}
		err := store.GuaranteedUpdate(ctx, data.PodKeys[index], podOut, false, nil, patchFunc(index, tracker), cachedObj)
		if err != nil {
			panic(fmt.Sprintf("Unexpected error on Patch %q: %v", data.PodKeys[index], err))
		} else {
			writes += 1
			latestRV.Store(&podOut.ResourceVersion)
			if len(data.PodResourceVersions) > 0 {
				data.PodResourceVersions[index].Store(&podOut.ResourceVersion)
			}
		}
	default:
		panic(fmt.Sprintf("Unknown traffic type: %s", trafficType))
	}
	return writes
}

func patchFunc(i int, tracker *WatchLatencyTracker) func(input runtime.Object, res storage.ResponseMeta) (runtime.Object, *uint64, error) {
	return func(input runtime.Object, res storage.ResponseMeta) (runtime.Object, *uint64, error) {
		curr := input.(*corev1.Pod)
		if curr.Annotations == nil {
			curr.Annotations = make(map[string]string)
		}
		curr.Annotations["updated-by-benchmark"] = strconv.FormatUint(globalUpdateCounter.Add(1), 10)
		if tracker != nil {
			tracker.RecordWrite(curr)
		}
		return curr, nil, nil
	}
}

func startBackgroundWatchers(ctx context.Context, store storage.Interface, data BenchmarkData, count int, readIndexed bool, wg *sync.WaitGroup, stopCh <-chan struct{}, eventCounter *atomic.Uint64, tracker *WatchLatencyTracker, resourceVersion string) {
	for i := range count {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			opts := storage.ListOptions{
				ResourceVersion: resourceVersion,
				Recursive:       true,
				Predicate:       storage.Everything,
			}
			if readIndexed {
				nodeName := "default-node"
				if len(data.NodeNames) > 0 {
					nodeName = data.NodeNames[i%len(data.NodeNames)]
				}
				opts.Predicate.GetAttrs = podAttr
				opts.Predicate.IndexFields = []string{"spec.nodeName"}
				opts.Predicate.Field = fields.SelectorFromSet(fields.Set{"spec.nodeName": nodeName})
			}
			w, err := store.Watch(ctx, "/pods/", opts)
			if err != nil {
				return
			}
			defer w.Stop()
			for {
				select {
				case <-stopCh:
					return
				case <-ctx.Done():
					return
				case ev, ok := <-w.ResultChan():
					if !ok {
						return
					}
					eventCounter.Add(1)
					if tracker != nil {
						tracker.HandleEvent(ev.Type, ev.Object)
					}
				}
			}
		}(i)
	}
}

func startBackgroundListers(ctx context.Context, store storage.Interface, data BenchmarkData, count int, readIndexed bool, wg *sync.WaitGroup, stopCh <-chan struct{}, listCounter *atomic.Uint64, objCounter *atomic.Uint64, rvMatch metav1.ResourceVersionMatch, latestRV *atomic.Pointer[string]) {
	for i := range count {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			listOut := &corev1.PodList{}
			for {
				select {
				case <-stopCh:
					return
				case <-ctx.Done():
					return
				default:
				}

				opts := storage.ListOptions{
					Recursive:            true,
					ResourceVersionMatch: rvMatch,
					Predicate:            storage.Everything,
				}
				switch rvMatch {
				case metav1.ResourceVersionMatchExact, metav1.ResourceVersionMatchNotOlderThan:
					rv := *latestRV.Load()
					if rv == "0" || rv == "" {
						time.Sleep(10 * time.Millisecond)
						continue
					}
					opts.ResourceVersion = rv
				case "":
				default:
					panic(fmt.Sprintf("Unknown rvMatch: %s", rvMatch))
				}
				if readIndexed {
					nodeName := "default-node"
					if len(data.NodeNames) > 0 {
						nodeName = data.NodeNames[i%len(data.NodeNames)]
					}
					opts.Predicate.GetAttrs = podAttr
					opts.Predicate.IndexFields = []string{"spec.nodeName"}
					opts.Predicate.Field = fields.SelectorFromSet(fields.Set{"spec.nodeName": nodeName})
				}
				err := store.GetList(ctx, "/pods/", opts, listOut)
				if err == nil {
					listCounter.Add(1)
					objCounter.Add(uint64(len(listOut.Items)))
				}
			}
		}(i)
	}
}

func startBackgroundWatchListers(ctx context.Context, store storage.Interface, data BenchmarkData, count int, readIndexed bool, wg *sync.WaitGroup, stopCh <-chan struct{}, listCounter *atomic.Uint64, objCounter *atomic.Uint64) {
	for i := range count {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			opts := storage.ListOptions{
				Recursive:         true,
				Predicate:         storage.Everything,
				SendInitialEvents: new(true),
			}
			opts.Predicate.AllowWatchBookmarks = true

			if readIndexed {
				nodeName := "default-node"
				if len(data.NodeNames) > 0 {
					nodeName = data.NodeNames[i%len(data.NodeNames)]
				}
				opts.Predicate.GetAttrs = podAttr
				opts.Predicate.IndexFields = []string{"spec.nodeName"}
				opts.Predicate.Field = fields.SelectorFromSet(fields.Set{"spec.nodeName": nodeName})
			}

			for {
				select {
				case <-stopCh:
					return
				case <-ctx.Done():
					return
				default:
				}

				w, err := store.Watch(ctx, "/pods/", opts)
				if err != nil {
					time.Sleep(10 * time.Millisecond)
					continue
				}

				initialFinished := false
				for !initialFinished {
					select {
					case <-stopCh:
						w.Stop()
						return
					case <-ctx.Done():
						w.Stop()
						return
					case ev, ok := <-w.ResultChan():
						if !ok {
							initialFinished = true
							break
						}
						switch ev.Type {
						case watch.Bookmark:
							pod, ok := ev.Object.(*corev1.Pod)
							if !ok {
								panic("Unexpected type in event")
							}
							if pod.Annotations != nil && pod.Annotations[metav1.InitialEventsAnnotationKey] == "true" {
								initialFinished = true
							}
						default:
							objCounter.Add(1)
						}
					}
				}
				w.Stop()
				listCounter.Add(1)
			}
		}(i)
	}
}

func RunBenchmarkStoreList(ctx context.Context, b *testing.B, store storage.Interface, data BenchmarkData, useIndex bool) {
	for _, rvm := range []metav1.ResourceVersionMatch{"", metav1.ResourceVersionMatchExact, metav1.ResourceVersionMatchNotOlderThan} {
		b.Run(fmt.Sprintf("RV=%s", rvm), func(b *testing.B) {
			for _, scope := range []scope{cluster, node, namespace} {
				b.Run(fmt.Sprintf("Scope=%s", scope), func(b *testing.B) {
					var expectedElements int
					switch scope {
					case namespace:
						expectedElements = len(data.Pods) / len(data.NamespaceNames)
					case node:
						expectedElements = len(data.Pods) / len(data.NodeNames)
					case cluster:
						expectedElements = len(data.Pods)
					}
					limitOptions := []int64{0}
					switch {
					case expectedElements > 1000:
						limitOptions = append(limitOptions, 1000)
					case expectedElements > 100:
						limitOptions = append(limitOptions, 100)
					}
					for _, limit := range limitOptions {
						b.Run(fmt.Sprintf("Paginate=%v", limit), func(b *testing.B) {
							runBenchmarkStoreList(ctx, b, store, limit, rvm, scope, data, useIndex)
						})
					}
				})
			}
		})
	}
}

func runBenchmarkStoreList(ctx context.Context, b *testing.B, store storage.Interface, limit int64, match metav1.ResourceVersionMatch, scope scope, data BenchmarkData, useIndex bool) {
	objectCount := atomic.Uint64{}
	listCount := atomic.Uint64{}
	var index atomic.Uint64

	b.SetParallelism(4)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := int(index.Add(1))
			resourceVersion := ""
			switch match {
			case metav1.ResourceVersionMatchExact, metav1.ResourceVersionMatchNotOlderThan:
				maxRevision := 1 + len(data.Pods)
				resourceVersion = fmt.Sprintf("%d", maxRevision-99+i%100)
			}
			nodeName := data.NodeNames[i%len(data.NodeNames)]
			namespaceName := data.NamespaceNames[i%len(data.NamespaceNames)]

			opts := storage.ListOptions{
				Recursive:            true,
				ResourceVersion:      resourceVersion,
				ResourceVersionMatch: match,
				Predicate: storage.SelectionPredicate{
					GetAttrs: podAttr,
					Label:    labels.Everything(),
					Field:    fields.Everything(),
					Limit:    limit,
				},
			}
			switch scope {
			case cluster:
				objects, lists := paginateList(ctx, store, "/pods/", opts)
				objectCount.Add(uint64(objects))
				listCount.Add(uint64(lists))
			case node:
				if useIndex {
					opts.Predicate.GetAttrs = podAttr
					opts.Predicate.IndexFields = []string{"spec.nodeName"}
					opts.Predicate.Field = fields.SelectorFromSet(fields.Set{"spec.nodeName": nodeName})
				}
				objects, lists := paginateList(ctx, store, "/pods/", opts)
				objectCount.Add(uint64(objects))
				listCount.Add(uint64(lists))
			case namespace:
				ctx := ctx
				if useIndex {
					opts.Predicate.IndexFields = []string{"metadata.namespace"}
					ctx = request.WithRequestInfo(ctx, &request.RequestInfo{Namespace: namespaceName})
				}
				objects, lists := paginateList(ctx, store, "/pods/"+namespaceName, opts)
				objectCount.Add(uint64(objects))
				listCount.Add(uint64(lists))
			}
		}
	})
	elapsedSeconds := b.Elapsed().Seconds()
	b.ReportMetric(float64(objectCount.Load())/elapsedSeconds, "list-objs/s")
	b.ReportMetric(float64(listCount.Load())/elapsedSeconds, "list-calls/s")
}

func paginateList(ctx context.Context, store storage.Interface, key string, opts storage.ListOptions) (objectCount int, listCount int) {
	listOut := &corev1.PodList{}
	err := store.GetList(ctx, key, opts, listOut)
	if err != nil {
		panic(fmt.Sprintf("Unexpected error %s", err))
	}
	opts.Predicate.Continue = listOut.Continue
	opts.ResourceVersion = ""
	opts.ResourceVersionMatch = ""
	listCount += 1
	objectCount += len(listOut.Items)
	for opts.Predicate.Continue != "" {
		listOut := &corev1.PodList{}
		err := store.GetList(ctx, key, opts, listOut)
		if err != nil {
			panic(fmt.Sprintf("Unexpected error %s", err))
		}
		opts.Predicate.Continue = listOut.Continue
		listCount += 1
		objectCount += len(listOut.Items)
	}
	return objectCount, listCount
}

func podAttr(obj runtime.Object) (labels.Set, fields.Set, error) {
	pod := obj.(*corev1.Pod)
	return nil, fields.Set{
		"spec.nodeName":      pod.Spec.NodeName,
		"metadata.namespace": pod.Namespace,
	}, nil
}

func PrepareBenchmarkData(namespaceCount, podPerNamespaceCount, nodeCount int) (data BenchmarkData) {
	exemplar := loadExemplarPod()
	data.NodeNames = make([]string, nodeCount)
	for i := 0; i < nodeCount; i++ {
		data.NodeNames[i] = fmt.Sprintf("node-%d", i)
	}
	data.NamespaceNames = make([]string, namespaceCount)
	for i := 0; i < namespaceCount; i++ {
		namespace := fmt.Sprintf("ns-%d", i)
		data.NamespaceNames[i] = namespace
		for j := 0; j < podPerNamespaceCount; j++ {
			p := exemplar.DeepCopy()
			nodeIdx := (i*podPerNamespaceCount + j) % nodeCount
			randomizePod(p, namespace, data.NodeNames[nodeIdx], j)
			data.Pods = append(data.Pods, p)
			data.PodKeys = append(data.PodKeys, computeCorev1PodKey(p))
		}
	}
	return data
}

func PrecreateBenchmarkPods(ctx context.Context, store storage.Interface, data BenchmarkData) error {
	errCh := make(chan error, len(data.Pods))
	var wg sync.WaitGroup
	limitCh := make(chan struct{}, 20) // limit to 20 concurrent writers

	for _, pod := range data.Pods {
		wg.Add(1)
		go func(p *corev1.Pod) {
			defer wg.Done()
			limitCh <- struct{}{}
			defer func() { <-limitCh }()

			podOut := &corev1.Pod{}
			key := computeCorev1PodKey(p)
			err := store.Create(ctx, key, p, podOut, 0)
			if err != nil && !storage.IsExist(err) {
				errCh <- fmt.Errorf("unexpected error pre-creating pod %q: %w", key, err)
			}
		}(pod)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

type BenchmarkData struct {
	Pods                []*corev1.Pod
	PodKeys             []string
	NamespaceNames      []string
	NodeNames           []string
	PodResourceVersions []atomic.Pointer[string]
}

func loadExemplarPod() *corev1.Pod {
	var pod corev1.Pod
	if len(exemplarPodYAML) == 0 {
		panic("exemplar pod empty")
	}
	if err := yaml.UnmarshalStrict(exemplarPodYAML, &pod); err != nil {
		panic(fmt.Sprintf("decode exemplar pod: %v", err))
	}
	return &pod
}

func randomizePod(pod *corev1.Pod, ns string, nodeName string, index int) {
	pod.Namespace = ns
	pod.Name = fmt.Sprintf("pod-%d", index)
	pod.UID = types.UID(fmt.Sprintf("uid-%s-%d", ns, index))
	pod.ResourceVersion = ""
	pod.Spec.NodeName = nodeName
}

func computeCorev1PodKey(obj *corev1.Pod) string {
	return fmt.Sprintf("/pods/%s/%s", obj.Namespace, obj.Name)
}

func RunBenchmarkStoreStats(ctx context.Context, b *testing.B, store storage.Interface) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.Stats(ctx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

const latencyTimestampAnnotation = "watch-latency-timestamp"

type WatchLatencyTracker struct {
	clock                  clock.Clock
	mu                     sync.Mutex
	durations              []time.Duration
	startResourceVersion   uint64
	highestResourceVersion uint64
	startTime              time.Time
}

func NewWatchLatencyTracker(clk clock.Clock) *WatchLatencyTracker {
	return &WatchLatencyTracker{
		clock: clk,
	}
}

func (t *WatchLatencyTracker) Reset(rv uint64, startTime time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.durations = nil
	t.startResourceVersion = rv
	t.highestResourceVersion = rv
	t.startTime = startTime
}

func (t *WatchLatencyTracker) RecordWrite(obj interface{}) {
	metaObj, ok := obj.(metav1.Object)
	if !ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	annotations := metaObj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[latencyTimestampAnnotation] = serializeTimestamp(t.clock.Now())
	metaObj.SetAnnotations(annotations)
}

func (t *WatchLatencyTracker) HandleEvent(eventType watch.EventType, obj interface{}) {
	metaObj, ok := obj.(metav1.Object)
	if !ok {
		return
	}
	rv, err := strconv.ParseUint(metaObj.GetResourceVersion(), 10, 64)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse RV %q: %v", metaObj.GetResourceVersion(), err))
	}
	t.mu.Lock()
	if rv > t.highestResourceVersion {
		t.highestResourceVersion = rv
	}
	t.mu.Unlock()

	if eventType == watch.Deleted || eventType == watch.Error || eventType == watch.Bookmark {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if rv < t.startResourceVersion {
		return
	}
	annotations := metaObj.GetAnnotations()
	if annotations == nil {
		panic(fmt.Sprintf("Annotations nil for obj %s/%s", metaObj.GetNamespace(), metaObj.GetName()))
	}
	tStr, ok := annotations[latencyTimestampAnnotation]
	if !ok {
		panic(fmt.Sprintf("Latency annotation missing for obj %s/%s, annotations: %v", metaObj.GetNamespace(), metaObj.GetName(), annotations))
	}
	writeTime, err := parseTimestamp(tStr)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse timestamp %q: %v", tStr, err))
	}
	if writeTime.Before(t.startTime) {
		return
	}
	delay := t.clock.Since(writeTime)
	t.durations = append(t.durations, delay)
}

func (t *WatchLatencyTracker) WaitForResourceVersion(targetRV uint64, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return wait.PollUntilContextCancel(ctx, 10*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		t.mu.Lock()
		defer t.mu.Unlock()
		return t.highestResourceVersion >= targetRV, nil
	})
}

func (t *WatchLatencyTracker) GetP99Latency() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.durations) < 100 {
		return 0
	}
	slices.Sort(t.durations)
	idx := len(t.durations)*99/100 - 1
	return t.durations[idx]
}

func serializeTimestamp(t time.Time) string {
	return strconv.FormatInt(t.UnixNano(), 10)
}

func parseTimestamp(s string) (time.Time, error) {
	tNano, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, tNano), nil
}

func PopulateInitialResourceVersions(ctx context.Context, b *testing.B, data *BenchmarkData, prefix string, getRevsFunc func(ctx context.Context, prefix string) (map[string]string, error)) {
	keyToRev, err := getRevsFunc(ctx, prefix)
	if err != nil {
		b.Fatalf("Failed to fetch initial resource versions: %v", err)
	}

	actualPrefix := prefix
	if !strings.HasPrefix(actualPrefix, "/") {
		actualPrefix = "/" + actualPrefix
	}
	if !strings.HasSuffix(actualPrefix, "/") {
		actualPrefix = actualPrefix + "/"
	}

	data.PodResourceVersions = make([]atomic.Pointer[string], len(data.PodKeys))
	for i, k := range data.PodKeys {
		etcdKey := actualPrefix + k
		if k[0] == '/' {
			etcdKey = actualPrefix + k[1:]
		}
		if rev, ok := keyToRev[etcdKey]; ok {
			r := rev
			data.PodResourceVersions[i].Store(&r)
		}
	}
}

type etcdStats struct {
	create uint64
	delete uint64
	update uint64
	get    uint64
}

func getEtcdRequestStats() etcdStats {
	stats := etcdStats{}
	metricFamilies, err := legacyregistry.DefaultGatherer.Gather()
	if err != nil {
		return stats
	}
	for _, mf := range metricFamilies {
		if mf.GetName() == "etcd_requests_total" {
			for _, m := range mf.Metric {
				var operation string
				for _, label := range m.Label {
					if label.GetName() == "operation" {
						operation = label.GetValue()
					}
				}
				if m.Counter != nil {
					val := uint64(m.Counter.GetValue())
					switch operation {
					case "create":
						stats.create = val
					case "delete":
						stats.delete = val
					case "update":
						stats.update = val
					case "get":
						stats.get = val
					}
				}
			}
		}
	}
	return stats
}

func SetupPreseededDatabase(b *testing.B, nsCount, totalPods, nodeCount int, data BenchmarkData, seedFn func(ctx context.Context, store storage.Interface) error, createStoreFn func(b testing.TB, dataDir string) (storage.Interface, func())) {
	archivePath := fmt.Sprintf("/tmp/etcd_db_%d_%d_%d.tar.gz", nsCount, totalPods, nodeCount)

	var dataDir string
	var isPreseeded bool
	if _, err := os.Stat(archivePath); err == nil {
		dataDir = b.TempDir()
		cmd := exec.Command("tar", "-xzf", archivePath, "-C", dataDir)
		if err := cmd.Run(); err != nil {
			b.Fatalf("failed to unarchive pre-seeded database: %v", err)
		}
		isPreseeded = true
		os.Setenv("ETCD_DATA_PRESEEDED", "true")
	} else {
		dataDir = b.TempDir()
		os.Setenv("ETCD_DATA_PRESEEDED", "false")
	}
	os.Setenv("BENCHMARK_ETCD_DATA_DIR", dataDir)

	b.Cleanup(func() {
		os.Unsetenv("BENCHMARK_ETCD_DATA_DIR")
		os.Unsetenv("ETCD_DATA_PRESEEDED")
	})

	if !isPreseeded {
		ctx := context.Background()
		store, stopStore := createStoreFn(b, dataDir)

		if err := seedFn(ctx, store); err != nil {
			b.Fatalf("failed to seed database: %v", err)
		}

		stopStore()

		cmd := exec.Command("tar", "-czf", archivePath, "-C", dataDir, ".")
		if out, err := cmd.CombinedOutput(); err != nil {
			b.Fatalf("failed to archive database: %v. Output: %s", err, string(out))
		}
		os.Setenv("ETCD_DATA_PRESEEDED", "true")
	}
}

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

package cacher

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/apis/example"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/cacher/metrics"
	cachertesting "k8s.io/apiserver/pkg/storage/cacher/testing"
	compbasemetrics "k8s.io/component-base/metrics"
)

// BenchmarkSlowWatcherTax measures event delivery latency through the cacher's
// dispatch path to a healthy watcher. It needs wall-clock time; run it with:
//
//	go test ./staging/src/k8s.io/apiserver/pkg/storage/cacher/ -run xxx -bench BenchmarkSlowWatcherTax -benchtime 1x -v
func BenchmarkSlowWatcherTax(b *testing.B) {
	registry := compbasemetrics.NewKubeRegistry()
	// The cacher's own instruments; an unregistered vector records nothing.
	for _, m := range []compbasemetrics.Registerable{metrics.DispatchStageDuration, metrics.TerminatedWatchersCounter} {
		if err := registry.Register(m); err != nil {
			b.Fatal(err)
		}
	}

	scenarios := []slowWatcherScenario{
		{name: "baseline", eventsPerSecond: 100},
	}
	for _, scenario := range scenarios {
		b.Run(scenario.name, func(b *testing.B) {
			var r slowWatcherResult
			for i := 0; i < b.N; i++ {
				r = runSlowWatcherScenario(b, registry, scenario)
			}
			b.ReportMetric(float64(r.percentile(0.5).Microseconds()), "p50-us")
			b.ReportMetric(float64(r.percentile(0.9).Microseconds()), "p90-us")
			b.ReportMetric(float64(r.percentile(0.99).Microseconds()), "p99-us")
			b.ReportMetric(float64(r.percentile(1.0).Microseconds()), "max-us")
			b.ReportMetric(float64(r.slowDispatches), "slow-dispatches")
			b.ReportMetric(float64(r.terminated), "force-closed")
			b.ReportMetric(float64(r.incomingHWM), "incoming-hwm")
			b.Logf("%s: %d of %d dispatches above %v, %d watcher(s) force closed, incoming high water mark %d",
				scenario.name, r.slowDispatches, r.allDispatches, slowDispatchGate, r.terminated, r.incomingHWM)
		})
	}
}

const (
	// slowWatcherScenarioDuration gives 1000 samples at 100 events/s, enough
	// to place p99 on a real sample rather than on the max.
	slowWatcherScenarioDuration = 10 * time.Second
	// slowDispatchGate is a bucket boundary of DispatchStageDuration.
	slowDispatchGate = 5 * time.Millisecond
)

type slowWatcherScenario struct {
	name            string
	eventsPerSecond int
}

type slowWatcherResult struct {
	sortedLatencies []time.Duration
	slowDispatches  uint64
	allDispatches   uint64
	terminated      int
	incomingHWM     int64
}

func (r slowWatcherResult) percentile(p float64) time.Duration {
	return r.sortedLatencies[int(float64(len(r.sortedLatencies)-1)*p)]
}

func runSlowWatcherScenario(b *testing.B, registry compbasemetrics.KubeRegistry, scenario slowWatcherScenario) slowWatcherResult {
	totalEvents := scenario.eventsPerSecond * int(slowWatcherScenarioDuration/time.Second)

	// Sized so that injection never blocks and skews the injection timestamps.
	fw := watch.NewFakeWithChanSize(totalEvents+10, false)
	backing := &cachertesting.MockStorage{
		WatchFn: func(_ context.Context, _ string, _ storage.ListOptions) (watch.Interface, error) {
			return fw, nil
		},
	}
	cacher, _, err := newTestCacher(backing)
	if err != nil {
		b.Fatal(err)
	}
	defer cacher.Stop()

	before := snapshotSlowWatcherMetrics(b, registry)

	healthy, err := cacher.Watch(context.Background(), "/pods/ns", storage.ListOptions{
		ResourceVersion: "100",
		Predicate:       storage.Everything,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer healthy.Stop()

	injected := make([]time.Time, totalEvents)
	stopInjector := make(chan struct{})
	var injector sync.WaitGroup
	injector.Add(1)
	go func() {
		defer injector.Done()
		ticker := time.NewTicker(time.Second / time.Duration(scenario.eventsPerSecond))
		defer ticker.Stop()
		for i := range totalEvents {
			select {
			case <-stopInjector:
				return
			case <-ticker.C:
			}
			injected[i] = time.Now()
			fw.Add(&example.Pod{
				Name:            fmt.Sprintf("pod-%06d", i),
				Namespace:       "ns",
				ResourceVersion: fmt.Sprintf("%d", 101+i),
			})
		}
	}()
	// Runs before cacher.Stop (defers are LIFO): the reflector closes the
	// fake watcher on stop, and fw.Add on a closed watcher panics.
	defer func() {
		close(stopInjector)
		injector.Wait()
	}()

	deadline := time.NewTimer(2 * slowWatcherScenarioDuration)
	defer deadline.Stop()
	latencies := make([]time.Duration, 0, totalEvents)
	for len(latencies) < totalEvents {
		var ev watch.Event
		var ok bool
		select {
		case ev, ok = <-healthy.ResultChan():
		case <-deadline.C:
			b.Fatalf("%s: received %d of %d events within %v", scenario.name, len(latencies), totalEvents, 2*slowWatcherScenarioDuration)
		}
		if !ok {
			b.Fatalf("%s: the healthy watcher was force closed after %d of %d events; the machine is too loaded to drain %d events/s",
				scenario.name, len(latencies), totalEvents, scenario.eventsPerSecond)
		}
		if ev.Type != watch.Added {
			continue
		}
		acc, err := meta.Accessor(ev.Object)
		if err != nil {
			b.Fatal(err)
		}
		var i int
		if n, err := fmt.Sscanf(acc.GetName(), "pod-%06d", &i); n != 1 || err != nil {
			b.Fatalf("unexpected object name %q", acc.GetName())
		}
		latencies = append(latencies, time.Since(injected[i]))
	}
	slices.Sort(latencies)

	injector.Wait()
	cacher.Stop()
	// Deltas over this scenario only: the vectors are global and shared with other tests.
	after := snapshotSlowWatcherMetrics(b, registry)
	return slowWatcherResult{
		sortedLatencies: latencies,
		slowDispatches:  after.slowDispatches - before.slowDispatches,
		allDispatches:   after.allDispatches - before.allDispatches,
		terminated:      after.terminated - before.terminated,
		incomingHWM:     atomic.LoadInt64((*int64)(&cacher.incomingHWM)),
	}
}

type slowWatcherMetrics struct {
	slowDispatches uint64 // stage="total" observations above slowDispatchGate
	allDispatches  uint64 // one per delivered event per watcher
	terminated     int
}

func snapshotSlowWatcherMetrics(b *testing.B, registry compbasemetrics.KubeRegistry) slowWatcherMetrics {
	families, err := registry.Gather()
	if err != nil {
		b.Fatal(err)
	}
	var s slowWatcherMetrics
	for _, mf := range families {
		switch mf.GetName() {
		case "apiserver_watch_events_dispatch_duration_seconds":
			for _, m := range mf.GetMetric() {
				if !hasMetricLabel(m, "stage", "total") {
					continue
				}
				h := m.GetHistogram()
				s.allDispatches += h.GetSampleCount()
				var under uint64
				for _, bucket := range h.GetBucket() {
					if bucket.GetUpperBound() <= slowDispatchGate.Seconds() {
						under = bucket.GetCumulativeCount()
					}
				}
				s.slowDispatches += h.GetSampleCount() - under
			}
		case "apiserver_terminated_watchers_total":
			for _, m := range mf.GetMetric() {
				s.terminated += int(m.GetCounter().GetValue())
			}
		}
	}
	return s
}

func hasMetricLabel(m *dto.Metric, name, value string) bool {
	for _, l := range m.GetLabel() {
		if l.GetName() == name && l.GetValue() == value {
			return true
		}
	}
	return false
}

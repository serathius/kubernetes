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

package metrics

import (
	"fmt"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/testutil"
)

var podsGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

func TestRealFIFO_Metrics(t *testing.T) {
	tests := []struct {
		name           string
		actions        []func(f *cache.RealFIFO)
		expectedMetric int
	}{
		{
			name:           "empty queue has zero metric",
			actions:        []func(f *cache.RealFIFO){},
			expectedMetric: 0,
		},
		{
			name: "Add increases metric",
			actions: []func(f *cache.RealFIFO){
				func(f *cache.RealFIFO) { _ = f.Add(mkFifoObj("foo", 1)) },
			},
			expectedMetric: 1,
		},
		{
			name: "multiple Adds increase metric",
			actions: []func(f *cache.RealFIFO){
				func(f *cache.RealFIFO) { _ = f.Add(mkFifoObj("foo", 1)) },
				func(f *cache.RealFIFO) { _ = f.Add(mkFifoObj("bar", 2)) },
				func(f *cache.RealFIFO) { _ = f.Add(mkFifoObj("baz", 3)) },
			},
			expectedMetric: 3,
		},
		{
			name: "Update increases metric",
			actions: []func(f *cache.RealFIFO){
				func(f *cache.RealFIFO) { _ = f.Add(mkFifoObj("foo", 1)) },
				func(f *cache.RealFIFO) { _ = f.Update(mkFifoObj("foo", 2)) },
			},
			expectedMetric: 2,
		},
		{
			name: "Delete increases metric",
			actions: []func(f *cache.RealFIFO){
				func(f *cache.RealFIFO) { _ = f.Add(mkFifoObj("foo", 1)) },
				func(f *cache.RealFIFO) { _ = f.Delete(mkFifoObj("foo", 2)) },
			},
			expectedMetric: 2,
		},
		{
			name: "Pop decreases metric",
			actions: []func(f *cache.RealFIFO){
				func(f *cache.RealFIFO) { _ = f.Add(mkFifoObj("foo", 1)) },
				func(f *cache.RealFIFO) { _ = f.Add(mkFifoObj("bar", 2)) },
				func(f *cache.RealFIFO) {
					_, _ = f.Pop(func(obj interface{}, isInInitialList bool) error { return nil })
				},
			},
			expectedMetric: 1,
		},
		{
			name: "PopBatch decreases metric",
			actions: []func(f *cache.RealFIFO){
				func(f *cache.RealFIFO) { _ = f.Add(mkFifoObj("foo", 1)) },
				func(f *cache.RealFIFO) { _ = f.Add(mkFifoObj("bar", 2)) },
				func(f *cache.RealFIFO) {
					_ = f.PopBatch(func(deltas []cache.Delta, isInInitialList bool) error { return nil })
				},
			},
			expectedMetric: 0,
		},
		{
			name: "Replace sets metric to new count",
			actions: []func(f *cache.RealFIFO){
				func(f *cache.RealFIFO) { _ = f.Add(mkFifoObj("old", 1)) },
				func(f *cache.RealFIFO) {
					_ = f.Replace([]interface{}{
						mkFifoObj("foo", 1),
						mkFifoObj("bar", 2),
					}, "0")
				},
			},
			// 1 (Add) + 1 (Delete for "old") + 2 (Replace items) = 4
			expectedMetric: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metricsProvider := newTestFIFOMetricsProvider()
			report := func(f float64) {metricsProvider.gauge.WithLabelValues("test-fifo", "", "v1", "pods").Set(f)}
			report(0)
			f := cache.NewRealFIFOWithOptions(cache.RealFIFOOptions{
				KeyFunction:     testFifoObjectKeyFunc,
				KnownObjects:    emptyKnownObjects(),
				ReportLength:    report,
			})

			for _, action := range tt.actions {
				action(f)
			}

			want := fmt.Sprintf(`# HELP informer_queued_items [ALPHA] Number of items currently queued in the FIFO.
# TYPE informer_queued_items gauge
informer_queued_items{group="",name="test-fifo",resource="pods",version="v1"} %d
`, tt.expectedMetric)
			if err := testutil.GatherAndCompare(metricsProvider.registry, strings.NewReader(want), "informer_queued_items"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type testFifoObject struct {
	name string
	val  interface{}
}

func testFifoObjectKeyFunc(obj interface{}) (string, error) {
	return obj.(testFifoObject).name, nil
}

func mkFifoObj(name string, val interface{}) testFifoObject {
	return testFifoObject{name: name, val: val}
}

type literalListerGetter func() []testFifoObject

func (l literalListerGetter) List() []interface{} {
	if l == nil {
		return nil
	}
	result := []interface{}{}
	for _, item := range l() {
		result = append(result, item)
	}
	return result
}

func (l literalListerGetter) ListKeys() []string {
	if l == nil {
		return nil
	}
	result := []string{}
	for _, item := range l() {
		result = append(result, item.name)
	}
	return result
}

func (l literalListerGetter) Get(key string) (interface{}, bool, error) {
	for _, item := range l() {
		if item.name == key {
			return item, true, nil
		}
	}
	return nil, false, nil
}

func (l literalListerGetter) GetByKey(key string) (interface{}, bool, error) {
	return l.Get(key)
}

func emptyKnownObjects() cache.KeyListerGetter {
	return literalListerGetter(
		func() []testFifoObject {
			return []testFifoObject{}
		},
	)
}

// testFIFOMetricsProvider is a test implementation of cache.FIFOMetricsProvider
// that uses real component-base metrics registered with a custom registry.
type testFIFOMetricsProvider struct {
	registry metrics.KubeRegistry
	gauge    *metrics.GaugeVec
}

func newTestFIFOMetricsProvider() *testFIFOMetricsProvider {
	registry := metrics.NewKubeRegistry()
	gauge := metrics.NewGaugeVec(
		&metrics.GaugeOpts{
			Subsystem:      "informer",
			Name:           "queued_items",
			Help:           "Number of items currently queued in the FIFO.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"name", "group", "version", "resource"},
	)
	registry.MustRegister(gauge)
	return &testFIFOMetricsProvider{
		registry: registry,
		gauge:    gauge,
	}
}


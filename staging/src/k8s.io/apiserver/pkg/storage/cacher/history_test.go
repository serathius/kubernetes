/*
Copyright 2021 The Kubernetes Authors.

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
	"fmt"
	"testing"
	"time"

	"k8s.io/client-go/tools/cache"
)

func TestDynamicCache(t *testing.T) {
	tests := []struct {
		name          string
		eventCount    int
		cacheCapacity int
		startIndex    int
		// interval is time duration between adjacent events.
		lowerBoundCapacity int
		upperBoundCapacity int
		interval           time.Duration
		expectCapacity     int
		expectStartIndex   int
	}{
		{
			name:               "[capacity not equals 4*n] events inside DefaultEventFreshDuration cause cache expanding",
			eventCount:         5,
			cacheCapacity:      5,
			lowerBoundCapacity: 5 / 2,
			upperBoundCapacity: 5 * 2,
			interval:           DefaultEventFreshDuration / 6,
			expectCapacity:     10,
			expectStartIndex:   0,
		},
		{
			name:               "[capacity not equals 4*n] events outside DefaultEventFreshDuration without change cache capacity",
			eventCount:         5,
			cacheCapacity:      5,
			lowerBoundCapacity: 5 / 2,
			upperBoundCapacity: 5 * 2,
			interval:           DefaultEventFreshDuration / 4,
			expectCapacity:     5,
			expectStartIndex:   0,
		},
		{
			name:               "[capacity not equals 4*n] quarter of recent events outside DefaultEventFreshDuration cause cache shrinking",
			eventCount:         5,
			cacheCapacity:      5,
			lowerBoundCapacity: 5 / 2,
			upperBoundCapacity: 5 * 2,
			interval:           DefaultEventFreshDuration + time.Second,
			expectCapacity:     2,
			expectStartIndex:   3,
		},
		{
			name:               "[capacity not equals 4*n] quarter of recent events outside DefaultEventFreshDuration cause cache shrinking with given lowerBoundCapacity",
			eventCount:         5,
			cacheCapacity:      5,
			lowerBoundCapacity: 3,
			upperBoundCapacity: 5 * 2,
			interval:           DefaultEventFreshDuration + time.Second,
			expectCapacity:     3,
			expectStartIndex:   2,
		},
		{
			name:               "[capacity not equals 4*n] events inside DefaultEventFreshDuration cause cache expanding with given upperBoundCapacity",
			eventCount:         5,
			cacheCapacity:      5,
			lowerBoundCapacity: 5 / 2,
			upperBoundCapacity: 8,
			interval:           DefaultEventFreshDuration / 6,
			expectCapacity:     8,
			expectStartIndex:   0,
		},
		{
			name:               "[capacity not equals 4*n] [startIndex not equal 0] events inside DefaultEventFreshDuration cause cache expanding",
			eventCount:         5,
			cacheCapacity:      5,
			startIndex:         3,
			lowerBoundCapacity: 5 / 2,
			upperBoundCapacity: 5 * 2,
			interval:           DefaultEventFreshDuration / 6,
			expectCapacity:     10,
			expectStartIndex:   3,
		},
		{
			name:               "[capacity not equals 4*n] [startIndex not equal 0] events outside DefaultEventFreshDuration without change cache capacity",
			eventCount:         5,
			cacheCapacity:      5,
			startIndex:         3,
			lowerBoundCapacity: 5 / 2,
			upperBoundCapacity: 5 * 2,
			interval:           DefaultEventFreshDuration / 4,
			expectCapacity:     5,
			expectStartIndex:   3,
		},
		{
			name:               "[capacity not equals 4*n] [startIndex not equal 0] quarter of recent events outside DefaultEventFreshDuration cause cache shrinking",
			eventCount:         5,
			cacheCapacity:      5,
			startIndex:         3,
			lowerBoundCapacity: 5 / 2,
			upperBoundCapacity: 5 * 2,
			interval:           DefaultEventFreshDuration + time.Second,
			expectCapacity:     2,
			expectStartIndex:   6,
		},
		{
			name:               "[capacity not equals 4*n] [startIndex not equal 0] quarter of recent events outside DefaultEventFreshDuration cause cache shrinking with given lowerBoundCapacity",
			eventCount:         5,
			cacheCapacity:      5,
			startIndex:         3,
			lowerBoundCapacity: 3,
			upperBoundCapacity: 5 * 2,
			interval:           DefaultEventFreshDuration + time.Second,
			expectCapacity:     3,
			expectStartIndex:   5,
		},
		{
			name:               "[capacity not equals 4*n] [startIndex not equal 0] events inside DefaultEventFreshDuration cause cache expanding with given upperBoundCapacity",
			eventCount:         5,
			cacheCapacity:      5,
			startIndex:         3,
			lowerBoundCapacity: 5 / 2,
			upperBoundCapacity: 8,
			interval:           DefaultEventFreshDuration / 6,
			expectCapacity:     8,
			expectStartIndex:   3,
		},
		{
			name:               "[capacity equals 4*n] events inside DefaultEventFreshDuration cause cache expanding",
			eventCount:         8,
			cacheCapacity:      8,
			lowerBoundCapacity: 8 / 2,
			upperBoundCapacity: 8 * 2,
			interval:           DefaultEventFreshDuration / 9,
			expectCapacity:     16,
			expectStartIndex:   0,
		},
		{
			name:               "[capacity equals 4*n] events outside DefaultEventFreshDuration without change cache capacity",
			eventCount:         8,
			cacheCapacity:      8,
			lowerBoundCapacity: 8 / 2,
			upperBoundCapacity: 8 * 2,
			interval:           DefaultEventFreshDuration / 8,
			expectCapacity:     8,
			expectStartIndex:   0,
		},
		{
			name:               "[capacity equals 4*n] quarter of recent events outside DefaultEventFreshDuration cause cache shrinking",
			eventCount:         8,
			cacheCapacity:      8,
			lowerBoundCapacity: 8 / 2,
			upperBoundCapacity: 8 * 2,
			interval:           DefaultEventFreshDuration/2 + time.Second,
			expectCapacity:     4,
			expectStartIndex:   4,
		},
		{
			name:               "[capacity equals 4*n] quarter of recent events outside DefaultEventFreshDuration cause cache shrinking with given lowerBoundCapacity",
			eventCount:         8,
			cacheCapacity:      8,
			lowerBoundCapacity: 7,
			upperBoundCapacity: 8 * 2,
			interval:           DefaultEventFreshDuration/2 + time.Second,
			expectCapacity:     7,
			expectStartIndex:   1,
		},
		{
			name:               "[capacity equals 4*n] events inside DefaultEventFreshDuration cause cache expanding with given upperBoundCapacity",
			eventCount:         8,
			cacheCapacity:      8,
			lowerBoundCapacity: 8 / 2,
			upperBoundCapacity: 10,
			interval:           DefaultEventFreshDuration / 9,
			expectCapacity:     10,
			expectStartIndex:   0,
		},
		{
			name:               "[capacity equals 4*n] [startIndex not equal 0] events inside DefaultEventFreshDuration cause cache expanding",
			eventCount:         8,
			cacheCapacity:      8,
			startIndex:         3,
			lowerBoundCapacity: 8 / 2,
			upperBoundCapacity: 8 * 2,
			interval:           DefaultEventFreshDuration / 9,
			expectCapacity:     16,
			expectStartIndex:   3,
		},
		{
			name:               "[capacity equals 4*n] [startIndex not equal 0] events outside DefaultEventFreshDuration without change cache capacity",
			eventCount:         8,
			cacheCapacity:      8,
			startIndex:         3,
			lowerBoundCapacity: 8 / 2,
			upperBoundCapacity: 8 * 2,
			interval:           DefaultEventFreshDuration / 8,
			expectCapacity:     8,
			expectStartIndex:   3,
		},
		{
			name:               "[capacity equals 4*n] [startIndex not equal 0] quarter of recent events outside DefaultEventFreshDuration cause cache shrinking",
			eventCount:         8,
			cacheCapacity:      8,
			startIndex:         3,
			lowerBoundCapacity: 8 / 2,
			upperBoundCapacity: 8 * 2,
			interval:           DefaultEventFreshDuration/2 + time.Second,
			expectCapacity:     4,
			expectStartIndex:   7,
		},
		{
			name:               "[capacity equals 4*n] [startIndex not equal 0] quarter of recent events outside DefaultEventFreshDuration cause cache shrinking with given lowerBoundCapacity",
			eventCount:         8,
			cacheCapacity:      8,
			startIndex:         3,
			lowerBoundCapacity: 7,
			upperBoundCapacity: 8 * 2,
			interval:           DefaultEventFreshDuration/2 + time.Second,
			expectCapacity:     7,
			expectStartIndex:   4,
		},
		{
			name:               "[capacity equals 4*n] [startIndex not equal 0] events inside DefaultEventFreshDuration cause cache expanding with given upperBoundCapacity",
			eventCount:         8,
			cacheCapacity:      8,
			startIndex:         3,
			lowerBoundCapacity: 8 / 2,
			upperBoundCapacity: 10,
			interval:           DefaultEventFreshDuration / 9,
			expectCapacity:     10,
			expectStartIndex:   3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newTestWatchCache(test.cacheCapacity, DefaultEventFreshDuration, &cache.Indexers{})
			defer store.Stop()
			store.history.cache = make([]*watchCacheEvent, test.cacheCapacity)
			store.history.startIndex = test.startIndex
			store.history.lowerBoundCapacity = test.lowerBoundCapacity
			store.history.upperBoundCapacity = test.upperBoundCapacity
			loadEventWithDuration(store, test.eventCount, test.interval)
			nextInterval := store.config.clock.Now().Add(time.Duration(test.interval.Nanoseconds() * int64(test.eventCount)))
			store.history.resizeCacheLocked(nextInterval)
			if store.history.capacity != test.expectCapacity {
				t.Errorf("expect capacity %d, but get %d", test.expectCapacity, store.history.capacity)
			}

			// check cache's startIndex, endIndex and all elements.
			if store.history.startIndex != test.expectStartIndex {
				t.Errorf("expect startIndex %d, but get %d", test.expectStartIndex, store.history.startIndex)
			}
			if store.history.endIndex != test.startIndex+test.eventCount {
				t.Errorf("expect endIndex %d get %d", test.startIndex+test.eventCount, store.history.endIndex)
			}
			if !checkCacheElements(store) {
				t.Errorf("some elements locations in cache is wrong")
			}
		})
	}
}

func loadEventWithDuration(cache *testWatchCache, count int, interval time.Duration) {
	for i := 0; i < count; i++ {
		event := &watchCacheEvent{
			Key:        fmt.Sprintf("event-%d", i+cache.history.startIndex),
			RecordTime: cache.config.clock.Now().Add(time.Duration(interval.Nanoseconds() * int64(i))),
		}
		cache.history.cache[(i+cache.history.startIndex)%cache.history.capacity] = event
	}
	cache.history.endIndex = cache.history.startIndex + count
}

func checkCacheElements(cache *testWatchCache) bool {
	for i := cache.history.startIndex; i < cache.history.endIndex; i++ {
		location := i % cache.history.capacity
		if cache.history.cache[location].Key != fmt.Sprintf("event-%d", i) {
			return false
		}
	}
	return true
}

func TestCapacityUpperBound(t *testing.T) {
	testCases := []struct {
		name               string
		eventFreshDuration time.Duration
		expected           int
	}{
		{
			name:               "default eventFreshDuration",
			eventFreshDuration: DefaultEventFreshDuration, // 75s
			expected:           defaultUpperBoundCapacity, // 100 * 1024
		},
		{
			name:               "lower eventFreshDuration, capacity limit unchanged",
			eventFreshDuration: 45 * time.Second,          // 45s
			expected:           defaultUpperBoundCapacity, // 100 * 1024
		},
		{
			name:               "higher eventFreshDuration, capacity limit scaled up",
			eventFreshDuration: 4 * DefaultEventFreshDuration, // 4 * 75s
			expected:           4 * defaultUpperBoundCapacity, // 4 * 100 * 1024
		},
		{
			name:               "higher eventFreshDuration, capacity limit scaled and rounded up",
			eventFreshDuration: 3 * DefaultEventFreshDuration, // 3 * 75s
			expected:           4 * defaultUpperBoundCapacity, // 4 * 100 * 1024
		},
		{
			name:               "higher eventFreshDuration, capacity limit scaled up and capped",
			eventFreshDuration: DefaultEventFreshDuration << 20, // 2^20 * 75s
			expected:           defaultUpperBoundCapacity << 14, // 2^14 * 100 * 1024
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			capacity := capacityUpperBound(test.eventFreshDuration)
			if test.expected != capacity {
				t.Errorf("expected %v, got %v", test.expected, capacity)
			}
		})
	}
}

func BenchmarkWatchCache_updateCache(b *testing.B) {
	store := newTestWatchCache(defaultUpperBoundCapacity, DefaultEventFreshDuration, &cache.Indexers{})
	defer store.Stop()
	store.history.cache = store.history.cache[:0]
	store.history.upperBoundCapacity = defaultUpperBoundCapacity
	loadEventWithDuration(store, defaultUpperBoundCapacity, 0)
	add := &watchCacheEvent{
		Key:        fmt.Sprintf("event-%d", defaultUpperBoundCapacity),
		RecordTime: store.config.clock.Now(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.history.updateCache(add)
	}
}

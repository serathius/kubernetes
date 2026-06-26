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

package history

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/storage/cacher/metrics"
	"k8s.io/klog/v2"
)

const (
	// DefaultEventFreshDuration is the default time duration of events
	// we want to keep.
	DefaultEventFreshDuration = 75 * time.Second

	// DefaultLowerBoundCapacity is a default value for event cache capacity's lower bound.
	// TODO: Figure out, to what value we can decreased it.
	DefaultLowerBoundCapacity = 100

	// DefaultUpperBoundCapacity should be able to keep the required history.
	DefaultUpperBoundCapacity = 100 * 1024
)

func NewHistory(groupResource schema.GroupResource, eventFreshDuration time.Duration) *History {
	h := &History{
		groupResource:      groupResource,
		capacity:           DefaultLowerBoundCapacity,
		cache:              make([]*Event, DefaultLowerBoundCapacity),
		lowerBoundCapacity: DefaultLowerBoundCapacity,
		upperBoundCapacity: CapacityUpperBound(eventFreshDuration),
		startIndex:         0,
		endIndex:           0,
		eventFreshDuration: eventFreshDuration,
	}
	metrics.WatchCacheCapacity.WithLabelValues(groupResource.Group, groupResource.Resource).Set(float64(h.capacity))
	return h
}

// CapacityUpperBound denotes the maximum possible capacity of the watch cache
// to which it can resize.
func CapacityUpperBound(eventFreshDuration time.Duration) int {
	if eventFreshDuration <= DefaultEventFreshDuration {
		return DefaultUpperBoundCapacity
	}
	// eventFreshDuration determines how long the watch events are supposed
	// to be stored in the watch cache.
	// In very high churn situations, there is a need to store more events
	// in the watch cache, hence it would have to be upsized accordingly.
	// Because of that, for larger values of eventFreshDuration, we set the
	// upper bound of the watch cache's capacity proportionally to the ratio
	// between eventFreshDuration and DefaultEventFreshDuration.
	// Given that the watch cache size can only double, we round up that
	// proportion to the next power of two.
	exponent := int(math.Ceil((math.Log2(eventFreshDuration.Seconds() / DefaultEventFreshDuration.Seconds()))))
	if maxExponent := int(math.Floor((math.Log2(math.MaxInt32 / DefaultUpperBoundCapacity)))); exponent > maxExponent {
		// Making sure that the capacity's upper bound fits in a 32-bit integer.
		exponent = maxExponent
		klog.Warningf("Capping watch cache capacity upper bound to %v", DefaultUpperBoundCapacity<<exponent)
	}
	return DefaultUpperBoundCapacity << exponent
}

type History struct {
	groupResource schema.GroupResource

	// Maximum size of history window.
	capacity int

	// upper bound of capacity since event cache has a dynamic size.
	upperBoundCapacity int

	// lower bound of capacity since event cache has a dynamic size.
	lowerBoundCapacity int

	// cache is used a cyclic buffer - the "current" contents of it are
	// stored in [start_index%capacity, end_index%capacity) - so the
	// "current" contents have exactly end_index-start_index items.
	cache      []*Event
	startIndex int
	endIndex   int
	// removedEventSinceRelist holds the information whether any of the events
	// were already removed from the `cache` cyclic buffer since the last relist
	removedEventSinceRelist bool

	// eventFreshDuration defines the minimum watch history watchcache will store.
	eventFreshDuration time.Duration
}

// Assumes that lock is already held for write.
func (w *History) UpdateCache(event *Event) {
	w.resizeCacheLocked(event.RecordTime)
	if w.IsCacheFullLocked() {
		// Cache is full - remove the oldest element.
		w.startIndex++
		w.removedEventSinceRelist = true
	}
	w.cache[w.endIndex%w.capacity] = event
	w.endIndex++
}

// resizeCacheLocked resizes the cache if necessary:
// - increases capacity by 2x if cache is full and all cached events occurred within last eventFreshDuration.
// - decreases capacity by 2x when recent quarter of events occurred outside of eventFreshDuration(protect watchCache from flapping).
func (w *History) resizeCacheLocked(eventTime time.Time) {
	if w.IsCacheFullLocked() && eventTime.Sub(w.cache[w.startIndex%w.capacity].RecordTime) < w.eventFreshDuration {
		capacity := min(w.capacity*2, w.upperBoundCapacity)
		if capacity > w.capacity {
			w.doCacheResizeLocked(capacity)
		}
		return
	}
	if w.IsCacheFullLocked() && eventTime.Sub(w.cache[(w.endIndex-w.capacity/4)%w.capacity].RecordTime) > w.eventFreshDuration {
		capacity := max(w.capacity/2, w.lowerBoundCapacity)
		if capacity < w.capacity {
			w.doCacheResizeLocked(capacity)
		}
		return
	}
}

// IsCacheFullLocked used to judge whether Event is full.
// Assumes that lock is already held for write.
func (w *History) IsCacheFullLocked() bool {
	return w.endIndex == w.startIndex+w.capacity
}

// doCacheResizeLocked resize watchCache's event array with different capacity.
// Assumes that lock is already held for write.
func (w *History) doCacheResizeLocked(capacity int) {
	newCache := make([]*Event, capacity)
	if capacity < w.capacity {
		// adjust startIndex if cache capacity shrink.
		w.startIndex = w.endIndex - capacity
	}
	for i := w.startIndex; i < w.endIndex; i++ {
		newCache[i%capacity] = w.cache[i%w.capacity]
	}
	w.cache = newCache
	metrics.RecordsWatchCacheCapacityChange(w.groupResource, w.capacity, capacity)
	w.capacity = capacity
}

// IsIndexValidLocked checks if a given index is still valid.
// This assumes that the lock is held.
func (w *History) IsIndexValidLocked(index int) bool {
	return index >= w.startIndex
}

// ResetLocked empties the cyclic buffer, ensuring startIndex doesn't decrease.
// Assumes that lock is already held for write.
func (w *History) ResetLocked() {
	w.startIndex = w.endIndex
	w.removedEventSinceRelist = false
	clear(w.cache)
}

const (
	// minWatchChanSize is the min size of channels used by the watch.
	// We keep that set to 10 for "backward compatibility" until we
	// convince ourselves based on some metrics that decreasing is safe.
	minWatchChanSize = 10
	// maxWatchChanSizeWithIndexAndTrigger is the max size of the channel
	// used by the watch using the index and trigger selector.
	maxWatchChanSizeWithIndexAndTrigger = 10
	// maxWatchChanSizeWithIndexWithoutTrigger is the max size of the channel
	// used by the watch using the index but without triggering selector.
	// We keep that set to 1000 for "backward compatibility", until we
	// convinced ourselves based on some metrics that decreasing is safe.
	maxWatchChanSizeWithIndexWithoutTrigger = 1000
	// maxWatchChanSizeWithoutIndex is the max size of the channel
	// used by the watch not using the index.
	maxWatchChanSizeWithoutIndex = 100
)

func (w *History) SuggestedWatchChannelSize(indexExists, triggerUsed bool) int {
	// To estimate the channel size we use a heuristic that a channel
	// should roughly be able to keep one second of history.
	// We don't have an exact data, but given we store updates from
	// the last <eventFreshDuration>, we approach it by dividing the
	// capacity by the length of the history window.
	chanSize := int(math.Ceil(float64(w.capacity) / w.eventFreshDuration.Seconds()))

	// Finally we adjust the size to avoid ending with too low or
	// to large values.
	chanSize = max(chanSize, minWatchChanSize)
	var maxChanSize int
	switch {
	case indexExists && triggerUsed:
		maxChanSize = maxWatchChanSizeWithIndexAndTrigger
	case indexExists && !triggerUsed:
		maxChanSize = maxWatchChanSizeWithIndexWithoutTrigger
	case !indexExists:
		maxChanSize = maxWatchChanSizeWithoutIndex
	}
	return min(chanSize, maxChanSize)
}

// GetIntervalLocked returns a Interval that can be used to
// retrieve events since a certain resourceVersion. This function assumes to
// be called under the lock.
func (w *History) GetIntervalLocked(resourceVersion uint64, listResourceVersion uint64, indexValidator IndexValidator, locker sync.Locker) (*Interval, error) {
	size := w.endIndex - w.startIndex
	var oldest uint64
	switch {
	case listResourceVersion > 0 && !w.removedEventSinceRelist:
		// If no event was removed from the buffer since last relist, the oldest watch
		// event we can deliver is one greater than the resource version of the list.
		oldest = listResourceVersion + 1
	case size > 0:
		// If the previous condition is not satisfied: either some event was already
		// removed from the buffer or we've never completed a list (the latter can
		// only happen in unit tests that populate the buffer without performing
		// list/replace operations), the oldest watch event we can deliver is the first
		// one in the buffer.
		oldest = w.cache[w.startIndex%w.capacity].ResourceVersion
	default:
		return nil, fmt.Errorf("watch cache isn't correctly initialized")
	}

	if resourceVersion < oldest-1 {
		return nil, errors.NewResourceExpired(fmt.Sprintf("too old resource version: %d (%d)", resourceVersion, oldest-1))
	}

	// Binary search the smallest index at which resourceVersion is greater than the given one.
	f := func(i int) bool {
		return w.cache[(w.startIndex+i)%w.capacity].ResourceVersion > resourceVersion
	}
	first := sort.Search(size, f)
	indexerFunc := func(i int) *Event {
		return w.cache[i%w.capacity]
	}
	ci := NewCacheInterval(w.startIndex+first, w.endIndex, indexerFunc, indexValidator, resourceVersion, locker)
	return ci, nil
}

// OldestResourceVersionLocked returns the resource version of the oldest event in the cyclic buffer.
func (w *History) OldestResourceVersionLocked() uint64 {
	return w.cache[w.startIndex%w.capacity].ResourceVersion
}

// Capacity returns the current capacity of the event history cache.
func (w *History) Capacity() int {
	return w.capacity
}

// StartIndex returns the start index of the cyclic buffer.
func (w *History) StartIndex() int {
	return w.startIndex
}

// EndIndex returns the end index of the cyclic buffer.
func (w *History) EndIndex() int {
	return w.endIndex
}

// Compact compacts the history by removing all events with ResourceVersion <= rv.
// This is used for testing compaction behavior.
func (w *History) Compact(rv uint64) {
	for w.startIndex < w.endIndex {
		index := w.startIndex % w.capacity
		if w.cache[index].ResourceVersion > rv {
			break
		}
		w.startIndex++
	}
}

// SetCapacity resets the capacity and allocates a new cache buffer.
// This is used for testing.
func (w *History) SetCapacity(capacity int) {
	w.capacity = capacity
	w.cache = make([]*Event, capacity)
}

// SetBounds sets the lower and upper capacity bounds.
// This is used for testing.
func (w *History) SetBounds(lowerBoundCapacity, upperBoundCapacity int) {
	w.lowerBoundCapacity = lowerBoundCapacity
	w.upperBoundCapacity = upperBoundCapacity
}

// SetStartIndex sets the start index of the cyclic buffer.
// This is used for testing.
func (w *History) SetStartIndex(startIndex int) {
	w.startIndex = startIndex
}

// SetEndIndex sets the end index of the cyclic buffer.
// This is used for testing.
func (w *History) SetEndIndex(endIndex int) {
	w.endIndex = endIndex
}

// SetEvent sets the event at the given index in the cyclic buffer.
// This is used for testing.
func (w *History) SetEvent(index int, event *Event) {
	w.cache[index%w.capacity] = event
}

// Clear clears the history cache.
// This is used for testing.
func (w *History) Clear() {
	w.cache = w.cache[:0]
}

// ResizeCache resizes the cache if necessary.
// This is used for testing.
func (w *History) ResizeCache(eventTime time.Time) {
	w.resizeCacheLocked(eventTime)
}

// GetEvent returns the event at the given index in the cyclic buffer.
// This is used for testing.
func (w *History) GetEvent(index int) *Event {
	return w.cache[index%w.capacity]
}

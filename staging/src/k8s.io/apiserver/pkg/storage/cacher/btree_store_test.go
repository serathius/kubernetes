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

package cacher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
)

func TestStoreListOrdered(t *testing.T) {
	store := newThreadedBtreeStoreIndexer(nil, 32)
	assert.NoError(t, store.Add(testStorageElement("foo3", "bar3", 1)))
	assert.NoError(t, store.Add(testStorageElement("foo1", "bar2", 2)))
	assert.NoError(t, store.Add(testStorageElement("foo2", "bar1", 3)))
	assert.Equal(t, []interface{}{
		testStorageElement("foo1", "bar2", 2),
		testStorageElement("foo2", "bar1", 3),
		testStorageElement("foo3", "bar3", 1),
	}, store.List())
}

func TestStoreListPrefix(t *testing.T) {
	store := newThreadedBtreeStoreIndexer(nil, 32)
	assert.NoError(t, store.Add(testStorageElement("foo3", "bar3", 1)))
	assert.NoError(t, store.Add(testStorageElement("foo1", "bar2", 2)))
	assert.NoError(t, store.Add(testStorageElement("foo2", "bar1", 3)))
	assert.NoError(t, store.Add(testStorageElement("bar", "baz", 4)))

	items, hasMore := store.ListPrefix("foo", "", 0)
	assert.False(t, hasMore)
	assert.Equal(t, []interface{}{
		testStorageElement("foo1", "bar2", 2),
		testStorageElement("foo2", "bar1", 3),
		testStorageElement("foo3", "bar3", 1),
	}, items)

	items, hasMore = store.ListPrefix("foo2", "", 0)
	assert.False(t, hasMore)
	assert.Equal(t, []interface{}{
		testStorageElement("foo2", "bar1", 3),
	}, items)

	items, hasMore = store.ListPrefix("foo", "", 1)
	assert.True(t, hasMore)
	assert.Equal(t, []interface{}{
		testStorageElement("foo1", "bar2", 2),
	}, items)

	items, hasMore = store.ListPrefix("foo", "foo1\x00", 1)
	assert.True(t, hasMore)
	assert.Equal(t, []interface{}{
		testStorageElement("foo2", "bar1", 3),
	}, items)

	items, hasMore = store.ListPrefix("foo", "foo2\x00", 1)
	assert.False(t, hasMore)
	assert.Equal(t, []interface{}{
		testStorageElement("foo3", "bar3", 1),
	}, items)

	items, hasMore = store.ListPrefix("bar", "", 0)
	assert.False(t, hasMore)
	assert.Equal(t, []interface{}{
		testStorageElement("bar", "baz", 4),
	}, items)
}

func TestStoreSingleKey(t *testing.T) {
	store := newThreadedBtreeStoreIndexer(nil, 32)
	assertStoreEmpty(t, store, "foo")

	require.NoError(t, store.Add(testStorageElement("foo", "bar", 1)))
	assertStoreSingleKey(t, store, "foo", "bar", 1)

	require.NoError(t, store.Update(testStorageElement("foo", "baz", 2)))
	assertStoreSingleKey(t, store, "foo", "baz", 2)

	require.NoError(t, store.Update(testStorageElement("foo", "baz", 3)))
	assertStoreSingleKey(t, store, "foo", "baz", 3)

	require.NoError(t, store.Replace([]interface{}{testStorageElement("foo", "bar", 4)}, ""))
	assertStoreSingleKey(t, store, "foo", "bar", 4)

	require.NoError(t, store.Delete(testStorageElement("foo", "", 0)))
	assertStoreEmpty(t, store, "foo")

	require.Error(t, store.Delete(testStorageElement("foo", "", 0)))
}

func TestStoreIndexerSingleKey(t *testing.T) {
	store := newThreadedBtreeStoreIndexer(testStoreIndexers(), 32)
	items, err := store.ByIndex("by_val", "bar")
	require.NoError(t, err)
	assert.Empty(t, items)

	require.NoError(t, store.Add(testStorageElement("foo", "bar", 1)))
	items, err = store.ByIndex("by_val", "bar")
	require.NoError(t, err)
	assert.Equal(t, []interface{}{
		testStorageElement("foo", "bar", 1),
	}, items)

	require.NoError(t, store.Update(testStorageElement("foo", "baz", 2)))
	items, err = store.ByIndex("by_val", "bar")
	require.NoError(t, err)
	assert.Empty(t, items)
	items, err = store.ByIndex("by_val", "baz")
	require.NoError(t, err)
	assert.Equal(t, []interface{}{
		testStorageElement("foo", "baz", 2),
	}, items)

	require.NoError(t, store.Update(testStorageElement("foo", "baz", 3)))
	items, err = store.ByIndex("by_val", "bar")
	require.NoError(t, err)
	assert.Empty(t, items)
	items, err = store.ByIndex("by_val", "baz")
	require.NoError(t, err)
	assert.Equal(t, []interface{}{
		testStorageElement("foo", "baz", 3),
	}, items)

	require.NoError(t, store.Replace([]interface{}{
		testStorageElement("foo", "bar", 4),
	}, ""))
	items, err = store.ByIndex("by_val", "bar")
	require.NoError(t, err)
	assert.Equal(t, []interface{}{
		testStorageElement("foo", "bar", 4),
	}, items)
	items, err = store.ByIndex("by_val", "baz")
	require.NoError(t, err)
	assert.Empty(t, items)

	require.NoError(t, store.Delete(testStorageElement("foo", "", 0)))
	items, err = store.ByIndex("by_val", "baz")
	require.NoError(t, err)
	assert.Empty(t, items)

	require.Error(t, store.Delete(testStorageElement("foo", "", 0)))
}

func assertStoreEmpty(t *testing.T, store *threadedStoreIndexer, nonExistingKey string) {
	item, ok, err := store.Get(testStorageElement(nonExistingKey, "", 0))
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, item)

	item, ok, err = store.GetByKey(nonExistingKey)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, item)

	items := store.List()
	assert.Empty(t, items)

	items, _ = store.ListPrefix("", "", 0)
	assert.Empty(t, items)
}

func assertStoreSingleKey(t *testing.T, store *threadedStoreIndexer, expectKey, expectValue string, expectRV int) {
	item, ok, err := store.Get(testStorageElement(expectKey, "", expectRV))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, expectValue, item.(*storeElement).Object.(fakeObj).value)

	item, ok, err = store.GetByKey(expectKey)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, expectValue, item.(*storeElement).Object.(fakeObj).value)

	items := store.List()
	assert.Equal(t, []interface{}{testStorageElement(expectKey, expectValue, expectRV)}, items)

	items, _ = store.ListPrefix("", "", 0)
	assert.Equal(t, []interface{}{testStorageElement(expectKey, expectValue, expectRV)}, items)
}

func testStorageElement(key, value string, rv int) *storeElement {
	return &storeElement{Key: key, Object: fakeObj{value: value, rv: rv}}
}

type fakeObj struct {
	value string
	rv    int
}

func (f fakeObj) GetObjectKind() schema.ObjectKind {
	panic("implement me")
}

func (f fakeObj) DeepCopyObject() runtime.Object {
	panic("implement me")
}

var _ runtime.Object = (*fakeObj)(nil)

func testStoreIndexFunc(obj interface{}) ([]string, error) {
	return []string{obj.(*storeElement).Object.(fakeObj).value}, nil
}

func testStoreIndexers() cache.Indexers {
	indexers := cache.Indexers{}
	indexers["by_val"] = testStoreIndexFunc
	return indexers
}

func TestContinueCacheCleanup(t *testing.T) {
	cache := newContinueCache()
	cache.Set(20, fakeOrderedLister{})
	cache.Set(30, fakeOrderedLister{})
	cache.Set(40, fakeOrderedLister{})
	assert.Len(t, cache.cache, 3)
	assert.Equal(t, 3, cache.revisions.Len())
	_, _, ok := cache.FindEqualOrLower(19)
	assert.False(t, ok)
	_, rv, ok := cache.FindEqualOrLower(20)
	assert.True(t, ok)
	assert.Equal(t, 20, int(rv))
	_, rv, ok = cache.FindEqualOrLower(21)
	assert.True(t, ok)
	assert.Equal(t, 20, int(rv))
	_, rv, ok = cache.FindEqualOrLower(32)
	assert.True(t, ok)
	assert.Equal(t, 30, int(rv))
	_, rv, ok = cache.FindEqualOrLower(43)
	assert.True(t, ok)
	assert.Equal(t, 40, int(rv))

	cache.Cleanup(20)
	assert.Len(t, cache.cache, 2)
	assert.Equal(t, 2, cache.revisions.Len())
	_, _, ok = cache.FindEqualOrLower(21)
	assert.False(t, ok)

	cache.Set(20, fakeOrderedLister{})
	cache.Set(20, fakeOrderedLister{})
	assert.Len(t, cache.cache, 3)
	assert.Equal(t, 3, cache.revisions.Len())
	_, rv, ok = cache.FindEqualOrLower(21)
	assert.True(t, ok)
	assert.Equal(t, 20, int(rv))
	cache.Cleanup(40)
	assert.Len(t, cache.cache, 0)
	assert.Equal(t, 0, cache.revisions.Len())
	_, _, ok = cache.FindEqualOrLower(43)
	assert.False(t, ok)
}

type fakeOrderedLister struct{}

func (f fakeOrderedLister) Add(obj interface{}) error    { return nil }
func (f fakeOrderedLister) Update(obj interface{}) error { return nil }
func (f fakeOrderedLister) Delete(obj interface{}) error { return nil }
func (f fakeOrderedLister) Clone() orderedStore          { return f }
func (f fakeOrderedLister) ListPrefix(prefixKey, continueKey string, limit int) ([]interface{}, bool) {
	return nil, false
}
func (f fakeOrderedLister) Count(prefixKey, continueKey string) int { return 0 }

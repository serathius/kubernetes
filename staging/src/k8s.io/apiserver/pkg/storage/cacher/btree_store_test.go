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
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestContinueCacheCleanup(t *testing.T) {
	cache := newContinueCache()
	cache.Set(20, fakeIndexer{})
	cache.Set(30, fakeIndexer{})
	cache.Set(40, fakeIndexer{})
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

	cache.Set(20, fakeIndexer{})
	cache.Set(20, fakeIndexer{})
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

type fakeIndexer struct{}

func (f fakeIndexer) Add(obj interface{}) error    { return nil }
func (f fakeIndexer) Update(obj interface{}) error { return nil }
func (f fakeIndexer) Delete(obj interface{}) error { return nil }
func (f fakeIndexer) List() []interface{}          { return nil }
func (f fakeIndexer) ListKeys() []string           { return nil }
func (f fakeIndexer) Get(obj interface{}) (item interface{}, exists bool, err error) {
	return nil, false, nil
}
func (f fakeIndexer) GetByKey(key string) (item interface{}, exists bool, err error) {
	return nil, false, nil
}
func (f fakeIndexer) Replace(i []interface{}, s string) error                     { return nil }
func (f fakeIndexer) Resync() error                                               { return nil }
func (f fakeIndexer) ByIndex(indexName, indexValue string) ([]interface{}, error) { return nil, nil }
func (f fakeIndexer) Clone() btreeIndexer                                         { return f }
func (f fakeIndexer) LimitPrefixRead(limit int, prefixKey, continueKey string) ([]interface{}, bool) {
	return nil, false
}
func (f fakeIndexer) Count(prefixKey, continueKey string) int { return 0 }

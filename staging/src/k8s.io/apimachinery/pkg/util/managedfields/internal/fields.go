/*
Copyright 2018 The Kubernetes Authors.

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

package internal

import (
	"hash/maphash"
	"sync/atomic"
	"unique"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/structured-merge-diff/v7/fieldpath"
)

const fieldSetCacheSize = 4096

type cachedFieldSet struct {
	handle unique.Handle[string]
	set    *fieldpath.Set
}

var (
	fieldSetCacheSeed = maphash.MakeSeed()
	fieldSetCache     [fieldSetCacheSize]atomic.Pointer[cachedFieldSet]
)

// EmptyFields represents a set with no paths
// It looks like metav1.Fields{Raw: []byte("{}")}
var EmptyFields = func() metav1.FieldsV1 {
	f, err := SetToFields(*fieldpath.NewSet())
	if err != nil {
		panic("should never happen")
	}
	return f
}()

// fieldsToSetRef returns an immutable *fieldpath.Set decoded from f, reusing the cached
// trie when f's canonical handle has already been parsed.
//
// Sharing *fieldpath.Set across callers and objects is safe because sigs.k8s.io/structured-merge-diff
// set operations (Union, Difference, Intersection, ReconcileFieldSetWithSchema, EnsureNamedFieldsAreMembers)
// never mutate a Set in place; they always allocate a new Set when the result differs.
func fieldsToSetRef(f metav1.FieldsV1) (*fieldpath.Set, error) {
	handle := f.UniqueHandle()
	if handle != (unique.Handle[string]{}) {
		idx := maphash.Comparable(fieldSetCacheSeed, handle) & (fieldSetCacheSize - 1)
		if cached := fieldSetCache[idx].Load(); cached != nil && cached.handle == handle {
			return cached.set, nil
		}
		var s fieldpath.Set
		if err := s.FromJSON(f.GetRawReader()); err != nil {
			return nil, err
		}
		fieldSetCache[idx].Store(&cachedFieldSet{handle: handle, set: &s})
		return &s, nil
	}
	var s fieldpath.Set
	if err := s.FromJSON(f.GetRawReader()); err != nil {
		return nil, err
	}
	return &s, nil
}

// FieldsToSet creates a set paths from an input trie of fields
func FieldsToSet(f metav1.FieldsV1) (s fieldpath.Set, err error) {
	ref, err := fieldsToSetRef(f)
	if err != nil {
		return fieldpath.Set{}, err
	}
	return *ref, nil
}

// SetToFields creates a trie of fields from an input set of paths
func SetToFields(s fieldpath.Set) (f metav1.FieldsV1, err error) {
	raw, err := s.ToJSON()
	f.SetRawBytes(raw)
	return f, err
}

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
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"sigs.k8s.io/structured-merge-diff/v7/fieldpath"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type origManagedEntry struct {
	entry     metav1.ManagedFieldsEntry
	set       *fieldpath.Set
	canonical bool
}

type fieldsSetCacheEntry struct {
	raw       string
	set       *fieldpath.Set
	canonical bool
}

type fieldsSetCacheShard struct {
	mu      sync.Mutex
	entries [16]fieldsSetCacheEntry
	next    uint8
}

type managerIDKey struct {
	manager     string
	operation   string
	apiVersion  string
	subresource string
}

type managerIDCacheEntry struct {
	key managerIDKey
	id  string
}

type managerIDCacheShard struct {
	mu      sync.Mutex
	entries [8]managerIDCacheEntry
	next    uint8
}

var (
	emptyFieldPathSet  = fieldpath.NewSet()
	fieldsSetCache     [64]fieldsSetCacheShard
	managerEncodeCache [64]managerIDCacheShard
	managerDecodeCache [64]managerIDCacheShard
)

func hashStringSample(s string) uint64 {
	const offset64 = 14695981039346656037
	const prime64 = 1099511628211
	h := uint64(offset64) ^ uint64(len(s))
	if len(s) <= 192 {
		for i := 0; i < len(s); i++ {
			h = (h ^ uint64(s[i])) * prime64
		}
		return h
	}
	for i := 0; i < 64; i++ {
		h = (h ^ uint64(s[i])) * prime64
	}
	mid := len(s)/2 - 32
	for i := mid; i < mid+64; i++ {
		h = (h ^ uint64(s[i])) * prime64
	}
	for i := len(s) - 64; i < len(s); i++ {
		h = (h ^ uint64(s[i])) * prime64
	}
	return h
}

func hashManagerIDKey(k managerIDKey) uint64 {
	const prime64 = 1099511628211
	h := hashStringSample(k.manager)
	h = (h ^ hashStringSample(k.operation)) * prime64
	h = (h ^ hashStringSample(k.apiVersion)) * prime64
	h = (h ^ hashStringSample(k.subresource)) * prime64
	return h
}

func cachedFieldsToSet(fields metav1.FieldsV1) (*fieldpath.Set, bool, error) {
	rawStr := fields.GetRawString()
	if rawStr == "{}" {
		return emptyFieldPathSet, true, nil
	}
	if len(rawStr) == 0 || len(rawStr) > 16384 {
		set, err := FieldsToSet(fields)
		if err != nil {
			return nil, false, err
		}
		return &set, false, nil
	}
	h := hashStringSample(rawStr)
	shard := &fieldsSetCache[h&63]
	base := ((h >> 6) & 3) * 4

	shard.mu.Lock()
	for i := uint64(0); i < 4; i++ {
		e := shard.entries[base+i]
		if e.set != nil && e.raw == rawStr {
			shard.mu.Unlock()
			return e.set, e.canonical, nil
		}
	}
	shard.mu.Unlock()

	set, err := FieldsToSet(fields)
	if err != nil {
		return nil, false, err
	}
	setPtr := &set
	canonical := false
	if canonBytes, canonErr := setPtr.ToJSON(); canonErr == nil && string(canonBytes) == rawStr {
		canonical = true
	}

	shard.mu.Lock()
	slot := base + uint64(shard.next&3)
	shard.next++
	shard.entries[slot] = fieldsSetCacheEntry{raw: rawStr, set: setPtr, canonical: canonical}
	shard.mu.Unlock()
	return setPtr, canonical, nil
}

func seedFieldsSetCache(rawStr string, set *fieldpath.Set) {
	if len(rawStr) == 0 || rawStr == "{}" || len(rawStr) > 16384 || set == nil {
		return
	}
	h := hashStringSample(rawStr)
	shard := &fieldsSetCache[h&63]
	base := ((h >> 6) & 3) * 4

	shard.mu.Lock()
	for i := uint64(0); i < 4; i++ {
		if shard.entries[base+i].set != nil && shard.entries[base+i].raw == rawStr {
			shard.mu.Unlock()
			return
		}
	}
	slot := base + uint64(shard.next&3)
	shard.next++
	shard.entries[slot] = fieldsSetCacheEntry{raw: rawStr, set: set, canonical: true}
	shard.mu.Unlock()
}

// ManagedInterface groups a fieldpath.ManagedFields together with the timestamps associated with each operation.
type ManagedInterface interface {
	// Fields gets the fieldpath.ManagedFields.
	Fields() fieldpath.ManagedFields

	// Times gets the timestamps associated with each operation.
	Times() map[string]*metav1.Time
}

type managedStruct struct {
	fields fieldpath.ManagedFields
	times  map[string]*metav1.Time
	orig   map[string]origManagedEntry
}

var _ ManagedInterface = &managedStruct{}

// Fields implements ManagedInterface.
func (m *managedStruct) Fields() fieldpath.ManagedFields {
	return m.fields
}

// Times implements ManagedInterface.
func (m *managedStruct) Times() map[string]*metav1.Time {
	return m.times
}

// NewEmptyManaged creates an empty ManagedInterface.
func NewEmptyManaged() ManagedInterface {
	return NewManaged(fieldpath.ManagedFields{}, map[string]*metav1.Time{})
}

// NewManaged creates a ManagedInterface from a fieldpath.ManagedFields and the timestamps associated with each operation.
func NewManaged(f fieldpath.ManagedFields, t map[string]*metav1.Time) ManagedInterface {
	return &managedStruct{
		fields: f,
		times:  t,
	}
}

func withManagedFields(prev ManagedInterface, f fieldpath.ManagedFields) ManagedInterface {
	if ms, ok := prev.(*managedStruct); ok {
		return &managedStruct{
			fields: f,
			times:  ms.times,
			orig:   ms.orig,
		}
	}
	return NewManaged(f, prev.Times())
}

// RemoveObjectManagedFields removes the ManagedFields from the object
// before we merge so that it doesn't appear in the ManagedFields
// recursively.
func RemoveObjectManagedFields(obj runtime.Object) {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		panic(fmt.Sprintf("couldn't get accessor: %v", err))
	}
	accessor.SetManagedFields(nil)
}

// EncodeObjectManagedFields converts and stores the fieldpathManagedFields into the objects ManagedFields
func EncodeObjectManagedFields(obj runtime.Object, managed ManagedInterface) error {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		panic(fmt.Sprintf("couldn't get accessor: %v", err))
	}

	encodedManagedFields, err := encodeManagedFields(managed)
	if err != nil {
		return fmt.Errorf("failed to convert back managed fields to API: %v", err)
	}
	accessor.SetManagedFields(encodedManagedFields)

	return nil
}

// DecodeManagedFields converts ManagedFields from the wire format (api format)
// to the format used by sigs.k8s.io/structured-merge-diff
func DecodeManagedFields(encodedManagedFields []metav1.ManagedFieldsEntry) (ManagedInterface, error) {
	managed := managedStruct{}
	managed.fields = make(fieldpath.ManagedFields, len(encodedManagedFields))
	managed.times = make(map[string]*metav1.Time, len(encodedManagedFields))
	if len(encodedManagedFields) > 0 {
		managed.orig = make(map[string]origManagedEntry, len(encodedManagedFields))
	}

	for i, encodedVersionedSet := range encodedManagedFields {
		switch encodedVersionedSet.Operation {
		case metav1.ManagedFieldsOperationApply, metav1.ManagedFieldsOperationUpdate:
		default:
			return nil, fmt.Errorf("operation must be `Apply` or `Update`")
		}
		if len(encodedVersionedSet.APIVersion) < 1 {
			return nil, fmt.Errorf("apiVersion must not be empty")
		}
		switch encodedVersionedSet.FieldsType {
		case "FieldsV1":
			// Valid case.
		case "":
			return nil, fmt.Errorf("missing fieldsType in managed fields entry %d", i)
		default:
			return nil, fmt.Errorf("invalid fieldsType %q in managed fields entry %d", encodedVersionedSet.FieldsType, i)
		}
		manager, err := BuildManagerIdentifier(&encodedVersionedSet)
		if err != nil {
			return nil, fmt.Errorf("error decoding manager from %v: %v", encodedVersionedSet, err)
		}
		vs, canonical, err := decodeVersionedSetWithCanonical(&encodedVersionedSet)
		if err != nil {
			return nil, fmt.Errorf("error decoding versioned set from %v: %v", encodedVersionedSet, err)
		}
		managed.fields[manager] = vs
		managed.times[manager] = encodedVersionedSet.Time
		managed.orig[manager] = origManagedEntry{
			entry:     encodedVersionedSet,
			set:       vs.Set(),
			canonical: canonical,
		}
	}
	return &managed, nil
}

// BuildManagerIdentifier creates a manager identifier string from a ManagedFieldsEntry
func BuildManagerIdentifier(encodedManager *metav1.ManagedFieldsEntry) (manager string, err error) {
	apiVersion := encodedManager.APIVersion
	if encodedManager.Operation == metav1.ManagedFieldsOperationApply {
		apiVersion = ""
	}
	key := managerIDKey{
		manager:     encodedManager.Manager,
		operation:   string(encodedManager.Operation),
		apiVersion:  apiVersion,
		subresource: encodedManager.Subresource,
	}
	if len(key.manager)+len(key.operation)+len(key.apiVersion)+len(key.subresource) <= 512 {
		eh := hashManagerIDKey(key)
		eShard := &managerEncodeCache[eh&63]
		eShard.mu.Lock()
		for i := 0; i < len(eShard.entries); i++ {
			e := eShard.entries[i]
			if e.id != "" && e.key == key {
				eShard.mu.Unlock()
				return e.id, nil
			}
		}
		eShard.mu.Unlock()

		encodedManagerCopy := metav1.ManagedFieldsEntry{
			Manager:     key.manager,
			Operation:   encodedManager.Operation,
			APIVersion:  key.apiVersion,
			Subresource: key.subresource,
		}
		b, err := json.Marshal(&encodedManagerCopy)
		if err != nil {
			return "", fmt.Errorf("error marshalling manager identifier: %v", err)
		}
		id := string(b)

		eShard.mu.Lock()
		eSlot := eShard.next & 7
		eShard.next++
		eShard.entries[eSlot] = managerIDCacheEntry{key: key, id: id}
		eShard.mu.Unlock()

		dh := hashStringSample(id)
		dShard := &managerDecodeCache[dh&63]
		dShard.mu.Lock()
		dSlot := dShard.next & 7
		dShard.next++
		dShard.entries[dSlot] = managerIDCacheEntry{key: key, id: id}
		dShard.mu.Unlock()
		return id, nil
	}

	encodedManagerCopy := *encodedManager
	encodedManagerCopy.FieldsType = ""
	encodedManagerCopy.FieldsV1 = nil
	encodedManagerCopy.Time = nil
	if encodedManager.Operation == metav1.ManagedFieldsOperationApply {
		encodedManagerCopy.APIVersion = ""
	}
	b, err := json.Marshal(&encodedManagerCopy)
	if err != nil {
		return "", fmt.Errorf("error marshalling manager identifier: %v", err)
	}
	return string(b), nil
}

func decodeVersionedSet(encodedVersionedSet *metav1.ManagedFieldsEntry) (versionedSet fieldpath.VersionedSet, err error) {
	vs, _, err := decodeVersionedSetWithCanonical(encodedVersionedSet)
	return vs, err
}

func decodeVersionedSetWithCanonical(encodedVersionedSet *metav1.ManagedFieldsEntry) (versionedSet fieldpath.VersionedSet, canonical bool, err error) {
	if encodedVersionedSet.FieldsV1 == nil {
		return fieldpath.NewVersionedSet(emptyFieldPathSet, fieldpath.APIVersion(encodedVersionedSet.APIVersion), encodedVersionedSet.Operation == metav1.ManagedFieldsOperationApply), false, nil
	}
	set, canonical, err := cachedFieldsToSet(*encodedVersionedSet.FieldsV1)
	if err != nil {
		return nil, false, fmt.Errorf("error decoding set: %v", err)
	}
	return fieldpath.NewVersionedSet(set, fieldpath.APIVersion(encodedVersionedSet.APIVersion), encodedVersionedSet.Operation == metav1.ManagedFieldsOperationApply), canonical, nil
}

// encodeManagedFields converts ManagedFields from the format used by
// sigs.k8s.io/structured-merge-diff to the wire format (api format)
func encodeManagedFields(managed ManagedInterface) (encodedManagedFields []metav1.ManagedFieldsEntry, err error) {
	fields := managed.Fields()
	if len(fields) == 0 {
		return nil, nil
	}
	times := managed.Times()
	ms, _ := managed.(*managedStruct)
	encodedManagedFields = make([]metav1.ManagedFieldsEntry, 0, len(fields))
	for manager, versionedSet := range fields {
		if ms != nil && ms.orig != nil {
			if origEntry, ok := ms.orig[manager]; ok && origEntry.canonical && origEntry.entry.FieldsV1 != nil {
				expectedOp := origEntry.entry.Operation
				if versionedSet.Applied() {
					expectedOp = metav1.ManagedFieldsOperationApply
				}
				if origEntry.entry.Operation == expectedOp &&
					origEntry.entry.APIVersion == string(versionedSet.APIVersion()) &&
					(origEntry.set == versionedSet.Set() || origEntry.set.Equals(versionedSet.Set())) {
					v := origEntry.entry
					if t, hasTime := times[manager]; hasTime {
						v.Time = t
					} else {
						v.Time = nil
					}
					encodedManagedFields = append(encodedManagedFields, v)
					continue
				}
			}
		}
		var v metav1.ManagedFieldsEntry
		if err := encodeManagerVersionedSetInto(manager, versionedSet, &v); err != nil {
			return nil, fmt.Errorf("error encoding versioned set for %v: %v", manager, err)
		}
		if t, ok := times[manager]; ok {
			v.Time = t
		}
		encodedManagedFields = append(encodedManagedFields, v)
	}
	return sortEncodedManagedFields(encodedManagedFields)
}

func sortEncodedManagedFields(encodedManagedFields []metav1.ManagedFieldsEntry) (sortedManagedFields []metav1.ManagedFieldsEntry, err error) {
	sort.Slice(encodedManagedFields, func(i, j int) bool {
		p, q := encodedManagedFields[i], encodedManagedFields[j]

		if p.Operation != q.Operation {
			return p.Operation < q.Operation
		}

		pSeconds, qSeconds := int64(0), int64(0)
		if p.Time != nil {
			pSeconds = p.Time.Unix()
		}
		if q.Time != nil {
			qSeconds = q.Time.Unix()
		}
		if pSeconds != qSeconds {
			return pSeconds < qSeconds
		}

		if p.Manager != q.Manager {
			return p.Manager < q.Manager
		}

		if p.APIVersion != q.APIVersion {
			return p.APIVersion < q.APIVersion
		}
		return p.Subresource < q.Subresource
	})

	return encodedManagedFields, nil
}

func encodeManagerVersionedSet(manager string, versionedSet fieldpath.VersionedSet) (encodedVersionedSet *metav1.ManagedFieldsEntry, err error) {
	var out metav1.ManagedFieldsEntry
	if err := encodeManagerVersionedSetInto(manager, versionedSet, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func encodeManagerVersionedSetInto(manager string, versionedSet fieldpath.VersionedSet, encodedVersionedSet *metav1.ManagedFieldsEntry) error {
	decodedFromCache := false
	if len(manager) > 0 && len(manager) <= 1024 {
		dh := hashStringSample(manager)
		dShard := &managerDecodeCache[dh&63]
		dShard.mu.Lock()
		for i := 0; i < len(dShard.entries); i++ {
			e := dShard.entries[i]
			if e.id == manager {
				encodedVersionedSet.Manager = e.key.manager
				encodedVersionedSet.Operation = metav1.ManagedFieldsOperationType(e.key.operation)
				encodedVersionedSet.APIVersion = e.key.apiVersion
				encodedVersionedSet.Subresource = e.key.subresource
				decodedFromCache = true
				break
			}
		}
		dShard.mu.Unlock()
	}
	if !decodedFromCache {
		if err := json.Unmarshal([]byte(manager), encodedVersionedSet); err != nil {
			return fmt.Errorf("error unmarshalling manager identifier %v: %v", manager, err)
		}
	}

	// Get the APIVersion, Operation, and Fields from the VersionedSet
	encodedVersionedSet.APIVersion = string(versionedSet.APIVersion())
	if versionedSet.Applied() {
		encodedVersionedSet.Operation = metav1.ManagedFieldsOperationApply
	}
	encodedVersionedSet.FieldsType = "FieldsV1"
	fields, err := SetToFields(*versionedSet.Set())
	if err != nil {
		return fmt.Errorf("error encoding set: %v", err)
	}
	seedFieldsSetCache(fields.GetRawString(), versionedSet.Set())
	encodedVersionedSet.FieldsV1 = &fields

	return nil
}

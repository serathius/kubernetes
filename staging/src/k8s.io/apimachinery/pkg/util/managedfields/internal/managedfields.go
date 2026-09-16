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
	"strings"

	"sigs.k8s.io/structured-merge-diff/v7/fieldpath"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// originalManagedEntry retains the wire ManagedFieldsEntry and decoded fieldpath.Set
// so unchanged sets can reuse their existing FieldsV1 raw bytes without re-encoding.
type originalManagedEntry struct {
	entry metav1.ManagedFieldsEntry
	set   *fieldpath.Set
}

// ManagedInterface groups a fieldpath.ManagedFields together with the timestamps associated with each operation.
type ManagedInterface interface {
	// Fields gets the fieldpath.ManagedFields.
	Fields() fieldpath.ManagedFields

	// Times gets the timestamps associated with each operation.
	Times() map[string]*metav1.Time

	// Originals gets the original wire entries decoded from the object.
	Originals() map[string]originalManagedEntry
}

type managedStruct struct {
	fields    fieldpath.ManagedFields
	times     map[string]*metav1.Time
	originals map[string]originalManagedEntry
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

// Originals implements ManagedInterface.
func (m *managedStruct) Originals() map[string]originalManagedEntry {
	return m.originals
}

// NewEmptyManaged creates an empty ManagedInterface.
func NewEmptyManaged() ManagedInterface {
	return NewManaged(fieldpath.ManagedFields{}, map[string]*metav1.Time{})
}

// NewManaged creates a ManagedInterface from a fieldpath.ManagedFields and the timestamps associated with each operation.
func NewManaged(f fieldpath.ManagedFields, t map[string]*metav1.Time) ManagedInterface {
	return &managedStruct{
		fields:    f,
		times:     t,
		originals: map[string]originalManagedEntry{},
	}
}

// NewManagedWithOriginals creates a ManagedInterface preserving the original decoded entries.
func NewManagedWithOriginals(f fieldpath.ManagedFields, t map[string]*metav1.Time, originals map[string]originalManagedEntry) ManagedInterface {
	if originals == nil {
		originals = map[string]originalManagedEntry{}
	}
	return &managedStruct{
		fields:    f,
		times:     t,
		originals: originals,
	}
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
	managed := managedStruct{
		fields:    make(fieldpath.ManagedFields, len(encodedManagedFields)),
		times:     make(map[string]*metav1.Time, len(encodedManagedFields)),
		originals: make(map[string]originalManagedEntry, len(encodedManagedFields)),
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
		vs, err := decodeVersionedSet(&encodedVersionedSet)
		if err != nil {
			return nil, fmt.Errorf("error decoding versioned set from %v: %v", encodedVersionedSet, err)
		}
		managed.fields[manager] = vs
		managed.times[manager] = encodedVersionedSet.Time
		managed.originals[manager] = originalManagedEntry{
			entry: encodedVersionedSet,
			set:   vs.Set(),
		}
	}
	return &managed, nil
}

func isSimpleJSONString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
			return false
		}
	}
	return true
}

// BuildManagerIdentifier creates a manager identifier string from a ManagedFieldsEntry
func BuildManagerIdentifier(encodedManager *metav1.ManagedFieldsEntry) (manager string, err error) {
	apiVersion := encodedManager.APIVersion
	if encodedManager.Operation == metav1.ManagedFieldsOperationApply {
		apiVersion = ""
	}
	if isSimpleJSONString(encodedManager.Manager) &&
		isSimpleJSONString(string(encodedManager.Operation)) &&
		isSimpleJSONString(apiVersion) &&
		isSimpleJSONString(encodedManager.Subresource) {
		var b strings.Builder
		b.Grow(32 + len(encodedManager.Manager) + len(encodedManager.Operation) + len(apiVersion) + len(encodedManager.Subresource))
		b.WriteByte('{')
		wroteField := false
		if encodedManager.Manager != "" {
			b.WriteString(`"manager":"`)
			b.WriteString(encodedManager.Manager)
			b.WriteByte('"')
			wroteField = true
		}
		if encodedManager.Operation != "" {
			if wroteField {
				b.WriteByte(',')
			}
			b.WriteString(`"operation":"`)
			b.WriteString(string(encodedManager.Operation))
			b.WriteByte('"')
			wroteField = true
		}
		if apiVersion != "" {
			if wroteField {
				b.WriteByte(',')
			}
			b.WriteString(`"apiVersion":"`)
			b.WriteString(apiVersion)
			b.WriteByte('"')
			wroteField = true
		}
		if encodedManager.Subresource != "" {
			if wroteField {
				b.WriteByte(',')
			}
			b.WriteString(`"subresource":"`)
			b.WriteString(encodedManager.Subresource)
			b.WriteByte('"')
		}
		b.WriteByte('}')
		return b.String(), nil
	}

	encodedManagerCopy := *encodedManager

	// Never include fields type in the manager identifier
	encodedManagerCopy.FieldsType = ""

	// Never include the fields in the manager identifier
	encodedManagerCopy.FieldsV1 = nil

	// Never include the time in the manager identifier
	encodedManagerCopy.Time = nil

	// For appliers, don't include the APIVersion in the manager identifier,
	// so it will always have the same manager identifier each time it applied.
	if encodedManager.Operation == metav1.ManagedFieldsOperationApply {
		encodedManagerCopy.APIVersion = ""
	}

	// Use the remaining fields to build the manager identifier
	b, err := json.Marshal(&encodedManagerCopy)
	if err != nil {
		return "", fmt.Errorf("error marshalling manager identifier: %v", err)
	}

	return string(b), nil
}

func decodeVersionedSet(encodedVersionedSet *metav1.ManagedFieldsEntry) (versionedSet fieldpath.VersionedSet, err error) {
	fields := EmptyFields
	if encodedVersionedSet.FieldsV1 != nil {
		fields = *encodedVersionedSet.FieldsV1
	}
	set, err := FieldsToSet(fields)
	if err != nil {
		return nil, fmt.Errorf("error decoding set: %v", err)
	}
	return fieldpath.NewVersionedSet(&set, fieldpath.APIVersion(encodedVersionedSet.APIVersion), encodedVersionedSet.Operation == metav1.ManagedFieldsOperationApply), nil
}

// encodeManagedFields converts ManagedFields from the format used by
// sigs.k8s.io/structured-merge-diff to the wire format (api format)
func encodeManagedFields(managed ManagedInterface) (encodedManagedFields []metav1.ManagedFieldsEntry, err error) {
	if len(managed.Fields()) == 0 {
		return nil, nil
	}
	encodedManagedFields = make([]metav1.ManagedFieldsEntry, 0, len(managed.Fields()))
	originals := managed.Originals()
	for manager, versionedSet := range managed.Fields() {
		if orig, ok := originals[manager]; ok {
			v := metav1.ManagedFieldsEntry{
				Manager:     orig.entry.Manager,
				Operation:   orig.entry.Operation,
				APIVersion:  string(versionedSet.APIVersion()),
				FieldsType:  "FieldsV1",
				Subresource: orig.entry.Subresource,
			}
			if versionedSet.Applied() {
				v.Operation = metav1.ManagedFieldsOperationApply
			}
			if t, hasTime := managed.Times()[manager]; hasTime {
				v.Time = t
			}
			if orig.set != nil && orig.entry.FieldsV1 != nil && (versionedSet.Set() == orig.set || versionedSet.Set().Equals(orig.set)) {
				v.FieldsV1 = orig.entry.FieldsV1
			} else {
				fields, err := SetToFields(*versionedSet.Set())
				if err != nil {
					return nil, fmt.Errorf("error encoding versioned set for %v: %v", manager, err)
				}
				v.FieldsV1 = &fields
			}
			encodedManagedFields = append(encodedManagedFields, v)
			continue
		}
		v, err := encodeManagerVersionedSet(manager, versionedSet)
		if err != nil {
			return nil, fmt.Errorf("error encoding versioned set for %v: %v", manager, err)
		}
		if t, ok := managed.Times()[manager]; ok {
			v.Time = t
		}
		encodedManagedFields = append(encodedManagedFields, *v)
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
	encodedVersionedSet = &metav1.ManagedFieldsEntry{}

	// Get as many fields as we can from the manager identifier
	err = json.Unmarshal([]byte(manager), encodedVersionedSet)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling manager identifier %v: %v", manager, err)
	}

	// Get the APIVersion, Operation, and Fields from the VersionedSet
	encodedVersionedSet.APIVersion = string(versionedSet.APIVersion())
	if versionedSet.Applied() {
		encodedVersionedSet.Operation = metav1.ManagedFieldsOperationApply
	}
	encodedVersionedSet.FieldsType = "FieldsV1"
	fields, err := SetToFields(*versionedSet.Set())
	if err != nil {
		return nil, fmt.Errorf("error encoding set: %v", err)
	}
	encodedVersionedSet.FieldsV1 = &fields

	return encodedVersionedSet, nil
}

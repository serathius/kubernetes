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

// Package lazy provides generic protobuf wire-level primitives and lazy
// metav1.ObjectMeta extraction/splicing for Kubernetes API objects.
package lazy

import (
	"maps"
	"slices"
	"sort"
	"time"
	"unsafe"

	"google.golang.org/protobuf/encoding/protowire"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Standard top-level and ObjectMeta protobuf field tag numbers across Kubernetes resources.
const (
	MetadataFieldNumber protowire.Number = 1
	SpecFieldNumber     protowire.Number = 2
	StatusFieldNumber   protowire.Number = 3

	MapEntryKeyFieldNumber   protowire.Number = 1
	MapEntryValueFieldNumber protowire.Number = 2

	MetaFieldName                       protowire.Number = 1
	MetaFieldGenerateName               protowire.Number = 2
	MetaFieldNamespace                  protowire.Number = 3
	MetaFieldSelfLink                   protowire.Number = 4
	MetaFieldUID                        protowire.Number = 5
	MetaFieldResourceVersion            protowire.Number = 6
	MetaFieldGeneration                 protowire.Number = 7
	MetaFieldCreationTimestamp          protowire.Number = 8
	MetaFieldDeletionTimestamp          protowire.Number = 9
	MetaFieldDeletionGracePeriodSeconds protowire.Number = 10
	MetaFieldLabels                     protowire.Number = 11
	MetaFieldAnnotations                protowire.Number = 12
	MetaFieldOwnerReferences            protowire.Number = 13
	MetaFieldFinalizers                 protowire.Number = 14
	MetaFieldManagedFields              protowire.Number = 17
)

// Dirty bitmask flags for lazy ObjectMeta field mutations.
const (
	dirtyMetaName uint16 = 1 << iota
	dirtyMetaGenerateName
	dirtyMetaNamespace
	dirtyMetaSelfLink
	dirtyMetaUID
	dirtyMetaResourceVersion
	dirtyMetaGeneration
	dirtyMetaCreationTimestamp
	dirtyMetaDeletionTimestamp
	dirtyMetaDeletionGracePeriodSeconds
	dirtyMetaLabels
	dirtyMetaAnnotations
	dirtyMetaOwnerReferences
	dirtyMetaFinalizers
	dirtyMetaManagedFields
)

// WireObjectMeta stores lazy overrides for metav1.ObjectMeta fields and provides
// zero-decoding getters, setters, and wire splicing over raw ObjectMeta protobuf bytes.
//
// +k8s:deepcopy-gen=false
type WireObjectMeta struct {
	parentRaw                  []byte
	metaFieldNum               protowire.Number
	metaBytes                  []byte
	scanned                    bool
	dirty                      uint16
	name                       string
	generateName               string
	namespace                  string
	selfLink                   string
	uid                        types.UID
	resourceVersion            string
	generation                 int64
	creationTimestamp          metav1.Time
	deletionTimestamp          *metav1.Time
	deletionGracePeriodSeconds *int64
	labels                     map[string]string
	annotations                map[string]string
	ownerReferences            []metav1.OwnerReference
	finalizers                 []string
	managedFields              []metav1.ManagedFieldsEntry
}

// InitFromParent initializes WireObjectMeta over a parent message's raw bytes.
func (m *WireObjectMeta) InitFromParent(parentRaw []byte, metaFieldNum protowire.Number) {
	*m = WireObjectMeta{
		parentRaw:    parentRaw,
		metaFieldNum: metaFieldNum,
	}
}

// CloneWithParent returns a deep copy of WireObjectMeta bound to newParentRaw.
func (m *WireObjectMeta) CloneWithParent(newParentRaw []byte, metaFieldNum protowire.Number) WireObjectMeta {
	cp := m.Clone()
	cp.parentRaw = newParentRaw
	cp.metaFieldNum = metaFieldNum
	cp.metaBytes = nil
	cp.scanned = false
	return cp
}

// Bytes returns the cached ObjectMeta sub-message bytes from parentRaw.
func (m *WireObjectMeta) Bytes() []byte {
	if m == nil {
		return nil
	}
	if !m.scanned {
		fieldNum := m.metaFieldNum
		if fieldNum == 0 {
			fieldNum = MetadataFieldNumber
		}
		m.metaBytes = SubMessage(m.parentRaw, fieldNum)
		m.scanned = true
	}
	return m.metaBytes
}

// IsDirty reports whether any ObjectMeta setter mutation is pending materialization.
func (m *WireObjectMeta) IsDirty() bool {
	return m != nil && m.dirty != 0
}

// ClearDirty resets all pending dirty flags after wire materialization.
func (m *WireObjectMeta) ClearDirty() {
	if m != nil {
		*m = WireObjectMeta{
			parentRaw:    m.parentRaw,
			metaFieldNum: m.metaFieldNum,
		}
	}
}

// Clone returns a deep copy of WireObjectMeta.
func (m *WireObjectMeta) Clone() WireObjectMeta {
	if m == nil {
		return WireObjectMeta{}
	}
	if m.dirty == 0 {
		return WireObjectMeta{
			parentRaw:    m.parentRaw,
			metaFieldNum: m.metaFieldNum,
		}
	}
	cp := *m
	if m.deletionTimestamp != nil {
		ts := *m.deletionTimestamp
		cp.deletionTimestamp = &ts
	}
	if m.deletionGracePeriodSeconds != nil {
		gp := *m.deletionGracePeriodSeconds
		cp.deletionGracePeriodSeconds = &gp
	}
	if m.labels != nil {
		cp.labels = maps.Clone(m.labels)
	}
	if m.annotations != nil {
		cp.annotations = maps.Clone(m.annotations)
	}
	if m.ownerReferences != nil {
		cp.ownerReferences = make([]metav1.OwnerReference, len(m.ownerReferences))
		for i := range m.ownerReferences {
			m.ownerReferences[i].DeepCopyInto(&cp.ownerReferences[i])
		}
	}
	if m.finalizers != nil {
		cp.finalizers = slices.Clone(m.finalizers)
	}
	if m.managedFields != nil {
		cp.managedFields = make([]metav1.ManagedFieldsEntry, len(m.managedFields))
		for i := range m.managedFields {
			m.managedFields[i].DeepCopyInto(&cp.managedFields[i])
		}
	}
	return cp
}

func (m *WireObjectMeta) GetName() string                       { return m.Name(m.Bytes()) }
func (m *WireObjectMeta) GetGenerateName() string               { return m.GenerateName(m.Bytes()) }
func (m *WireObjectMeta) GetNamespace() string                  { return m.Namespace(m.Bytes()) }
func (m *WireObjectMeta) GetSelfLink() string                   { return m.SelfLink(m.Bytes()) }
func (m *WireObjectMeta) GetUID() types.UID                     { return m.UID(m.Bytes()) }
func (m *WireObjectMeta) GetResourceVersion() string            { return m.ResourceVersion(m.Bytes()) }
func (m *WireObjectMeta) GetGeneration() int64                  { return m.Generation(m.Bytes()) }
func (m *WireObjectMeta) GetCreationTimestamp() metav1.Time     { return m.CreationTimestamp(m.Bytes()) }
func (m *WireObjectMeta) GetDeletionTimestamp() *metav1.Time    { return m.DeletionTimestamp(m.Bytes()) }
func (m *WireObjectMeta) GetDeletionGracePeriodSeconds() *int64 { return m.DeletionGracePeriodSeconds(m.Bytes()) }
func (m *WireObjectMeta) GetLabels() map[string]string          { return m.Labels(m.Bytes()) }
func (m *WireObjectMeta) GetAnnotations() map[string]string     { return m.Annotations(m.Bytes()) }
func (m *WireObjectMeta) GetOwnerReferences() []metav1.OwnerReference {
	return m.OwnerReferences(m.Bytes())
}
func (m *WireObjectMeta) GetFinalizers() []string { return m.Finalizers(m.Bytes()) }
func (m *WireObjectMeta) GetManagedFields() []metav1.ManagedFieldsEntry {
	return m.ManagedFields(m.Bytes())
}

// Name returns metadata.name from overrides or wire bytes.
func (m *WireObjectMeta) Name(metaBytes []byte) string {
	if m != nil && m.dirty&dirtyMetaName != 0 {
		return m.name
	}
	return ExtractFirstStringField(metaBytes, MetaFieldName)
}

// SetName records a lazy override for metadata.name.
func (m *WireObjectMeta) SetName(name string) {
	m.name = name
	m.dirty |= dirtyMetaName
}

// GenerateName returns metadata.generateName from overrides or wire bytes.
func (m *WireObjectMeta) GenerateName(metaBytes []byte) string {
	if m != nil && m.dirty&dirtyMetaGenerateName != 0 {
		return m.generateName
	}
	return ExtractFirstStringField(metaBytes, MetaFieldGenerateName)
}

// SetGenerateName records a lazy override for metadata.generateName.
func (m *WireObjectMeta) SetGenerateName(generateName string) {
	m.generateName = generateName
	m.dirty |= dirtyMetaGenerateName
}

// Namespace returns metadata.namespace from overrides or wire bytes.
func (m *WireObjectMeta) Namespace(metaBytes []byte) string {
	if m != nil && m.dirty&dirtyMetaNamespace != 0 {
		return m.namespace
	}
	return ExtractFirstStringField(metaBytes, MetaFieldNamespace)
}

// SetNamespace records a lazy override for metadata.namespace.
func (m *WireObjectMeta) SetNamespace(namespace string) {
	m.namespace = namespace
	m.dirty |= dirtyMetaNamespace
}

// SelfLink returns metadata.selfLink from overrides or wire bytes.
func (m *WireObjectMeta) SelfLink(metaBytes []byte) string {
	if m != nil && m.dirty&dirtyMetaSelfLink != 0 {
		return m.selfLink
	}
	return ExtractFirstStringField(metaBytes, MetaFieldSelfLink)
}

// SetSelfLink records a lazy override for metadata.selfLink.
func (m *WireObjectMeta) SetSelfLink(selfLink string) {
	m.selfLink = selfLink
	m.dirty |= dirtyMetaSelfLink
}

// UID returns metadata.uid from overrides or wire bytes.
func (m *WireObjectMeta) UID(metaBytes []byte) types.UID {
	if m != nil && m.dirty&dirtyMetaUID != 0 {
		return m.uid
	}
	return types.UID(ExtractFirstStringField(metaBytes, MetaFieldUID))
}

// SetUID records a lazy override for metadata.uid.
func (m *WireObjectMeta) SetUID(uid types.UID) {
	m.uid = uid
	m.dirty |= dirtyMetaUID
}

// ResourceVersion returns metadata.resourceVersion from overrides or wire bytes.
func (m *WireObjectMeta) ResourceVersion(metaBytes []byte) string {
	if m != nil && m.dirty&dirtyMetaResourceVersion != 0 {
		return m.resourceVersion
	}
	return ExtractFirstStringField(metaBytes, MetaFieldResourceVersion)
}

// SetResourceVersion records a lazy override for metadata.resourceVersion.
func (m *WireObjectMeta) SetResourceVersion(rv string) {
	m.resourceVersion = rv
	m.dirty |= dirtyMetaResourceVersion
}

// Generation returns metadata.generation from overrides or wire bytes.
func (m *WireObjectMeta) Generation(metaBytes []byte) int64 {
	if m != nil && m.dirty&dirtyMetaGeneration != 0 {
		return m.generation
	}
	return int64(ExtractVarintField(metaBytes, MetaFieldGeneration))
}

// SetGeneration records a lazy override for metadata.generation.
func (m *WireObjectMeta) SetGeneration(gen int64) {
	m.generation = gen
	m.dirty |= dirtyMetaGeneration
}

// CreationTimestamp returns metadata.creationTimestamp from overrides or wire bytes.
func (m *WireObjectMeta) CreationTimestamp(metaBytes []byte) metav1.Time {
	if m != nil && m.dirty&dirtyMetaCreationTimestamp != 0 {
		return m.creationTimestamp
	}
	tsBytes := SubMessage(metaBytes, MetaFieldCreationTimestamp)
	if len(tsBytes) == 0 {
		return metav1.Time{}
	}
	return ParseTimestamp(tsBytes)
}

// SetCreationTimestamp records a lazy override for metadata.creationTimestamp.
func (m *WireObjectMeta) SetCreationTimestamp(ts metav1.Time) {
	m.creationTimestamp = ts
	m.dirty |= dirtyMetaCreationTimestamp
}

// DeletionTimestamp returns metadata.deletionTimestamp from overrides or wire bytes.
func (m *WireObjectMeta) DeletionTimestamp(metaBytes []byte) *metav1.Time {
	if m != nil && m.dirty&dirtyMetaDeletionTimestamp != 0 {
		if m.deletionTimestamp == nil {
			return nil
		}
		cp := *m.deletionTimestamp
		return &cp
	}
	tsBytes := SubMessage(metaBytes, MetaFieldDeletionTimestamp)
	if len(tsBytes) == 0 {
		return nil
	}
	t := ParseTimestamp(tsBytes)
	return &t
}

// SetDeletionTimestamp records a lazy override for metadata.deletionTimestamp.
func (m *WireObjectMeta) SetDeletionTimestamp(ts *metav1.Time) {
	if ts == nil {
		m.deletionTimestamp = nil
	} else {
		cp := *ts
		m.deletionTimestamp = &cp
	}
	m.dirty |= dirtyMetaDeletionTimestamp
}

// HasDeletionTimestamp reports whether metadata.deletionTimestamp is non-nil without allocating.
func (m *WireObjectMeta) HasDeletionTimestamp(metaBytes []byte) bool {
	if m != nil && m.dirty&dirtyMetaDeletionTimestamp != 0 {
		return m.deletionTimestamp != nil
	}
	return len(SubMessage(metaBytes, MetaFieldDeletionTimestamp)) > 0
}

// DeletionGracePeriodSeconds returns metadata.deletionGracePeriodSeconds from overrides or wire bytes.
func (m *WireObjectMeta) DeletionGracePeriodSeconds(metaBytes []byte) *int64 {
	if m != nil && m.dirty&dirtyMetaDeletionGracePeriodSeconds != 0 {
		if m.deletionGracePeriodSeconds == nil {
			return nil
		}
		cp := *m.deletionGracePeriodSeconds
		return &cp
	}
	if v, ok := ExtractOptionalVarintField(metaBytes, MetaFieldDeletionGracePeriodSeconds); ok {
		iv := int64(v)
		return &iv
	}
	return nil
}

// SetDeletionGracePeriodSeconds records a lazy override for metadata.deletionGracePeriodSeconds.
func (m *WireObjectMeta) SetDeletionGracePeriodSeconds(s *int64) {
	if s == nil {
		m.deletionGracePeriodSeconds = nil
	} else {
		cp := *s
		m.deletionGracePeriodSeconds = &cp
	}
	m.dirty |= dirtyMetaDeletionGracePeriodSeconds
}

// Labels returns metadata.labels from overrides or wire bytes.
func (m *WireObjectMeta) Labels(metaBytes []byte) map[string]string {
	if m != nil && m.dirty&dirtyMetaLabels != 0 {
		return m.labels
	}
	return ExtractMapField(metaBytes, MetaFieldLabels)
}

// SetLabels records a lazy override for metadata.labels.
func (m *WireObjectMeta) SetLabels(labels map[string]string) {
	m.labels = labels
	m.dirty |= dirtyMetaLabels
}

// Annotations returns metadata.annotations from overrides or wire bytes.
func (m *WireObjectMeta) Annotations(metaBytes []byte) map[string]string {
	if m != nil && m.dirty&dirtyMetaAnnotations != 0 {
		return m.annotations
	}
	return ExtractMapField(metaBytes, MetaFieldAnnotations)
}

// SetAnnotations records a lazy override for metadata.annotations.
func (m *WireObjectMeta) SetAnnotations(annotations map[string]string) {
	m.annotations = annotations
	m.dirty |= dirtyMetaAnnotations
}

// HasAnnotationValue reports whether metadata.annotations[key] == val without allocating a map.
func (m *WireObjectMeta) HasAnnotationValue(metaBytes []byte, key, val string) bool {
	if m != nil && m.dirty&dirtyMetaAnnotations != 0 {
		return m.annotations[key] == val
	}
	offset := 0
	found := false
	var lastVal string
	for offset < len(metaBytes) {
		num, typ, tagLen := protowire.ConsumeTag(metaBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, metaBytes[offset:])
		if valLen < 0 {
			break
		}
		if num == MetaFieldAnnotations && typ == protowire.BytesType {
			entry, _ := protowire.ConsumeBytes(metaBytes[offset : offset+valLen])
			if ExtractFirstStringFieldNoCopy(entry, MapEntryKeyFieldNumber) == key {
				found = true
				lastVal = ExtractFirstStringFieldNoCopy(entry, MapEntryValueFieldNumber)
			}
		}
		offset += valLen
	}
	if !found {
		return val == ""
	}
	return lastVal == val
}

// OwnerReferences returns metadata.ownerReferences from overrides or wire bytes.
func (m *WireObjectMeta) OwnerReferences(metaBytes []byte) []metav1.OwnerReference {
	if m != nil && m.dirty&dirtyMetaOwnerReferences != 0 {
		return m.ownerReferences
	}
	var refs []metav1.OwnerReference
	offset := 0
	for offset < len(metaBytes) {
		num, typ, tagLen := protowire.ConsumeTag(metaBytes[offset:])
		if tagLen < 0 {
			return refs
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, metaBytes[offset:])
		if valLen < 0 {
			return refs
		}
		if num == MetaFieldOwnerReferences && typ == protowire.BytesType {
			refBytes, _ := protowire.ConsumeBytes(metaBytes[offset : offset+valLen])
			var ref metav1.OwnerReference
			if err := ref.Unmarshal(refBytes); err == nil {
				refs = append(refs, ref)
			}
		}
		offset += valLen
	}
	return refs
}

// SetOwnerReferences records a lazy override for metadata.ownerReferences.
func (m *WireObjectMeta) SetOwnerReferences(refs []metav1.OwnerReference) {
	m.ownerReferences = refs
	m.dirty |= dirtyMetaOwnerReferences
}

// HasMultipleOwnerReferences reports whether metadata.ownerReferences has more than 1 entry without allocating.
func (m *WireObjectMeta) HasMultipleOwnerReferences(metaBytes []byte) bool {
	if m != nil && m.dirty&dirtyMetaOwnerReferences != 0 {
		return len(m.ownerReferences) > 1
	}
	count := 0
	offset := 0
	for offset < len(metaBytes) {
		num, typ, tagLen := protowire.ConsumeTag(metaBytes[offset:])
		if tagLen < 0 {
			return false
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, metaBytes[offset:])
		if valLen < 0 {
			return false
		}
		if num == MetaFieldOwnerReferences && typ == protowire.BytesType {
			count++
			if count > 1 {
				return true
			}
		}
		offset += valLen
	}
	return false
}

// Finalizers returns metadata.finalizers from overrides or wire bytes.
func (m *WireObjectMeta) Finalizers(metaBytes []byte) []string {
	if m != nil && m.dirty&dirtyMetaFinalizers != 0 {
		return m.finalizers
	}
	return ExtractStringSliceField(metaBytes, MetaFieldFinalizers)
}

// SetFinalizers records a lazy override for metadata.finalizers.
func (m *WireObjectMeta) SetFinalizers(finalizers []string) {
	m.finalizers = finalizers
	m.dirty |= dirtyMetaFinalizers
}

// ManagedFields returns metadata.managedFields from overrides or wire bytes.
func (m *WireObjectMeta) ManagedFields(metaBytes []byte) []metav1.ManagedFieldsEntry {
	if m != nil && m.dirty&dirtyMetaManagedFields != 0 {
		return m.managedFields
	}
	var entries []metav1.ManagedFieldsEntry
	offset := 0
	for offset < len(metaBytes) {
		num, typ, tagLen := protowire.ConsumeTag(metaBytes[offset:])
		if tagLen < 0 {
			return entries
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, metaBytes[offset:])
		if valLen < 0 {
			return entries
		}
		if num == MetaFieldManagedFields && typ == protowire.BytesType {
			entryBytes, _ := protowire.ConsumeBytes(metaBytes[offset : offset+valLen])
			var entry metav1.ManagedFieldsEntry
			if err := entry.Unmarshal(entryBytes); err == nil {
				entries = append(entries, entry)
			}
		}
		offset += valLen
	}
	return entries
}

// SetManagedFields records a lazy override for metadata.managedFields.
func (m *WireObjectMeta) SetManagedFields(managedFields []metav1.ManagedFieldsEntry) {
	m.managedFields = managedFields
	m.dirty |= dirtyMetaManagedFields
}

// ApplyToObjectMeta applies any pending dirty overrides onto a decoded metav1.ObjectMeta.
func (m *WireObjectMeta) ApplyToObjectMeta(meta *metav1.ObjectMeta) {
	if m == nil || m.dirty == 0 {
		return
	}
	if m.dirty&dirtyMetaName != 0 {
		meta.Name = m.name
	}
	if m.dirty&dirtyMetaGenerateName != 0 {
		meta.GenerateName = m.generateName
	}
	if m.dirty&dirtyMetaNamespace != 0 {
		meta.Namespace = m.namespace
	}
	if m.dirty&dirtyMetaSelfLink != 0 {
		meta.SelfLink = m.selfLink
	}
	if m.dirty&dirtyMetaUID != 0 {
		meta.UID = m.uid
	}
	if m.dirty&dirtyMetaResourceVersion != 0 {
		meta.ResourceVersion = m.resourceVersion
	}
	if m.dirty&dirtyMetaGeneration != 0 {
		meta.Generation = m.generation
	}
	if m.dirty&dirtyMetaCreationTimestamp != 0 {
		meta.CreationTimestamp = m.creationTimestamp
	}
	if m.dirty&dirtyMetaDeletionTimestamp != 0 {
		if m.deletionTimestamp == nil {
			meta.DeletionTimestamp = nil
		} else {
			cp := *m.deletionTimestamp
			meta.DeletionTimestamp = &cp
		}
	}
	if m.dirty&dirtyMetaDeletionGracePeriodSeconds != 0 {
		if m.deletionGracePeriodSeconds == nil {
			meta.DeletionGracePeriodSeconds = nil
		} else {
			cp := *m.deletionGracePeriodSeconds
			meta.DeletionGracePeriodSeconds = &cp
		}
	}
	if m.dirty&dirtyMetaLabels != 0 {
		meta.Labels = maps.Clone(m.labels)
	}
	if m.dirty&dirtyMetaAnnotations != 0 {
		meta.Annotations = maps.Clone(m.annotations)
	}
	if m.dirty&dirtyMetaOwnerReferences != 0 {
		if m.ownerReferences == nil {
			meta.OwnerReferences = nil
		} else {
			meta.OwnerReferences = make([]metav1.OwnerReference, len(m.ownerReferences))
			for i := range m.ownerReferences {
				m.ownerReferences[i].DeepCopyInto(&meta.OwnerReferences[i])
			}
		}
	}
	if m.dirty&dirtyMetaFinalizers != 0 {
		meta.Finalizers = slices.Clone(m.finalizers)
	}
	if m.dirty&dirtyMetaManagedFields != 0 {
		if m.managedFields == nil {
			meta.ManagedFields = nil
		} else {
			meta.ManagedFields = make([]metav1.ManagedFieldsEntry, len(m.managedFields))
			for i := range m.managedFields {
				m.managedFields[i].DeepCopyInto(&meta.ManagedFields[i])
			}
		}
	}
}

// ExtractObjectMetaInto unmarshals only the ObjectMeta submessage and applies any dirty overrides.
func (m *WireObjectMeta) ExtractObjectMetaInto(metaBytes []byte, out *metav1.ObjectMeta) {
	*out = metav1.ObjectMeta{}
	if len(metaBytes) > 0 {
		_ = out.Unmarshal(metaBytes)
	}
	m.ApplyToObjectMeta(out)
}

// SpliceMetaFields splices any dirty ObjectMeta overrides into metaBytes in canonical protobuf tag order.
func (m *WireObjectMeta) SpliceMetaFields(metaBytes []byte) []byte {
	if m == nil || m.dirty == 0 {
		return metaBytes
	}
	out := make([]byte, 0, len(metaBytes)+64)
	emitted := uint16(0)

	emitDirtyUpTo := func(limitNum protowire.Number) {
		if m.dirty&dirtyMetaName != 0 && emitted&dirtyMetaName == 0 && limitNum >= MetaFieldName {
			out = protowire.AppendTag(out, MetaFieldName, protowire.BytesType)
			out = protowire.AppendString(out, m.name)
			emitted |= dirtyMetaName
		}
		if m.dirty&dirtyMetaGenerateName != 0 && emitted&dirtyMetaGenerateName == 0 && limitNum >= MetaFieldGenerateName {
			out = protowire.AppendTag(out, MetaFieldGenerateName, protowire.BytesType)
			out = protowire.AppendString(out, m.generateName)
			emitted |= dirtyMetaGenerateName
		}
		if m.dirty&dirtyMetaNamespace != 0 && emitted&dirtyMetaNamespace == 0 && limitNum >= MetaFieldNamespace {
			out = protowire.AppendTag(out, MetaFieldNamespace, protowire.BytesType)
			out = protowire.AppendString(out, m.namespace)
			emitted |= dirtyMetaNamespace
		}
		if m.dirty&dirtyMetaSelfLink != 0 && emitted&dirtyMetaSelfLink == 0 && limitNum >= MetaFieldSelfLink {
			out = protowire.AppendTag(out, MetaFieldSelfLink, protowire.BytesType)
			out = protowire.AppendString(out, m.selfLink)
			emitted |= dirtyMetaSelfLink
		}
		if m.dirty&dirtyMetaUID != 0 && emitted&dirtyMetaUID == 0 && limitNum >= MetaFieldUID {
			out = protowire.AppendTag(out, MetaFieldUID, protowire.BytesType)
			out = protowire.AppendString(out, string(m.uid))
			emitted |= dirtyMetaUID
		}
		if m.dirty&dirtyMetaResourceVersion != 0 && emitted&dirtyMetaResourceVersion == 0 && limitNum >= MetaFieldResourceVersion {
			out = protowire.AppendTag(out, MetaFieldResourceVersion, protowire.BytesType)
			out = protowire.AppendString(out, m.resourceVersion)
			emitted |= dirtyMetaResourceVersion
		}
		if m.dirty&dirtyMetaGeneration != 0 && emitted&dirtyMetaGeneration == 0 && limitNum >= MetaFieldGeneration {
			out = protowire.AppendTag(out, MetaFieldGeneration, protowire.VarintType)
			out = protowire.AppendVarint(out, uint64(m.generation))
			emitted |= dirtyMetaGeneration
		}
		if m.dirty&dirtyMetaCreationTimestamp != 0 && emitted&dirtyMetaCreationTimestamp == 0 && limitNum >= MetaFieldCreationTimestamp {
			out = AppendTimestamp(out, MetaFieldCreationTimestamp, m.creationTimestamp)
			emitted |= dirtyMetaCreationTimestamp
		}
		if m.dirty&dirtyMetaDeletionTimestamp != 0 && emitted&dirtyMetaDeletionTimestamp == 0 && limitNum >= MetaFieldDeletionTimestamp {
			if m.deletionTimestamp != nil {
				out = AppendTimestamp(out, MetaFieldDeletionTimestamp, *m.deletionTimestamp)
			}
			emitted |= dirtyMetaDeletionTimestamp
		}
		if m.dirty&dirtyMetaDeletionGracePeriodSeconds != 0 && emitted&dirtyMetaDeletionGracePeriodSeconds == 0 && limitNum >= MetaFieldDeletionGracePeriodSeconds {
			if m.deletionGracePeriodSeconds != nil {
				out = protowire.AppendTag(out, MetaFieldDeletionGracePeriodSeconds, protowire.VarintType)
				out = protowire.AppendVarint(out, uint64(*m.deletionGracePeriodSeconds))
			}
			emitted |= dirtyMetaDeletionGracePeriodSeconds
		}
		if m.dirty&dirtyMetaLabels != 0 && emitted&dirtyMetaLabels == 0 && limitNum >= MetaFieldLabels {
			out = AppendSortedMapField(out, MetaFieldLabels, m.labels)
			emitted |= dirtyMetaLabels
		}
		if m.dirty&dirtyMetaAnnotations != 0 && emitted&dirtyMetaAnnotations == 0 && limitNum >= MetaFieldAnnotations {
			out = AppendSortedMapField(out, MetaFieldAnnotations, m.annotations)
			emitted |= dirtyMetaAnnotations
		}
		if m.dirty&dirtyMetaOwnerReferences != 0 && emitted&dirtyMetaOwnerReferences == 0 && limitNum >= MetaFieldOwnerReferences {
			for i := range m.ownerReferences {
				if b, err := m.ownerReferences[i].Marshal(); err == nil {
					out = protowire.AppendTag(out, MetaFieldOwnerReferences, protowire.BytesType)
					out = protowire.AppendBytes(out, b)
				}
			}
			emitted |= dirtyMetaOwnerReferences
		}
		if m.dirty&dirtyMetaFinalizers != 0 && emitted&dirtyMetaFinalizers == 0 && limitNum >= MetaFieldFinalizers {
			for _, f := range m.finalizers {
				out = protowire.AppendTag(out, MetaFieldFinalizers, protowire.BytesType)
				out = protowire.AppendString(out, f)
			}
			emitted |= dirtyMetaFinalizers
		}
		if m.dirty&dirtyMetaManagedFields != 0 && emitted&dirtyMetaManagedFields == 0 && limitNum >= MetaFieldManagedFields {
			for i := range m.managedFields {
				if b, err := m.managedFields[i].Marshal(); err == nil {
					out = protowire.AppendTag(out, MetaFieldManagedFields, protowire.BytesType)
					out = protowire.AppendBytes(out, b)
				}
			}
			emitted |= dirtyMetaManagedFields
		}
	}

	offset := 0
	for offset < len(metaBytes) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(metaBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, metaBytes[offset:])
		if valLen < 0 {
			break
		}
		offset += valLen

		emitDirtyUpTo(num)

		if (num == MetaFieldName && m.dirty&dirtyMetaName != 0) ||
			(num == MetaFieldGenerateName && m.dirty&dirtyMetaGenerateName != 0) ||
			(num == MetaFieldNamespace && m.dirty&dirtyMetaNamespace != 0) ||
			(num == MetaFieldSelfLink && m.dirty&dirtyMetaSelfLink != 0) ||
			(num == MetaFieldUID && m.dirty&dirtyMetaUID != 0) ||
			(num == MetaFieldResourceVersion && m.dirty&dirtyMetaResourceVersion != 0) ||
			(num == MetaFieldGeneration && m.dirty&dirtyMetaGeneration != 0) ||
			(num == MetaFieldCreationTimestamp && m.dirty&dirtyMetaCreationTimestamp != 0) ||
			(num == MetaFieldDeletionTimestamp && m.dirty&dirtyMetaDeletionTimestamp != 0) ||
			(num == MetaFieldDeletionGracePeriodSeconds && m.dirty&dirtyMetaDeletionGracePeriodSeconds != 0) ||
			(num == MetaFieldLabels && m.dirty&dirtyMetaLabels != 0) ||
			(num == MetaFieldAnnotations && m.dirty&dirtyMetaAnnotations != 0) ||
			(num == MetaFieldOwnerReferences && m.dirty&dirtyMetaOwnerReferences != 0) ||
			(num == MetaFieldFinalizers && m.dirty&dirtyMetaFinalizers != 0) ||
			(num == MetaFieldManagedFields && m.dirty&dirtyMetaManagedFields != 0) {
			continue
		}
		out = append(out, metaBytes[fieldStart:offset]...)
	}

	emitDirtyUpTo(protowire.MaxValidNumber)
	return out
}

// SpliceIntoRaw splices pending ObjectMeta mutations into the top-level resource wire bytes raw
// and clears the dirty bitmask.
func (m *WireObjectMeta) SpliceIntoRaw(raw []byte) []byte {
	if m == nil || m.dirty == 0 {
		return raw
	}
	offset := 0
	for offset < len(raw) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(raw[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, raw[offset:])
		if valLen < 0 {
			break
		}
		valBytes := raw[offset : offset+valLen]
		offset += valLen

		if num == MetadataFieldNumber && typ == protowire.BytesType {
			metaContent, _ := protowire.ConsumeBytes(valBytes)
			newMeta := m.SpliceMetaFields(metaContent)
			out := make([]byte, 0, len(raw)-valLen+len(newMeta)+16)
			out = append(out, raw[:fieldStart]...)
			out = protowire.AppendTag(out, MetadataFieldNumber, protowire.BytesType)
			out = protowire.AppendBytes(out, newMeta)
			out = append(out, raw[offset:]...)
			m.ClearDirty()
			return out
		}
	}

	newMeta := m.SpliceMetaFields(nil)
	out := make([]byte, 0, len(raw)+len(newMeta)+16)
	out = protowire.AppendTag(out, MetadataFieldNumber, protowire.BytesType)
	out = protowire.AppendBytes(out, newMeta)
	out = append(out, raw...)
	m.ClearDirty()
	return out
}

type rvSpliceOffsets struct {
	foundMeta      bool
	metaFieldStart int
	metaFieldEnd   int
	metaContent    []byte
	rvStart        int
	rvEnd          int
	newMetaLen     int
}

func (m *WireObjectMeta) computeRVSpliceOffsets(raw []byte) rvSpliceOffsets {
	offset := 0
	for offset < len(raw) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(raw[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, raw[offset:])
		if valLen < 0 {
			break
		}
		valBytes := raw[offset : offset+valLen]
		offset += valLen

		if num == MetadataFieldNumber && typ == protowire.BytesType {
			metaContent, _ := protowire.ConsumeBytes(valBytes)
			rvStart, rvEnd := findMetaRVSpan(metaContent)
			newRVFieldLen := 1 + protowire.SizeBytes(len(m.resourceVersion))
			newMetaLen := len(metaContent) - (rvEnd - rvStart) + newRVFieldLen
			return rvSpliceOffsets{
				foundMeta:      true,
				metaFieldStart: fieldStart,
				metaFieldEnd:   offset,
				metaContent:    metaContent,
				rvStart:        rvStart,
				rvEnd:          rvEnd,
				newMetaLen:     newMetaLen,
			}
		}
	}

	newRVFieldLen := 1 + protowire.SizeBytes(len(m.resourceVersion))
	return rvSpliceOffsets{
		foundMeta:  false,
		newMetaLen: newRVFieldLen,
	}
}

func findMetaRVSpan(metaBytes []byte) (int, int) {
	offset := 0
	for offset < len(metaBytes) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(metaBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, metaBytes[offset:])
		if valLen < 0 {
			break
		}
		offset += valLen

		if num == MetaFieldResourceVersion && typ == protowire.BytesType {
			return fieldStart, offset
		}
		if num > MetaFieldResourceVersion {
			return fieldStart, fieldStart
		}
	}
	return len(metaBytes), len(metaBytes)
}

// SerializedSize returns the exact protobuf wire size of raw after applying any pending
// ObjectMeta mutations, returning a possibly-updated raw slice when general meta fields are spliced.
func (m *WireObjectMeta) SerializedSize(raw []byte) ([]byte, int) {
	if m.dirty == 0 {
		return raw, len(raw)
	}
	if m.dirty == dirtyMetaResourceVersion {
		loc := m.computeRVSpliceOffsets(raw)
		newMetaFieldLen := 1 + protowire.SizeBytes(loc.newMetaLen)
		if !loc.foundMeta {
			return raw, newMetaFieldLen + len(raw)
		}
		return raw, loc.metaFieldStart + newMetaFieldLen + (len(raw) - loc.metaFieldEnd)
	}
	updated := m.SpliceIntoRaw(raw)
	return updated, len(updated)
}

// MarshalToSizedBuffer writes raw with any pending ObjectMeta mutations to the end of dAtA,
// splicing resourceVersion directly into dAtA without intermediate heap allocations.
func (m *WireObjectMeta) MarshalToSizedBuffer(dAtA []byte, raw []byte) ([]byte, int, error) {
	if m.dirty == 0 {
		n := len(raw)
		copy(dAtA[len(dAtA)-n:], raw)
		return raw, n, nil
	}
	if m.dirty == dirtyMetaResourceVersion {
		loc := m.computeRVSpliceOffsets(raw)
		newMetaFieldLen := 1 + protowire.SizeBytes(loc.newMetaLen)
		var totalSize int
		if !loc.foundMeta {
			totalSize = newMetaFieldLen + len(raw)
		} else {
			totalSize = loc.metaFieldStart + newMetaFieldLen + (len(raw) - loc.metaFieldEnd)
		}

		dst := dAtA[len(dAtA)-totalSize : len(dAtA)-totalSize]
		if loc.foundMeta {
			dst = append(dst, raw[:loc.metaFieldStart]...)
			dst = protowire.AppendTag(dst, MetadataFieldNumber, protowire.BytesType)
			dst = protowire.AppendVarint(dst, uint64(loc.newMetaLen))
			dst = append(dst, loc.metaContent[:loc.rvStart]...)
			dst = protowire.AppendTag(dst, MetaFieldResourceVersion, protowire.BytesType)
			dst = protowire.AppendString(dst, m.resourceVersion)
			dst = append(dst, loc.metaContent[loc.rvEnd:]...)
			dst = append(dst, raw[loc.metaFieldEnd:]...)
		} else {
			dst = protowire.AppendTag(dst, MetadataFieldNumber, protowire.BytesType)
			dst = protowire.AppendVarint(dst, uint64(loc.newMetaLen))
			dst = protowire.AppendTag(dst, MetaFieldResourceVersion, protowire.BytesType)
			dst = protowire.AppendString(dst, m.resourceVersion)
			dst = append(dst, raw...)
		}
		return raw, totalSize, nil
	}

	updated := m.SpliceIntoRaw(raw)
	n := len(updated)
	copy(dAtA[len(dAtA)-n:], updated)
	return updated, n, nil
}


// SubMessage returns the payload of the first length-delimited field with tag topField in raw.
func SubMessage(raw []byte, topField protowire.Number) []byte {
	offset := 0
	for offset < len(raw) {
		num, typ, tagLen := protowire.ConsumeTag(raw[offset:])
		if tagLen < 0 {
			return nil
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, raw[offset:])
		if valLen < 0 {
			return nil
		}
		if num == topField && typ == protowire.BytesType {
			content, _ := protowire.ConsumeBytes(raw[offset : offset+valLen])
			return content
		}
		offset += valLen
	}
	return nil
}

// ExtractFirstStringField returns a heap-allocated string for the first occurrence of targetNum in msg.
func ExtractFirstStringField(msg []byte, targetNum protowire.Number) string {
	offset := 0
	for offset < len(msg) {
		num, typ, tagLen := protowire.ConsumeTag(msg[offset:])
		if tagLen < 0 {
			return ""
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, msg[offset:])
		if valLen < 0 {
			return ""
		}
		if num == targetNum && typ == protowire.BytesType {
			s, _ := protowire.ConsumeString(msg[offset : offset+valLen])
			return s
		}
		offset += valLen
	}
	return ""
}

// ConsumeStringNoCopy returns a zero-copy string view over a length-delimited field value.
func ConsumeStringNoCopy(valBytes []byte) string {
	b, n := protowire.ConsumeBytes(valBytes)
	if n < 0 || len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// ExtractFirstStringFieldNoCopy returns a zero-copy string view for the first occurrence of targetNum in msg.
func ExtractFirstStringFieldNoCopy(msg []byte, targetNum protowire.Number) string {
	offset := 0
	for offset < len(msg) {
		num, typ, tagLen := protowire.ConsumeTag(msg[offset:])
		if tagLen < 0 {
			return ""
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, msg[offset:])
		if valLen < 0 {
			return ""
		}
		if num == targetNum && typ == protowire.BytesType {
			return ConsumeStringNoCopy(msg[offset : offset+valLen])
		}
		offset += valLen
	}
	return ""
}

// ExtractVarintField returns the varint value for the first occurrence of targetNum in msg, or 0.
func ExtractVarintField(msg []byte, targetNum protowire.Number) uint64 {
	v, _ := ExtractOptionalVarintField(msg, targetNum)
	return v
}

// ExtractOptionalVarintField returns the varint value and presence boolean for targetNum in msg.
func ExtractOptionalVarintField(msg []byte, targetNum protowire.Number) (uint64, bool) {
	offset := 0
	for offset < len(msg) {
		num, typ, tagLen := protowire.ConsumeTag(msg[offset:])
		if tagLen < 0 {
			return 0, false
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, msg[offset:])
		if valLen < 0 {
			return 0, false
		}
		if num == targetNum && typ == protowire.VarintType {
			v, _ := protowire.ConsumeVarint(msg[offset : offset+valLen])
			return v, true
		}
		offset += valLen
	}
	return 0, false
}

// ExtractMapField extracts a protobuf map<string, string> field from msg.
func ExtractMapField(msg []byte, targetNum protowire.Number) map[string]string {
	var res map[string]string
	offset := 0
	for offset < len(msg) {
		num, typ, tagLen := protowire.ConsumeTag(msg[offset:])
		if tagLen < 0 {
			return res
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, msg[offset:])
		if valLen < 0 {
			return res
		}
		if num == targetNum && typ == protowire.BytesType {
			entry, _ := protowire.ConsumeBytes(msg[offset : offset+valLen])
			k := ExtractFirstStringField(entry, MapEntryKeyFieldNumber)
			v := ExtractFirstStringField(entry, MapEntryValueFieldNumber)
			if res == nil {
				res = make(map[string]string)
			}
			res[k] = v
		}
		offset += valLen
	}
	return res
}

// ExtractStringSliceField extracts a repeated string field from msg.
func ExtractStringSliceField(msg []byte, targetNum protowire.Number) []string {
	var res []string
	offset := 0
	for offset < len(msg) {
		num, typ, tagLen := protowire.ConsumeTag(msg[offset:])
		if tagLen < 0 {
			return res
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, msg[offset:])
		if valLen < 0 {
			return res
		}
		if num == targetNum && typ == protowire.BytesType {
			s, _ := protowire.ConsumeString(msg[offset : offset+valLen])
			res = append(res, s)
		}
		offset += valLen
	}
	return res
}

// HasField reports whether msg contains at least one field with tag targetNum.
func HasField(msg []byte, targetNum protowire.Number) bool {
	offset := 0
	for offset < len(msg) {
		num, typ, tagLen := protowire.ConsumeTag(msg[offset:])
		if tagLen < 0 {
			return false
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, msg[offset:])
		if valLen < 0 {
			return false
		}
		if num == targetNum {
			return true
		}
		offset += valLen
	}
	return false
}

// AppendSortedMapField appends a protobuf map<string, string> in deterministic key order.
func AppendSortedMapField(out []byte, fieldNum protowire.Number, m map[string]string) []byte {
	if len(m) == 0 {
		return out
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		var entry []byte
		entry = protowire.AppendTag(entry, MapEntryKeyFieldNumber, protowire.BytesType)
		entry = protowire.AppendString(entry, k)
		entry = protowire.AppendTag(entry, MapEntryValueFieldNumber, protowire.BytesType)
		entry = protowire.AppendString(entry, m[k])
		out = protowire.AppendTag(out, fieldNum, protowire.BytesType)
		out = protowire.AppendBytes(out, entry)
	}
	return out
}

// ParseTimestamp decodes a metav1.Time protobuf message (tag 1 = seconds, tag 2 = nanos).
func ParseTimestamp(tsBytes []byte) metav1.Time {
	var sec int64
	var nsec int32
	offset := 0
	for offset < len(tsBytes) {
		num, typ, tagLen := protowire.ConsumeTag(tsBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, tsBytes[offset:])
		if valLen < 0 {
			break
		}
		if typ == protowire.VarintType {
			v, _ := protowire.ConsumeVarint(tsBytes[offset : offset+valLen])
			switch num {
			case 1:
				sec = int64(v)
			case 2:
				nsec = int32(v)
			}
		}
		offset += valLen
	}
	if sec == 0 && nsec == 0 {
		return metav1.Time{}
	}
	return metav1.Time{Time: time.Unix(sec, int64(nsec)).Local()}
}

// AppendTimestamp appends a metav1.Time protobuf submessage with tag fieldNum.
func AppendTimestamp(out []byte, fieldNum protowire.Number, ts metav1.Time) []byte {
	b, err := ts.Marshal()
	if err != nil {
		return out
	}
	out = protowire.AppendTag(out, fieldNum, protowire.BytesType)
	out = protowire.AppendBytes(out, b)
	return out
}

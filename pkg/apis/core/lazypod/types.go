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

package lazypod

import (
	"bytes"
	stdjson "encoding/json"
	"fmt"
	"maps"
	"slices"
	"unsafe"

	"github.com/gogo/protobuf/proto"
	"google.golang.org/protobuf/encoding/protowire"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	cbordirect "k8s.io/apimachinery/pkg/runtime/serializer/cbor/direct"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/kubernetes/pkg/apis/core"
	corev1 "k8s.io/kubernetes/pkg/apis/core/v1"
)

// ============================================================================
// External v1 Lazy Pod & PodList
// ============================================================================

// V1Pod is a lazy wrapper for v1.Pod that defers Protobuf unmarshaling of Spec and Status
// while supporting wire-level defaulting, O(1) conversion to internal Pod, and zero-reencode
// Protobuf/JSON serialization.
//
// +k8s:deepcopy-gen=false
type V1Pod struct {
	metav1.TypeMeta `json:",inline"`
	wire            *WirePod
	wireOwn         *V1Pod
	wireCanCache    bool
	decoded         *v1.Pod
}

var (
	_ runtime.Object                    = (*V1Pod)(nil)
	_ runtime.LazyObject                = (*V1Pod)(nil)
	_ metav1.Object                     = (*V1Pod)(nil)
	_ metav1.ObjectMetaAccessor         = (*V1Pod)(nil)
	_ proto.Message                     = (*V1Pod)(nil)
	_ runtime.ProtobufReverseMarshaller = (*V1Pod)(nil)
	_ stdjson.Marshaler                 = (*V1Pod)(nil)
	_ stdjson.Unmarshaler               = (*V1Pod)(nil)
)

// NewV1PodFromWire creates a lazy V1Pod backed by raw Protobuf bytes.
func NewV1PodFromWire(raw []byte) *V1Pod {
	p := &V1Pod{wire: NewWirePod(raw)}
	p.wireOwn = p
	return p
}

// NewV1PodFromDecoded creates a V1Pod backed by an eagerly decoded *v1.Pod.
func NewV1PodFromDecoded(pod *v1.Pod) *V1Pod {
	var tm metav1.TypeMeta
	if pod != nil {
		tm = pod.TypeMeta
	}
	return &V1Pod{TypeMeta: tm, decoded: pod}
}

// IsLazy reports whether the V1Pod is currently backed by unparsed wire bytes.
func (p *V1Pod) IsLazy() bool {
	return p.wire != nil && p.decoded == nil
}

// IsDecoded implements runtime.LazyObject.
func (p *V1Pod) IsDecoded() bool {
	return p.decoded != nil
}

// Wire returns the underlying WirePod if present.
func (p *V1Pod) Wire() *WirePod {
	return p.wire
}

// EnsureDecoded decodes the underlying wire bytes into a *v1.Pod if not already decoded.
func (p *V1Pod) EnsureDecoded() (*v1.Pod, error) {
	if p.decoded != nil {
		return p.decoded, nil
	}
	if p.wire == nil {
		p.decoded = &v1.Pod{TypeMeta: p.TypeMeta}
		return p.decoded, nil
	}
	v1Pod, err := p.wire.DecodeToV1Pod()
	if err != nil {
		return nil, err
	}
	v1Pod.TypeMeta = p.TypeMeta
	p.decoded = v1Pod
	p.wire = nil
	p.wireOwn = nil
	p.wireCanCache = false
	return p.decoded, nil
}

// EnsureDecodedObject implements runtime.LazyObject.
func (p *V1Pod) EnsureDecodedObject() (runtime.Object, error) {
	return p.EnsureDecoded()
}

func (p *V1Pod) mustDecoded() *v1.Pod {
	dec, err := p.EnsureDecoded()
	if err != nil {
		panic(fmt.Sprintf("lazypod.V1Pod: failed to decode wire bytes: %v", err))
	}
	return dec
}

// GetObjectKind implements runtime.Object.
func (p *V1Pod) GetObjectKind() schema.ObjectKind {
	if p.decoded != nil {
		return &p.decoded.TypeMeta
	}
	return &p.TypeMeta
}

// DeepCopyObject implements runtime.Object.
func (p *V1Pod) DeepCopyObject() runtime.Object {
	return p.DeepCopy()
}

// DeepCopy returns a deep copy of V1Pod, cloning only the wire bytes when lazy.
func (p *V1Pod) DeepCopy() *V1Pod {
	if p == nil {
		return nil
	}
	out := &V1Pod{TypeMeta: p.TypeMeta}
	if p.decoded != nil {
		out.decoded = p.decoded.DeepCopy()
		return out
	}
	if p.wire != nil {
		if p.wireOwn == p {
			p.wire.DisownCachedMeta()
		}
		out.wire = p.wire.Clone()
		out.wireOwn = out
	}
	return out
}

// Protobuf interface implementation (proto.Message + gogo Unmarshal/Marshal/MarshalToSizedBuffer/Size)

func (p *V1Pod) Reset()         { *p = V1Pod{} }
func (p *V1Pod) String() string { return "lazypod.V1Pod" }
func (p *V1Pod) ProtoMessage()  {}

// Unmarshal captures raw Protobuf wire bytes into a lazy WirePod without decoding Spec/Status.
func (p *V1Pod) Unmarshal(dAtA []byte) error {
	rawCopy := make([]byte, len(dAtA))
	copy(rawCopy, dAtA)
	p.decoded = nil
	p.wireCanCache = false
	if p.wire == nil || p.wireOwn != p {
		p.wire = NewWirePod(rawCopy)
		p.wireOwn = p
	} else {
		p.wire.Reset(rawCopy)
	}
	return nil
}

// Size returns the exact Protobuf wire size of the V1Pod.
func (p *V1Pod) Size() int {
	if p.decoded != nil {
		return p.decoded.Size()
	}
	if p.wire != nil {
		return p.wire.SerializedSize()
	}
	return 0
}

// Marshal serializes V1Pod into Protobuf wire bytes.
func (p *V1Pod) Marshal() ([]byte, error) {
	if p.decoded != nil {
		return p.decoded.Marshal()
	}
	if p.wire != nil {
		dAtA := make([]byte, p.wire.SerializedSize())
		n, err := p.wire.MarshalToSizedBuffer(dAtA)
		if err != nil {
			return nil, err
		}
		return dAtA[len(dAtA)-n:], nil
	}
	return nil, nil
}

// MarshalTo serializes V1Pod into dAtA.
func (p *V1Pod) MarshalTo(dAtA []byte) (int, error) {
	size := p.Size()
	return p.MarshalToSizedBuffer(dAtA[:size])
}

// MarshalToSizedBuffer writes V1Pod to the end of dAtA without decoding when in lazy wire mode.
func (p *V1Pod) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	if p.decoded != nil {
		return p.decoded.MarshalToSizedBuffer(dAtA)
	}
	if p.wire != nil {
		return p.wire.MarshalToSizedBuffer(dAtA)
	}
	return 0, nil
}

// MarshalJSON implements json.Marshaler.
func (p *V1Pod) MarshalJSON() ([]byte, error) {
	dec, err := p.EnsureDecoded()
	if err != nil {
		return nil, err
	}
	return json.Marshal(dec)
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *V1Pod) UnmarshalJSON(data []byte) error {
	pod := &v1.Pod{}
	if err := json.Unmarshal(data, pod); err != nil {
		return err
	}
	p.TypeMeta = pod.TypeMeta
	p.decoded = pod
	p.wire = nil
	p.wireOwn = nil
	p.wireCanCache = false
	return nil
}

// MarshalCBOR implements cbor.Marshaler.
func (p *V1Pod) MarshalCBOR() ([]byte, error) {
	dec, err := p.EnsureDecoded()
	if err != nil {
		return nil, err
	}
	return cbordirect.Marshal(dec)
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (p *V1Pod) UnmarshalCBOR(data []byte) error {
	pod := &v1.Pod{}
	if err := cbordirect.Unmarshal(data, pod); err != nil {
		return err
	}
	p.TypeMeta = pod.TypeMeta
	p.decoded = pod
	p.wire = nil
	p.wireOwn = nil
	p.wireCanCache = false
	return nil
}

// GetObjectMeta implements metav1.ObjectMetaAccessor.
func (p *V1Pod) GetObjectMeta() metav1.Object {
	if p.decoded != nil {
		return &p.decoded.ObjectMeta
	}
	return p
}

func (p *V1Pod) canCache() bool {
	return p.wireOwn == p || p.wireCanCache
}

// ExtractObjectMetaInto populates out from the wire without full pod decoding.
func (p *V1Pod) ExtractObjectMetaInto(out *metav1.ObjectMeta) {
	if p.decoded != nil {
		p.decoded.ObjectMeta.DeepCopyInto(out)
		return
	}
	if p.wire != nil {
		p.wire.ExtractObjectMetaForUpdate(out, false)
	}
}

// BorrowObjectMetaInto populates out for read-only callers without DeepCopying maps/slices when clean.
func (p *V1Pod) BorrowObjectMetaInto(out *metav1.ObjectMeta, dropManagedFields bool) {
	if p.decoded != nil {
		*out = p.decoded.ObjectMeta
		if dropManagedFields {
			out.ManagedFields = nil
		}
		return
	}
	if p.wire != nil {
		p.wire.BorrowObjectMetaInto(out, dropManagedFields, p.canCache())
	}
}

func (p *V1Pod) ensureWire() *WirePod {
	if p.wire == nil {
		p.wire = NewWirePod(nil)
		p.wireOwn = p
		p.wireCanCache = false
		return p.wire
	}
	if p.wireOwn != p {
		p.wire = p.wire.Clone()
		p.wireOwn = p
		p.wireCanCache = false
	}
	return p.wire
}

func (p *V1Pod) ensureWireForMetaEdit() *WirePod {
	w := p.ensureWire()
	w.MarkNonManagedMetaDirty()
	return w
}

func (p *V1Pod) GetNamespace() string {
	if p.decoded != nil {
		return p.decoded.Namespace
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.Namespace
		}
		return p.wire.meta.GetNamespace()
	}
	return ""
}
func (p *V1Pod) SetNamespace(namespace string) {
	if p.decoded != nil {
		p.decoded.Namespace = namespace
		return
	}
	p.ensureWireForMetaEdit().meta.SetNamespace(namespace)
}
func (p *V1Pod) GetName() string {
	if p.decoded != nil {
		return p.decoded.Name
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.Name
		}
		return p.wire.meta.GetName()
	}
	return ""
}
func (p *V1Pod) SetName(name string) {
	if p.decoded != nil {
		p.decoded.Name = name
		return
	}
	p.ensureWireForMetaEdit().meta.SetName(name)
}
func (p *V1Pod) GetGenerateName() string {
	if p.decoded != nil {
		return p.decoded.GenerateName
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.GenerateName
		}
		return p.wire.meta.GetGenerateName()
	}
	return ""
}
func (p *V1Pod) SetGenerateName(name string) {
	if p.decoded != nil {
		p.decoded.GenerateName = name
		return
	}
	p.ensureWireForMetaEdit().meta.SetGenerateName(name)
}
func (p *V1Pod) GetUID() types.UID {
	if p.decoded != nil {
		return p.decoded.UID
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.UID
		}
		return p.wire.meta.GetUID()
	}
	return ""
}
func (p *V1Pod) SetUID(uid types.UID) {
	if p.decoded != nil {
		p.decoded.UID = uid
		return
	}
	p.ensureWireForMetaEdit().meta.SetUID(uid)
}
func (p *V1Pod) GetResourceVersion() string {
	if p.decoded != nil {
		return p.decoded.ResourceVersion
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.ResourceVersion
		}
		return p.wire.meta.GetResourceVersion()
	}
	return ""
}
func (p *V1Pod) SetResourceVersion(version string) {
	if p.decoded != nil {
		p.decoded.ResourceVersion = version
		return
	}
	p.ensureWire().SetResourceVersion(version)
}
func (p *V1Pod) GetGeneration() int64 {
	if p.decoded != nil {
		return p.decoded.Generation
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.Generation
		}
		return p.wire.meta.GetGeneration()
	}
	return 0
}
func (p *V1Pod) SetGeneration(generation int64) {
	if p.decoded != nil {
		p.decoded.Generation = generation
		return
	}
	p.ensureWireForMetaEdit().meta.SetGeneration(generation)
}
func (p *V1Pod) GetSelfLink() string {
	if p.decoded != nil {
		return p.decoded.SelfLink
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.SelfLink
		}
		return p.wire.meta.GetSelfLink()
	}
	return ""
}
func (p *V1Pod) SetSelfLink(selfLink string) {
	if p.decoded != nil {
		p.decoded.SelfLink = selfLink
		return
	}
	p.ensureWireForMetaEdit().meta.SetSelfLink(selfLink)
}
func (p *V1Pod) GetCreationTimestamp() metav1.Time {
	if p.decoded != nil {
		return p.decoded.CreationTimestamp
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.CreationTimestamp
		}
		return p.wire.meta.GetCreationTimestamp()
	}
	return metav1.Time{}
}
func (p *V1Pod) SetCreationTimestamp(timestamp metav1.Time) {
	if p.decoded != nil {
		p.decoded.CreationTimestamp = timestamp
		return
	}
	p.ensureWireForMetaEdit().meta.SetCreationTimestamp(timestamp)
}
func (p *V1Pod) GetDeletionTimestamp() *metav1.Time {
	if p.decoded != nil {
		return p.decoded.DeletionTimestamp
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.DeletionTimestamp
		}
		return p.wire.meta.GetDeletionTimestamp()
	}
	return nil
}
func (p *V1Pod) SetDeletionTimestamp(timestamp *metav1.Time) {
	if p.decoded != nil {
		p.decoded.DeletionTimestamp = timestamp
		return
	}
	p.ensureWireForMetaEdit().meta.SetDeletionTimestamp(timestamp)
}
func (p *V1Pod) GetDeletionGracePeriodSeconds() *int64 {
	if p.decoded != nil {
		return p.decoded.DeletionGracePeriodSeconds
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.DeletionGracePeriodSeconds
		}
		return p.wire.meta.GetDeletionGracePeriodSeconds()
	}
	return nil
}
func (p *V1Pod) SetDeletionGracePeriodSeconds(gracePeriodSeconds *int64) {
	if p.decoded != nil {
		p.decoded.DeletionGracePeriodSeconds = gracePeriodSeconds
		return
	}
	p.ensureWireForMetaEdit().meta.SetDeletionGracePeriodSeconds(gracePeriodSeconds)
}
func (p *V1Pod) GetLabels() map[string]string {
	if p.decoded != nil {
		return p.decoded.Labels
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			if p.wireOwn == p && p.wire.IsCachedMetaOwned() {
				return cm.Labels
			}
			return maps.Clone(cm.Labels)
		}
		return p.wire.meta.GetLabels()
	}
	return nil
}
func (p *V1Pod) SetLabels(labels map[string]string) {
	if p.decoded != nil {
		p.decoded.Labels = labels
		return
	}
	p.ensureWireForMetaEdit().meta.SetLabels(labels)
}
func (p *V1Pod) GetAnnotations() map[string]string {
	if p.decoded != nil {
		return p.decoded.Annotations
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			if p.wireOwn == p && p.wire.IsCachedMetaOwned() {
				return cm.Annotations
			}
			return maps.Clone(cm.Annotations)
		}
		return p.wire.meta.GetAnnotations()
	}
	return nil
}
func (p *V1Pod) SetAnnotations(annotations map[string]string) {
	if p.decoded != nil {
		p.decoded.Annotations = annotations
		return
	}
	p.ensureWireForMetaEdit().meta.SetAnnotations(annotations)
}
func (p *V1Pod) GetFinalizers() []string {
	if p.decoded != nil {
		return p.decoded.Finalizers
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.Finalizers
		}
		return p.wire.meta.GetFinalizers()
	}
	return nil
}
func (p *V1Pod) SetFinalizers(finalizers []string) {
	if p.decoded != nil {
		p.decoded.Finalizers = finalizers
		return
	}
	p.ensureWireForMetaEdit().meta.SetFinalizers(finalizers)
}
func (p *V1Pod) GetOwnerReferences() []metav1.OwnerReference {
	if p.decoded != nil {
		return p.decoded.OwnerReferences
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.OwnerReferences
		}
		return p.wire.meta.GetOwnerReferences()
	}
	return nil
}
func (p *V1Pod) SetOwnerReferences(references []metav1.OwnerReference) {
	if p.decoded != nil {
		p.decoded.OwnerReferences = references
		return
	}
	p.ensureWireForMetaEdit().meta.SetOwnerReferences(references)
}
func (p *V1Pod) GetManagedFields() []metav1.ManagedFieldsEntry {
	if p.decoded != nil {
		return p.decoded.ManagedFields
	}
	if p.wire != nil {
		return p.wire.ManagedFields(p.canCache())
	}
	return nil
}
func (p *V1Pod) SetManagedFields(managedFields []metav1.ManagedFieldsEntry) {
	if p.decoded != nil {
		p.decoded.ManagedFields = managedFields
		return
	}
	p.ensureWire().SetManagedFields(managedFields)
}

// V1PodList is a lazy wrapper for v1.PodList that serializes and deserializes lazy V1Pod items
// without eagerly decoding them.
//
// +k8s:deepcopy-gen=false
type V1PodList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items           []V1Pod `json:"items" protobuf:"bytes,2,rep,name=items"`
}

var (
	_ runtime.Object                    = (*V1PodList)(nil)
	_ runtime.LazyObject                = (*V1PodList)(nil)
	_ metav1.ListInterface              = (*V1PodList)(nil)
	_ metav1.ListMetaAccessor           = (*V1PodList)(nil)
	_ proto.Message                     = (*V1PodList)(nil)
	_ runtime.ProtobufReverseMarshaller = (*V1PodList)(nil)
)

func (l *V1PodList) GetObjectKind() schema.ObjectKind { return &l.TypeMeta }
func (l *V1PodList) GetListMeta() metav1.ListInterface {
	return &l.ListMeta
}

func (l *V1PodList) IsDecoded() bool { return false }

func (l *V1PodList) EnsureDecodedObject() (runtime.Object, error) {
	out := &v1.PodList{
		TypeMeta: l.TypeMeta,
		ListMeta: l.ListMeta,
	}
	if l.Items != nil {
		out.Items = make([]v1.Pod, len(l.Items))
		for i := range l.Items {
			dec, err := l.Items[i].EnsureDecoded()
			if err != nil {
				return nil, err
			}
			out.Items[i] = *dec
		}
	}
	return out, nil
}

func (l *V1PodList) DeepCopyObject() runtime.Object {
	if l == nil {
		return nil
	}
	out := &V1PodList{
		TypeMeta: l.TypeMeta,
	}
	l.ListMeta.DeepCopyInto(&out.ListMeta)
	if l.Items != nil {
		out.Items = make([]V1Pod, len(l.Items))
		for i := range l.Items {
			out.Items[i] = *l.Items[i].DeepCopy()
		}
	}
	return out
}

func (l *V1PodList) Reset()         { *l = V1PodList{} }
func (l *V1PodList) String() string { return "lazypod.V1PodList" }
func (l *V1PodList) ProtoMessage()  {}

func (l *V1PodList) Size() int {
	n := 0
	l1 := l.ListMeta.Size()
	n += 1 + l1 + protowire.SizeVarint(uint64(l1))
	for i := range l.Items {
		l2 := l.Items[i].Size()
		n += 1 + l2 + protowire.SizeVarint(uint64(l2))
	}
	return n
}

func (l *V1PodList) Marshal() ([]byte, error) {
	dAtA := make([]byte, l.Size())
	n, err := l.MarshalToSizedBuffer(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (l *V1PodList) MarshalTo(dAtA []byte) (int, error) {
	size := l.Size()
	return l.MarshalToSizedBuffer(dAtA[:size])
}

func (l *V1PodList) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	for idx := len(l.Items) - 1; idx >= 0; idx-- {
		size, err := l.Items[idx].MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintPodList(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x12 // field 2 (items), wire type 2
	}
	{
		size, err := l.ListMeta.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintPodList(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x0a // field 1 (metadata), wire type 2
	}
	return len(dAtA) - i, nil
}

func encodeVarintPodList(dAtA []byte, offset int, v uint64) int {
	offset -= protowire.SizeVarint(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}

func (l *V1PodList) Unmarshal(dAtA []byte) error {
	l.Reset()
	offset := 0
	for offset < len(dAtA) {
		num, typ, tagLen := protowire.ConsumeTag(dAtA[offset:])
		if tagLen < 0 {
			return fmt.Errorf("lazypod.V1PodList: invalid tag")
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, dAtA[offset:])
		if valLen < 0 {
			return fmt.Errorf("lazypod.V1PodList: invalid field value")
		}
		if typ == protowire.BytesType {
			content, _ := protowire.ConsumeBytes(dAtA[offset : offset+valLen])
			switch num {
			case 1:
				if err := l.ListMeta.Unmarshal(content); err != nil {
					return err
				}
			case 2:
				var item V1Pod
				if err := item.Unmarshal(content); err != nil {
					return err
				}
				l.Items = append(l.Items, item)
			}
		}
		offset += valLen
	}
	return nil
}

// ============================================================================
// Internal Lazy Pod & PodList (implements core.PodAccessor & core.PodListAccessor)
// ============================================================================

// Pod is the internal lazy Pod representation. It holds either a lazy *WirePod
// or an eagerly decoded *core.Pod, implementing core.PodAccessor so cacher indexers,
// field selectors, table printers, and subresources operate without full struct decoding.
//
// +k8s:deepcopy-gen=false
type Pod struct {
	metav1.TypeMeta
	wire    *WirePod
	wireOwn *Pod
	decoded *core.Pod
}

var (
	_ runtime.Object            = (*Pod)(nil)
	_ runtime.LazyObject        = (*Pod)(nil)
	_ metav1.Object             = (*Pod)(nil)
	_ metav1.ObjectMetaAccessor = (*Pod)(nil)
	_ core.PodAccessor          = (*Pod)(nil)
)

// NewPodFromWire creates an internal lazy Pod backed by raw v1.Pod Protobuf bytes.
func NewPodFromWire(raw []byte) *Pod {
	p := &Pod{wire: NewWirePod(raw)}
	p.wireOwn = p
	return p
}

// NewPodFromDecoded creates an internal Pod backed by an eagerly decoded *core.Pod.
func NewPodFromDecoded(pod *core.Pod) *Pod {
	var tm metav1.TypeMeta
	if pod != nil {
		tm = pod.TypeMeta
	}
	return &Pod{TypeMeta: tm, decoded: pod}
}

// IsLazy reports whether the internal Pod is currently backed by unparsed wire bytes.
func (p *Pod) IsLazy() bool {
	return p.wire != nil && p.decoded == nil
}

// IsDecoded implements runtime.LazyObject.
func (p *Pod) IsDecoded() bool {
	return p.decoded != nil
}

// Wire returns the underlying WirePod if present.
func (p *Pod) Wire() *WirePod {
	return p.wire
}

// EnsureDecoded decodes the underlying wire bytes into a *core.Pod if not already decoded,
// using zero-copy layout casting between *v1.Pod and *core.Pod.
func (p *Pod) EnsureDecoded() (*core.Pod, error) {
	if p.decoded != nil {
		return p.decoded, nil
	}
	if p.wire == nil {
		p.decoded = &core.Pod{TypeMeta: p.TypeMeta}
		return p.decoded, nil
	}
	v1Pod, err := p.wire.DecodeToV1Pod()
	if err != nil {
		return nil, err
	}
	internalPod := (*core.Pod)(unsafe.Pointer(v1Pod))
	internalPod.TypeMeta = p.TypeMeta
	p.decoded = internalPod
	p.wire = nil
	p.wireOwn = nil
	return p.decoded, nil
}

// EnsureDecodedObject implements runtime.LazyObject.
func (p *Pod) EnsureDecodedObject() (runtime.Object, error) {
	return p.EnsureDecoded()
}

func (p *Pod) mustDecoded() *core.Pod {
	dec, err := p.EnsureDecoded()
	if err != nil {
		panic(fmt.Sprintf("lazypod.Pod: failed to decode wire bytes: %v", err))
	}
	return dec
}

// GetObjectKind implements runtime.Object.
func (p *Pod) GetObjectKind() schema.ObjectKind {
	if p.decoded != nil {
		return &p.decoded.TypeMeta
	}
	return &p.TypeMeta
}

// DeepCopyObject implements runtime.Object.
func (p *Pod) DeepCopyObject() runtime.Object {
	return p.DeepCopy()
}

// DeepCopy returns a deep copy of Pod, cloning only the wire bytes when lazy.
func (p *Pod) DeepCopy() *Pod {
	if p == nil {
		return nil
	}
	out := &Pod{TypeMeta: p.TypeMeta}
	if p.decoded != nil {
		out.decoded = p.decoded.DeepCopy()
		return out
	}
	if p.wire != nil {
		if p.wireOwn == p {
			p.wire.DisownCachedMeta()
		}
		out.wire = p.wire.Clone()
		out.wireOwn = out
	}
	return out
}

// GetObjectMeta implements metav1.ObjectMetaAccessor.
func (p *Pod) GetObjectMeta() metav1.Object {
	if p.decoded != nil {
		return &p.decoded.ObjectMeta
	}
	return p
}

// ExtractObjectMetaInto populates out from the wire without full pod decoding.
func (p *Pod) ExtractObjectMetaInto(out *metav1.ObjectMeta) {
	if p.decoded != nil {
		p.decoded.ObjectMeta.DeepCopyInto(out)
		return
	}
	if p.wire != nil {
		p.wire.ExtractObjectMetaForUpdate(out, false)
	}
}

// BorrowObjectMetaInto populates out for read-only callers without DeepCopying maps/slices when clean.
func (p *Pod) BorrowObjectMetaInto(out *metav1.ObjectMeta, dropManagedFields bool) {
	if p.decoded != nil {
		*out = p.decoded.ObjectMeta
		if dropManagedFields {
			out.ManagedFields = nil
		}
		return
	}
	if p.wire != nil {
		p.wire.BorrowObjectMetaInto(out, dropManagedFields, p.wireOwn == p)
	}
}

func (p *Pod) ensureWire() *WirePod {
	if p.wire == nil {
		p.wire = NewWirePod(nil)
		p.wireOwn = p
		return p.wire
	}
	if p.wireOwn != p {
		p.wire = p.wire.Clone()
		p.wireOwn = p
	}
	return p.wire
}

func (p *Pod) ensureWireForMetaEdit() *WirePod {
	w := p.ensureWire()
	w.MarkNonManagedMetaDirty()
	return w
}

func (p *Pod) GetNamespace() string {
	if p.decoded != nil {
		return p.decoded.Namespace
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.Namespace
		}
		return p.wire.meta.GetNamespace()
	}
	return ""
}
func (p *Pod) SetNamespace(namespace string) {
	if p.decoded != nil {
		p.decoded.Namespace = namespace
		return
	}
	p.ensureWireForMetaEdit().meta.SetNamespace(namespace)
}
func (p *Pod) GetName() string {
	if p.decoded != nil {
		return p.decoded.Name
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.Name
		}
		return p.wire.meta.GetName()
	}
	return ""
}
func (p *Pod) SetName(name string) {
	if p.decoded != nil {
		p.decoded.Name = name
		return
	}
	p.ensureWireForMetaEdit().meta.SetName(name)
}
func (p *Pod) GetGenerateName() string {
	if p.decoded != nil {
		return p.decoded.GenerateName
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.GenerateName
		}
		return p.wire.meta.GetGenerateName()
	}
	return ""
}
func (p *Pod) SetGenerateName(name string) {
	if p.decoded != nil {
		p.decoded.GenerateName = name
		return
	}
	p.ensureWireForMetaEdit().meta.SetGenerateName(name)
}
func (p *Pod) GetUID() types.UID {
	if p.decoded != nil {
		return p.decoded.UID
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.UID
		}
		return p.wire.meta.GetUID()
	}
	return ""
}
func (p *Pod) SetUID(uid types.UID) {
	if p.decoded != nil {
		p.decoded.UID = uid
		return
	}
	p.ensureWireForMetaEdit().meta.SetUID(uid)
}
func (p *Pod) GetResourceVersion() string {
	if p.decoded != nil {
		return p.decoded.ResourceVersion
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.ResourceVersion
		}
		return p.wire.meta.GetResourceVersion()
	}
	return ""
}
func (p *Pod) SetResourceVersion(version string) {
	if p.decoded != nil {
		p.decoded.ResourceVersion = version
		return
	}
	p.ensureWire().SetResourceVersion(version)
}
func (p *Pod) GetGeneration() int64 {
	if p.decoded != nil {
		return p.decoded.Generation
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.Generation
		}
		return p.wire.meta.GetGeneration()
	}
	return 0
}
func (p *Pod) SetGeneration(generation int64) {
	if p.decoded != nil {
		p.decoded.Generation = generation
		return
	}
	p.ensureWireForMetaEdit().meta.SetGeneration(generation)
}
func (p *Pod) GetSelfLink() string {
	if p.decoded != nil {
		return p.decoded.SelfLink
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.SelfLink
		}
		return p.wire.meta.GetSelfLink()
	}
	return ""
}
func (p *Pod) SetSelfLink(selfLink string) {
	if p.decoded != nil {
		p.decoded.SelfLink = selfLink
		return
	}
	p.ensureWireForMetaEdit().meta.SetSelfLink(selfLink)
}
func (p *Pod) GetCreationTimestamp() metav1.Time {
	if p.decoded != nil {
		return p.decoded.CreationTimestamp
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.CreationTimestamp
		}
		return p.wire.meta.GetCreationTimestamp()
	}
	return metav1.Time{}
}
func (p *Pod) SetCreationTimestamp(timestamp metav1.Time) {
	if p.decoded != nil {
		p.decoded.CreationTimestamp = timestamp
		return
	}
	p.ensureWireForMetaEdit().meta.SetCreationTimestamp(timestamp)
}
func (p *Pod) GetDeletionTimestamp() *metav1.Time {
	if p.decoded != nil {
		return p.decoded.DeletionTimestamp
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.DeletionTimestamp
		}
		return p.wire.meta.GetDeletionTimestamp()
	}
	return nil
}
func (p *Pod) SetDeletionTimestamp(timestamp *metav1.Time) {
	if p.decoded != nil {
		p.decoded.DeletionTimestamp = timestamp
		return
	}
	p.ensureWireForMetaEdit().meta.SetDeletionTimestamp(timestamp)
}
func (p *Pod) GetDeletionGracePeriodSeconds() *int64 {
	if p.decoded != nil {
		return p.decoded.DeletionGracePeriodSeconds
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.DeletionGracePeriodSeconds
		}
		return p.wire.meta.GetDeletionGracePeriodSeconds()
	}
	return nil
}
func (p *Pod) SetDeletionGracePeriodSeconds(gracePeriodSeconds *int64) {
	if p.decoded != nil {
		p.decoded.DeletionGracePeriodSeconds = gracePeriodSeconds
		return
	}
	p.ensureWireForMetaEdit().meta.SetDeletionGracePeriodSeconds(gracePeriodSeconds)
}
func (p *Pod) GetLabels() map[string]string {
	if p.decoded != nil {
		return p.decoded.Labels
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			if p.wireOwn == p && p.wire.IsCachedMetaOwned() {
				return cm.Labels
			}
			return maps.Clone(cm.Labels)
		}
		return p.wire.meta.GetLabels()
	}
	return nil
}
func (p *Pod) SetLabels(labels map[string]string) {
	if p.decoded != nil {
		p.decoded.Labels = labels
		return
	}
	p.ensureWireForMetaEdit().meta.SetLabels(labels)
}
func (p *Pod) GetAnnotations() map[string]string {
	if p.decoded != nil {
		return p.decoded.Annotations
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			if p.wireOwn == p && p.wire.IsCachedMetaOwned() {
				return cm.Annotations
			}
			return maps.Clone(cm.Annotations)
		}
		return p.wire.meta.GetAnnotations()
	}
	return nil
}
func (p *Pod) SetAnnotations(annotations map[string]string) {
	if p.decoded != nil {
		p.decoded.Annotations = annotations
		return
	}
	p.ensureWireForMetaEdit().meta.SetAnnotations(annotations)
}
func (p *Pod) GetFinalizers() []string {
	if p.decoded != nil {
		return p.decoded.Finalizers
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.Finalizers
		}
		return p.wire.meta.GetFinalizers()
	}
	return nil
}
func (p *Pod) SetFinalizers(finalizers []string) {
	if p.decoded != nil {
		p.decoded.Finalizers = finalizers
		return
	}
	p.ensureWireForMetaEdit().meta.SetFinalizers(finalizers)
}
func (p *Pod) GetOwnerReferences() []metav1.OwnerReference {
	if p.decoded != nil {
		return p.decoded.OwnerReferences
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.OwnerReferences
		}
		return p.wire.meta.GetOwnerReferences()
	}
	return nil
}
func (p *Pod) SetOwnerReferences(references []metav1.OwnerReference) {
	if p.decoded != nil {
		p.decoded.OwnerReferences = references
		return
	}
	p.ensureWireForMetaEdit().meta.SetOwnerReferences(references)
}
func (p *Pod) GetManagedFields() []metav1.ManagedFieldsEntry {
	if p.decoded != nil {
		return p.decoded.ManagedFields
	}
	if p.wire != nil {
		return p.wire.ManagedFields(p.wireOwn == p)
	}
	return nil
}
func (p *Pod) SetManagedFields(managedFields []metav1.ManagedFieldsEntry) {
	if p.decoded != nil {
		p.decoded.ManagedFields = managedFields
		return
	}
	p.ensureWire().SetManagedFields(managedFields)
}

// ============================================================================
// core.PodAccessor implementation on *Pod
// ============================================================================

func (p *Pod) HasDeletionTimestamp() bool {
	if p.decoded != nil {
		return p.decoded.HasDeletionTimestamp()
	}
	if p.wire != nil {
		if cm, ok := p.wire.CachedObjectMeta(); ok {
			return cm.DeletionTimestamp != nil
		}
		return p.wire.meta.HasDeletionTimestamp(p.wire.meta.Bytes())
	}
	return false
}

func (p *Pod) HasLegacyInitContainerAnnotations() bool {
	if p.decoded != nil {
		return p.decoded.HasLegacyInitContainerAnnotations()
	}
	if p.wire != nil {
		return p.wire.HasLegacyInitContainerAnnotations()
	}
	return false
}

func (p *Pod) GetSpecNodeName() string {
	if p.decoded != nil {
		return p.decoded.Spec.NodeName
	}
	if p.wire != nil {
		return p.wire.NodeName()
	}
	return ""
}

func (p *Pod) SetSpecNodeName(nodeName string) {
	if p.decoded != nil {
		p.decoded.Spec.NodeName = nodeName
		return
	}
	p.ensureWire().SetNodeName(nodeName)
}

func (p *Pod) GetSpecRestartPolicy() core.RestartPolicy {
	if p.decoded != nil {
		return p.decoded.Spec.RestartPolicy
	}
	if p.wire != nil {
		return p.wire.RestartPolicy()
	}
	return ""
}

func (p *Pod) GetSpecSchedulerName() string {
	if p.decoded != nil {
		return p.decoded.Spec.SchedulerName
	}
	if p.wire != nil {
		return p.wire.SchedulerName()
	}
	return ""
}

func (p *Pod) GetSpecServiceAccountName() string {
	if p.decoded != nil {
		return p.decoded.Spec.ServiceAccountName
	}
	if p.wire != nil {
		return p.wire.ServiceAccountName()
	}
	return ""
}

func (p *Pod) GetSpecHostNetwork() bool {
	if p.decoded != nil {
		return p.decoded.Spec.HostNetwork
	}
	if p.wire != nil {
		return p.wire.HostNetwork()
	}
	return false
}

func (p *Pod) GetSpecTerminationGracePeriodSeconds() *int64 {
	if p.decoded != nil {
		return p.decoded.Spec.TerminationGracePeriodSeconds
	}
	if p.wire != nil {
		return p.wire.TerminationGracePeriodSeconds()
	}
	return nil
}

func (p *Pod) GetSpecActiveDeadlineSeconds() *int64 {
	if p.decoded != nil {
		return p.decoded.Spec.ActiveDeadlineSeconds
	}
	if p.wire != nil {
		return p.wire.ActiveDeadlineSeconds()
	}
	return nil
}

func (p *Pod) HasSpecSchedulingGates() bool {
	if p.decoded != nil {
		return len(p.decoded.Spec.SchedulingGates) != 0
	}
	if p.wire != nil {
		return p.wire.HasSchedulingGates()
	}
	return false
}

func (p *Pod) GetSpecSchedulingGates() []core.PodSchedulingGate {
	return p.mustDecoded().GetSpecSchedulingGates()
}

func (p *Pod) GetSpecTolerations() []core.Toleration {
	return p.mustDecoded().GetSpecTolerations()
}

func (p *Pod) GetSpecInitContainers() []core.Container {
	return p.mustDecoded().Spec.InitContainers
}

func (p *Pod) GetSpecContainers() []core.Container {
	return p.mustDecoded().Spec.Containers
}

func (p *Pod) GetSpecEphemeralContainers() []core.EphemeralContainer {
	return p.mustDecoded().Spec.EphemeralContainers
}

func (p *Pod) GetSpecAffinity() *core.Affinity {
	return p.mustDecoded().Spec.Affinity
}

func (p *Pod) EnsureDefaultFaultTolerations(notReady, unreachable core.Toleration) {
	if p.decoded != nil {
		p.decoded.EnsureDefaultFaultTolerations(notReady, unreachable)
		return
	}
	if p.wire != nil && p.wire.HasDefaultFaultTolerations(notReady.Key, unreachable.Key) {
		return
	}
	p.mustDecoded().EnsureDefaultFaultTolerations(notReady, unreachable)
}

func (p *Pod) GetFirstContainerPort() int32 {
	if p.decoded != nil {
		return p.decoded.GetFirstContainerPort()
	}
	if p.wire != nil {
		return p.wire.FirstContainerPort()
	}
	return 0
}

func (p *Pod) ResolveContainer(container string) (string, bool, []string) {
	if p.decoded != nil {
		return p.decoded.ResolveContainer(container)
	}
	if p.wire != nil {
		return p.wire.ResolveContainer(container)
	}
	return "", false, nil
}

func (p *Pod) GetStatusPhase() core.PodPhase {
	if p.decoded != nil {
		return p.decoded.Status.Phase
	}
	if p.wire != nil {
		return p.wire.Phase()
	}
	return ""
}

func (p *Pod) GetStatusQOSClass() core.PodQOSClass {
	return p.mustDecoded().GetStatusQOSClass()
}

func (p *Pod) SetStatusQOSClass(qos core.PodQOSClass) {
	p.mustDecoded().SetStatusQOSClass(qos)
}

func (p *Pod) GetStatusObservedGeneration() int64 {
	return p.mustDecoded().GetStatusObservedGeneration()
}

func (p *Pod) SetStatusObservedGeneration(gen int64) {
	p.mustDecoded().SetStatusObservedGeneration(gen)
}

func (p *Pod) GetStatusPodIP() string {
	if p.decoded != nil {
		return p.decoded.Status.PodIP
	}
	if p.wire != nil {
		return p.wire.PodIP()
	}
	return ""
}

func (p *Pod) GetStatusPodIPs() []core.PodIP {
	if p.decoded != nil {
		return p.decoded.GetStatusPodIPs()
	}
	if p.wire != nil {
		return p.wire.StatusPodIPs()
	}
	return nil
}

func (p *Pod) GetStatusPrimaryPodIP() string {
	if p.decoded != nil {
		return p.decoded.GetStatusPrimaryPodIP()
	}
	if p.wire != nil {
		return p.wire.PodIP()
	}
	return ""
}

func (p *Pod) GetStatusFirstPodIP() string {
	if p.decoded != nil {
		return p.decoded.GetStatusFirstPodIP()
	}
	if p.wire != nil {
		return p.wire.StatusFirstPodIP()
	}
	return ""
}

func (p *Pod) GetStatusHostIP() string {
	return p.mustDecoded().GetStatusHostIP()
}

func (p *Pod) GetStatusHostIPs() []core.HostIP {
	if p.decoded != nil {
		return p.decoded.GetStatusHostIPs()
	}
	if p.wire != nil {
		return p.wire.StatusHostIPs()
	}
	return nil
}

func (p *Pod) GetStatusNominatedNodeName() string {
	if p.decoded != nil {
		return p.decoded.Status.NominatedNodeName
	}
	if p.wire != nil {
		return p.wire.NominatedNodeName()
	}
	return ""
}

func (p *Pod) SetStatusNominatedNodeName(nodeName string) {
	if p.decoded != nil {
		p.decoded.Status.NominatedNodeName = nodeName
		return
	}
	p.ensureWire().SetNominatedNodeName(nodeName)
}

func (p *Pod) GetStatusConditions() []core.PodCondition {
	return p.mustDecoded().GetStatusConditions()
}

func (p *Pod) GetStatusResourceClaimStatuses() []core.PodResourceClaimStatus {
	return p.mustDecoded().Status.ResourceClaimStatuses
}

func (p *Pod) GetStatusExtendedResourceClaimStatus() *core.PodExtendedResourceClaimStatus {
	return p.mustDecoded().Status.ExtendedResourceClaimStatus
}

func (p *Pod) GetStatusNodeAllocatableResourceClaimStatuses() []core.NodeAllocatableResourceClaimStatus {
	return p.mustDecoded().Status.NodeAllocatableResourceClaimStatuses
}

func (p *Pod) UpsertStatusCondition(condition core.PodCondition) bool {
	if p.decoded != nil {
		return p.decoded.UpsertStatusCondition(condition)
	}
	return p.ensureWire().UpsertStatusCondition(condition)
}

func (p *Pod) IsPodReady() bool {
	if p.decoded != nil {
		return p.decoded.IsPodReady()
	}
	if p.wire != nil {
		return p.wire.IsPodReady()
	}
	return false
}

func (p *Pod) GetPodTableSummary(wide bool) core.PodTableSummary {
	if p.decoded != nil {
		return p.decoded.GetPodTableSummary(wide)
	}
	if p.wire != nil {
		return p.wire.TableSummary(wide)
	}
	return core.PodTableSummary{}
}

// PodList is the internal lazy PodList representation.
//
// +k8s:deepcopy-gen=false
type PodList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []Pod
}

var (
	_ runtime.Object          = (*PodList)(nil)
	_ runtime.LazyObject      = (*PodList)(nil)
	_ metav1.ListInterface    = (*PodList)(nil)
	_ metav1.ListMetaAccessor = (*PodList)(nil)
	_ core.PodListAccessor    = (*PodList)(nil)
)

func (l *PodList) GetObjectKind() schema.ObjectKind  { return &l.TypeMeta }
func (l *PodList) GetListMeta() metav1.ListInterface { return &l.ListMeta }
func (l *PodList) Len() int                          { return len(l.Items) }
func (l *PodList) PodAt(i int) core.PodAccessor      { return &l.Items[i] }
func (l *PodList) IsDecoded() bool                   { return false }

// EnsureDecodedList converts all lazy items into a standard *core.PodList.
func (l *PodList) EnsureDecodedList() (*core.PodList, error) {
	out := &core.PodList{
		TypeMeta: l.TypeMeta,
		ListMeta: l.ListMeta,
	}
	if l.Items != nil {
		out.Items = make([]core.Pod, len(l.Items))
		for i := range l.Items {
			dec, err := l.Items[i].EnsureDecoded()
			if err != nil {
				return nil, err
			}
			out.Items[i] = *dec
		}
	}
	return out, nil
}

// EnsureDecodedObject implements runtime.LazyObject.
func (l *PodList) EnsureDecodedObject() (runtime.Object, error) {
	return l.EnsureDecodedList()
}

func (l *PodList) DeepCopyObject() runtime.Object {
	if l == nil {
		return nil
	}
	out := &PodList{
		TypeMeta: l.TypeMeta,
	}
	l.ListMeta.DeepCopyInto(&out.ListMeta)
	if l.Items != nil {
		out.Items = make([]Pod, len(l.Items))
		for i := range l.Items {
			out.Items[i] = *l.Items[i].DeepCopy()
		}
	}
	return out
}

var (
	_ runtime.VersionedObjectCreator = (*Pod)(nil)
	_ runtime.VersionedObjectCreator = (*PodList)(nil)
	_ runtime.LazyUpdateProjector    = (*V1Pod)(nil)
	_ runtime.LazyScopedPatcher      = (*V1Pod)(nil)
	_ runtime.LazyScopedPatcher      = (*Pod)(nil)
	_ runtime.LazySubtreePatcher     = (*V1Pod)(nil)
	_ runtime.LazySubtreePatcher     = (*Pod)(nil)
)

// HasEqualSpecWireBytes reports whether p and other are lazy and have byte-identical spec sub-messages.
func (p *V1Pod) HasEqualSpecWireBytes(other runtime.Object) bool {
	if p == nil || p.wire == nil || p.decoded != nil {
		return false
	}
	o, ok := other.(*V1Pod)
	if !ok || o == nil || o.wire == nil || o.decoded != nil {
		return false
	}
	return bytes.Equal(p.wire.EffectiveSubMessage(podFieldSpec), o.wire.EffectiveSubMessage(podFieldSpec))
}

func diffWireStatusTagMask(a, b *WirePod) (uint64, bool) {
	mask, ok := DiffSpecTagMask(a.EffectiveSubMessage(podFieldStatus), b.EffectiveSubMessage(podFieldStatus))
	if !ok {
		return 0, false
	}
	diffEmpty := a.statusEmptySlices ^ b.statusEmptySlices
	if diffEmpty&statusEmptyResourceClaimStatuses != 0 {
		mask |= uint64(1) << statusFieldResourceClaimStatuses
	}
	if diffEmpty&statusEmptyNodeAllocatableClaimStatuses != 0 {
		mask |= uint64(1) << statusFieldNodeAllocatableResourceClaimStatuses
	}
	return mask, true
}

// DiffSpecTagMask returns the bitmask of PodSpec field tags that differ on the wire between p and other.
func (p *V1Pod) DiffSpecTagMask(other runtime.Object) (uint64, bool) {
	if p == nil || p.wire == nil || p.decoded != nil {
		return 0, false
	}
	o, ok := other.(*V1Pod)
	if !ok || o == nil || o.wire == nil || o.decoded != nil {
		return 0, false
	}
	return DiffSpecTagMask(p.wire.EffectiveSubMessage(podFieldSpec), o.wire.EffectiveSubMessage(podFieldSpec))
}

// DiffStatusTagMask returns the bitmask of PodStatus field tags that differ on the wire between p and other.
func (p *V1Pod) DiffStatusTagMask(other runtime.Object) (uint64, bool) {
	if p == nil || p.wire == nil || p.decoded != nil {
		return 0, false
	}
	o, ok := other.(*V1Pod)
	if !ok || o == nil || o.wire == nil || o.decoded != nil {
		return 0, false
	}
	return diffWireStatusTagMask(p.wire, o.wire)
}

// EqualModuloManagedFields implements runtime.LazySubtreePatcher on *V1Pod.
func (p *V1Pod) EqualModuloManagedFields(other runtime.Object) (bool, bool) {
	if p == nil || p.wire == nil || p.decoded != nil {
		return false, false
	}
	o, ok := other.(*V1Pod)
	if !ok || o == nil || o.wire == nil || o.decoded != nil {
		return false, false
	}
	if p.TypeMeta != o.TypeMeta {
		return false, true
	}
	return p.wire.EqualModuloManagedFields(o.wire), true
}

// HasEqualSpecWireBytes reports whether p and other are lazy and have byte-identical spec sub-messages.
func (p *Pod) HasEqualSpecWireBytes(other runtime.Object) bool {
	if p == nil || p.wire == nil || p.decoded != nil {
		return false
	}
	o, ok := other.(*Pod)
	if !ok || o == nil || o.wire == nil || o.decoded != nil {
		return false
	}
	return bytes.Equal(p.wire.EffectiveSubMessage(podFieldSpec), o.wire.EffectiveSubMessage(podFieldSpec))
}

// DiffSpecTagMask returns the bitmask of PodSpec field tags that differ on the wire between p and other.
func (p *Pod) DiffSpecTagMask(other runtime.Object) (uint64, bool) {
	if p == nil || p.wire == nil || p.decoded != nil {
		return 0, false
	}
	o, ok := other.(*Pod)
	if !ok || o == nil || o.wire == nil || o.decoded != nil {
		return 0, false
	}
	return DiffSpecTagMask(p.wire.EffectiveSubMessage(podFieldSpec), o.wire.EffectiveSubMessage(podFieldSpec))
}

// DiffStatusTagMask returns the bitmask of PodStatus field tags that differ on the wire between p and other.
func (p *Pod) DiffStatusTagMask(other runtime.Object) (uint64, bool) {
	if p == nil || p.wire == nil || p.decoded != nil {
		return 0, false
	}
	o, ok := other.(*Pod)
	if !ok || o == nil || o.wire == nil || o.decoded != nil {
		return 0, false
	}
	return diffWireStatusTagMask(p.wire, o.wire)
}

// HasEqualOwnerReferences reports whether p and other are lazy and have byte-identical metadata.ownerReferences.
func (p *Pod) HasEqualOwnerReferences(other *Pod) bool {
	if p == nil || other == nil || p.wire == nil || other.wire == nil || p.decoded != nil || other.decoded != nil {
		return false
	}
	return p.wire.HasEqualOwnerReferences(other.wire)
}

// EqualModuloManagedFields implements runtime.LazySubtreePatcher on *Pod.
func (p *Pod) EqualModuloManagedFields(other runtime.Object) (bool, bool) {
	if p == nil || p.wire == nil || p.decoded != nil {
		return false, false
	}
	o, ok := other.(*Pod)
	if !ok || o == nil || o.wire == nil || o.decoded != nil {
		return false, false
	}
	if p.TypeMeta != o.TypeMeta {
		return false, true
	}
	return p.wire.EqualModuloManagedFields(o.wire), true
}

// HasEqualStatusWireBytes reports whether p and other are lazy and have byte-identical status sub-messages.
func (p *Pod) HasEqualStatusWireBytes(other runtime.Object) bool {
	if p == nil || p.wire == nil || p.decoded != nil {
		return false
	}
	o, ok := other.(*Pod)
	if !ok || o == nil || o.wire == nil || o.decoded != nil {
		return false
	}
	if p.wire.statusEmptySlices != o.wire.statusEmptySlices {
		return false
	}
	return bytes.Equal(p.wire.EffectiveSubMessage(podFieldStatus), o.wire.EffectiveSubMessage(podFieldStatus))
}

func equalMetaTimePtr(a, b *metav1.Time) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Equal(b)
}

func equalMetaInt64Ptr(a, b *int64) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func equalMetaBoolPtr(a, b *bool) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func equalMetaOwnerReferences(a, b []metav1.OwnerReference) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].APIVersion != b[i].APIVersion ||
			a[i].Kind != b[i].Kind ||
			a[i].Name != b[i].Name ||
			a[i].UID != b[i].UID ||
			!equalMetaBoolPtr(a[i].Controller, b[i].Controller) ||
			!equalMetaBoolPtr(a[i].BlockOwnerDeletion, b[i].BlockOwnerDeletion) {
			return false
		}
	}
	return true
}

// projectObjectMetaDiffForUpdate populates selfOut and peerOut with only the non-stripSet ObjectMeta
// fields that differ between selfMeta and peerMeta, preserving nil-vs-empty map/slice distinctions.
func projectObjectMetaDiffForUpdate(selfMeta, peerMeta, selfOut, peerOut *metav1.ObjectMeta) {
	if selfMeta.GenerateName != peerMeta.GenerateName {
		selfOut.GenerateName = selfMeta.GenerateName
		peerOut.GenerateName = peerMeta.GenerateName
	}
	if !equalMetaTimePtr(selfMeta.DeletionTimestamp, peerMeta.DeletionTimestamp) {
		selfOut.DeletionTimestamp = selfMeta.DeletionTimestamp
		peerOut.DeletionTimestamp = peerMeta.DeletionTimestamp
	}
	if !equalMetaInt64Ptr(selfMeta.DeletionGracePeriodSeconds, peerMeta.DeletionGracePeriodSeconds) {
		selfOut.DeletionGracePeriodSeconds = selfMeta.DeletionGracePeriodSeconds
		peerOut.DeletionGracePeriodSeconds = peerMeta.DeletionGracePeriodSeconds
	}
	if (selfMeta.Labels == nil) != (peerMeta.Labels == nil) || !maps.Equal(selfMeta.Labels, peerMeta.Labels) {
		selfOut.Labels = selfMeta.Labels
		peerOut.Labels = peerMeta.Labels
	}
	if (selfMeta.Annotations == nil) != (peerMeta.Annotations == nil) || !maps.Equal(selfMeta.Annotations, peerMeta.Annotations) {
		selfOut.Annotations = selfMeta.Annotations
		peerOut.Annotations = peerMeta.Annotations
	}
	if !equalMetaOwnerReferences(selfMeta.OwnerReferences, peerMeta.OwnerReferences) {
		selfOut.OwnerReferences = selfMeta.OwnerReferences
		peerOut.OwnerReferences = peerMeta.OwnerReferences
	}
	if (selfMeta.Finalizers == nil) != (peerMeta.Finalizers == nil) || !slices.Equal(selfMeta.Finalizers, peerMeta.Finalizers) {
		selfOut.Finalizers = selfMeta.Finalizers
		peerOut.Finalizers = peerMeta.Finalizers
	}
}

// ProjectForUpdate implements runtime.LazyUpdateProjector for structured-merge-diff Update comparisons,
// omitting Spec, Status, and unchanged ObjectMeta fields when excluded by resetFields/stripSet or equal on the wire.
func (p *V1Pod) ProjectForUpdate(peer runtime.Object, ignoreSpec, ignoreStatus bool) (runtime.Object, runtime.Object, bool, error) {
	if p == nil || p.wire == nil || p.decoded != nil {
		return nil, nil, false, nil
	}
	if peerV1, ok := peer.(*V1Pod); ok && peerV1 != nil && peerV1.wire != nil && peerV1.decoded == nil {
		selfSpec := p.wire.EffectiveSubMessage(podFieldSpec)
		peerSpec := peerV1.wire.EffectiveSubMessage(podFieldSpec)
		var specDiffMask uint64
		fullSpec := false
		if !ignoreSpec {
			if mask, diffOK := DiffSpecTagMask(selfSpec, peerSpec); diffOK {
				if mask&SpecTagMaskContainersAndVolumes != 0 {
					fullSpec = true
				} else {
					specDiffMask = mask
				}
			} else {
				fullSpec = true
			}
		}

		var statusDiffMask uint64
		fullStatus := false
		if !ignoreStatus {
			if sMask, sOK := diffWireStatusTagMask(p.wire, peerV1.wire); sOK {
				statusDiffMask = sMask
			} else {
				fullStatus = true
			}
		}

		if fullSpec && fullStatus {
			return nil, nil, false, nil
		}

		var selfMeta, peerMeta metav1.ObjectMeta
		p.BorrowObjectMetaInto(&selfMeta, true)
		peerV1.BorrowObjectMetaInto(&peerMeta, true)

		selfProj := &v1.Pod{TypeMeta: p.TypeMeta}
		peerProj := &v1.Pod{TypeMeta: peerV1.TypeMeta}
		projectObjectMetaDiffForUpdate(&selfMeta, &peerMeta, &selfProj.ObjectMeta, &peerProj.ObjectMeta)

		if fullSpec {
			if err := selfProj.Spec.Unmarshal(selfSpec); err != nil {
				return nil, nil, false, err
			}
			if err := peerProj.Spec.Unmarshal(peerSpec); err != nil {
				return nil, nil, false, err
			}
		} else if specDiffMask != 0 {
			if err := extractSpecSubtreeFromBytes(selfSpec, specDiffMask, &selfProj.Spec); err != nil {
				return nil, nil, false, err
			}
			if err := extractSpecSubtreeFromBytes(peerSpec, specDiffMask, &peerProj.Spec); err != nil {
				return nil, nil, false, err
			}
		}
		if fullStatus {
			if err := p.wire.ExtractV1StatusInto(&selfProj.Status); err != nil {
				return nil, nil, false, err
			}
			if err := peerV1.wire.ExtractV1StatusInto(&peerProj.Status); err != nil {
				return nil, nil, false, err
			}
		} else if statusDiffMask != 0 {
			if err := p.wire.ExtractV1StatusSubtreeInto(statusDiffMask, &selfProj.Status); err != nil {
				return nil, nil, false, err
			}
			if err := peerV1.wire.ExtractV1StatusSubtreeInto(statusDiffMask, &peerProj.Status); err != nil {
				return nil, nil, false, err
			}
		}
		return selfProj, peerProj, true, nil
	}

	if !ignoreSpec && !ignoreStatus {
		return nil, nil, false, nil
	}
	peerDecObj, err := runtime.EnsureDecodedObject(peer)
	if err != nil {
		return nil, nil, false, err
	}
	peerDec, ok := peerDecObj.(*v1.Pod)
	if !ok || peerDec == nil {
		return nil, nil, false, nil
	}
	var selfMeta metav1.ObjectMeta
	p.BorrowObjectMetaInto(&selfMeta, true)
	selfProj := &v1.Pod{TypeMeta: p.TypeMeta}
	peerProj := &v1.Pod{TypeMeta: peerDec.TypeMeta}
	projectObjectMetaDiffForUpdate(&selfMeta, &peerDec.ObjectMeta, &selfProj.ObjectMeta, &peerProj.ObjectMeta)
	if !ignoreSpec {
		if err := selfProj.Spec.Unmarshal(p.wire.EffectiveSubMessage(podFieldSpec)); err != nil {
			return nil, nil, false, err
		}
		peerProj.Spec = peerDec.Spec
	}
	if !ignoreStatus {
		if err := p.wire.ExtractV1StatusInto(&selfProj.Status); err != nil {
			return nil, nil, false, err
		}
		peerProj.Status = peerDec.Status
	}
	return selfProj, peerProj, true, nil
}

// SpecTagMaskForField implements runtime.LazySubtreePatcher on *V1Pod.
func (p *V1Pod) SpecTagMaskForField(fieldName string) (uint64, bool) {
	return SpecTagMaskForField(fieldName)
}

// StatusTagMaskForField implements runtime.LazySubtreePatcher on *V1Pod.
func (p *V1Pod) StatusTagMaskForField(fieldName string) (uint64, bool) {
	return StatusTagMaskForField(fieldName)
}

// ExtractScopedPatchBase implements runtime.LazyScopedPatcher on external *V1Pod.
func (p *V1Pod) ExtractScopedPatchBase(includeMetadata, includeStatus, dropManagedFields bool) (runtime.Object, error) {
	var statusMask uint64
	if includeStatus {
		statusMask = ^uint64(0)
	}
	return p.ExtractSubtreePatchBase(includeMetadata, 0, statusMask, dropManagedFields)
}

// ExtractSubtreePatchBase implements runtime.LazySubtreePatcher on external *V1Pod.
func (p *V1Pod) ExtractSubtreePatchBase(includeMetadata bool, specTagMask, statusTagMask uint64, dropManagedFields bool) (runtime.Object, error) {
	base := &v1.Pod{TypeMeta: p.TypeMeta}
	if p.wire == nil {
		return base, nil
	}
	if includeMetadata {
		p.wire.ExtractObjectMetaForUpdate(&base.ObjectMeta, dropManagedFields)
		if dropManagedFields && p.canCache() {
			p.wire.CacheDecodedMeta(&base.ObjectMeta)
		}
	}
	if specTagMask != 0 {
		if err := p.wire.ExtractV1SpecSubtreeInto(specTagMask, &base.Spec); err != nil {
			return nil, err
		}
	}
	if statusTagMask == ^uint64(0) {
		if err := p.wire.ExtractV1StatusInto(&base.Status); err != nil {
			return nil, err
		}
		if p.canCache() {
			p.wire.CacheDecodedStatus(base.Status.DeepCopy())
		}
	} else if statusTagMask != 0 {
		if err := p.wire.ExtractV1StatusSubtreeInto(statusTagMask, &base.Status); err != nil {
			return nil, err
		}
	}
	return base, nil
}

// SpliceScopedPatchResult implements runtime.LazyScopedPatcher on external *V1Pod.
func (p *V1Pod) SpliceScopedPatchResult(patched runtime.Object, includeMetadata, includeStatus bool) (runtime.Object, error) {
	var statusMask uint64
	if includeStatus {
		statusMask = ^uint64(0)
	}
	return p.SpliceSubtreePatchResult(patched, includeMetadata, 0, statusMask)
}

// SpliceSubtreePatchResult implements runtime.LazySubtreePatcher on external *V1Pod.
func (p *V1Pod) SpliceSubtreePatchResult(patched runtime.Object, includeMetadata bool, specTagMask, statusTagMask uint64) (runtime.Object, error) {
	decObj, err := runtime.EnsureDecodedObject(patched)
	if err != nil {
		return nil, err
	}
	patchedV1, ok := decObj.(*v1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected *v1.Pod, got %T", decObj)
	}
	var metaPtr *metav1.ObjectMeta
	if includeMetadata {
		metaPtr = &patchedV1.ObjectMeta
	} else if p.canCache() {
		p.wire.DisownCachedMeta()
	}
	specBytes := p.wire.EffectiveSubMessage(podFieldSpec)
	if specTagMask != 0 {
		specBytes, err = SpliceSpecByTagMask(specBytes, &patchedV1.Spec, specTagMask)
		if err != nil {
			return nil, err
		}
	}
	var newWire *WirePod
	switch {
	case statusTagMask == ^uint64(0):
		newWire, err = p.wire.ReplaceSubMessages(metaPtr, specBytes, &patchedV1.Status)
	case statusTagMask != 0:
		var statusBytes []byte
		var emptySlices uint8
		statusBytes, emptySlices, err = SpliceStatusByTagMask(
			p.wire.EffectiveSubMessage(podFieldStatus),
			p.wire.statusEmptySlices,
			&patchedV1.Status,
			statusTagMask,
		)
		if err == nil {
			newWire, err = p.wire.ReplaceSubMessagesWithStatusBytes(metaPtr, specBytes, statusBytes, emptySlices, nil)
		}
	default:
		newWire, err = p.wire.ReplaceSubMessages(metaPtr, specBytes, nil)
	}
	if err != nil {
		return nil, err
	}
	out := &V1Pod{TypeMeta: p.TypeMeta, wire: newWire}
	out.wireOwn = out
	return out, nil
}

// SpecTagMaskForField implements runtime.LazySubtreePatcher on *Pod.
func (p *Pod) SpecTagMaskForField(fieldName string) (uint64, bool) {
	return SpecTagMaskForField(fieldName)
}

// StatusTagMaskForField implements runtime.LazySubtreePatcher on *Pod.
func (p *Pod) StatusTagMaskForField(fieldName string) (uint64, bool) {
	return StatusTagMaskForField(fieldName)
}

// ExtractScopedPatchBase implements runtime.LazyScopedPatcher on internal *Pod.
func (p *Pod) ExtractScopedPatchBase(includeMetadata, includeStatus, dropManagedFields bool) (runtime.Object, error) {
	var statusMask uint64
	if includeStatus {
		statusMask = ^uint64(0)
	}
	return p.ExtractSubtreePatchBase(includeMetadata, 0, statusMask, dropManagedFields)
}

// ExtractSubtreePatchBase implements runtime.LazySubtreePatcher on internal *Pod.
func (p *Pod) ExtractSubtreePatchBase(includeMetadata bool, specTagMask, statusTagMask uint64, dropManagedFields bool) (runtime.Object, error) {
	base := &core.Pod{TypeMeta: p.TypeMeta}
	if p.wire == nil {
		return base, nil
	}
	if includeMetadata {
		p.wire.ExtractObjectMetaForUpdate(&base.ObjectMeta, dropManagedFields)
		if dropManagedFields && p.wireOwn == p {
			p.wire.CacheDecodedMeta(&base.ObjectMeta)
		}
	}
	if specTagMask != 0 {
		if err := p.wire.ExtractCoreSpecSubtreeInto(specTagMask, &base.Spec); err != nil {
			return nil, err
		}
	}
	if statusTagMask == ^uint64(0) {
		if err := p.wire.ExtractCoreStatusInto(&base.Status); err != nil {
			return nil, err
		}
		if p.wireOwn == p {
			cp := base.Status.DeepCopy()
			p.wire.CacheDecodedStatus((*v1.PodStatus)(unsafe.Pointer(cp)))
		}
	} else if statusTagMask != 0 {
		if err := p.wire.ExtractCoreStatusSubtreeInto(statusTagMask, &base.Status); err != nil {
			return nil, err
		}
	}
	return base, nil
}

// SpliceScopedPatchResult implements runtime.LazyScopedPatcher on internal *Pod.
func (p *Pod) SpliceScopedPatchResult(patched runtime.Object, includeMetadata, includeStatus bool) (runtime.Object, error) {
	var statusMask uint64
	if includeStatus {
		statusMask = ^uint64(0)
	}
	return p.SpliceSubtreePatchResult(patched, includeMetadata, 0, statusMask)
}

// SpliceSubtreePatchResult implements runtime.LazySubtreePatcher on internal *Pod.
func (p *Pod) SpliceSubtreePatchResult(patched runtime.Object, includeMetadata bool, specTagMask, statusTagMask uint64) (runtime.Object, error) {
	decObj, err := runtime.EnsureDecodedObject(patched)
	if err != nil {
		return nil, err
	}
	patchedCore, ok := decObj.(*core.Pod)
	if !ok {
		return nil, fmt.Errorf("expected *core.Pod, got %T", decObj)
	}
	var metaPtr *metav1.ObjectMeta
	if includeMetadata {
		metaPtr = &patchedCore.ObjectMeta
	} else if p.wireOwn == p {
		p.wire.DisownCachedMeta()
	}
	specBytes := p.wire.EffectiveSubMessage(podFieldSpec)
	if specTagMask != 0 {
		specBytes, err = SpliceSpecByTagMask(specBytes, (*v1.PodSpec)(unsafe.Pointer(&patchedCore.Spec)), specTagMask)
		if err != nil {
			return nil, err
		}
	}
	var newWire *WirePod
	v1StatusPtr := (*v1.PodStatus)(unsafe.Pointer(&patchedCore.Status))
	switch {
	case statusTagMask == ^uint64(0):
		newWire, err = p.wire.ReplaceSubMessages(metaPtr, specBytes, v1StatusPtr)
	case statusTagMask != 0:
		var statusBytes []byte
		var emptySlices uint8
		statusBytes, emptySlices, err = SpliceStatusByTagMask(
			p.wire.EffectiveSubMessage(podFieldStatus),
			p.wire.statusEmptySlices,
			v1StatusPtr,
			statusTagMask,
		)
		if err == nil {
			newWire, err = p.wire.ReplaceSubMessagesWithStatusBytes(metaPtr, specBytes, statusBytes, emptySlices, nil)
		}
	default:
		newWire, err = p.wire.ReplaceSubMessages(metaPtr, specBytes, nil)
	}
	if err != nil {
		return nil, err
	}
	out := &Pod{TypeMeta: p.TypeMeta, wire: newWire}
	out.wireOwn = out
	return out, nil
}

// ReadOnlyCoreStatus returns a read-only *core.PodStatus without DeepCopying when already cached on p.
func (p *Pod) ReadOnlyCoreStatus() (*core.PodStatus, error) {
	if p.decoded != nil {
		return &p.decoded.Status, nil
	}
	if p.wire != nil {
		return p.wire.ReadOnlyCoreStatus(p.wireOwn == p)
	}
	return &core.PodStatus{}, nil
}

// CacheDecodedMeta stores a decoded ObjectMeta on p's WirePod for reuse across update steps.
func (p *Pod) CacheDecodedMeta(meta *metav1.ObjectMeta) {
	if p == nil || p.wire == nil || meta == nil || p.wireOwn != p {
		return
	}
	p.wire.CacheDecodedMeta(meta)
}

// ExtractObjectMetaForUpdate unmarshals ObjectMeta from p, eliding ManagedFields when dropManagedFields is true.
func (p *Pod) ExtractObjectMetaForUpdate(out *metav1.ObjectMeta, dropManagedFields bool) {
	if p.decoded != nil {
		p.decoded.ObjectMeta.DeepCopyInto(out)
		if dropManagedFields {
			out.ManagedFields = nil
		}
		return
	}
	if p.wire != nil {
		p.wire.ExtractObjectMetaForUpdate(out, dropManagedFields)
	}
}

// ExtractMetaAndStatus decodes only ObjectMeta and PodStatus from a lazy Pod without decoding PodSpec.
func (p *Pod) ExtractMetaAndStatus() (metav1.ObjectMeta, core.PodStatus, error) {
	return p.ExtractMetaAndStatusForUpdate(false)
}

// ExtractMetaAndStatusForUpdate decodes only ObjectMeta and PodStatus from a lazy Pod without decoding PodSpec,
// eliding ManagedFields when dropManagedFields is true.
func (p *Pod) ExtractMetaAndStatusForUpdate(dropManagedFields bool) (metav1.ObjectMeta, core.PodStatus, error) {
	var meta metav1.ObjectMeta
	var status core.PodStatus
	if p.decoded != nil {
		p.decoded.ObjectMeta.DeepCopyInto(&meta)
		if dropManagedFields {
			meta.ManagedFields = nil
		}
		p.decoded.Status.DeepCopyInto(&status)
		return meta, status, nil
	}
	if p.wire != nil {
		p.wire.ExtractObjectMetaForUpdate(&meta, dropManagedFields)
		if err := p.wire.ExtractCoreStatusInto(&status); err != nil {
			return meta, status, err
		}
	}
	return meta, status, nil
}

// CacheDecodedStatus stores a decoded PodStatus on p's WirePod for reuse in subsequent validation steps.
func (p *Pod) CacheDecodedStatus(status *core.PodStatus) {
	if p == nil || p.wire == nil || status == nil || p.wireOwn != p {
		return
	}
	p.wire.CacheDecodedStatus((*v1.PodStatus)(unsafe.Pointer(status)))
}

// ReplaceMetaAndStatusFromOldSpec updates p in-place to hold meta + old.Spec (on the wire) + status.
func (p *Pod) ReplaceMetaAndStatusFromOldSpec(meta *metav1.ObjectMeta, status *core.PodStatus, old *Pod) error {
	if meta == nil && old.wireOwn == old {
		old.wire.DisownCachedMeta()
	}
	var statusPtr *v1.PodStatus
	if status != nil {
		statusPtr = (*v1.PodStatus)(unsafe.Pointer(status))
	}
	newWire, err := old.wire.ReplaceSubMessages(meta, old.wire.EffectiveSubMessage(podFieldSpec), statusPtr)
	if err != nil {
		return err
	}
	p.decoded = nil
	p.wire = newWire
	p.wireOwn = p
	return nil
}

// ReplaceMetaWithOldSpecAndStatus updates p in-place to hold meta + old.Spec (on the wire) + old.Status (on the wire).
func (p *Pod) ReplaceMetaWithOldSpecAndStatus(meta *metav1.ObjectMeta, old *Pod) error {
	if meta == nil && old.wireOwn == old {
		old.wire.DisownCachedMeta()
	}
	newWire, err := old.wire.ReplaceSubMessages(meta, old.wire.EffectiveSubMessage(podFieldSpec), nil)
	if err != nil {
		return err
	}
	p.decoded = nil
	p.wire = newWire
	p.wireOwn = p
	return nil
}

// ReplaceMetaAndKeepSpecWithOldStatus updates p in-place to hold meta + p.Spec (on the wire) + old.Status (on the wire).
func (p *Pod) ReplaceMetaAndKeepSpecWithOldStatus(meta *metav1.ObjectMeta, old *Pod) error {
	if meta == nil && old.wireOwn == old {
		old.wire.DisownCachedMeta()
	}
	newWire, err := old.wire.ReplaceSubMessages(meta, p.wire.EffectiveSubMessage(podFieldSpec), nil)
	if err != nil {
		return err
	}
	p.decoded = nil
	p.wire = newWire
	p.wireOwn = p
	return nil
}

// SpecSummaryForStatusValidation extracts the PodSpec fields required by common-case ValidatePodStatusUpdate without decoding PodSpec.
func (p *Pod) SpecSummaryForStatusValidation() (nodeName string, restartPolicy core.RestartPolicy, podOS *core.PodOS) {
	if p.decoded != nil {
		return p.decoded.Spec.NodeName, p.decoded.Spec.RestartPolicy, p.decoded.Spec.OS
	}
	if p.wire != nil {
		return p.wire.NodeName(), p.wire.RestartPolicy(), p.wire.SpecOS()
	}
	return "", "", nil
}

// NewVersionedObject implements runtime.VersionedObjectCreator so Scheme.ConvertToVersion
// allocates a lazy *Pod when converting an external *V1Pod to the internal hub version.
func (p *V1Pod) NewVersionedObject(gvk schema.GroupVersionKind) (runtime.Object, bool) {
	if gvk.GroupVersion() == core.SchemeGroupVersion && gvk.Kind == "Pod" {
		return &Pod{}, true
	}
	return nil, false
}

// NewVersionedObject implements runtime.VersionedObjectCreator so Scheme.ConvertToVersion
// allocates a lazy *PodList when converting an external *V1PodList to the internal hub version.
func (l *V1PodList) NewVersionedObject(gvk schema.GroupVersionKind) (runtime.Object, bool) {
	if gvk.GroupVersion() == core.SchemeGroupVersion && gvk.Kind == "PodList" {
		return &PodList{}, true
	}
	return nil, false
}

// NewVersionedObject implements runtime.VersionedObjectCreator so that Protobuf and JSON
// serializers allocate a lazy *V1Pod when encoding/converting an internal *lazypod.Pod.
func (p *Pod) NewVersionedObject(gvk schema.GroupVersionKind) (runtime.Object, bool) {
	if gvk.GroupVersion() == v1.SchemeGroupVersion && gvk.Kind == "Pod" {
		return &V1Pod{}, true
	}
	return nil, false
}

// NewVersionedObject implements runtime.VersionedObjectCreator so that Protobuf and JSON
// serializers allocate a lazy *V1PodList when encoding/converting an internal *lazypod.PodList.
func (l *PodList) NewVersionedObject(gvk schema.GroupVersionKind) (runtime.Object, bool) {
	if gvk.GroupVersion() == v1.SchemeGroupVersion && gvk.Kind == "PodList" {
		return &V1PodList{}, true
	}
	return nil, false
}

var _ = corev1.SetObjectDefaults_Pod

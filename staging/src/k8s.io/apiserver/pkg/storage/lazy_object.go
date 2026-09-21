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

package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"sync"
	"unsafe"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

type lazyMetadataCarrierKey struct{}

// WithLazyMetadataCarrier marks ctx as eligible to use a LazyObject's
// MetadataCarrier in GuaranteedUpdate instead of fully decoding the object.
func WithLazyMetadataCarrier(ctx context.Context) context.Context {
	return context.WithValue(ctx, lazyMetadataCarrierKey{}, true)
}

// CanUseLazyMetadataCarrier reports whether GuaranteedUpdate may pass a
// LazyObject's MetadataCarrier to tryUpdate.
func CanUseLazyMetadataCarrier(ctx context.Context) bool {
	v, _ := ctx.Value(lazyMetadataCarrierKey{}).(bool)
	return v
}

// LazyObject is implemented by wrappers that store serialized bytes and only
// decode the full structure on demand.
type LazyObject interface {
	Decode() (runtime.Object, error)
	DecodeNew() (runtime.Object, error)
	MetadataCarrier() (runtime.Object, error)
	CopyMetadataOnlyInto(dst runtime.Object) bool
	RawStorageBytes() []byte
	StorageRevision() int64
}

// PrecomputedAttrsObject is implemented by lazy wrappers that pre-extract
// selectable labels, fields, and index attributes from wire bytes without
// full object decoding.
type PrecomputedAttrsObject interface {
	GetAttrs() (labels.Set, fields.Set, error)
	GetNodeName() string
	GetNodeNameSlice() []string
}

// DecodeLazyObject decodes the object if it implements LazyObject.
func DecodeLazyObject(obj runtime.Object) (runtime.Object, error) {
	if lazy, ok := obj.(LazyObject); ok {
		return lazy.Decode()
	}
	return obj, nil
}

// PanicOnLazyDecode is used in tests to assert that lazy decoding was triggered.
var PanicOnLazyDecode bool

type lazyObjectWrapper struct {
	metav1.ObjectMeta

	codec          runtime.Codec
	versioner      Versioner
	data           []byte
	rev            int64
	underlyingType reflect.Type

	nodeName           string
	nodeNameSlice      [1]string
	restartPolicy      string
	schedulerName      string
	serviceAccountName string
	hostNetwork        bool
	phase              string
	podIP              string
	nominatedNodeName  string

	mfOnce        sync.Once
	managedFields []metav1.ManagedFieldsEntry
	mfErr         error

	once    sync.Once
	fullObj runtime.Object
	err     error
}

var _ runtime.Object = &lazyObjectWrapper{}
var _ runtime.TypedObject = &lazyObjectWrapper{}
var _ metav1.Object = &lazyObjectWrapper{}
var _ LazyObject = &lazyObjectWrapper{}
var _ PrecomputedAttrsObject = &lazyObjectWrapper{}

var protoMagicPrefix = []byte{0x6b, 0x38, 0x73, 0x00}

func NewLazyObjectWrapper(codec runtime.Codec, versioner Versioner, data []byte, rev int64, underlyingType reflect.Type) (runtime.Object, error) {
	if underlyingType == nil || underlyingType.Kind() != reflect.Ptr || underlyingType.Elem().Name() != "Pod" {
		obj, err := runtime.Decode(codec, data)
		if err != nil {
			return nil, err
		}
		if err := versioner.UpdateObject(obj, uint64(rev)); err != nil {
			return nil, err
		}
		return obj, nil
	}
	l := &lazyObjectWrapper{
		codec:          codec,
		versioner:      versioner,
		data:           data,
		rev:            rev,
		underlyingType: underlyingType,
	}
	isCorePod := underlyingType.Elem().PkgPath() == "k8s.io/kubernetes/pkg/apis/core"
	if err := decodeLazyPodData(data, l, isCorePod); err != nil {
		return nil, err
	}
	l.ObjectMeta.ResourceVersion = strconv.FormatUint(uint64(rev), 10)
	l.nodeNameSlice[0] = l.nodeName
	return l, nil
}

func (l *lazyObjectWrapper) GetObjectKind() schema.ObjectKind {
	return schema.EmptyObjectKind
}

func (l *lazyObjectWrapper) GetUnderlyingType() reflect.Type {
	return l.underlyingType
}

func (l *lazyObjectWrapper) RawStorageBytes() []byte {
	return l.data
}

func (l *lazyObjectWrapper) StorageRevision() int64 {
	return l.rev
}

func (l *lazyObjectWrapper) GetNodeName() string {
	return l.nodeName
}

func (l *lazyObjectWrapper) GetNodeNameSlice() []string {
	return l.nodeNameSlice[:]
}

func (l *lazyObjectWrapper) GetAttrs() (labels.Set, fields.Set, error) {
	hostNet := "false"
	if l.hostNetwork {
		hostNet = "true"
	}
	fieldsSet := fields.Set{
		"metadata.name":            l.ObjectMeta.Name,
		"metadata.namespace":       l.ObjectMeta.Namespace,
		"spec.nodeName":            l.nodeName,
		"spec.restartPolicy":       l.restartPolicy,
		"spec.schedulerName":       l.schedulerName,
		"spec.serviceAccountName":  l.serviceAccountName,
		"spec.hostNetwork":         hostNet,
		"status.phase":             l.phase,
		"status.podIP":             l.podIP,
		"status.nominatedNodeName": l.nominatedNodeName,
	}
	return labels.Set(l.ObjectMeta.Labels), fieldsSet, nil
}

func (l *lazyObjectWrapper) DeepCopyObject() runtime.Object {
	full, err := l.Decode()
	if err != nil {
		panic(fmt.Sprintf("failed to decode lazy object during DeepCopyObject: %v", err))
	}
	return full.DeepCopyObject()
}

func (l *lazyObjectWrapper) CopyMetadataOnlyInto(dst runtime.Object) bool {
	if l.ObjectMeta.LazyWire == nil {
		return false
	}
	metaObj, ok := dst.(metav1.ObjectMetaAccessor)
	if !ok {
		return false
	}
	dstMeta, ok := metaObj.GetObjectMeta().(*metav1.ObjectMeta)
	if !ok || dstMeta == nil {
		return false
	}
	*dstMeta = l.ObjectMeta
	return true
}

func (l *lazyObjectWrapper) MetadataCarrier() (runtime.Object, error) {
	if l.ObjectMeta.LazyWire == nil {
		return l.Decode()
	}
	l.mfOnce.Do(func() {
		l.managedFields, l.mfErr = scanManagedFieldsProto(l.ObjectMeta.LazyWire.MetaRaw)
	})
	if l.mfErr != nil {
		return nil, l.mfErr
	}
	carrier := reflect.New(l.underlyingType.Elem()).Interface().(runtime.Object)
	metaObj, ok := carrier.(metav1.ObjectMetaAccessor)
	if !ok {
		return l.Decode()
	}
	carrierMeta, ok := metaObj.GetObjectMeta().(*metav1.ObjectMeta)
	if !ok || carrierMeta == nil {
		return l.Decode()
	}
	*carrierMeta = l.ObjectMeta
	carrierMeta.ManagedFields = l.managedFields
	return carrier, nil
}

func (l *lazyObjectWrapper) decodeFullInto(dst interface{}) error {
	full, err := l.Decode()
	if err != nil {
		return err
	}
	fullCopy := full.DeepCopyObject()
	var savedLabels map[string]string
	var savedMF []metav1.ManagedFieldsEntry
	var savedRV string
	var hasSavedMeta bool
	var wasMetaModified bool
	if metaObj, ok := dst.(metav1.ObjectMetaAccessor); ok {
		if m, ok := metaObj.GetObjectMeta().(*metav1.ObjectMeta); ok && m != nil {
			savedLabels = m.Labels
			savedMF = m.ManagedFields
			savedRV = m.ResourceVersion
			hasSavedMeta = true
			wasMetaModified = m.LazyWire != nil && m.LazyWire.MetaModified
		}
	}

	dstVal := reflect.ValueOf(dst)
	fullVal := reflect.ValueOf(fullCopy)
	if dstVal.Kind() == reflect.Pointer && fullVal.Kind() == reflect.Pointer {
		if dstVal.Type() == fullVal.Type() {
			dstVal.Elem().Set(fullVal.Elem())
		}
	}
	if hasSavedMeta {
		if metaObj, ok := dst.(metav1.ObjectMetaAccessor); ok {
			if m, ok := metaObj.GetObjectMeta().(*metav1.ObjectMeta); ok && m != nil {
				if wasMetaModified || savedLabels != nil {
					m.Labels = savedLabels
				}
				if wasMetaModified || savedMF != nil {
					m.ManagedFields = savedMF
				}
				if savedRV != "" {
					m.ResourceVersion = savedRV
				}
				m.LazyWire = nil
			}
		}
	}
	return nil
}

func (l *lazyObjectWrapper) Decode() (runtime.Object, error) {
	l.once.Do(func() {
		if PanicOnLazyDecode {
			panic("lazy decoding triggered")
		}
		obj, err := runtime.Decode(l.codec, l.data)
		if err != nil {
			l.err = err
			return
		}
		if err := l.versioner.UpdateObject(obj, uint64(l.rev)); err != nil {
			l.err = err
			return
		}
		l.fullObj = obj
	})
	return l.fullObj, l.err
}

func (l *lazyObjectWrapper) DecodeNew() (runtime.Object, error) {
	if PanicOnLazyDecode {
		panic("lazy decoding triggered")
	}
	obj, err := runtime.Decode(l.codec, l.data)
	if err != nil {
		return nil, err
	}
	if err := l.versioner.UpdateObject(obj, uint64(l.rev)); err != nil {
		return nil, err
	}
	return obj, nil
}

type lazyPodJSON struct {
	Metadata struct {
		Name              string            `json:"name"`
		GenerateName      string            `json:"generateName"`
		Namespace         string            `json:"namespace"`
		UID               types.UID         `json:"uid"`
		Generation        int64             `json:"generation"`
		CreationTimestamp metav1.Time       `json:"creationTimestamp"`
		DeletionTimestamp *metav1.Time      `json:"deletionTimestamp"`
		Labels            map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		NodeName           string `json:"nodeName"`
		RestartPolicy      string `json:"restartPolicy"`
		SchedulerName      string `json:"schedulerName"`
		ServiceAccountName string `json:"serviceAccountName"`
		DeprecatedSA       string `json:"serviceAccount"`
		HostNetwork        bool   `json:"hostNetwork"`
	} `json:"spec"`
	Status struct {
		Phase             string `json:"phase"`
		PodIP             string `json:"podIP"`
		NominatedNodeName string `json:"nominatedNodeName"`
		PodIPs            []struct {
			IP string `json:"ip"`
		} `json:"podIPs"`
	} `json:"status"`
}

func decodeLazyPodData(data []byte, l *lazyObjectWrapper, isCorePod bool) error {
	if bytes.HasPrefix(data, protoMagicPrefix) {
		rawPod, prefixEnd, suffixStart, err := extractUnknownRawBounds(data)
		if err != nil {
			return err
		}
		metaRaw, metaFixedRaw, restRaw, err := scanPodProto(rawPod, l)
		if err != nil {
			return err
		}
		l.ObjectMeta.LazyWire = &metav1.RawStorageWire{
			Envelope:       data,
			EnvelopePrefix: data[:prefixEnd],
			EnvelopeSuffix: data[suffixStart:],
			MetaRaw:        metaRaw,
			MetaFixedRaw:   metaFixedRaw,
			RestRaw:        restRaw,
			DecodeFullInto: l.decodeFullInto,
		}
	} else {
		var parsed lazyPodJSON
		if err := json.Unmarshal(data, &parsed); err != nil {
			return err
		}
		l.ObjectMeta.Name = parsed.Metadata.Name
		l.ObjectMeta.GenerateName = parsed.Metadata.GenerateName
		l.ObjectMeta.Namespace = parsed.Metadata.Namespace
		l.ObjectMeta.UID = parsed.Metadata.UID
		l.ObjectMeta.Generation = parsed.Metadata.Generation
		l.ObjectMeta.CreationTimestamp = parsed.Metadata.CreationTimestamp
		l.ObjectMeta.DeletionTimestamp = parsed.Metadata.DeletionTimestamp
		l.ObjectMeta.Labels = parsed.Metadata.Labels

		l.nodeName = parsed.Spec.NodeName
		l.restartPolicy = parsed.Spec.RestartPolicy
		l.schedulerName = parsed.Spec.SchedulerName
		l.serviceAccountName = parsed.Spec.ServiceAccountName
		if l.serviceAccountName == "" {
			l.serviceAccountName = parsed.Spec.DeprecatedSA
		}
		l.hostNetwork = parsed.Spec.HostNetwork

		l.phase = parsed.Status.Phase
		l.nominatedNodeName = parsed.Status.NominatedNodeName
		if len(parsed.Status.PodIPs) > 0 {
			l.podIP = parsed.Status.PodIPs[0].IP
		} else if isCorePod {
			l.podIP = parsed.Status.PodIP
		} else {
			l.podIP = parsed.Status.PodIP
		}
	}

	if isCorePod {
		if l.restartPolicy == "" {
			l.restartPolicy = "Always"
		}
		if l.schedulerName == "" {
			l.schedulerName = "default-scheduler"
		}
	}
	return nil
}

func extractUnknownRaw(b []byte) ([]byte, error) {
	raw, _, _, err := extractUnknownRawBounds(append(protoMagicPrefix, b...))
	return raw, err
}

func extractUnknownRawBounds(data []byte) (raw []byte, prefixEnd int, suffixStart int, err error) {
	b := data[4:]
	i := 0
	for i < len(b) {
		tagStart := i
		wire, next, err := readVarint(b, i)
		if err != nil {
			return nil, 0, 0, err
		}
		i = next
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if fieldNum <= 0 {
			return nil, 0, 0, fmt.Errorf("proto: illegal tag %d", fieldNum)
		}
		if fieldNum == 2 && wireType == 2 {
			val, next, err := readBytesField(b, i)
			if err != nil {
				return nil, 0, 0, err
			}
			raw = val
			prefixEnd = 4 + tagStart
			suffixStart = 4 + next
			i = next
			continue
		}
		next, err = skipField(b, i, wireType)
		if err != nil {
			return nil, 0, 0, err
		}
		i = next
	}
	return raw, prefixEnd, suffixStart, nil
}

func scanPodProto(b []byte, l *lazyObjectWrapper) (metaRaw []byte, metaFixedRaw []byte, restRaw []byte, err error) {
	i := 0
	for i < len(b) {
		wire, next, err := readVarint(b, i)
		if err != nil {
			return nil, nil, nil, err
		}
		i = next
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if fieldNum <= 0 {
			return nil, nil, nil, fmt.Errorf("proto: illegal tag %d", fieldNum)
		}
		switch fieldNum {
		case 1: // ObjectMeta
			if wireType != 2 {
				return nil, nil, nil, fmt.Errorf("proto: wrong wireType %d for ObjectMeta", wireType)
			}
			val, next, err := readBytesField(b, i)
			if err != nil {
				return nil, nil, nil, err
			}
			metaRaw = val
			restRaw = b[next:]
			metaFixedRaw, err = scanObjectMetaProto(val, &l.ObjectMeta)
			if err != nil {
				return nil, nil, nil, err
			}
			i = next
		case 2: // PodSpec
			if wireType != 2 {
				return nil, nil, nil, fmt.Errorf("proto: wrong wireType %d for PodSpec", wireType)
			}
			val, next, err := readBytesField(b, i)
			if err != nil {
				return nil, nil, nil, err
			}
			if err := scanPodSpecProto(val, l); err != nil {
				return nil, nil, nil, err
			}
			i = next
		case 3: // PodStatus
			if wireType != 2 {
				return nil, nil, nil, fmt.Errorf("proto: wrong wireType %d for PodStatus", wireType)
			}
			val, next, err := readBytesField(b, i)
			if err != nil {
				return nil, nil, nil, err
			}
			if err := scanPodStatusProto(val, l); err != nil {
				return nil, nil, nil, err
			}
			i = next
		default:
			next, err = skipField(b, i, wireType)
			if err != nil {
				return nil, nil, nil, err
			}
			i = next
		}
	}
	return metaRaw, metaFixedRaw, restRaw, nil
}

func bytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func scanObjectMetaProto(b []byte, m *metav1.ObjectMeta) ([]byte, error) {
	var fixed []byte
	spanStart := 0
	i := 0
	for i < len(b) {
		tagStart := i
		wire, next, err := readVarint(b, i)
		if err != nil {
			return nil, err
		}
		i = next
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		excludeFromFixed := fieldNum == 6 || fieldNum == 11 || fieldNum == 17
		if excludeFromFixed && tagStart > spanStart {
			if fixed == nil {
				fixed = make([]byte, 0, len(b))
			}
			fixed = append(fixed, b[spanStart:tagStart]...)
		}
		switch fieldNum {
		case 1: // name
			val, next, err := readBytesField(b, i)
			if err != nil {
				return nil, err
			}
			m.Name = bytesToString(val)
			i = next
		case 2: // generateName
			val, next, err := readBytesField(b, i)
			if err != nil {
				return nil, err
			}
			m.GenerateName = bytesToString(val)
			i = next
		case 3: // namespace
			val, next, err := readBytesField(b, i)
			if err != nil {
				return nil, err
			}
			m.Namespace = bytesToString(val)
			i = next
		case 5: // uid
			val, next, err := readBytesField(b, i)
			if err != nil {
				return nil, err
			}
			m.UID = types.UID(bytesToString(val))
			i = next
		case 6: // resourceVersion
			val, next, err := readBytesField(b, i)
			if err != nil {
				return nil, err
			}
			m.ResourceVersion = bytesToString(val)
			i = next
		case 7: // generation
			v, next, err := readVarint(b, i)
			if err != nil {
				return nil, err
			}
			m.Generation = int64(v)
			i = next
		case 8: // creationTimestamp
			val, next, err := readBytesField(b, i)
			if err != nil {
				return nil, err
			}
			if err := m.CreationTimestamp.Unmarshal(val); err != nil {
				return nil, err
			}
			i = next
		case 9: // deletionTimestamp
			val, next, err := readBytesField(b, i)
			if err != nil {
				return nil, err
			}
			t := &metav1.Time{}
			if err := t.Unmarshal(val); err != nil {
				return nil, err
			}
			m.DeletionTimestamp = t
			i = next
		case 11: // labels
			val, next, err := readBytesField(b, i)
			if err != nil {
				return nil, err
			}
			if m.Labels == nil {
				m.Labels = make(map[string]string, 8)
			}
			k, v, err := scanMapEntryProto(val)
			if err != nil {
				return nil, err
			}
			m.Labels[k] = v
			i = next
		default:
			next, err = skipField(b, i, wireType)
			if err != nil {
				return nil, err
			}
			i = next
		}
		if excludeFromFixed {
			spanStart = i
		}
	}
	if spanStart == 0 {
		return b, nil
	}
	if spanStart < len(b) {
		fixed = append(fixed, b[spanStart:]...)
	}
	return fixed, nil
}

func scanManagedFieldsProto(b []byte) ([]metav1.ManagedFieldsEntry, error) {
	var entries []metav1.ManagedFieldsEntry
	i := 0
	for i < len(b) {
		wire, next, err := readVarint(b, i)
		if err != nil {
			return nil, err
		}
		i = next
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if fieldNum == 17 && wireType == 2 {
			val, next, err := readBytesField(b, i)
			if err != nil {
				return nil, err
			}
			var entry metav1.ManagedFieldsEntry
			if err := entry.Unmarshal(val); err != nil {
				return nil, err
			}
			entries = append(entries, entry)
			i = next
			continue
		}
		next, err = skipField(b, i, wireType)
		if err != nil {
			return nil, err
		}
		i = next
	}
	return entries, nil
}

func scanPodSpecProto(b []byte, l *lazyObjectWrapper) error {
	var deprecatedSA string
	i := 0
	for i < len(b) {
		wire, next, err := readVarint(b, i)
		if err != nil {
			return err
		}
		i = next
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		switch fieldNum {
		case 3: // restartPolicy
			val, next, err := readBytesField(b, i)
			if err != nil {
				return err
			}
			l.restartPolicy = bytesToString(val)
			i = next
		case 8: // serviceAccountName
			val, next, err := readBytesField(b, i)
			if err != nil {
				return err
			}
			l.serviceAccountName = bytesToString(val)
			i = next
		case 9: // deprecatedServiceAccount
			val, next, err := readBytesField(b, i)
			if err != nil {
				return err
			}
			deprecatedSA = bytesToString(val)
			i = next
		case 10: // nodeName
			val, next, err := readBytesField(b, i)
			if err != nil {
				return err
			}
			l.nodeName = bytesToString(val)
			i = next
		case 11: // hostNetwork
			v, next, err := readVarint(b, i)
			if err != nil {
				return err
			}
			l.hostNetwork = (v != 0)
			i = next
		case 19: // schedulerName
			val, next, err := readBytesField(b, i)
			if err != nil {
				return err
			}
			l.schedulerName = bytesToString(val)
			i = next
		default:
			next, err = skipField(b, i, wireType)
			if err != nil {
				return err
			}
			i = next
		}
	}
	if l.serviceAccountName == "" && deprecatedSA != "" {
		l.serviceAccountName = deprecatedSA
	}
	return nil
}

func scanPodStatusProto(b []byte, l *lazyObjectWrapper) error {
	hasFirstPodIP := false
	i := 0
	for i < len(b) {
		wire, next, err := readVarint(b, i)
		if err != nil {
			return err
		}
		i = next
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		switch fieldNum {
		case 1: // phase
			val, next, err := readBytesField(b, i)
			if err != nil {
				return err
			}
			l.phase = bytesToString(val)
			i = next
		case 6: // podIP
			val, next, err := readBytesField(b, i)
			if err != nil {
				return err
			}
			if !hasFirstPodIP {
				l.podIP = bytesToString(val)
			}
			i = next
		case 11: // nominatedNodeName
			val, next, err := readBytesField(b, i)
			if err != nil {
				return err
			}
			l.nominatedNodeName = bytesToString(val)
			i = next
		case 12: // podIPs
			val, next, err := readBytesField(b, i)
			if err != nil {
				return err
			}
			if !hasFirstPodIP {
				ip, err := scanFirstFieldStringProto(val)
				if err != nil {
					return err
				}
				l.podIP = ip
				hasFirstPodIP = true
			}
			i = next
		default:
			next, err = skipField(b, i, wireType)
			if err != nil {
				return err
			}
			i = next
		}
	}
	return nil
}

func scanMapEntryProto(b []byte) (string, string, error) {
	var k, v string
	i := 0
	for i < len(b) {
		wire, next, err := readVarint(b, i)
		if err != nil {
			return "", "", err
		}
		i = next
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if fieldNum == 1 && wireType == 2 {
			val, next, err := readBytesField(b, i)
			if err != nil {
				return "", "", err
			}
			k = bytesToString(val)
			i = next
		} else if fieldNum == 2 && wireType == 2 {
			val, next, err := readBytesField(b, i)
			if err != nil {
				return "", "", err
			}
			v = bytesToString(val)
			i = next
		} else {
			next, err = skipField(b, i, wireType)
			if err != nil {
				return "", "", err
			}
			i = next
		}
	}
	return k, v, nil
}

func scanFirstFieldStringProto(b []byte) (string, error) {
	var s string
	i := 0
	for i < len(b) {
		wire, next, err := readVarint(b, i)
		if err != nil {
			return "", err
		}
		i = next
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if fieldNum == 1 && wireType == 2 {
			val, next, err := readBytesField(b, i)
			if err != nil {
				return "", err
			}
			s = bytesToString(val)
			i = next
		} else {
			next, err = skipField(b, i, wireType)
			if err != nil {
				return "", err
			}
			i = next
		}
	}
	return s, nil
}

func readVarint(b []byte, i int) (uint64, int, error) {
	var wire uint64
	for shift := uint(0); ; shift += 7 {
		if shift >= 64 {
			return 0, i, fmt.Errorf("proto: varint overflow")
		}
		if i >= len(b) {
			return 0, i, io.ErrUnexpectedEOF
		}
		c := b[i]
		i++
		wire |= uint64(c&0x7F) << shift
		if c < 0x80 {
			break
		}
	}
	return wire, i, nil
}

func readBytesField(b []byte, i int) ([]byte, int, error) {
	length, next, err := readVarint(b, i)
	if err != nil {
		return nil, i, err
	}
	n := int(length)
	if n < 0 || next+n < 0 || next+n > len(b) {
		return nil, i, io.ErrUnexpectedEOF
	}
	return b[next : next+n], next + n, nil
}

func skipField(b []byte, i int, wireType int) (int, error) {
	switch wireType {
	case 0: // varint
		_, next, err := readVarint(b, i)
		return next, err
	case 1: // 64-bit
		if i+8 > len(b) {
			return i, io.ErrUnexpectedEOF
		}
		return i + 8, nil
	case 2: // length-delimited
		_, next, err := readBytesField(b, i)
		return next, err
	case 5: // 32-bit
		if i+4 > len(b) {
			return i, io.ErrUnexpectedEOF
		}
		return i + 4, nil
	default:
		return i, fmt.Errorf("proto: unsupported wireType %d", wireType)
	}
}

// ExtractResourceVersionFromStorageBytes extracts metadata.resourceVersion from a protobuf-encoded Kubernetes object envelope.
func ExtractResourceVersionFromStorageBytes(data []byte) (string, error) {
	if len(data) < 4 || !bytes.Equal(data[:4], protoMagicPrefix) {
		return "", fmt.Errorf("not protobuf storage data")
	}
	rawObjBytes, err := extractUnknownRaw(data[4:])
	if err != nil {
		return "", err
	}
	i := 0
	for i < len(rawObjBytes) {
		wire, next, err := readVarint(rawObjBytes, i)
		if err != nil {
			return "", err
		}
		i = next
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if fieldNum == 1 && wireType == 2 {
			metaBytes, _, err := readBytesField(rawObjBytes, i)
			if err != nil {
				return "", err
			}
			j := 0
			for j < len(metaBytes) {
				mWire, mNext, err := readVarint(metaBytes, j)
				if err != nil {
					return "", err
				}
				j = mNext
				mField := int32(mWire >> 3)
				mType := int(mWire & 0x7)
				if mField == 6 && mType == 2 {
					val, _, err := readBytesField(metaBytes, j)
					if err != nil {
						return "", err
					}
					return bytesToString(val), nil
				}
				j, err = skipField(metaBytes, j, mType)
				if err != nil {
					return "", err
				}
			}
			return "", nil
		}
		i, err = skipField(rawObjBytes, i, wireType)
		if err != nil {
			return "", err
		}
	}
	return "", nil
}


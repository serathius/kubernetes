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
	"encoding/json"
	"fmt"
	"reflect"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)


// LazyObject is implemented by wrappers that store serialized bytes and only
// decode the full structure on demand.
type LazyObject interface {
	Decode() (runtime.Object, error)
}

// SerializedObject represents an object that can expose its raw serialized bytes to avoid re-encoding.
type SerializedObject interface {
	SerializedData() []byte
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

type extractedPodAttrs struct {
	nodeName string
}

type lazyObjectWrapper struct {
	metav1.Object

	codec          runtime.Codec
	versioner      Versioner
	data           []byte
	rev            int64
	underlyingType reflect.Type

	podAttrs *extractedPodAttrs

	once    sync.Once
	fullObj runtime.Object
	err     error
}

var _ runtime.Object = &lazyObjectWrapper{}
var _ runtime.TypedObject = &lazyObjectWrapper{}
var _ LazyObject = &lazyObjectWrapper{}
var _ SerializedObject = &lazyObjectWrapper{}

func (l *lazyObjectWrapper) SerializedData() []byte {
	return l.data
}

func NewLazyObjectWrapper(codec runtime.Codec, versioner Versioner, data []byte, rev int64, underlyingType reflect.Type) (runtime.Object, error) {
	meta, err := decodeMetadata(data)
	if err != nil {
		return nil, err
	}
	if err := versioner.UpdateObject(meta, uint64(rev)); err != nil {
		return nil, fmt.Errorf("failure to version api object metadata (%d) %#v: %v", rev, meta, err)
	}

	isPod := false
	if underlyingType != nil {
		t := underlyingType
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		if t.Kind() == reflect.Struct && t.Name() == "Pod" {
			isPod = true
		}
	}

	var podAttrs *extractedPodAttrs
	if isPod {
		attrs, err := extractPodAttrs(data)
		if err != nil {
			return nil, fmt.Errorf("failed to extract pod attributes: %v", err)
		}
		podAttrs = attrs
	}

	return &lazyObjectWrapper{
		Object:         meta,
		codec:          codec,
		versioner:      versioner,
		data:           data,
		rev:            rev,
		underlyingType: underlyingType,
		podAttrs:       podAttrs,
	}, nil
}


func decodeMetadata(data []byte) (*metav1.PartialObjectMetadata, error) {
	if bytes.HasPrefix(data, []byte{0x6b, 0x38, 0x73, 0x00}) {
		unk := &runtime.Unknown{}
		if err := unk.Unmarshal(data[4:]); err != nil {
			return nil, err
		}
		meta := &metav1.PartialObjectMetadata{}
		if err := meta.Unmarshal(unk.Raw); err != nil {
			return nil, err
		}
		return meta, nil
	}

	meta := &metav1.PartialObjectMetadata{}
	if err := json.Unmarshal(data, meta); err != nil {
		return nil, err
	}
	return meta, nil
}

func (l *lazyObjectWrapper) GetObjectKind() schema.ObjectKind {
	return l.Object.(runtime.Object).GetObjectKind()
}

func (l *lazyObjectWrapper) GetUnderlyingType() reflect.Type {
	return l.underlyingType
}

func (l *lazyObjectWrapper) DeepCopyObject() runtime.Object {
	full, err := l.Decode()
	if err != nil {
		panic(fmt.Sprintf("failed to decode lazy object during DeepCopyObject: %v", err))
	}
	return full.DeepCopyObject()
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

func extractPodAttrs(data []byte) (*extractedPodAttrs, error) {
	if bytes.HasPrefix(data, []byte{0x6b, 0x38, 0x73, 0x00}) {
		unk := &runtime.Unknown{}
		if err := unk.Unmarshal(data[4:]); err != nil {
			return nil, err
		}
		return extractAttrsFromPodProto(unk.Raw)
	}
	return extractAttrsFromPodJSON(data)
}

func readVarint(data []byte) (uint64, int) {
	var val uint64
	var shift uint
	for i, b := range data {
		val |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return val, i + 1
		}
		shift += 7
	}
	return 0, 0
}

func skipField(wireType uint64, data []byte) int {
	switch wireType {
	case 0: // varint
		_, n := readVarint(data)
		return n
	case 1: // 64-bit
		return 8
	case 2: // length-delimited
		length, n := readVarint(data)
		return n + int(length)
	case 5: // 32-bit
		return 4
	default:
		return 0
	}
}

func extractAttrsFromPodProto(data []byte) (*extractedPodAttrs, error) {
	attrs := &extractedPodAttrs{}
	idx := 0
	for idx < len(data) {
		key, n := readVarint(data[idx:])
		if n == 0 {
			return nil, fmt.Errorf("invalid proto data")
		}
		idx += n
		fieldNum := key >> 3
		wireType := key & 0x7
		if fieldNum == 2 && wireType == 2 { // Spec field
			specLen, n := readVarint(data[idx:])
			if n == 0 {
				return nil, fmt.Errorf("invalid spec length")
			}
			idx += n
			specEnd := idx + int(specLen)
			for idx < specEnd {
				specKey, sn := readVarint(data[idx:])
				if sn == 0 {
					return nil, fmt.Errorf("invalid spec field key")
				}
				idx += sn
				specFieldNum := specKey >> 3
				specWireType := specKey & 0x7
				switch specFieldNum {
				case 10: // nodeName
					if specWireType == 2 {
						nameLen, ssn := readVarint(data[idx:])
						idx += ssn
						attrs.nodeName = string(data[idx : idx+int(nameLen)])
						idx += int(nameLen)
					}
				default:
					skipLen := skipField(specWireType, data[idx:])
					idx += skipLen
				}
			}
		} else {
			skipLen := skipField(wireType, data[idx:])
			idx += skipLen
		}
	}
	return attrs, nil
}

type podSpecSubset struct {
	Spec struct {
		NodeName string `json:"nodeName,omitempty"`
	} `json:"spec,omitempty"`
}

func extractAttrsFromPodJSON(data []byte) (*extractedPodAttrs, error) {
	pod := &podSpecSubset{}
	if err := json.Unmarshal(data, pod); err != nil {
		return nil, err
	}
	return &extractedPodAttrs{
		nodeName: pod.Spec.NodeName,
	}, nil
}

func GetPodAttrsFromLazyObject(obj runtime.Object) (labels.Set, fields.Set, bool) {
	lazy, ok := obj.(*lazyObjectWrapper)
	if !ok || lazy.podAttrs == nil {
		return nil, nil, false
	}
	attrs := lazy.podAttrs

	podSpecificFieldsSet := make(fields.Set, 3)
	podSpecificFieldsSet["spec.nodeName"] = attrs.nodeName
	podSpecificFieldsSet["metadata.name"] = lazy.GetName()
	podSpecificFieldsSet["metadata.namespace"] = lazy.GetNamespace()

	return labels.Set(lazy.GetLabels()), podSpecificFieldsSet, true
}

// PodAttrsGetter can be implemented by lazy wrappers to expose pod attributes
// without triggering full deserialization.
type PodAttrsGetter interface {
	GetPodAttrs() (nodeName string, ok bool)
}

func (l *lazyObjectWrapper) GetPodAttrs() (string, bool) {
	if l.podAttrs == nil {
		return "", false
	}
	return l.podAttrs.nodeName, true
}



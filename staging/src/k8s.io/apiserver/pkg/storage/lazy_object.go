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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// LazyObject is implemented by wrappers that store serialized bytes and only
// decode the full structure on demand.
type LazyObject interface {
	Decode() (runtime.Object, error)
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
	metav1.Object

	codec          runtime.Codec
	versioner      Versioner
	data           []byte
	rev            int64
	underlyingType reflect.Type

	once    sync.Once
	fullObj runtime.Object
	err     error
}

var _ runtime.Object = &lazyObjectWrapper{}
var _ runtime.TypedObject = &lazyObjectWrapper{}
var _ LazyObject = &lazyObjectWrapper{}

func NewLazyObjectWrapper(codec runtime.Codec, versioner Versioner, data []byte, rev int64, underlyingType reflect.Type) (runtime.Object, error) {
	meta, err := decodeMetadata(data)
	if err != nil {
		return nil, err
	}
	if err := versioner.UpdateObject(meta, uint64(rev)); err != nil {
		return nil, fmt.Errorf("failure to version api object metadata (%d) %#v: %v", rev, meta, err)
	}
	return &lazyObjectWrapper{
		Object:         meta,
		codec:          codec,
		versioner:      versioner,
		data:           data,
		rev:            rev,
		underlyingType: underlyingType,
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

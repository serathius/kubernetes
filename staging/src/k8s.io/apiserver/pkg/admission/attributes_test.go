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

package admission

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	auditinternal "k8s.io/apiserver/pkg/apis/audit"
)

type fakeLazyObject struct {
	decoded     runtime.Object
	decodeCount int
}

func (f *fakeLazyObject) GetObjectKind() schema.ObjectKind { return schema.EmptyObjectKind }
func (f *fakeLazyObject) DeepCopyObject() runtime.Object   { return f }
func (f *fakeLazyObject) IsDecoded() bool                  { return f.decodeCount > 0 }
func (f *fakeLazyObject) EnsureDecodedObject() (runtime.Object, error) {
	f.decodeCount++
	return f.decoded, nil
}

func TestLazyObjectOnDemandDecodeInAttributes(t *testing.T) {
	innerObj := &fakeLazyObject{}
	innerOld := &fakeLazyObject{}
	lazyObj := &fakeLazyObject{decoded: innerObj}
	lazyOld := &fakeLazyObject{decoded: innerOld}

	attr := NewAttributesRecord(lazyObj, lazyOld, schema.GroupVersionKind{}, "default", "foo", schema.GroupVersionResource{}, "", Delete, nil, false, nil)
	assert.Equal(t, 0, lazyObj.decodeCount, "object should not be decoded before GetObject is called")
	assert.Equal(t, 0, lazyOld.decodeCount, "oldObject should not be decoded before GetOldObject is called")

	assert.Same(t, innerObj, attr.GetObject())
	assert.Same(t, innerObj, attr.GetObject())
	assert.Equal(t, 1, lazyObj.decodeCount, "GetObject should decode exactly once")
	assert.Equal(t, 0, lazyOld.decodeCount, "GetObject should not decode oldObject")

	assert.Same(t, innerOld, attr.GetOldObject())
	assert.Same(t, innerOld, attr.GetOldObject())
	assert.Equal(t, 1, lazyOld.decodeCount, "GetOldObject should decode exactly once")
}

func TestAddAnnotation(t *testing.T) {
	attr := &attributesRecord{}

	// test AddAnnotation
	attr.AddAnnotation("foo.admission.k8s.io/key1", "value1")
	attr.AddAnnotation("foo.admission.k8s.io/key2", "value2")
	annotations := attr.getAnnotations(auditinternal.LevelMetadata)
	assert.Equal(t, "value1", annotations["foo.admission.k8s.io/key1"])

	// test overwrite
	assert.Error(t, attr.AddAnnotation("foo.admission.k8s.io/key1", "value1-overwrite"),
		"admission annotations should not be allowd to be overwritten")
	annotations = attr.getAnnotations(auditinternal.LevelMetadata)
	assert.Equal(t, "value1", annotations["foo.admission.k8s.io/key1"], "admission annotations should not be overwritten")

	// test invalid plugin names
	var testCases = map[string]string{
		"invalid dns subdomain": "INVALID-DNS-Subdomain/policy",
		"no plugin name":        "policy",
		"no key name":           "foo.admission.k8s.io",
		"empty key":             "",
	}
	for name, invalidKey := range testCases {
		err := attr.AddAnnotation(invalidKey, "value-foo")
		assert.Error(t, err)
		annotations = attr.getAnnotations(auditinternal.LevelMetadata)
		assert.Equal(t, "", annotations[invalidKey], name+": invalid pluginName is not allowed ")
	}

	// test all saved annotations
	assert.Equal(
		t,
		map[string]string{
			"foo.admission.k8s.io/key1": "value1",
			"foo.admission.k8s.io/key2": "value2",
		}, annotations,
		"unexpected final annotations",
	)
}

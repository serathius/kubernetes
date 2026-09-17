/*
Copyright 2026 The Kubernetes Authors.

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

package handlers

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
)

// objectMetaSchemaReference provides the strategic merge patch metadata (patch strategies
// and merge keys) of the metadata subtree. ObjectMeta is version independent, so a single
// instance works for every group/version/kind.
var objectMetaSchemaReference = &metav1.ObjectMeta{}

// errUnsupportedMetadataOnlyPatch is returned if an object turns out not to support the
// metadata scoped patch path after supportsMetadataOnlyPatch accepted it, which would mean
// the two checks disagree.
var errUnsupportedMetadataOnlyPatch = fmt.Errorf("object does not support metadata scoped patching")

// metadataOnlyPatchMap returns the metadata subtree of a strategic merge patch if applying
// the patch cannot affect anything outside of metadata.
//
// The patch must consist of exactly one non-empty "metadata" object: any other top level
// key, including strategic merge directives such as "$patch" or "$retainKeys", may change
// fields outside of metadata (or delete the metadata subtree itself) and disqualifies the
// scoped path.
func metadataOnlyPatchMap(patchMap map[string]interface{}) (map[string]interface{}, bool) {
	if len(patchMap) != 1 {
		return nil, false
	}
	metadataPatch, ok := patchMap["metadata"].(map[string]interface{})
	if !ok || len(metadataPatch) == 0 {
		return nil, false
	}
	return metadataPatch, true
}

// objectMetaOf returns the ObjectMeta embedded in a typed API object. Objects that do not
// embed metav1.ObjectMeta (unstructured objects, lists, objects without metadata) are not
// supported and report false.
//
// meta.Accessor is not usable here: typed objects satisfy metav1.Object through the methods
// promoted from the embedded ObjectMeta, so the accessor hands back the object itself
// rather than the metadata subtree we want to patch in isolation.
func objectMetaOf(obj runtime.Object) (*metav1.ObjectMeta, bool) {
	value := reflect.ValueOf(obj)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return nil, false
	}
	elem := value.Elem()
	if elem.Kind() != reflect.Struct {
		return nil, false
	}
	index, ok := objectMetaFieldIndex(elem.Type())
	if !ok {
		return nil, false
	}
	return elem.Field(index).Addr().Interface().(*metav1.ObjectMeta), true
}

var objectMetaType = reflect.TypeOf(metav1.ObjectMeta{})

// objectMetaFieldIndices caches reflect.Type -> index of the embedded ObjectMeta field.
var objectMetaFieldIndices sync.Map

func objectMetaFieldIndex(objectType reflect.Type) (int, bool) {
	if cached, ok := objectMetaFieldIndices.Load(objectType); ok {
		index := cached.(int)
		return index, index >= 0
	}
	index := -1
	for i := 0; i < objectType.NumField(); i++ {
		if field := objectType.Field(i); field.Anonymous && field.Type == objectMetaType {
			index = i
			break
		}
	}
	objectMetaFieldIndices.Store(objectType, index)
	return index, index >= 0
}

// supportsMetadataOnlyPatch reports whether the metadata scoped patch path can be used for
// this pair of objects. Both must be the same concrete pointer-to-struct type embedding
// ObjectMeta, so that everything outside of metadata can be copied as-is.
func supportsMetadataOnlyPatch(originalObject, objToUpdate runtime.Object) bool {
	originalType := reflect.TypeOf(originalObject)
	if originalType != reflect.TypeOf(objToUpdate) || originalType == nil || originalType.Kind() != reflect.Pointer {
		return false
	}
	if _, ok := objectMetaOf(originalObject); !ok {
		return false
	}
	_, ok := objectMetaOf(objToUpdate)
	return ok
}

// applyMetadataPatchToObject applies the metadata subtree of a strategic merge patch,
// copying everything outside of metadata from originalObject verbatim.
//
// This is equivalent to converting the whole object to unstructured, merging, and
// converting it back, but the conversions are $O(\text{len(metadata)})$ instead of
// $O(\text{len(object)})$, which matters a lot for objects with a large spec/status.
func applyMetadataPatchToObject(
	requestContext context.Context,
	defaulter runtime.ObjectDefaulter,
	originalObject runtime.Object,
	patchMap map[string]interface{},
	metadataPatch map[string]interface{},
	objToUpdate runtime.Object,
	strictErrs []error,
	validationDirective string,
) error {
	originalMeta, ok := objectMetaOf(originalObject)
	if !ok {
		return errUnsupportedMetadataOnlyPatch
	}
	_, patchesManagedFields := metadataPatch["managedFields"]

	// managedFields belong to the field manager, which recomputes them right after the
	// patch is applied. Unless the patch explicitly targets them, keep the FieldsV1 blobs
	// (tens of kilobytes on an object with a handful of managers) out of both the deep
	// copy below and the round trip through unstructured.
	source := originalObject
	metadataToPatch := originalMeta
	if !patchesManagedFields {
		detached, detachedMeta, ok := shallowCopyObject(originalObject)
		if !ok {
			return errUnsupportedMetadataOnlyPatch
		}
		detachedMeta.ManagedFields = nil
		source, metadataToPatch = detached, detachedMeta
	}

	// Everything but metadata is carried over untouched. The deep copy keeps the patched
	// object from aliasing the object the storage layer handed us, which admission
	// plugins and update validation rely on.
	if !deepCopyObjectInto(source, objToUpdate) {
		return errUnsupportedMetadataOnlyPatch
	}
	updatedMeta, ok := objectMetaOf(objToUpdate)
	if !ok {
		return errUnsupportedMetadataOnlyPatch
	}
	if !patchesManagedFields {
		// Carried over by reference: entries are replaced, never mutated in place, and the
		// field manager overwrites this slice with the result of the update anyway.
		defer func() {
			updatedMeta.ManagedFields = originalMeta.ManagedFields
		}()
	}

	originalMetaMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(metadataToPatch)
	if err != nil {
		return err
	}
	patchedMetaMap, err := strategicpatch.StrategicMergeMapPatch(originalMetaMap, metadataPatch, objectMetaSchemaReference)
	if err != nil {
		return interpretStrategicMergePatchError(err)
	}

	returnUnknownFields := validationDirective == metav1.FieldValidationWarn || validationDirective == metav1.FieldValidationStrict
	err = runtime.DefaultUnstructuredConverter.FromUnstructuredWithValidation(patchedMetaMap, updatedMeta, returnUnknownFields)
	if err := handlePatchDecodingErrors(requestContext, err, patchMap, strictErrs, validationDirective); err != nil {
		return err
	}

	// Decoding from JSON to a versioned object would apply defaults, so we do the same here
	defaulter.Default(objToUpdate)
	return nil
}

// shallowCopyObject returns a copy of obj that shares all of its referenced memory, along
// with the metadata of the copy. Only fields that are replaced (not mutated in place) on
// the copy may be touched.
func shallowCopyObject(obj runtime.Object) (runtime.Object, *metav1.ObjectMeta, bool) {
	value := reflect.ValueOf(obj)
	if value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		return nil, nil, false
	}
	copiedValue := reflect.New(value.Elem().Type())
	copiedValue.Elem().Set(value.Elem())
	copied, ok := copiedValue.Interface().(runtime.Object)
	if !ok {
		return nil, nil, false
	}
	copiedMeta, ok := objectMetaOf(copied)
	if !ok {
		return nil, nil, false
	}
	return copied, copiedMeta, true
}

// deepCopyObjectInto deep copies src into the object dst points at.
func deepCopyObjectInto(src, dst runtime.Object) bool {
	dstValue := reflect.ValueOf(dst)
	if dstValue.Kind() != reflect.Pointer || dstValue.IsNil() {
		return false
	}
	copied := reflect.ValueOf(src.DeepCopyObject())
	if copied.Type() != dstValue.Type() {
		return false
	}
	dstValue.Elem().Set(copied.Elem())
	return true
}

// updateMetadataScopedManagedFields updates managedFields for an update that is known to
// leave everything outside of metadata untouched.
//
// The field manager only needs to observe the metadata subtree in that case: the
// structured-merge-diff comparison of two identical subtrees contributes nothing to the
// added/modified/removed field sets, so projecting both objects down to their metadata
// produces the same managedFields while converting (and schema validating) a fraction of
// the object.
//
// Reports false if the objects do not support projection, in which case the caller must
// fall back to the unscoped field manager update.
func updateMetadataScopedManagedFields(fieldManager *managedfields.FieldManager, liveObj, newObj runtime.Object, manager string) (runtime.Object, bool) {
	liveProjection, liveProjectionMeta, ok := projectObjectMetadata(liveObj)
	if !ok {
		return nil, false
	}
	newProjection, _, ok := projectObjectMetadata(newObj)
	if !ok {
		return nil, false
	}
	newMeta, ok := objectMetaOf(newObj)
	if !ok {
		return nil, false
	}

	// The live managedFields never take part in the diff: the field manager drops them
	// from the new object before comparing, and .metadata.managedFields is stripped from
	// every manager's field set. Dropping them here avoids re-parsing the (potentially
	// very large) FieldsV1 blobs into the typed live object on every request.
	liveProjectionMeta.ManagedFields = nil

	result := fieldManager.UpdateNoErrors(liveProjection, newProjection, manager)
	resultMeta, ok := objectMetaOf(result)
	if !ok {
		return nil, false
	}
	newMeta.ManagedFields = resultMeta.ManagedFields
	return newObj, true
}

// projectObjectMetadata returns a new, otherwise empty object of the same type as obj that
// carries obj's type meta and a shallow copy of its metadata.
func projectObjectMetadata(obj runtime.Object) (runtime.Object, *metav1.ObjectMeta, bool) {
	value := reflect.ValueOf(obj)
	if value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		return nil, nil, false
	}
	objectMeta, ok := objectMetaOf(obj)
	if !ok {
		return nil, nil, false
	}
	projection, ok := reflect.New(value.Elem().Type()).Interface().(runtime.Object)
	if !ok {
		return nil, nil, false
	}
	projectionMeta, ok := objectMetaOf(projection)
	if !ok {
		return nil, nil, false
	}
	projection.GetObjectKind().SetGroupVersionKind(obj.GetObjectKind().GroupVersionKind())
	// Shallow copy: the field manager reads the metadata but never mutates it in place.
	*projectionMeta = *objectMeta
	return projection, projectionMeta, true
}

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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

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
func isLabelsOnlyMetadataPatch(metadataPatch map[string]interface{}) bool {
	if len(metadataPatch) != 1 {
		return false
	}
	_, ok := metadataPatch["labels"]
	return ok
}

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
	if originalMeta.LazyWire != nil && !isLabelsOnlyMetadataPatch(metadataPatch) && originalMeta.LazyWire.DecodeFullInto != nil {
		if err := originalMeta.LazyWire.DecodeFullInto(originalObject); err != nil {
			return err
		}
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

	// Everything outside of metadata is carried over by shallow copy so untouched
	// subtrees (such as Pod.Spec and Pod.Status) are not deep-copied and retain
	// pointer identity with originalObject for downstream DeepEqual checks.
	if !shallowCopyObjectInto(source, objToUpdate) {
		return errUnsupportedMetadataOnlyPatch
	}
	updatedMeta, ok := objectMetaOf(objToUpdate)
	if !ok {
		return errUnsupportedMetadataOnlyPatch
	}
	// Reset updatedMeta before decoding patchedMetaMap so FromUnstructuredWithValidation
	// allocates fresh maps/slices rather than mutating originalMeta's backing storage.
	*updatedMeta = metav1.ObjectMeta{}
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

// applyMetadataScopedPatch applies a metadata-only strategic merge patch directly to a
// shallow copy of currentObject without converting or deep-copying untouched subtrees
// (such as Spec and Status) to the external version and back.
//
// Returns (nil, false, nil) if the patch touches anything outside of metadata or if the
// object does not embed metav1.ObjectMeta.
func (p *smpPatcher) applyMetadataScopedPatch(requestContext context.Context, currentObject runtime.Object, manager string) (runtime.Object, bool, error) {
	currentMeta, ok := objectMetaOf(currentObject)
	if !ok {
		return nil, false, nil
	}
	if patched, ok := p.tryApplyLabelsOnlyFastPath(currentObject, currentMeta, manager); ok {
		return patched, true, nil
	}
	if currentMeta.LazyWire != nil && currentMeta.LazyWire.DecodeFullInto != nil {
		if decErr := currentMeta.LazyWire.DecodeFullInto(currentObject); decErr != nil {
			return nil, true, decErr
		}
	}
	versionedCarrier, carrierMeta, ok := p.newVersionedMetadataCarrier(currentObject)
	if !ok {
		return nil, false, nil
	}
	versionedObjToUpdate, err := p.creater.New(p.kind)
	if err != nil {
		return nil, false, nil
	}

	metadataOnly, err := strategicPatchObjectWithScope(
		requestContext,
		p.defaulter,
		versionedCarrier,
		p.patchBytes,
		versionedObjToUpdate,
		p.schemaReferenceObj,
		p.validationDirective,
	)
	if !metadataOnly {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	_ = carrierMeta

	updatedVersionedMeta, ok := objectMetaOf(versionedObjToUpdate)
	if !ok {
		return nil, false, nil
	}
	newObj, newMeta, ok := shallowCopyObject(currentObject)
	if !ok {
		return nil, false, nil
	}
	*newMeta = *updatedVersionedMeta

	if scoped, ok := updateMetadataScopedManagedFields(p.fieldManager, currentObject, newObj, manager); ok {
		return scoped, true, nil
	}
	return p.fieldManager.UpdateNoErrors(currentObject, newObj, manager), true, nil
}

// tryApplyLabelsOnlyFastPath handles the common {"metadata":{"labels":{"k":"v"}}} patch
// directly on ObjectMeta without unstructured round-trips or structured-merge-diff walkers
// when the patched label keys are already exclusively owned by manager.
func (p *smpPatcher) tryApplyLabelsOnlyFastPath(currentObject runtime.Object, currentMeta *metav1.ObjectMeta, manager string) (runtime.Object, bool) {
	patchedLabels, ok := parseSimpleLabelsOnlyPatch(p.patchBytes)
	if !ok || len(patchedLabels) == 0 {
		return nil, false
	}

	newObj, newMeta, ok := shallowCopyObject(currentObject)
	if !ok {
		return nil, false
	}
	newLabels := make(map[string]string, len(currentMeta.Labels)+len(patchedLabels))
	for k, v := range currentMeta.Labels {
		newLabels[k] = v
	}
	for k, v := range patchedLabels {
		newLabels[k] = v
	}
	newMeta.Labels = newLabels
	if currentMeta.LazyWire != nil {
		newMeta.LazyWire = currentMeta.LazyWire.WithMetaModified()
	}

	apiVersion := p.kind.GroupVersion().String()
	if updatedMF, ok := tryUpdateManagedFieldsForOwnedLabels(currentMeta, patchedLabels, manager, apiVersion); ok {
		newMeta.ManagedFields = updatedMF
		return newObj, true
	}
	if scoped, ok := updateMetadataScopedManagedFields(p.fieldManager, currentObject, newObj, manager); ok {
		return scoped, true
	}
	if currentMeta.LazyWire != nil {
		return nil, false
	}
	return p.fieldManager.UpdateNoErrors(currentObject, newObj, manager), true
}

func isSimpleLabelsOnlyPatchPayload(patchBytes []byte) bool {
	trimmed := bytes.TrimSpace(patchBytes)
	return bytes.HasPrefix(trimmed, []byte(`{"metadata":{"labels":{`)) && bytes.HasSuffix(trimmed, []byte(`}}}`))
}

func parseSimpleLabelsOnlyPatch(patchBytes []byte) (map[string]string, bool) {
	// Fast prefix check for `{"metadata":{"labels":{`
	trimmed := bytes.TrimSpace(patchBytes)
	if !bytes.HasPrefix(trimmed, []byte(`{"metadata":{"labels":{`)) || !bytes.HasSuffix(trimmed, []byte(`}}}`)) {
		return nil, false
	}
	inner := trimmed[len(`{"metadata":{"labels":`) : len(trimmed)-2]
	if bytes.Contains(inner, []byte(`"$patch"`)) || bytes.Contains(inner, []byte(`null`)) {
		return nil, false
	}
	var labels map[string]string
	if err := json.Unmarshal(inner, &labels); err != nil || len(labels) == 0 {
		return nil, false
	}
	return labels, true
}

func tryUpdateManagedFieldsForOwnedLabels(currentMeta *metav1.ObjectMeta, patchedLabels map[string]string, manager, apiVersion string) ([]metav1.ManagedFieldsEntry, bool) {
	if len(currentMeta.ManagedFields) == 0 || len(currentMeta.Labels) == 0 {
		return nil, false
	}
	managerIdx := -1
	for i := range currentMeta.ManagedFields {
		mf := &currentMeta.ManagedFields[i]
		if mf.Manager == manager && mf.Operation == metav1.ManagedFieldsOperationUpdate && mf.APIVersion == apiVersion && mf.Subresource == "" {
			if managerIdx != -1 {
				return nil, false
			}
			managerIdx = i
		}
	}
	if managerIdx == -1 || currentMeta.ManagedFields[managerIdx].FieldsV1 == nil {
		return nil, false
	}
	managerRaw := currentMeta.ManagedFields[managerIdx].FieldsV1.String()

	for k := range patchedLabels {
		if _, exists := currentMeta.Labels[k]; !exists {
			return nil, false
		}
		var needleBuf [64]byte
		needle := append(needleBuf[:0], `"f:`...)
		needle = append(needle, k...)
		needle = append(needle, `":`...)
		needleStr := string(needle)
		if !strings.Contains(managerRaw, string(append(needle, '{', '}'))) {
			return nil, false
		}
		for i := range currentMeta.ManagedFields {
			if i == managerIdx || currentMeta.ManagedFields[i].FieldsV1 == nil {
				continue
			}
			if strings.Contains(currentMeta.ManagedFields[i].FieldsV1.String(), needleStr) {
				return nil, false
			}
		}
	}

	newMF := make([]metav1.ManagedFieldsEntry, len(currentMeta.ManagedFields))
	copy(newMF, currentMeta.ManagedFields)
	now := metav1.NewTime(time.Now().UTC())
	newMF[managerIdx].Time = &now
	return newMF, true
}

func (p *smpPatcher) newVersionedMetadataCarrier(currentObject runtime.Object) (runtime.Object, *metav1.ObjectMeta, bool) {
	currentMeta, ok := objectMetaOf(currentObject)
	if !ok {
		return nil, nil, false
	}
	carrier, err := p.creater.New(p.kind)
	if err != nil {
		return nil, nil, false
	}
	carrierMeta, ok := objectMetaOf(carrier)
	if !ok {
		return nil, nil, false
	}
	*carrierMeta = *currentMeta
	return carrier, carrierMeta, true
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

// shallowCopyObjectInto copies the top-level struct of src into dst without deep-copying
// referenced subtrees.
func shallowCopyObjectInto(src, dst runtime.Object) bool {
	srcValue := reflect.ValueOf(src)
	dstValue := reflect.ValueOf(dst)
	if srcValue.Kind() != reflect.Pointer || srcValue.IsNil() || dstValue.Kind() != reflect.Pointer || dstValue.IsNil() {
		return false
	}
	if srcValue.Type() != dstValue.Type() {
		return false
	}
	dstValue.Elem().Set(srcValue.Elem())
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

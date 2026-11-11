/*
Copyright 2019 The Kubernetes Authors.

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
	"fmt"
	"sigs.k8s.io/structured-merge-diff/v7/fieldpath"
	"sigs.k8s.io/structured-merge-diff/v7/merge"
	"sigs.k8s.io/structured-merge-diff/v7/typed"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type structuredMergeManager struct {
	typeConverter   TypeConverter
	objectConverter runtime.ObjectConvertor
	objectDefaulter runtime.ObjectDefaulter
	groupVersion    schema.GroupVersion
	hubVersion      schema.GroupVersion
	updater         merge.Updater
	ignoreSpec      bool
	ignoreStatus    bool
}

var _ Manager = &structuredMergeManager{}

var (
	filterProbeSet  = fieldpath.NewSet(fieldpath.MakePathOrDie("__probe__"))
	filterSpecSet   = fieldpath.NewSet(fieldpath.MakePathOrDie("spec"))
	filterStatusSet = fieldpath.NewSet(fieldpath.MakePathOrDie("status"))
)

func excludedTopLevelSections(gv schema.GroupVersion, resetFields map[fieldpath.APIVersion]fieldpath.Filter) (ignoreSpec, ignoreStatus bool) {
	if resetFields == nil {
		return false, false
	}
	filter := resetFields[fieldpath.APIVersion(gv.String())]
	if filter == nil || filter.Filter(filterProbeSet).Empty() {
		return false, false
	}
	return filter.Filter(filterSpecSet).Empty(), filter.Filter(filterStatusSet).Empty()
}

// NewStructuredMergeManager creates a new Manager that merges apply requests
// and update managed fields for other types of requests.
func NewStructuredMergeManager(typeConverter TypeConverter, objectConverter runtime.ObjectConvertor, objectDefaulter runtime.ObjectDefaulter, gv schema.GroupVersion, hub schema.GroupVersion, resetFields map[fieldpath.APIVersion]fieldpath.Filter) (Manager, error) {
	if typeConverter == nil {
		return nil, fmt.Errorf("typeconverter must not be nil")
	}
	ignoreSpec, ignoreStatus := excludedTopLevelSections(gv, resetFields)
	return &structuredMergeManager{
		typeConverter:   typeConverter,
		objectConverter: objectConverter,
		objectDefaulter: objectDefaulter,
		groupVersion:    gv,
		hubVersion:      hub,
		updater: merge.Updater{
			Converter:    newVersionConverter(typeConverter, objectConverter, hub), // This is the converter provided to SMD from k8s
			IgnoreFilter: resetFields,
		},
		ignoreSpec:   ignoreSpec,
		ignoreStatus: ignoreStatus,
	}, nil
}

// NewCRDStructuredMergeManager creates a new Manager specifically for
// CRDs. This allows for the possibility of fields which are not defined
// in models, as well as having no models defined at all.
func NewCRDStructuredMergeManager(typeConverter TypeConverter, objectConverter runtime.ObjectConvertor, objectDefaulter runtime.ObjectDefaulter, gv schema.GroupVersion, hub schema.GroupVersion, resetFields map[fieldpath.APIVersion]fieldpath.Filter) (_ Manager, err error) {
	return &structuredMergeManager{
		typeConverter:   typeConverter,
		objectConverter: objectConverter,
		objectDefaulter: objectDefaulter,
		groupVersion:    gv,
		hubVersion:      hub,
		updater: merge.Updater{
			Converter:    newCRDVersionConverter(typeConverter, objectConverter, hub),
			IgnoreFilter: resetFields,
		},
	}, nil
}

func objectGVKNN(obj runtime.Object) string {
	name := "<unknown>"
	namespace := "<unknown>"
	if accessor, err := meta.Accessor(obj); err == nil {
		name = accessor.GetName()
		namespace = accessor.GetNamespace()
	}

	return fmt.Sprintf("%v/%v; %v", namespace, name, obj.GetObjectKind().GroupVersionKind())
}

// Update implements Manager.
func (f *structuredMergeManager) Update(liveObj, newObj runtime.Object, managed Managed, manager string) (runtime.Object, Managed, error) {
	newObjVersioned, err := f.toVersioned(newObj)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert new object (%v) to proper version (%v): %v", objectGVKNN(newObj), f.groupVersion, err)
	}
	liveObjVersioned, err := f.toVersioned(liveObj)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert live object (%v) to proper version: %v", objectGVKNN(liveObj), err)
	}
	projected := false
	if projector, ok := liveObjVersioned.(runtime.LazyUpdateProjector); ok {
		if liveProj, newProj, projOK, projErr := projector.ProjectForUpdate(newObjVersioned, f.ignoreSpec, f.ignoreStatus); projErr != nil {
			return nil, nil, fmt.Errorf("failed to project objects (%v) for update: %v", objectGVKNN(liveObj), projErr)
		} else if projOK {
			liveObjVersioned = liveProj
			newObjVersioned = newProj
			projected = true
		}
	}
	if !projected {
		if projector, ok := newObjVersioned.(runtime.LazyUpdateProjector); ok {
			if newProj, liveProj, projOK, projErr := projector.ProjectForUpdate(liveObjVersioned, f.ignoreSpec, f.ignoreStatus); projErr != nil {
				return nil, nil, fmt.Errorf("failed to project objects (%v) for update: %v", objectGVKNN(newObj), projErr)
			} else if projOK {
				newObjVersioned = newProj
				liveObjVersioned = liveProj
				projected = true
			}
		}
	}
	if !projected {
		newObjVersioned, err = runtime.EnsureDecodedObject(newObjVersioned)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode new object (%v): %v", objectGVKNN(newObjVersioned), err)
		}
		liveObjVersioned, err = runtime.EnsureDecodedObject(liveObjVersioned)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode live object (%v): %v", objectGVKNN(liveObjVersioned), err)
		}
	}
	newObjTyped, err := f.typeConverter.ObjectToTyped(newObjVersioned, typed.AllowDuplicates)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert new object (%v) to smd typed: %v", objectGVKNN(newObjVersioned), err)
	}
	// Temporarily clear managedFields on liveObjVersioned so ObjectToTyped and
	// updater.Update do not walk it (newObj's managedFields are already cleared,
	// and stripMetaManager ignores metadata.managedFields).
	if !projected {
		if liveMeta, ok := liveObjVersioned.(metav1.ObjectMetaAccessor); ok {
			objectMeta := liveMeta.GetObjectMeta()
			managedFields := objectMeta.GetManagedFields()
			objectMeta.SetManagedFields(nil)
			defer objectMeta.SetManagedFields(managedFields)
		}
	}
	liveObjTyped, err := f.typeConverter.ObjectToTyped(liveObjVersioned, typed.AllowDuplicates)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert live object (%v) to smd typed: %v", objectGVKNN(liveObjVersioned), err)
	}
	apiVersion := fieldpath.APIVersion(f.groupVersion.String())

	// TODO(apelisse) use the first return value when unions are implemented
	_, managedFields, err := f.updater.Update(liveObjTyped, newObjTyped, apiVersion, managed.Fields(), manager)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to update ManagedFields (%v): %v", objectGVKNN(newObjVersioned), err)
	}
	managed = withManagedFields(managed, managedFields)

	return newObj, managed, nil
}

// Apply implements Manager.
func (f *structuredMergeManager) Apply(liveObj, patchObj runtime.Object, managed Managed, manager string, force bool) (runtime.Object, Managed, error) {
	// Check that the patch object has the same version as the live object
	if patchVersion := patchObj.GetObjectKind().GroupVersionKind().GroupVersion(); patchVersion != f.groupVersion {
		return nil, nil,
			errors.NewBadRequest(
				fmt.Sprintf("Incorrect version specified in apply patch. "+
					"Specified patch version: %s, expected: %s",
					patchVersion, f.groupVersion))
	}

	patchObjMeta, err := meta.Accessor(patchObj)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't get accessor: %v", err)
	}
	if patchObjMeta.GetManagedFields() != nil {
		return nil, nil, errors.NewBadRequest("metadata.managedFields must be nil")
	}

	liveObjVersioned, err := f.toVersioned(liveObj)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert live object (%v) to proper version: %v", objectGVKNN(liveObj), err)
	}

	// Don't allow duplicates in the applied object.
	patchObjTyped, err := f.typeConverter.ObjectToTyped(patchObj)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create typed patch object (%v): %v", objectGVKNN(patchObj), err)
	}

	apiVersion := fieldpath.APIVersion(f.groupVersion.String())
	if subtreePatcher, ok := liveObjVersioned.(runtime.LazySubtreePatcher); ok && !subtreePatcher.IsDecoded() {
		if includeMetadata, specTagMask, statusTagMask, subOK := computeApplySubtree(patchObj, managed.Fields(), manager, apiVersion, subtreePatcher); subOK {
			liveProj, err := subtreePatcher.ExtractSubtreePatchBase(includeMetadata, specTagMask, statusTagMask, true)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to extract subtree live object (%v): %v", objectGVKNN(liveObjVersioned), err)
			}
			liveObjTyped, err := f.typeConverter.ObjectToTyped(liveProj, typed.AllowDuplicates)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create typed live object (%v): %v", objectGVKNN(liveObjVersioned), err)
			}
			newObjTyped, managedFields, err := f.updater.Apply(liveObjTyped, patchObjTyped, apiVersion, managed.Fields(), manager, force)
			if err != nil {
				return nil, nil, err
			}
			managed = withManagedFields(managed, managedFields)
			if newObjTyped == nil {
				return nil, managed, nil
			}
			newObj, err := f.typeConverter.TypedToObject(newObjTyped)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to convert new typed object (%v) to object: %v", objectGVKNN(patchObj), err)
			}
			newObjVersioned, err := f.toVersioned(newObj)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to convert new object (%v) to proper version: %v", objectGVKNN(patchObj), err)
			}
			f.objectDefaulter.Default(newObjVersioned)
			splicedVersioned, err := subtreePatcher.SpliceSubtreePatchResult(newObjVersioned, includeMetadata, specTagMask, statusTagMask)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to splice subtree result (%v): %v", objectGVKNN(patchObj), err)
			}
			newObjUnversioned, err := f.toUnversioned(splicedVersioned)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to convert to unversioned (%v): %v", objectGVKNN(patchObj), err)
			}
			return newObjUnversioned, managed, nil
		}
	}

	liveObjVersioned, err = runtime.EnsureDecodedObject(liveObjVersioned)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode live object (%v): %v", objectGVKNN(liveObjVersioned), err)
	}

	liveObjTyped, err := f.typeConverter.ObjectToTyped(liveObjVersioned, typed.AllowDuplicates)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create typed live object (%v): %v", objectGVKNN(liveObjVersioned), err)
	}

	newObjTyped, managedFields, err := f.updater.Apply(liveObjTyped, patchObjTyped, apiVersion, managed.Fields(), manager, force)
	if err != nil {
		return nil, nil, err
	}
	managed = withManagedFields(managed, managedFields)

	if newObjTyped == nil {
		return nil, managed, nil
	}

	newObj, err := f.typeConverter.TypedToObject(newObjTyped)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert new typed object (%v) to object: %v", objectGVKNN(patchObj), err)
	}

	newObjVersioned, err := f.toVersioned(newObj)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert new object (%v) to proper version: %v", objectGVKNN(patchObj), err)
	}
	f.objectDefaulter.Default(newObjVersioned)

	newObjUnversioned, err := f.toUnversioned(newObjVersioned)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert to unversioned (%v): %v", objectGVKNN(patchObj), err)
	}
	return newObjUnversioned, managed, nil
}

func computeApplySubtree(patchObj runtime.Object, managedFields fieldpath.ManagedFields, manager string, apiVersion fieldpath.APIVersion, subtreePatcher runtime.LazySubtreePatcher) (includeMetadata bool, specTagMask, statusTagMask uint64, ok bool) {
	patchUnstructured, isUnstructured := patchObj.(runtime.Unstructured)
	if !isUnstructured {
		return false, 0, 0, false
	}
	for _, vs := range managedFields {
		if vs != nil && vs.APIVersion() != apiVersion {
			return false, 0, 0, false
		}
	}
	for k, v := range patchUnstructured.UnstructuredContent() {
		switch k {
		case "apiVersion", "kind":
		case "metadata":
			if v != nil {
				if _, isMap := v.(map[string]interface{}); !isMap {
					return false, 0, 0, false
				}
			}
			includeMetadata = true
		case "status":
			if v == nil {
				statusTagMask = ^uint64(0)
				continue
			}
			statusMap, isMap := v.(map[string]interface{})
			if !isMap {
				return false, 0, 0, false
			}
			for sk := range statusMap {
				m, known := subtreePatcher.StatusTagMaskForField(sk)
				if !known {
					statusTagMask = ^uint64(0)
					break
				}
				statusTagMask |= m
			}
		case "spec":
			if v == nil {
				return false, 0, 0, false
			}
			specMap, isMap := v.(map[string]interface{})
			if !isMap {
				return false, 0, 0, false
			}
			for sk := range specMap {
				m, known := subtreePatcher.SpecTagMaskForField(sk)
				if !known {
					return false, 0, 0, false
				}
				specTagMask |= m
			}
		default:
			return false, 0, 0, false
		}
	}

	if lastSet := managedFields[manager]; lastSet != nil && !lastSet.Set().Empty() {
		valid := true
		lastSet.Set().Members.Iterate(func(pe fieldpath.PathElement) {
			if !valid {
				return
			}
			if pe.FieldName == nil {
				valid = false
				return
			}
			switch *pe.FieldName {
			case "apiVersion", "kind":
			case "metadata":
				includeMetadata = true
			case "status":
				statusTagMask = ^uint64(0)
			default:
				valid = false
			}
		})
		if !valid {
			return false, 0, 0, false
		}
		lastSet.Set().Children.Iterate(func(pe fieldpath.PathElement) {
			if !valid {
				return
			}
			if pe.FieldName == nil {
				valid = false
				return
			}
			switch *pe.FieldName {
			case "metadata":
				includeMetadata = true
			case "status":
				if statusTagMask == ^uint64(0) {
					return
				}
				if statusSet, hasStatus := lastSet.Set().Children.Get(pe); hasStatus && statusSet != nil {
					statusSet.Members.Iterate(func(spe fieldpath.PathElement) {
						if statusTagMask == ^uint64(0) {
							return
						}
						if spe.FieldName == nil {
							statusTagMask = ^uint64(0)
							return
						}
						m, known := subtreePatcher.StatusTagMaskForField(*spe.FieldName)
						if !known {
							statusTagMask = ^uint64(0)
							return
						}
						statusTagMask |= m
					})
					statusSet.Children.Iterate(func(spe fieldpath.PathElement) {
						if statusTagMask == ^uint64(0) {
							return
						}
						if spe.FieldName == nil {
							statusTagMask = ^uint64(0)
							return
						}
						m, known := subtreePatcher.StatusTagMaskForField(*spe.FieldName)
						if !known {
							statusTagMask = ^uint64(0)
							return
						}
						statusTagMask |= m
					})
				}
			case "spec":
				if specSet, hasSpec := lastSet.Set().Children.Get(pe); hasSpec && specSet != nil {
					specSet.Members.Iterate(func(spe fieldpath.PathElement) {
						if !valid {
							return
						}
						if spe.FieldName == nil {
							valid = false
							return
						}
						m, known := subtreePatcher.SpecTagMaskForField(*spe.FieldName)
						if !known {
							valid = false
							return
						}
						specTagMask |= m
					})
					specSet.Children.Iterate(func(spe fieldpath.PathElement) {
						if !valid {
							return
						}
						if spe.FieldName == nil {
							valid = false
							return
						}
						m, known := subtreePatcher.SpecTagMaskForField(*spe.FieldName)
						if !known {
							valid = false
							return
						}
						specTagMask |= m
					})
				}
			default:
				valid = false
			}
		})
		if !valid {
			return false, 0, 0, false
		}
	}
	return includeMetadata, specTagMask, statusTagMask, true
}

func (f *structuredMergeManager) toVersioned(obj runtime.Object) (runtime.Object, error) {
	return f.objectConverter.ConvertToVersion(obj, f.groupVersion)
}

func (f *structuredMergeManager) toUnversioned(obj runtime.Object) (runtime.Object, error) {
	return f.objectConverter.ConvertToVersion(obj, f.hubVersion)
}

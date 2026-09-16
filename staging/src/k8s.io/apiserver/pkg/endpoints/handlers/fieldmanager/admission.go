/*
Copyright 2021 The Kubernetes Authors.

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

package fieldmanager

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/warning"
)

// InvalidManagedFieldsAfterMutatingAdmissionWarningFormat is the warning that a client receives
// when a create/update/patch request results in invalid managedFields after going through the admission chain.
const InvalidManagedFieldsAfterMutatingAdmissionWarningFormat = ".metadata.managedFields was in an invalid state after admission; this could be caused by an outdated mutating admission controller; please fix your requests: %v"

// NewManagedFieldsValidatingAdmissionController validates the managedFields after calling
// the provided admission and resets them to their original state if they got changed to an invalid value
func NewManagedFieldsValidatingAdmissionController(wrap admission.Interface) admission.Interface {
	if wrap == nil {
		return nil
	}
	return &managedFieldsValidatingAdmissionController{wrap: wrap}
}

type managedFieldsValidatingAdmissionController struct {
	wrap admission.Interface
}

var _ admission.Interface = &managedFieldsValidatingAdmissionController{}
var _ admission.MutationInterface = &managedFieldsValidatingAdmissionController{}
var _ admission.ValidationInterface = &managedFieldsValidatingAdmissionController{}

// Handles calls the wrapped admission.Interface if applicable
func (admit *managedFieldsValidatingAdmissionController) Handles(operation admission.Operation) bool {
	return admit.wrap.Handles(operation)
}

// Admit calls the wrapped admission.Interface if applicable and resets the managedFields to their state before admission if they
// got modified in an invalid way
func (admit *managedFieldsValidatingAdmissionController) Admit(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) (err error) {
	mutationInterface, isMutationInterface := admit.wrap.(admission.MutationInterface)
	if !isMutationInterface {
		return nil
	}
	objectMeta, err := meta.Accessor(a.GetObject())
	if err != nil {
		// the object we are dealing with doesn't have object metadata defined
		// in that case we don't have to keep track of the managedField
		// just call the wrapped admission
		return mutationInterface.Admit(ctx, a, o)
	}
	origSlice := objectMeta.GetManagedFields()
	var stackBuf [16]metav1.ManagedFieldsEntry
	var managedFieldsBeforeAdmission []metav1.ManagedFieldsEntry
	if len(origSlice) <= len(stackBuf) {
		managedFieldsBeforeAdmission = stackBuf[:len(origSlice)]
		copy(managedFieldsBeforeAdmission, origSlice)
	} else {
		managedFieldsBeforeAdmission = slices.Clone(origSlice)
	}
	if err := mutationInterface.Admit(ctx, a, o); err != nil {
		return err
	}
	managedFieldsAfterAdmission := objectMeta.GetManagedFields()
	if !managedFieldsEqual(managedFieldsBeforeAdmission, managedFieldsAfterAdmission) {
		if err := managedfields.ValidateManagedFields(managedFieldsAfterAdmission); err != nil {
			objectMeta.SetManagedFields(slices.Clone(managedFieldsBeforeAdmission))
			warning.AddWarning(ctx, "",
				fmt.Sprintf(InvalidManagedFieldsAfterMutatingAdmissionWarningFormat,
					err.Error()),
			)
		}
	}
	return nil
}

func managedFieldsEqual(a, b []metav1.ManagedFieldsEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Manager != b[i].Manager ||
			a[i].Operation != b[i].Operation ||
			a[i].APIVersion != b[i].APIVersion ||
			a[i].FieldsType != b[i].FieldsType ||
			a[i].Subresource != b[i].Subresource ||
			!a[i].Time.Equal(b[i].Time) {
			return false
		}
		if (a[i].FieldsV1 == nil) != (b[i].FieldsV1 == nil) {
			return false
		}
		if a[i].FieldsV1 != nil && !bytes.Equal(a[i].FieldsV1.Raw, b[i].FieldsV1.Raw) {
			return false
		}
	}
	return true
}

// Validate calls the wrapped admission.Interface if aplicable
func (admit *managedFieldsValidatingAdmissionController) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) (err error) {
	if validationInterface, isValidationInterface := admit.wrap.(admission.ValidationInterface); isValidationInterface {
		return validationInterface.Validate(ctx, a, o)
	}
	return nil
}

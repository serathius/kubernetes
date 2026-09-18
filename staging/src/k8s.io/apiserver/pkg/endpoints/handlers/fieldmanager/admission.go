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
	"context"
	"fmt"

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
	managedFieldsBeforeAdmission := objectMeta.GetManagedFields()
	if err := mutationInterface.Admit(ctx, a, o); err != nil {
		return err
	}
	managedFieldsAfterAdmission := objectMeta.GetManagedFields()
	// Validating means decoding every FieldsV1 blob and throwing the result away,
	// which for a large object costs more than the rest of admission. The entries
	// arrive valid (the field manager just produced them), so only a mutating
	// plugin can have broken them: if nothing changed, there is nothing to check.
	if managedFieldsEntriesEqual(managedFieldsBeforeAdmission, managedFieldsAfterAdmission) {
		return nil
	}
	if err := managedfields.ValidateManagedFields(managedFieldsAfterAdmission); err != nil {
		objectMeta.SetManagedFields(managedFieldsBeforeAdmission)
		warning.AddWarning(ctx, "",
			fmt.Sprintf(InvalidManagedFieldsAfterMutatingAdmissionWarningFormat,
				err.Error()),
		)
	}
	return nil
}

// managedFieldsEntriesEqual reports whether two sets of entries are identical.
//
// Comparing the raw FieldsV1 bytes is deliberate: it is a memcmp against a parse
// into a fieldpath.Set, so it stays cheap even when a webhook round trip hands
// back byte-identical entries in freshly allocated slices.
//
// A plugin that mutates the entries in place is not detected, because both
// arguments then alias the same backing array. The reset below already assumes
// plugins replace rather than mutate in place — restoring an aliased slice would
// be a no-op — so this adds no new assumption.
func managedFieldsEntriesEqual(before, after []metav1.ManagedFieldsEntry) bool {
	if len(before) != len(after) {
		return false
	}
	for i := range before {
		x, y := &before[i], &after[i]
		if x.Manager != y.Manager ||
			x.Operation != y.Operation ||
			x.APIVersion != y.APIVersion ||
			x.FieldsType != y.FieldsType ||
			x.Subresource != y.Subresource ||
			!x.Time.Equal(y.Time) {
			return false
		}
		if (x.FieldsV1 == nil) != (y.FieldsV1 == nil) {
			return false
		}
		if x.FieldsV1 != nil && !x.FieldsV1.Equal(*y.FieldsV1) {
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

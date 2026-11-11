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
	objectMeta, err := meta.Accessor(admission.RawObjectFrom(a))
	if err != nil {
		// the object we are dealing with doesn't have object metadata defined
		// in that case we don't have to keep track of the managedField
		// just call the wrapped admission
		return mutationInterface.Admit(ctx, a, o)
	}
	managedFieldsBeforeAdmission := objectMeta.GetManagedFields()
	var snapshotBuf [8]managedFieldsEntrySnapshot
	beforeSnapshot := captureManagedFieldsSnapshot(managedFieldsBeforeAdmission, &snapshotBuf)
	if err := mutationInterface.Admit(ctx, a, o); err != nil {
		return err
	}
	managedFieldsAfterAdmission := objectMeta.GetManagedFields()
	if managedFieldsEqualSnapshot(managedFieldsAfterAdmission, beforeSnapshot) {
		return nil
	}
	if err := managedfields.ValidateManagedFields(managedFieldsAfterAdmission); err != nil {
		objectMeta.SetManagedFields(restoreManagedFieldsSnapshot(beforeSnapshot))
		warning.AddWarning(ctx, "",
			fmt.Sprintf(InvalidManagedFieldsAfterMutatingAdmissionWarningFormat,
				err.Error()),
		)
	}
	return nil
}

type managedFieldsEntrySnapshot struct {
	entry       metav1.ManagedFieldsEntry
	hasTime     bool
	time        metav1.Time
	hasFieldsV1 bool
	fieldsV1    metav1.FieldsV1
}

func captureManagedFieldsSnapshot(entries []metav1.ManagedFieldsEntry, stackBuf *[8]managedFieldsEntrySnapshot) []managedFieldsEntrySnapshot {
	var out []managedFieldsEntrySnapshot
	if len(entries) <= len(stackBuf) {
		out = stackBuf[:len(entries)]
	} else {
		out = make([]managedFieldsEntrySnapshot, len(entries))
	}
	for i := range entries {
		e := entries[i]
		s := managedFieldsEntrySnapshot{entry: e}
		if e.Time != nil {
			s.hasTime = true
			s.time = *e.Time
		}
		if e.FieldsV1 != nil {
			s.hasFieldsV1 = true
			s.fieldsV1 = *e.FieldsV1
		}
		out[i] = s
	}
	return out
}

func managedFieldsEqualSnapshot(after []metav1.ManagedFieldsEntry, before []managedFieldsEntrySnapshot) bool {
	if len(after) != len(before) {
		return false
	}
	for i := range after {
		e := after[i]
		s := before[i]
		if e != s.entry {
			return false
		}
		if (e.Time != nil) != s.hasTime || (e.Time != nil && !e.Time.Equal(&s.time)) {
			return false
		}
		if (e.FieldsV1 != nil) != s.hasFieldsV1 || (e.FieldsV1 != nil && !e.FieldsV1.Equal(s.fieldsV1)) {
			return false
		}
	}
	return true
}

func restoreManagedFieldsSnapshot(before []managedFieldsEntrySnapshot) []metav1.ManagedFieldsEntry {
	if len(before) == 0 {
		return nil
	}
	restored := make([]metav1.ManagedFieldsEntry, len(before))
	for i := range before {
		e := before[i].entry
		if before[i].hasTime {
			t := before[i].time
			e.Time = &t
		}
		if before[i].hasFieldsV1 {
			fv1 := before[i].fieldsV1
			e.FieldsV1 = &fv1
		}
		restored[i] = e
	}
	return restored
}

// Validate calls the wrapped admission.Interface if aplicable
func (admit *managedFieldsValidatingAdmissionController) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) (err error) {
	if validationInterface, isValidationInterface := admit.wrap.(admission.ValidationInterface); isValidationInterface {
		return validationInterface.Validate(ctx, a, o)
	}
	return nil
}

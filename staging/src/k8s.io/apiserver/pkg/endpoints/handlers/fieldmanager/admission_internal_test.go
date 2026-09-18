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

package fieldmanager

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestManagedFieldsEntriesEqual(t *testing.T) {
	now := metav1.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	later := metav1.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)

	entry := func(mutate ...func(*metav1.ManagedFieldsEntry)) []metav1.ManagedFieldsEntry {
		e := metav1.ManagedFieldsEntry{
			Manager:    "kubelet",
			Operation:  metav1.ManagedFieldsOperationUpdate,
			APIVersion: "v1",
			FieldsType: "FieldsV1",
			Time:       &now,
			FieldsV1:   metav1.NewFieldsV1(`{"f:metadata":{"f:labels":{"f:a":{}}}}`),
		}
		for _, m := range mutate {
			m(&e)
		}
		return []metav1.ManagedFieldsEntry{e}
	}

	tests := []struct {
		name  string
		after []metav1.ManagedFieldsEntry
		equal bool
	}{
		{
			// The common case: a webhook round trip reallocates everything but
			// changes nothing. Must still compare equal, or the optimization
			// never fires for clusters that run webhooks.
			name:  "identical values in fresh allocations",
			after: entry(),
			equal: true,
		},
		{
			name:  "different manager",
			after: entry(func(e *metav1.ManagedFieldsEntry) { e.Manager = "other" }),
		},
		{
			name:  "different operation",
			after: entry(func(e *metav1.ManagedFieldsEntry) { e.Operation = metav1.ManagedFieldsOperationApply }),
		},
		{
			name:  "different apiVersion",
			after: entry(func(e *metav1.ManagedFieldsEntry) { e.APIVersion = "v2" }),
		},
		{
			name:  "different fieldsType",
			after: entry(func(e *metav1.ManagedFieldsEntry) { e.FieldsType = "" }),
		},
		{
			name:  "different subresource",
			after: entry(func(e *metav1.ManagedFieldsEntry) { e.Subresource = "status" }),
		},
		{
			name:  "different time",
			after: entry(func(e *metav1.ManagedFieldsEntry) { e.Time = &later }),
		},
		{
			name:  "nil time",
			after: entry(func(e *metav1.ManagedFieldsEntry) { e.Time = nil }),
		},
		{
			name:  "different fieldsV1 payload",
			after: entry(func(e *metav1.ManagedFieldsEntry) { e.FieldsV1 = metav1.NewFieldsV1(`{}`) }),
		},
		{
			name:  "nil fieldsV1",
			after: entry(func(e *metav1.ManagedFieldsEntry) { e.FieldsV1 = nil }),
		},
		{
			name:  "entry removed",
			after: nil,
		},
		{
			name:  "entry added",
			after: append(entry(), entry(func(e *metav1.ManagedFieldsEntry) { e.Manager = "other" })...),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := managedFieldsEntriesEqual(entry(), tc.after); got != tc.equal {
				t.Errorf("managedFieldsEntriesEqual() = %v, want %v", got, tc.equal)
			}
		})
	}

	t.Run("both nil", func(t *testing.T) {
		if !managedFieldsEntriesEqual(nil, nil) {
			t.Error("managedFieldsEntriesEqual(nil, nil) = false, want true")
		}
	})

	t.Run("both nil fieldsV1", func(t *testing.T) {
		nilFields := func(e *metav1.ManagedFieldsEntry) { e.FieldsV1 = nil }
		if !managedFieldsEntriesEqual(entry(nilFields), entry(nilFields)) {
			t.Error("entries with nil FieldsV1 should compare equal")
		}
	})
}

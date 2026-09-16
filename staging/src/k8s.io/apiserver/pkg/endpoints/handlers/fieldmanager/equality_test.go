/*
Copyright 2024 The Kubernetes Authors.

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

func TestEqualIgnoringFieldValueAtPath(t *testing.T) {
	cases := []struct {
		name string
		a, b map[string]any
		want bool
	}{
		{
			name: "identical objects",
			a: map[string]any{
				"metadata": map[string]any{
					"labels":        map[string]any{"env": "dev"},
					"managedFields": []any{},
				},
				"spec": map[string]any{
					"field": "value",
				},
			},
			b: map[string]any{
				"metadata": map[string]any{
					"labels":        map[string]any{"env": "dev"},
					"managedFields": []any{},
				},
				"spec": map[string]any{
					"field": "value",
				},
			},
			want: true,
		},
		{
			name: "different metadata label value",
			a: map[string]any{
				"metadata": map[string]any{
					"labels":        map[string]any{"env": "dev"},
					"managedFields": []any{},
				},
				"spec": map[string]any{
					"field": "value",
				},
			},
			b: map[string]any{
				"metadata": map[string]any{
					"labels":        map[string]any{"env": "prod"},
					"managedFields": []any{},
				},
				"spec": map[string]any{
					"field": "value",
				},
			},
			want: false,
		},
		{
			name: "different spec value",
			a: map[string]any{
				"metadata": map[string]any{
					"labels":        map[string]any{"env": "dev"},
					"managedFields": []any{},
				},
				"spec": map[string]any{
					"field": "value1",
				},
			},
			b: map[string]any{
				"metadata": map[string]any{
					"labels":        map[string]any{"env": "dev"},
					"managedFields": []any{},
				},
				"spec": map[string]any{
					"field": "value2",
				},
			},
			want: false,
		},
		{
			name: "extra spec field",
			a: map[string]any{
				"metadata": map[string]any{
					"labels":        map[string]any{"env": "dev"},
					"managedFields": []any{},
				},
				"spec": map[string]any{
					"field":      "value1",
					"otherField": "other",
				},
			},
			b: map[string]any{
				"metadata": map[string]any{
					"labels":        map[string]any{"env": "dev"},
					"managedFields": []any{},
				},
				"spec": map[string]any{
					"field": "value1",
				},
			},
			want: false,
		},
		{
			name: "different spec field",
			a: map[string]any{
				"metadata": map[string]any{
					"labels":        map[string]any{"env": "dev"},
					"managedFields": []any{},
				},
				"spec": map[string]any{
					"field": "value1",
				},
			},
			b: map[string]any{
				"metadata": map[string]any{
					"labels":        map[string]any{"env": "dev"},
					"managedFields": []any{},
				},
				"spec": map[string]any{
					"field":      "value1",
					"otherField": "other",
				},
			},
			want: false,
		},
		{
			name: "different managed fields should be ignored",
			a: map[string]any{
				"metadata": map[string]any{
					"labels":        map[string]any{"env": "dev"},
					"managedFields": []any{map[string]any{"manager": "client1"}},
				},
				"spec": map[string]any{
					"field": "value",
				},
			},
			b: map[string]any{
				"metadata": map[string]any{
					"labels":        map[string]any{"env": "dev"},
					"managedFields": []any{map[string]any{"manager": "client2"}},
				},
				"spec": map[string]any{
					"field": "value",
				},
			},
			want: true,
		},
		{
			name: "wrong type for metadata result in differences being ignored",
			a: map[string]any{
				"metadata": []any{
					"something",
				},
				"spec": map[string]any{
					"field": "value",
				},
			},
			b: map[string]any{
				"metadata": []any{
					"something else",
				},
				"spec": map[string]any{
					"field": "value",
				},
			},
			want: true,
		},
	}

	path := []string{"metadata", "managedFields"}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual := equalIgnoringValueAtPath(c.a, c.b, path)
			if actual != c.want {
				t.Error("Expected equality check to return ", c.want, ", but got ", actual)
			}
			// Check that equality is commutative
			actual = equalIgnoringValueAtPath(c.b, c.a, path)
			if actual != c.want {
				t.Error("Expected equality check to return ", c.want, ", but got ", actual)
			}
		})
	}
}

func TestManagedFieldsEqualIgnoringTimestamp(t *testing.T) {
	t1 := metav1.Now()
	t2 := metav1.NewTime(t1.Add(10 * time.Second))
	entry1 := metav1.ManagedFieldsEntry{
		Manager:    "manager-1",
		Operation:  metav1.ManagedFieldsOperationApply,
		APIVersion: "v1",
		FieldsType: "FieldsV1",
		FieldsV1:   &metav1.FieldsV1{Raw: []byte(`{"f:spec":{}}`)},
		Time:       &t1,
	}
	entry2 := entry1
	entry2.Time = &t2

	if !managedFieldsEqualIgnoringTimestamp([]metav1.ManagedFieldsEntry{entry1}, []metav1.ManagedFieldsEntry{entry2}) {
		t.Errorf("expected entries differing only by timestamp to be equal")
	}

	entry3 := entry2
	entry3.FieldsV1 = &metav1.FieldsV1{Raw: []byte(`{"f:spec":{"f:replicas":{}}}`)}
	if managedFieldsEqualIgnoringTimestamp([]metav1.ManagedFieldsEntry{entry1}, []metav1.ManagedFieldsEntry{entry3}) {
		t.Errorf("expected entries with different FieldsV1 bytes to be unequal")
	}
}


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
	"fmt"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kjson "sigs.k8s.io/json"
	"sigs.k8s.io/structured-merge-diff/v7/fieldpath"
)

type nopDefaulter struct{}

func (nopDefaulter) Default(runtime.Object) {}

func metadataPatchTestPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-pod",
			Namespace:   "default",
			UID:         types.UID("7bc1b1a0-0000-4000-8000-000000000001"),
			Labels:      map[string]string{"app": "test", "tier": "backend"},
			Annotations: map[string]string{"keep": "me", "drop": "later"},
			Finalizers:  []string{"first", "second"},
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "v1", Kind: "ReplicationController", Name: "rc", UID: types.UID("owner-1")},
			},
			ManagedFields: []metav1.ManagedFieldsEntry{{
				Manager:    "creator",
				Operation:  metav1.ManagedFieldsOperationUpdate,
				APIVersion: "v1",
				FieldsType: "FieldsV1",
				FieldsV1:   &metav1.FieldsV1{Raw: []byte(`{"f:metadata":{"f:labels":{"f:app":{}}}}`)},
			}},
		},
		Spec: corev1.PodSpec{
			NodeName:   "node-1",
			Containers: []corev1.Container{{Name: "app", Image: "image:v1"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// TestMetadataScopedPatchMatchesGenericPatch asserts that patching only the metadata
// subtree produces exactly the object the whole object round trip produces.
func TestMetadataScopedPatchMatchesGenericPatch(t *testing.T) {
	testCases := []struct {
		name         string
		patch        string
		metadataOnly bool
	}{{
		name:         "add label",
		patch:        `{"metadata":{"labels":{"new":"value"}}}`,
		metadataOnly: true,
	}, {
		name:         "overwrite label",
		patch:        `{"metadata":{"labels":{"app":"other"}}}`,
		metadataOnly: true,
	}, {
		name:         "delete label",
		patch:        `{"metadata":{"labels":{"app":null}}}`,
		metadataOnly: true,
	}, {
		name:         "delete all annotations",
		patch:        `{"metadata":{"annotations":null}}`,
		metadataOnly: true,
	}, {
		name:         "replace annotations",
		patch:        `{"metadata":{"annotations":{"$patch":"replace","only":"this"}}}`,
		metadataOnly: true,
	}, {
		name:         "merge finalizers",
		patch:        `{"metadata":{"finalizers":["third"]}}`,
		metadataOnly: true,
	}, {
		name:         "delete from finalizers",
		patch:        `{"metadata":{"$deleteFromPrimitiveList/finalizers":["first"]}}`,
		metadataOnly: true,
	}, {
		name:         "reorder finalizers",
		patch:        `{"metadata":{"$setElementOrder/finalizers":["second","first"]}}`,
		metadataOnly: true,
	}, {
		name:         "merge owner references by uid",
		patch:        `{"metadata":{"ownerReferences":[{"apiVersion":"v1","kind":"Deployment","name":"d","uid":"owner-2"}]}}`,
		metadataOnly: true,
	}, {
		name:         "retain keys",
		patch:        `{"metadata":{"labels":{"$retainKeys":["app"],"app":"kept"}}}`,
		metadataOnly: true,
	}, {
		name:         "set managed fields",
		patch:        `{"metadata":{"managedFields":[{"manager":"other","operation":"Update","apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{}}}]}}`,
		metadataOnly: true,
	}, {
		name:         "generation and resource version",
		patch:        `{"metadata":{"generation":7,"resourceVersion":"42"}}`,
		metadataOnly: true,
	}, {
		name:  "spec patch is not metadata scoped",
		patch: `{"spec":{"containers":[{"name":"app","image":"image:v2"}]}}`,
	}, {
		name:  "mixed patch is not metadata scoped",
		patch: `{"metadata":{"labels":{"new":"value"}},"spec":{"nodeName":"node-2"}}`,
	}, {
		name:  "top level directive is not metadata scoped",
		patch: `{"$retainKeys":["metadata"],"metadata":{"labels":{"new":"value"}}}`,
	}, {
		name:  "metadata deletion is not metadata scoped",
		patch: `{"metadata":null}`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scoped := &corev1.Pod{}
			metadataOnly, err := strategicPatchObjectWithScope(context.TODO(), nopDefaulter{}, metadataPatchTestPod(), []byte(tc.patch), scoped, &corev1.Pod{}, metav1.FieldValidationStrict)
			if err != nil {
				t.Fatalf("scoped patch failed: %v", err)
			}
			if metadataOnly != tc.metadataOnly {
				t.Fatalf("metadataOnly = %v, want %v", metadataOnly, tc.metadataOnly)
			}

			// Compare against the whole object round trip, which the scoped path must be
			// indistinguishable from.
			generic := &corev1.Pod{}
			original := metadataPatchTestPod()
			originalMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(original)
			if err != nil {
				t.Fatalf("ToUnstructured failed: %v", err)
			}
			patchMap := map[string]interface{}{}
			strictErrs, err := kjson.UnmarshalStrict([]byte(tc.patch), &patchMap)
			if err != nil {
				t.Fatalf("failed to decode patch: %v", err)
			}
			if err := applyPatchToObject(context.TODO(), nopDefaulter{}, originalMap, patchMap, generic, &corev1.Pod{}, strictErrs, metav1.FieldValidationStrict); err != nil {
				t.Fatalf("generic patch failed: %v", err)
			}

			if !reflect.DeepEqual(scoped, generic) {
				t.Errorf("scoped patch result differs from generic patch result:\nscoped:  %#v\ngeneric: %#v", scoped.ObjectMeta, generic.ObjectMeta)
			}
		})
	}
}

// TestMetadataScopedManagedFieldsMatchUnscoped asserts that running the field manager on
// the metadata projection of an object yields the same managedFields as running it on the
// whole object.
func TestMetadataScopedManagedFieldsMatchUnscoped(t *testing.T) {
	_, fieldManager, livePod := initBenchmarkFixtures(t)

	testCases := []struct {
		name  string
		patch func(*corev1.Pod)
	}{{
		name:  "take ownership of a new label",
		patch: func(pod *corev1.Pod) { pod.Labels["scoped-test"] = "1" },
	}, {
		name:  "update an owned label",
		patch: func(pod *corev1.Pod) { pod.Labels["bench-updated"] = "2" },
	}, {
		name:  "drop an owned label",
		patch: func(pod *corev1.Pod) { delete(pod.Labels, "bench-updated") },
	}, {
		name:  "take ownership of a label owned by another manager",
		patch: func(pod *corev1.Pod) { pod.Labels["group"] = "other" },
	}, {
		name:  "add an annotation",
		patch: func(pod *corev1.Pod) { pod.Annotations["scoped-test"] = "1" },
	}, {
		name:  "no op",
		patch: func(pod *corev1.Pod) {},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scopedPod := livePod.DeepCopy()
			tc.patch(scopedPod)
			unscopedPod := scopedPod.DeepCopy()

			scoped, ok := updateMetadataScopedManagedFields(fieldManager, livePod, scopedPod, "patch-manager")
			if !ok {
				t.Fatal("updateMetadataScopedManagedFields reported the object as unsupported")
			}
			unscoped := fieldManager.UpdateNoErrors(livePod, unscopedPod, "patch-manager")

			scopedMeta, _ := objectMetaOf(scoped)
			unscopedMeta, _ := objectMetaOf(unscoped)
			if diff := managedFieldsDiff(scopedMeta.ManagedFields, unscopedMeta.ManagedFields); diff != "" {
				t.Errorf("scoped managedFields differ from unscoped managedFields: %s", diff)
			}
		})
	}
}

// managedFieldsDiff compares managedFields entries, ignoring the timestamps the field
// manager stamps with the current time.
func managedFieldsDiff(scoped, unscoped []metav1.ManagedFieldsEntry) string {
	if len(scoped) != len(unscoped) {
		return fmt.Sprintf("entry count %d != %d", len(scoped), len(unscoped))
	}
	for i := range scoped {
		scopedEntry, unscopedEntry := scoped[i], unscoped[i]
		scopedEntry.Time, unscopedEntry.Time = nil, nil
		if scopedEntry.Manager != unscopedEntry.Manager {
			return fmt.Sprintf("entry %d manager %q != %q", i, scopedEntry.Manager, unscopedEntry.Manager)
		}
		scopedFields, unscopedFields := scopedEntry.FieldsV1, unscopedEntry.FieldsV1
		scopedEntry.FieldsV1, unscopedEntry.FieldsV1 = nil, nil
		if !reflect.DeepEqual(scopedEntry, unscopedEntry) {
			return fmt.Sprintf("entry %d %#v != %#v", i, scopedEntry, unscopedEntry)
		}
		if !fieldsEqual(scopedFields, unscopedFields) {
			return fmt.Sprintf("entry %d (%s) fields %s != %s", i, scopedEntry.Manager, fieldsString(scopedFields), fieldsString(unscopedFields))
		}
	}
	return ""
}

// fieldsEqual compares two FieldsV1 by the field set they encode, so that reusing the
// original encoding of an untouched manager does not register as a difference.
func fieldsEqual(lhs, rhs *metav1.FieldsV1) bool {
	if lhs == nil || rhs == nil {
		return lhs == rhs
	}
	lhsSet, rhsSet := fieldpath.NewSet(), fieldpath.NewSet()
	if err := lhsSet.FromJSON(bytes.NewReader(lhs.Raw)); err != nil {
		return false
	}
	if err := rhsSet.FromJSON(bytes.NewReader(rhs.Raw)); err != nil {
		return false
	}
	return lhsSet.Equals(rhsSet)
}

func fieldsString(fields *metav1.FieldsV1) string {
	if fields == nil {
		return "<nil>"
	}
	return string(fields.Raw)
}

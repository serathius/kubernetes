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

package lazy

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/encoding/protowire"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func wrapTopLevelMeta(t *testing.T, meta *metav1.ObjectMeta) []byte {
	t.Helper()
	metaBytes, err := meta.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal ObjectMeta: %v", err)
	}
	var raw []byte
	raw = protowire.AppendTag(raw, MetadataFieldNumber, protowire.BytesType)
	raw = protowire.AppendBytes(raw, metaBytes)
	raw = protowire.AppendTag(raw, SpecFieldNumber, protowire.BytesType)
	raw = protowire.AppendBytes(raw, []byte{0x08, 0x01})
	return raw
}

func TestWireObjectMetaReadAndSplice(t *testing.T) {
	now := metav1.NewTime(time.Unix(1700000000, 0))
	delTime := metav1.NewTime(time.Unix(1700000030, 0))
	grace := int64(30)
	ctrl := true
	orig := metav1.ObjectMeta{
		Name:                       "pod-a",
		GenerateName:               "pod-",
		Namespace:                  "ns-a",
		SelfLink:                   "/api/v1/namespaces/ns-a/pods/pod-a",
		UID:                        types.UID("uid-123"),
		ResourceVersion:            "42",
		Generation:                 3,
		CreationTimestamp:          now,
		DeletionTimestamp:          &delTime,
		DeletionGracePeriodSeconds: &grace,
		Labels:                     map[string]string{"app": "web", "tier": "frontend"},
		Annotations:                map[string]string{"anno-1": "val-1", "empty-anno": ""},
		OwnerReferences: []metav1.OwnerReference{
			{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs-1", UID: "rs-uid-1", Controller: &ctrl},
		},
		Finalizers: []string{"finalizer.k8s.io/one", "finalizer.k8s.io/two"},
		ManagedFields: []metav1.ManagedFieldsEntry{
			{Manager: "kubectl", Operation: metav1.ManagedFieldsOperationApply, APIVersion: "v1", FieldsType: "FieldsV1"},
		},
	}

	raw := wrapTopLevelMeta(t, &orig)
	metaBytes := SubMessage(raw, MetadataFieldNumber)

	var wm WireObjectMeta
	if got := wm.Name(metaBytes); got != orig.Name {
		t.Errorf("Name = %q, want %q", got, orig.Name)
	}
	if got := wm.GenerateName(metaBytes); got != orig.GenerateName {
		t.Errorf("GenerateName = %q, want %q", got, orig.GenerateName)
	}
	if got := wm.Namespace(metaBytes); got != orig.Namespace {
		t.Errorf("Namespace = %q, want %q", got, orig.Namespace)
	}
	if got := wm.SelfLink(metaBytes); got != orig.SelfLink {
		t.Errorf("SelfLink = %q, want %q", got, orig.SelfLink)
	}
	if got := wm.UID(metaBytes); got != orig.UID {
		t.Errorf("UID = %q, want %q", got, orig.UID)
	}
	if got := wm.ResourceVersion(metaBytes); got != orig.ResourceVersion {
		t.Errorf("ResourceVersion = %q, want %q", got, orig.ResourceVersion)
	}
	if got := wm.Generation(metaBytes); got != orig.Generation {
		t.Errorf("Generation = %d, want %d", got, orig.Generation)
	}
	if got := wm.CreationTimestamp(metaBytes); !got.Equal(&orig.CreationTimestamp) {
		t.Errorf("CreationTimestamp = %v, want %v", got, orig.CreationTimestamp)
	}
	if !wm.HasDeletionTimestamp(metaBytes) {
		t.Errorf("HasDeletionTimestamp = false, want true")
	}
	if got := wm.DeletionTimestamp(metaBytes); got == nil || !got.Equal(orig.DeletionTimestamp) {
		t.Errorf("DeletionTimestamp = %v, want %v", got, orig.DeletionTimestamp)
	}
	if got := wm.DeletionGracePeriodSeconds(metaBytes); got == nil || *got != grace {
		t.Errorf("DeletionGracePeriodSeconds = %v, want %d", got, grace)
	}
	if !wm.HasAnnotationValue(metaBytes, "anno-1", "val-1") {
		t.Errorf("expected HasAnnotationValue(anno-1, val-1) == true")
	}
	if !wm.HasAnnotationValue(metaBytes, "missing", "") {
		t.Errorf("expected HasAnnotationValue(missing, \"\") == true")
	}
	if wm.HasMultipleOwnerReferences(metaBytes) {
		t.Errorf("expected HasMultipleOwnerReferences == false for 1 ownerRef")
	}

	var extracted metav1.ObjectMeta
	wm.ExtractObjectMetaInto(metaBytes, &extracted)
	if !apiequality.Semantic.DeepEqual(orig, extracted) {
		t.Fatalf("ExtractObjectMetaInto diff (-want +got):\n%s", cmp.Diff(orig, extracted))
	}

	// Mutate via WireObjectMeta setters and verify SpliceIntoRaw round-trips cleanly.
	newGrace := int64(10)
	wm.SetName("pod-b")
	wm.SetResourceVersion("43")
	wm.SetGeneration(4)
	wm.SetDeletionGracePeriodSeconds(&newGrace)
	wm.SetLabels(map[string]string{"app": "backend"})
	wm.SetFinalizers([]string{"finalizer.k8s.io/one"})

	splicedRaw := wm.SpliceIntoRaw(raw)
	if wm.IsDirty() {
		t.Fatalf("expected WireObjectMeta dirty bitmask cleared after SpliceIntoRaw")
	}
	splicedMetaBytes := SubMessage(splicedRaw, MetadataFieldNumber)
	var afterSplice metav1.ObjectMeta
	if err := afterSplice.Unmarshal(splicedMetaBytes); err != nil {
		t.Fatalf("failed to unmarshal spliced ObjectMeta: %v", err)
	}

	want := orig.DeepCopy()
	want.Name = "pod-b"
	want.ResourceVersion = "43"
	want.Generation = 4
	want.DeletionGracePeriodSeconds = &newGrace
	want.Labels = map[string]string{"app": "backend"}
	want.Finalizers = []string{"finalizer.k8s.io/one"}

	if !apiequality.Semantic.DeepEqual(*want, afterSplice) {
		t.Fatalf("spliced ObjectMeta diff (-want +got):\n%s", cmp.Diff(*want, afterSplice))
	}
	// Verify spec field (tag 2) was preserved untouched.
	if gotSpec := SubMessage(splicedRaw, SpecFieldNumber); string(gotSpec) != "\x08\x01" {
		t.Fatalf("expected spec bytes preserved, got %x", gotSpec)
	}
}

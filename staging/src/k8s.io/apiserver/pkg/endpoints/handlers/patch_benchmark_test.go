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

package handlers

import (
	"context"
	"fmt"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apimachinery/pkg/runtime/serializer/versioning"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/endpoints/handlers/fieldmanager"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/client-go/applyconfigurations"
	"sigs.k8s.io/structured-merge-diff/v7/fieldpath"
)

func BenchmarkPatchPod(b *testing.B) {
	scheme, fm, livePod := initBenchmarkFixtures(b)
	gvk := corev1.SchemeGroupVersion.WithKind("Pod")
	gvr := corev1.SchemeGroupVersion.WithResource("pods")
	ctx := request.WithNamespace(context.Background(), livePod.Namespace)

	scope := &RequestScope{
		Namer:           ContextBasedNaming{Namer: meta.NewAccessor()},
		Creater:         scheme,
		Defaulter:       scheme,
		Typer:           scheme,
		UnsafeConvertor: runtime.UnsafeObjectConvertor(scheme),
		Kind:            gvk,
		Resource:        gvr,
		HubGroupVersion: corev1.SchemeGroupVersion,
		FieldManager:    fm,
	}

	admit := fieldmanager.NewManagedFieldsValidatingAdmissionController(benchAdmission{})
	mutatingAdmission, _ := admit.(admission.MutationInterface)
	staticUpdateAttributes := admission.NewAttributesRecord(
		nil, nil, gvk, livePod.Namespace, livePod.Name, gvr, "", admission.Update, &metav1.UpdateOptions{}, false, nil,
	)

	s := protobuf.NewSerializer(scheme, scheme)
	codec := versioning.NewDefaultingCodecForScheme(scheme, s, s, corev1.SchemeGroupVersion, corev1.SchemeGroupVersion)

	p := patcher{
		namer:               scope.Namer,
		creater:             scope.Creater,
		defaulter:           scope.Defaulter,
		typer:               scope.Typer,
		unsafeConvertor:     scope.UnsafeConvertor,
		kind:                scope.Kind,
		resource:            scope.Resource,
		hubGroupVersion:     scope.HubGroupVersion,
		validationDirective: metav1.FieldValidationWarn,
		objectInterfaces:    scope,
		admissionCheck:      mutatingAdmission,
		updateValidation:    rest.AdmissionToValidateObjectUpdateFunc(admit, staticUpdateAttributes, scope),
		options:             &metav1.PatchOptions{FieldManager: "patch-manager"},
		restPatcher:         &benchRestPatcher{livePod: livePod, codec: codec},
		name:                livePod.Name,
		patchType:           types.StrategicMergePatchType,
	}

	for b.Loop() {
		p.patchBytes = fmt.Appendf(nil, `{"metadata":{"labels":{"bench-updated":"%d"}}}`, i+1)
		if _, _, err := p.patchResource(ctx, scope); err != nil {
			b.Fatalf("patchResource failed: %v", err)
		}
	}
}

func loadBenchmarkPod(b testing.TB, fm *managedfields.FieldManager) *corev1.Pod {
	b.Helper()
	data, err := os.ReadFile("responsewriters/testdata/exemplar_pod.yaml")
	if err != nil {
		b.Fatalf("failed to read exemplar_pod.yaml: %v", err)
	}
	var pod corev1.Pod
	if err := yaml.Unmarshal(data, &pod); err != nil {
		b.Fatalf("failed to unmarshal exemplar_pod.yaml: %v", err)
	}

	patched := pod.DeepCopy()
	patched.Labels["bench-updated"] = "0"
	obj, err := fm.Update(&pod, patched, "patch-manager")
	if err != nil {
		b.Fatalf("failed initial patch fm.Update: %v", err)
	}
	return obj.(*corev1.Pod)
}

type benchRestPatcher struct {
	livePod     *corev1.Pod
	codec       runtime.Codec
	lastEncoded []byte
}

func (r *benchRestPatcher) New() runtime.Object {
	return &corev1.Pod{}
}

func (r *benchRestPatcher) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return r.livePod.DeepCopy(), nil
}

func (r *benchRestPatcher) Update(ctx context.Context, name string, objInfo rest.UpdatedObjectInfo, createValidation rest.ValidateObjectFunc, updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	existing := r.livePod.DeepCopy()
	obj, err := objInfo.UpdatedObject(ctx, existing)
	if err != nil {
		return nil, false, err
	}

	// Store.Update runs BeforeUpdate (PrepareForUpdate + ValidatePodUpdate + Validate_Pod),
	// which compares newPod.Spec against oldPod.Spec three times via Semantic.DeepEqual.
	newPod, oldPod := obj.(*corev1.Pod), existing
	if !apiequality.Semantic.DeepEqual(&newPod.Spec, &oldPod.Spec) {
		newPod.Generation++
	}
	_ = apiequality.Semantic.DeepEqual(&newPod.Spec, &oldPod.Spec)
	_ = apiequality.Semantic.DeepEqual(&newPod.Spec, &oldPod.Spec)

	obj, err = fieldmanager.IgnoreManagedFieldsTimestampsTransformer(ctx, obj, existing)
	if err != nil {
		return nil, false, err
	}

	if updateValidation != nil {
		if err := updateValidation(ctx, obj.DeepCopyObject(), existing.DeepCopyObject()); err != nil {
			return nil, false, err
		}
	}

	r.lastEncoded, err = runtime.Encode(r.codec, obj)
	if err != nil {
		return nil, false, err
	}
	return obj, false, nil
}

type benchAdmission struct{}

func (benchAdmission) Handles(admission.Operation) bool { return true }

func (benchAdmission) Admit(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	return nil
}

func (benchAdmission) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	return nil
}

func initBenchmarkFixtures(b testing.TB) (*runtime.Scheme, *managedfields.FieldManager, *corev1.Pod) {
	b.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		b.Fatal(err)
	}
	metav1.AddToGroupVersion(scheme, corev1.SchemeGroupVersion)

	gvk := corev1.SchemeGroupVersion.WithKind("Pod")
	resetFields := fieldpath.NewExcludeFilterSetMap(map[fieldpath.APIVersion]*fieldpath.Set{
		"v1": fieldpath.NewSet(fieldpath.MakePathOrDie("status")),
	})
	fm, err := managedfields.NewDefaultFieldManager(
		applyconfigurations.NewTypeConverter(scheme),
		runtime.UnsafeObjectConvertor(scheme),
		scheme,
		scheme,
		gvk,
		corev1.SchemeGroupVersion,
		"",
		resetFields,
	)
	if err != nil {
		b.Fatalf("failed to create field manager: %v", err)
	}
	return scheme, fm, loadBenchmarkPod(b, fm)
}

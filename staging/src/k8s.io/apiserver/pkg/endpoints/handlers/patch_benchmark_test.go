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
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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

func initBenchmarkScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		panic(err)
	}
	metav1.AddToGroupVersion(s, corev1.SchemeGroupVersion)
	return s
}

func newBenchmarkFieldManager(b *testing.B, scheme *runtime.Scheme) *managedfields.FieldManager {
	b.Helper()
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
	return fm
}

func loadBenchmarkPod(b *testing.B, scheme *runtime.Scheme, fm *managedfields.FieldManager) *corev1.Pod {
	b.Helper()
	data, err := os.ReadFile("testdata/pod_30KB.yaml")
	if err != nil {
		b.Fatalf("failed to read testdata/pod_30KB.yaml: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	cleanLines := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "{{$group :=") {
			continue
		}
		l = strings.ReplaceAll(l, "{{$group}}", "bench-pod")
		l = strings.ReplaceAll(l, "{{.Name}}", "bench-pod-0")
		l = strings.ReplaceAll(l, "{{.ImageRegistry}}", "registry.k8s.io")
		cleanLines = append(cleanLines, l)
	}

	var pod corev1.Pod
	if err := yaml.Unmarshal([]byte(strings.Join(cleanLines, "\n")), &pod); err != nil {
		b.Fatalf("failed to unmarshal pod: %v", err)
	}
	pod.Namespace = "default"
	pod.UID = types.UID("8475fa3d-88b4-8f93-ecbe-397ef03b90df")
	pod.ResourceVersion = "100"
	pod.Generation = 1
	pod.CreationTimestamp = metav1.Now()

	// Simulate initial creation managedFields from clusterloader2
	createdObj, err := fm.Update(&corev1.Pod{}, &pod, "clusterloader2")
	if err != nil {
		b.Fatalf("failed initial fm.Update: %v", err)
	}
	livePod := createdObj.(*corev1.Pod)

	// Simulate first patch so managedFields has the 2 entries seen in steady-state patching
	firstPatchPod := livePod.DeepCopy()
	if firstPatchPod.Labels == nil {
		firstPatchPod.Labels = make(map[string]string)
	}
	firstPatchPod.Labels["bench-updated"] = "0"
	patchedObj, err := fm.Update(livePod, firstPatchPod, "patch-manager")
	if err != nil {
		b.Fatalf("failed first patch fm.Update: %v", err)
	}
	return patchedObj.(*corev1.Pod)
}

var (
	benchOnce    sync.Once
	benchScheme  *runtime.Scheme
	benchFM      *managedfields.FieldManager
	benchLivePod *corev1.Pod
)

func initBenchmarkFixtures(b *testing.B) (*runtime.Scheme, *managedfields.FieldManager, *corev1.Pod) {
	b.Helper()
	benchOnce.Do(func() {
		benchScheme = initBenchmarkScheme()
		benchFM = newBenchmarkFieldManager(b, benchScheme)
		benchLivePod = loadBenchmarkPod(b, benchScheme, benchFM)
	})
	return benchScheme, benchFM, benchLivePod.DeepCopy()
}

type benchRestPatcher struct {
	livePod *corev1.Pod
}

func (r *benchRestPatcher) New() runtime.Object {
	return &corev1.Pod{}
}

func (r *benchRestPatcher) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return r.livePod.DeepCopy(), nil
}

func (r *benchRestPatcher) Update(ctx context.Context, name string, objInfo rest.UpdatedObjectInfo, createValidation rest.ValidateObjectFunc, updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	// Cacher/storage deep-copies the cached live object before passing it to Store.Update
	existing := r.livePod.DeepCopy()

	obj, err := objInfo.UpdatedObject(ctx, existing)
	if err != nil {
		return nil, false, err
	}

	obj, err = fieldmanager.IgnoreManagedFieldsTimestampsTransformer(ctx, obj, existing)
	if err != nil {
		return nil, false, err
	}

	if updateValidation != nil {
		if err := updateValidation(ctx, obj.DeepCopyObject(), existing.DeepCopyObject()); err != nil {
			return nil, false, err
		}
	}

	return obj, false, nil
}

func BenchmarkPatch30KBPod(b *testing.B) {
	scheme, fm, livePod := initBenchmarkFixtures(b)
	ctx := request.WithNamespace(context.Background(), "default")

	gvk := corev1.SchemeGroupVersion.WithKind("Pod")
	gvr := corev1.SchemeGroupVersion.WithResource("pods")
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

	admit := fieldmanager.NewManagedFieldsValidatingAdmissionController(nil)
	mutatingAdmission, _ := admit.(admission.MutationInterface)
	staticUpdateAttributes := admission.NewAttributesRecord(
		nil, nil, gvk, "default", "bench-pod-0", gvr, "", admission.Update, &metav1.UpdateOptions{}, false, nil,
	)

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
		restPatcher:         &benchRestPatcher{livePod: livePod},
		name:                "bench-pod-0",
		patchType:           types.StrategicMergePatchType,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.patchBytes = fmt.Appendf(nil, `{"metadata":{"labels":{"bench-updated":"%d"}}}`, i+1)
		if _, _, err := p.patchResource(ctx, scope); err != nil {
			b.Fatalf("patchResource failed: %v", err)
		}
	}
}

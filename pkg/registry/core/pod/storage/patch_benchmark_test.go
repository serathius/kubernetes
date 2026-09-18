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

package storage

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/endpoints/handlers"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/client-go/applyconfigurations"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	api "k8s.io/kubernetes/pkg/apis/core"
	"sigs.k8s.io/structured-merge-diff/v7/fieldpath"
)

//go:embed testdata/exemplar_pod.yaml
var exemplarPodYAML []byte

func BenchmarkPatchPod(b *testing.B) {
	storage, scope, admit, pod := setupBenchmarkPatch(b)
	patchTypes := []string{string(types.StrategicMergePatchType)}
	ctx := audit.WithAuditContext(request.WithNamespace(request.WithRequestInfo(context.Background(), &request.RequestInfo{
		IsResourceRequest: true,
		Verb:              "patch",
		APIVersion:        "v1",
		Resource:          "pods",
		Namespace:         pod.Namespace,
		Name:              pod.Name,
	}), pod.Namespace))
	target := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s?fieldManager=patch-manager", pod.Namespace, pod.Name)

	patch := func(i int) {
		body := bytes.NewReader(fmt.Appendf(nil, `{"metadata":{"labels":{"bench-updated":"%d"}}}`, i))
		req := httptest.NewRequestWithContext(ctx, http.MethodPatch, target, body)
		req.Header.Set("Content-Type", string(types.StrategicMergePatchType))
		req.Header.Set("Accept", runtime.ContentTypeProtobuf)
		w := httptest.NewRecorder()
		handlers.PatchResource(storage, scope, admit, patchTypes)(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
		}
	}
	patch(0)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		patch(i + 1)
	}
}

func setupBenchmarkPatch(b *testing.B) (*REST, *handlers.RequestScope, admission.Interface, *api.Pod) {
	b.Helper()
	storage, _, _, server := newStorage(b)
	b.Cleanup(func() {
		server.Terminate(b)
		storage.Store.DestroyFunc()
	})

	scheme := legacyscheme.Scheme
	gvk := v1.SchemeGroupVersion.WithKind("Pod")
	fm, err := managedfields.NewDefaultFieldManager(
		applyconfigurations.NewTypeConverter(scheme),
		runtime.UnsafeObjectConvertor(scheme),
		scheme,
		scheme,
		gvk,
		api.SchemeGroupVersion,
		"",
		fieldpath.NewExcludeFilterSetMap(storage.GetResetFields()),
	)
	if err != nil {
		b.Fatalf("failed to create field manager: %v", err)
	}

	pod := createBenchmarkPod(b, storage)
	scope := &handlers.RequestScope{
		Namer:               handlers.ContextBasedNaming{Namer: meta.NewAccessor()},
		Serializer:          legacyscheme.Codecs,
		ParameterCodec:      legacyscheme.ParameterCodec,
		Creater:             scheme,
		Convertor:           scheme,
		Defaulter:           scheme,
		Typer:               scheme,
		UnsafeConvertor:     runtime.UnsafeObjectConvertor(scheme),
		MaxRequestBodyBytes: 3 * 1024 * 1024,
		Kind:                gvk,
		Resource:            v1.SchemeGroupVersion.WithResource("pods"),
		MetaGroupVersion:    metav1.SchemeGroupVersion,
		HubGroupVersion:     api.SchemeGroupVersion,
		FieldManager:        fm,
	}
	admit := admission.NewChainHandler(admission.NewHandler(admission.Update))
	return storage, scope, admit, pod
}

func createBenchmarkPod(b *testing.B, storage *REST) *api.Pod {
	b.Helper()
	var v1Pod v1.Pod
	if err := yaml.Unmarshal(exemplarPodYAML, &v1Pod); err != nil {
		b.Fatalf("failed to unmarshal exemplar_pod.yaml: %v", err)
	}
	var internalPod api.Pod
	if err := legacyscheme.Scheme.Convert(&v1Pod, &internalPod, nil); err != nil {
		b.Fatalf("failed to convert pod: %v", err)
	}
	internalPod.ResourceVersion = ""
	ctx := request.WithNamespace(request.WithRequestInfo(context.Background(), &request.RequestInfo{
		IsResourceRequest: true,
		Verb:              "create",
		APIVersion:        "v1",
		Resource:          "pods",
		Namespace:         internalPod.Namespace,
	}), internalPod.Namespace)
	created, err := storage.Create(ctx, &internalPod, rest.ValidateAllObjectFunc, &metav1.CreateOptions{})
	if err != nil {
		b.Fatalf("failed to create pod: %v", err)
	}
	return created.(*api.Pod)
}

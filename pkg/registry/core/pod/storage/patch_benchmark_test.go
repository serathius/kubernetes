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
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	etcd3testing "k8s.io/apiserver/pkg/storage/etcd3/testing"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/client-go/applyconfigurations"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/registry/registrytest"
	"sigs.k8s.io/structured-merge-diff/v7/fieldpath"
)

//go:embed testdata/exemplar_pod.yaml
var exemplarPodYAML []byte

const benchmarkPodCount = 64

func BenchmarkPatchPod(b *testing.B) {
	restStorage, scope, admit, pods, _, _ := setupBenchmarkPatch(b)
	patchTypes := []string{string(types.StrategicMergePatchType)}

	patchAndGet := func(i int) {
		pod := pods[i%len(pods)]
		ctx := audit.WithAuditContext(request.WithNamespace(request.WithRequestInfo(context.Background(), &request.RequestInfo{
			IsResourceRequest: true,
			Verb:              "patch",
			APIVersion:        "v1",
			Resource:          "pods",
			Namespace:         pod.Namespace,
			Name:              pod.Name,
		}), pod.Namespace))
		target := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s?fieldManager=patch-manager", pod.Namespace, pod.Name)
		body := bytes.NewReader(fmt.Appendf(nil, `{"metadata":{"labels":{"bench-updated":"%d"}}}`, i))
		req := httptest.NewRequestWithContext(ctx, http.MethodPatch, target, body)
		req.Header.Set("Content-Type", string(types.StrategicMergePatchType))
		req.Header.Set("Accept", runtime.ContentTypeProtobuf)
		w := httptest.NewRecorder()
		handlers.PatchResource(restStorage, scope, admit, patchTypes)(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
		}

		rv, err := storage.ExtractResourceVersionFromStorageBytes(w.Body.Bytes())
		if err != nil || rv == "" {
			b.Fatalf("failed to extract resourceVersion from patch response: %v (rv=%q)", err, rv)
		}
		// Wait for watch cache to observe the patched revision and read the object through Get.
		if _, err := restStorage.Get(ctx, pod.Name, &metav1.GetOptions{ResourceVersion: rv}); err != nil {
			b.Fatalf("Get from watch cache failed: %v", err)
		}
	}
	for i := range pods {
		patchAndGet(i)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		patchAndGet(i + len(pods))
	}
}

func setupBenchmarkPatch(b *testing.B) (*REST, *handlers.RequestScope, admission.Interface, []*api.Pod, *storagebackend.ConfigForResource, *etcd3testing.EtcdTestServer) {
	b.Helper()
	etcdStorage, server := registrytest.NewEtcdStorage(b, "")
	restOptions := generic.RESTOptions{
		StorageConfig:           etcdStorage,
		Decorator:               genericregistry.StorageWithCacher(),
		DeleteCollectionWorkers: 3,
		ResourcePrefix:          "pods",
	}
	podStorage, err := NewStorage(restOptions, nil, nil, nil, nil)
	if err != nil {
		b.Fatalf("unexpected error from REST storage: %v", err)
	}
	storage := podStorage.Pod
	b.Cleanup(func() {
		storage.Store.DestroyFunc()
		server.Terminate(b)
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

	pods := createBenchmarkPods(b, storage, benchmarkPodCount)
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
	return storage, scope, admit, pods, etcdStorage, server
}

func createBenchmarkPods(b *testing.B, storage *REST, count int) []*api.Pod {
	b.Helper()
	var v1Pod v1.Pod
	if err := yaml.Unmarshal(exemplarPodYAML, &v1Pod); err != nil {
		b.Fatalf("failed to unmarshal exemplar_pod.yaml: %v", err)
	}
	var basePod api.Pod
	if err := legacyscheme.Scheme.Convert(&v1Pod, &basePod, nil); err != nil {
		b.Fatalf("failed to convert pod: %v", err)
	}
	basePod.ResourceVersion = ""
	ctx := request.WithNamespace(context.Background(), basePod.Namespace)
	pods := make([]*api.Pod, count)
	for i := 0; i < count; i++ {
		pod := basePod.DeepCopy()
		pod.Name = fmt.Sprintf("%s-%d", basePod.Name, i)
		key, err := storage.KeyFunc(ctx, pod.Name)
		if err != nil {
			b.Fatalf("failed to compute key: %v", err)
		}
		var created api.Pod
		if err := storage.Store.Storage.Create(ctx, key, pod, &created, 0, false); err != nil {
			b.Fatalf("failed to create pod in storage: %v", err)
		}
		pods[i] = &created
	}
	return pods
}

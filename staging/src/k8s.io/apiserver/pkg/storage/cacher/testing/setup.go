/*
Copyright 2025 The Kubernetes Authors.

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

package testing

import (
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/api/apitesting"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/apis/example"
	examplev1 "k8s.io/apiserver/pkg/apis/example/v1"
	example2v1 "k8s.io/apiserver/pkg/apis/example2/v1"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/etcd3"
	etcd3testing "k8s.io/apiserver/pkg/storage/etcd3/testing"
	"k8s.io/apiserver/pkg/storage/value/encrypt/identity"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"
)

var (
	Scheme   = runtime.NewScheme()
	Codecs   = serializer.NewCodecFactory(Scheme)
	ErrDummy = fmt.Errorf("dummy error")
)

func init() {
	metav1.AddToGroupVersion(Scheme, metav1.SchemeGroupVersion)
	utilruntime.Must(example.AddToScheme(Scheme))
	utilruntime.Must(examplev1.AddToScheme(Scheme))
	utilruntime.Must(example2v1.AddToScheme(Scheme))
}

func NewPod() runtime.Object     { return &example.Pod{} }
func NewPodList() runtime.Object { return &example.PodList{} }

func NewEtcdTestStorage(t testing.TB, prefix string) (*etcd3testing.EtcdTestServer, storage.Interface) {
	server, _ := etcd3testing.NewUnsecuredEtcd3TestClientServer(t)
	versioner := storage.APIObjectVersioner{}
	codec := apitesting.TestCodec(Codecs, examplev1.SchemeGroupVersion)
	compactor := etcd3.NewCompactor(server.V3Client.Client, 0, clock.RealClock{}, nil)
	t.Cleanup(compactor.Stop)
	storage, err := etcd3.New(
		server.V3Client,
		compactor,
		codec,
		NewPod,
		NewPodList,
		prefix,
		"/pods/",
		schema.GroupResource{Resource: "pods"},
		identity.NewEncryptCheckTransformer(),
		etcd3.NewDefaultLeaseManagerConfig(),
		etcd3.NewDefaultDecoder(codec, versioner),
		versioner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(storage.Close)
	return server, storage
}

// GetPodAttrs returns labels and fields of a given object for filtering purposes.
func GetPodAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	pod, ok := obj.(*example.Pod)
	if !ok {
		return nil, nil, fmt.Errorf("not a pod")
	}
	return labels.Set(pod.ObjectMeta.Labels), PodToSelectableFields(pod), nil
}

// PodToSelectableFields returns a field set that represents the object
// TODO: fields are not labels, and the validation rules for them do not apply.
func PodToSelectableFields(pod *example.Pod) fields.Set {
	// The purpose of allocation with a given number of elements is to reduce
	// amount of allocations needed to create the fields.Set. If you add any
	// field here or the number of object-meta related fields changes, this should
	// be adjusted.
	podSpecificFieldsSet := make(fields.Set, 5)
	podSpecificFieldsSet["spec.nodeName"] = pod.Spec.NodeName
	podSpecificFieldsSet["spec.restartPolicy"] = string(pod.Spec.RestartPolicy)
	podSpecificFieldsSet["status.phase"] = string(pod.Status.Phase)
	return AddObjectMetaFieldsSet(podSpecificFieldsSet, &pod.ObjectMeta, true)
}

func AddObjectMetaFieldsSet(source fields.Set, objectMeta *metav1.ObjectMeta, hasNamespaceField bool) fields.Set {
	source["metadata.name"] = objectMeta.Name
	if hasNamespaceField {
		source["metadata.namespace"] = objectMeta.Namespace
	}
	return source
}

func ComputePodKey(obj *example.Pod) string {
	return fmt.Sprintf("/pods/%s/%s", obj.Namespace, obj.Name)
}

type TearDownFunc func()

type SetupOptions struct {
	ResourcePrefix string
	KeyFunc        func(runtime.Object) (string, error)
	IndexerFuncs   map[string]storage.IndexerFunc
	Indexers       cache.Indexers
	Clock          clock.WithTicker
}

type SetupOption func(*SetupOptions)

func WithDefaults(options *SetupOptions) {
	prefix := "/pods/"

	options.ResourcePrefix = prefix
	options.KeyFunc = func(obj runtime.Object) (string, error) { return storage.NamespaceKeyFunc(prefix, obj) }
	options.Clock = clock.RealClock{}
}

func WithClusterScopedKeyFunc(options *SetupOptions) {
	options.KeyFunc = func(obj runtime.Object) (string, error) {
		return storage.NoNamespaceKeyFunc(options.ResourcePrefix, obj)
	}
}

// mirror indexer configuration from pkg/registry/core/pod/strategy.go
func WithNodeNameAndNamespaceIndex(options *SetupOptions) {
	options.IndexerFuncs = map[string]storage.IndexerFunc{
		"spec.nodeName": func(obj runtime.Object) string {
			pod, ok := obj.(*example.Pod)
			if !ok {
				return ""
			}
			return pod.Spec.NodeName
		},
	}
	options.Indexers = map[string]cache.IndexFunc{
		"f:spec.nodeName": func(obj interface{}) ([]string, error) {
			pod := obj.(*example.Pod)
			return []string{pod.Spec.NodeName}, nil
		},
		"f:metadata.namespace": func(obj interface{}) ([]string, error) {
			pod := obj.(*example.Pod)
			return []string{pod.ObjectMeta.Namespace}, nil
		},
	}
}


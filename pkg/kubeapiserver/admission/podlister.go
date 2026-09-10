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

package admission

import (
	"context"
	"errors"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/kubernetes/pkg/apis/core"
	_ "k8s.io/kubernetes/pkg/apis/core/install"
	podsecurityadmission "k8s.io/pod-security-admission/admission"
)

// PodStorage defines the methods needed from the underlying pod storage.
type PodStorage interface {
	Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error)
	List(ctx context.Context, options *metainternalversion.ListOptions) (runtime.Object, error)
}

// StoragePodLister provides pod listing and getting directly from the storage watch cache.
// It implements both podsecurityadmission.PodLister and corev1listers.PodLister.
type StoragePodLister struct {
	store PodStorage
}

var _ podsecurityadmission.PodLister = &StoragePodLister{}
var _ corev1listers.PodLister = &StoragePodLister{}

// NewStoragePodLister creates a new StoragePodLister backed by PodStorage.
func NewStoragePodLister(store PodStorage) *StoragePodLister {
	return &StoragePodLister{store: store}
}

// ListPods queries the storage watch cache (RV=0) for pods in the specified namespace.
func (s *StoragePodLister) ListPods(ctx context.Context, namespace string) ([]*corev1.Pod, error) {
	ctx = genericapirequest.WithNamespace(ctx, namespace)
	obj, err := s.store.List(ctx, &metainternalversion.ListOptions{ResourceVersion: "0"})
	if err != nil {
		return nil, err
	}
	return toV1PodSlice(obj)
}

// List lists all Pods matching the selector across all namespaces directly from storage (RV=0).
func (s *StoragePodLister) List(selector labels.Selector) ([]*corev1.Pod, error) {
	ctx := genericapirequest.NewContext()
	listOptions := &metainternalversion.ListOptions{
		ResourceVersion: "0",
	}
	if selector != nil && !selector.Empty() {
		listOptions.LabelSelector = selector
	}
	obj, err := s.store.List(ctx, listOptions)
	if err != nil {
		return nil, err
	}
	return toV1PodSlice(obj)
}

// Pods returns an object that can list and get Pods for a namespace.
func (s *StoragePodLister) Pods(namespace string) corev1listers.PodNamespaceLister {
	return &storagePodNamespaceLister{
		store:     s.store,
		namespace: namespace,
	}
}

type storagePodNamespaceLister struct {
	store     PodStorage
	namespace string
}

func (s *storagePodNamespaceLister) List(selector labels.Selector) ([]*corev1.Pod, error) {
	ctx := genericapirequest.WithNamespace(context.Background(), s.namespace)
	listOptions := &metainternalversion.ListOptions{
		ResourceVersion: "0",
	}
	if selector != nil && !selector.Empty() {
		listOptions.LabelSelector = selector
	}
	obj, err := s.store.List(ctx, listOptions)
	if err != nil {
		return nil, err
	}
	return toV1PodSlice(obj)
}

func (s *storagePodNamespaceLister) Get(name string) (*corev1.Pod, error) {
	ctx := genericapirequest.WithNamespace(context.Background(), s.namespace)
	obj, err := s.store.Get(ctx, name, &metav1.GetOptions{ResourceVersion: "0"})
	if err != nil {
		return nil, err
	}
	corePod, ok := obj.(*core.Pod)
	if !ok {
		return nil, fmt.Errorf("expected *core.Pod from pod storage, got %T", obj)
	}
	var v1Pod corev1.Pod
	if err := legacyscheme.Scheme.Convert(corePod, &v1Pod, nil); err != nil {
		return nil, fmt.Errorf("failed to convert core Pod to v1 Pod: %w", err)
	}
	return &v1Pod, nil
}

func toV1PodSlice(obj runtime.Object) ([]*corev1.Pod, error) {
	coreList, ok := obj.(*core.PodList)
	if !ok {
		return nil, fmt.Errorf("expected *core.PodList from pod storage, got %T", obj)
	}
	var v1PodList corev1.PodList
	if err := legacyscheme.Scheme.Convert(coreList, &v1PodList, nil); err != nil {
		return nil, fmt.Errorf("failed to convert core PodList to v1 PodList: %w", err)
	}
	pods := make([]*corev1.Pod, len(v1PodList.Items))
	for i := range v1PodList.Items {
		pods[i] = &v1PodList.Items[i]
	}
	return pods, nil
}

// LazyPodLister delegates calls to an underlying StoragePodLister that is configured asynchronously.
// It implements both podsecurityadmission.PodLister and corev1listers.PodLister.
type LazyPodLister struct {
	lock     sync.RWMutex
	delegate *StoragePodLister
}

var _ podsecurityadmission.PodLister = &LazyPodLister{}
var _ corev1listers.PodLister = &LazyPodLister{}

// NewLazyPodLister constructs a LazyPodLister.
func NewLazyPodLister() *LazyPodLister {
	return &LazyPodLister{}
}

// SetDelegate sets the underlying delegate StoragePodLister.
func (l *LazyPodLister) SetDelegate(delegate *StoragePodLister) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.delegate = delegate
}

func (l *LazyPodLister) getDelegate() (*StoragePodLister, error) {
	l.lock.RLock()
	defer l.lock.RUnlock()
	if l.delegate == nil {
		return nil, errors.New("pod storage is not yet initialized")
	}
	return l.delegate, nil
}

// ListPods delegates to the configured delegate.
func (l *LazyPodLister) ListPods(ctx context.Context, namespace string) ([]*corev1.Pod, error) {
	delegate, err := l.getDelegate()
	if err != nil {
		return nil, err
	}
	return delegate.ListPods(ctx, namespace)
}

// List delegates to the configured delegate.
func (l *LazyPodLister) List(selector labels.Selector) ([]*corev1.Pod, error) {
	delegate, err := l.getDelegate()
	if err != nil {
		return nil, err
	}
	return delegate.List(selector)
}

// Pods returns a namespace lister that delegates to the configured delegate.
func (l *LazyPodLister) Pods(namespace string) corev1listers.PodNamespaceLister {
	return &lazyPodNamespaceLister{
		lazy:      l,
		namespace: namespace,
	}
}

type lazyPodNamespaceLister struct {
	lazy      *LazyPodLister
	namespace string
}

func (l *lazyPodNamespaceLister) List(selector labels.Selector) ([]*corev1.Pod, error) {
	delegate, err := l.lazy.getDelegate()
	if err != nil {
		return nil, err
	}
	return delegate.Pods(l.namespace).List(selector)
}

func (l *lazyPodNamespaceLister) Get(name string) (*corev1.Pod, error) {
	delegate, err := l.lazy.getDelegate()
	if err != nil {
		return nil, err
	}
	return delegate.Pods(l.namespace).Get(name)
}

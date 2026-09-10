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
	"fmt"
	"sync"
	"testing"

	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/kubernetes/pkg/apis/core"
)

type fakeStore struct {
	getFunc  func(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error)
	listFunc func(ctx context.Context, options *metainternalversion.ListOptions) (runtime.Object, error)
}

func (f *fakeStore) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	if f.getFunc != nil {
		return f.getFunc(ctx, name, options)
	}
	return nil, nil
}

func (f *fakeStore) List(ctx context.Context, options *metainternalversion.ListOptions) (runtime.Object, error) {
	if f.listFunc != nil {
		return f.listFunc(ctx, options)
	}
	return &core.PodList{}, nil
}

func TestStoragePodLister(t *testing.T) {
	expectedNamespace := "test-ns"
	podName := "test-pod"

	store := &fakeStore{
		getFunc: func(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
			ns, ok := genericapirequest.NamespaceFrom(ctx)
			if !ok || ns != expectedNamespace {
				return nil, fmt.Errorf("unexpected namespace in ctx: %q, expected %q", ns, expectedNamespace)
			}
			if options == nil || options.ResourceVersion != "0" {
				return nil, fmt.Errorf("expected ResourceVersion=0, got %+v", options)
			}
			if name != podName {
				return nil, fmt.Errorf("unexpected name %q", name)
			}
			return &core.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: expectedNamespace,
				},
				Spec: core.PodSpec{
					Containers: []core.Container{
						{
							Name:  "c1",
							Image: "image1",
						},
					},
				},
			}, nil
		},
		listFunc: func(ctx context.Context, options *metainternalversion.ListOptions) (runtime.Object, error) {
			ns, ok := genericapirequest.NamespaceFrom(ctx)
			if ok && ns != expectedNamespace {
				return nil, fmt.Errorf("unexpected namespace in ctx: %q, expected %q", ns, expectedNamespace)
			}
			if options == nil || options.ResourceVersion != "0" {
				return nil, fmt.Errorf("expected ResourceVersion=0, got %+v", options)
			}
			return &core.PodList{
				Items: []core.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      podName,
							Namespace: expectedNamespace,
						},
						Spec: core.PodSpec{
							Containers: []core.Container{
								{
									Name:  "c1",
									Image: "image1",
								},
							},
						},
					},
				},
			}, nil
		},
	}

	lister := NewStoragePodLister(store)

	// Test ListPods
	pods, err := lister.ListPods(context.Background(), expectedNamespace)
	if err != nil {
		t.Fatalf("unexpected error listing pods: %v", err)
	}
	if len(pods) != 1 || pods[0].Name != podName {
		t.Fatalf("expected pod %s, got %+v", podName, pods)
	}

	// Test Pods(ns).Get
	pod, err := lister.Pods(expectedNamespace).Get(podName)
	if err != nil {
		t.Fatalf("unexpected error getting pod: %v", err)
	}
	if pod.Name != podName || pod.Namespace != expectedNamespace {
		t.Fatalf("unexpected pod: %+v", pod)
	}

	// Test Pods(ns).List
	pods, err = lister.Pods(expectedNamespace).List(nil)
	if err != nil {
		t.Fatalf("unexpected error listing pods by namespace: %v", err)
	}
	if len(pods) != 1 || pods[0].Name != podName {
		t.Fatalf("expected pod %s, got %+v", podName, pods)
	}
}

func TestLazyPodLister(t *testing.T) {
	lazy := NewLazyPodLister()

	// Calling before delegate set returns error
	_, err := lazy.ListPods(context.Background(), "ns1")
	if err == nil {
		t.Fatalf("expected error when delegate is not set, got nil")
	}
	_, err = lazy.Pods("ns1").Get("test")
	if err == nil {
		t.Fatalf("expected error when delegate is not set, got nil")
	}

	// Set delegate
	store := &fakeStore{
		getFunc: func(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
			return &core.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: "ns1",
				},
			}, nil
		},
		listFunc: func(ctx context.Context, options *metainternalversion.ListOptions) (runtime.Object, error) {
			return &core.PodList{
				Items: []core.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "lazy-pod",
							Namespace: "ns1",
						},
					},
				},
			}, nil
		},
	}
	lazy.SetDelegate(NewStoragePodLister(store))

	pods, err := lazy.ListPods(context.Background(), "ns1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pods) != 1 || pods[0].Name != "lazy-pod" {
		t.Fatalf("unexpected pods: %+v", pods)
	}

	pod, err := lazy.Pods("ns1").Get("lazy-pod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pod.Name != "lazy-pod" {
		t.Fatalf("unexpected pod: %+v", pod)
	}

	// Concurrency test
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = lazy.ListPods(context.Background(), "ns1")
			_, _ = lazy.Pods("ns1").Get("lazy-pod")
		}()
		go func(idx int) {
			defer wg.Done()
			lazy.SetDelegate(NewStoragePodLister(store))
		}(i)
	}
	wg.Wait()
}

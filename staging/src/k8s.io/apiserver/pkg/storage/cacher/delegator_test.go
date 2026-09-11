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

package cacher

import (
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/apis/example"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/cacher/consistency"
)

func TestConsistencyCheckerDigestMatches(t *testing.T) {
	ctx, store, terminate := testSetup(t)
	t.Cleanup(terminate)

	var out example.Pod
	resourceVersion := ""
	t.Logf("Create %d pods to ensure pagination", storageWatchListPageSize+1)
	for i := 0; i < int(storageWatchListPageSize)+1; i++ {
		pod := &example.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: fmt.Sprintf("%d", i)}}
		err := store.Create(ctx, computePodKey(pod), pod, &out, 0)
		if err != nil {
			t.Fatal(err)
		}
		resourceVersion = out.ResourceVersion
	}

	t.Log("Execute list to ensure cache is up to date")
	outList := &example.PodList{}
	err := store.cacher.GetList(ctx, "/pods/", storage.ListOptions{ResourceVersion: resourceVersion, Recursive: true, Predicate: storage.Everything, ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan}, outList)
	if err != nil {
		t.Fatal(err)
	}
	if len(outList.Items) != int(storageWatchListPageSize)+1 {
		t.Errorf("Expect to get %d pods, got %d", storageWatchListPageSize+1, len(outList.Items))
	}

	checker := consistency.NewChecker("/pods/", schema.GroupResource{}, store.cacher.newListFunc, store.cacher, store.storage)
	digest, err := checker.CalculateDigests(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if digest.CacheDigest != digest.EtcdDigest {
		t.Errorf("Expect digests to match, cache: %s etcd: %q", digest.CacheDigest, digest.EtcdDigest)
	}
	if digest.ResourceVersion != resourceVersion {
		t.Errorf("Expect resourceVersion to equal: %q, got %q", resourceVersion, digest.ResourceVersion)
	}
}

func TestCacheDelegatorGuaranteedUpdateDelayedRetry(t *testing.T) {
	ctx, store, terminate := testSetup(t)
	t.Cleanup(terminate)

	pod := &example.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "retry-pod"}}
	key := computePodKey(pod)
	var out example.Pod
	if err := store.Create(ctx, key, pod, &out, 0); err != nil {
		t.Fatal(err)
	}

	// Wait until watch cache receives the created pod.
	if err := store.cacher.Get(ctx, key, storage.GetOptions{ResourceVersion: out.ResourceVersion}, &example.Pod{}); err != nil {
		t.Fatal(err)
	}

	firstAttempt := true
	updateAttempts := 0
	err := store.GuaranteedUpdate(ctx, key, &out, false, nil, func(input runtime.Object, res storage.ResponseMeta) (runtime.Object, *uint64, error) {
		updateAttempts++
		if firstAttempt {
			firstAttempt = false
			// Perform an out-of-band update directly to underlying storage to induce a conflict on attempt 1.
			var intermediate example.Pod
			if err := store.storage.GuaranteedUpdate(ctx, key, &intermediate, false, nil, storage.SimpleUpdate(func(obj runtime.Object) (runtime.Object, error) {
				p := obj.(*example.Pod).DeepCopy()
				if p.Annotations == nil {
					p.Annotations = make(map[string]string)
				}
				p.Annotations["concurrent"] = "write"
				return p, nil
			}), nil); err != nil {
				return nil, nil, err
			}
		}

		p := input.(*example.Pod).DeepCopy()
		if p.Annotations == nil {
			p.Annotations = make(map[string]string)
		}
		p.Annotations["delegator"] = "success"
		return p, nil, nil
	}, nil)

	if err != nil {
		t.Fatalf("GuaranteedUpdate failed unexpectedly: %v", err)
	}
	if updateAttempts != 2 {
		t.Errorf("Expected exactly 2 update attempts (1 conflict + 1 successful retry), got %d", updateAttempts)
	}
	if out.Annotations["concurrent"] != "write" {
		t.Errorf("Expected out object to contain intermediate concurrent write, got annotations: %v", out.Annotations)
	}
	if out.Annotations["delegator"] != "success" {
		t.Errorf("Expected out object to contain delegator update, got annotations: %v", out.Annotations)
	}
}

func TestCacheDelegatorGuaranteedUpdatePreconditionFailureNotRetried(t *testing.T) {
	ctx, store, terminate := testSetup(t)
	t.Cleanup(terminate)

	pod := &example.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "precond-pod"}}
	key := computePodKey(pod)
	var out example.Pod
	if err := store.Create(ctx, key, pod, &out, 0); err != nil {
		t.Fatal(err)
	}

	// Update pod so out.ResourceVersion is no longer the latest.
	var updated example.Pod
	if err := store.storage.GuaranteedUpdate(ctx, key, &updated, false, nil, storage.SimpleUpdate(func(obj runtime.Object) (runtime.Object, error) {
		p := obj.(*example.Pod).DeepCopy()
		p.Annotations = map[string]string{"v": "2"}
		return p, nil
	}), nil); err != nil {
		t.Fatal(err)
	}

	// Now try GuaranteedUpdate with precondition expecting outdated out.ResourceVersion.
	staleRV := out.ResourceVersion
	preconditions := &storage.Preconditions{ResourceVersion: &staleRV}
	updateAttempts := 0
	err := store.GuaranteedUpdate(ctx, key, &out, false, preconditions, func(input runtime.Object, res storage.ResponseMeta) (runtime.Object, *uint64, error) {
		updateAttempts++
		return input, nil, nil
	}, nil)

	if err == nil {
		t.Fatal("Expected precondition error, got nil")
	}
	if !storage.IsInvalidObj(err) {
		t.Errorf("Expected IsInvalidObj error, got %v", err)
	}
	if updateAttempts > 1 {
		t.Errorf("Expected at most 1 update attempt before failing precondition, got %d", updateAttempts)
	}
}


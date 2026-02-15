/*
Copyright 2024 The Kubernetes Authors.

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
	"context"
	"testing"
	"time"
	"unsafe"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/apis/example"
	"k8s.io/apiserver/pkg/storage"
)

func TestCacherInterning(t *testing.T) {
	ctx, cacher, terminate := testSetup(t)
	defer terminate()

	// Create two pods with same strings but different memory
	// We use []byte conversion to force allocation
	s1 := string([]byte("test-shared-string"))
	s2 := string([]byte("test-shared-string"))

	// Verify they are different initially
	if unsafe.StringData(s1) == unsafe.StringData(s2) {
		t.Skip("Strings already interned by compiler/runtime, cannot verify interning logic")
	}

	pod1 := &example.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "default",
			Labels: map[string]string{
				"key": s1,
			},
		},
	}

	pod2 := &example.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod2",
			Namespace: "default",
			Labels: map[string]string{
				"key": s2,
			},
		},
	}

	// Create pod1
	if err := cacher.Create(ctx, "/pods/default/pod1", pod1, pod1, 0); err != nil {
		t.Fatalf("Failed to create pod1: %v", err)
	}

	// Create pod2
	if err := cacher.Create(ctx, "/pods/default/pod2", pod2, pod2, 0); err != nil {
		t.Fatalf("Failed to create pod2: %v", err)
	}

	// Wait for objects to be in cache
	err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		out1 := &example.Pod{}
		if err := cacher.Get(ctx, "/pods/default/pod1", storage.GetOptions{ResourceVersion: "0"}, out1); err != nil {
			return false, nil
		}
		out2 := &example.Pod{}
		if err := cacher.Get(ctx, "/pods/default/pod2", storage.GetOptions{ResourceVersion: "0"}, out2); err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("Failed to wait for pods to be cached: %v", err)
	}

	out1 := &example.Pod{}
	if err := cacher.Get(ctx, "/pods/default/pod1", storage.GetOptions{ResourceVersion: "0"}, out1); err != nil {
		t.Fatalf("Failed to get pod1: %v", err)
	}

	out2 := &example.Pod{}
	if err := cacher.Get(ctx, "/pods/default/pod2", storage.GetOptions{ResourceVersion: "0"}, out2); err != nil {
		t.Fatalf("Failed to get pod2: %v", err)
	}

	// Verify labels share memory
	l1 := out1.Labels["key"]
	l2 := out2.Labels["key"]

	if unsafe.StringData(l1) != unsafe.StringData(l2) {
		t.Errorf("Expected labels to share memory. l1=%p, l2=%p", unsafe.StringData(l1), unsafe.StringData(l2))
	}
}

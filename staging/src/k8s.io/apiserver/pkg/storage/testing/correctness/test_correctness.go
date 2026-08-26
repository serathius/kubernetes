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

package correctness

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/apis/example"
	"k8s.io/apiserver/pkg/storage"
)

type testStep struct {
	Name             string
	Request          Request
	CorrectResponse  Response
	InvalidResponses []Response
}

var (
	pod1    = newTestPod("pod1", "ns1", "uid-1", "")
	pod2    = newTestPod("pod2", "ns1", "uid-2", "")
	pod1Key = mustGetKey(pod1)
	pod2Key = mustGetKey(pod2)

	steps = []testStep{
		{
			Name: "1. Create pod1 returns success RV=1",
			Request: Request{
				Op:     OpCreate,
				Key:    pod1Key,
				Object: pod1,
			},
			CorrectResponse: Response{
				Object: withRV(pod1, "1"),
			},
			InvalidResponses: []Response{
				{Object: &example.Pod{}, Err: storage.NewKeyExistsError(pod1Key, 0)},
				{Object: &example.Pod{}, Err: storage.NewKeyNotFoundError(pod1Key, 0)},
				{Object: withRV(pod1, "2")},
				{Object: withRV(pod1, "invalid-rv")},
				{Object: nil, Err: nil},
			},
		},
		{
			Name: "2. Create pod1 duplicate returns key exists error",
			Request: Request{
				Op:     OpCreate,
				Key:    pod1Key,
				Object: pod1,
			},
			CorrectResponse: Response{
				Object: nil,
				Err:    storage.NewKeyExistsError(pod1Key, 0),
			},
			InvalidResponses: []Response{
				{Object: withRV(pod1, "2")},
				{Object: &example.Pod{}, Err: storage.NewKeyNotFoundError(pod1Key, 0)},
				{Object: nil, Err: nil},
			},
		},
		{
			Name: "3. Get pod1 returns success RV=1",
			Request: Request{
				Op:  OpGet,
				Key: pod1Key,
			},
			CorrectResponse: Response{
				Object: withRV(pod1, "1"),
			},
			InvalidResponses: []Response{
				{Object: &example.Pod{}, Err: storage.NewKeyNotFoundError(pod1Key, 0)},
				{Object: withRV(pod1, "2")},
				{Object: withRV(pod1, "uid-2")},
				{Object: nil, Err: nil},
			},
		},
		{
			Name: "4. Create pod2 returns success RV=2",
			Request: Request{
				Op:     OpCreate,
				Key:    pod2Key,
				Object: pod2,
			},
			CorrectResponse: Response{
				Object: withRV(pod2, "2"),
			},
			InvalidResponses: []Response{
				{Object: &example.Pod{}, Err: storage.NewKeyExistsError(pod2Key, 0)},
				{Object: withRV(pod2, "1")},
				{Object: withRV(pod2, "3")},
				{Object: nil, Err: nil},
			},
		},
		{
			Name: "5. Get pod2 returns success RV=2",
			Request: Request{
				Op:  OpGet,
				Key: pod2Key,
			},
			CorrectResponse: Response{
				Object: withRV(pod2, "2"),
			},
			InvalidResponses: []Response{
				{Object: &example.Pod{}, Err: storage.NewKeyNotFoundError(pod2Key, 0)},
				{Object: withRV(pod2, "1")},
				{Object: nil, Err: nil},
			},
		},
		{
			Name: "6. Delete pod1 returns success RV=3",
			Request: Request{
				Op:  OpDelete,
				Key: pod1Key,
			},
			CorrectResponse: Response{
				Object: withRV(pod1, "3"),
			},
			InvalidResponses: []Response{
				{Object: &example.Pod{}, Err: storage.NewKeyNotFoundError(pod1Key, 0)},
				{Object: withRV(pod1, "2")},
				{Object: withRV(pod1, "4")},
				{Object: nil, Err: nil},
			},
		},
		{
			Name: "7. Delete pod1 duplicate returns NotFound",
			Request: Request{
				Op:  OpDelete,
				Key: pod1Key,
			},
			CorrectResponse: Response{
				Object: nil,
				Err:    storage.NewKeyNotFoundError(pod1Key, 0),
			},
			InvalidResponses: []Response{
				{Object: withRV(pod1, "4")},
				{Object: nil, Err: nil},
			},
		},
		{
			Name: "8. Get pod1 after delete returns NotFound",
			Request: Request{
				Op:  OpGet,
				Key: pod1Key,
			},
			CorrectResponse: Response{
				Object: nil,
				Err:    storage.NewKeyNotFoundError(pod1Key, 0),
			},
			InvalidResponses: []Response{
				{Object: withRV(pod1, "1")},
				{Object: withRV(pod1, "3")},
				{Object: nil, Err: nil},
			},
		},
		{
			Name: "9. Get pod2 returns success RV=2",
			Request: Request{
				Op:  OpGet,
				Key: pod2Key,
			},
			CorrectResponse: Response{
				Object: withRV(pod2, "2"),
			},
			InvalidResponses: []Response{
				{Object: &example.Pod{}, Err: storage.NewKeyNotFoundError(pod2Key, 0)},
				{Object: withRV(pod2, "3")},
				{Object: nil, Err: nil},
			},
		},
	}
)

// RunTestCorrectness executes the operations from the sequential storage model against real storage
// and validates that every transition matches the StorageModel specification.
func RunTestCorrectness(ctx context.Context, t *testing.T, store storage.Interface, storagePrefix string) {
	list := &example.PodList{}
	err := store.GetList(ctx, "/pods", storage.ListOptions{Recursive: true, Predicate: storage.Everything}, list)
	require.NoError(t, err)
	state, err := NewStateFromStorage(storagePrefix, list, getKey)
	require.NoError(t, err)

	for _, step := range steps {
		out := &example.Pod{}
		var err error
		switch step.Request.Op {
		case OpCreate:
			err = store.Create(ctx, step.Request.Key, step.Request.Object, out, 0)
		case OpGet:
			err = store.Get(ctx, step.Request.Key, step.Request.GetOptions, out)
		case OpDelete:
			err = store.Delete(ctx, step.Request.Key, out, step.Request.Preconditions, storage.ValidateAllObjectFunc, nil, storage.DeleteOptions{})
		default:
			t.Fatalf("unknown operation: %v", step.Request.Op)
		}
		var respObj runtime.Object
		if err == nil {
			respObj = out
		}
		resp := Response{Object: respObj, Err: err}
		ok, next := state.Step(step.Request, resp)
		if respObj != nil {
			acc, _ := meta.Accessor(respObj)
			t.Logf("Step: %s, State RV before: %d, Response RV: %s, Obj: %+v, err: %v", step.Name, state.ResourceVersion, acc.GetResourceVersion(), respObj, err)
		} else {
			t.Logf("Step: %s, State RV before: %d, Response Err: %v", step.Name, state.ResourceVersion, err)
		}
		require.True(t, ok, "step %s failed to match model state transition: req=%+v resp=%+v", step.Name, step.Request, resp)
		state = next
	}
}

func newTestPod(name, namespace, uid string, rv string) *example.Pod {
	pod := &example.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID(uid),
		},
	}
	pod.ResourceVersion = rv
	return pod
}

func withRV(pod *example.Pod, rv string) *example.Pod {
	new := pod.DeepCopy()
	new.ResourceVersion = rv
	return new
}

func mustGetKey(obj runtime.Object) string {
	key, err := getKey(obj)
	if err != nil {
		panic(err)
	}
	return key
}

func getKey(obj runtime.Object) (string, error) {
	pod, ok := obj.(*example.Pod)
	if !ok {
		return "", fmt.Errorf("object is not a pod: %T", obj)
	}
	return "/pods/" + pod.Namespace + "/" + pod.Name, nil
}

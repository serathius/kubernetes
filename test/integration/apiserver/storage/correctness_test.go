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
	"os"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/testing/correctness"
	api "k8s.io/kubernetes/pkg/apis/core"
)

var (
	ops = []ChoiceWeight[correctness.OpType]{{
		Choice: correctness.OpCreate,
		Weight: 25,
	}, {
		Choice: correctness.OpDelete,
		Weight: 25,
	}, {
		Choice: correctness.OpGet,
		Weight: 50,
	}}

	cfg = TraffiConfig{
		Concurrency:   8,
		Namespaces:    2,
		Objects:       4,
		MaxOperations: 10000,
		Ops:           ops,
	}
)

func TestCorrectness(t *testing.T) {
	storages := []struct {
		name string
		fn   func(t *testing.T) (storage.Interface, string)
	}{
		{"etcd3", func(t *testing.T) (storage.Interface, string) {
			return setupStore(t, generic.UndecoratedStorage)
		}},
		{"cacher", func(t *testing.T) (storage.Interface, string) {
			return setupStore(t, genericregistry.StorageWithCacher())
		}},
	}
	for _, s := range storages {
		t.Run(s.name, func(t *testing.T) {
			ctx := t.Context()
			store, storagePrefix := s.fn(t)

			list := &api.PodList{}
			err := store.GetList(ctx, "/pods", storage.ListOptions{Recursive: true, Predicate: storage.Everything}, list)
			require.NoError(t, err)
			initialState, err := correctness.NewStateFromStorage(storagePrefix, list, cacheKeyFunc)
			require.NoError(t, err)

			operations, err := RunTraffic(t.Context(), store, cfg)
			require.NoError(t, err)
			t.Logf("Collected %d operations across %d concurrent workers on %s",
				len(operations), cfg.Concurrency, s.name)

			model := ToPorcupineModel(initialState)
			res, info := porcupine.CheckOperationsVerbose(model, toPorcupineOperations(operations), time.Minute)

			path := os.Getenv("KUBE_STORAGE_VISUALIZATION_PATH")
			if path != "" {
				_ = porcupine.VisualizePath(model, info, path)
				t.Logf("Linearization visualization written to: %s", path)
			}

			require.Equal(t, porcupine.Ok, res, "Linearizability check failed across %d operations", len(operations))
			t.Logf("Linearizability check succeeded across %d operations", len(operations))
		})
	}
}

// ToPorcupineModel maps a correctness.Model to porcupine.Model with an initial state.
func ToPorcupineModel(s *correctness.State) porcupine.Model {
	return porcupine.Model{
		Init: func() any {
			return s.Clone()
		},
		Step: func(state, input, output any) (bool, any) {
			return state.(*correctness.State).Step(input.(correctness.Request), output.(correctness.Response))
		},
		Equal: func(state1, state2 any) bool {
			return state1.(*correctness.State).Equal(state2.(*correctness.State))
		},
		DescribeOperation: func(input, output any) string {
			return input.(correctness.Request).Describe(output.(correctness.Response))
		},
		DescribeState: func(state any) string {
			return state.(*correctness.State).Describe()
		},
	}
}

func toPorcupineOperations(ops []correctness.Operation) []porcupine.Operation {
	pOps := make([]porcupine.Operation, len(ops))
	for i, op := range ops {
		pOps[i] = porcupine.Operation{
			ClientId: int(op.ClientID),
			Input:    op.Request,
			Call:     op.Start.UnixNano(),
			Output:   op.Response,
			Return:   op.End.UnixNano(),
		}
	}
	return pOps
}

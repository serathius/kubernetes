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
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/storage"
)

func TestCorrectness(t *testing.T) {
	model := NewEmptyModel("")
	steps := correctnessTestSteps()
	executedOps := make([]Operation, 0, len(steps))

	for _, step := range steps {
		t.Run(step.Name, func(t *testing.T) {
			for i, invalidResponse := range step.InvalidResponses {
				ok, _ := model.Step(step.Request, invalidResponse)
				require.False(t, ok, "alternative response #%d should return ok=false: req=%+v resp=%+v", i, step.Request, invalidResponse)
			}

			ok, next := model.Step(step.Request, step.CorrectResponse)
			require.True(t, ok, "valid response should return ok=true: req=%+v resp=%+v", step.Request, step.CorrectResponse)
			model = next
		})
		executedOps = append(executedOps, Operation{
			Request:  step.Request,
			Response: step.CorrectResponse,
		})
	}

	t.Run("WatchCorrectness", func(t *testing.T) {
		versioner := storage.APIObjectVersioner{}
		history := NewWatchHistory(executedOps, versioner)

		// 1. Validate full watch on /pods/ from RV 1
		allEvents := history.ExpectedEvents("/pods/", 1, storage.Everything)
		require.Len(t, allEvents, 4, "expected 4 mutating events for full /pods/ watch")
		require.Equal(t, watch.Added, allEvents[0].Type)
		require.Equal(t, watch.Added, allEvents[1].Type)
		require.Equal(t, watch.Deleted, allEvents[2].Type)
		require.Equal(t, watch.Deleted, allEvents[3].Type)

		ValidateWatchGuarantees(t, versioner, history, RecordedWatch{
			Name:            "watch-all-simulated",
			Prefix:          "/pods/",
			ResourceVersion: "1",
			Events:          allEvents,
		})

		// 2. Validate filtered watch on /pods/ matching metadata.name=pod1
		predPod1 := storage.SelectionPredicate{Field: fields.OneTermEqualSelector("metadata.name", "pod1")}
		pod1Events := history.ExpectedEvents("/pods/", 1, predPod1)
		require.Len(t, pod1Events, 2, "expected 2 mutating events for pod1 filtered watch")
		require.Equal(t, watch.Added, pod1Events[0].Type)
		require.Equal(t, watch.Deleted, pod1Events[1].Type)

		ValidateWatchGuarantees(t, versioner, history, RecordedWatch{
			Name:            "watch-pod1-simulated",
			Prefix:          "/pods/",
			ResourceVersion: "1",
			Predicate:       predPod1,
			Events:          pod1Events,
		})

		// 3. Validate resumed watch from RV 2
		from2Events := history.ExpectedEvents("/pods/", 2, storage.Everything)
		require.Len(t, from2Events, 3, "expected 3 mutating events for watch from RV 2")
		require.Equal(t, watch.Added, from2Events[0].Type)
		require.Equal(t, watch.Deleted, from2Events[1].Type)
		require.Equal(t, watch.Deleted, from2Events[2].Type)

		ValidateWatchGuarantees(t, versioner, history, RecordedWatch{
			Name:            "watch-from2-simulated",
			Prefix:          "/pods/",
			ResourceVersion: "2",
			Events:          from2Events,
		})
	})
}

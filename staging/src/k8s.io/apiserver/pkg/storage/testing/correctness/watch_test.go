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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/apis/example"
	"k8s.io/apiserver/pkg/storage"
)

func TestWatchListValidation(t *testing.T) {
	versioner := storage.APIObjectVersioner{}
	pod1 := newTestPod("pod1", "ns1", types.UID("uid-1"), "")
	pod2 := newTestPod("pod2", "ns1", types.UID("uid-2"), "")

	ops := []Operation{
		{
			Request: Request{Op: OpCreate, Key: "/pods/ns1/pod1", Object: pod1},
			Response: Response{
				Object: withRV(pod1, "2"),
			},
		},
		{
			Request: Request{Op: OpCreate, Key: "/pods/ns1/pod2", Object: pod2},
			Response: Response{
				Object: withRV(pod2, "3"),
			},
		},
		{
			Request: Request{Op: OpDelete, Key: "/pods/ns1/pod1"},
			Response: Response{
				Object: withRV(pod1, "4"),
			},
		},
	}

	history := NewWatchHistory(ops, versioner)

	// Bookmark at RV 3 (after pod1 and pod2 created)
	initialBookmark := &example.Pod{
		ObjectMeta: metav1.ObjectMeta{
			ResourceVersion: "3",
			Annotations: map[string]string{
				"k8s.io/initial-events-end": "true",
			},
		},
	}

	// Initial events before bookmark are ignored; streaming events after bookmark are validated.
	events := []watch.Event{
		{Type: watch.Added, Object: withRV(pod1, "2")},
		{Type: watch.Added, Object: withRV(pod2, "3")},
		{Type: watch.Bookmark, Object: initialBookmark},
		{Type: watch.Deleted, Object: withRV(pod1, "4")},
	}

	ValidateWatchGuarantees(t, versioner, history, RecordedWatch{
		Name:              "watchlist-test",
		Prefix:            "/pods/",
		SendInitialEvents: true,
		Events:            events,
	})
}

func TestWatchPredicateTransitions(t *testing.T) {
	versioner := storage.APIObjectVersioner{}

	podNodeA := newTestPod("podA", "ns1", types.UID("uid-a"), "")
	podNodeA.Spec.NodeName = "node-a"

	podNodeB := newTestPod("podA", "ns1", types.UID("uid-a"), "")
	podNodeB.Spec.NodeName = "node-b"

	ops := []Operation{
		{
			Request: Request{Op: OpCreate, Key: "/pods/ns1/podA", Object: podNodeA},
			Response: Response{
				Object: withRV(podNodeA, "2"),
			},
		},
		{
			// Update from node-a to node-b
			Request: Request{Op: OpUpdate, Key: "/pods/ns1/podA", Object: podNodeB},
			Response: Response{
				Object: withRV(podNodeB, "3"),
			},
		},
		{
			// Delete podA
			Request: Request{Op: OpDelete, Key: "/pods/ns1/podA"},
			Response: Response{
				Object: withRV(podNodeB, "4"),
			},
		},
	}

	history := NewWatchHistory(ops, versioner)

	// Watch matching node-a: should see Added at RV=2, then Deleted at RV=3 (leaving node-a)
	predNodeA := storage.SelectionPredicate{Field: fields.OneTermEqualSelector("spec.nodeName", "node-a")}
	eventsNodeA := history.ExpectedEvents("/pods/", 1, predNodeA)
	require.Len(t, eventsNodeA, 2)
	require.Equal(t, watch.Added, eventsNodeA[0].Type)
	require.Equal(t, watch.Deleted, eventsNodeA[1].Type)

	// Watch matching node-b: should see Added at RV=3 (entering node-b), then Deleted at RV=4 (deleted)
	predNodeB := storage.SelectionPredicate{Field: fields.OneTermEqualSelector("spec.nodeName", "node-b")}
	eventsNodeB := history.ExpectedEvents("/pods/", 1, predNodeB)
	require.Len(t, eventsNodeB, 2)
	require.Equal(t, watch.Added, eventsNodeB[0].Type)
	require.Equal(t, watch.Deleted, eventsNodeB[1].Type)
}

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

package node

import (
	"testing"

	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	storagev1listers "k8s.io/client-go/listers/storage/v1"
	"k8s.io/client-go/tools/cache"
)

func TestGraphPopulator_CoalescedDeleteAndRecreate(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	graph := NewGraph()

	g := &graphPopulator{
		graph:            graph,
		attachmentQueue:  newRateLimitingQueue("test_node_authorizer_attachment_populator"),
		attachmentLister: storagev1listers.NewVolumeAttachmentLister(indexer),
	}

	// Step 1: VolumeAttachment 1 on node1 is in the graph.
	va1 := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "va-x",
		},
		Spec: storagev1.VolumeAttachmentSpec{
			NodeName: "node1",
		},
	}
	graph.AddVolumeAttachment(va1.Name, va1.Spec.NodeName)

	vaVert, ok := graph.getVertexRLocked(vaVertexType, "", "va-x")
	if !ok {
		t.Fatalf("expected va-x vertex")
	}
	node1Vert, ok := graph.getVertexRLocked(nodeVertexType, "", "node1")
	if !ok {
		t.Fatalf("expected node1 vertex")
	}
	if !graph.graph.HasEdgeFromTo(vaVert, node1Vert) {
		t.Fatalf("expected initial graph edge for va1")
	}

	// Step 2: Simulate va1 deletion event and va2 creation event queued together.
	va2 := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "va-x",
		},
		Spec: storagev1.VolumeAttachmentSpec{
			NodeName: "node2",
		},
	}

	if err := indexer.Add(va2); err != nil {
		t.Fatalf("failed to add va2 to indexer: %v", err)
	}

	// Enqueue delete for va1, then enqueue add for va2 (coalesces into 1 item in workqueue)
	g.deleteVolumeAttachment(va1)
	g.addVolumeAttachment(va2)

	if g.attachmentQueue.Len() != 1 {
		t.Fatalf("expected queue length 1 due to event coalescing, got %d", g.attachmentQueue.Len())
	}

	// Step 3: Run processNextWorkItem once.
	processed := processNextWorkItem(g.attachmentQueue, g.processAttachmentKey)
	if !processed {
		t.Fatalf("expected processNextWorkItem to return true")
	}
	if g.attachmentQueue.Len() != 0 {
		t.Fatalf("expected queue to be empty after processing, got %d", g.attachmentQueue.Len())
	}

	// Step 4: Assert graph state.
	graph.lock.RLock()
	defer graph.lock.RUnlock()

	vaVert, ok = graph.getVertexRLocked(vaVertexType, "", "va-x")
	if !ok {
		t.Fatalf("expected va-x vertex after processing")
	}
	node2Vert, ok := graph.getVertexRLocked(nodeVertexType, "", "node2")
	if !ok {
		t.Fatalf("expected node2 vertex after processing")
	}
	if !graph.graph.HasEdgeFromTo(vaVert, node2Vert) {
		t.Errorf("expected edge from va-x to node2")
	}
	if node1Vert, ok := graph.getVertexRLocked(nodeVertexType, "", "node1"); ok {
		if graph.graph.HasEdgeFromTo(vaVert, node1Vert) {
			t.Errorf("expected va-x to NOT have edge to node1")
		}
	}
}

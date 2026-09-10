/*
Copyright 2018 The Kubernetes Authors.

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
	"fmt"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	certsv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestDeleteEdgesLocked(t *testing.T) {
	cases := []struct {
		desc        string
		fromType    vertexType
		toType      vertexType
		toNamespace string
		toName      string
		start       *Graph
		expect      *Graph
	}{
		{
			// single edge from a configmap to a node, will delete edge and orphaned configmap
			desc:        "edges and source orphans are deleted, destination orphans are preserved",
			fromType:    configMapVertexType,
			toType:      nodeVertexType,
			toNamespace: "",
			toName:      "node1",
			start: func() *Graph {
				g := NewGraph()
				g.getOrCreateVertexLocked(configMapVertexType, "namespace1", "configmap2")
				nodeVertex := g.getOrCreateVertexLocked(nodeVertexType, "", "node1")
				configmapVertex := g.getOrCreateVertexLocked(configMapVertexType, "namespace1", "configmap1")
				g.addEdgeLocked(configmapVertex, nodeVertex, nodeVertex)
				return g
			}(),
			expect: func() *Graph {
				g := NewGraph()
				g.getOrCreateVertexLocked(configMapVertexType, "namespace1", "configmap2")
				g.getOrCreateVertexLocked(nodeVertexType, "", "node1")
				return g
			}(),
		},
		{
			// two edges from the same configmap to distinct nodes, will delete one of the edges
			desc:        "edges are deleted, non-orphans and destination orphans are preserved",
			fromType:    configMapVertexType,
			toType:      nodeVertexType,
			toNamespace: "",
			toName:      "node2",
			start: func() *Graph {
				g := NewGraph()
				nodeVertex1 := g.getOrCreateVertexLocked(nodeVertexType, "", "node1")
				nodeVertex2 := g.getOrCreateVertexLocked(nodeVertexType, "", "node2")
				configmapVertex := g.getOrCreateVertexLocked(configMapVertexType, "namespace1", "configmap1")
				g.addEdgeLocked(configmapVertex, nodeVertex1, nodeVertex1)
				g.addEdgeLocked(configmapVertex, nodeVertex2, nodeVertex2)
				return g
			}(),
			expect: func() *Graph {
				g := NewGraph()
				nodeVertex1 := g.getOrCreateVertexLocked(nodeVertexType, "", "node1")
				g.getOrCreateVertexLocked(nodeVertexType, "", "node2")
				configmapVertex := g.getOrCreateVertexLocked(configMapVertexType, "namespace1", "configmap1")
				g.addEdgeLocked(configmapVertex, nodeVertex1, nodeVertex1)
				return g
			}(),
		},
		{
			desc:        "no edges to delete",
			fromType:    configMapVertexType,
			toType:      nodeVertexType,
			toNamespace: "",
			toName:      "node1",
			start: func() *Graph {
				g := NewGraph()
				g.getOrCreateVertexLocked(nodeVertexType, "", "node1")
				g.getOrCreateVertexLocked(configMapVertexType, "namespace1", "configmap1")
				return g
			}(),
			expect: func() *Graph {
				g := NewGraph()
				g.getOrCreateVertexLocked(nodeVertexType, "", "node1")
				g.getOrCreateVertexLocked(configMapVertexType, "namespace1", "configmap1")
				return g
			}(),
		},
		{
			desc:        "destination vertex does not exist",
			fromType:    configMapVertexType,
			toType:      nodeVertexType,
			toNamespace: "",
			toName:      "node1",
			start: func() *Graph {
				g := NewGraph()
				g.getOrCreateVertexLocked(configMapVertexType, "namespace1", "configmap1")
				return g
			}(),
			expect: func() *Graph {
				g := NewGraph()
				g.getOrCreateVertexLocked(configMapVertexType, "namespace1", "configmap1")
				return g
			}(),
		},
		{
			desc:        "source vertex type doesn't exist",
			fromType:    configMapVertexType,
			toType:      nodeVertexType,
			toNamespace: "",
			toName:      "node1",
			start: func() *Graph {
				g := NewGraph()
				g.getOrCreateVertexLocked(nodeVertexType, "", "node1")
				return g
			}(),
			expect: func() *Graph {
				g := NewGraph()
				g.getOrCreateVertexLocked(nodeVertexType, "", "node1")
				return g
			}(),
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			c.start.deleteEdgesLocked(c.fromType, c.toType, c.toNamespace, c.toName)

			// Note: We assert on substructures (graph.Nodes(), graph.Edges()) because the graph tracks
			// freed IDs for reuse, which results in an irrelevant inequality between start and expect.

			// sort the nodes by ID
			// (the slices we get back are from map iteration, where order is not guaranteed)
			expectNodes := c.expect.graph.Nodes()
			sort.Slice(expectNodes, func(i, j int) bool {
				return expectNodes[i].ID() < expectNodes[j].ID()
			})
			startNodes := c.start.graph.Nodes()
			sort.Slice(startNodes, func(i, j int) bool {
				return startNodes[i].ID() < startNodes[j].ID()
			})
			assert.Equal(t, expectNodes, startNodes)

			// sort the edges by from ID, then to ID
			// (the slices we get back are from map iteration, where order is not guaranteed)
			expectEdges := c.expect.graph.Edges()
			sort.Slice(expectEdges, func(i, j int) bool {
				if expectEdges[i].From().ID() == expectEdges[j].From().ID() {
					return expectEdges[i].To().ID() < expectEdges[j].To().ID()
				}
				return expectEdges[i].From().ID() < expectEdges[j].From().ID()
			})
			startEdges := c.start.graph.Edges()
			sort.Slice(startEdges, func(i, j int) bool {
				if startEdges[i].From().ID() == startEdges[j].From().ID() {
					return startEdges[i].To().ID() < startEdges[j].To().ID()
				}
				return startEdges[i].From().ID() < startEdges[j].From().ID()
			})
			assert.Equal(t, expectEdges, startEdges)

			// vertices is a recursive map, no need to sort
			assert.Equal(t, c.expect.vertices, c.start.vertices)
		})
	}
}

func TestIndex2(t *testing.T) {
	NewTestGraph := func() *Graph {
		g := NewGraph()
		g.destinationEdgeThreshold = 3
		return g
	}

	pv := func(pvName, pvcName, secretName string) *corev1.PersistentVolume {
		pv := &corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{Name: pvName, UID: types.UID(fmt.Sprintf("pv%suid", pvName))},
			Spec: corev1.PersistentVolumeSpec{
				ClaimRef: &corev1.ObjectReference{
					Name:      pvcName,
					Namespace: "ns",
				},
			},
		}
		if secretName != "" {
			pv.Spec.PersistentVolumeSource = corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					NodePublishSecretRef: &corev1.SecretReference{
						Name:      secretName,
						Namespace: "ns",
					},
				},
			}
		}
		return pv
	}

	toString := func(g *Graph, id int) string {
		for _, namespaceName := range g.vertices {
			for _, nameVertex := range namespaceName {
				for _, vertex := range nameVertex {
					if vertex.id == id {
						return vertex.String()
					}
				}
			}
		}
		return ""
	}
	expectGraph := func(t *testing.T, g *Graph, expect map[string][]string) {
		t.Helper()
		actual := map[string][]string{}
		for _, node := range g.graph.Nodes() {
			sortedTo := []string{}
			for _, to := range g.graph.From(node) {
				sortedTo = append(sortedTo, toString(g, to.ID()))
			}
			sort.Strings(sortedTo)
			actual[toString(g, node.ID())] = sortedTo
		}
		if diff := cmp.Diff(actual, expect); diff != "" {
			t.Errorf("Bad graph; diff (-got +want):\n%s", diff)
		}
	}
	expectIndex := func(t *testing.T, g *Graph, expect map[string][]string) {
		t.Helper()
		actual := map[string][]string{}
		for from, to := range g.destinationEdgeIndex {
			sortedValues := []string{}
			for member, count := range to.members {
				sortedValues = append(sortedValues, fmt.Sprintf("%s=%d", toString(g, member), count))
			}
			sort.Strings(sortedValues)
			actual[toString(g, from)] = sortedValues
		}
		if diff := cmp.Diff(actual, expect); diff != "" {
			t.Errorf("Bad index; diff (-got +want):\n%s", diff)
		}
	}

	cases := []struct {
		desc             string
		startingGraph    *Graph
		graphTransformer func(*Graph)
		expectedGraph    map[string][]string
		expectedIndex    map[string][]string
	}{
		{
			desc:             "empty graph",
			startingGraph:    NewTestGraph(),
			graphTransformer: func(_ *Graph) {},
			expectedGraph:    map[string][]string{},
			expectedIndex:    map[string][]string{},
		},
		{
			desc:          "resourceslices adding",
			startingGraph: NewTestGraph(),
			graphTransformer: func(g *Graph) {
				g.AddResourceSlice("s1", "node1")
				g.AddResourceSlice("s2", "node2")
				g.AddResourceSlice("s3", "node3")
			},
			expectedGraph: map[string][]string{
				"node:node1":       {},
				"node:node2":       {},
				"node:node3":       {},
				"resourceslice:s1": {"node:node1"},
				"resourceslice:s2": {"node:node2"},
				"resourceslice:s3": {"node:node3"},
			},
			expectedIndex: map[string][]string{},
		},
		{
			desc: "resourceslices deleting",
			startingGraph: func() *Graph {
				g := NewTestGraph()
				g.AddResourceSlice("s1", "node1")
				g.AddResourceSlice("s2", "node2")
				g.AddResourceSlice("s3", "node3")
				return g
			}(),
			graphTransformer: func(g *Graph) {
				g.DeleteResourceSlice("s1")
			},
			expectedGraph: map[string][]string{
				"node:node2":       {},
				"node:node3":       {},
				"resourceslice:s2": {"node:node2"},
				"resourceslice:s3": {"node:node3"},
			},
			expectedIndex: map[string][]string{},
		},
		{
			desc:          "volumeattachments adding",
			startingGraph: NewTestGraph(),
			graphTransformer: func(g *Graph) {
				g.AddVolumeAttachment("va1", "node1")
				g.AddVolumeAttachment("va2", "node2")
				g.AddVolumeAttachment("va3", "node3")
			},
			expectedGraph: map[string][]string{
				"node:node1":           {},
				"node:node2":           {},
				"node:node3":           {},
				"volumeattachment:va1": {"node:node1"},
				"volumeattachment:va2": {"node:node2"},
				"volumeattachment:va3": {"node:node3"},
			},
			expectedIndex: map[string][]string{},
		},
		{
			desc: "volumeattachments deleting",
			startingGraph: func() *Graph {
				g := NewTestGraph()
				g.AddVolumeAttachment("va1", "node1")
				g.AddVolumeAttachment("va2", "node2")
				g.AddVolumeAttachment("va3", "node3")
				return g
			}(),
			graphTransformer: func(g *Graph) {
				g.DeleteVolumeAttachment("va1")
			},
			expectedGraph: map[string][]string{
				"node:node2":           {},
				"node:node3":           {},
				"volumeattachment:va2": {"node:node2"},
				"volumeattachment:va3": {"node:node3"},
			},
			expectedIndex: map[string][]string{},
		},
		{
			desc:          "persistentvolumes adding",
			startingGraph: NewTestGraph(),
			graphTransformer: func(g *Graph) {
				g.AddPV(pv("pv1", "pvc1", ""))
				g.AddPV(pv("pv2", "pvc2", ""))
				g.AddPV(pv("pv3", "pvc3", ""))
			},
			expectedGraph: map[string][]string{
				"pv:pv1":      {"pvc:ns/pvc1"},
				"pv:pv2":      {"pvc:ns/pvc2"},
				"pv:pv3":      {"pvc:ns/pvc3"},
				"pvc:ns/pvc1": {},
				"pvc:ns/pvc2": {},
				"pvc:ns/pvc3": {},
			},
			expectedIndex: map[string][]string{},
		},
		{
			desc: "persistentvolumes deleting",
			startingGraph: func() *Graph {
				g := NewTestGraph()
				g.AddPV(pv("pv1", "pvc1", ""))
				g.AddPV(pv("pv2", "pvc2", ""))
				g.AddPV(pv("pv3", "pvc3", ""))
				return g
			}(),
			graphTransformer: func(g *Graph) {
				g.DeletePV("pv1")
			},
			expectedGraph: map[string][]string{
				"pv:pv2":      {"pvc:ns/pvc2"},
				"pv:pv3":      {"pvc:ns/pvc3"},
				"pvc:ns/pvc2": {},
				"pvc:ns/pvc3": {},
			},
			expectedIndex: map[string][]string{},
		},
		{
			desc:          "persistentvolumes with secrets",
			startingGraph: NewTestGraph(),
			graphTransformer: func(g *Graph) {
				g.AddPV(pv("pv1", "pvc1", "s1"))
				g.AddPV(pv("pv2", "pvc2", "s2"))
				g.AddPV(pv("pv3", "pvc3", "s3"))
			},
			expectedGraph: map[string][]string{
				"pv:pv1":       {"pvc:ns/pvc1"},
				"pv:pv2":       {"pvc:ns/pvc2"},
				"pv:pv3":       {"pvc:ns/pvc3"},
				"pvc:ns/pvc1":  {},
				"pvc:ns/pvc2":  {},
				"pvc:ns/pvc3":  {},
				"secret:ns/s1": {"pv:pv1"},
				"secret:ns/s2": {"pv:pv2"},
				"secret:ns/s3": {"pv:pv3"},
			},
			expectedIndex: map[string][]string{},
		},
		{
			desc:          "podcertificaterequest adding",
			startingGraph: NewTestGraph(),
			graphTransformer: func(g *Graph) {
				g.AddPodCertificateRequest(pcr("foo", "pcr1", "pod1", "sa1", "node1"))
				g.AddPodCertificateRequest(pcr("foo", "pcr2", "pod1", "sa1", "node1"))
				g.AddPodCertificateRequest(pcr("foo", "pcr3", "pod2", "sa2", "node1"))
				g.AddPodCertificateRequest(pcr("foo", "pcr4", "pod4", "sa4", "node2"))
			},
			expectedGraph: map[string][]string{
				"node:node1":                     {},
				"node:node2":                     {},
				"podcertificaterequest:foo/pcr1": {"node:node1"},
				"podcertificaterequest:foo/pcr2": {"node:node1"},
				"podcertificaterequest:foo/pcr3": {"node:node1"},
				"podcertificaterequest:foo/pcr4": {"node:node2"},
			},
			expectedIndex: map[string][]string{},
		},
		{
			desc: "podcertificaterequest deleting",
			startingGraph: func() *Graph {
				g := NewTestGraph()
				g.AddPodCertificateRequest(pcr("foo", "pcr1", "pod1", "sa1", "node1"))
				g.AddPodCertificateRequest(pcr("foo", "pcr2", "pod1", "sa1", "node1"))
				g.AddPodCertificateRequest(pcr("foo", "pcr3", "pod2", "sa2", "node1"))
				g.AddPodCertificateRequest(pcr("foo", "pcr4", "pod4", "sa4", "node2"))
				return g
			}(),
			graphTransformer: func(g *Graph) {
				g.DeletePodCertificateRequest(pcr("foo", "pcr3", "", "", ""))
				g.DeletePodCertificateRequest(pcr("foo", "pcr4", "", "", ""))
			},
			expectedGraph: map[string][]string{
				"node:node1":                     {},
				"podcertificaterequest:foo/pcr1": {"node:node1"},
				"podcertificaterequest:foo/pcr2": {"node:node1"},
			},
			expectedIndex: map[string][]string{},
		},
		{
			desc: "podcertificaterequest deleting (check namespace/name ordering)",
			startingGraph: func() *Graph {
				g := NewTestGraph()
				g.AddPodCertificateRequest(pcr("foo", "bar", "pod1", "sa1", "node1"))
				g.AddPodCertificateRequest(pcr("bar", "foo", "pod2", "sa2", "node2"))
				return g
			}(),
			graphTransformer: func(g *Graph) {
				g.DeletePodCertificateRequest(pcr("foo", "bar", "", "", ""))
			},
			expectedGraph: map[string][]string{
				"node:node2":                    {},
				"podcertificaterequest:bar/foo": {"node:node2"},
			},
			expectedIndex: map[string][]string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			tc.graphTransformer(tc.startingGraph)
			expectGraph(t, tc.startingGraph, tc.expectedGraph)
			expectIndex(t, tc.startingGraph, tc.expectedIndex)
		})
	}
}

func pcr(namespace, name, podName, saName, nodeName string) *certsv1.PodCertificateRequest {
	pcr := &certsv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       types.UID(fmt.Sprintf("pcr%suid", name)),
		},
		Spec: certsv1.PodCertificateRequestSpec{
			PodName:            podName,
			ServiceAccountName: saName,
			NodeName:           types.NodeName(nodeName),
		},
	}
	return pcr
}

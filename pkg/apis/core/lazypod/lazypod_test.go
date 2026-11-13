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

package lazypod_test

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"sigs.k8s.io/randfill"

	v1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/cbor"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/etcd3"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/kubernetes/pkg/apis/core"
	_ "k8s.io/kubernetes/pkg/apis/core/install"
	"k8s.io/kubernetes/pkg/apis/core/lazypod"
	corev1 "k8s.io/kubernetes/pkg/apis/core/v1"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/printers"
	printersinternal "k8s.io/kubernetes/pkg/printers/internalversion"
	registrypod "k8s.io/kubernetes/pkg/registry/core/pod"
)

type writeCountingBuffer struct {
	bytes.Buffer
	writes int
}

func (b *writeCountingBuffer) Write(p []byte) (int, error) {
	b.writes++
	return b.Buffer.Write(p)
}

func newStandardScheme(t *testing.T) (*runtime.Scheme, serializer.CodecFactory) {
	t.Helper()
	scheme := runtime.NewScheme()
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})
	if err := core.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add core to standard scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add core/v1 to standard scheme: %v", err)
	}
	return scheme, serializer.NewCodecFactory(
		scheme,
		serializer.WithStreamingCollectionEncodingToJSON(),
		serializer.WithStreamingCollectionEncodingToProtobuf(),
		serializer.WithSerializer(cbor.NewSerializerInfo),
	)
}

func newLazyScheme(t *testing.T) (*runtime.Scheme, serializer.CodecFactory) {
	t.Helper()
	scheme, codecs := newStandardScheme(t)
	if err := lazypod.Install(scheme); err != nil {
		t.Fatalf("failed to install lazypod into scheme: %v", err)
	}
	return scheme, codecs
}

func protobufCodecFor(t *testing.T, codecs serializer.CodecFactory) runtime.Codec {
	t.Helper()
	info, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), runtime.ContentTypeProtobuf)
	if !ok {
		t.Fatalf("protobuf serializer not found in CodecFactory")
	}
	return codecs.CodecForVersions(info.Serializer, info.Serializer, v1.SchemeGroupVersion, core.SchemeGroupVersion)
}

func jsonCodecFor(t *testing.T, codecs serializer.CodecFactory) runtime.Codec {
	t.Helper()
	info, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), runtime.ContentTypeJSON)
	if !ok {
		t.Fatalf("json serializer not found in CodecFactory")
	}
	return codecs.CodecForVersions(info.Serializer, info.Serializer, v1.SchemeGroupVersion, core.SchemeGroupVersion)
}

func cborCodecFor(t *testing.T, codecs serializer.CodecFactory) runtime.Codec {
	t.Helper()
	info, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), runtime.ContentTypeCBOR)
	if !ok {
		t.Fatalf("cbor serializer not found in CodecFactory")
	}
	return codecs.CodecForVersions(info.Serializer, info.Serializer, v1.SchemeGroupVersion, core.SchemeGroupVersion)
}

func encodeRawV1PodToEtcdBytes(t *testing.T, pod *v1.Pod) []byte {
	t.Helper()
	rawScheme := runtime.NewScheme()
	rawScheme.AddKnownTypes(v1.SchemeGroupVersion, &v1.Pod{})
	rawCodecs := serializer.NewCodecFactory(rawScheme)
	info, ok := runtime.SerializerInfoForMediaType(rawCodecs.SupportedMediaTypes(), runtime.ContentTypeProtobuf)
	if !ok {
		t.Fatalf("protobuf serializer not found")
	}
	codec := rawCodecs.EncoderForVersion(info.Serializer, v1.SchemeGroupVersion)
	podCopy := pod.DeepCopy()
	podCopy.ResourceVersion = ""
	var buf bytes.Buffer
	if err := codec.Encode(podCopy, &buf); err != nil {
		t.Fatalf("failed to encode raw v1.Pod: %v", err)
	}
	return buf.Bytes()
}

func testPodFixtures() []struct {
	name string
	pod  *v1.Pod
} {
	negGrace := int64(-10)
	customGrace := int64(45)
	enableLinksFalse := false

	alreadyDefaulted := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "already-defaulted-pod",
			Namespace: "kube-system",
			UID:       types.UID("11111111-2222-3333-4444-555555555555"),
			Labels:    map[string]string{"app": "apiserver", "tier": "control-plane"},
		},
		Spec: v1.PodSpec{
			NodeName:           "node-control-1",
			ServiceAccountName: "default",
			Containers: []v1.Container{
				{
					Name:  "apiserver",
					Image: "registry.k8s.io/kube-apiserver:v1.32.0",
				},
			},
		},
		Status: v1.PodStatus{
			Phase: v1.PodRunning,
			PodIP: "10.0.0.15",
		},
	}
	corev1.SetObjectDefaults_Pod(alreadyDefaulted)

	return []struct {
		name string
		pod  *v1.Pod
	}{
		{
			name: "minimal-undefaulted-latest-image",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx-minimal",
					Namespace: "default",
					UID:       types.UID("uid-minimal-1"),
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "nginx",
							Image: "nginx:latest",
						},
					},
				},
			},
		},
		{
			name: "already-defaulted-pod",
			pod:  alreadyDefaulted,
		},
		{
			name: "multi-container-hostnetwork-ports-resources-sa-sync",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "complex-worker",
					Namespace:   "production",
					UID:         types.UID("uid-complex-2"),
					Generation:  3,
					Labels:      map[string]string{"app": "worker", "env": "prod", "shard": "01"},
					Annotations: map[string]string{"prometheus.io/scrape": "true"},
				},
				Spec: v1.PodSpec{
					NodeName:                      "worker-node-42",
					HostNetwork:                   true,
					ServiceAccountName:            "worker-sa",
					TerminationGracePeriodSeconds: &negGrace,
					InitContainers: []v1.Container{
						{
							Name:  "init-sysctl",
							Image: "busybox:1.36",
						},
					},
					Containers: []v1.Container{
						{
							Name:  "agent",
							Image: "gcr.io/example/agent",
							Ports: []v1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: 8080,
								},
								{
									Name:          "metrics",
									ContainerPort: 9090,
									HostPort:      19090,
									Protocol:      v1.ProtocolUDP,
								},
							},
							Resources: v1.ResourceRequirements{
								Limits: v1.ResourceList{
									v1.ResourceCPU:    resource.MustParse("500m"),
									v1.ResourceMemory: resource.MustParse("256Mi"),
								},
								Requests: v1.ResourceList{
									v1.ResourceCPU: resource.MustParse("250m"),
								},
							},
						},
					},
				},
				Status: v1.PodStatus{
					Phase:             v1.PodRunning,
					PodIP:             "192.168.1.50",
					NominatedNodeName: "worker-node-42",
				},
			},
		},
		{
			name: "volumes-emptydir-secret-configmap-downward-projected-hostpath-and-podips-sync",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "storage-pod",
					Namespace: "storage-ns",
					UID:       types.UID("uid-storage-3"),
				},
				Spec: v1.PodSpec{
					DeprecatedServiceAccount:      "legacy-sa",
					TerminationGracePeriodSeconds: &customGrace,
					EnableServiceLinks:            &enableLinksFalse,
					Volumes: []v1.Volume{
						{
							Name:         "cache-vol",
							VolumeSource: v1.VolumeSource{},
						},
						{
							Name: "secret-vol",
							VolumeSource: v1.VolumeSource{
								Secret: &v1.SecretVolumeSource{
									SecretName: "my-secret",
								},
							},
						},
						{
							Name: "cm-vol",
							VolumeSource: v1.VolumeSource{
								ConfigMap: &v1.ConfigMapVolumeSource{
									LocalObjectReference: v1.LocalObjectReference{Name: "my-cm"},
								},
							},
						},
						{
							Name: "downward-vol",
							VolumeSource: v1.VolumeSource{
								DownwardAPI: &v1.DownwardAPIVolumeSource{},
							},
						},
						{
							Name: "projected-vol",
							VolumeSource: v1.VolumeSource{
								Projected: &v1.ProjectedVolumeSource{},
							},
						},
						{
							Name: "hostpath-vol",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/var/log",
								},
							},
						},
					},
					Containers: []v1.Container{
						{
							Name:  "pause",
							Image: "registry.k8s.io/pause:3.9",
						},
					},
				},
				Status: v1.PodStatus{
					Phase: v1.PodPending,
					PodIPs: []v1.PodIP{
						{IP: "fd00::10"},
						{IP: "10.244.0.10"},
					},
				},
			},
		},
	}
}

func TestEtcd3ReadDefaultingAndRVSplicing1To1Parity(t *testing.T) {
	_, stdCodecs := newStandardScheme(t)
	stdPBCodec := protobufCodecFor(t, stdCodecs)
	stdJSONCodec := jsonCodecFor(t, stdCodecs)
	stdCBORCodec := cborCodecFor(t, stdCodecs)
	stdDecoder := etcd3.NewDefaultDecoder(stdPBCodec, storage.APIObjectVersioner{})

	_, lazyCodecs := newLazyScheme(t)
	lazyPBCodec := protobufCodecFor(t, lazyCodecs)
	lazyJSONCodec := jsonCodecFor(t, lazyCodecs)
	lazyCBORCodec := cborCodecFor(t, lazyCodecs)
	lazyDecoder := etcd3.NewDefaultDecoder(lazyPBCodec, storage.APIObjectVersioner{})

	const modRev int64 = 987654

	for _, tc := range testPodFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			etcdBytes := encodeRawV1PodToEtcdBytes(t, tc.pod)

			stdInternal := &core.Pod{}
			if err := stdDecoder.Decode(etcdBytes, stdInternal, modRev); err != nil {
				t.Fatalf("standard Decode failed: %v", err)
			}

			lazyInternal := &lazypod.Pod{}
			if err := lazyDecoder.Decode(etcdBytes, lazyInternal, modRev); err != nil {
				t.Fatalf("lazy Decode failed: %v", err)
			}

			if !lazyInternal.IsLazy() {
				t.Fatalf("expected lazyInternal.IsLazy() == true after etcd3 Decode + wire defaulting + RV update")
			}

			// Verify Protobuf GET encoding parity while staying lazy.
			var stdOutBuf, lazyOutBuf bytes.Buffer
			if err := stdPBCodec.Encode(stdInternal, &stdOutBuf); err != nil {
				t.Fatalf("stdPBCodec.Encode failed: %v", err)
			}
			if err := lazyPBCodec.Encode(lazyInternal, &lazyOutBuf); err != nil {
				t.Fatalf("lazyPBCodec.Encode failed: %v", err)
			}
			if !lazyInternal.IsLazy() {
				t.Fatalf("expected lazyInternal.IsLazy() == true after Protobuf Encode")
			}
			if !bytes.Equal(stdOutBuf.Bytes(), lazyOutBuf.Bytes()) {
				var stdV1, lazyV1 v1.Pod
				_, _, _ = stdPBCodec.Decode(stdOutBuf.Bytes(), nil, &stdV1)
				_, _, _ = stdPBCodec.Decode(lazyOutBuf.Bytes(), nil, &lazyV1)
				t.Fatalf("Protobuf output bytes mismatch (std len=%d, lazy len=%d)\nv1 diff:\n%s\nstd hex:  %x\nlazy hex: %x",
					stdOutBuf.Len(), lazyOutBuf.Len(), cmp.Diff(&stdV1, &lazyV1), stdOutBuf.Bytes(), lazyOutBuf.Bytes())
			}

			// Verify AsPartialObjectMetadata fast path stays lazy and matches standard.
			stdPartial := meta.AsPartialObjectMetadata(stdInternal)
			lazyPartial := meta.AsPartialObjectMetadata(lazyInternal)
			if !lazyInternal.IsLazy() {
				t.Fatalf("expected lazyInternal.IsLazy() == true after AsPartialObjectMetadata")
			}
			if !apiequality.Semantic.DeepEqual(stdPartial, lazyPartial) {
				t.Fatalf("PartialObjectMetadata mismatch:\n%s", cmp.Diff(stdPartial, lazyPartial))
			}

			// Verify cacher indexers and field selection stay lazy and match standard.
			stdLabels, stdFields, err := registrypod.GetAttrs(stdInternal)
			if err != nil {
				t.Fatalf("std GetAttrs failed: %v", err)
			}
			lazyLabels, lazyFields, err := registrypod.GetAttrs(lazyInternal)
			if err != nil {
				t.Fatalf("lazy GetAttrs failed: %v", err)
			}
			if !lazyInternal.IsLazy() {
				t.Fatalf("expected lazyInternal.IsLazy() == true after GetAttrs")
			}
			if !apiequality.Semantic.DeepEqual(stdLabels, lazyLabels) {
				t.Fatalf("GetAttrs labels mismatch:\n%s", cmp.Diff(stdLabels, lazyLabels))
			}
			if !apiequality.Semantic.DeepEqual(stdFields, lazyFields) {
				t.Fatalf("GetAttrs fields mismatch:\n%s", cmp.Diff(stdFields, lazyFields))
			}

			// Verify TableGenerator (both normal and wide) stays lazy and matches standard.
			tableGen := printers.NewTableGenerator().With(printersinternal.AddHandlers)
			for _, wide := range []bool{false, true} {
				opts := metav1.TableOptions{}
				if !wide {
					opts.NoHeaders = false
				}
				_ = wide
				stdTable, err := tableGen.GenerateTable(stdInternal, printers.GenerateOptions{Wide: wide})
				if err != nil {
					t.Fatalf("std GenerateTable(wide=%v) failed: %v", wide, err)
				}
				lazyTable, err := tableGen.GenerateTable(lazyInternal, printers.GenerateOptions{Wide: wide})
				if err != nil {
					t.Fatalf("lazy GenerateTable(wide=%v) failed: %v", wide, err)
				}
				if !lazyInternal.IsLazy() {
					t.Fatalf("expected lazyInternal.IsLazy() == true after GenerateTable(wide=%v)", wide)
				}
				if len(stdTable.Rows) != len(lazyTable.Rows) {
					t.Fatalf("table row count mismatch: %d vs %d", len(stdTable.Rows), len(lazyTable.Rows))
				}
				if !apiequality.Semantic.DeepEqual(stdTable.Rows[0].Cells, lazyTable.Rows[0].Cells) {
					t.Fatalf("table cells mismatch (wide=%v):\n%s", wide, cmp.Diff(stdTable.Rows[0].Cells, lazyTable.Rows[0].Cells))
				}
			}

			// Verify JSON encoding parity (decodes on demand without mutating source WirePod).
			shallowJSONCopy := &lazypod.Pod{}
			reflect.ValueOf(shallowJSONCopy).Elem().Set(reflect.ValueOf(lazyInternal).Elem())
			var stdJSONBuf, lazyJSONBuf bytes.Buffer
			if err := stdJSONCodec.Encode(stdInternal, &stdJSONBuf); err != nil {
				t.Fatalf("stdJSONCodec.Encode failed: %v", err)
			}
			if err := lazyJSONCodec.Encode(shallowJSONCopy, &lazyJSONBuf); err != nil {
				t.Fatalf("lazyJSONCodec.Encode failed: %v", err)
			}
			if !bytes.Equal(stdJSONBuf.Bytes(), lazyJSONBuf.Bytes()) {
				t.Fatalf("JSON output mismatch:\n%s", cmp.Diff(stdJSONBuf.String(), lazyJSONBuf.String()))
			}

			// Verify CBOR encoding & decoding parity via direct MarshalCBOR/UnmarshalCBOR.
			shallowCBORCopy := &lazypod.Pod{}
			reflect.ValueOf(shallowCBORCopy).Elem().Set(reflect.ValueOf(lazyInternal).Elem())
			var stdCBORBuf, lazyCBORBuf bytes.Buffer
			if err := stdCBORCodec.Encode(stdInternal, &stdCBORBuf); err != nil {
				t.Fatalf("stdCBORCodec.Encode failed: %v", err)
			}
			if err := lazyCBORCodec.Encode(shallowCBORCopy, &lazyCBORBuf); err != nil {
				t.Fatalf("lazyCBORCodec.Encode failed: %v", err)
			}
			if !bytes.Equal(stdCBORBuf.Bytes(), lazyCBORBuf.Bytes()) {
				t.Fatalf("CBOR output mismatch: std len=%d, lazy len=%d", stdCBORBuf.Len(), lazyCBORBuf.Len())
			}
			decodedFromCBOR, _, err := lazyCBORCodec.Decode(lazyCBORBuf.Bytes(), nil, &lazypod.Pod{})
			if err != nil {
				t.Fatalf("lazyCBORCodec.Decode failed: %v", err)
			}
			unwrappedCBOR, err := runtime.EnsureDecodedObject(decodedFromCBOR)
			if err != nil {
				t.Fatalf("EnsureDecodedObject(CBOR) failed: %v", err)
			}
			if !apiequality.Semantic.DeepEqual(stdInternal, unwrappedCBOR) {
				t.Fatalf("CBOR round-trip mismatch:\n%s", cmp.Diff(stdInternal, unwrappedCBOR))
			}
			if !lazyInternal.IsLazy() {
				t.Fatalf("expected lazyInternal.IsLazy() == true after shallow JSON/CBOR encodes")
			}

			// Verify PodIPs / HostIPs accessors and scoped patch / projection interfaces stay lazy.
			if !apiequality.Semantic.DeepEqual(stdInternal.GetStatusPodIPs(), lazyInternal.GetStatusPodIPs()) {
				t.Fatalf("GetStatusPodIPs mismatch:\n%s", cmp.Diff(stdInternal.GetStatusPodIPs(), lazyInternal.GetStatusPodIPs()))
			}
			if !apiequality.Semantic.DeepEqual(stdInternal.GetStatusHostIPs(), lazyInternal.GetStatusHostIPs()) {
				t.Fatalf("GetStatusHostIPs mismatch:\n%s", cmp.Diff(stdInternal.GetStatusHostIPs(), lazyInternal.GetStatusHostIPs()))
			}
			baseMetaObj, err := lazyInternal.ExtractScopedPatchBase(true, false, true)
			if err != nil {
				t.Fatalf("ExtractScopedPatchBase failed: %v", err)
			}
			patchedCore := baseMetaObj.(*core.Pod)
			if patchedCore.Annotations == nil {
				patchedCore.Annotations = map[string]string{}
			}
			patchedCore.Annotations["lazypod.k8s.io/scoped"] = "ok"
			splicedObj, err := lazyInternal.SpliceScopedPatchResult(patchedCore, true, false)
			if err != nil {
				t.Fatalf("SpliceScopedPatchResult failed: %v", err)
			}
			splicedPod := splicedObj.(*lazypod.Pod)
			if !splicedPod.IsLazy() || !splicedPod.HasEqualSpecWireBytes(lazyInternal) {
				t.Fatalf("expected splicedPod to remain lazy with equal spec wire bytes")
			}
			if got := splicedPod.GetAnnotations()["lazypod.k8s.io/scoped"]; got != "ok" {
				t.Fatalf("expected spliced annotation, got %q", got)
			}
			if !lazyInternal.IsLazy() {
				t.Fatalf("expected lazyInternal.IsLazy() == true after scoped patch & IP accessors")
			}

			// Verify EnsureDecodedObject unwraps *lazypod.Pod into an identical *core.Pod.
			unwrapped, err := runtime.EnsureDecodedObject(lazyInternal)
			if err != nil {
				t.Fatalf("EnsureDecodedObject failed: %v", err)
			}
			decodedPod, ok := unwrapped.(*core.Pod)
			if !ok {
				t.Fatalf("expected *core.Pod from EnsureDecodedObject, got %T", unwrapped)
			}
			if !apiequality.Semantic.DeepEqual(stdInternal, decodedPod) {
				t.Fatalf("EnsureDecodedObject mismatch:\n%s", cmp.Diff(stdInternal, decodedPod))
			}
		})
	}
}

func TestPodListProtobufAndTableParity(t *testing.T) {
	_, stdCodecs := newStandardScheme(t)
	stdPBCodec := protobufCodecFor(t, stdCodecs)
	stdDecoder := etcd3.NewDefaultDecoder(stdPBCodec, storage.APIObjectVersioner{})

	_, lazyCodecs := newLazyScheme(t)
	lazyPBCodec := protobufCodecFor(t, lazyCodecs)
	lazyDecoder := etcd3.NewDefaultDecoder(lazyPBCodec, storage.APIObjectVersioner{})

	fixtures := testPodFixtures()
	stdList := &core.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "5000"}}
	lazyList := &lazypod.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "5000"}}

	for i, tc := range fixtures {
		etcdBytes := encodeRawV1PodToEtcdBytes(t, tc.pod)
		var sp core.Pod
		if err := stdDecoder.Decode(etcdBytes, &sp, int64(100+i)); err != nil {
			t.Fatalf("std Decode failed: %v", err)
		}
		stdList.Items = append(stdList.Items, sp)

		var lp lazypod.Pod
		if err := lazyDecoder.Decode(etcdBytes, &lp, int64(100+i)); err != nil {
			t.Fatalf("lazy Decode failed: %v", err)
		}
		lazyList.Items = append(lazyList.Items, lp)
	}

	var stdBuf, lazyBuf writeCountingBuffer
	if err := stdPBCodec.Encode(stdList, &stdBuf); err != nil {
		t.Fatalf("stdPBCodec.Encode(PodList) failed: %v", err)
	}
	if err := lazyPBCodec.Encode(lazyList, &lazyBuf); err != nil {
		t.Fatalf("lazyPBCodec.Encode(PodList) failed: %v", err)
	}
	if lazyBuf.writes <= 1 || lazyBuf.writes != stdBuf.writes {
		t.Fatalf("expected streaming collection writes matching standard (%d), got %d", stdBuf.writes, lazyBuf.writes)
	}
	for i := range lazyList.Items {
		if !lazyList.Items[i].IsLazy() {
			t.Fatalf("expected item %d to remain lazy after PodList Protobuf encode", i)
		}
	}
	if !bytes.Equal(stdBuf.Bytes(), lazyBuf.Bytes()) {
		t.Fatalf("PodList Protobuf bytes mismatch")
	}

	tableGen := printers.NewTableGenerator().With(printersinternal.AddHandlers)
	for _, wide := range []bool{false, true} {
		stdTable, err := tableGen.GenerateTable(stdList, printers.GenerateOptions{Wide: wide})
		if err != nil {
			t.Fatalf("stdTable(PodList, wide=%v) failed: %v", wide, err)
		}
		lazyTable, err := tableGen.GenerateTable(lazyList, printers.GenerateOptions{Wide: wide})
		if err != nil {
			t.Fatalf("lazyTable(PodList, wide=%v) failed: %v", wide, err)
		}
		for i := range lazyList.Items {
			if !lazyList.Items[i].IsLazy() {
				t.Fatalf("expected item %d to remain lazy after PodList GenerateTable(wide=%v)", i, wide)
			}
		}
		if len(stdTable.Rows) != len(lazyTable.Rows) {
			t.Fatalf("row count mismatch: %d vs %d", len(stdTable.Rows), len(lazyTable.Rows))
		}
		for i := range stdTable.Rows {
			if !apiequality.Semantic.DeepEqual(stdTable.Rows[i].Cells, lazyTable.Rows[i].Cells) {
				t.Fatalf("row %d cells mismatch:\n%s", i, cmp.Diff(stdTable.Rows[i].Cells, lazyTable.Rows[i].Cells))
			}
		}
	}

	// Verify EnsureDecodedObject on *lazypod.PodList unwraps to *core.PodList.
	unwrapped, err := runtime.EnsureDecodedObject(lazyList)
	if err != nil {
		t.Fatalf("EnsureDecodedObject(PodList) failed: %v", err)
	}
	decodedList, ok := unwrapped.(*core.PodList)
	if !ok {
		t.Fatalf("expected *core.PodList, got %T", unwrapped)
	}
	if !apiequality.Semantic.DeepEqual(stdList, decodedList) {
		t.Fatalf("EnsureDecodedObject(PodList) mismatch:\n%s", cmp.Diff(stdList, decodedList))
	}
	_ = context.Background()
}

func TestShallowCopyAndConcurrentAccessIsolation(t *testing.T) {
	_, lazyCodecs := newLazyScheme(t)
	lazyPBCodec := protobufCodecFor(t, lazyCodecs)
	lazyJSONCodec := jsonCodecFor(t, lazyCodecs)
	lazyCBORCodec := cborCodecFor(t, lazyCodecs)
	lazyDecoder := etcd3.NewDefaultDecoder(lazyPBCodec, storage.APIObjectVersioner{})

	unbound := testPodFixtures()[0].pod.DeepCopy()
	etcdBytes := encodeRawV1PodToEtcdBytes(t, unbound)

	cached := &lazypod.Pod{}
	if err := lazyDecoder.Decode(etcdBytes, cached, 500); err != nil {
		t.Fatalf("lazy Decode failed: %v", err)
	}

	var workers sync.WaitGroup
	for g := 0; g < 24; g++ {
		workers.Add(1)
		go func(id int) {
			defer workers.Done()
			for iter := 0; iter < 20; iter++ {
				// Simulate Cacher.Get shallow struct copy (reflect.Value.Set).
				bindCopy := &lazypod.Pod{}
				reflect.ValueOf(bindCopy).Elem().Set(reflect.ValueOf(cached).Elem())
				if bindCopy.GetSpecNodeName() != "" {
					t.Errorf("worker %d: cached pod leaked nodeName %q", id, bindCopy.GetSpecNodeName())
					return
				}
				bindCopy.SetSpecNodeName("worker-node-bound")
				bindCopy.SetAnnotations(map[string]string{"bound": "true"})
				bindCopy.UpsertStatusCondition(core.PodCondition{
					Type:   core.PodScheduled,
					Status: core.ConditionTrue,
				})

				delCopy := &lazypod.Pod{}
				reflect.ValueOf(delCopy).Elem().Set(reflect.ValueOf(cached).Elem())
				now := metav1.Now()
				zero := int64(0)
				_ = delCopy.GetDeletionGracePeriodSeconds()
				delCopy.SetDeletionTimestamp(&now)
				delCopy.SetDeletionGracePeriodSeconds(&zero)
				if id%2 == 0 {
					delCopy.SetDeletionGracePeriodSeconds(nil)
				}
				_ = delCopy.GetDeletionGracePeriodSeconds()

				readCopy := &lazypod.Pod{}
				reflect.ValueOf(readCopy).Elem().Set(reflect.ValueOf(cached).Elem())
				var buf bytes.Buffer
				if err := lazyPBCodec.Encode(readCopy, &buf); err != nil {
					t.Errorf("worker %d PB Encode failed: %v", id, err)
					return
				}
				buf.Reset()
				if err := lazyJSONCodec.Encode(readCopy, &buf); err != nil {
					t.Errorf("worker %d JSON Encode failed: %v", id, err)
					return
				}
				buf.Reset()
				if err := lazyCBORCodec.Encode(readCopy, &buf); err != nil {
					t.Errorf("worker %d CBOR Encode failed: %v", id, err)
					return
				}
			}
		}(g)
	}
	workers.Wait()

	if !cached.IsLazy() {
		t.Fatalf("expected cached pod to remain lazy")
	}
	if got := cached.GetSpecNodeName(); got != "" {
		t.Fatalf("cached pod nodeName mutated to %q, want empty", got)
	}
	if got := cached.GetDeletionTimestamp(); got != nil {
		t.Fatalf("cached pod deletionTimestamp mutated to %v, want nil", got)
	}
	if got := cached.GetDeletionGracePeriodSeconds(); got != nil {
		t.Fatalf("cached pod deletionGracePeriodSeconds mutated to %v, want nil", got)
	}
}

func BenchmarkLazyPodVsStandardPod(b *testing.B) {
	t := &testing.T{}
	_, stdCodecs := newStandardScheme(t)
	_, lazyCodecs := newLazyScheme(t)
	stdPBCodec := protobufCodecFor(t, stdCodecs)
	lazyPBCodec := protobufCodecFor(t, lazyCodecs)
	stdDecoder := etcd3.NewDefaultDecoder(stdPBCodec, storage.APIObjectVersioner{})
	lazyDecoder := etcd3.NewDefaultDecoder(lazyPBCodec, storage.APIObjectVersioner{})

	rawPod := testPodFixtures()[2].pod.DeepCopy()
	corev1.SetObjectDefaults_Pod(rawPod)
	etcdBytes := encodeRawV1PodToEtcdBytes(t, rawPod)
	tableGen := printers.NewTableGenerator().With(printersinternal.AddHandlers)

	b.Run("WatchCacheDecodeAndIndex/Standard", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var pod core.Pod
			if err := stdDecoder.Decode(etcdBytes, &pod, 100); err != nil {
				b.Fatal(err)
			}
			_ = pod.GetName()
			_ = pod.GetNamespace()
			_ = pod.GetLabels()
			_ = pod.GetSpecNodeName()
			_ = pod.GetStatusPhase()
			_ = pod.GetStatusFirstPodIP()
		}
	})

	b.Run("WatchCacheDecodeAndIndex/LazyPod", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var pod lazypod.Pod
			if err := lazyDecoder.Decode(etcdBytes, &pod, 100); err != nil {
				b.Fatal(err)
			}
			_ = pod.GetName()
			_ = pod.GetNamespace()
			_ = pod.GetLabels()
			_ = pod.GetSpecNodeName()
			_ = pod.GetStatusPhase()
			_ = pod.GetStatusFirstPodIP()
		}
	})

	b.Run("List100Protobuf/Standard", func(b *testing.B) {
		b.ReportAllocs()
		var buf bytes.Buffer
		for i := 0; i < b.N; i++ {
			list := &core.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "200"}, Items: make([]core.Pod, 100)}
			for j := 0; j < 100; j++ {
				if err := stdDecoder.Decode(etcdBytes, &list.Items[j], int64(100+j)); err != nil {
					b.Fatal(err)
				}
			}
			buf.Reset()
			if err := stdPBCodec.Encode(list, &buf); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("List100Protobuf/LazyPod", func(b *testing.B) {
		b.ReportAllocs()
		var buf bytes.Buffer
		for i := 0; i < b.N; i++ {
			list := &lazypod.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "200"}, Items: make([]lazypod.Pod, 100)}
			for j := 0; j < 100; j++ {
				if err := lazyDecoder.Decode(etcdBytes, &list.Items[j], int64(100+j)); err != nil {
					b.Fatal(err)
				}
			}
			buf.Reset()
			if err := lazyPBCodec.Encode(list, &buf); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("List100TableWide/Standard", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			list := &core.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "200"}, Items: make([]core.Pod, 100)}
			for j := 0; j < 100; j++ {
				if err := stdDecoder.Decode(etcdBytes, &list.Items[j], int64(100+j)); err != nil {
					b.Fatal(err)
				}
			}
			if _, err := tableGen.GenerateTable(list, printers.GenerateOptions{Wide: true}); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("List100TableWide/LazyPod", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			list := &lazypod.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "200"}, Items: make([]lazypod.Pod, 100)}
			for j := 0; j < 100; j++ {
				if err := lazyDecoder.Decode(etcdBytes, &list.Items[j], int64(100+j)); err != nil {
					b.Fatal(err)
				}
			}
			if _, err := tableGen.GenerateTable(list, printers.GenerateOptions{Wide: true}); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("GracefulDeleteRoundTrip/Standard", func(b *testing.B) {
		b.ReportAllocs()
		var buf bytes.Buffer
		now := metav1.NewTime(time.Unix(1700000100, 0).UTC())
		grace := int64(30)
		for i := 0; i < b.N; i++ {
			var pod core.Pod
			if err := stdDecoder.Decode(etcdBytes, &pod, 100); err != nil {
				b.Fatal(err)
			}
			_ = pod.GetSpecTerminationGracePeriodSeconds()
			_ = pod.GetSpecNodeName()
			_ = pod.GetStatusPhase()
			pod.SetDeletionTimestamp(&now)
			pod.SetDeletionGracePeriodSeconds(&grace)
			pod.SetGeneration(pod.GetGeneration() + 1)
			buf.Reset()
			if err := stdPBCodec.Encode(&pod, &buf); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("GracefulDeleteRoundTrip/LazyPod", func(b *testing.B) {
		b.ReportAllocs()
		var buf bytes.Buffer
		now := metav1.NewTime(time.Unix(1700000100, 0).UTC())
		grace := int64(30)
		for i := 0; i < b.N; i++ {
			var pod lazypod.Pod
			if err := lazyDecoder.Decode(etcdBytes, &pod, 100); err != nil {
				b.Fatal(err)
			}
			_ = pod.GetSpecTerminationGracePeriodSeconds()
			_ = pod.GetSpecNodeName()
			_ = pod.GetStatusPhase()
			pod.SetDeletionTimestamp(&now)
			pod.SetDeletionGracePeriodSeconds(&grace)
			pod.SetGeneration(pod.GetGeneration() + 1)
			buf.Reset()
			if err := lazyPBCodec.Encode(&pod, &buf); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func assertWireDefaultingMatchesGenerated(t *testing.T, rawPod *v1.Pod) {
	t.Helper()
	rawBytes, err := rawPod.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal v1.Pod: %v", err)
	}
	var stdPod v1.Pod
	if err := stdPod.Unmarshal(rawBytes); err != nil {
		t.Fatalf("failed to unmarshal baseline v1.Pod: %v", err)
	}
	corev1.SetObjectDefaults_Pod(&stdPod)

	lazyPod := lazypod.NewV1PodFromWire(rawBytes)
	lazypod.SetObjectDefaults_V1Pod(lazyPod)
	if !lazyPod.IsLazy() {
		t.Fatalf("expected lazyPod to remain lazy after SetObjectDefaults_V1Pod")
	}
	decLazy, err := lazyPod.EnsureDecoded()
	if err != nil {
		t.Fatalf("EnsureDecoded failed: %v", err)
	}
	if !apiequality.Semantic.DeepEqual(&stdPod, decLazy) {
		t.Fatalf("wire defaulting diverged from SetObjectDefaults_Pod:\n%s", cmp.Diff(&stdPod, decLazy))
	}
}

func newPodFuzzer(seed int64) *randfill.Filler {
	quantities := []string{"100m", "250m", "1", "64Mi", "500n", "250u", "0.0005", "0"}
	return randfill.NewWithSeed(seed).NilChance(0.55).NumElements(0, 2).MaxDepth(8).Funcs(
		func(q *resource.Quantity, c randfill.Continue) {
			*q = resource.MustParse(quantities[c.Intn(len(quantities))])
		},
		func(ios *intstr.IntOrString, c randfill.Continue) {
			if c.Bool() {
				*ios = intstr.FromInt32(int32(1 + c.Intn(65535)))
			} else {
				*ios = intstr.FromString("http")
			}
		},
		func(tm *metav1.Time, c randfill.Continue) {
			*tm = metav1.NewTime(time.Unix(int64(c.Intn(1_800_000_000)), 0).UTC())
		},
		func(mt *metav1.MicroTime, c randfill.Continue) {
			*mt = metav1.NewMicroTime(time.Unix(int64(c.Intn(1_800_000_000)), 0).UTC())
		},
		func(f *metav1.FieldsV1, c randfill.Continue) {
			*f = *metav1.NewFieldsV1(`{"f:metadata":{"f:labels":{"f:app":{}}}}`)
		},
		func(tm *metav1.TypeMeta, _ randfill.Continue) {
			*tm = metav1.TypeMeta{}
		},
	)
}

func TestWirePodDefaultingParityWithGeneratedDefaults(t *testing.T) {
	t.Run("RandomFuzzDefaultFeatureGates", func(t *testing.T) {
		for seed := int64(1); seed <= 300; seed++ {
			f := newPodFuzzer(seed)
			var pod v1.Pod
			f.Fill(&pod)
			assertWireDefaultingMatchesGenerated(t, &pod)
		}
	})

	t.Run("RandomFuzzFeatureGatesToggled", func(t *testing.T) {
		featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.H2CContainerProbe, true)
		featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.ImageVolume, true)
		featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.PodLevelResources, true)
		featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.PodLevelResourcesFixDefaulting, false)
		for seed := int64(1001); seed <= 1200; seed++ {
			f := newPodFuzzer(seed)
			var pod v1.Pod
			f.Fill(&pod)
			assertWireDefaultingMatchesGenerated(t, &pod)
		}
	})

	t.Run("TargetedNestedAndFeatureGatedCases", func(t *testing.T) {
		featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.H2CContainerProbe, true)
		featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.ImageVolume, true)
		featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.PodLevelResources, true)
		featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.PodLevelResourcesFixDefaulting, false)

		nestedPod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "nested-defaults", Namespace: "default"},
			Spec: v1.PodSpec{
				Resources: &v1.ResourceRequirements{
					Limits: v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
				},
				Overhead: v1.ResourceList{v1.ResourceCPU: resource.MustParse("100n")},
				Volumes: []v1.Volume{
					{Name: "iscsi", VolumeSource: v1.VolumeSource{ISCSI: &v1.ISCSIVolumeSource{TargetPortal: "10.0.0.1:3260", IQN: "iqn.test"}}},
					{Name: "rbd", VolumeSource: v1.VolumeSource{RBD: &v1.RBDVolumeSource{CephMonitors: []string{"10.0.0.2"}, RBDImage: "img"}}},
					{Name: "azure", VolumeSource: v1.VolumeSource{AzureDisk: &v1.AzureDiskVolumeSource{DiskName: "d", DataDiskURI: "u"}}},
					{Name: "scaleio", VolumeSource: v1.VolumeSource{ScaleIO: &v1.ScaleIOVolumeSource{Gateway: "gw", System: "sys"}}},
					{Name: "downward", VolumeSource: v1.VolumeSource{DownwardAPI: &v1.DownwardAPIVolumeSource{
						Items: []v1.DownwardAPIVolumeFile{{Path: "name", FieldRef: &v1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
					}}},
					{Name: "projected", VolumeSource: v1.VolumeSource{Projected: &v1.ProjectedVolumeSource{
						Sources: []v1.VolumeProjection{
							{ServiceAccountToken: &v1.ServiceAccountTokenProjection{Path: "token"}},
							{DownwardAPI: &v1.DownwardAPIProjection{
								Items: []v1.DownwardAPIVolumeFile{{Path: "ns", FieldRef: &v1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}},
							}},
						},
					}}},
					{Name: "ephemeral", VolumeSource: v1.VolumeSource{Ephemeral: &v1.EphemeralVolumeSource{
						VolumeClaimTemplate: &v1.PersistentVolumeClaimTemplate{
							Spec: v1.PersistentVolumeClaimSpec{
								Resources: v1.VolumeResourceRequirements{Requests: v1.ResourceList{v1.ResourceStorage: resource.MustParse("500n")}},
							},
						},
					}}},
					{Name: "image", VolumeSource: v1.VolumeSource{Image: &v1.ImageVolumeSource{Reference: "registry.k8s.io/img:latest"}}},
				},
				Containers: []v1.Container{{
					Name:  "app",
					Image: "nginx:1.27",
					Env: []v1.EnvVar{
						{Name: "POD_NAME", ValueFrom: &v1.EnvVarSource{FieldRef: &v1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
						{Name: "FILE_VAL", ValueFrom: &v1.EnvVarSource{FileKeyRef: &v1.FileKeySelector{VolumeName: "downward", Path: "name", Key: "k"}}},
					},
					Resources: v1.ResourceRequirements{
						Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("0.0005")},
					},
					LivenessProbe: &v1.Probe{
						ProbeHandler: v1.ProbeHandler{HTTPGet: &v1.HTTPGetAction{Port: intstr.FromInt32(8080)}},
					},
					ReadinessProbe: &v1.Probe{
						ProbeHandler: v1.ProbeHandler{GRPC: &v1.GRPCAction{Port: 9090}},
					},
					Lifecycle: &v1.Lifecycle{
						PreStop: &v1.LifecycleHandler{HTTPGet: &v1.HTTPGetAction{Port: intstr.FromInt32(8080)}},
					},
				}},
				EphemeralContainers: []v1.EphemeralContainer{{
					EphemeralContainerCommon: v1.EphemeralContainerCommon{
						Name:  "debugger",
						Image: "busybox:latest",
						Ports: []v1.ContainerPort{{ContainerPort: 9999}},
					},
				}},
			},
			Status: v1.PodStatus{
				PodIP:              "10.244.0.5",
				AllocatedResources: v1.ResourceList{v1.ResourceCPU: resource.MustParse("250u")},
				ContainerStatuses: []v1.ContainerStatus{{
					Name:               "app",
					AllocatedResources: v1.ResourceList{v1.ResourceCPU: resource.MustParse("100n")},
				}},
			},
		}
		assertWireDefaultingMatchesGenerated(t, nestedPod)

		// Verify V1PodList scheme defaulting parity as well.
		lazyScheme, _ := newLazyScheme(t)
		rawItemBytes, err := nestedPod.Marshal()
		if err != nil {
			t.Fatalf("failed to marshal nestedPod: %v", err)
		}
		lazyList := &lazypod.V1PodList{
			Items: []lazypod.V1Pod{*lazypod.NewV1PodFromWire(rawItemBytes)},
		}
		lazyScheme.Default(lazyList)
		decListObj, err := lazyList.EnsureDecodedObject()
		if err != nil {
			t.Fatalf("EnsureDecodedObject(V1PodList) failed: %v", err)
		}
		stdList := &v1.PodList{Items: []v1.Pod{*nestedPod.DeepCopy()}}
		corev1.SetObjectDefaults_PodList(stdList)
		if !apiequality.Semantic.DeepEqual(stdList, decListObj) {
			t.Fatalf("V1PodList defaulting mismatch:\n%s", cmp.Diff(stdList, decListObj))
		}
	})

	t.Run("ZeroAllocOnAlreadyDefaultedRealisticPod", func(t *testing.T) {
		expSec := int64(3600)
		svcEmpty := ""
		optFalse := false
		pod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "prod-pod", Namespace: "default"},
			Spec: v1.PodSpec{
				Volumes: []v1.Volume{{
					Name: "kube-api-access",
					VolumeSource: v1.VolumeSource{Projected: &v1.ProjectedVolumeSource{
						Sources: []v1.VolumeProjection{
							{ServiceAccountToken: &v1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: &expSec}},
							{ConfigMap: &v1.ConfigMapProjection{LocalObjectReference: v1.LocalObjectReference{Name: "kube-root-ca.crt"}}},
							{DownwardAPI: &v1.DownwardAPIProjection{Items: []v1.DownwardAPIVolumeFile{
								{Path: "namespace", FieldRef: &v1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.namespace"}},
							}}},
						},
					}},
				}},
				Containers: []v1.Container{{
					Name:  "web",
					Image: "registry.k8s.io/web:v1.0.0",
					Ports: []v1.ContainerPort{{ContainerPort: 8080, Protocol: v1.ProtocolTCP}},
					Env: []v1.EnvVar{
						{Name: "POD_IP", ValueFrom: &v1.EnvVarSource{FieldRef: &v1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "status.podIP"}}},
						{Name: "F", ValueFrom: &v1.EnvVarSource{FileKeyRef: &v1.FileKeySelector{VolumeName: "v", Path: "p", Key: "k", Optional: &optFalse}}},
					},
					Resources: v1.ResourceRequirements{
						Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m"), v1.ResourceMemory: resource.MustParse("256Mi")},
						Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("250m"), v1.ResourceMemory: resource.MustParse("256Mi")},
					},
					LivenessProbe: &v1.Probe{
						ProbeHandler: v1.ProbeHandler{HTTPGet: &v1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(8080), Scheme: v1.URISchemeHTTP}},
					},
					ReadinessProbe: &v1.Probe{
						ProbeHandler: v1.ProbeHandler{GRPC: &v1.GRPCAction{Port: 9090, Service: &svcEmpty}},
					},
				}},
			},
			Status: v1.PodStatus{
				Phase:  v1.PodRunning,
				PodIP:  "10.244.1.9",
				PodIPs: []v1.PodIP{{IP: "10.244.1.9"}},
				ContainerStatuses: []v1.ContainerStatus{{
					Name:               "web",
					Ready:              true,
					AllocatedResources: v1.ResourceList{v1.ResourceCPU: resource.MustParse("250m")},
				}},
			},
		}
		corev1.SetObjectDefaults_Pod(pod)
		rawBytes, err := pod.Marshal()
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}
		w := lazypod.NewWirePod(rawBytes)
		allocs := testing.AllocsPerRun(100, func() {
			w.DefaultOnWire()
		})
		if allocs != 0 {
			t.Fatalf("expected 0 allocs/op on already-defaulted realistic Pod, got %v", allocs)
		}
	})
}

func makeLarge45KBPod() *v1.Pod {
	bigData := string(bytes.Repeat([]byte("x"), 7*1024))
	expSec := int64(3600)
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pod-45kb",
			Namespace:       "default",
			UID:             types.UID("22222222-2222-2222-2222-222222222222"),
			ResourceVersion: "100",
			Generation:      1,
			CreationTimestamp: metav1.Time{
				Time: time.Unix(1700000000, 0).UTC(),
			},
			Labels:      map[string]string{"app": "web"},
			Annotations: map[string]string{"note": "v1"},
		},
		Spec: v1.PodSpec{
			ServiceAccountName: "default",
			OS:                 &v1.PodOS{Name: v1.Linux},
			Volumes: []v1.Volume{
				{Name: "vol-1", VolumeSource: v1.VolumeSource{ConfigMap: &v1.ConfigMapVolumeSource{LocalObjectReference: v1.LocalObjectReference{Name: bigData}}}},
				{Name: "vol-2", VolumeSource: v1.VolumeSource{ConfigMap: &v1.ConfigMapVolumeSource{LocalObjectReference: v1.LocalObjectReference{Name: bigData}}}},
				{Name: "vol-3", VolumeSource: v1.VolumeSource{ConfigMap: &v1.ConfigMapVolumeSource{LocalObjectReference: v1.LocalObjectReference{Name: bigData}}}},
				{Name: "vol-4", VolumeSource: v1.VolumeSource{ConfigMap: &v1.ConfigMapVolumeSource{LocalObjectReference: v1.LocalObjectReference{Name: bigData}}}},
				{Name: "vol-5", VolumeSource: v1.VolumeSource{Projected: &v1.ProjectedVolumeSource{
					Sources: []v1.VolumeProjection{{ServiceAccountToken: &v1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: &expSec}}},
				}}},
			},
			Containers: []v1.Container{{
				Name:  "app",
				Image: "registry.k8s.io/nginx:1.27",
				Resources: v1.ResourceRequirements{
					Requests: v1.ResourceList{
						v1.ResourceCPU:    resource.MustParse("250m"),
						v1.ResourceMemory: resource.MustParse("256Mi"),
					},
					Limits: v1.ResourceList{
						v1.ResourceCPU:    resource.MustParse("500m"),
						v1.ResourceMemory: resource.MustParse("512Mi"),
					},
				},
			}},
		},
		Status: v1.PodStatus{
			Phase:    v1.PodRunning,
			QOSClass: v1.PodQOSBurstable,
			PodIP:    "10.244.0.10",
			PodIPs:   []v1.PodIP{{IP: "10.244.0.10"}},
			ContainerStatuses: []v1.ContainerStatus{{
				Name:  "app",
				Ready: true,
			}},
		},
	}
	corev1.SetObjectDefaults_Pod(pod)
	return pod
}

func TestSplitWireMetaCacheAndLazySubtreeStrategies(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.LazyPodEncoding, true)
	ctx := context.Background()
	v1Pod := makeLarge45KBPod()
	rawBytes, err := v1Pod.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	t.Run("MetaCachePreservedAcrossNoOpNamespaceNameAndGenerationBump", func(t *testing.T) {
		p := lazypod.NewPodFromWire(rawBytes)
		var meta metav1.ObjectMeta
		p.BorrowObjectMetaInto(&meta, true)
		if _, ok := p.Wire().CachedObjectMeta(); !ok {
			t.Fatalf("expected CachedObjectMeta to be populated")
		}
		p.SetNamespace("default")
		p.SetName("pod-45kb")
		p.SetGeneration(2)
		cm, ok := p.Wire().CachedObjectMeta()
		if !ok {
			t.Fatalf("expected CachedObjectMeta to stay populated after no-op SetNamespace/SetName and SetGeneration")
		}
		if cm.Generation != 2 || p.GetGeneration() != 2 {
			t.Fatalf("expected cached Generation=2, got cm=%d get=%d", cm.Generation, p.GetGeneration())
		}

		dst := &lazypod.Pod{}
		copied, err := p.LazyCopyIntoStorageDestination(dst)
		if err != nil || !copied || !dst.IsLazy() {
			t.Fatalf("LazyCopyIntoStorageDestination failed: copied=%v err=%v lazy=%v", copied, err, dst.IsLazy())
		}
		if dst.GetGeneration() != 2 || dst.GetNamespace() != "default" {
			t.Fatalf("unexpected copied pod metadata: gen=%d ns=%q", dst.GetGeneration(), dst.GetNamespace())
		}
	})

	t.Run("ContainerImageUpdateStaysLazyAndRejectsInvalidContainerEdit", func(t *testing.T) {
		oldLazy := lazypod.NewPodFromWire(rawBytes)
		oldV1 := lazypod.NewV1PodFromWire(rawBytes)
		mask, ok := oldV1.SpecTagMaskForField("containers")
		if !ok {
			t.Fatalf("expected containers SpecTagMaskForField to succeed")
		}
		baseObj, err := oldV1.ExtractSubtreePatchBase(false, mask, 0, true)
		if err != nil {
			t.Fatalf("ExtractSubtreePatchBase failed: %v", err)
		}
		basePod := baseObj.(*v1.Pod)
		basePod.Spec.Containers[0].Image = "registry.k8s.io/nginx:1.28"
		corev1.SetObjectDefaults_Pod(basePod)
		splicedObj, err := oldV1.SpliceSubtreePatchResult(basePod, false, mask, 0)
		if err != nil {
			t.Fatalf("SpliceSubtreePatchResult failed: %v", err)
		}
		splicedV1 := splicedObj.(*lazypod.V1Pod)

		// Verify split WirePod MarshalToSizedBuffer matches decoded v1.Pod Marshal byte-for-byte.
		gotBytes := make([]byte, splicedV1.Size())
		if _, err := splicedV1.MarshalToSizedBuffer(gotBytes); err != nil {
			t.Fatalf("split MarshalToSizedBuffer failed: %v", err)
		}
		var roundTrip v1.Pod
		if err := roundTrip.Unmarshal(gotBytes); err != nil {
			t.Fatalf("Unmarshal split wire bytes failed: %v", err)
		}
		if roundTrip.Spec.Containers[0].Image != "registry.k8s.io/nginx:1.28" || len(roundTrip.Spec.Volumes) != 5 {
			t.Fatalf("unexpected roundTrip pod: image=%q vols=%d", roundTrip.Spec.Containers[0].Image, len(roundTrip.Spec.Volumes))
		}

		var newLazy lazypod.Pod
		if err := lazypod.Convert_v1_Pod_To_core_Pod(splicedV1, &newLazy, nil); err != nil {
			t.Fatalf("Convert failed: %v", err)
		}
		registrypod.Strategy.PrepareForUpdate(ctx, &newLazy, oldLazy)
		if !newLazy.IsLazy() {
			t.Fatalf("expected newLazy to remain lazy after container image PrepareForUpdate")
		}
		if newLazy.GetGeneration() != 2 {
			t.Fatalf("expected generation=2, got %d", newLazy.GetGeneration())
		}
		if errs := registrypod.Strategy.ValidateUpdate(ctx, &newLazy, oldLazy); len(errs) > 0 {
			t.Fatalf("expected valid container image update, got %v", errs)
		}
		if !newLazy.IsLazy() || !oldLazy.IsLazy() {
			t.Fatalf("expected both pods to remain lazy after ValidateUpdate")
		}

		// Forbidden mutation of container command on main Pod resource must fail validation.
		badBase := basePod.DeepCopy()
		badBase.Spec.Containers[0].Command = []string{"/bin/sh"}
		badSpliced, err := oldV1.SpliceSubtreePatchResult(badBase, false, mask, 0)
		if err != nil {
			t.Fatalf("SpliceSubtreePatchResult failed: %v", err)
		}
		var badLazy lazypod.Pod
		_ = lazypod.Convert_v1_Pod_To_core_Pod(badSpliced.(*lazypod.V1Pod), &badLazy, nil)
		registrypod.Strategy.PrepareForUpdate(ctx, &badLazy, oldLazy.DeepCopy())
		if errs := registrypod.Strategy.ValidateUpdate(ctx, &badLazy, oldLazy.DeepCopy()); len(errs) == 0 {
			t.Fatalf("expected forbidden error when mutating container command on main Pod update")
		}
	})

	t.Run("ResizeSubresourceStaysLazyAndEnforcesInvariants", func(t *testing.T) {
		oldLazy := lazypod.NewPodFromWire(rawBytes)
		oldV1 := lazypod.NewV1PodFromWire(rawBytes)
		mask, _ := oldV1.SpecTagMaskForField("containers")
		baseObj, err := oldV1.ExtractSubtreePatchBase(false, mask, 0, true)
		if err != nil {
			t.Fatalf("ExtractSubtreePatchBase failed: %v", err)
		}
		basePod := baseObj.(*v1.Pod)
		basePod.Spec.Containers[0].Resources.Requests[v1.ResourceCPU] = resource.MustParse("300m")
		basePod.Spec.Containers[0].Resources.Limits[v1.ResourceCPU] = resource.MustParse("600m")
		// Attempt an ignored container image edit on /resize: ResizeStrategy must drop it.
		basePod.Spec.Containers[0].Image = "registry.k8s.io/ignored:9.9"
		corev1.SetObjectDefaults_Pod(basePod)
		splicedObj, err := oldV1.SpliceSubtreePatchResult(basePod, false, mask, 0)
		if err != nil {
			t.Fatalf("SpliceSubtreePatchResult failed: %v", err)
		}
		var newLazy lazypod.Pod
		_ = lazypod.Convert_v1_Pod_To_core_Pod(splicedObj.(*lazypod.V1Pod), &newLazy, nil)

		registrypod.ResizeStrategy.PrepareForUpdate(ctx, &newLazy, oldLazy)
		if !newLazy.IsLazy() {
			t.Fatalf("expected newLazy to remain lazy after ResizeStrategy.PrepareForUpdate")
		}
		if errs := registrypod.ResizeStrategy.ValidateUpdate(ctx, &newLazy, oldLazy); len(errs) > 0 {
			t.Fatalf("expected valid resize update, got %v", errs)
		}
		if !newLazy.IsLazy() || !oldLazy.IsLazy() {
			t.Fatalf("expected both pods to remain lazy after ResizeStrategy.ValidateUpdate")
		}
		dec, err := newLazy.DeepCopy().EnsureDecoded()
		if err != nil {
			t.Fatalf("EnsureDecoded failed: %v", err)
		}
		if dec.Spec.Containers[0].Image != "registry.k8s.io/nginx:1.27" {
			t.Fatalf("expected ResizeStrategy to drop image change, got %q", dec.Spec.Containers[0].Image)
		}
		if !dec.Spec.Containers[0].Resources.Requests[core.ResourceCPU].Equal(resource.MustParse("300m")) {
			t.Fatalf("expected resized CPU request=300m, got %v", dec.Spec.Containers[0].Resources.Requests[core.ResourceCPU])
		}

		// Invalid resize changing QoS class from Burstable to Guaranteed must fail.
		badQoS := basePod.DeepCopy()
		badQoS.Spec.Containers[0].Resources.Requests[v1.ResourceCPU] = resource.MustParse("600m")
		badQoS.Spec.Containers[0].Resources.Limits[v1.ResourceCPU] = resource.MustParse("600m")
		badQoS.Spec.Containers[0].Resources.Requests[v1.ResourceMemory] = resource.MustParse("512Mi")
		badQoS.Spec.Containers[0].Resources.Limits[v1.ResourceMemory] = resource.MustParse("512Mi")
		badSpliced, _ := oldV1.SpliceSubtreePatchResult(badQoS, false, mask, 0)
		var badLazy lazypod.Pod
		_ = lazypod.Convert_v1_Pod_To_core_Pod(badSpliced.(*lazypod.V1Pod), &badLazy, nil)
		registrypod.ResizeStrategy.PrepareForUpdate(ctx, &badLazy, oldLazy.DeepCopy())
		if errs := registrypod.ResizeStrategy.ValidateUpdate(ctx, &badLazy, oldLazy.DeepCopy()); len(errs) == 0 {
			t.Fatalf("expected error when resize changes Pod QoS class")
		}
	})

	t.Run("EphemeralContainersSubresourceStaysLazy", func(t *testing.T) {
		oldLazy := lazypod.NewPodFromWire(rawBytes)
		oldV1 := lazypod.NewV1PodFromWire(rawBytes)
		mask, _ := oldV1.SpecTagMaskForField("ephemeralContainers")
		baseObj, err := oldV1.ExtractSubtreePatchBase(false, mask, 0, true)
		if err != nil {
			t.Fatalf("ExtractSubtreePatchBase failed: %v", err)
		}
		basePod := baseObj.(*v1.Pod)
		basePod.Spec.EphemeralContainers = []v1.EphemeralContainer{{
			EphemeralContainerCommon: v1.EphemeralContainerCommon{
				Name:  "debug-1",
				Image: "registry.k8s.io/busybox:1.36",
			},
		}}
		corev1.SetObjectDefaults_Pod(basePod)
		splicedObj, err := oldV1.SpliceSubtreePatchResult(basePod, false, mask, 0)
		if err != nil {
			t.Fatalf("SpliceSubtreePatchResult failed: %v", err)
		}
		var newLazy lazypod.Pod
		_ = lazypod.Convert_v1_Pod_To_core_Pod(splicedObj.(*lazypod.V1Pod), &newLazy, nil)

		registrypod.EphemeralContainersStrategy.PrepareForUpdate(ctx, &newLazy, oldLazy)
		if !newLazy.IsLazy() {
			t.Fatalf("expected newLazy to remain lazy after EphemeralContainersStrategy.PrepareForUpdate")
		}
		if errs := registrypod.EphemeralContainersStrategy.ValidateUpdate(ctx, &newLazy, oldLazy); len(errs) > 0 {
			t.Fatalf("expected valid ephemeralContainers update, got %v", errs)
		}
		if !newLazy.IsLazy() || !oldLazy.IsLazy() {
			t.Fatalf("expected both pods to remain lazy after EphemeralContainersStrategy.ValidateUpdate")
		}
	})

	t.Run("OwnedStorageEnvelopeAndSharedMetaCache", func(t *testing.T) {
		_, lazyCodecs := newLazyScheme(t)
		pbCodec := runtime.NewCodec(protobufCodecFor(t, lazyCodecs), protobufCodecFor(t, lazyCodecs))

		srcPod := lazypod.NewPodFromWire(rawBytes)
		srcPod.SetResourceVersion("")
		encodedEnvelope, err := runtime.Encode(pbCodec, srcPod)
		if err != nil {
			t.Fatalf("runtime.Encode failed: %v", err)
		}

		into := &lazypod.Pod{}
		decodedObj, err := runtime.DecodeOwnedStorage(pbCodec, encodedEnvelope, into)
		if err != nil {
			t.Fatalf("DecodeOwnedStorage failed: %v", err)
		}
		cachedPod := decodedObj.(*lazypod.Pod)
		cachedPod.SetResourceVersion("100")

		clone1 := cachedPod.DeepCopyObject().(*lazypod.Pod)
		if gotRaw, ok := clone1.RawStorageBytes(); !ok || !bytes.Equal(gotRaw, encodedEnvelope) {
			t.Fatalf("expected RawStorageBytes to match encodedEnvelope (ok=%v)", ok)
		}

		versioner := storage.APIObjectVersioner{}
		state, err := storage.GetStateFromObject(versioner, pbCodec, clone1, false)
		if err != nil {
			t.Fatalf("GetStateFromObject failed: %v", err)
		}
		if state.Rev != 100 || !bytes.Equal(state.Data, encodedEnvelope) {
			t.Fatalf("unexpected ObjState: rev=%d dataEqual=%v", state.Rev, bytes.Equal(state.Data, encodedEnvelope))
		}

		var meta1 metav1.ObjectMeta
		clone1.BorrowObjectMetaInto(&meta1, true)
		if meta1.ResourceVersion != "100" || meta1.Name != "pod-45kb" {
			t.Fatalf("unexpected borrowed meta1: rv=%q name=%q", meta1.ResourceVersion, meta1.Name)
		}

		// A fresh clone from the watchCache object must reuse sharedMeta with zero unmarshal allocs.
		clone2 := cachedPod.DeepCopyObject().(*lazypod.Pod)
		var meta2 metav1.ObjectMeta
		allocs := testing.AllocsPerRun(50, func() {
			clone2.BorrowObjectMetaInto(&meta2, true)
		})
		if allocs != 0 {
			t.Fatalf("expected 0 allocs borrowing sharedMeta on second clone, got %v", allocs)
		}

		// No-op SetCreationTimestamp preserves RawStorageBytes; mutating SetUID invalidates RawStorageBytes
		// while keeping cachedMeta populated and EqualModuloManagedFields allocation-free against its clone.
		clone2.SetCreationTimestamp(clone2.GetCreationTimestamp())
		if _, ok := clone2.RawStorageBytes(); !ok {
			t.Fatalf("expected no-op SetCreationTimestamp to preserve RawStorageBytes")
		}
		clone2.SetUID("new-uid-999")
		if _, ok := clone2.RawStorageBytes(); ok {
			t.Fatalf("expected mutating SetUID to invalidate RawStorageBytes")
		}
		if clone2.GetUID() != "new-uid-999" {
			t.Fatalf("expected GetUID=new-uid-999, got %q", clone2.GetUID())
		}
		beforeAdmit := clone2.DeepCopyObject()
		eqAllocs := testing.AllocsPerRun(50, func() {
			eq, ok := clone2.EqualModuloManagedFields(beforeAdmit)
			if !ok || !eq {
				t.Fatalf("expected EqualModuloManagedFields=(true,true), got (%v,%v)", eq, ok)
			}
		})
		if eqAllocs != 0 {
			t.Fatalf("expected 0 allocs in EqualModuloManagedFields against unmodified clone, got %v", eqAllocs)
		}

		t.Log("Concurrent DeepCopyObject + BorrowObjectMetaInto + GetLabels across goroutines must be race-free")
		warmedPod := cachedPod.DeepCopyObject().(*lazypod.Pod)
		warmedPod.SetAnnotations(map[string]string{"owned": "true"})
		var concurrencyGroup sync.WaitGroup
		for range 8 {
			concurrencyGroup.Add(1)
			go func() {
				defer concurrencyGroup.Done()
				for range 50 {
					c1 := cachedPod.DeepCopyObject().(*lazypod.Pod)
					var m metav1.ObjectMeta
					c1.BorrowObjectMetaInto(&m, true)
					c2 := warmedPod.DeepCopyObject().(*lazypod.Pod)
					_ = c2.GetAnnotations()
					_ = warmedPod.GetAnnotations()
				}
			}()
		}
		concurrencyGroup.Wait()

		t.Log("PUT setter ordering (SetUID before GetLabels/GetAnnotations) warms cachedMeta once without re-splicing")
		putPayload := lazypod.NewPodFromWire(rawBytes)
		putPayload.SetUID("put-assigned-uid")
		putPayload.SetResourceVersion(cachedPod.GetResourceVersion())
		legacyAllocs := testing.AllocsPerRun(50, func() {
			if putPayload.Wire().HasLegacyInitContainerAnnotations() {
				t.Fatal("unexpected legacy init container annotation")
			}
		})
		if legacyAllocs != 0 {
			t.Fatalf("expected 0 allocs in HasLegacyInitContainerAnnotations after SetUID, got %v", legacyAllocs)
		}
		_ = putPayload.GetLabels()
		matchingPeer := cachedPod.DeepCopyObject().(*lazypod.Pod)
		matchingPeer.SetUID("put-assigned-uid")
		_ = matchingPeer.GetAnnotations()
		var borrowed metav1.ObjectMeta
		postWarmAllocs := testing.AllocsPerRun(50, func() {
			_ = putPayload.GetAnnotations()
			putPayload.BorrowObjectMetaInto(&borrowed, true)
			if eq, ok := putPayload.EqualModuloManagedFields(cachedPod); !ok || eq {
				t.Fatalf("expected EqualModuloManagedFields=(false,true) against mismatched UID cachedPod, got (%v,%v)", eq, ok)
			}
			if eq, ok := putPayload.EqualModuloManagedFields(matchingPeer); !ok || !eq {
				t.Fatalf("expected EqualModuloManagedFields=(true,true) against matchingPeer, got (%v,%v)", eq, ok)
			}
		})
		if postWarmAllocs != 0 {
			t.Fatalf("expected 0 allocs after GetLabels warmed cachedMeta on PUT payload, got %v", postWarmAllocs)
		}
	})
}

func BenchmarkLazyPodSubtreeMutations45KB(b *testing.B) {
	ctx := context.Background()
	v1Pod := makeLarge45KBPod()
	rawBytes, err := v1Pod.Marshal()
	if err != nil {
		b.Fatalf("Marshal failed: %v", err)
	}
	imgPatchJSON := []byte(`{"spec":{"containers":[{"name":"app","image":"registry.k8s.io/nginx:1.28"}]}}`)
	resizePatchJSON := []byte(`{"spec":{"containers":[{"name":"app","resources":{"requests":{"cpu":"300m"},"limits":{"cpu":"600m"}}}]}}`)
	ephPatchJSON := []byte(`{"spec":{"ephemeralContainers":[{"name":"dbg","image":"registry.k8s.io/busybox:1.36"}]}}`)
	schemaRef := &v1.Pod{}

	// Warm up DefaultUnstructuredConverter reflection cache before timed loops.
	_, _ = runtime.DefaultUnstructuredConverter.ToUnstructured(v1Pod)

	b.Run("ContainerImageSMP/Decoded", func(b *testing.B) {
		b.ReportAllocs()
		outBuf := make([]byte, len(rawBytes)+512)
		for b.Loop() {
			var oldV1 v1.Pod
			_ = oldV1.Unmarshal(rawBytes)
			var patchMap map[string]any
			_ = json.Unmarshal(imgPatchJSON, &patchMap)
			origMap, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(&oldV1)
			patchedMap, err := strategicpatch.StrategicMergeMapPatch(origMap, patchMap, schemaRef)
			if err != nil {
				b.Fatal(err)
			}
			var updV1 v1.Pod
			_ = runtime.DefaultUnstructuredConverter.FromUnstructured(patchedMap, &updV1)
			corev1.SetObjectDefaults_Pod(&updV1)
			var oldCore, newCore core.Pod
			_ = corev1.Convert_v1_Pod_To_core_Pod(&oldV1, &oldCore, nil)
			_ = corev1.Convert_v1_Pod_To_core_Pod(&updV1, &newCore, nil)
			registrypod.Strategy.PrepareForUpdate(ctx, &newCore, &oldCore)
			if errs := registrypod.Strategy.ValidateUpdate(ctx, &newCore, &oldCore); len(errs) > 0 {
				b.Fatal(errs)
			}
			var outV1 v1.Pod
			_ = corev1.Convert_core_Pod_To_v1_Pod(&newCore, &outV1, nil)
			_, _ = outV1.MarshalToSizedBuffer(outBuf[:outV1.Size()])
		}
	})

	b.Run("ContainerImageSMP/Lazy", func(b *testing.B) {
		b.ReportAllocs()
		outBuf := make([]byte, len(rawBytes)+512)
		mask, _ := lazypod.SpecTagMaskForField("containers")
		for b.Loop() {
			oldV1 := lazypod.NewV1PodFromWire(rawBytes)
			var patchMap map[string]any
			_ = json.Unmarshal(imgPatchJSON, &patchMap)
			baseObj, _ := oldV1.ExtractSubtreePatchBase(false, mask, 0, true)
			origMap, _ := runtime.DefaultUnstructuredConverter.ToUnstructuredTopLevel(baseObj, patchMap)
			patchedMap, err := strategicpatch.StrategicMergeMapPatch(origMap, patchMap, schemaRef)
			if err != nil {
				b.Fatal(err)
			}
			updV1 := baseObj.(*v1.Pod)
			_ = runtime.DefaultUnstructuredConverter.FromUnstructured(patchedMap, updV1)
			corev1.SetObjectDefaults_Pod(updV1)
			splicedObj, _ := oldV1.SpliceSubtreePatchResult(updV1, false, mask, 0)
			_, _, _, _ = oldV1.ProjectForUpdate(splicedObj, false, true)
			var oldCore, newCore lazypod.Pod
			_ = lazypod.Convert_v1_Pod_To_core_Pod(oldV1, &oldCore, nil)
			_ = lazypod.Convert_v1_Pod_To_core_Pod(splicedObj.(*lazypod.V1Pod), &newCore, nil)
			registrypod.Strategy.PrepareForUpdate(ctx, &newCore, &oldCore)
			if errs := registrypod.Strategy.ValidateUpdate(ctx, &newCore, &oldCore); len(errs) > 0 {
				b.Fatal(errs)
			}
			var outV1 lazypod.V1Pod
			_ = lazypod.Convert_core_Pod_To_v1_Pod(&newCore, &outV1, nil)
			_, _ = outV1.MarshalToSizedBuffer(outBuf[:outV1.Size()])
		}
	})

	b.Run("PodResizeSMP/Decoded", func(b *testing.B) {
		b.ReportAllocs()
		outBuf := make([]byte, len(rawBytes)+512)
		for b.Loop() {
			var oldV1 v1.Pod
			_ = oldV1.Unmarshal(rawBytes)
			var patchMap map[string]any
			_ = json.Unmarshal(resizePatchJSON, &patchMap)
			origMap, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(&oldV1)
			patchedMap, err := strategicpatch.StrategicMergeMapPatch(origMap, patchMap, schemaRef)
			if err != nil {
				b.Fatal(err)
			}
			var updV1 v1.Pod
			_ = runtime.DefaultUnstructuredConverter.FromUnstructured(patchedMap, &updV1)
			corev1.SetObjectDefaults_Pod(&updV1)
			var oldCore, newCore core.Pod
			_ = corev1.Convert_v1_Pod_To_core_Pod(&oldV1, &oldCore, nil)
			_ = corev1.Convert_v1_Pod_To_core_Pod(&updV1, &newCore, nil)
			registrypod.ResizeStrategy.PrepareForUpdate(ctx, &newCore, &oldCore)
			if errs := registrypod.ResizeStrategy.ValidateUpdate(ctx, &newCore, &oldCore); len(errs) > 0 {
				b.Fatal(errs)
			}
			var outV1 v1.Pod
			_ = corev1.Convert_core_Pod_To_v1_Pod(&newCore, &outV1, nil)
			_, _ = outV1.MarshalToSizedBuffer(outBuf[:outV1.Size()])
		}
	})

	b.Run("PodResizeSMP/Lazy", func(b *testing.B) {
		b.ReportAllocs()
		outBuf := make([]byte, len(rawBytes)+512)
		mask, _ := lazypod.SpecTagMaskForField("containers")
		for b.Loop() {
			oldV1 := lazypod.NewV1PodFromWire(rawBytes)
			var patchMap map[string]any
			_ = json.Unmarshal(resizePatchJSON, &patchMap)
			baseObj, _ := oldV1.ExtractSubtreePatchBase(false, mask, 0, true)
			origMap, _ := runtime.DefaultUnstructuredConverter.ToUnstructuredTopLevel(baseObj, patchMap)
			patchedMap, err := strategicpatch.StrategicMergeMapPatch(origMap, patchMap, schemaRef)
			if err != nil {
				b.Fatal(err)
			}
			updV1 := baseObj.(*v1.Pod)
			_ = runtime.DefaultUnstructuredConverter.FromUnstructured(patchedMap, updV1)
			corev1.SetObjectDefaults_Pod(updV1)
			splicedObj, _ := oldV1.SpliceSubtreePatchResult(updV1, false, mask, 0)
			_, _, _, _ = oldV1.ProjectForUpdate(splicedObj, false, false)
			var oldCore, newCore lazypod.Pod
			_ = lazypod.Convert_v1_Pod_To_core_Pod(oldV1, &oldCore, nil)
			_ = lazypod.Convert_v1_Pod_To_core_Pod(splicedObj.(*lazypod.V1Pod), &newCore, nil)
			registrypod.ResizeStrategy.PrepareForUpdate(ctx, &newCore, &oldCore)
			if errs := registrypod.ResizeStrategy.ValidateUpdate(ctx, &newCore, &oldCore); len(errs) > 0 {
				b.Fatal(errs)
			}
			var outV1 lazypod.V1Pod
			_ = lazypod.Convert_core_Pod_To_v1_Pod(&newCore, &outV1, nil)
			_, _ = outV1.MarshalToSizedBuffer(outBuf[:outV1.Size()])
		}
	})

	b.Run("EphemeralContainersSMP/Decoded", func(b *testing.B) {
		b.ReportAllocs()
		outBuf := make([]byte, len(rawBytes)+512)
		for b.Loop() {
			var oldV1 v1.Pod
			_ = oldV1.Unmarshal(rawBytes)
			var patchMap map[string]any
			_ = json.Unmarshal(ephPatchJSON, &patchMap)
			origMap, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(&oldV1)
			patchedMap, err := strategicpatch.StrategicMergeMapPatch(origMap, patchMap, schemaRef)
			if err != nil {
				b.Fatal(err)
			}
			var updV1 v1.Pod
			_ = runtime.DefaultUnstructuredConverter.FromUnstructured(patchedMap, &updV1)
			corev1.SetObjectDefaults_Pod(&updV1)
			var oldCore, newCore core.Pod
			_ = corev1.Convert_v1_Pod_To_core_Pod(&oldV1, &oldCore, nil)
			_ = corev1.Convert_v1_Pod_To_core_Pod(&updV1, &newCore, nil)
			registrypod.EphemeralContainersStrategy.PrepareForUpdate(ctx, &newCore, &oldCore)
			if errs := registrypod.EphemeralContainersStrategy.ValidateUpdate(ctx, &newCore, &oldCore); len(errs) > 0 {
				b.Fatal(errs)
			}
			var outV1 v1.Pod
			_ = corev1.Convert_core_Pod_To_v1_Pod(&newCore, &outV1, nil)
			_, _ = outV1.MarshalToSizedBuffer(outBuf[:outV1.Size()])
		}
	})

	b.Run("EphemeralContainersSMP/Lazy", func(b *testing.B) {
		b.ReportAllocs()
		outBuf := make([]byte, len(rawBytes)+512)
		mask, _ := lazypod.SpecTagMaskForField("ephemeralContainers")
		for b.Loop() {
			oldV1 := lazypod.NewV1PodFromWire(rawBytes)
			var patchMap map[string]any
			_ = json.Unmarshal(ephPatchJSON, &patchMap)
			baseObj, _ := oldV1.ExtractSubtreePatchBase(false, mask, 0, true)
			origMap, _ := runtime.DefaultUnstructuredConverter.ToUnstructuredTopLevel(baseObj, patchMap)
			patchedMap, err := strategicpatch.StrategicMergeMapPatch(origMap, patchMap, schemaRef)
			if err != nil {
				b.Fatal(err)
			}
			updV1 := baseObj.(*v1.Pod)
			_ = runtime.DefaultUnstructuredConverter.FromUnstructured(patchedMap, updV1)
			corev1.SetObjectDefaults_Pod(updV1)
			splicedObj, _ := oldV1.SpliceSubtreePatchResult(updV1, false, mask, 0)
			_, _, _, _ = oldV1.ProjectForUpdate(splicedObj, false, false)
			var oldCore, newCore lazypod.Pod
			_ = lazypod.Convert_v1_Pod_To_core_Pod(oldV1, &oldCore, nil)
			_ = lazypod.Convert_v1_Pod_To_core_Pod(splicedObj.(*lazypod.V1Pod), &newCore, nil)
			registrypod.EphemeralContainersStrategy.PrepareForUpdate(ctx, &newCore, &oldCore)
			if errs := registrypod.EphemeralContainersStrategy.ValidateUpdate(ctx, &newCore, &oldCore); len(errs) > 0 {
				b.Fatal(errs)
			}
			var outV1 lazypod.V1Pod
			_ = lazypod.Convert_core_Pod_To_v1_Pod(&newCore, &outV1, nil)
			_, _ = outV1.MarshalToSizedBuffer(outBuf[:outV1.Size()])
		}
	})
}

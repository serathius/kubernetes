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
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

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
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/etcd3"
	"k8s.io/kubernetes/pkg/apis/core"
	_ "k8s.io/kubernetes/pkg/apis/core/install"
	"k8s.io/kubernetes/pkg/apis/core/lazypod"
	corev1 "k8s.io/kubernetes/pkg/apis/core/v1"
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

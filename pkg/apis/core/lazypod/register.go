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

package lazypod

import (
	"bytes"
	"context"
	"fmt"
	"unsafe"

	v1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/operation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/apis/core"
	corev1 "k8s.io/kubernetes/pkg/apis/core/v1"
)

func init() {
	utilruntime.Must(apiequality.Semantic.AddFuncs(
		func(a, b Pod) bool {
			if a.TypeMeta != b.TypeMeta {
				return false
			}
			if a.wire != nil && a.decoded == nil && b.wire != nil && b.decoded == nil {
				if bytes.Equal(a.wire.Bytes(), b.wire.Bytes()) {
					return true
				}
			}
			da, err := a.EnsureDecoded()
			if err != nil {
				return false
			}
			db, err := b.EnsureDecoded()
			if err != nil {
				return false
			}
			return apiequality.Semantic.DeepEqual(da, db)
		},
		func(a, b V1Pod) bool {
			if a.TypeMeta != b.TypeMeta {
				return false
			}
			if a.wire != nil && a.decoded == nil && b.wire != nil && b.decoded == nil {
				if bytes.Equal(a.wire.Bytes(), b.wire.Bytes()) {
					return true
				}
			}
			da, err := a.EnsureDecoded()
			if err != nil {
				return false
			}
			db, err := b.EnsureDecoded()
			if err != nil {
				return false
			}
			return apiequality.Semantic.DeepEqual(da, db)
		},
	))
}

func decodeV1PodNonMutating(p *V1Pod) (*v1.Pod, error) {
	if p == nil {
		return nil, nil
	}
	if p.decoded != nil {
		return p.decoded, nil
	}
	if p.wire == nil {
		return &v1.Pod{TypeMeta: p.TypeMeta}, nil
	}
	dec, err := p.wire.DecodeToV1Pod()
	if err != nil {
		return nil, err
	}
	dec.TypeMeta = p.TypeMeta
	return dec, nil
}

func validateV1PodDeclaratively(ctx context.Context, op operation.Operation, obj, oldObj interface{}) field.ErrorList {
	switch op.Request.SubresourcePath() {
	case "/", "/ephemeralcontainers", "/eviction", "/resize", "/status":
	default:
		return field.ErrorList{
			field.InternalError(nil, fmt.Errorf("no validation found for %T, subresource: %v", obj, op.Request.SubresourcePath())),
		}
	}

	newLazy, ok := obj.(*V1Pod)
	if !ok || newLazy == nil {
		return nil
	}
	var oldLazy *V1Pod
	if oldObj != nil {
		oldLazy, _ = oldObj.(*V1Pod)
	}

	if op.Type == operation.Update && oldLazy != nil && newLazy.IsLazy() && oldLazy.IsLazy() && newLazy.HasEqualSpecWireBytes(oldLazy) {
		projNew := &v1.Pod{TypeMeta: newLazy.TypeMeta}
		projOld := &v1.Pod{TypeMeta: oldLazy.TypeMeta}
		metaEqual := !newLazy.wire.meta.IsDirty() && !oldLazy.wire.meta.IsDirty() &&
			bytes.Equal(newLazy.wire.meta.Bytes(), oldLazy.wire.meta.Bytes())
		if !metaEqual {
			newLazy.ExtractObjectMetaInto(&projNew.ObjectMeta)
			oldLazy.ExtractObjectMetaInto(&projOld.ObjectMeta)
		}
		newStatusBytes := newLazy.wire.EffectiveSubMessage(podFieldStatus)
		oldStatusBytes := oldLazy.wire.EffectiveSubMessage(podFieldStatus)
		if !bytes.Equal(newStatusBytes, oldStatusBytes) {
			if err := newLazy.wire.ExtractV1StatusInto(&projNew.Status); err != nil {
				return field.ErrorList{field.InternalError(field.NewPath("status"), err)}
			}
			if err := oldLazy.wire.ExtractV1StatusInto(&projOld.Status); err != nil {
				return field.ErrorList{field.InternalError(field.NewPath("status"), err)}
			}
		}
		return corev1.Validate_Pod(ctx, op, nil, projNew, projOld)
	}

	decNew, err := decodeV1PodNonMutating(newLazy)
	if err != nil {
		return field.ErrorList{field.InternalError(nil, err)}
	}
	var decOld *v1.Pod
	if oldLazy != nil {
		decOld, err = decodeV1PodNonMutating(oldLazy)
		if err != nil {
			return field.ErrorList{field.InternalError(nil, err)}
		}
	} else if oldPod, ok := oldObj.(*v1.Pod); ok {
		decOld = oldPod
	}
	return corev1.Validate_Pod(ctx, op, nil, decNew, decOld)
}

// Install registers the lazy V1Pod (v1, Kind="Pod") and internal lazy Pod (__internal, Kind="Pod")
// along with wire-level defaulting and zero-copy V1Pod <-> Pod conversions into scheme.
func Install(scheme *runtime.Scheme) error {
	scheme.AddAlternativeTypeWithName(core.SchemeGroupVersion.WithKind("Pod"), &Pod{})
	scheme.AddAlternativeTypeWithName(core.SchemeGroupVersion.WithKind("PodList"), &PodList{})
	scheme.AddAlternativeTypeWithName(v1.SchemeGroupVersion.WithKind("Pod"), &V1Pod{})
	scheme.AddAlternativeTypeWithName(v1.SchemeGroupVersion.WithKind("PodList"), &V1PodList{})

	scheme.AddTypeDefaultingFunc(&V1Pod{}, func(obj interface{}) {
		SetObjectDefaults_V1Pod(obj.(*V1Pod))
	})
	scheme.AddValidationFunc((*V1Pod)(nil), validateV1PodDeclaratively)

	if err := scheme.AddGeneratedConversionFunc((*V1Pod)(nil), (*Pod)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1_Pod_To_core_Pod(a.(*V1Pod), b.(*Pod), scope)
	}); err != nil {
		return err
	}
	if err := scheme.AddGeneratedConversionFunc((*Pod)(nil), (*V1Pod)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_core_Pod_To_v1_Pod(a.(*Pod), b.(*V1Pod), scope)
	}); err != nil {
		return err
	}
	if err := scheme.AddGeneratedConversionFunc((*PodList)(nil), (*V1PodList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_core_PodList_To_v1_PodList(a.(*PodList), b.(*V1PodList), scope)
	}); err != nil {
		return err
	}
	if err := scheme.AddGeneratedConversionFunc((*V1PodList)(nil), (*PodList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1_PodList_To_core_PodList(a.(*V1PodList), b.(*PodList), scope)
	}); err != nil {
		return err
	}
	if err := scheme.AddGeneratedConversionFunc((*V1Pod)(nil), (*core.Pod)(nil), func(a, b interface{}, _ conversion.Scope) error {
		dec, err := a.(*V1Pod).EnsureDecoded()
		if err != nil {
			return err
		}
		out := b.(*core.Pod)
		tm := out.TypeMeta
		*out = *(*core.Pod)(unsafe.Pointer(dec))
		out.TypeMeta = tm
		return nil
	}); err != nil {
		return err
	}
	if err := scheme.AddGeneratedConversionFunc((*core.Pod)(nil), (*V1Pod)(nil), func(a, b interface{}, _ conversion.Scope) error {
		out := b.(*V1Pod)
		v1Copy := *(*v1.Pod)(unsafe.Pointer(a.(*core.Pod)))
		v1Copy.TypeMeta = out.TypeMeta
		out.wire = nil
		out.wireOwn = nil
		out.decoded = &v1Copy
		return nil
	}); err != nil {
		return err
	}
	if err := scheme.AddGeneratedConversionFunc((*Pod)(nil), (*v1.Pod)(nil), func(a, b interface{}, _ conversion.Scope) error {
		dec, err := a.(*Pod).EnsureDecoded()
		if err != nil {
			return err
		}
		out := b.(*v1.Pod)
		tm := out.TypeMeta
		*out = *(*v1.Pod)(unsafe.Pointer(dec))
		out.TypeMeta = tm
		return nil
	}); err != nil {
		return err
	}
	if err := scheme.AddGeneratedConversionFunc((*v1.Pod)(nil), (*Pod)(nil), func(a, b interface{}, _ conversion.Scope) error {
		out := b.(*Pod)
		podCopy := *(*core.Pod)(unsafe.Pointer(a.(*v1.Pod)))
		podCopy.TypeMeta = out.TypeMeta
		out.wire = nil
		out.wireOwn = nil
		out.decoded = &podCopy
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// NewScheme creates a new runtime.Scheme and serializer.CodecFactory with lazy Pod
// wire-level decoding, defaulting, conversion, and encoding enabled.
func NewScheme() (*runtime.Scheme, serializer.CodecFactory, error) {
	scheme := runtime.NewScheme()
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})
	if err := Install(scheme); err != nil {
		return nil, serializer.CodecFactory{}, err
	}
	return scheme, serializer.NewCodecFactory(scheme), nil
}

// SetObjectDefaults_V1Pod applies v1.Pod defaults directly on the Protobuf wire bytes
// when the pod is in lazy wire form, or falls back to struct defaulting if already decoded.
func SetObjectDefaults_V1Pod(in *V1Pod) {
	if in.wire != nil && in.decoded == nil {
		in.ensureWire().DefaultOnWire()
		return
	}
	if in.decoded != nil {
		corev1.SetObjectDefaults_Pod(in.decoded)
	}
}

// Convert_v1_Pod_To_core_Pod transfers the lazy WirePod buffer from V1Pod to internal Pod
// in O(1) without decoding when V1Pod is in lazy wire form, or uses zero-copy layout casting if decoded.
func Convert_v1_Pod_To_core_Pod(in *V1Pod, out *Pod, _ conversion.Scope) error {
	if in.wire != nil && in.decoded == nil {
		out.wire = in.wire
		if in.wireOwn == in {
			in.wireOwn = nil
			out.wireOwn = out
		} else {
			out.wireOwn = nil
		}
		out.decoded = nil
		return nil
	}
	decodedV1, err := in.EnsureDecoded()
	if err != nil {
		return err
	}
	out.wire = nil
	out.wireOwn = nil
	podCopy := *(*core.Pod)(unsafe.Pointer(decodedV1))
	podCopy.TypeMeta = out.TypeMeta
	out.decoded = &podCopy
	return nil
}

// Convert_core_Pod_To_v1_Pod transfers the lazy WirePod buffer from internal Pod to V1Pod
// in O(1) without decoding when internal Pod is in lazy wire form, or uses zero-copy layout casting if decoded.
func Convert_core_Pod_To_v1_Pod(in *Pod, out *V1Pod, _ conversion.Scope) error {
	if in.wire != nil && in.decoded == nil {
		out.wire = in.wire
		out.wireOwn = nil
		out.decoded = nil
		return nil
	}
	out.wire = nil
	out.wireOwn = nil
	if in.decoded != nil {
		v1Copy := *(*v1.Pod)(unsafe.Pointer(in.decoded))
		v1Copy.TypeMeta = out.TypeMeta
		out.decoded = &v1Copy
	}
	return nil
}

// Convert_core_PodList_To_v1_PodList converts an internal lazy PodList to V1PodList in O(N) without decoding items.
func Convert_core_PodList_To_v1_PodList(in *PodList, out *V1PodList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items == nil {
		out.Items = nil
		return nil
	}
	out.Items = make([]V1Pod, len(in.Items))
	for i := range in.Items {
		if err := Convert_core_Pod_To_v1_Pod(&in.Items[i], &out.Items[i], s); err != nil {
			return err
		}
	}
	return nil
}

// Convert_v1_PodList_To_core_PodList converts an external lazy V1PodList to PodList in O(N) without decoding items.
func Convert_v1_PodList_To_core_PodList(in *V1PodList, out *PodList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items == nil {
		out.Items = nil
		return nil
	}
	out.Items = make([]Pod, len(in.Items))
	for i := range in.Items {
		if err := Convert_v1_Pod_To_core_Pod(&in.Items[i], &out.Items[i], s); err != nil {
			return err
		}
	}
	return nil
}

/*
Copyright 2014 The Kubernetes Authors.

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

package pod

import (
	"context"
	"fmt"
	"maps"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"sigs.k8s.io/structured-merge-diff/v7/fieldpath"

	netutils "k8s.io/utils/net"

	apiv1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/apiserver/pkg/warning"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	podutil "k8s.io/kubernetes/pkg/api/pod"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/core/helper/qos"
	"k8s.io/kubernetes/pkg/apis/core/lazypod"
	corevalidation "k8s.io/kubernetes/pkg/apis/core/validation"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/kubelet/client"
)

// podStrategy implements behavior for Pods
type podStrategy struct {
	rest.DeclarativeValidation
	names.NameGenerator
}

// Strategy is the default logic that applies when creating and updating Pod
// objects via the REST API.
var Strategy = podStrategy{rest.DeclarativeValidation{Scheme: legacyscheme.Scheme}, names.SimpleNameGenerator}

// NamespaceScoped is true for pods.
func (podStrategy) NamespaceScoped() bool {
	return true
}

// GetResetFields returns the set of fields that get reset by the strategy
// and should not be modified by the user.
func (podStrategy) GetResetFields() map[fieldpath.APIVersion]*fieldpath.Set {
	fields := map[fieldpath.APIVersion]*fieldpath.Set{
		"v1": fieldpath.NewSet(
			fieldpath.MakePathOrDie("status"),
		),
	}

	return fields
}

var corePodPairPool = sync.Pool{
	New: func() any {
		return new([2]api.Pod)
	},
}

func ensureDecodedPod(obj runtime.Object) *api.Pod {
	dec, err := runtime.EnsureDecodedObject(obj)
	if err != nil {
		panic(err)
	}
	return dec.(*api.Pod)
}

// PrepareForCreate clears fields that are not allowed to be set by end users on creation.
func (podStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	pod := ensureDecodedPod(obj)
	pod.Generation = 1

	pod.Status = api.PodStatus{
		Phase: api.PodPending,
	}

	podutil.DropDisabledPodFields(pod, nil)

	applySchedulingGatedCondition(pod)
	mutatePodAffinity(pod)
	mutateTopologySpreadConstraints(pod)
	applyAppArmorVersionSkew(ctx, pod)
	podutil.DefaultPodLevelResources(pod)

	pod.Status.QOSClass = qos.GetPodQOS(pod)
}

// PrepareForUpdate clears fields that are not allowed to be set by end users on update.
func (podStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	if newLazy, ok1 := obj.(*lazypod.Pod); ok1 && newLazy.IsLazy() {
		if oldLazy, ok2 := old.(*lazypod.Pod); ok2 && oldLazy.IsLazy() {
			if specDiffMask, diffOK := newLazy.DiffSpecTagMask(oldLazy); diffOK &&
				(specDiffMask&^(lazypod.SpecTagMaskFastMutable|lazypod.SpecTagMaskContainers)) == 0 {
				specReady := true
				if specDiffMask != 0 {
					var newSubSpec, oldSubSpec api.PodSpec
					if err1 := newLazy.Wire().ExtractCoreSpecSubtreeInto(specDiffMask, &newSubSpec); err1 != nil {
						specReady = false
					} else if err2 := oldLazy.Wire().ExtractCoreSpecSubtreeInto(specDiffMask, &oldSubSpec); err2 != nil {
						specReady = false
					} else if specDiffMask&lazypod.SpecTagMaskContainers != 0 &&
						!onlyContainerImagesChangedInSpec(&newSubSpec, &oldSubSpec) {
						specReady = false
					} else if !apiequality.Semantic.DeepEqual(newSubSpec, oldSubSpec) {
						newLazy.SetGeneration(newLazy.GetGeneration() + 1)
					}
				}
				if specReady {
					if newLazy.HasLegacyInitContainerAnnotations() {
						ann := maps.Clone(newLazy.GetAnnotations())
						podutil.DropInitContainerAnnotations(ann)
						newLazy.SetAnnotations(ann)
					}
					if newLazy.HasEqualStatusWireBytes(oldLazy) {
						return
					}
					var newMeta metav1.ObjectMeta
					newLazy.BorrowObjectMetaInto(&newMeta, false)
					if err := newLazy.ReplaceMetaAndKeepSpecWithOldStatus(&newMeta, oldLazy); err == nil {
						return
					}
				}
			}
		}
	}
	newPod := ensureDecodedPod(obj)
	oldPod := ensureDecodedPod(old)
	newPod.Status = oldPod.Status

	if utilfeature.DefaultFeatureGate.Enabled(features.PodLevelResourcesFixDefaulting) {
		if newPod.Spec.Resources == nil && oldPod.Spec.Resources != nil {
			// preserve existing PLR for requests from potentially PLR-unaware clients that completely dropped the field
			newPod.Spec.Resources = oldPod.Spec.Resources.DeepCopy()
		}
	}

	podutil.DropDisabledPodFields(newPod, oldPod)
	updatePodGeneration(newPod, oldPod)
}

// Validate validates a new pod.
func (podStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	pod := ensureDecodedPod(obj)
	opts := corevalidation.GetValidationOptionsFromPodSpecAndMeta(&pod.Spec, nil, &pod.ObjectMeta, nil)
	opts.ResourceIsPod = true
	return corevalidation.ValidatePodCreate(pod, opts)
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (podStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	newPod := ensureDecodedPod(obj)
	var warnings []string
	if msgs := utilvalidation.IsDNS1123Label(newPod.Name); len(msgs) != 0 {
		warnings = append(warnings, fmt.Sprintf("metadata.name: this is used in the Pod's hostname, which can result in surprising behavior; a DNS label is recommended: %v", msgs))
	}
	warnings = append(warnings, podutil.GetWarningsForPod(ctx, newPod, nil)...)
	return warnings
}

// Canonicalize normalizes the object after validation.
func (podStrategy) Canonicalize(obj runtime.Object) {
}

// AllowCreateOnUpdate is false for pods.
func (podStrategy) AllowCreateOnUpdate(ctx context.Context) bool {
	return false
}

// ValidateUpdate is the default update validation for an end user.
func (podStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	if newLazy, ok1 := obj.(*lazypod.Pod); ok1 && newLazy.IsLazy() {
		if oldLazy, ok2 := old.(*lazypod.Pod); ok2 && oldLazy.IsLazy() {
			if specDiffMask, diffOK := newLazy.DiffSpecTagMask(oldLazy); diffOK &&
				(specDiffMask&^(lazypod.SpecTagMaskFastMutable|lazypod.SpecTagMaskContainers)) == 0 {
				if specDiffMask == 0 {
					var newMeta, oldMeta metav1.ObjectMeta
					newLazy.BorrowObjectMetaInto(&newMeta, false)
					oldLazy.BorrowObjectMetaInto(&oldMeta, true)
					if newMeta.Annotations[api.TolerationsAnnotationKey] == "" &&
						!hasDeprecatedAppArmorContainerAnnotation(newMeta.Annotations) {
						fldPath := field.NewPath("metadata")
						allErrs := corevalidation.ValidateObjectMetaUpdate(&newMeta, &oldMeta, fldPath)
						allErrs = append(allErrs, corevalidation.ValidateObjectMeta(&newMeta, true, corevalidation.ValidatePodName, fldPath)...)
						opts := corevalidation.GetValidationOptionsFromPodSpecAndMeta(nil, nil, &newMeta, &oldMeta)
						opts.ResourceIsPod = true
						allErrs = append(allErrs, corevalidation.ValidatePodSpecificAnnotationUpdates(newLazy, oldMeta.Annotations, fldPath.Child("annotations"), opts)...)
						if len(allErrs) == 0 {
							return nil
						}
					}
				} else if oldLazy.Wire().HasContainers() {
					var newMeta, oldMeta metav1.ObjectMeta
					newLazy.BorrowObjectMetaInto(&newMeta, false)
					oldLazy.BorrowObjectMetaInto(&oldMeta, true)
					if newMeta.Annotations[api.TolerationsAnnotationKey] == "" &&
						!hasDeprecatedAppArmorContainerAnnotation(newMeta.Annotations) {
						var newSubSpec, oldSubSpec api.PodSpec
						if err1 := newLazy.Wire().ExtractCoreSpecSubtreeInto(specDiffMask, &newSubSpec); err1 == nil {
							if err2 := oldLazy.Wire().ExtractCoreSpecSubtreeInto(specDiffMask, &oldSubSpec); err2 == nil {
								opts := corevalidation.GetValidationOptionsFromPodSpecAndMeta(&newSubSpec, &oldSubSpec, &newMeta, &oldMeta)
								opts.ResourceIsPod = true
								if validateFastMutablePodSpecUpdate(&newMeta, &oldMeta, newLazy, &newSubSpec, &oldSubSpec, specDiffMask, opts) {
									return nil
								}
							}
						}
					}
				}
			}
		}
	}
	// Allow downward api usage of hugepages on pod update if feature is enabled or if the old pod already had used them.
	pod := ensureDecodedPod(obj)
	oldPod := ensureDecodedPod(old)
	opts := corevalidation.GetValidationOptionsFromPodSpecAndMeta(&pod.Spec, &oldPod.Spec, &pod.ObjectMeta, &oldPod.ObjectMeta)
	opts.ResourceIsPod = true
	return corevalidation.ValidatePodUpdate(pod, oldPod, opts)
}

func hasDeprecatedAppArmorContainerAnnotation(annotations map[string]string) bool {
	for k := range annotations {
		if strings.HasPrefix(k, apiv1.DeprecatedAppArmorBetaContainerAnnotationKeyPrefix) {
			return true
		}
	}
	return false
}

func onlyContainerImagesChanged(newCtrs, oldCtrs []api.Container) bool {
	if len(newCtrs) != len(oldCtrs) {
		return false
	}
	for i := range newCtrs {
		if newCtrs[i].Image != oldCtrs[i].Image {
			if len(newCtrs[i].Image) == 0 || len(strings.TrimSpace(newCtrs[i].Image)) != len(newCtrs[i].Image) {
				return false
			}
			cp := newCtrs[i]
			cp.Image = oldCtrs[i].Image
			if !apiequality.Semantic.DeepEqual(cp, oldCtrs[i]) {
				return false
			}
		} else if !apiequality.Semantic.DeepEqual(newCtrs[i], oldCtrs[i]) {
			return false
		}
	}
	return true
}

func onlyContainerImagesChangedInSpec(newSpec, oldSpec *api.PodSpec) bool {
	return onlyContainerImagesChanged(newSpec.Containers, oldSpec.Containers) &&
		onlyContainerImagesChanged(newSpec.InitContainers, oldSpec.InitContainers)
}

func validateFastMutablePodSpecUpdate(newMeta, oldMeta *metav1.ObjectMeta, newLazy *lazypod.Pod, newSpec, oldSpec *api.PodSpec, specDiffMask uint64, opts corevalidation.PodValidationOptions) bool {
	fldPath := field.NewPath("metadata")
	if len(corevalidation.ValidateObjectMetaUpdate(newMeta, oldMeta, fldPath)) > 0 {
		return false
	}
	if len(corevalidation.ValidateObjectMeta(newMeta, true, corevalidation.ValidatePodName, fldPath)) > 0 {
		return false
	}
	if len(corevalidation.ValidatePodSpecificAnnotationUpdates(newLazy, oldMeta.Annotations, fldPath.Child("annotations"), opts)) > 0 {
		return false
	}
	if specDiffMask&lazypod.SpecTagMaskContainers != 0 && !onlyContainerImagesChangedInSpec(newSpec, oldSpec) {
		return false
	}
	specPath := field.NewPath("spec")
	if specDiffMask&lazypod.SpecTagMaskActiveDeadlineSeconds != 0 {
		if newSpec.ActiveDeadlineSeconds == nil {
			if oldSpec.ActiveDeadlineSeconds != nil {
				return false
			}
		} else {
			val := *newSpec.ActiveDeadlineSeconds
			if val < 1 || val > math.MaxInt32 {
				return false
			}
			if oldSpec.ActiveDeadlineSeconds != nil && *oldSpec.ActiveDeadlineSeconds < val {
				return false
			}
		}
	}
	if specDiffMask&lazypod.SpecTagMaskTolerations != 0 {
		for i := range oldSpec.Tolerations {
			oldTol := &oldSpec.Tolerations[i]
			found := false
			for j := range newSpec.Tolerations {
				newTol := &newSpec.Tolerations[j]
				if oldTol.Key == newTol.Key && oldTol.Operator == newTol.Operator && oldTol.Value == newTol.Value && oldTol.Effect == newTol.Effect {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		if len(corevalidation.ValidateTolerations(newSpec.Tolerations, specPath.Child("tolerations"), opts, corevalidation.KeyFormatCovered)) > 0 {
			return false
		}
	}
	if specDiffMask&lazypod.SpecTagMaskSchedulingGates != 0 {
		gatesPath := specPath.Child("schedulingGates")
		for i, g := range newSpec.SchedulingGates {
			if len(corevalidation.ValidateQualifiedName(g.Name, gatesPath.Index(i))) > 0 {
				return false
			}
			for j := 0; j < i; j++ {
				if newSpec.SchedulingGates[j].Name == g.Name {
					return false
				}
			}
			existed := false
			for j := range oldSpec.SchedulingGates {
				if oldSpec.SchedulingGates[j].Name == g.Name {
					existed = true
					break
				}
			}
			if !existed {
				return false
			}
		}
	}
	return true
}

// WarningsOnUpdate returns warnings for the given update.
func (podStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	// skip warnings on pod update, since humans don't typically interact directly with pods,
	// and we don't want to pay the evaluation cost on what might be a high-frequency update path
	return nil
}

// AllowUnconditionalUpdate allows pods to be overwritten
func (podStrategy) AllowUnconditionalUpdate(ctx context.Context) bool {
	return true
}

// CheckGracefulDelete allows a pod to be gracefully deleted. It updates the DeleteOptions to
// reflect the desired grace value.
func (podStrategy) CheckGracefulDelete(ctx context.Context, obj runtime.Object, options *metav1.DeleteOptions) bool {
	if options == nil {
		return false
	}
	pod := obj.(api.PodAccessor)
	period := int64(0)
	// user has specified a value
	if options.GracePeriodSeconds != nil {
		period = *options.GracePeriodSeconds
	} else {
		// use the default value if set, or deletes the pod immediately (0)
		if tgp := pod.GetSpecTerminationGracePeriodSeconds(); tgp != nil {
			period = *tgp
		}
	}
	// if the pod is not scheduled, delete immediately
	if len(pod.GetSpecNodeName()) == 0 {
		period = 0
	}
	// if the pod is already terminated, delete immediately
	if phase := pod.GetStatusPhase(); phase == api.PodFailed || phase == api.PodSucceeded {
		period = 0
	}

	if period < 0 {
		period = 1
	}

	// ensure the options and the pod are in sync
	options.GracePeriodSeconds = &period
	return true
}

type podStatusStrategy struct {
	podStrategy
}

// StatusStrategy wraps and exports the used podStrategy for the storage package.
var StatusStrategy = podStatusStrategy{Strategy}

// GetResetFields returns the set of fields that get reset by the strategy
// and should not be modified by the user.
func (podStatusStrategy) GetResetFields() map[fieldpath.APIVersion]*fieldpath.Set {
	return map[fieldpath.APIVersion]*fieldpath.Set{
		"v1": fieldpath.NewSet(
			fieldpath.MakePathOrDie("spec"),
			fieldpath.MakePathOrDie("metadata", "deletionTimestamp"),
			fieldpath.MakePathOrDie("metadata", "ownerReferences"),
		),
	}
}

func (podStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	if newLazy, ok1 := obj.(*lazypod.Pod); ok1 && newLazy.IsLazy() {
		if oldLazy, ok2 := old.(*lazypod.Pod); ok2 && oldLazy.IsLazy() {
			specEqual := newLazy.HasEqualSpecWireBytes(oldLazy)
			if specEqual &&
				!newLazy.HasDeletionTimestamp() &&
				newLazy.HasEqualOwnerReferences(oldLazy) &&
				!newLazy.HasLegacyInitContainerAnnotations() {
				if statusDiffMask, diffOK := newLazy.DiffStatusTagMask(oldLazy); diffOK &&
					(statusDiffMask&^lazypod.StatusTagMaskFastScalar) == 0 &&
					(utilfeature.DefaultFeatureGate.Enabled(features.CSIVolumeHealth) || !oldLazy.Wire().HasVolumeStatuses()) {
					return
				}
			}
			var newMeta, oldMeta metav1.ObjectMeta
			newLazy.BorrowObjectMetaInto(&newMeta, true)
			oldLazy.BorrowObjectMetaInto(&oldMeta, true)
			newStatusRO, err1 := newLazy.ReadOnlyCoreStatus()
			oldStatusRO, err2 := oldLazy.ReadOnlyCoreStatus()
			if err1 == nil && err2 == nil {
				if specEqual && !podStatusNeedsPrepareMutation(newLazy, &newMeta, newStatusRO, &oldMeta, oldStatusRO) {
					return
				}
				var mutMeta metav1.ObjectMeta
				newMeta.DeepCopyInto(&mutMeta)
				var mutStatus api.PodStatus
				newStatusRO.DeepCopyInto(&mutStatus)
				changed := preparePodStatusFields(&mutMeta, &mutStatus, &oldMeta, oldStatusRO)
				tmpNew := api.Pod{ObjectMeta: mutMeta, Status: mutStatus}
				tmpOld := api.Pod{ObjectMeta: oldMeta, Status: *oldStatusRO}
				if podutil.DropDisabledPodStatusFields(&tmpNew, &tmpOld) {
					changed = true
				}
				if !changed && specEqual {
					return
				}
				tmpNew.ManagedFields = newLazy.GetManagedFields()
				if err := newLazy.ReplaceMetaAndStatusFromOldSpec(&tmpNew.ObjectMeta, &tmpNew.Status, oldLazy); err == nil {
					return
				}
			}
		}
	}
	newPod := ensureDecodedPod(obj)
	oldPod := ensureDecodedPod(old)
	newPod.Spec = oldPod.Spec
	preparePodStatusFields(&newPod.ObjectMeta, &newPod.Status, &oldPod.ObjectMeta, &oldPod.Status)
	podutil.DropDisabledPodFields(newPod, oldPod)
}

func podStatusNeedsPrepareMutation(newLazy *lazypod.Pod, newMeta *metav1.ObjectMeta, newStatus *api.PodStatus, oldMeta *metav1.ObjectMeta, oldStatus *api.PodStatus) bool {
	if newMeta.DeletionTimestamp != nil ||
		!equalOwnerReferences(newMeta.OwnerReferences, oldMeta.OwnerReferences) ||
		newLazy.HasLegacyInitContainerAnnotations() {
		return true
	}
	if (newStatus.QOSClass == "" && oldStatus.QOSClass != "") ||
		(newStatus.ResourceClaimStatuses == nil && oldStatus.ResourceClaimStatuses != nil) ||
		(newStatus.ExtendedResourceClaimStatus == nil && oldStatus.ExtendedResourceClaimStatus != nil) ||
		(newStatus.NodeAllocatableResourceClaimStatuses == nil && oldStatus.NodeAllocatableResourceClaimStatuses != nil) ||
		(newStatus.ObservedGeneration == 0 && oldStatus.ObservedGeneration != 0) {
		return true
	}
	for i := range newStatus.Conditions {
		if newStatus.Conditions[i].ObservedGeneration == 0 && len(oldStatus.Conditions) > 0 {
			return true
		}
	}
	if (newStatus.Resources != nil || newStatus.AllocatedResources != nil) &&
		!utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodLevelResourcesVerticalScaling) {
		return true
	}
	if newStatus.ExtendedResourceClaimStatus != nil && !utilfeature.DefaultFeatureGate.Enabled(features.DRAExtendedResource) {
		return true
	}
	if newStatus.NodeAllocatableResourceClaimStatuses != nil && !utilfeature.DefaultFeatureGate.Enabled(features.DRANodeAllocatableResources) {
		return true
	}
	if newStatus.VolumeStatuses != nil && !utilfeature.DefaultFeatureGate.Enabled(features.CSIVolumeHealth) {
		return true
	}
	if !utilfeature.DefaultFeatureGate.Enabled(features.PodObservedGenerationTracking) {
		if newStatus.ObservedGeneration != 0 {
			return true
		}
		for i := range newStatus.Conditions {
			if newStatus.Conditions[i].ObservedGeneration != 0 {
				return true
			}
		}
	}
	needDropAllocRes := !utilfeature.DefaultFeatureGate.Enabled(features.ResourceHealthStatus) ||
		!utilfeature.DefaultFeatureGate.Enabled(features.ResourceHealthStatusMessage)
	needDropImgDigest := !utilfeature.DefaultFeatureGate.Enabled(features.ImageVolumeWithDigest)
	if needDropAllocRes || needDropImgDigest {
		for _, csl := range [][]api.ContainerStatus{newStatus.ContainerStatuses, newStatus.InitContainerStatuses, newStatus.EphemeralContainerStatuses} {
			for i := range csl {
				if needDropAllocRes && len(csl[i].AllocatedResourcesStatus) > 0 {
					return true
				}
				if needDropImgDigest && len(csl[i].VolumeMounts) > 0 {
					return true
				}
			}
		}
	}
	return false
}

func preparePodStatusFields(newMeta *metav1.ObjectMeta, newStatus *api.PodStatus, oldMeta *metav1.ObjectMeta, oldStatus *api.PodStatus) bool {
	changed := false
	if newMeta.DeletionTimestamp != nil {
		newMeta.DeletionTimestamp = nil
		changed = true
	}

	// don't allow the pods/status endpoint to touch owner references since old kubelets corrupt them in a way
	// that breaks garbage collection
	if !equalOwnerReferences(newMeta.OwnerReferences, oldMeta.OwnerReferences) {
		newMeta.OwnerReferences = oldMeta.OwnerReferences
		changed = true
	}
	// the Pod QoS is immutable and populated at creation time by the kube-apiserver.
	// we need to backfill it for backward compatibility because the old kubelet dropped this field when the pod was rejected.
	if newStatus.QOSClass == "" && oldStatus.QOSClass != "" {
		newStatus.QOSClass = oldStatus.QOSClass
		changed = true
	}

	// Preserve DRA-related status fields when an old or misbehaving client
	// strips fields that it does not know about during a pods/status update.
	// For the slice fields, a non-nil empty slice can still clear the field.
	if newStatus.ResourceClaimStatuses == nil && oldStatus.ResourceClaimStatuses != nil {
		newStatus.ResourceClaimStatuses = oldStatus.ResourceClaimStatuses
		changed = true
	}
	if newStatus.ExtendedResourceClaimStatus == nil && oldStatus.ExtendedResourceClaimStatus != nil {
		newStatus.ExtendedResourceClaimStatus = oldStatus.ExtendedResourceClaimStatus
		changed = true
	}
	if newStatus.NodeAllocatableResourceClaimStatuses == nil && oldStatus.NodeAllocatableResourceClaimStatuses != nil {
		newStatus.NodeAllocatableResourceClaimStatuses = oldStatus.NodeAllocatableResourceClaimStatuses
		changed = true
	}

	if preserveOldObservedGenerationStatus(newStatus, oldStatus) {
		changed = true
	}
	return changed
}

func equalBoolPtr(a, b *bool) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func equalOwnerReferences(a, b []metav1.OwnerReference) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].APIVersion != b[i].APIVersion ||
			a[i].Kind != b[i].Kind ||
			a[i].Name != b[i].Name ||
			a[i].UID != b[i].UID ||
			!equalBoolPtr(a[i].Controller, b[i].Controller) ||
			!equalBoolPtr(a[i].BlockOwnerDeletion, b[i].BlockOwnerDeletion) {
			return false
		}
	}
	return true
}

// If a client request tries to clear `observedGeneration`, in the pod status or
// conditions, we preserve the original value.
func preserveOldObservedGeneration(newPod, oldPod *api.Pod) {
	preserveOldObservedGenerationStatus(&newPod.Status, &oldPod.Status)
}

func preserveOldObservedGenerationStatus(newStatus, oldStatus *api.PodStatus) bool {
	changed := false
	if newStatus.ObservedGeneration == 0 && oldStatus.ObservedGeneration != 0 {
		newStatus.ObservedGeneration = oldStatus.ObservedGeneration
		changed = true
	}

	hasZeroConditionGeneration := false
	for i := range newStatus.Conditions {
		if newStatus.Conditions[i].ObservedGeneration == 0 {
			hasZeroConditionGeneration = true
			break
		}
	}
	if !hasZeroConditionGeneration {
		return changed
	}

	// Remember observedGeneration values from old status conditions.
	// This is a list per type because validation permits multiple conditions with the same type.
	oldConditionGenerations := map[api.PodConditionType][]int64{}
	for _, oldCondition := range oldStatus.Conditions {
		oldConditionGenerations[oldCondition.Type] = append(oldConditionGenerations[oldCondition.Type], oldCondition.ObservedGeneration)
	}

	// For any conditions in the new status without observedGeneration set, preserve the old value.
	for i, newCondition := range newStatus.Conditions {
		oldGeneration := int64(0)
		if oldGenerations, ok := oldConditionGenerations[newCondition.Type]; ok && len(oldGenerations) > 0 {
			oldGeneration = oldGenerations[0]
			oldConditionGenerations[newCondition.Type] = oldGenerations[1:]
		}

		if newCondition.ObservedGeneration == 0 && oldGeneration != 0 {
			newStatus.Conditions[i].ObservedGeneration = oldGeneration
			changed = true
		}
	}
	return changed
}

func statusUpdateNeedsFullSpec(newMeta *metav1.ObjectMeta, newStatus, oldStatus *api.PodStatus) bool {
	if len(newStatus.ResourceClaimStatuses) > 0 ||
		newStatus.ExtendedResourceClaimStatus != nil ||
		len(newStatus.NodeAllocatableResourceClaimStatuses) > 0 ||
		len(newStatus.VolumeStatuses) > 0 {
		return true
	}
	if newMeta.Annotations[api.TolerationsAnnotationKey] != "" {
		return true
	}
	for k := range newMeta.Annotations {
		if strings.HasPrefix(k, apiv1.DeprecatedAppArmorBetaContainerAnnotationKeyPrefix) {
			return true
		}
	}
	for i := range newStatus.ContainerStatuses {
		if len(newStatus.ContainerStatuses[i].AllocatedResourcesStatus) > 0 {
			return true
		}
	}
	for i := range newStatus.InitContainerStatuses {
		if len(newStatus.InitContainerStatuses[i].AllocatedResourcesStatus) > 0 {
			return true
		}
	}
	return hasTerminatedToNonTerminatedTransition(newStatus.ContainerStatuses, oldStatus.ContainerStatuses) ||
		hasTerminatedToNonTerminatedTransition(newStatus.InitContainerStatuses, oldStatus.InitContainerStatuses)
}

func hasTerminatedToNonTerminatedTransition(newStatuses, oldStatuses []api.ContainerStatus) bool {
	for i := range oldStatuses {
		if oldStatuses[i].State.Terminated == nil {
			continue
		}
		for j := range newStatuses {
			if newStatuses[j].Name == oldStatuses[i].Name && newStatuses[j].State.Terminated == nil {
				return true
			}
		}
	}
	return false
}

func (podStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	if newLazy, ok1 := obj.(*lazypod.Pod); ok1 && newLazy.IsLazy() {
		if oldLazy, ok2 := old.(*lazypod.Pod); ok2 && oldLazy.IsLazy() {
			var newMeta, oldMeta metav1.ObjectMeta
			newLazy.BorrowObjectMetaInto(&newMeta, false)
			oldLazy.BorrowObjectMetaInto(&oldMeta, true)
			newStatusRO, err1 := newLazy.ReadOnlyCoreStatus()
			oldStatusRO, err2 := oldLazy.ReadOnlyCoreStatus()
			if err1 == nil && err2 == nil && !statusUpdateNeedsFullSpec(&newMeta, newStatusRO, oldStatusRO) {
				nodeName, restartPolicy, podOS := oldLazy.SpecSummaryForStatusValidation()
				minSpec := api.PodSpec{
					NodeName:      nodeName,
					RestartPolicy: restartPolicy,
					OS:            podOS,
				}
				pair := corePodPairPool.Get().(*[2]api.Pod)
				tmpNew := &pair[0]
				tmpOld := &pair[1]
				tmpNew.ObjectMeta = newMeta
				tmpNew.Spec = minSpec
				tmpNew.Status = *newStatusRO
				tmpOld.ObjectMeta = oldMeta
				tmpOld.Spec = minSpec
				tmpOld.Status = *oldStatusRO
				opts := corevalidation.GetValidationOptionsFromPodSpecAndMeta(nil, nil, &newMeta, &oldMeta)
				opts.ResourceIsPod = true
				errs := corevalidation.ValidatePodStatusUpdate(tmpNew, tmpOld, opts)
				if len(errs) == 0 {
					*pair = [2]api.Pod{}
					corePodPairPool.Put(pair)
				}
				return errs
			}
		}
	}
	pod := ensureDecodedPod(obj)
	oldPod := ensureDecodedPod(old)
	opts := corevalidation.GetValidationOptionsFromPodSpecAndMeta(&pod.Spec, &oldPod.Spec, &pod.ObjectMeta, &oldPod.ObjectMeta)
	opts.ResourceIsPod = true

	return corevalidation.ValidatePodStatusUpdate(pod, oldPod, opts)
}

// WarningsOnUpdate returns warnings for the given update.
func (podStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	pod := obj.(api.PodAccessor)
	var warnings []string

	for i, podIP := range pod.GetStatusPodIPs() {
		warnings = append(warnings, utilvalidation.GetWarningsForIP(field.NewPath("status", "podIPs").Index(i).Child("ip"), podIP.IP)...)
	}
	for i, hostIP := range pod.GetStatusHostIPs() {
		warnings = append(warnings, utilvalidation.GetWarningsForIP(field.NewPath("status", "hostIPs").Index(i).Child("ip"), hostIP.IP)...)
	}

	return warnings
}

type podEphemeralContainersStrategy struct {
	podStrategy

	resetFieldsFilter fieldpath.Filter
}

// EphemeralContainersStrategy wraps and exports the used podStrategy for the storage package.
var EphemeralContainersStrategy = podEphemeralContainersStrategy{
	podStrategy: Strategy,
	resetFieldsFilter: fieldpath.NewIncludeMatcherFilter(
		fieldpath.MakePrefixMatcherOrDie("spec", "ephemeralContainers"),
	),
}

// dropNonEphemeralContainerUpdates discards all changes except for pod.Spec.EphemeralContainers and certain metadata
func dropNonEphemeralContainerUpdates(newPod, oldPod *api.Pod) *api.Pod {
	newEphemeralContainerSpec := newPod.Spec.EphemeralContainers
	newPod.Spec = oldPod.Spec
	newPod.Status = oldPod.Status
	metav1.ResetObjectMetaForStatus(&newPod.ObjectMeta, &oldPod.ObjectMeta)
	newPod.Spec.EphemeralContainers = newEphemeralContainerSpec
	return newPod
}

func (podEphemeralContainersStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	if newLazy, ok1 := obj.(*lazypod.Pod); ok1 && newLazy.IsLazy() {
		if oldLazy, ok2 := old.(*lazypod.Pod); ok2 && oldLazy.IsLazy() {
			var newSubSpec, oldSubSpec api.PodSpec
			if err1 := newLazy.Wire().ExtractCoreSpecSubtreeInto(lazypod.SpecTagMaskEphemeralContainers, &newSubSpec); err1 == nil {
				if err2 := oldLazy.Wire().ExtractCoreSpecSubtreeInto(lazypod.SpecTagMaskEphemeralContainers, &oldSubSpec); err2 == nil {
					tmpNew := api.Pod{Spec: newSubSpec}
					tmpOld := api.Pod{Spec: oldSubSpec}
					podutil.DropDisabledPodFields(&tmpNew, &tmpOld)
					specDiffMask, diffOK := newLazy.DiffSpecTagMask(oldLazy)
					if diffOK && (specDiffMask&^lazypod.SpecTagMaskEphemeralContainers) == 0 &&
						newLazy.Wire().HasEqualNonManagedMeta(oldLazy.Wire()) &&
						newLazy.HasEqualStatusWireBytes(oldLazy) &&
						!newLazy.HasLegacyInitContainerAnnotations() &&
						apiequality.Semantic.DeepEqual(tmpNew.Spec.EphemeralContainers, newSubSpec.EphemeralContainers) {
						if !apiequality.Semantic.DeepEqual(tmpNew.Spec.EphemeralContainers, oldSubSpec.EphemeralContainers) {
							newLazy.SetGeneration(newLazy.GetGeneration() + 1)
						}
						return
					}
					var metaPtr *metav1.ObjectMeta
					if !newLazy.Wire().HasEqualNonManagedMeta(oldLazy.Wire()) {
						var newMeta, oldMeta metav1.ObjectMeta
						newLazy.ExtractObjectMetaForUpdate(&newMeta, false)
						oldLazy.BorrowObjectMetaInto(&oldMeta, true)
						metav1.ResetObjectMetaForStatus(&newMeta, &oldMeta)
						podutil.DropInitContainerAnnotations(newMeta.Annotations)
						metaPtr = &newMeta
					}
					if err := newLazy.ReplaceMetaAndSpliceSpecOntoOld(metaPtr, &tmpNew.Spec, lazypod.SpecTagMaskEphemeralContainers, oldLazy); err == nil {
						if !apiequality.Semantic.DeepEqual(tmpNew.Spec.EphemeralContainers, oldSubSpec.EphemeralContainers) {
							newLazy.SetGeneration(newLazy.GetGeneration() + 1)
						}
						return
					}
				}
			}
		}
	}
	newPod := ensureDecodedPod(obj)
	oldPod := ensureDecodedPod(old)

	*newPod = *dropNonEphemeralContainerUpdates(newPod, oldPod)
	podutil.DropDisabledPodFields(newPod, oldPod)
	updatePodGeneration(newPod, oldPod)
}

func (podEphemeralContainersStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	if newLazy, ok1 := obj.(*lazypod.Pod); ok1 && newLazy.IsLazy() {
		if oldLazy, ok2 := old.(*lazypod.Pod); ok2 && oldLazy.IsLazy() {
			if specDiffMask, diffOK := newLazy.DiffSpecTagMask(oldLazy); diffOK &&
				(specDiffMask&^lazypod.SpecTagMaskEphemeralContainers) == 0 &&
				validateFastEphemeralContainersUpdate(newLazy, oldLazy) {
				return nil
			}
			pair := corePodPairPool.Get().(*[2]api.Pod)
			tmpNew := &pair[0]
			tmpOld := &pair[1]
			newLazy.BorrowObjectMetaInto(&tmpNew.ObjectMeta, false)
			oldLazy.BorrowObjectMetaInto(&tmpOld.ObjectMeta, true)
			err1 := newLazy.Wire().ExtractCoreSpecSubtreeInto(^uint64(0), &tmpNew.Spec)
			err2 := oldLazy.Wire().ExtractCoreSpecSubtreeInto(lazypod.SpecTagMaskEphemeralContainers, &tmpOld.Spec)
			if err1 == nil && err2 == nil {
				opts := corevalidation.GetValidationOptionsFromPodSpecAndMeta(&tmpNew.Spec, &tmpOld.Spec, &tmpNew.ObjectMeta, &tmpOld.ObjectMeta)
				opts.ResourceIsPod = true
				errs := corevalidation.ValidatePodEphemeralContainersUpdate(tmpNew, tmpOld, opts)
				if len(errs) == 0 {
					*pair = [2]api.Pod{}
					corePodPairPool.Put(pair)
				}
				return errs
			}
			*pair = [2]api.Pod{}
			corePodPairPool.Put(pair)
		}
	}
	newPod := ensureDecodedPod(obj)
	oldPod := ensureDecodedPod(old)
	opts := corevalidation.GetValidationOptionsFromPodSpecAndMeta(&newPod.Spec, &oldPod.Spec, &newPod.ObjectMeta, &oldPod.ObjectMeta)
	opts.ResourceIsPod = true
	return corevalidation.ValidatePodEphemeralContainersUpdate(newPod, oldPod, opts)
}

func isSimpleValidEphemeralContainer(ec *api.EphemeralContainer) bool {
	if len(utilvalidation.IsDNS1123Label(ec.Name)) > 0 {
		return false
	}
	if len(ec.Image) == 0 || len(strings.TrimSpace(ec.Image)) != len(ec.Image) {
		return false
	}
	switch ec.ImagePullPolicy {
	case api.PullAlways, api.PullIfNotPresent, api.PullNever:
	default:
		return false
	}
	if !strings.HasPrefix(ec.TerminationMessagePath, "/") {
		return false
	}
	switch ec.TerminationMessagePolicy {
	case api.TerminationMessageReadFile, api.TerminationMessageFallbackToLogsOnError:
	default:
		return false
	}
	return len(ec.Ports) == 0 &&
		len(ec.EnvFrom) == 0 &&
		len(ec.Env) == 0 &&
		len(ec.Resources.Limits) == 0 &&
		len(ec.Resources.Requests) == 0 &&
		len(ec.Resources.Claims) == 0 &&
		len(ec.ResizePolicy) == 0 &&
		ec.RestartPolicy == nil &&
		len(ec.RestartPolicyRules) == 0 &&
		len(ec.VolumeMounts) == 0 &&
		len(ec.VolumeDevices) == 0 &&
		ec.LivenessProbe == nil &&
		ec.ReadinessProbe == nil &&
		ec.StartupProbe == nil &&
		ec.Lifecycle == nil &&
		ec.SecurityContext == nil
}

func validateFastEphemeralContainersUpdate(newLazy, oldLazy *lazypod.Pod) bool {
	var newMeta, oldMeta metav1.ObjectMeta
	newLazy.BorrowObjectMetaInto(&newMeta, false)
	oldLazy.BorrowObjectMetaInto(&oldMeta, true)
	if _, isMirror := oldMeta.Annotations[api.MirrorPodAnnotationKey]; isMirror {
		return false
	}
	if newMeta.Annotations[api.TolerationsAnnotationKey] != "" || hasDeprecatedAppArmorContainerAnnotation(newMeta.Annotations) {
		return false
	}
	fldPath := field.NewPath("metadata")
	if len(corevalidation.ValidateObjectMetaUpdate(&newMeta, &oldMeta, fldPath)) > 0 {
		return false
	}
	if len(corevalidation.ValidateObjectMeta(&newMeta, true, corevalidation.ValidatePodName, fldPath)) > 0 {
		return false
	}
	opts := corevalidation.GetValidationOptionsFromPodSpecAndMeta(nil, nil, &newMeta, &oldMeta)
	opts.ResourceIsPod = true
	if len(corevalidation.ValidatePodSpecificAnnotationUpdates(newLazy, oldMeta.Annotations, fldPath.Child("annotations"), opts)) > 0 {
		return false
	}
	var newSubSpec, oldSubSpec api.PodSpec
	if err := newLazy.Wire().ExtractCoreSpecSubtreeInto(lazypod.SpecTagMaskContainers|lazypod.SpecTagMaskEphemeralContainers, &newSubSpec); err != nil {
		return false
	}
	if err := oldLazy.Wire().ExtractCoreSpecSubtreeInto(lazypod.SpecTagMaskEphemeralContainers, &oldSubSpec); err != nil {
		return false
	}
	if len(newSubSpec.Containers) == 0 {
		return false
	}
	otherNames := make(map[string]struct{}, len(newSubSpec.Containers)+len(newSubSpec.InitContainers))
	allNames := make(map[string]struct{}, len(newSubSpec.Containers)+len(newSubSpec.InitContainers)+len(newSubSpec.EphemeralContainers))
	for i := range newSubSpec.Containers {
		name := newSubSpec.Containers[i].Name
		otherNames[name] = struct{}{}
		allNames[name] = struct{}{}
	}
	for i := range newSubSpec.InitContainers {
		name := newSubSpec.InitContainers[i].Name
		otherNames[name] = struct{}{}
		allNames[name] = struct{}{}
	}
	newByName := make(map[string]*api.EphemeralContainer, len(newSubSpec.EphemeralContainers))
	for i := range newSubSpec.EphemeralContainers {
		ec := &newSubSpec.EphemeralContainers[i]
		if !isSimpleValidEphemeralContainer(ec) {
			return false
		}
		if _, dup := allNames[ec.Name]; dup {
			return false
		}
		allNames[ec.Name] = struct{}{}
		if ec.TargetContainerName != "" {
			if _, exists := otherNames[ec.TargetContainerName]; !exists {
				return false
			}
		}
		newByName[ec.Name] = ec
	}
	for i := range oldSubSpec.EphemeralContainers {
		oldEC := &oldSubSpec.EphemeralContainers[i]
		newEC, ok := newByName[oldEC.Name]
		if !ok || !apiequality.Semantic.DeepEqual(*oldEC, *newEC) {
			return false
		}
	}
	return true
}

// WarningsOnUpdate returns warnings for the given update.
func (podEphemeralContainersStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// GetResetFieldsFilter returns a set of fields filter reset by the strategy
// and should not be modified by the user.
func (p podEphemeralContainersStrategy) GetResetFieldsFilter() map[fieldpath.APIVersion]fieldpath.Filter {
	return map[fieldpath.APIVersion]fieldpath.Filter{
		"v1": p.resetFieldsFilter,
	}
}

type podResizeStrategy struct {
	podStrategy

	resetFieldsFilter fieldpath.Filter
}

// ResizeStrategy wraps and exports the used podStrategy for the storage package.
var ResizeStrategy = podResizeStrategy{
	podStrategy: Strategy,
	resetFieldsFilter: fieldpath.NewIncludeMatcherFilter(
		fieldpath.MakePrefixMatcherOrDie("spec", "containers", fieldpath.MatchAnyPathElement(), "resources"),
		fieldpath.MakePrefixMatcherOrDie("spec", "containers", fieldpath.MatchAnyPathElement(), "resizePolicy"),
		fieldpath.MakePrefixMatcherOrDie("spec", "initContainers", fieldpath.MatchAnyPathElement(), "resources"),
		fieldpath.MakePrefixMatcherOrDie("spec", "initContainers", fieldpath.MatchAnyPathElement(), "resizePolicy"),
	),
}

// dropNonResizeUpdates discards all changes except for
// pod.Spec.Containers[*].Resources, pod.Spec.InitContainers[*].Resources,
// ResizePolicy and certain metadata. If InPlacePodLevelResourcesVerticalScaling
// feature is enabled, pod-level resources are also preserved.
func dropNonResizeUpdates(newPod, oldPod *api.Pod) *api.Pod {
	// Containers are not allowed to be added, removed, re-ordered, or renamed.
	// If we detect any of these changes, we will return new podspec as-is and
	// allow the validation to catch the error and drop the update.
	if len(newPod.Spec.Containers) != len(oldPod.Spec.Containers) || len(newPod.Spec.InitContainers) != len(oldPod.Spec.InitContainers) {
		return newPod
	}

	// Preserve the incoming pod-level resource from the new pod object.
	newPodResources := newPod.Spec.Resources

	newVolumes := dropNonResizeUpdatesForVolumes(newPod.Spec.Volumes, oldPod.Spec.Volumes)

	containers := dropNonResizeUpdatesForContainers(newPod.Spec.Containers, oldPod.Spec.Containers)
	initContainers := dropNonResizeUpdatesForContainers(newPod.Spec.InitContainers, oldPod.Spec.InitContainers)

	newPod.Spec = oldPod.Spec
	// If PodLevelResources and InPlacePodLevelResourcesVerticalScaling feature gates is enabled,
	// restore the saved pod-level resource requests to the new pod's spec.
	if utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodLevelResourcesVerticalScaling) {
		newPod.Spec.Resources = newPodResources
	}

	newPod.Status = oldPod.Status
	metav1.ResetObjectMetaForStatus(&newPod.ObjectMeta, &oldPod.ObjectMeta)

	newPod.Spec.Containers = containers
	newPod.Spec.InitContainers = initContainers
	newPod.Spec.Volumes = newVolumes

	return newPod
}

func dropNonResizeUpdatesForContainers(new, old []api.Container) []api.Container {
	if len(new) == 0 {
		return new
	}

	oldCopyWithMergedResources := make([]api.Container, len(old))
	copy(oldCopyWithMergedResources, old)

	for i, ctr := range new {
		if oldCopyWithMergedResources[i].Name != new[i].Name {
			// This is an attempt to reorder or rename a container, which is not allowed.
			// Allow validation to catch this error.
			return new
		}
		oldCopyWithMergedResources[i].Resources = ctr.Resources
		oldCopyWithMergedResources[i].ResizePolicy = ctr.ResizePolicy
	}

	return oldCopyWithMergedResources
}

func dropNonResizeUpdatesForVolumes(new, old []api.Volume) []api.Volume {
	if !utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScalingMemoryBackedVolumes) {
		return old
	}
	return new
}

func (podResizeStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	if newLazy, ok1 := obj.(*lazypod.Pod); ok1 && newLazy.IsLazy() {
		if oldLazy, ok2 := old.(*lazypod.Pod); ok2 && oldLazy.IsLazy() &&
			!oldLazy.Wire().HasSpecResources() && !newLazy.Wire().HasSpecResources() {
			specDiffMask, diffOK := newLazy.DiffSpecTagMask(oldLazy)
			volumesNeedKeepNew := utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScalingMemoryBackedVolumes) &&
				(!diffOK || specDiffMask&lazypod.SpecTagMaskVolumes != 0)
			if !volumesNeedKeepNew {
				var newSubSpec, oldSubSpec api.PodSpec
				if err1 := newLazy.Wire().ExtractCoreSpecSubtreeInto(lazypod.SpecTagMaskContainers, &newSubSpec); err1 == nil {
					if err2 := oldLazy.Wire().ExtractCoreSpecSubtreeInto(lazypod.SpecTagMaskContainers, &oldSubSpec); err2 == nil &&
						hasMatchingContainerOrder(newSubSpec.Containers, oldSubSpec.Containers) &&
						hasMatchingContainerOrder(newSubSpec.InitContainers, oldSubSpec.InitContainers) {
						mergedSpec := api.PodSpec{
							Containers:     dropNonResizeUpdatesForContainers(newSubSpec.Containers, oldSubSpec.Containers),
							InitContainers: dropNonResizeUpdatesForContainers(newSubSpec.InitContainers, oldSubSpec.InitContainers),
						}
						if diffOK && (specDiffMask&^lazypod.SpecTagMaskContainers) == 0 &&
							newLazy.Wire().HasEqualNonManagedMeta(oldLazy.Wire()) &&
							newLazy.HasEqualStatusWireBytes(oldLazy) &&
							!newLazy.HasLegacyInitContainerAnnotations() &&
							apiequality.Semantic.DeepEqual(mergedSpec, newSubSpec) {
							if !apiequality.Semantic.DeepEqual(mergedSpec, oldSubSpec) {
								newLazy.SetGeneration(newLazy.GetGeneration() + 1)
							}
							return
						}
						var metaPtr *metav1.ObjectMeta
						if !newLazy.Wire().HasEqualNonManagedMeta(oldLazy.Wire()) {
							var newMeta, oldMeta metav1.ObjectMeta
							newLazy.ExtractObjectMetaForUpdate(&newMeta, false)
							oldLazy.BorrowObjectMetaInto(&oldMeta, true)
							metav1.ResetObjectMetaForStatus(&newMeta, &oldMeta)
							podutil.DropInitContainerAnnotations(newMeta.Annotations)
							metaPtr = &newMeta
						}
						if err := newLazy.ReplaceMetaAndSpliceSpecOntoOld(metaPtr, &mergedSpec, lazypod.SpecTagMaskContainers, oldLazy); err == nil {
							if !apiequality.Semantic.DeepEqual(mergedSpec, oldSubSpec) {
								newLazy.SetGeneration(newLazy.GetGeneration() + 1)
							}
							return
						}
					}
				}
			}
		}
	}
	newPod := ensureDecodedPod(obj)
	oldPod := ensureDecodedPod(old)

	*newPod = *dropNonResizeUpdates(newPod, oldPod)

	// When pod-level resources are set or updated via resize, apply defaulting
	// so any unmanaged resources (e.g. memory when only CPU existed) are complete and consistent.
	if utilfeature.DefaultFeatureGate.Enabled(features.PodLevelResourcesFixDefaulting) {
		if newPod.Spec.Resources == nil && oldPod.Spec.Resources != nil {
			// preserve existing PLR for requests from potentially PLR-unaware clients that completely dropped the field
			newPod.Spec.Resources = oldPod.Spec.Resources.DeepCopy()
		}

		if newPod.Spec.Resources != nil {
			podutil.DefaultPodLevelResources(newPod)
		}
	}

	podutil.DropDisabledPodFields(newPod, oldPod)
	updatePodGeneration(newPod, oldPod)
}

func (podResizeStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	if newLazy, ok1 := obj.(*lazypod.Pod); ok1 && newLazy.IsLazy() {
		if oldLazy, ok2 := old.(*lazypod.Pod); ok2 && oldLazy.IsLazy() {
			if specDiffMask, diffOK := newLazy.DiffSpecTagMask(oldLazy); diffOK &&
				(specDiffMask&^lazypod.SpecTagMaskContainers) == 0 &&
				!oldLazy.Wire().HasSpecResources() && !newLazy.Wire().HasSpecResources() &&
				validateFastPodResize(newLazy, oldLazy) {
				return nil
			}
		}
	}
	newPod := ensureDecodedPod(obj)
	oldPod := ensureDecodedPod(old)
	opts := corevalidation.GetValidationOptionsFromPodSpecAndMeta(&newPod.Spec, &oldPod.Spec, &newPod.ObjectMeta, &oldPod.ObjectMeta)
	opts.ResourceIsPod = true
	return corevalidation.ValidatePodResize(newPod, oldPod, opts)
}

func hasMatchingContainerOrder(newCtrs, oldCtrs []api.Container) bool {
	if len(newCtrs) != len(oldCtrs) {
		return false
	}
	for i := range oldCtrs {
		if newCtrs[i].Name != oldCtrs[i].Name {
			return false
		}
	}
	return true
}

func resizeResourcesRemoved(newList, oldList api.ResourceList) bool {
	if len(oldList) > len(newList) {
		return true
	}
	for name := range oldList {
		if _, ok := newList[name]; !ok {
			return true
		}
	}
	return false
}

func maskContainerCPUMemoryResources(ctr, oldCtr *api.Container) api.Container {
	masked := *ctr
	var lim, req api.ResourceList
	if ctr.Resources.Limits != nil || oldCtr.Resources.Limits != nil {
		lim = ctr.Resources.Limits.DeepCopy()
		if lim == nil {
			lim = make(api.ResourceList)
		}
		delete(lim, api.ResourceCPU)
		delete(lim, api.ResourceMemory)
		if v, ok := oldCtr.Resources.Limits[api.ResourceCPU]; ok {
			lim[api.ResourceCPU] = v
		}
		if v, ok := oldCtr.Resources.Limits[api.ResourceMemory]; ok {
			lim[api.ResourceMemory] = v
		}
	}
	if ctr.Resources.Requests != nil || oldCtr.Resources.Requests != nil {
		req = ctr.Resources.Requests.DeepCopy()
		if req == nil {
			req = make(api.ResourceList)
		}
		delete(req, api.ResourceCPU)
		delete(req, api.ResourceMemory)
		if v, ok := oldCtr.Resources.Requests[api.ResourceCPU]; ok {
			req[api.ResourceCPU] = v
		}
		if v, ok := oldCtr.Resources.Requests[api.ResourceMemory]; ok {
			req[api.ResourceMemory] = v
		}
	}
	masked.Resources = api.ResourceRequirements{Limits: lim, Requests: req, Claims: ctr.Resources.Claims}
	return masked
}

func validateFastPodResize(newLazy, oldLazy *lazypod.Pod) bool {
	var newMeta, oldMeta metav1.ObjectMeta
	newLazy.BorrowObjectMetaInto(&newMeta, false)
	oldLazy.BorrowObjectMetaInto(&oldMeta, true)
	if _, isMirror := oldMeta.Annotations[api.MirrorPodAnnotationKey]; isMirror {
		return false
	}
	if newMeta.Annotations[api.TolerationsAnnotationKey] != "" || hasDeprecatedAppArmorContainerAnnotation(newMeta.Annotations) {
		return false
	}
	if podOS := oldLazy.Wire().SpecOS(); podOS != nil && podOS.Name != api.Linux {
		return false
	}
	fldPath := field.NewPath("metadata")
	if len(corevalidation.ValidateObjectMetaUpdate(&newMeta, &oldMeta, fldPath)) > 0 {
		return false
	}
	if len(corevalidation.ValidateObjectMeta(&newMeta, true, corevalidation.ValidatePodName, fldPath)) > 0 {
		return false
	}
	var newSubSpec, oldSubSpec api.PodSpec
	if err := newLazy.Wire().ExtractCoreSpecSubtreeInto(lazypod.SpecTagMaskContainers, &newSubSpec); err != nil {
		return false
	}
	if err := oldLazy.Wire().ExtractCoreSpecSubtreeInto(lazypod.SpecTagMaskContainers, &oldSubSpec); err != nil {
		return false
	}
	if len(newSubSpec.Containers) == 0 ||
		!hasMatchingContainerOrder(newSubSpec.Containers, oldSubSpec.Containers) ||
		!hasMatchingContainerOrder(newSubSpec.InitContainers, oldSubSpec.InitContainers) {
		return false
	}
	oldQOS := oldLazy.Wire().StatusQOSClass()
	if oldQOS == "" {
		oldQOS = qos.ComputePodQOS(&api.Pod{Spec: oldSubSpec})
	}
	if oldQOS != qos.ComputePodQOS(&api.Pod{Spec: newSubSpec}) {
		return false
	}
	opts := corevalidation.GetValidationOptionsFromPodSpecAndMeta(&newSubSpec, &oldSubSpec, &newMeta, &oldMeta)
	opts.ResourceIsPod = true
	specPath := field.NewPath("spec")
	for i := range newSubSpec.Containers {
		newCtr, oldCtr := &newSubSpec.Containers[i], &oldSubSpec.Containers[i]
		if apiequality.Semantic.DeepEqual(*newCtr, *oldCtr) {
			continue
		}
		if len(newCtr.Resources.Claims) > 0 ||
			resizeResourcesRemoved(newCtr.Resources.Requests, oldCtr.Resources.Requests) ||
			resizeResourcesRemoved(newCtr.Resources.Limits, oldCtr.Resources.Limits) {
			return false
		}
		if len(corevalidation.ValidateContainerResourceRequirements(&newCtr.Resources, nil, specPath.Child("containers").Index(i).Child("resources"), opts)) > 0 {
			return false
		}
		if !apiequality.Semantic.DeepEqual(maskContainerCPUMemoryResources(newCtr, oldCtr), *oldCtr) {
			return false
		}
	}
	allowInitResize := utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScalingInitContainers)
	for i := range newSubSpec.InitContainers {
		newCtr, oldCtr := &newSubSpec.InitContainers[i], &oldSubSpec.InitContainers[i]
		if apiequality.Semantic.DeepEqual(*newCtr, *oldCtr) {
			continue
		}
		isSidecar := podutil.IsRestartableInitContainer(newCtr)
		if !isSidecar && !allowInitResize {
			return false
		}
		if !isSidecar {
			for _, rp := range newCtr.ResizePolicy {
				if rp.RestartPolicy == api.RestartContainer {
					return false
				}
			}
		}
		if len(newCtr.Resources.Claims) > 0 ||
			resizeResourcesRemoved(newCtr.Resources.Requests, oldCtr.Resources.Requests) ||
			resizeResourcesRemoved(newCtr.Resources.Limits, oldCtr.Resources.Limits) {
			return false
		}
		if len(corevalidation.ValidateContainerResourceRequirements(&newCtr.Resources, nil, specPath.Child("initContainers").Index(i).Child("resources"), opts)) > 0 {
			return false
		}
		if !apiequality.Semantic.DeepEqual(maskContainerCPUMemoryResources(newCtr, oldCtr), *oldCtr) {
			return false
		}
	}
	return true
}

// WarningsOnUpdate returns warnings for the given update.
func (podResizeStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// GetResetFieldsFilter returns a set of fields filter reset by the strategy
// and should not be modified by the user.
func (p podResizeStrategy) GetResetFieldsFilter() map[fieldpath.APIVersion]fieldpath.Filter {
	return map[fieldpath.APIVersion]fieldpath.Filter{
		"v1": p.resetFieldsFilter,
	}
}

// GetAttrs returns labels and fields of a given object for filtering purposes.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	pod, ok := obj.(api.PodAccessor)
	if !ok {
		return nil, nil, fmt.Errorf("not a pod")
	}
	return labels.Set(pod.GetLabels()), ToSelectableFields(pod), nil
}

// MatchPod returns a generic matcher for a given label and field selector.
func MatchPod(label labels.Selector, field fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:       label,
		Field:       field,
		GetAttrs:    GetAttrs,
		IndexFields: []string{"spec.nodeName"},
	}
}

// NodeNameTriggerFunc returns value spec.nodename of given object.
func NodeNameTriggerFunc(obj runtime.Object) string {
	return obj.(api.PodAccessor).GetSpecNodeName()
}

// NodeNameIndexFunc return value spec.nodename of given object.
func NodeNameIndexFunc(obj interface{}) ([]string, error) {
	pod, ok := obj.(api.PodAccessor)
	if !ok {
		return nil, fmt.Errorf("not a pod")
	}
	return []string{pod.GetSpecNodeName()}, nil
}

// Indexers returns the indexers for pod storage.
func Indexers() *cache.Indexers {
	return &cache.Indexers{
		storage.FieldIndex("spec.nodeName"): NodeNameIndexFunc,
	}
}

// ToSelectableFields returns a field set that represents the object
// TODO: fields are not labels, and the validation rules for them do not apply.
func ToSelectableFields(pod api.PodAccessor) fields.Set {
	// The purpose of allocation with a given number of elements is to reduce
	// amount of allocations needed to create the fields.Set. If you add any
	// field here or the number of object-meta related fields changes, this should
	// be adjusted.
	podSpecificFieldsSet := make(fields.Set, 10)
	podSpecificFieldsSet["spec.nodeName"] = pod.GetSpecNodeName()
	podSpecificFieldsSet["spec.restartPolicy"] = string(pod.GetSpecRestartPolicy())
	podSpecificFieldsSet["spec.schedulerName"] = pod.GetSpecSchedulerName()
	podSpecificFieldsSet["spec.serviceAccountName"] = pod.GetSpecServiceAccountName()
	podSpecificFieldsSet["spec.hostNetwork"] = strconv.FormatBool(pod.GetSpecHostNetwork())
	podSpecificFieldsSet["status.phase"] = string(pod.GetStatusPhase())
	// TODO: add podIPs as a downward API value(s) with proper format
	podSpecificFieldsSet["status.podIP"] = pod.GetStatusFirstPodIP()
	podSpecificFieldsSet["status.nominatedNodeName"] = pod.GetStatusNominatedNodeName()
	return generic.AddObjectMetaFieldsSet(podSpecificFieldsSet, pod, true)
}

// ResourceGetter is an interface for retrieving resources by ResourceLocation.
type ResourceGetter interface {
	Get(context.Context, string, *metav1.GetOptions) (runtime.Object, error)
}

func getPod(ctx context.Context, getter ResourceGetter, name string) (api.PodAccessor, error) {
	obj, err := getter.Get(ctx, name, &metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if p, ok := obj.(*api.Pod); ok && p == nil {
		return nil, fmt.Errorf("Unexpected object type: %#v", p)
	}
	pod, ok := obj.(api.PodAccessor)
	if !ok || pod == nil {
		return nil, fmt.Errorf("Unexpected object type: %#v", obj)
	}
	return pod, nil
}

// getPodIP returns primary IP for a Pod
func getPodIP(pod api.PodAccessor) string {
	if pod == nil {
		return ""
	}
	return pod.GetStatusFirstPodIP()
}

// ResourceLocation returns a URL to which one can send traffic for the specified pod.
func ResourceLocation(ctx context.Context, getter ResourceGetter, rt http.RoundTripper, id string) (*url.URL, http.RoundTripper, error) {
	// Allow ID as "podname" or "podname:port" or "scheme:podname:port".
	// If port is not specified, try to use the first defined port on the pod.
	scheme, name, port, valid := utilnet.SplitSchemeNamePort(id)
	if !valid {
		return nil, nil, errors.NewBadRequest(fmt.Sprintf("invalid pod request %q", id))
	}

	pod, err := getPod(ctx, getter, name)
	if err != nil {
		return nil, nil, err
	}

	// Try to figure out a port.
	if port == "" {
		if firstPort := pod.GetFirstContainerPort(); firstPort != 0 {
			port = fmt.Sprintf("%d", firstPort)
		}
	}
	podIP := getPodIP(pod)
	if ip := netutils.ParseIPSloppy(podIP); ip == nil || !ip.IsGlobalUnicast() {
		return nil, nil, errors.NewBadRequest("address not allowed")
	}

	loc := &url.URL{
		Scheme: scheme,
	}
	if port == "" {
		// when using an ipv6 IP as a hostname in a URL, it must be wrapped in [...]
		// net.JoinHostPort does this for you.
		if strings.Contains(podIP, ":") {
			loc.Host = "[" + podIP + "]"
		} else {
			loc.Host = podIP
		}
	} else {
		loc.Host = net.JoinHostPort(podIP, port)
	}
	return loc, rt, nil
}

// LogLocation returns the log URL for a pod container. If opts.Container is blank
// and only one container is present in the pod, that container is used.
func LogLocation(
	ctx context.Context, getter ResourceGetter,
	connInfo client.ConnectionInfoGetter,
	name string,
	opts *api.PodLogOptions,
) (*url.URL, http.RoundTripper, error) {
	pod, err := getPod(ctx, getter, name)
	if err != nil {
		return nil, nil, err
	}

	// Try to figure out a container
	// If a container was provided, it must be valid
	container := opts.Container
	container, err = validateContainer(container, pod)
	if err != nil {
		return nil, nil, err
	}
	nodeName := types.NodeName(pod.GetSpecNodeName())
	if len(nodeName) == 0 {
		// If pod has not been assigned a host, return an empty location
		return nil, nil, nil
	}
	nodeInfo, err := connInfo.GetConnectionInfo(ctx, nodeName)
	if err != nil {
		return nil, nil, err
	}
	params := url.Values{}
	if opts.Follow {
		params.Add("follow", "true")
	}
	if opts.Previous {
		params.Add("previous", "true")
	}
	if opts.Timestamps {
		params.Add("timestamps", "true")
	}
	if opts.SinceSeconds != nil {
		params.Add("sinceSeconds", strconv.FormatInt(*opts.SinceSeconds, 10))
	}
	if opts.SinceTime != nil {
		params.Add("sinceTime", opts.SinceTime.Format(time.RFC3339))
	}
	if opts.TailLines != nil {
		params.Add("tailLines", strconv.FormatInt(*opts.TailLines, 10))
	}
	if opts.LimitBytes != nil {
		params.Add("limitBytes", strconv.FormatInt(*opts.LimitBytes, 10))
	}
	if utilfeature.DefaultFeatureGate.Enabled(features.PodLogsQuerySplitStreams) {
		// With defaulters, We can be confident that opts.Stream is not nil here.
		params.Add("stream", string(*opts.Stream))
	}
	loc := &url.URL{
		Scheme:   nodeInfo.Scheme,
		Host:     net.JoinHostPort(nodeInfo.Hostname, nodeInfo.Port),
		Path:     fmt.Sprintf("/containerLogs/%s/%s/%s", pod.GetNamespace(), pod.GetName(), container),
		RawQuery: params.Encode(),
	}

	if opts.InsecureSkipTLSVerifyBackend {
		return loc, nodeInfo.InsecureSkipTLSVerifyTransport, nil
	}
	return loc, nodeInfo.Transport, nil
}

func streamParams(params url.Values, opts runtime.Object) error {
	switch opts := opts.(type) {
	case *api.PodExecOptions:
		if opts.Stdin {
			params.Add(api.ExecStdinParam, "1")
		}
		if opts.Stdout {
			params.Add(api.ExecStdoutParam, "1")
		}
		if opts.Stderr {
			params.Add(api.ExecStderrParam, "1")
		}
		if opts.TTY {
			params.Add(api.ExecTTYParam, "1")
		}
		for _, c := range opts.Command {
			params.Add("command", c)
		}
	case *api.PodAttachOptions:
		if opts.Stdin {
			params.Add(api.ExecStdinParam, "1")
		}
		if opts.Stdout {
			params.Add(api.ExecStdoutParam, "1")
		}
		if opts.Stderr {
			params.Add(api.ExecStderrParam, "1")
		}
		if opts.TTY {
			params.Add(api.ExecTTYParam, "1")
		}
	case *api.PodPortForwardOptions:
		if len(opts.Ports) > 0 {
			ports := make([]string, len(opts.Ports))
			for i, p := range opts.Ports {
				ports[i] = strconv.FormatInt(int64(p), 10)
			}
			params.Add(api.PortHeader, strings.Join(ports, ","))
		}
	default:
		return fmt.Errorf("Unknown object for streaming: %v", opts)
	}
	return nil
}

// AttachLocation returns the attach URL for a pod container. If opts.Container is blank
// and only one container is present in the pod, that container is used.
func AttachLocation(
	ctx context.Context,
	getter ResourceGetter,
	connInfo client.ConnectionInfoGetter,
	name string,
	opts *api.PodAttachOptions,
) (*url.URL, *client.ConnectionInfo, error) {
	return streamLocation(ctx, getter, connInfo, name, opts, opts.Container, "attach")
}

// ExecLocation returns the exec URL for a pod container. If opts.Container is blank
// and only one container is present in the pod, that container is used.
func ExecLocation(
	ctx context.Context,
	getter ResourceGetter,
	connInfo client.ConnectionInfoGetter,
	name string,
	opts *api.PodExecOptions,
) (*url.URL, *client.ConnectionInfo, error) {
	return streamLocation(ctx, getter, connInfo, name, opts, opts.Container, "exec")
}

func streamLocation(
	ctx context.Context,
	getter ResourceGetter,
	connInfo client.ConnectionInfoGetter,
	name string,
	opts runtime.Object,
	container,
	path string,
) (*url.URL, *client.ConnectionInfo, error) {
	pod, err := getPod(ctx, getter, name)
	if err != nil {
		return nil, nil, err
	}

	// Try to figure out a container
	// If a container was provided, it must be valid
	container, err = validateContainer(container, pod)
	if err != nil {
		return nil, nil, err
	}

	nodeName := types.NodeName(pod.GetSpecNodeName())
	if len(nodeName) == 0 {
		// If pod has not been assigned a host, return an empty location
		return nil, nil, errors.NewBadRequest(fmt.Sprintf("pod %s does not have a host assigned", name))
	}
	nodeInfo, err := connInfo.GetConnectionInfo(ctx, nodeName)
	if err != nil {
		return nil, nil, err
	}
	params := url.Values{}
	if err := streamParams(params, opts); err != nil {
		return nil, nil, err
	}
	loc := &url.URL{
		Scheme:   nodeInfo.Scheme,
		Host:     net.JoinHostPort(nodeInfo.Hostname, nodeInfo.Port),
		Path:     fmt.Sprintf("/%s/%s/%s/%s", path, pod.GetNamespace(), pod.GetName(), container),
		RawQuery: params.Encode(),
	}
	return loc, nodeInfo, nil
}

// PortForwardLocation returns the port-forward URL for a pod.
func PortForwardLocation(
	ctx context.Context,
	getter ResourceGetter,
	connInfo client.ConnectionInfoGetter,
	name string,
	opts *api.PodPortForwardOptions,
) (*url.URL, *client.ConnectionInfo, error) {
	pod, err := getPod(ctx, getter, name)
	if err != nil {
		return nil, nil, err
	}

	nodeName := types.NodeName(pod.GetSpecNodeName())
	if len(nodeName) == 0 {
		// If pod has not been assigned a host, return an empty location
		return nil, nil, errors.NewBadRequest(fmt.Sprintf("pod %s does not have a host assigned", name))
	}
	nodeInfo, err := connInfo.GetConnectionInfo(ctx, nodeName)
	if err != nil {
		return nil, nil, err
	}
	params := url.Values{}
	if err := streamParams(params, opts); err != nil {
		return nil, nil, err
	}
	loc := &url.URL{
		Scheme:   nodeInfo.Scheme,
		Host:     net.JoinHostPort(nodeInfo.Hostname, nodeInfo.Port),
		Path:     fmt.Sprintf("/portForward/%s/%s", pod.GetNamespace(), pod.GetName()),
		RawQuery: params.Encode(),
	}
	return loc, nodeInfo, nil
}

// validateContainer validate container is valid for pod, return valid container
func validateContainer(container string, pod api.PodAccessor) (string, error) {
	resolved, ok, allNames := pod.ResolveContainer(container)
	if ok {
		return resolved, nil
	}
	if len(container) == 0 {
		if len(allNames) == 0 {
			return "", errors.NewBadRequest(fmt.Sprintf("a container name must be specified for pod %s", pod.GetName()))
		}
		errStr := fmt.Sprintf("a container name must be specified for pod %s, choose one of: %s", pod.GetName(), allNames)
		return "", errors.NewBadRequest(errStr)
	}
	return "", errors.NewBadRequest(fmt.Sprintf("container %s is not valid for pod %s", container, pod.GetName()))
}

// applyLabelKeysToLabelSelector obtains the label value from the given label set by the key in labelKeys,
// and merge to LabelSelector with the given operator:
func applyLabelKeysToLabelSelector(labelSelector *metav1.LabelSelector, labelKeys []string, operator metav1.LabelSelectorOperator, podLabels map[string]string) {
	for _, key := range labelKeys {
		if value, ok := podLabels[key]; ok {
			labelSelector.MatchExpressions = append(labelSelector.MatchExpressions, metav1.LabelSelectorRequirement{
				Key:      key,
				Operator: operator,
				Values:   []string{value},
			})
		}
	}
}

// applyMatchLabelKeysAndMismatchLabelKeys obtains the labels from the pod labels by the key in matchLabelKeys or mismatchLabelKeys,
// and merge to LabelSelector of PodAffinityTerm depending on field:
// - If matchLabelKeys, key in (value) is merged with LabelSelector.
// - If mismatchLabelKeys, key notin (value) is merged with LabelSelector.
func applyMatchLabelKeysAndMismatchLabelKeys(term *api.PodAffinityTerm, label map[string]string) {
	if (len(term.MatchLabelKeys) == 0 && len(term.MismatchLabelKeys) == 0) || term.LabelSelector == nil {
		// If LabelSelector is nil, we don't need to apply label keys to it because nil-LabelSelector is match none.
		return
	}

	applyLabelKeysToLabelSelector(term.LabelSelector, term.MatchLabelKeys, metav1.LabelSelectorOpIn, label)
	applyLabelKeysToLabelSelector(term.LabelSelector, term.MismatchLabelKeys, metav1.LabelSelectorOpNotIn, label)
}

func mutatePodAffinity(pod *api.Pod) {
	if pod.Spec.Affinity == nil {
		return
	}
	if affinity := pod.Spec.Affinity.PodAffinity; affinity != nil {
		for i := range affinity.PreferredDuringSchedulingIgnoredDuringExecution {
			applyMatchLabelKeysAndMismatchLabelKeys(&affinity.PreferredDuringSchedulingIgnoredDuringExecution[i].PodAffinityTerm, pod.Labels)
		}
		for i := range affinity.RequiredDuringSchedulingIgnoredDuringExecution {
			applyMatchLabelKeysAndMismatchLabelKeys(&affinity.RequiredDuringSchedulingIgnoredDuringExecution[i], pod.Labels)
		}
	}
	if affinity := pod.Spec.Affinity.PodAntiAffinity; affinity != nil {
		for i := range affinity.PreferredDuringSchedulingIgnoredDuringExecution {
			applyMatchLabelKeysAndMismatchLabelKeys(&affinity.PreferredDuringSchedulingIgnoredDuringExecution[i].PodAffinityTerm, pod.Labels)
		}
		for i := range affinity.RequiredDuringSchedulingIgnoredDuringExecution {
			applyMatchLabelKeysAndMismatchLabelKeys(&affinity.RequiredDuringSchedulingIgnoredDuringExecution[i], pod.Labels)
		}
	}
}

func applyMatchLabelKeys(constraint *api.TopologySpreadConstraint, labels map[string]string) {
	if len(constraint.MatchLabelKeys) == 0 || constraint.LabelSelector == nil {
		// If LabelSelector is nil, we don't need to apply label keys to it because nil-LabelSelector is match none.
		return
	}

	applyLabelKeysToLabelSelector(constraint.LabelSelector, constraint.MatchLabelKeys, metav1.LabelSelectorOpIn, labels)
}

func mutateTopologySpreadConstraints(pod *api.Pod) {
	if !utilfeature.DefaultFeatureGate.Enabled(features.MatchLabelKeysInPodTopologySpread) || !utilfeature.DefaultFeatureGate.Enabled(features.MatchLabelKeysInPodTopologySpreadSelectorMerge) || pod.Spec.TopologySpreadConstraints == nil {
		return
	}
	topologySpreadConstraints := pod.Spec.TopologySpreadConstraints
	for i := range topologySpreadConstraints {
		applyMatchLabelKeys(&topologySpreadConstraints[i], pod.Labels)
	}
}

// applySchedulingGatedCondition adds a {type:PodScheduled, reason:SchedulingGated} condition
// to a new-created Pod if necessary.
func applySchedulingGatedCondition(pod *api.Pod) {
	if len(pod.Spec.SchedulingGates) == 0 {
		return
	}

	// If found a condition with type PodScheduled, return.
	for _, condition := range pod.Status.Conditions {
		if condition.Type == api.PodScheduled {
			return
		}
	}

	podutil.UpdatePodCondition(&pod.Status, &api.PodCondition{
		Type:    api.PodScheduled,
		Status:  api.ConditionFalse,
		Reason:  apiv1.PodReasonSchedulingGated,
		Message: "Scheduling is blocked due to non-empty scheduling gates",
	})
}

// applyAppArmorVersionSkew implements the version skew behavior described in:
// https://github.com/kubernetes/enhancements/tree/master/keps/sig-node/24-apparmor#version-skew-strategy
func applyAppArmorVersionSkew(ctx context.Context, pod *api.Pod) {
	if pod.Spec.OS != nil && pod.Spec.OS.Name == api.Windows {
		return
	}

	var podProfile *api.AppArmorProfile
	if pod.Spec.SecurityContext != nil {
		podProfile = pod.Spec.SecurityContext.AppArmorProfile
	}

	// Handle the containers of the pod
	podutil.VisitContainers(&pod.Spec, podutil.AllFeatureEnabledContainers(),
		func(ctr *api.Container, _ podutil.ContainerType) bool {
			// get possible annotation and field
			key := api.DeprecatedAppArmorAnnotationKeyPrefix + ctr.Name
			annotation, hasAnnotation := pod.Annotations[key]

			var containerProfile *api.AppArmorProfile
			if ctr.SecurityContext != nil {
				containerProfile = ctr.SecurityContext.AppArmorProfile
			}

			// Sync deprecated AppArmor annotations to fields
			if hasAnnotation && containerProfile == nil {
				newField := podutil.ApparmorFieldForAnnotation(annotation)
				if errs := corevalidation.ValidateAppArmorProfileField(newField, &field.Path{}); len(errs) > 0 {
					// Skip copying invalid value.
					newField = nil
				}

				// warn if we had an annotation that we couldn't derive a valid field from
				deprecationWarning := newField == nil

				// Only copy the annotation to the field if it is different from the pod-level profile.
				if newField != nil && !apiequality.Semantic.DeepEqual(newField, podProfile) {
					if ctr.SecurityContext == nil {
						ctr.SecurityContext = &api.SecurityContext{}
					}
					ctr.SecurityContext.AppArmorProfile = newField
					// warn if there was an annotation without a corresponding field
					deprecationWarning = true
				}

				if deprecationWarning {
					// Note: annotation deprecation warning must be added here rather than the
					// typical WarningsOnCreate path to emit the warning before syncing the
					// annotations & fields.
					fldPath := field.NewPath("metadata", "annotations").Key(key)
					warning.AddWarning(ctx, "", fmt.Sprintf(`%s: deprecated since v1.30; use the "appArmorProfile" field instead`, fldPath))
				}
			}

			return true
		})
}

// updatePodGeneration bumps metadata.generation if needed for any updates
// to the podspec.
func updatePodGeneration(newPod, oldPod *api.Pod) {
	if !apiequality.Semantic.DeepEqual(newPod.Spec, oldPod.Spec) {
		newPod.Generation++
	}
}

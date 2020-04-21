/*
Copyright 2020 The Kubernetes Authors.

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

package gvisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/core/pods"
	"k8s.io/kubernetes/pkg/apis/node"
)

const (
	// PluginName indicates name of admission plugin.
	PluginName = "Gvisor"

	// gvisorNodeKey is the key for gvisor node label and taint after beta.
	gvisorNodeKey = "sandbox.gke.io/runtime"
	// gvisorNodeValue is the value for gvisor node label and taint.
	gvisorNodeValue = "gvisor"

	// gvisorRuntimeClass is the name of the gvisor runtime class.
	gvisorRuntimeClass = "gvisor"

	subresEphemeralContainers = "ephemeralcontainers"

	annotationPrefix = "dev.gvisor."

	// Annotation keys for gvisor mount.
	mountAnnotationPrefix = annotationPrefix + "spec.mount."
	mountShareKey         = mountAnnotationPrefix + "%s.share"
	mountTypeKey          = mountAnnotationPrefix + "%s.type"
	mountOptionsKey       = mountAnnotationPrefix + "%s.options"

	// Internal annotations.
	internalAnnotationPrefix = annotationPrefix + "internal."
	seccompKey               = internalAnnotationPrefix + "seccomp."

	// Accelerator annotations.
	nvidiaAnnotation = internalAnnotationPrefix + "nvproxy"
	tpuAnnotation    = internalAnnotationPrefix + "tpuproxy"
)

var (
	// deprecatedAnnotations are old annotations not allowed anymore.
	deprecatedAnnotations = map[string]string{
		"runtime-handler.cri.kubernetes.io":    "gvisor", // Used during Alpha.
		"io.kubernetes.cri.untrusted-workload": "true",   // Used during Dogfood.
	}

	// disallowedCapabilities contains capabilities to be dropped if not
	// explicitly added by users.
	disallowedCapabilities = []core.Capability{"NET_RAW"}

	// Accelerator resource request names.
	gpuResourceName = core.ResourceName("nvidia.com/gpu")
	tpuResourceName = core.ResourceName("google.com/tpu")
)

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		return new(), nil
	})
}

func new() *Gvisor {
	return &Gvisor{
		Handler: admission.NewHandler(admission.Create, admission.Update),
	}
}

// Gvisor is an implementation of admission.Interface.
type Gvisor struct {
	*admission.Handler
}

var _ admission.MutationInterface = (*Gvisor)(nil)
var _ admission.ValidationInterface = (*Gvisor)(nil)

// checkDeprecatedAnnotation determines whether a pod contains any of the set of
// deprecated, disallowed annotations
func checkDeprecatedAnnotation(pod *core.Pod) error {
	for k, v := range deprecatedAnnotations {
		if pod.Annotations[k] == v {
			return fmt.Errorf("annotation %q is deprecated. Use %q instead", k, "PodSpec.runtimeClassName: gvisor")
		}
	}
	return nil
}

// Admit determines whether a gvisor pod can be created, and modifies the pod
// in the request as needed
func (r *Gvisor) Admit(_ context.Context, attributes admission.Attributes, _ admission.ObjectInterfaces) error {
	res := attributes.GetResource()
	if res.Group == "" && res.Resource == "pods" {
		switch attributes.GetOperation() {
		case admission.Create:
			if len(attributes.GetSubresource()) == 0 {
				return admitPodCreate(attributes)
			}
		case admission.Update:
			if attributes.GetSubresource() == subresEphemeralContainers {
				return admitEphemeralContainer(attributes)
			}
		}
	}
	return nil
}

// Validate makes sure that a pod/runtimeclass adheres to Gvisor's definition
func (r *Gvisor) Validate(_ context.Context, attributes admission.Attributes, _ admission.ObjectInterfaces) error {
	res := attributes.GetResource()
	switch {
	case res.Group == "" && res.Resource == "pods":
		switch attributes.GetSubresource() {
		case "", "status", subresEphemeralContainers:
			return validatePod(attributes)
		}
	case res.Group == "node.k8s.io" && res.Resource == "runtimeclasses" && len(attributes.GetSubresource()) == 0:
		return validateRuntimeClass(attributes)
	}
	return nil
}

func validatePod(attributes admission.Attributes) error {
	pod, err := getPod(attributes.GetObject())
	if err != nil {
		return admission.NewForbidden(attributes, err)
	}
	if err := checkDeprecatedAnnotation(pod); err != nil {
		return admission.NewForbidden(attributes, err)
	}

	switch attributes.GetOperation() {
	case admission.Create:
		return validatePodCreate(attributes, pod)

	case admission.Update:
		oldPod, err := getPod(attributes.GetOldObject())
		if err != nil {
			return admission.NewForbidden(attributes, err)
		}
		return validatePodUpdate(attributes, oldPod, pod)
	}
	return nil
}

// admitPodCreate performs some validation on the incoming object, and if
// it is a gvisor pod creation request, mutates the pod as necessary.
func admitPodCreate(attributes admission.Attributes) error {
	pod, err := getPod(attributes.GetObject())
	if err != nil {
		return admission.NewForbidden(attributes, err)
	}
	if err := checkDeprecatedAnnotation(pod); err != nil {
		return admission.NewForbidden(attributes, err)
	}
	if !isGvisorPod(pod) {
		// Pod is not a gVisor pod, there is nothing else to do.
		return nil
	}

	if err := validateGVisorPod(pod); err != nil {
		return admission.NewForbidden(attributes, err)
	}
	mutateGVisorPod(pod)
	// Check that pod didn't have other annotations that aren't allowed.
	if err := checkAnnotations(pod, pod.Annotations, nil, true); err != nil {
		return admission.NewForbidden(attributes, err)
	}
	return nil
}

// admitEphemeralContainer handles the dynamic addition of ephemeral containers
// mutating them to apply the same rules as init and regular containers.
func admitEphemeralContainer(attributes admission.Attributes) error {
	oldPod, err := getPod(attributes.GetOldObject())
	if err != nil {
		return admission.NewForbidden(attributes, err)
	}
	pod, err := getPod(attributes.GetObject())
	if err != nil {
		return admission.NewForbidden(attributes, err)
	}
	if !isGvisorPod(oldPod) && !isGvisorPod(pod) {
		// Neither pod is a gVisor pod, there is nothing else to do.
		return nil
	}
	if !isGvisorPod(oldPod) || !isGvisorPod(pod) {
		return admission.NewForbidden(attributes, errors.New("runtimeClassName cannot be changed"))
	}

	for _, added := range findNewContainers(oldPod.Spec.EphemeralContainers, pod.Spec.EphemeralContainers) {
		c := (*core.Container)(&pod.Spec.EphemeralContainers[added].EphemeralContainerCommon)
		updateCapabilities(c)
	}
	return nil
}

// findNewContainers returns the indexes of all containers that have been added
// between old and new.
func findNewContainers(old, new []core.EphemeralContainer) []int {
	names := make(map[string]struct{})
	for _, cont := range old {
		names[cont.Name] = struct{}{}
	}
	var idxs []int
	for i, cont := range new {
		if _, ok := names[cont.Name]; !ok {
			idxs = append(idxs, i)
		}
	}
	return idxs
}

// mutateGVisorPod is a helper function that modifies a pod object to meet
// gVisor specifications.
func mutateGVisorPod(pod *core.Pod) {
	updatePodCapabilities(pod)
	updateVolumePodAnnotations(pod)
	updateSeccompAnnotations(pod)
	updateAcceleratorAnnotations(pod)
}

// updatePodCapabilities updates capabilities for given containers
func updatePodCapabilities(pod *core.Pod) {
	pods.VisitContainersWithPath(&pod.Spec, field.NewPath("spec"), func(c *core.Container, _ *field.Path) bool {
		updateCapabilities(c)
		return true
	})
}

func updateCapabilities(c *core.Container) {
	if c.SecurityContext == nil {
		c.SecurityContext = &core.SecurityContext{}
	}
	if c.SecurityContext.Capabilities == nil {
		c.SecurityContext.Capabilities = &core.Capabilities{}
	}
	if hasCapability("ALL", c.SecurityContext.Capabilities.Add) ||
		hasCapability("ALL", c.SecurityContext.Capabilities.Drop) {
		return
	}
	for _, capToDrop := range disallowedCapabilities {
		if !hasCapability(capToDrop, c.SecurityContext.Capabilities.Add) &&
			!hasCapability(capToDrop, c.SecurityContext.Capabilities.Drop) {
			c.SecurityContext.Capabilities.Drop = append(c.SecurityContext.Capabilities.Drop, capToDrop)
		}
	}
}

// hasCapability checks whether a given cap is in the cap list.
func hasCapability(cap core.Capability, caps []core.Capability) bool {
	for _, c := range caps {
		if strings.EqualFold(string(cap), string(c)) {
			return true
		}
	}
	return false
}

// updateVolumePodAnnotations puts volume information into gvisor specific pod
// annotations. This is mainly for optimizing volume performance.
func updateVolumePodAnnotations(pod *core.Pod) {
	addAnnotations(pod, getVolumeAnnotations(pod))
}

func getVolumeAnnotations(pod *core.Pod) map[string]string {
	rv := make(map[string]string)
	for _, v := range pod.Spec.Volumes {
		info, ok := checkVolume(v, pod)
		if !ok {
			continue
		}
		rv[fmt.Sprintf(mountShareKey, v.Name)] = info.share
		rv[fmt.Sprintf(mountTypeKey, v.Name)] = info.mountType
		mode := "rw"
		if info.readOnly {
			mode = "ro"
		}
		rv[fmt.Sprintf(mountOptionsKey, v.Name)] = strings.Join([]string{mode, info.propagation}, ",")
	}
	return rv
}

// mountInfo holds mount info for gVisor specific mount.
type mountInfo struct {
	share       string
	mountType   string
	propagation string
	readOnly    bool
}

// checkVolume checks whether a volume requires gVisor specific mount.
// For this optimization, gVisor currently only supports a
// single volume mounted into different containers with exactly
// the same mount option.
func checkVolume(v core.Volume, pod *core.Pod) (mountInfo, bool) {
	// Currently only emptydir can be optimized.
	if v.EmptyDir == nil {
		return mountInfo{}, false
	}
	mountType, err := getMountType(v.EmptyDir.Medium)
	if err != nil {
		return mountInfo{}, false
	}

	info := mountInfo{
		mountType: mountType,
		readOnly:  true,
	}
	mountNum := 0
	ok := pods.VisitContainersWithPath(&pod.Spec, field.NewPath("spec"), func(c *core.Container, _ *field.Path) bool {
		m := findVolumeMount(c, v.Name)
		if m == nil {
			// Volume is not used by this container, skip to the next...
			return true
		}
		if m.SubPath != "" || m.SubPathExpr != "" {
			// TODO(b/142076984): gVisor currently doesn't handle subpath mounts.
			return false
		}

		cpropagation := "rprivate"
		if m.MountPropagation != nil &&
			*m.MountPropagation == core.MountPropagationHostToContainer {
			cpropagation = "rslave"
		}
		if info.propagation != "" && info.propagation != cpropagation {
			return false
		}
		info.propagation = cpropagation

		if !m.ReadOnly {
			// If any of the containers can write to the emptydir, the master mount
			// must be read-write.
			info.readOnly = false
		}
		mountNum++
		return true
	})
	if !ok {
		return mountInfo{}, false
	}

	switch {
	case mountNum == 1:
		info.share = "container"
	case mountNum > 1:
		info.share = "pod"
	default:
		// Skip this because no container mounts this volume.
		return mountInfo{}, false
	}
	return info, true
}

func findVolumeMount(c *core.Container, name string) *core.VolumeMount {
	for _, m := range c.VolumeMounts {
		if m.Name == name {
			return &m
		}
	}
	return nil
}

func getMountType(medium core.StorageMedium) (string, error) {
	switch medium {
	case core.StorageMediumMemory, core.StorageMediumHugePages:
		// gVisor doesn't support huge pages, but tmpfs is the closest mapping.
		return "tmpfs", nil
	case core.StorageMediumDefault:
		return "bind", nil
	default:
		return "", fmt.Errorf("unsupported StorageMedium %v", medium)
	}
}

func updateSeccompAnnotations(pod *core.Pod) {
	addAnnotations(pod, getSeccompAnnotations(pod))
}

func addAnnotations(pod *core.Pod, add map[string]string) {
	for key, val := range add {
		if pod.Annotations == nil {
			pod.Annotations = make(map[string]string)
		}
		pod.Annotations[key] = val
	}
}

func getSeccompAnnotations(pod *core.Pod) map[string]string {
	rv := make(map[string]string)

	var podSeccomp core.SeccompProfileType
	if secCtx := pod.Spec.SecurityContext; secCtx != nil {
		if profile := secCtx.SeccompProfile; profile != nil {
			podSeccomp = profile.Type
		}
	}

	pods.VisitContainersWithPath(&pod.Spec, field.NewPath("spec"), func(c *core.Container, _ *field.Path) bool {
		seccomp := seccompForContainer(c, podSeccomp)
		if seccomp == core.SeccompProfileTypeRuntimeDefault {
			rv[seccompKey+c.Name] = string(seccomp)
		}
		return true
	})
	return rv
}

func seccompForContainer(cont *core.Container, podSeccomp core.SeccompProfileType) core.SeccompProfileType {
	if secCtx := cont.SecurityContext; secCtx != nil {
		if profile := secCtx.SeccompProfile; profile != nil {
			if len(profile.Type) > 0 {
				return profile.Type
			}
		}
	}
	// Container doesn't specify it, defaults to the pod.
	return podSeccomp
}

func updateAcceleratorAnnotations(pod *core.Pod) {
	addAnnotations(pod, getAcceleratorAnnotations(pod))
}

func getAcceleratorAnnotations(pod *core.Pod) map[string]string {
	rv := make(map[string]string)
	pods.VisitContainersWithPath(&pod.Spec, field.NewPath("spec"), func(c *core.Container, _ *field.Path) bool {
		if containerHasResourceRequestsAndLimits(c, gpuResourceName) {
			rv[nvidiaAnnotation] = "true"
		}

		if containerHasResourceRequestsAndLimits(c, tpuResourceName) {
			rv[tpuAnnotation] = "true"
		}
		return true
	})
	return rv
}

func containerHasResourceRequestsAndLimits(c *core.Container, name core.ResourceName) bool {
	if res, ok := c.Resources.Limits[name]; ok && !res.IsZero() {
		return true
	}
	if res, ok := c.Resources.Requests[name]; ok && !res.IsZero() {
		return true
	}
	return false
}

// getPod is an utility function that casts the object to core.Pod and returns
// an API error if it fails.
func getPod(obj runtime.Object) (*core.Pod, error) {
	// Verify that the object is indeed a Pod.
	pod, ok := obj.(*core.Pod)
	if !ok {
		return nil, apierrors.NewBadRequest("Resource was marked with kind Pod but was unable to be converted")
	}
	return pod, nil
}

// isGvisorPod returns true if this pod has been annotated with the gVisor
// runtime class name.
func isGvisorPod(pod *core.Pod) bool {
	rc := pod.Spec.RuntimeClassName
	return rc != nil && *rc == gvisorRuntimeClass
}

// validatePodCreate determines whether a pod create request is valid
func validatePodCreate(attributes admission.Attributes, pod *core.Pod) error {
	if !isGvisorPod(pod) {
		// Pod is not a gVisor pod, there is nothing else to do.
		return nil
	}
	if err := validateGVisorPod(pod); err != nil {
		return admission.NewForbidden(attributes, err)
	}
	if err := checkAnnotations(pod, pod.Annotations, nil, true); err != nil {
		return admission.NewForbidden(attributes, err)
	}
	return nil
}

// validatePodUpdate determines whether a pod update request is valid
func validatePodUpdate(attributes admission.Attributes, oldPod, pod *core.Pod) error {
	if !isGvisorPod(oldPod) && !isGvisorPod(pod) {
		// Neither pod is a gVisor pod, there is nothing else to do.
		return nil
	}

	switch attributes.GetSubresource() {
	case "", "status":
		if !isGvisorPod(oldPod) || !isGvisorPod(pod) {
			return admission.NewForbidden(attributes, errors.New("runtimeClassName cannot be changed"))
		}
		add, del := annotationDiff(oldPod, pod)
		if len(add) > 0 || len(del) > 0 {
			if err := checkAnnotations(pod, add, del, false); err != nil {
				return admission.NewForbidden(attributes, err)
			}
		}

	case subresEphemeralContainers:
		for _, added := range findNewContainers(oldPod.Spec.EphemeralContainers, pod.Spec.EphemeralContainers) {
			c := (*core.Container)(&pod.Spec.EphemeralContainers[added].EphemeralContainerCommon)
			if err := validateContainer(c); err != nil {
				return admission.NewForbidden(attributes, err)
			}
		}
	}

	// RuntimeClassName is immutable, so no need to perform additional validation.
	return nil
}

// Returns annotations that have been added and removed from the pod, in this
// order. Annotation that have changed are only considered added.
func annotationDiff(old *core.Pod, new *core.Pod) (map[string]string, map[string]string) {
	add := make(map[string]string)
	del := make(map[string]string)
	for key, val := range new.Annotations {
		if oldVal, ok := old.Annotations[key]; !ok || val != oldVal {
			add[key] = val
		}
	}
	for key, val := range old.Annotations {
		if _, ok := new.Annotations[key]; !ok {
			del[key] = val
		}
	}
	return add, del
}

// validateGVisorPod validates whether the pod is eligible to run in gVisor.
//  1. Pods with host path are not allowed.
//  2. Pods with host namespace are not allowed.
func validateGVisorPod(pod *core.Pod) error {
	if pod.Spec.NodeSelector != nil {
		if v, ok := pod.Spec.NodeSelector[gvisorNodeKey]; ok && v != gvisorNodeValue {
			return fmt.Errorf("conflict: pod.spec.nodeSelector[%q] = %q; it must be removed or set to %q", gvisorNodeKey, v, gvisorNodeValue)
		}
	}
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			return fmt.Errorf("HostPath is not allowed: %q", v.HostPath.Path)
		}
	}
	if pod.Spec.SecurityContext != nil {
		if pod.Spec.SecurityContext.HostNetwork {
			return fmt.Errorf("HostNetwork is not allowed")
		}
		if pod.Spec.SecurityContext.HostPID {
			return fmt.Errorf("HostPID is not allowed")
		}
		if pod.Spec.SecurityContext.HostIPC {
			return fmt.Errorf("HostIPC is not allowed")
		}
		if pod.Spec.SecurityContext.SELinuxOptions != nil {
			return fmt.Errorf("SELinuxOptions is not supported")
		}
		if len(pod.Spec.SecurityContext.Sysctls) > 0 {
			return fmt.Errorf("Sysctls is not supported")
		}
		if profile := pod.Spec.SecurityContext.SeccompProfile; profile != nil {
			if profile.Type != core.SeccompProfileTypeUnconfined && profile.Type != core.SeccompProfileTypeRuntimeDefault {
				return fmt.Errorf("only Unconfined and RuntimeDefault seccomp profiles are supported")
			}
		}
	}
	for k := range pod.Annotations {
		if strings.HasPrefix(k, "container.apparmor.security.beta.kubernetes.io") {
			return fmt.Errorf("Apparmor is not supported")
		}
		if strings.HasPrefix(k, "seccomp.security.alpha.kubernetes.io") {
			return fmt.Errorf("Seccomp via annotations is not supported; use pod SecurityContext")
		}
		if strings.HasPrefix(k, "container.seccomp.security.alpha.kubernetes.io") {
			return fmt.Errorf("Seccomp via annotations is not supported; use pod SecurityContext")
		}
	}

	var containerErr error
	pods.VisitContainersWithPath(&pod.Spec, field.NewPath("spec"), func(c *core.Container, _ *field.Path) bool {
		containerErr = validateContainer(c)
		// Visit containers until an error is found.
		return containerErr == nil
	})
	return containerErr
}

func validateContainer(c *core.Container) error {
	if c.SecurityContext != nil {
		if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			return fmt.Errorf("Privileged=true is not supported")
		}
		if c.SecurityContext.SELinuxOptions != nil {
			return fmt.Errorf("SELinuxOptions is not supported")
		}
		if c.SecurityContext.AllowPrivilegeEscalation != nil && *c.SecurityContext.AllowPrivilegeEscalation {
			return fmt.Errorf("AllowPrivilegeEscalation=true is not supported")
		}
		if c.SecurityContext.ProcMount != nil && *c.SecurityContext.ProcMount != core.DefaultProcMount {
			return fmt.Errorf("ProcMount=%s is not supported", *c.SecurityContext.ProcMount)
		}
		if profile := c.SecurityContext.SeccompProfile; profile != nil {
			if profile.Type != core.SeccompProfileTypeUnconfined && profile.Type != core.SeccompProfileTypeRuntimeDefault {
				return fmt.Errorf("only Unconfined and RuntimeDefault seccomp profiles are supported")
			}
		}
	}
	if len(c.VolumeDevices) != 0 {
		return fmt.Errorf("VolumeDevices is not supported")
	}
	for _, m := range c.VolumeMounts {
		if m.MountPropagation != nil &&
			*m.MountPropagation != core.MountPropagationNone &&
			*m.MountPropagation != core.MountPropagationHostToContainer {
			return fmt.Errorf("MountPropagation=%s is not supported", *m.MountPropagation)
		}
	}
	return nil
}

func checkAnnotations(pod *core.Pod, add, del map[string]string, all bool) error {
	if err := checkAnnotationsHelper(getVolumeAnnotations(pod), mountAnnotationPrefix, add, del, all); err != nil {
		return err
	}

	internalAnnotations := getSeccompAnnotations(pod)
	for k, v := range getAcceleratorAnnotations(pod) {
		internalAnnotations[k] = v
	}
	return checkAnnotationsHelper(internalAnnotations, internalAnnotationPrefix, add, del, all)
}

func checkAnnotationsHelper(allowed map[string]string, prefix string, add, del map[string]string, all bool) error {
	for key, val := range add {
		if strings.HasPrefix(key, prefix) {
			if wantVal, ok := allowed[key]; !ok {
				return fmt.Errorf("user annotations starting with %q are not allowed", prefix)
			} else if wantVal != val {
				return fmt.Errorf(`invalid annotation '%s: %q', expected value: %q`, key, val, wantVal)
			}
			delete(allowed, key)
		}
	}
	// If caller requested all, ensure that all allowed annotations are present.
	if all && len(allowed) > 0 {
		for key, val := range allowed {
			// Pick the first one for the error message.
			return fmt.Errorf(`annotation was removed from pod '%s: %q'`, key, val)
		}
	}

	// Check that none of the annotations that should be present has been removed.
	for key, val := range del {
		if _, ok := allowed[key]; ok {
			return fmt.Errorf(`annotation was removed from pod '%s: %q'`, key, val)
		}
	}

	return nil
}

// validateRuntimeClass performs admission checks on RuntimeClass resources. We
// only care about the gVisor, so all other runtimeclasses are ignored.
func validateRuntimeClass(attributes admission.Attributes) error {
	// Ignore non-gvisor runtime classes.
	if attributes.GetName() != gvisorRuntimeClass {
		return nil
	}
	// Verify that the object is indeed a runtimeclass.
	rc, ok := attributes.GetObject().(*node.RuntimeClass)
	if !ok {
		return apierrors.NewBadRequest("Resource was marked with kind RuntimeClass but was unable to be converted")
	}
	// If this is the gvisor RuntimeClass, its runtimeHandler MUST also be gvisor.
	if rc.Handler != gvisorRuntimeClass {
		return admission.NewForbidden(attributes, admission.NewForbidden(attributes, fmt.Errorf("gvisor RuntimeClass cannot have a non-gvisor Handler: %s", rc.Handler)))
	}
	return nil
}

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

package v1

import (
	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/util/parsers"
	"k8s.io/utils/ptr"
)

// PodDefaulter abstracts read/write access to Pod sub-structures so the same defaulting
// logic can run against both eager *v1.Pod structs and alternative Pod representations.
//
// +k8s:deepcopy-gen=false
type PodDefaulter interface {
	Spec() PodSpecDefaulter
	Status() PodStatusDefaulter
}

// PodSpecDefaulter provides getters and setters for PodSpec defaulting.
//
// +k8s:deepcopy-gen=false
type PodSpecDefaulter interface {
	GetDNSPolicy() v1.DNSPolicy
	SetDNSPolicy(v1.DNSPolicy)
	GetRestartPolicy() v1.RestartPolicy
	SetRestartPolicy(v1.RestartPolicy)
	HasSecurityContext() bool
	InitEmptySecurityContext()
	GetTerminationGracePeriodSeconds() (int64, bool)
	SetTerminationGracePeriodSeconds(int64)
	GetServiceAccountName() string
	SetServiceAccountName(string)
	GetDeprecatedServiceAccount() string
	SetDeprecatedServiceAccount(string)
	HasEnableServiceLinks() bool
	SetEnableServiceLinks(bool)
	GetSchedulerName() string
	SetSchedulerName(string)
	GetHostNetwork() bool

	NumVolumes() int
	Volume(i int) VolumeDefaulter
	NumContainers() int
	Container(i int) ContainerDefaulter
	NumInitContainers() int
	InitContainer(i int) ContainerDefaulter
}

// ContainerDefaulter provides getters and setters for Container defaulting.
//
// +k8s:deepcopy-gen=false
type ContainerDefaulter interface {
	GetImage() string
	GetImagePullPolicy() v1.PullPolicy
	SetImagePullPolicy(v1.PullPolicy)
	GetTerminationMessagePath() string
	SetTerminationMessagePath(string)
	GetTerminationMessagePolicy() v1.TerminationMessagePolicy
	SetTerminationMessagePolicy(v1.TerminationMessagePolicy)
	NumPorts() int
	Port(i int) ContainerPortDefaulter
	HasMissingResourceRequestsFromLimits() bool
	CopyMissingResourceLimitsToRequests()
}

// ContainerPortDefaulter provides getters and setters for ContainerPort defaulting.
//
// +k8s:deepcopy-gen=false
type ContainerPortDefaulter interface {
	GetHostPort() int32
	SetHostPort(int32)
	GetContainerPort() int32
	GetProtocol() v1.Protocol
	SetProtocol(v1.Protocol)
}

// VolumeDefaulter provides getters and setters for Volume and VolumeSource defaulting.
//
// +k8s:deepcopy-gen=false
type VolumeDefaulter interface {
	IsVolumeSourceEmpty() bool
	SetEmptyDirDefault()
	HasHostPath() bool
	HasHostPathType() bool
	SetHostPathType(v1.HostPathType)
	HasSecret() bool
	HasSecretDefaultMode() bool
	SetSecretDefaultMode(int32)
	HasDownwardAPI() bool
	HasDownwardAPIDefaultMode() bool
	SetDownwardAPIDefaultMode(int32)
	HasConfigMap() bool
	HasConfigMapDefaultMode() bool
	SetConfigMapDefaultMode(int32)
	HasProjected() bool
	HasProjectedDefaultMode() bool
	SetProjectedDefaultMode(int32)
}

// PodStatusDefaulter provides getters and setters for PodStatus defaulting.
//
// +k8s:deepcopy-gen=false
type PodStatusDefaulter interface {
	GetPodIP() string
	SetPodIP(string)
	NumPodIPs() int
	GetFirstPodIP() string
	SetSinglePodIP(ip string)
}

// DefaultObjectPod applies the complete v1.Pod defaulting pipeline through accessors.
// Because setters are only called when a getter reports an undefaulted value,
// an already-defaulted Pod incurs zero setter calls.
func DefaultObjectPod[P PodDefaulter](pod P) {
	spec := pod.Spec()
	DefaultPodLevel(spec)
	DefaultPodSpec(spec)
	for i, n := 0, spec.NumVolumes(); i < n; i++ {
		DefaultVolumeAndSources(spec.Volume(i))
	}
	for i, n := 0, spec.NumInitContainers(); i < n; i++ {
		c := spec.InitContainer(i)
		DefaultContainer(c)
		DefaultContainerPortsProtocol(c)
	}
	for i, n := 0, spec.NumContainers(); i < n; i++ {
		c := spec.Container(i)
		DefaultContainer(c)
		DefaultContainerPortsProtocol(c)
	}
	DefaultPodStatus(pod.Status())
}

// DefaultPodLevel applies the pod-level defaults from SetDefaults_Pod via accessors.
func DefaultPodLevel[S PodSpecDefaulter](spec S) {
	if tgp, ok := spec.GetTerminationGracePeriodSeconds(); ok && tgp < 0 {
		spec.SetTerminationGracePeriodSeconds(1)
	}
	for i, n := 0, spec.NumContainers(); i < n; i++ {
		c := spec.Container(i)
		if c.HasMissingResourceRequestsFromLimits() {
			c.CopyMissingResourceLimitsToRequests()
		}
	}
	for i, n := 0, spec.NumInitContainers(); i < n; i++ {
		c := spec.InitContainer(i)
		if c.HasMissingResourceRequestsFromLimits() {
			c.CopyMissingResourceLimitsToRequests()
		}
	}
	if !spec.HasEnableServiceLinks() {
		spec.SetEnableServiceLinks(v1.DefaultEnableServiceLinks)
	}
	if spec.GetHostNetwork() {
		for i, n := 0, spec.NumContainers(); i < n; i++ {
			defaultContainerHostNetworkPorts(spec.Container(i))
		}
		for i, n := 0, spec.NumInitContainers(); i < n; i++ {
			defaultContainerHostNetworkPorts(spec.InitContainer(i))
		}
	}
}

func defaultContainerHostNetworkPorts[C ContainerDefaulter](c C) {
	for j, m := 0, c.NumPorts(); j < m; j++ {
		p := c.Port(j)
		if p.GetHostPort() == 0 {
			if cp := p.GetContainerPort(); cp != 0 {
				p.SetHostPort(cp)
			}
		}
	}
}

// DefaultPodSpec applies SetDefaults_PodSpec via accessors.
func DefaultPodSpec[S PodSpecDefaulter](spec S) {
	sa := spec.GetServiceAccountName()
	depSA := spec.GetDeprecatedServiceAccount()
	if len(sa) == 0 && len(depSA) > 0 {
		sa = depSA
		spec.SetServiceAccountName(sa)
	}
	if depSA != sa {
		spec.SetDeprecatedServiceAccount(sa)
	}
	if spec.GetDNSPolicy() == "" {
		spec.SetDNSPolicy(v1.DNSClusterFirst)
	}
	if spec.GetRestartPolicy() == "" {
		spec.SetRestartPolicy(v1.RestartPolicyAlways)
	}
	if !spec.HasSecurityContext() {
		spec.InitEmptySecurityContext()
	}
	if _, ok := spec.GetTerminationGracePeriodSeconds(); !ok {
		spec.SetTerminationGracePeriodSeconds(v1.DefaultTerminationGracePeriodSeconds)
	}
	if spec.GetSchedulerName() == "" {
		spec.SetSchedulerName(v1.DefaultSchedulerName)
	}
}

// DefaultContainer applies SetDefaults_Container via accessors.
func DefaultContainer[C ContainerDefaulter](c C) {
	if c.GetImagePullPolicy() == "" {
		_, tag, _, _ := parsers.ParseImageName(c.GetImage())
		if tag == "latest" {
			c.SetImagePullPolicy(v1.PullAlways)
		} else {
			c.SetImagePullPolicy(v1.PullIfNotPresent)
		}
	}
	if c.GetTerminationMessagePath() == "" {
		c.SetTerminationMessagePath(v1.TerminationMessagePathDefault)
	}
	if c.GetTerminationMessagePolicy() == "" {
		c.SetTerminationMessagePolicy(v1.TerminationMessageReadFile)
	}
}

// DefaultContainerPortsProtocol defaults empty ContainerPort.Protocol to TCP.
func DefaultContainerPortsProtocol[C ContainerDefaulter](c C) {
	for j, m := 0, c.NumPorts(); j < m; j++ {
		p := c.Port(j)
		if p.GetProtocol() == "" {
			p.SetProtocol(v1.ProtocolTCP)
		}
	}
}

// DefaultVolume applies SetDefaults_Volume via accessors.
func DefaultVolume[V VolumeDefaulter](v V) {
	if v.IsVolumeSourceEmpty() {
		v.SetEmptyDirDefault()
	}
}

// DefaultVolumeAndSources applies SetDefaults_Volume and volume source defaults via accessors.
func DefaultVolumeAndSources[V VolumeDefaulter](v V) {
	DefaultVolume(v)
	if v.HasHostPath() && !v.HasHostPathType() {
		v.SetHostPathType(v1.HostPathUnset)
	}
	if v.HasSecret() && !v.HasSecretDefaultMode() {
		v.SetSecretDefaultMode(v1.SecretVolumeSourceDefaultMode)
	}
	if v.HasDownwardAPI() && !v.HasDownwardAPIDefaultMode() {
		v.SetDownwardAPIDefaultMode(v1.DownwardAPIVolumeSourceDefaultMode)
	}
	if v.HasConfigMap() && !v.HasConfigMapDefaultMode() {
		v.SetConfigMapDefaultMode(v1.ConfigMapVolumeSourceDefaultMode)
	}
	if v.HasProjected() && !v.HasProjectedDefaultMode() {
		v.SetProjectedDefaultMode(v1.ProjectedVolumeSourceDefaultMode)
	}
}

// DefaultPodStatus applies SetDefaults_PodStatus via accessors.
func DefaultPodStatus[S PodStatusDefaulter](status S) {
	podIP := status.GetPodIP()
	hasIP := len(podIP) > 0
	hasIPs := status.NumPodIPs() > 0
	switch {
	case hasIP && !hasIPs:
		status.SetSinglePodIP(podIP)
	case !hasIP && hasIPs:
		if first := status.GetFirstPodIP(); first != "" {
			status.SetPodIP(first)
		}
	case hasIP && hasIPs && status.GetFirstPodIP() != podIP:
		status.SetSinglePodIP(podIP)
	}
}

// Eager *v1.Pod, *v1.PodSpec, *v1.Container, *v1.Volume, and *v1.PodStatus adapter implementations.

// +k8s:deepcopy-gen=false
type v1PodAdapter struct{ pod *v1.Pod }

// AsPodDefaulter wraps an eager *v1.Pod in a PodDefaulter.
func AsPodDefaulter(pod *v1.Pod) PodDefaulter { return v1PodAdapter{pod: pod} }

func (a v1PodAdapter) Spec() PodSpecDefaulter     { return v1PodSpecAdapter{spec: &a.pod.Spec} }
func (a v1PodAdapter) Status() PodStatusDefaulter { return v1PodStatusAdapter{status: &a.pod.Status} }

// +k8s:deepcopy-gen=false
type v1PodSpecAdapter struct{ spec *v1.PodSpec }

// AsPodSpecDefaulter wraps an eager *v1.PodSpec in a PodSpecDefaulter.
func AsPodSpecDefaulter(spec *v1.PodSpec) PodSpecDefaulter { return v1PodSpecAdapter{spec: spec} }

func (a v1PodSpecAdapter) GetDNSPolicy() v1.DNSPolicy          { return a.spec.DNSPolicy }
func (a v1PodSpecAdapter) SetDNSPolicy(p v1.DNSPolicy)         { a.spec.DNSPolicy = p }
func (a v1PodSpecAdapter) GetRestartPolicy() v1.RestartPolicy  { return a.spec.RestartPolicy }
func (a v1PodSpecAdapter) SetRestartPolicy(p v1.RestartPolicy) { a.spec.RestartPolicy = p }
func (a v1PodSpecAdapter) HasSecurityContext() bool            { return a.spec.SecurityContext != nil }
func (a v1PodSpecAdapter) InitEmptySecurityContext() {
	a.spec.SecurityContext = &v1.PodSecurityContext{}
}
func (a v1PodSpecAdapter) GetTerminationGracePeriodSeconds() (int64, bool) {
	if a.spec.TerminationGracePeriodSeconds == nil {
		return 0, false
	}
	return *a.spec.TerminationGracePeriodSeconds, true
}
func (a v1PodSpecAdapter) SetTerminationGracePeriodSeconds(v int64) {
	a.spec.TerminationGracePeriodSeconds = &v
}
func (a v1PodSpecAdapter) GetServiceAccountName() string  { return a.spec.ServiceAccountName }
func (a v1PodSpecAdapter) SetServiceAccountName(s string) { a.spec.ServiceAccountName = s }
func (a v1PodSpecAdapter) GetDeprecatedServiceAccount() string {
	return a.spec.DeprecatedServiceAccount
}
func (a v1PodSpecAdapter) SetDeprecatedServiceAccount(s string) { a.spec.DeprecatedServiceAccount = s }
func (a v1PodSpecAdapter) HasEnableServiceLinks() bool          { return a.spec.EnableServiceLinks != nil }
func (a v1PodSpecAdapter) SetEnableServiceLinks(b bool)         { a.spec.EnableServiceLinks = &b }
func (a v1PodSpecAdapter) GetSchedulerName() string             { return a.spec.SchedulerName }
func (a v1PodSpecAdapter) SetSchedulerName(s string)            { a.spec.SchedulerName = s }
func (a v1PodSpecAdapter) GetHostNetwork() bool                 { return a.spec.HostNetwork }
func (a v1PodSpecAdapter) NumVolumes() int                      { return len(a.spec.Volumes) }
func (a v1PodSpecAdapter) Volume(i int) VolumeDefaulter {
	return v1VolumeAdapter{vol: &a.spec.Volumes[i]}
}
func (a v1PodSpecAdapter) NumContainers() int { return len(a.spec.Containers) }
func (a v1PodSpecAdapter) Container(i int) ContainerDefaulter {
	return v1ContainerAdapter{c: &a.spec.Containers[i]}
}
func (a v1PodSpecAdapter) NumInitContainers() int { return len(a.spec.InitContainers) }
func (a v1PodSpecAdapter) InitContainer(i int) ContainerDefaulter {
	return v1ContainerAdapter{c: &a.spec.InitContainers[i]}
}

// +k8s:deepcopy-gen=false
type v1ContainerAdapter struct{ c *v1.Container }

// AsContainerDefaulter wraps an eager *v1.Container in a ContainerDefaulter.
func AsContainerDefaulter(c *v1.Container) ContainerDefaulter { return v1ContainerAdapter{c: c} }

func (a v1ContainerAdapter) GetImage() string                   { return a.c.Image }
func (a v1ContainerAdapter) GetImagePullPolicy() v1.PullPolicy  { return a.c.ImagePullPolicy }
func (a v1ContainerAdapter) SetImagePullPolicy(p v1.PullPolicy) { a.c.ImagePullPolicy = p }
func (a v1ContainerAdapter) GetTerminationMessagePath() string  { return a.c.TerminationMessagePath }
func (a v1ContainerAdapter) SetTerminationMessagePath(p string) { a.c.TerminationMessagePath = p }
func (a v1ContainerAdapter) GetTerminationMessagePolicy() v1.TerminationMessagePolicy {
	return a.c.TerminationMessagePolicy
}
func (a v1ContainerAdapter) SetTerminationMessagePolicy(p v1.TerminationMessagePolicy) {
	a.c.TerminationMessagePolicy = p
}
func (a v1ContainerAdapter) NumPorts() int { return len(a.c.Ports) }
func (a v1ContainerAdapter) Port(i int) ContainerPortDefaulter {
	return v1PortAdapter{p: &a.c.Ports[i]}
}
func (a v1ContainerAdapter) HasMissingResourceRequestsFromLimits() bool {
	if a.c.Resources.Limits == nil {
		return false
	}
	if a.c.Resources.Requests == nil {
		return true
	}
	for k := range a.c.Resources.Limits {
		if _, exists := a.c.Resources.Requests[k]; !exists {
			return true
		}
	}
	return false
}
func (a v1ContainerAdapter) CopyMissingResourceLimitsToRequests() {
	if a.c.Resources.Limits == nil {
		return
	}
	if a.c.Resources.Requests == nil {
		a.c.Resources.Requests = make(v1.ResourceList)
	}
	for k, v := range a.c.Resources.Limits {
		if _, exists := a.c.Resources.Requests[k]; !exists {
			a.c.Resources.Requests[k] = v.DeepCopy()
		}
	}
}

// +k8s:deepcopy-gen=false
type v1PortAdapter struct{ p *v1.ContainerPort }

func (a v1PortAdapter) GetHostPort() int32        { return a.p.HostPort }
func (a v1PortAdapter) SetHostPort(v int32)       { a.p.HostPort = v }
func (a v1PortAdapter) GetContainerPort() int32   { return a.p.ContainerPort }
func (a v1PortAdapter) GetProtocol() v1.Protocol  { return a.p.Protocol }
func (a v1PortAdapter) SetProtocol(p v1.Protocol) { a.p.Protocol = p }

// +k8s:deepcopy-gen=false
type v1VolumeAdapter struct{ vol *v1.Volume }

// AsVolumeDefaulter wraps an eager *v1.Volume in a VolumeDefaulter.
func AsVolumeDefaulter(vol *v1.Volume) VolumeDefaulter { return v1VolumeAdapter{vol: vol} }

func (a v1VolumeAdapter) IsVolumeSourceEmpty() bool { return ptr.AllPtrFieldsNil(&a.vol.VolumeSource) }
func (a v1VolumeAdapter) SetEmptyDirDefault() {
	a.vol.VolumeSource = v1.VolumeSource{EmptyDir: &v1.EmptyDirVolumeSource{}}
}
func (a v1VolumeAdapter) HasHostPath() bool { return a.vol.VolumeSource.HostPath != nil }
func (a v1VolumeAdapter) HasHostPathType() bool {
	return a.vol.VolumeSource.HostPath != nil && a.vol.VolumeSource.HostPath.Type != nil
}
func (a v1VolumeAdapter) SetHostPathType(t v1.HostPathType) {
	a.vol.VolumeSource.HostPath.Type = &t
}
func (a v1VolumeAdapter) HasSecret() bool { return a.vol.VolumeSource.Secret != nil }
func (a v1VolumeAdapter) HasSecretDefaultMode() bool {
	return a.vol.VolumeSource.Secret != nil && a.vol.VolumeSource.Secret.DefaultMode != nil
}
func (a v1VolumeAdapter) SetSecretDefaultMode(m int32) {
	a.vol.VolumeSource.Secret.DefaultMode = &m
}
func (a v1VolumeAdapter) HasDownwardAPI() bool { return a.vol.VolumeSource.DownwardAPI != nil }
func (a v1VolumeAdapter) HasDownwardAPIDefaultMode() bool {
	return a.vol.VolumeSource.DownwardAPI != nil && a.vol.VolumeSource.DownwardAPI.DefaultMode != nil
}
func (a v1VolumeAdapter) SetDownwardAPIDefaultMode(m int32) {
	a.vol.VolumeSource.DownwardAPI.DefaultMode = &m
}
func (a v1VolumeAdapter) HasConfigMap() bool { return a.vol.VolumeSource.ConfigMap != nil }
func (a v1VolumeAdapter) HasConfigMapDefaultMode() bool {
	return a.vol.VolumeSource.ConfigMap != nil && a.vol.VolumeSource.ConfigMap.DefaultMode != nil
}
func (a v1VolumeAdapter) SetConfigMapDefaultMode(m int32) {
	a.vol.VolumeSource.ConfigMap.DefaultMode = &m
}
func (a v1VolumeAdapter) HasProjected() bool { return a.vol.VolumeSource.Projected != nil }
func (a v1VolumeAdapter) HasProjectedDefaultMode() bool {
	return a.vol.VolumeSource.Projected != nil && a.vol.VolumeSource.Projected.DefaultMode != nil
}
func (a v1VolumeAdapter) SetProjectedDefaultMode(m int32) {
	a.vol.VolumeSource.Projected.DefaultMode = &m
}

// +k8s:deepcopy-gen=false
type v1PodStatusAdapter struct{ status *v1.PodStatus }

// AsPodStatusDefaulter wraps an eager *v1.PodStatus in a PodStatusDefaulter.
func AsPodStatusDefaulter(status *v1.PodStatus) PodStatusDefaulter {
	return v1PodStatusAdapter{status: status}
}

func (a v1PodStatusAdapter) GetPodIP() string   { return a.status.PodIP }
func (a v1PodStatusAdapter) SetPodIP(ip string) { a.status.PodIP = ip }
func (a v1PodStatusAdapter) NumPodIPs() int     { return len(a.status.PodIPs) }
func (a v1PodStatusAdapter) GetFirstPodIP() string {
	if len(a.status.PodIPs) > 0 {
		return a.status.PodIPs[0].IP
	}
	return ""
}
func (a v1PodStatusAdapter) SetSinglePodIP(ip string) {
	a.status.PodIPs = []v1.PodIP{{IP: ip}}
}

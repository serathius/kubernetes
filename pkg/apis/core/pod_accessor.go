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

package core

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// PodTableSummary holds the fields required to render a Pod row in a metav1.Table.
//
// +k8s:deepcopy-gen=false
type PodTableSummary struct {
	TotalContainers int
	ReadyContainers int
	Restarts        int
	LastRestartTime metav1.Time
	StatusReason    string
	RawStatusReason string
	Phase           PodPhase
	PodIP           string
	NodeName        string
	NominatedNode   string
	ReadinessGates  string
}

// PodAccessor provides read and targeted write access to Pod fields required for
// indexing, label/field selection, watch-cache triggers, table printing, subresources,
// and admission without requiring the caller to assert a concrete *Pod struct.
//
// +k8s:deepcopy-gen=false
type PodAccessor interface {
	runtime.Object
	metav1.Object
	HasDeletionTimestamp() bool
	HasLegacyInitContainerAnnotations() bool

	GetSpecNodeName() string
	SetSpecNodeName(nodeName string)
	GetSpecRestartPolicy() RestartPolicy
	GetSpecSchedulerName() string
	GetSpecServiceAccountName() string
	GetSpecHostNetwork() bool
	GetSpecTerminationGracePeriodSeconds() *int64
	GetSpecActiveDeadlineSeconds() *int64
	HasSpecSchedulingGates() bool
	GetSpecSchedulingGates() []PodSchedulingGate
	GetSpecTolerations() []Toleration
	EnsureDefaultFaultTolerations(notReady, unreachable Toleration)
	GetFirstContainerPort() int32
	ResolveContainer(container string) (resolved string, ok bool, allNames []string)

	GetStatusPhase() PodPhase
	GetStatusQOSClass() PodQOSClass
	SetStatusQOSClass(qos PodQOSClass)
	GetStatusObservedGeneration() int64
	SetStatusObservedGeneration(gen int64)
	GetStatusPodIP() string
	GetStatusPodIPs() []PodIP
	GetStatusPrimaryPodIP() string
	GetStatusFirstPodIP() string
	GetStatusHostIP() string
	GetStatusHostIPs() []HostIP
	GetStatusNominatedNodeName() string
	SetStatusNominatedNodeName(nodeName string)
	GetStatusConditions() []PodCondition
	UpsertStatusCondition(condition PodCondition) bool
	IsPodReady() bool

	GetPodTableSummary(wide bool) PodTableSummary
}

var _ PodAccessor = (*Pod)(nil)

func (p *Pod) HasDeletionTimestamp() bool { return !p.ObjectMeta.DeletionTimestamp.IsZero() }

func (p *Pod) HasLegacyInitContainerAnnotations() bool {
	if len(p.Annotations) == 0 {
		return false
	}
	_, ok1 := p.Annotations["pod.beta.kubernetes.io/init-containers"]
	_, ok2 := p.Annotations["pod.alpha.kubernetes.io/init-containers"]
	_, ok3 := p.Annotations["pod.beta.kubernetes.io/init-container-statuses"]
	_, ok4 := p.Annotations["pod.alpha.kubernetes.io/init-container-statuses"]
	return ok1 || ok2 || ok3 || ok4
}

func (p *Pod) GetSpecNodeName() string             { return p.Spec.NodeName }
func (p *Pod) SetSpecNodeName(nodeName string)     { p.Spec.NodeName = nodeName }
func (p *Pod) GetSpecRestartPolicy() RestartPolicy { return p.Spec.RestartPolicy }
func (p *Pod) GetSpecSchedulerName() string        { return p.Spec.SchedulerName }
func (p *Pod) GetSpecServiceAccountName() string   { return p.Spec.ServiceAccountName }
func (p *Pod) GetSpecHostNetwork() bool            { return p.Spec.HostNetwork }
func (p *Pod) GetSpecTerminationGracePeriodSeconds() *int64 {
	return p.Spec.TerminationGracePeriodSeconds
}
func (p *Pod) GetSpecActiveDeadlineSeconds() *int64        { return p.Spec.ActiveDeadlineSeconds }
func (p *Pod) HasSpecSchedulingGates() bool                { return len(p.Spec.SchedulingGates) != 0 }
func (p *Pod) GetSpecSchedulingGates() []PodSchedulingGate { return p.Spec.SchedulingGates }
func (p *Pod) GetSpecTolerations() []Toleration            { return p.Spec.Tolerations }

func (p *Pod) EnsureDefaultFaultTolerations(notReady, unreachable Toleration) {
	toleratesNodeNotReady := false
	toleratesNodeUnreachable := false
	for _, toleration := range p.Spec.Tolerations {
		if (toleration.Key == notReady.Key || len(toleration.Key) == 0) &&
			(toleration.Effect == TaintEffectNoExecute || len(toleration.Effect) == 0) {
			toleratesNodeNotReady = true
		}
		if (toleration.Key == unreachable.Key || len(toleration.Key) == 0) &&
			(toleration.Effect == TaintEffectNoExecute || len(toleration.Effect) == 0) {
			toleratesNodeUnreachable = true
		}
	}
	if !toleratesNodeNotReady {
		p.Spec.Tolerations = append(p.Spec.Tolerations, notReady)
	}
	if !toleratesNodeUnreachable {
		p.Spec.Tolerations = append(p.Spec.Tolerations, unreachable)
	}
}

func (p *Pod) GetFirstContainerPort() int32 {
	for i := range p.Spec.Containers {
		if len(p.Spec.Containers[i].Ports) > 0 {
			return p.Spec.Containers[i].Ports[0].ContainerPort
		}
	}
	return 0
}

func (p *Pod) ResolveContainer(container string) (string, bool, []string) {
	if len(container) == 0 {
		switch len(p.Spec.Containers) {
		case 1:
			return p.Spec.Containers[0].Name, true, nil
		case 0:
			return "", false, nil
		default:
			names := make([]string, 0, len(p.Spec.InitContainers)+len(p.Spec.Containers)+len(p.Spec.EphemeralContainers))
			for i := range p.Spec.InitContainers {
				names = append(names, p.Spec.InitContainers[i].Name)
			}
			for i := range p.Spec.Containers {
				names = append(names, p.Spec.Containers[i].Name)
			}
			for i := range p.Spec.EphemeralContainers {
				names = append(names, p.Spec.EphemeralContainers[i].Name)
			}
			return "", false, names
		}
	}
	for i := range p.Spec.InitContainers {
		if p.Spec.InitContainers[i].Name == container {
			return container, true, nil
		}
	}
	for i := range p.Spec.Containers {
		if p.Spec.Containers[i].Name == container {
			return container, true, nil
		}
	}
	for i := range p.Spec.EphemeralContainers {
		if p.Spec.EphemeralContainers[i].Name == container {
			return container, true, nil
		}
	}
	return "", false, nil
}

func (p *Pod) GetStatusPhase() PodPhase            { return p.Status.Phase }
func (p *Pod) GetStatusQOSClass() PodQOSClass      { return p.Status.QOSClass }
func (p *Pod) SetStatusQOSClass(qos PodQOSClass)   { p.Status.QOSClass = qos }
func (p *Pod) GetStatusObservedGeneration() int64  { return p.Status.ObservedGeneration }
func (p *Pod) SetStatusObservedGeneration(g int64) { p.Status.ObservedGeneration = g }
func (p *Pod) GetStatusPodIP() string              { return p.Status.PodIP }
func (p *Pod) GetStatusPodIPs() []PodIP            { return p.Status.PodIPs }

func (p *Pod) GetStatusPrimaryPodIP() string {
	if len(p.Status.PodIPs) > 0 {
		return p.Status.PodIPs[0].IP
	}
	return p.Status.PodIP
}

func (p *Pod) GetStatusFirstPodIP() string {
	if p == nil {
		return ""
	}
	if len(p.Status.PodIPs) > 0 {
		return p.Status.PodIPs[0].IP
	}
	return ""
}

func (p *Pod) GetStatusHostIP() string                    { return p.Status.HostIP }
func (p *Pod) GetStatusHostIPs() []HostIP                 { return p.Status.HostIPs }
func (p *Pod) GetStatusNominatedNodeName() string         { return p.Status.NominatedNodeName }
func (p *Pod) SetStatusNominatedNodeName(nodeName string) { p.Status.NominatedNodeName = nodeName }
func (p *Pod) GetStatusConditions() []PodCondition        { return p.Status.Conditions }

func (p *Pod) IsPodReady() bool {
	for i := range p.Status.Conditions {
		if p.Status.Conditions[i].Type == PodReady {
			return p.Status.Conditions[i].Status == ConditionTrue
		}
	}
	return false
}

func (p *Pod) UpsertStatusCondition(condition PodCondition) bool {
	condition.LastTransitionTime = metav1.Now()
	for i := range p.Status.Conditions {
		if p.Status.Conditions[i].Type == condition.Type {
			oldCondition := &p.Status.Conditions[i]
			if condition.Status == oldCondition.Status {
				condition.LastTransitionTime = oldCondition.LastTransitionTime
			}
			isEqual := condition.Status == oldCondition.Status &&
				condition.Reason == oldCondition.Reason &&
				condition.Message == oldCondition.Message &&
				condition.LastProbeTime.Equal(&oldCondition.LastProbeTime) &&
				condition.LastTransitionTime.Equal(&oldCondition.LastTransitionTime)
			p.Status.Conditions[i] = condition
			return !isEqual
		}
	}
	p.Status.Conditions = append(p.Status.Conditions, condition)
	return true
}

func isRestartableInitContainer(c *Container) bool {
	return c != nil && c.RestartPolicy != nil && *c.RestartPolicy == ContainerRestartPolicyAlways
}

func (p *Pod) findInitContainer(name string) *Container {
	for i := range p.Spec.InitContainers {
		if p.Spec.InitContainers[i].Name == name {
			return &p.Spec.InitContainers[i]
		}
	}
	return nil
}

func hasPodInitializedConditionTrue(conditions []PodCondition) bool {
	for i := range conditions {
		if conditions[i].Type == PodInitialized {
			return conditions[i].Status == ConditionTrue
		}
	}
	return false
}

func (p *Pod) GetPodTableSummary(wide bool) PodTableSummary {
	restarts := 0
	restartableInitContainerRestarts := 0
	totalContainers := len(p.Spec.Containers)
	readyContainers := 0
	lastRestartDate := metav1.NewTime(time.Time{})
	lastRestartableInitContainerRestartDate := metav1.NewTime(time.Time{})

	podPhase := p.Status.Phase
	reason := string(podPhase)
	if p.Status.Reason != "" {
		reason = p.Status.Reason
	}

	for i := range p.Status.Conditions {
		if p.Status.Conditions[i].Type == PodScheduled && p.Status.Conditions[i].Reason == "SchedulingGated" {
			reason = "SchedulingGated"
		}
	}

	for i := range p.Spec.InitContainers {
		if isRestartableInitContainer(&p.Spec.InitContainers[i]) {
			totalContainers++
		}
	}

	initializing := false
	for i := range p.Status.InitContainerStatuses {
		container := &p.Status.InitContainerStatuses[i]
		restarts += int(container.RestartCount)
		if container.LastTerminationState.Terminated != nil {
			terminatedDate := container.LastTerminationState.Terminated.FinishedAt
			if lastRestartDate.Before(&terminatedDate) {
				lastRestartDate = terminatedDate
			}
		}
		initSpec := p.findInitContainer(container.Name)
		restartable := isRestartableInitContainer(initSpec)
		if restartable {
			restartableInitContainerRestarts += int(container.RestartCount)
			if container.LastTerminationState.Terminated != nil {
				terminatedDate := container.LastTerminationState.Terminated.FinishedAt
				if lastRestartableInitContainerRestartDate.Before(&terminatedDate) {
					lastRestartableInitContainerRestartDate = terminatedDate
				}
			}
		}
		switch {
		case container.State.Terminated != nil && container.State.Terminated.ExitCode == 0:
			continue
		case restartable && container.Started != nil && *container.Started:
			if container.Ready {
				readyContainers++
			}
			continue
		case container.State.Terminated != nil:
			if len(container.State.Terminated.Reason) == 0 {
				if container.State.Terminated.Signal != 0 {
					reason = fmt.Sprintf("Init:Signal:%d", container.State.Terminated.Signal)
				} else {
					reason = fmt.Sprintf("Init:ExitCode:%d", container.State.Terminated.ExitCode)
				}
			} else {
				reason = "Init:" + container.State.Terminated.Reason
			}
			initializing = true
		case container.State.Waiting != nil && len(container.State.Waiting.Reason) > 0 && container.State.Waiting.Reason != "PodInitializing":
			reason = "Init:" + container.State.Waiting.Reason
			initializing = true
		default:
			reason = fmt.Sprintf("Init:%d/%d", i, len(p.Spec.InitContainers))
			initializing = true
		}
		break
	}

	if !initializing || hasPodInitializedConditionTrue(p.Status.Conditions) {
		restarts = restartableInitContainerRestarts
		lastRestartDate = lastRestartableInitContainerRestartDate
		hasRunning := false
		errorReason := ""
		for i := len(p.Status.ContainerStatuses) - 1; i >= 0; i-- {
			container := &p.Status.ContainerStatuses[i]
			restarts += int(container.RestartCount)
			if container.LastTerminationState.Terminated != nil {
				terminatedDate := container.LastTerminationState.Terminated.FinishedAt
				if lastRestartDate.Before(&terminatedDate) {
					lastRestartDate = terminatedDate
				}
			}
			switch {
			case container.State.Waiting != nil && container.State.Waiting.Reason != "":
				reason = container.State.Waiting.Reason
			case container.State.Terminated != nil:
				if len(container.State.Terminated.Reason) > 0 {
					reason = container.State.Terminated.Reason
				} else if container.State.Terminated.Signal != 0 {
					reason = fmt.Sprintf("Signal:%d", container.State.Terminated.Signal)
				} else {
					reason = fmt.Sprintf("ExitCode:%d", container.State.Terminated.ExitCode)
				}
				if container.State.Terminated.ExitCode != 0 {
					errorReason = reason
				}
			case container.Ready && container.State.Running != nil:
				hasRunning = true
				readyContainers++
			}
		}

		if reason == "Completed" {
			if hasRunning && p.IsPodReady() {
				reason = "Running"
			} else if errorReason != "" {
				reason = errorReason
			} else if hasRunning {
				reason = "NotReady"
			}
		}
	}

	sum := PodTableSummary{
		TotalContainers: totalContainers,
		ReadyContainers: readyContainers,
		Restarts:        restarts,
		LastRestartTime: lastRestartDate,
		StatusReason:    reason,
		RawStatusReason: p.Status.Reason,
		Phase:           podPhase,
	}

	if wide {
		sum.NodeName = p.Spec.NodeName
		sum.NominatedNode = p.Status.NominatedNodeName
		if len(p.Status.PodIPs) > 0 {
			sum.PodIP = p.Status.PodIPs[0].IP
		}
		if len(p.Spec.ReadinessGates) > 0 {
			trueConditions := 0
			for i := range p.Spec.ReadinessGates {
				conditionType := p.Spec.ReadinessGates[i].ConditionType
				for j := range p.Status.Conditions {
					if p.Status.Conditions[j].Type == conditionType {
						if p.Status.Conditions[j].Status == ConditionTrue {
							trueConditions++
						}
						break
					}
				}
			}
			sum.ReadinessGates = fmt.Sprintf("%d/%d", trueConditions, len(p.Spec.ReadinessGates))
		}
	}

	return sum
}

// PodListAccessor abstracts iteration over a list of PodAccessor items.
type PodListAccessor interface {
	runtime.Object
	Len() int
	PodAt(i int) PodAccessor
}

var _ PodListAccessor = (*PodList)(nil)

func (l *PodList) Len() int                { return len(l.Items) }
func (l *PodList) PodAt(i int) PodAccessor { return &l.Items[i] }


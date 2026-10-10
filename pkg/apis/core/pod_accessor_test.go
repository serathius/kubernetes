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
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPodAccessorBasic(t *testing.T) {
	now := metav1.Now()
	tgp := int64(30)
	ads := int64(60)
	var accessor PodAccessor = &Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-pod",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Annotations: map[string]string{
				"pod.beta.kubernetes.io/init-containers": "[]",
			},
		},
		Spec: PodSpec{
			NodeName:                      "node-1",
			RestartPolicy:                 RestartPolicyAlways,
			SchedulerName:                 "default-scheduler",
			ServiceAccountName:            "default",
			HostNetwork:                   true,
			TerminationGracePeriodSeconds: &tgp,
			ActiveDeadlineSeconds:         &ads,
			SchedulingGates:               []PodSchedulingGate{{Name: "gate-1"}},
			InitContainers: []Container{
				{Name: "init-1"},
			},
			Containers: []Container{
				{Name: "app-1", Ports: []ContainerPort{{ContainerPort: 8080}}},
				{Name: "app-2"},
			},
			EphemeralContainers: []EphemeralContainer{
				{EphemeralContainerCommon: EphemeralContainerCommon{Name: "debug-1"}},
			},
		},
		Status: PodStatus{
			Phase:              PodRunning,
			QOSClass:           PodQOSBurstable,
			ObservedGeneration: 3,
			PodIP:              "10.0.0.1",
			PodIPs:             []PodIP{{IP: "10.0.0.1"}, {IP: "fd00::1"}},
			HostIP:             "192.168.1.1",
			HostIPs:            []HostIP{{IP: "192.168.1.1"}},
			NominatedNodeName:  "node-2",
			Conditions: []PodCondition{
				{Type: PodReady, Status: ConditionTrue},
			},
		},
	}

	if !accessor.HasDeletionTimestamp() {
		t.Errorf("expected HasDeletionTimestamp() to be true")
	}
	if !accessor.HasLegacyInitContainerAnnotations() {
		t.Errorf("expected HasLegacyInitContainerAnnotations() to be true")
	}
	if got := accessor.GetSpecNodeName(); got != "node-1" {
		t.Errorf("expected node-1, got %q", got)
	}
	accessor.SetSpecNodeName("node-updated")
	if got := accessor.GetSpecNodeName(); got != "node-updated" {
		t.Errorf("expected node-updated, got %q", got)
	}
	if got := accessor.GetSpecRestartPolicy(); got != RestartPolicyAlways {
		t.Errorf("expected Always, got %q", got)
	}
	if got := accessor.GetSpecSchedulerName(); got != "default-scheduler" {
		t.Errorf("expected default-scheduler, got %q", got)
	}
	if got := accessor.GetSpecServiceAccountName(); got != "default" {
		t.Errorf("expected default, got %q", got)
	}
	if !accessor.GetSpecHostNetwork() {
		t.Errorf("expected HostNetwork true")
	}
	if got := accessor.GetSpecTerminationGracePeriodSeconds(); got == nil || *got != 30 {
		t.Errorf("expected TerminationGracePeriodSeconds=30, got %v", got)
	}
	if got := accessor.GetSpecActiveDeadlineSeconds(); got == nil || *got != 60 {
		t.Errorf("expected ActiveDeadlineSeconds=60, got %v", got)
	}
	if !accessor.HasSpecSchedulingGates() || len(accessor.GetSpecSchedulingGates()) != 1 {
		t.Errorf("expected 1 scheduling gate")
	}
	if got := accessor.GetFirstContainerPort(); got != 8080 {
		t.Errorf("expected first container port 8080, got %d", got)
	}

	resolved, ok, allNames := accessor.ResolveContainer("")
	if ok || resolved != "" {
		t.Errorf("expected ambiguous empty container to fail resolution, got ok=%v resolved=%q", ok, resolved)
	}
	wantNames := []string{"init-1", "app-1", "app-2", "debug-1"}
	if diff := cmp.Diff(wantNames, allNames); diff != "" {
		t.Errorf("ResolveContainer names mismatch (-want +got):\n%s", diff)
	}
	for _, validName := range wantNames {
		if r, ok, _ := accessor.ResolveContainer(validName); !ok || r != validName {
			t.Errorf("expected ResolveContainer(%q) to succeed, got ok=%v r=%q", validName, ok, r)
		}
	}
	if _, ok, _ := accessor.ResolveContainer("nonexistent"); ok {
		t.Errorf("expected ResolveContainer(nonexistent) to return false")
	}

	if got := accessor.GetStatusPhase(); got != PodRunning {
		t.Errorf("expected phase Running, got %q", got)
	}
	if got := accessor.GetStatusQOSClass(); got != PodQOSBurstable {
		t.Errorf("expected QOS Burstable, got %q", got)
	}
	accessor.SetStatusQOSClass(PodQOSGuaranteed)
	if got := accessor.GetStatusQOSClass(); got != PodQOSGuaranteed {
		t.Errorf("expected QOS Guaranteed, got %q", got)
	}
	if got := accessor.GetStatusObservedGeneration(); got != 3 {
		t.Errorf("expected ObservedGeneration 3, got %d", got)
	}
	accessor.SetStatusObservedGeneration(4)
	if got := accessor.GetStatusObservedGeneration(); got != 4 {
		t.Errorf("expected ObservedGeneration 4, got %d", got)
	}
	if got := accessor.GetStatusPrimaryPodIP(); got != "10.0.0.1" {
		t.Errorf("expected primary PodIP 10.0.0.1, got %q", got)
	}
	if got := accessor.GetStatusFirstPodIP(); got != "10.0.0.1" {
		t.Errorf("expected first PodIP 10.0.0.1, got %q", got)
	}
	if got := accessor.GetStatusNominatedNodeName(); got != "node-2" {
		t.Errorf("expected NominatedNodeName node-2, got %q", got)
	}
	accessor.SetStatusNominatedNodeName("")
	if got := accessor.GetStatusNominatedNodeName(); got != "" {
		t.Errorf("expected empty NominatedNodeName, got %q", got)
	}
	if !accessor.IsPodReady() {
		t.Errorf("expected IsPodReady() true")
	}
	if !accessor.UpsertStatusCondition(PodCondition{Type: PodScheduled, Status: ConditionTrue}) {
		t.Errorf("expected UpsertStatusCondition to return true on new condition")
	}
	if accessor.UpsertStatusCondition(PodCondition{Type: PodScheduled, Status: ConditionTrue}) {
		t.Errorf("expected UpsertStatusCondition to return false on unchanged condition")
	}
}

func TestPodAccessorEnsureDefaultFaultTolerations(t *testing.T) {
	sec := int64(300)
	notReady := Toleration{
		Key:               "node.kubernetes.io/not-ready",
		Operator:          TolerationOpExists,
		Effect:            TaintEffectNoExecute,
		TolerationSeconds: &sec,
	}
	unreachable := Toleration{
		Key:               "node.kubernetes.io/unreachable",
		Operator:          TolerationOpExists,
		Effect:            TaintEffectNoExecute,
		TolerationSeconds: &sec,
	}

	var accessor PodAccessor = &Pod{}
	accessor.EnsureDefaultFaultTolerations(notReady, unreachable)
	if got := len(accessor.GetSpecTolerations()); got != 2 {
		t.Fatalf("expected 2 tolerations, got %d", got)
	}
	// Calling again should be a no-op.
	accessor.EnsureDefaultFaultTolerations(notReady, unreachable)
	if got := len(accessor.GetSpecTolerations()); got != 2 {
		t.Fatalf("expected 2 tolerations after second call, got %d", got)
	}
}

func TestPodAccessorGetPodTableSummary(t *testing.T) {
	restartAlways := ContainerRestartPolicyAlways
	started := true
	restartTime := metav1.NewTime(time.Unix(1700000000, 0))
	var accessor PodAccessor = &Pod{
		Spec: PodSpec{
			NodeName: "node-1",
			InitContainers: []Container{
				{Name: "sidecar", RestartPolicy: &restartAlways},
			},
			Containers: []Container{
				{Name: "main"},
			},
			ReadinessGates: []PodReadinessGate{
				{ConditionType: "custom-gate"},
			},
		},
		Status: PodStatus{
			Phase:             PodRunning,
			NominatedNodeName: "node-2",
			PodIPs:            []PodIP{{IP: "10.0.0.5"}},
			Conditions: []PodCondition{
				{Type: PodInitialized, Status: ConditionTrue},
				{Type: PodReady, Status: ConditionTrue},
				{Type: "custom-gate", Status: ConditionTrue},
			},
			InitContainerStatuses: []ContainerStatus{
				{
					Name:         "sidecar",
					Started:      &started,
					Ready:        true,
					RestartCount: 1,
					State:        ContainerState{Running: &ContainerStateRunning{}},
					LastTerminationState: ContainerState{
						Terminated: &ContainerStateTerminated{FinishedAt: restartTime},
					},
				},
			},
			ContainerStatuses: []ContainerStatus{
				{
					Name:         "main",
					Ready:        true,
					RestartCount: 2,
					State:        ContainerState{Running: &ContainerStateRunning{}},
				},
			},
		},
	}

	sum := accessor.GetPodTableSummary(true)
	want := PodTableSummary{
		TotalContainers: 2,
		ReadyContainers: 2,
		Restarts:        3,
		LastRestartTime: restartTime,
		StatusReason:    "Running",
		RawStatusReason: "",
		Phase:           PodRunning,
		PodIP:           "10.0.0.5",
		NodeName:        "node-1",
		NominatedNode:   "node-2",
		ReadinessGates:  "1/1",
	}
	if diff := cmp.Diff(want, sum); diff != "" {
		t.Errorf("GetPodTableSummary mismatch (-want +got):\n%s", diff)
	}
}

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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/node"
)

func toPtr[T any](val T) *T {
	return &val
}

func procMountTypePtr(p core.ProcMountType) *core.ProcMountType {
	return &p
}

func mountPropagationModePtr(p core.MountPropagationMode) *core.MountPropagationMode {
	return &p
}

func makePodCreateAttrs(pod *core.Pod, subres string) admission.Attributes {
	return admission.NewAttributesRecord(pod, nil, core.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, core.Resource("pods").WithVersion("version"), subres, admission.Create, &metav1.CreateOptions{}, false, &user.DefaultInfo{})
}

func makePodUpdateAttrs(pod, oldPod *core.Pod, subres string) admission.Attributes {
	return admission.NewAttributesRecord(pod, oldPod, core.Kind("Pod").WithVersion("version"), pod.Namespace, pod.Name, core.Resource("pods").WithVersion("version"), subres, admission.Update, &metav1.UpdateOptions{}, false, &user.DefaultInfo{})
}

func makeRuntimeClassCreateAttrs(rc *node.RuntimeClass) admission.Attributes {
	return admission.NewAttributesRecord(rc, nil, core.Kind("RuntimeClass").WithVersion("version"), rc.Namespace, rc.Name, core.Resource("runtimeclasses").WithVersion("version"), "", admission.Create, &metav1.CreateOptions{}, false, &user.DefaultInfo{})
}

func TestDeprecatedAnnotations(t *testing.T) {
	for name, test := range map[string]struct {
		annotations map[string]string
		expectErr   bool
	}{
		"runtime-handler.cri.kubernetes.io annotation": {
			annotations: map[string]string{
				"runtime-handler.cri.kubernetes.io": "gvisor",
			},
			expectErr: true,
		},
		"io.kubernetes.cri.untrusted-workload annotation": {
			annotations: map[string]string{
				"io.kubernetes.cri.untrusted-workload": "true",
			},
			expectErr: true,
		},
		"both gvisor annotations": {
			annotations: map[string]string{
				"io.kubernetes.cri.untrusted-workload": "true",
				"runtime-handler.cri.kubernetes.io":    "gvisor",
			},
			expectErr: true,
		},
		"other annotation": {
			annotations: map[string]string{
				"io.kubernetes.cri.untrusted-workload": "false",
				"runtime-handler.cri.kubernetes.io":    "other",
			},
			expectErr: false,
		},
		"no annotation": {
			expectErr: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			pod := &core.Pod{}
			pod.Annotations = test.annotations

			err := checkDeprecatedAnnotation(pod)
			if test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateGVisorPod(t *testing.T) {
	for name, test := range map[string]struct {
		pod       core.Pod
		expectErr bool
	}{
		"regular pod": {
			pod:       core.Pod{},
			expectErr: false,
		},
		"pod with existing node selector": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					NodeSelector:     map[string]string{"other": "selector"},
				},
			},
			expectErr: false,
		},
		"pod with host path": {
			pod: core.Pod{
				Spec: core.PodSpec{
					Volumes: []core.Volume{
						{
							Name: "test-host-path",
							VolumeSource: core.VolumeSource{
								HostPath: &core.HostPathVolumeSource{
									Path: "/test/host/path",
								},
							},
						},
					},
				},
			},
			expectErr: true,
		},
		"pod with host network": {
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						HostNetwork: true,
					},
				},
			},
			expectErr: true,
		},
		"pod with host pid": {
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						HostPID: true,
					},
				},
			},
			expectErr: true,
		},
		"pod with host ipc": {
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						HostIPC: true,
					},
				},
			},
			expectErr: true,
		},
		"pod with selinux options": {
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SELinuxOptions: &core.SELinuxOptions{
							User:  "user",
							Role:  "role",
							Type:  "type",
							Level: "level",
						},
					},
				},
			},
			expectErr: true,
		},
		"pod with FSGroup": {
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						FSGroup: toPtr[int64](1234),
					},
				},
			},
			expectErr: false,
		},
		"pod with Sysctls": {
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						Sysctls: []core.Sysctl{
							{
								Name:  "kernel.shm_rmid_forced",
								Value: "0",
							},
						},
					},
				},
			},
			expectErr: true,
		},
		"pod with RuntimeDefault seccomp profile": {
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
				},
			},
			expectErr: false,
		},
		"pod with Unconfined seccomp profile": {
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeUnconfined,
						},
					},
				},
			},
			expectErr: false,
		},
		"pod with invalid seccomp profile": {
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: "invalid profile",
						},
					},
				},
			},
			expectErr: true,
		},
		"pod with container with RuntimeDefault seccomp profile": {
			pod: core.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"dev.gvisor.internal.seccomp.container": string(core.SeccompProfileTypeRuntimeDefault),
					},
				},
				Spec: core.PodSpec{
					Containers: []core.Container{
						{
							Name: "container",
							SecurityContext: &core.SecurityContext{
								SeccompProfile: &core.SeccompProfile{
									Type: core.SeccompProfileTypeRuntimeDefault,
								},
							},
						},
					},
				},
			},
			expectErr: false,
		},
		"pod with container with Unconfined seccomp profile": {
			pod: core.Pod{
				Spec: core.PodSpec{
					Containers: []core.Container{
						{
							Name: "container",
							SecurityContext: &core.SecurityContext{
								SeccompProfile: &core.SeccompProfile{
									Type: core.SeccompProfileTypeUnconfined,
								},
							},
						},
					},
				},
			},
			expectErr: false,
		},
		"pod with Seccomp": {
			pod: core.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"seccomp.security.alpha.kubernetes.io/pod": "test",
					},
				},
			},
			expectErr: true,
		},
		"pod with Seccomp container": {
			pod: core.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"container.seccomp.security.alpha.kubernetes.io/test": "test",
					},
				},
			},
			expectErr: true,
		},
		"pod with RuntimeDefault Seccomp": {
			pod: core.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"seccomp.security.alpha.kubernetes.io/pod": "RuntimeDefault",
					},
				},
			},
			expectErr: true,
		},
		"pod with RuntimeDefault Seccomp container": {
			pod: core.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"container.seccomp.security.alpha.kubernetes.io/test": "RuntimeDefault",
					},
				},
			},
			expectErr: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateGVisorPod(&test.pod); test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateContainer(t *testing.T) {
	for _, tc := range []struct {
		name      string
		container core.Container
		expectErr bool
	}{
		{
			name: "empty SecurityContext",
			container: core.Container{
				Name:            "container",
				SecurityContext: &core.SecurityContext{},
			},
		},
		{
			name: "non-Privileged",
			container: core.Container{
				Name: "container",
				SecurityContext: &core.SecurityContext{
					Privileged: toPtr(false),
				},
			},
		},
		{
			name: "Privileged",
			container: core.Container{
				Name: "container",
				SecurityContext: &core.SecurityContext{
					Privileged: toPtr(true),
				},
			},
			expectErr: true,
		},
		{
			name: "SELinux",
			container: core.Container{
				Name: "container",
				SecurityContext: &core.SecurityContext{
					SELinuxOptions: &core.SELinuxOptions{
						User:  "user",
						Role:  "role",
						Type:  "type",
						Level: "level",
					},
				},
			},
			expectErr: true,
		},
		{
			name: "invalid seccomp",
			container: core.Container{
				Name: "container",
				SecurityContext: &core.SecurityContext{
					SeccompProfile: &core.SeccompProfile{
						Type: "invalid profile",
					},
				},
			},
			expectErr: true,
		},
		{
			name: "non-AllowPrivilegeEscalation",
			container: core.Container{
				Name: "container",
				SecurityContext: &core.SecurityContext{
					AllowPrivilegeEscalation: toPtr(false),
				},
			},
		},
		{
			name: "AllowPrivilegeEscalation",
			container: core.Container{
				Name: "container",
				SecurityContext: &core.SecurityContext{
					AllowPrivilegeEscalation: toPtr(true),
				},
			},
			expectErr: true,
		},
		{
			name: "Default ProcMount",
			container: core.Container{
				Name: "container",
				SecurityContext: &core.SecurityContext{
					ProcMount: procMountTypePtr(core.DefaultProcMount),
				},
			},
		},
		{
			name: "Unmasked ProcMount",
			container: core.Container{
				Name: "container",
				SecurityContext: &core.SecurityContext{
					ProcMount: procMountTypePtr(core.UnmaskedProcMount),
				},
			},
			expectErr: true,
		},
		{
			name: "VolumeDevices",
			container: core.Container{
				Name: "container",
				VolumeDevices: []core.VolumeDevice{
					{
						Name:       "dev1",
						DevicePath: "/dev/dev1",
					},
				},
			},
			expectErr: true,
		},
		{
			name: "VolumeMounts",
			container: core.Container{
				Name: "container",
				VolumeMounts: []core.VolumeMount{
					{
						Name:      "volume1",
						MountPath: "/",
					},
				},
			},
			expectErr: false,
		},
		{
			name: "MountPropagation None",
			container: core.Container{
				Name: "container",
				VolumeMounts: []core.VolumeMount{
					{
						Name:             "volume1",
						MountPath:        "/",
						MountPropagation: mountPropagationModePtr(core.MountPropagationNone),
					},
				},
			},
		},
		{
			name: "MountPropagation HostToContainer",
			container: core.Container{
				Name: "container",
				VolumeMounts: []core.VolumeMount{
					{
						Name:             "volume1",
						MountPath:        "/",
						MountPropagation: mountPropagationModePtr(core.MountPropagationHostToContainer),
					},
				},
			},
		},
		{
			name: "MountPropagation Bidirectional",
			container: core.Container{
				Name: "container",
				VolumeMounts: []core.VolumeMount{
					{
						Name:             "volume1",
						MountPath:        "/",
						MountPropagation: mountPropagationModePtr(core.MountPropagationBidirectional),
					},
				},
			},
			expectErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateContainer(&tc.container); tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAdmitCreate(t *testing.T) {
	createPodTests := map[string]struct {
		pod, expected core.Pod
		expectErr     bool
	}{
		"create regular pod": {
			pod:       core.Pod{},
			expectErr: false,
			expected:  core.Pod{},
		},
		"create pod with gvisor runtimeclass": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
				},
			},
			expectErr: false,
			expected: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
				},
			},
		},
		"create pod with non-gvisor runtimeclass": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr("other"),
				},
			},
			expectErr: false,
			expected: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr("other"),
				},
			},
		},
		"create gvisor pod with some disallowed options": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					SecurityContext: &core.PodSecurityContext{
						HostNetwork: true,
						HostPID:     true,
						HostIPC:     true,
						SELinuxOptions: &core.SELinuxOptions{
							User:  "user",
							Role:  "role",
							Type:  "type",
							Level: "level",
						},
						FSGroup: toPtr[int64](1234),
						Sysctls: []core.Sysctl{
							{
								Name:  "kernel.shm_rmid_forced",
								Value: "0",
							},
						},
					},
					Containers: []core.Container{
						{
							Name: "container",
							VolumeDevices: []core.VolumeDevice{
								{
									Name:       "dev1",
									DevicePath: "/dev/dev1",
								},
							},
						},
					},
				},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"seccomp.security.alpha.kubernetes.io/pod":            "test",
						"container.seccomp.security.alpha.kubernetes.io/test": "test",
						"container.apparmor.security.beta.kubernetes.io/test": "test",
					},
				},
			},
			expectErr: true,
		},
	}

	for name, test := range createPodTests {
		t.Run(name, func(t *testing.T) {
			gvisor := new()
			attr := makePodCreateAttrs(&test.pod, "")
			if err := gvisor.Admit(context.TODO(), attr, nil); test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, test.pod)
			}
		})
	}
}

func TestAdmitUpdate(t *testing.T) {
	gvisorPod := &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gvisor-pod",
		},
		Spec: core.PodSpec{
			Containers:       []core.Container{{Image: "my-image:v1"}},
			RuntimeClassName: toPtr("gvisor"),
		},
	}
	deprecatedGvisorPod := &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gvisor-pod",
			Annotations: map[string]string{
				"runtime-handler.cri.kubernetes.io":    "gvisor",
				"io.kubernetes.cri.untrusted-workload": "true",
			},
		},
		Spec: core.PodSpec{
			Containers: []core.Container{{Image: "my-image:v1"}},
		},
	}
	nativePod := &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "native-pod",
		},
		Spec: core.PodSpec{
			Containers: []core.Container{{Image: "my-image:v1"}},
		},
	}
	gvisorPodNewImage := gvisorPod.DeepCopy()
	gvisorPodNewImage.Spec.Containers[0].Image = "my-image:v2"

	updatePodTests := map[string]struct {
		oldPod, newPod, expected *core.Pod
		expectErr                bool
	}{
		"non-gvisor->non-gvisor": {
			oldPod:    nativePod,
			newPod:    nativePod,
			expectErr: false,
			expected:  nativePod.DeepCopy(),
		},
		"gvisor->deprecated-gvisor": {
			oldPod:    gvisorPod,
			newPod:    deprecatedGvisorPod,
			expectErr: false, //  It's Validate's job to fail this case, not Admit's
			expected:  deprecatedGvisorPod.DeepCopy(),
		},
		"gvisor->modified-image": {
			oldPod:    gvisorPod,
			newPod:    gvisorPodNewImage,
			expectErr: false,
			expected:  gvisorPodNewImage.DeepCopy(),
		},
	}
	for name, test := range updatePodTests {
		t.Run(name, func(t *testing.T) {
			gvisor := new()
			// Ensure test pod isn't changed because it may be used by multiple tests.
			newPod := test.newPod.DeepCopy()
			attrs := makePodUpdateAttrs(newPod, test.oldPod, "")
			if err := gvisor.Admit(context.TODO(), attrs, nil); test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, newPod)
			}
		})
	}

	gvisorPod = &core.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "testname", Namespace: "testnamespace"},
		Spec: core.PodSpec{
			RuntimeClassName: toPtr(gvisorRuntimeClass),
		},
	}
	expectedGvisorPod := gvisorPod.DeepCopy()

	ephemeralPod := gvisorPod.DeepCopy()
	ephemeralPod.Spec.EphemeralContainers = []core.EphemeralContainer{
		{
			EphemeralContainerCommon: core.EphemeralContainerCommon{
				Name: "ephemeral",
			},
		},
	}
	expectedEphemeralPod := ephemeralPod.DeepCopy()
	expectedEphemeralPod.Spec.EphemeralContainers[0].EphemeralContainerCommon.SecurityContext = &core.SecurityContext{
		Capabilities: &core.Capabilities{
			Drop: []core.Capability{"NET_RAW"},
		},
	}

	otherTests := map[string]struct {
		obj         runtime.Object
		oldObj      runtime.Object
		kind        string
		namespace   string
		name        string
		resource    string
		subresource string
		operation   admission.Operation
		options     runtime.Object
		expectErr   bool
		expected    runtime.Object
	}{
		"other resource": {
			obj:       gvisorPod,
			kind:      "Foo",
			namespace: gvisorPod.Namespace,
			name:      gvisorPod.Name,
			resource:  "foos",
			operation: admission.Create,
			options:   &metav1.CreateOptions{},
			expected:  expectedGvisorPod,
		},
		"non-empty subresource": {
			obj:         gvisorPod,
			kind:        "Pod",
			namespace:   gvisorPod.Namespace,
			name:        gvisorPod.Name,
			resource:    "pods",
			subresource: "foo",
			operation:   admission.Create,
			options:     &metav1.CreateOptions{},
			expected:    expectedGvisorPod,
		},
		"non-create pod operation": {
			obj:       gvisorPod,
			kind:      "Pod",
			namespace: gvisorPod.Namespace,
			name:      gvisorPod.Name,
			resource:  "pods",
			operation: admission.Delete,
			options:   &metav1.DeleteOptions{},
			expected:  expectedGvisorPod,
		},
		"create non-pod marked as kind pod": {
			obj:       &core.Service{},
			kind:      "Pod",
			namespace: gvisorPod.Namespace,
			name:      gvisorPod.Name,
			resource:  "pods",
			operation: admission.Create,
			options:   &metav1.CreateOptions{},
			expectErr: true,
		},
		"ephemeral container": {
			obj:         ephemeralPod,
			oldObj:      gvisorPod,
			kind:        "Pod",
			namespace:   ephemeralPod.Namespace,
			name:        ephemeralPod.Name,
			resource:    "pods",
			subresource: subresEphemeralContainers,
			operation:   admission.Update,
			expected:    expectedEphemeralPod,
		},
	}

	for name, test := range otherTests {
		t.Run(name, func(t *testing.T) {
			gvisor := new()
			// Ensure test pod isn't changed because it may be used by multiple tests.
			newObj := test.obj.DeepCopyObject()
			var oldObj runtime.Object
			if test.oldObj != nil {
				oldObj = test.oldObj.DeepCopyObject()
			}
			attrs := admission.NewAttributesRecord(newObj, oldObj, core.Kind(test.kind).WithVersion("version"), test.namespace, test.name, core.Resource(test.resource).WithVersion("version"), test.subresource, test.operation, test.options, false, nil)
			if err := gvisor.Admit(context.TODO(), attrs, nil); test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, newObj)
			}
		})
	}
}

func TestAdmitPodCreate(t *testing.T) {
	tests := map[string]struct {
		pod       core.Pod
		expected  core.Pod
		expectErr bool
	}{
		"create regular pod": {
			pod:       core.Pod{},
			expectErr: false,
			expected:  core.Pod{},
		},
		"pod with deprecated annotation": {
			pod: core.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "gvisor-pod",
					Annotations: map[string]string{
						"runtime-handler.cri.kubernetes.io":    "gvisor",
						"io.kubernetes.cri.untrusted-workload": "true",
					},
				},
				Spec: core.PodSpec{
					Containers: []core.Container{{Image: "my-image:v1"}},
				},
			},
			expectErr: true,
		},
		"create pod with gvisor runtimeclass": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
				},
			},
			expectErr: false,
			expected: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
				},
			},
		},
		"create pod with non-gvisor runtimeclass": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr("other"),
				},
			},
			expectErr: false,
			expected: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr("other"),
				},
			},
		},
		"gvisor pod with host path": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					Volumes: []core.Volume{
						{
							Name: "test-host-path",
							VolumeSource: core.VolumeSource{
								HostPath: &core.HostPathVolumeSource{
									Path: "/test/host/path",
								},
							},
						},
					},
				},
			},
			expectErr: true,
		},
		"empty pod": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
				},
			},
			expectErr: false,
			expected: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
				},
			},
		},
		"pod NET_RAW capability": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					InitContainers: []core.Container{
						{
							Name: "init-container-with-net-raw-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "init-container-with-net-raw-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "init-container-without-net-raw",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{},
								},
							},
						},
						{
							Name:            "init-container-without-capabilities",
							SecurityContext: &core.SecurityContext{},
						},
						{
							Name: "init-container-without-security-context",
						},
						{
							Name: "init-container-with-all-caps-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"ALL"},
								},
							},
						},
						{
							Name: "init-container-with-all-caps-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"ALL"},
								},
							},
						},
					},
					Containers: []core.Container{
						{
							Name: "container-with-net-raw-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "container-with-net-raw-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "container-without-net-raw",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{},
								},
							},
						},
						{
							Name:            "container-without-capabilities",
							SecurityContext: &core.SecurityContext{},
						},
						{
							Name: "container-without-security-context",
						},
						{
							Name: "container-with-all-caps-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"ALL"},
								},
							},
						},
						{
							Name: "container-with-all-caps-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"ALL"},
								},
							},
						},
					},
				},
			},
			expectErr: false,
			expected: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					InitContainers: []core.Container{
						{
							Name: "init-container-with-net-raw-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "init-container-with-net-raw-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "init-container-without-net-raw",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "init-container-without-capabilities",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "init-container-without-security-context",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "init-container-with-all-caps-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"ALL"},
								},
							},
						},
						{
							Name: "init-container-with-all-caps-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"ALL"},
								},
							},
						},
					},
					Containers: []core.Container{
						{
							Name: "container-with-net-raw-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "container-with-net-raw-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "container-without-net-raw",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "container-without-capabilities",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "container-without-security-context",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "container-with-all-caps-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"ALL"},
								},
							},
						},
						{
							Name: "container-with-all-caps-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"ALL"},
								},
							},
						},
					},
				},
			},
		},
		"internal annotation": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
				},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"dev.gvisor.internal.foo": "bar",
					},
				},
			},
			expectErr: true,
		},
		"seccomp RuntimeDefault": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []core.Container{
						{Name: "cont1"},
						{Name: "cont2"},
					},
					InitContainers: []core.Container{
						{Name: "init"},
					},
				},
			},
			expectErr: false,
			expected: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []core.Container{
						{
							Name: "cont1",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "cont2",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
					},
					InitContainers: []core.Container{
						{
							Name: "init",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
					},
				},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"dev.gvisor.internal.seccomp.cont1": string(core.SeccompProfileTypeRuntimeDefault),
						"dev.gvisor.internal.seccomp.cont2": string(core.SeccompProfileTypeRuntimeDefault),
						"dev.gvisor.internal.seccomp.init":  string(core.SeccompProfileTypeRuntimeDefault),
					},
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			attrs := makePodCreateAttrs(&test.pod, "")
			err := admitPodCreate(attrs)
			if test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, test.pod)
			}
		})
	}
}

func TestMutateGVisorPod(t *testing.T) {
	for name, test := range map[string]struct {
		pod      core.Pod
		expected core.Pod
	}{
		"empty pod": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
				},
			},
			expected: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
				},
			},
		},
		"pod NET_RAW capability": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					InitContainers: []core.Container{
						{
							Name: "init-container-with-net-raw-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "init-container-with-net-raw-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "init-container-without-net-raw",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{},
								},
							},
						},
						{
							Name:            "init-container-without-capabilities",
							SecurityContext: &core.SecurityContext{},
						},
						{
							Name: "init-container-without-security-context",
						},
						{
							Name: "init-container-with-all-caps-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"ALL"},
								},
							},
						},
						{
							Name: "init-container-with-all-caps-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"ALL"},
								},
							},
						},
					},
					Containers: []core.Container{
						{
							Name: "container-with-net-raw-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "container-with-net-raw-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "container-without-net-raw",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{},
								},
							},
						},
						{
							Name:            "container-without-capabilities",
							SecurityContext: &core.SecurityContext{},
						},
						{
							Name: "container-without-security-context",
						},
						{
							Name: "container-with-all-caps-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"ALL"},
								},
							},
						},
						{
							Name: "container-with-all-caps-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"ALL"},
								},
							},
						},
					},
				},
			},
			expected: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					InitContainers: []core.Container{
						{
							Name: "init-container-with-net-raw-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "init-container-with-net-raw-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "init-container-without-net-raw",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "init-container-without-capabilities",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "init-container-without-security-context",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "init-container-with-all-caps-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"ALL"},
								},
							},
						},
						{
							Name: "init-container-with-all-caps-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"ALL"},
								},
							},
						},
					},
					Containers: []core.Container{
						{
							Name: "container-with-net-raw-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "container-with-net-raw-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "container-without-net-raw",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "container-without-capabilities",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "container-without-security-context",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"NET_RAW"},
								},
							},
						},
						{
							Name: "container-with-all-caps-added",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Add: []core.Capability{"ALL"},
								},
							},
						},
						{
							Name: "container-with-all-caps-dropped",
							SecurityContext: &core.SecurityContext{
								Capabilities: &core.Capabilities{
									Drop: []core.Capability{"ALL"},
								},
							},
						},
					},
				},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			pod := test.pod
			mutateGVisorPod(&pod)
			assert.Equal(t, test.expected, pod)
		})
	}
}

func TestNodeSelectorConflict(t *testing.T) {
	pod := core.Pod{
		Spec: core.PodSpec{
			RuntimeClassName: toPtr(gvisorRuntimeClass),
			NodeSelector:     map[string]string{gvisorNodeKey: "other"},
		},
	}
	err := validateGVisorPod(&pod)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "conflict:")
}

func createEmptyDir(name string, medium core.StorageMedium) core.Volume {
	return core.Volume{
		Name: name,
		VolumeSource: core.VolumeSource{
			EmptyDir: &core.EmptyDirVolumeSource{
				Medium: medium,
			},
		},
	}
}

func createContainer(name string, readonly bool, prop core.MountPropagationMode, volumes ...string) core.Container {
	c := core.Container{
		Name:         name,
		VolumeMounts: make([]core.VolumeMount, 0, len(volumes)),
	}
	for _, v := range volumes {
		c.VolumeMounts = append(c.VolumeMounts, core.VolumeMount{
			Name:             v,
			ReadOnly:         readonly,
			MountPropagation: mountPropagationModePtr(prop),
		})
	}
	return c
}

type annotation struct {
	name    string
	typ     string
	share   string
	options string
}

func createAnnotations(annons ...annotation) map[string]string {
	rv := map[string]string{}
	for _, a := range annons {
		rv["dev.gvisor.spec.mount."+a.name+".type"] = a.typ
		rv["dev.gvisor.spec.mount."+a.name+".share"] = a.share
		rv["dev.gvisor.spec.mount."+a.name+".options"] = a.options
	}
	return rv
}

func TestVolumeHints(t *testing.T) {
	type test struct {
		name       string
		volumes    []core.Volume
		containers []core.Container
		want       map[string]string
	}
	var tests []test

	// Add tests that are the same for all mediums.
	for _, medium := range []core.StorageMedium{core.StorageMediumDefault, core.StorageMediumMemory, core.StorageMediumHugePages} {
		typ, err := getMountType(medium)
		assert.NoError(t, err)

		tests = append(tests,
			test{
				name: typ + ": volume not used",
				volumes: []core.Volume{
					createEmptyDir("empty", medium),
				},
				containers: []core.Container{
					createContainer("container", false, core.MountPropagationNone),
				},
				want: nil,
			},
			test{
				name: typ + ": access type mismatch",
				volumes: []core.Volume{
					createEmptyDir("empty", medium),
				},
				containers: []core.Container{
					createContainer("container", false, core.MountPropagationNone),
					createContainer("container", true, core.MountPropagationNone),
				},
				want: nil,
			},
			test{
				name: typ + ": propagation mismatch",
				volumes: []core.Volume{
					createEmptyDir("empty", medium),
				},
				containers: []core.Container{
					createContainer("container", false, core.MountPropagationNone),
					createContainer("container", false, core.MountPropagationHostToContainer),
				},
				want: nil,
			},
			test{
				name: typ + ": subpath",
				volumes: []core.Volume{
					createEmptyDir("empty", medium),
				},
				containers: []core.Container{
					{
						Name: "container",
						VolumeMounts: []core.VolumeMount{
							{
								Name:    "empty",
								SubPath: "/subpath",
							},
						},
					},
				},
				want: nil,
			},
			test{
				name: typ + ": subpathexpr",
				volumes: []core.Volume{
					createEmptyDir("empty", medium),
				},
				containers: []core.Container{
					{
						Name: "container",
						VolumeMounts: []core.VolumeMount{
							{
								Name:        "empty",
								SubPathExpr: "/subpath",
							},
						},
					},
				},
				want: nil,
			},
			test{
				name:    typ + ": not empty",
				volumes: []core.Volume{{Name: "non-empty"}},
				containers: []core.Container{
					createContainer("container", false, core.MountPropagationNone, "non-empty"),
				},
				want: nil,
			},
			test{
				name: typ + ": default propagation",
				volumes: []core.Volume{
					createEmptyDir("empty", medium),
				},
				containers: []core.Container{
					{
						Name:         "container",
						VolumeMounts: []core.VolumeMount{{Name: "empty"}},
					},
				},
				want: createAnnotations(annotation{
					name:    "empty",
					typ:     typ,
					share:   "container",
					options: "rw,rprivate",
				}),
			},
			test{
				name: typ + ": rw + ro",
				volumes: []core.Volume{
					createEmptyDir("empty", medium),
				},
				containers: []core.Container{
					{
						Name:         "read-only",
						VolumeMounts: []core.VolumeMount{{Name: "empty", ReadOnly: true}},
					},
					{
						Name:         "read-write",
						VolumeMounts: []core.VolumeMount{{Name: "empty"}},
					},
				},
				want: createAnnotations(annotation{
					name:    "empty",
					typ:     typ,
					share:   "pod",
					options: "rw,rprivate",
				}),
			},
		)

		for _, readonly := range []bool{true, false} {
			for _, prop := range []core.MountPropagationMode{core.MountPropagationNone, core.MountPropagationHostToContainer} {
				options := "rw"
				if readonly {
					options = "ro"
				}
				if prop == core.MountPropagationNone {
					options += ",rprivate"
				} else {
					options += ",rslave"
				}

				tests = append(tests,
					test{
						name: fmt.Sprintf("%s+readonly(%t)+%s: container", typ, readonly, prop),
						volumes: []core.Volume{
							createEmptyDir("empty", medium),
						},
						containers: []core.Container{
							createContainer("container", readonly, prop, "empty"),
						},
						want: createAnnotations(annotation{
							name:    "empty",
							typ:     typ,
							share:   "container",
							options: options,
						}),
					},
					test{
						name: fmt.Sprintf("%s+readonly(%t)+%s: container + empty container", typ, readonly, prop),
						volumes: []core.Volume{
							createEmptyDir("empty", medium),
						},
						containers: []core.Container{
							createContainer("container1", readonly, prop, "empty"),
							createContainer("container2", readonly, prop),
						},
						want: createAnnotations(annotation{
							name:    "empty",
							typ:     typ,
							share:   "container",
							options: options,
						}),
					},
					test{
						name: fmt.Sprintf("%s+readonly(%t)+%s: pod", typ, readonly, prop),
						volumes: []core.Volume{
							createEmptyDir("empty", medium),
						},
						containers: []core.Container{
							createContainer("container1", readonly, prop, "empty"),
							createContainer("container2", readonly, prop, "empty"),
						},
						want: createAnnotations(annotation{
							name:    "empty",
							typ:     typ,
							share:   "pod",
							options: options,
						}),
					},
					test{
						name: fmt.Sprintf("%s+readonly(%t)+%s: two mounts", typ, readonly, prop),
						volumes: []core.Volume{
							createEmptyDir("empty1", medium),
							createEmptyDir("empty2", medium),
						},
						containers: []core.Container{
							createContainer("container1", readonly, prop, "empty1", "empty2"),
						},
						want: createAnnotations(
							annotation{
								name:    "empty1",
								typ:     typ,
								share:   "container",
								options: options,
							},
							annotation{
								name:    "empty2",
								typ:     typ,
								share:   "container",
								options: options,
							}),
					},
				)
			}
		}
	}

	tests = append(tests,
		test{
			name: "combo",
			volumes: []core.Volume{
				createEmptyDir("empty-default", core.StorageMediumDefault),
				createEmptyDir("empty-memory", core.StorageMediumMemory),
				createEmptyDir("empty-huge", core.StorageMediumHugePages),
				createEmptyDir("empty-memory-shared", core.StorageMediumMemory),
				{Name: "non-empty"},
			},
			containers: []core.Container{
				createContainer("container", false, core.MountPropagationNone, "empty-default", "empty-memory", "empty-huge", "non-empty"),
				createContainer("container", false, core.MountPropagationNone, "empty-memory-shared", "non-empty"),
				createContainer("container", false, core.MountPropagationNone, "empty-memory-shared"),
				createContainer("container", false, core.MountPropagationNone),
			},
			want: createAnnotations(
				annotation{
					name:    "empty-default",
					typ:     "bind",
					share:   "container",
					options: "rw,rprivate",
				},
				annotation{
					name:    "empty-memory",
					typ:     "tmpfs",
					share:   "container",
					options: "rw,rprivate",
				},
				annotation{
					name:    "empty-huge",
					typ:     "tmpfs",
					share:   "container",
					options: "rw,rprivate",
				},
				annotation{
					name:    "empty-memory-shared",
					typ:     "tmpfs",
					share:   "pod",
					options: "rw,rprivate",
				},
			),
		},
	)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for i := range tc.containers {
				// Shift containers to run with different orders.
				containers := append(tc.containers[i:], tc.containers[0:i]...)
				pod := core.Pod{
					Spec: core.PodSpec{
						Volumes:    tc.volumes,
						Containers: containers,
					},
				}
				mutateGVisorPod(&pod)
				assert.Equal(t, tc.want, pod.Annotations)

				// Make one of the containers an init container. End result should
				// be the same.
				pod.Annotations = nil
				pod.Spec.InitContainers = []core.Container{containers[0]}
				pod.Spec.Containers = containers[1:]
				mutateGVisorPod(&pod)
				assert.Equal(t, tc.want, pod.Annotations)

				// Make one of the containers an ephemeral container. End result should
				// be the same.
				pod.Annotations = nil
				pod.Spec.InitContainers = nil
				pod.Spec.EphemeralContainers = []core.EphemeralContainer{
					{
						EphemeralContainerCommon: core.EphemeralContainerCommon(containers[0]),
					},
				}
				pod.Spec.Containers = containers[1:]
				mutateGVisorPod(&pod)
				assert.Equal(t, tc.want, pod.Annotations)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	gvisor := new()

	createPodTests := map[string]struct {
		pod       core.Pod
		expectErr bool
	}{
		"create regular pod": {
			pod:       core.Pod{},
			expectErr: false,
		},
		"pod with deprecated annotation": {
			pod: core.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "gvisor-pod",
					Annotations: map[string]string{
						"runtime-handler.cri.kubernetes.io":    "gvisor",
						"io.kubernetes.cri.untrusted-workload": "true",
					},
				},
				Spec: core.PodSpec{
					Containers: []core.Container{{Image: "my-image:v1"}},
				},
			},
			expectErr: true,
		},
		"create pod with gvisor runtimeclass": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
				},
			},
			expectErr: false,
		},
		"create pod with non-gvisor runtimeclass": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr("other"),
				},
			},
			expectErr: false,
		},
		"create gvisor pod with some disallowed options": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					SecurityContext: &core.PodSecurityContext{
						HostNetwork: true,
						HostPID:     true,
						HostIPC:     true,
						SELinuxOptions: &core.SELinuxOptions{
							User:  "user",
							Role:  "role",
							Type:  "type",
							Level: "level",
						},
						FSGroup: toPtr[int64](1234),
						Sysctls: []core.Sysctl{
							{
								Name:  "kernel.shm_rmid_forced",
								Value: "0",
							},
						},
					},
					Containers: []core.Container{
						{
							Name: "container",
							VolumeDevices: []core.VolumeDevice{
								{
									Name:       "dev1",
									DevicePath: "/dev/dev1",
								},
							},
						},
					},
				},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"seccomp.security.alpha.kubernetes.io/pod":            "test",
						"container.seccomp.security.alpha.kubernetes.io/test": "test",
						"container.apparmor.security.beta.kubernetes.io/test": "test",
					},
				},
			},
			expectErr: true,
		},
	}

	for name, test := range createPodTests {
		t.Run(name, func(t *testing.T) {
			for name, attrs := range map[string]admission.Attributes{
				"empty":  makePodCreateAttrs(&test.pod, ""),
				"status": makePodCreateAttrs(&test.pod, "status"),
			} {
				t.Run(name, func(t *testing.T) {
					err := gvisor.Validate(context.TODO(), attrs, nil)
					if test.expectErr {
						assert.Error(t, err)
					} else {
						assert.NoError(t, err)
					}
				})
			}
		})
	}

	gvisorPod := &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gvisor-pod",
		},
		Spec: core.PodSpec{
			Containers:       []core.Container{{Image: "my-image:v1"}},
			RuntimeClassName: toPtr("gvisor"),
		},
	}
	deprecatedGvisorPod := &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gvisor-pod",
			Annotations: map[string]string{
				"runtime-handler.cri.kubernetes.io":    "gvisor",
				"io.kubernetes.cri.untrusted-workload": "true",
			},
		},
		Spec: core.PodSpec{
			Containers: []core.Container{{Image: "my-image:v1"}},
		},
	}
	nativePod := &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "native-pod",
		},
		Spec: core.PodSpec{
			Containers: []core.Container{{Image: "my-image:v1"}},
		},
	}
	gvisorPodNewImage := gvisorPod.DeepCopy()
	gvisorPodNewImage.Spec.Containers[0].Image = "my-image:v2"

	gvisorPodSeccomp := &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gvisor-pod",
			Annotations: map[string]string{
				"dev.gvisor.internal.seccomp.cont": string(core.SeccompProfileTypeRuntimeDefault),
			},
		},
		Spec: core.PodSpec{
			Containers:       []core.Container{{Name: "cont"}},
			RuntimeClassName: toPtr("gvisor"),
			SecurityContext: &core.PodSecurityContext{
				SeccompProfile: &core.SeccompProfile{
					Type: core.SeccompProfileTypeRuntimeDefault,
				},
			},
		},
	}
	gvisorPodSeccompInvalidAnnotation := gvisorPodSeccomp.DeepCopy()
	gvisorPodSeccompInvalidAnnotation.Annotations["dev.gvisor.internal.seccomp.cont"] = "another-value"

	updatePodTests := map[string]struct {
		oldPod, newPod *core.Pod
		expectErr      bool
	}{
		"non-gvisor->non-gvisor": {
			oldPod:    nativePod.DeepCopy(),
			newPod:    nativePod.DeepCopy(),
			expectErr: false,
		},
		"gvisor->deprecated-gvisor": {
			oldPod:    gvisorPod.DeepCopy(),
			newPod:    deprecatedGvisorPod.DeepCopy(),
			expectErr: true,
		},
		"gvisor->modified-image": {
			oldPod:    gvisorPod.DeepCopy(),
			newPod:    gvisorPodNewImage.DeepCopy(),
			expectErr: false,
		},
		"gvisor->seccomp": {
			oldPod:    gvisorPodSeccomp.DeepCopy(),
			newPod:    gvisorPodSeccomp.DeepCopy(),
			expectErr: false,
		},
		"gvisor->annotation-changed": {
			oldPod:    gvisorPodSeccomp.DeepCopy(),
			newPod:    gvisorPodSeccompInvalidAnnotation.DeepCopy(),
			expectErr: true,
		},
	}
	for name, test := range updatePodTests {
		t.Run(name, func(t *testing.T) {
			for name, attrs := range map[string]admission.Attributes{
				"empty":  makePodUpdateAttrs(test.newPod, test.oldPod, ""),
				"status": makePodUpdateAttrs(test.newPod, test.oldPod, "status"),
			} {
				t.Run(name, func(t *testing.T) {
					err := gvisor.Validate(context.TODO(), attrs, nil)
					if test.expectErr {
						assert.Error(t, err)
					} else {
						assert.NoError(t, err)
					}
				})
			}
		})
	}

	runtimeclassTests := map[string]struct {
		obj       *node.RuntimeClass
		oldObj    runtime.Object
		operation admission.Operation
		options   runtime.Object
		expectErr bool
	}{
		"create gvisor rtc": {
			obj: &node.RuntimeClass{
				ObjectMeta: metav1.ObjectMeta{Name: "gvisor"},
				Handler:    "gvisor",
			},
			operation: admission.Create,
			options:   &metav1.CreateOptions{},
			expectErr: false,
		},
		"update gvisor rtc": {
			obj: &node.RuntimeClass{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Handler:    "bar",
			},
			oldObj: &node.RuntimeClass{
				ObjectMeta: metav1.ObjectMeta{Name: "gvisor"},
				Handler:    "gvisor",
			},
			operation: admission.Update,
			options:   &metav1.UpdateOptions{},
			expectErr: false,
		},
		"delete gvisor rtc": {
			obj: &node.RuntimeClass{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Handler:    "bar",
			},
			operation: admission.Delete,
			options:   &metav1.DeleteOptions{},
			expectErr: false,
		},
		"create with non-gvisor handler": {
			obj: &node.RuntimeClass{
				ObjectMeta: metav1.ObjectMeta{Name: "gvisor"},
				Handler:    "foo",
			},
			operation: admission.Create,
			options:   &metav1.CreateOptions{},
			expectErr: true,
		},
		"create non-gvisor runtimeclass": {
			obj: &node.RuntimeClass{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Handler:    "bar",
			},
			operation: admission.Create,
			options:   &metav1.CreateOptions{},
			expectErr: false,
		},
	}

	for testName, test := range runtimeclassTests {
		t.Run(testName, func(t *testing.T) {
			attrs := admission.NewAttributesRecord(test.obj, test.oldObj, node.Kind("RuntimeClass").WithVersion("version"), "testnamespace", test.obj.Name, node.Resource("runtimeclasses").WithVersion("version"), "", test.operation, test.options, false, &user.DefaultInfo{})
			err := gvisor.Validate(context.TODO(), attrs, nil)
			if test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	gvisorPod = &core.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "testname", Namespace: "testnamespace"},
		Spec: core.PodSpec{
			RuntimeClassName: toPtr(gvisorRuntimeClass),
		},
	}

	otherTests := map[string]struct {
		obj         runtime.Object
		oldObj      runtime.Object
		kind        string
		namespace   string
		name        string
		resource    string
		subresource string
		operation   admission.Operation
		options     runtime.Object
		expectErr   bool
	}{
		"other resource": {
			obj:       gvisorPod,
			kind:      "Foo",
			namespace: gvisorPod.Namespace,
			name:      gvisorPod.Name,
			resource:  "foos",
			operation: admission.Create,
			options:   &metav1.CreateOptions{},
			expectErr: false,
		},
		"non-empty subresource": {
			obj:         gvisorPod,
			kind:        "Pod",
			namespace:   gvisorPod.Namespace,
			name:        gvisorPod.Name,
			resource:    "pods",
			subresource: "foo",
			operation:   admission.Create,
			options:     &metav1.CreateOptions{},
			expectErr:   false,
		},
		"non-create/update pod operation": {
			obj:       gvisorPod,
			kind:      "Pod",
			namespace: gvisorPod.Namespace,
			name:      gvisorPod.Name,
			resource:  "pods",
			operation: admission.Delete,
			options:   &metav1.DeleteOptions{},
			expectErr: false,
		},
		"create non-pod marked as kind pod": {
			obj:       &core.Service{},
			kind:      "Pod",
			namespace: gvisorPod.Namespace,
			name:      gvisorPod.Name,
			resource:  "pods",
			operation: admission.Create,
			options:   &metav1.CreateOptions{},
			expectErr: true,
		},
		"update non-pod marked as kind pod": {
			obj:       gvisorPod,
			oldObj:    &core.Service{},
			kind:      "Pod",
			namespace: gvisorPod.Namespace,
			name:      gvisorPod.Name,
			resource:  "pods",
			operation: admission.Update,
			options:   &metav1.UpdateOptions{},
			expectErr: true,
		},
		"update pod to non-pod marked as kind pod": {
			obj:       &core.Service{},
			oldObj:    gvisorPod,
			kind:      "Pod",
			namespace: gvisorPod.Namespace,
			name:      gvisorPod.Name,
			resource:  "pods",
			operation: admission.Update,
			options:   &metav1.UpdateOptions{},
			expectErr: true,
		},
	}

	for name, test := range otherTests {
		t.Run(name, func(t *testing.T) {
			attrs := admission.NewAttributesRecord(test.obj, test.oldObj, core.Kind(test.kind).WithVersion("version"), test.namespace, test.name, core.Resource(test.resource).WithVersion("version"), test.subresource, test.operation, test.options, false, nil)
			err := gvisor.Validate(context.TODO(), attrs, nil)
			if test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	t.Run("non-rtc object marked as kind rtc", func(t *testing.T) {
		attrs := admission.NewAttributesRecord(gvisorPod, nil, node.Kind("RuntimeClass").WithVersion("version"), "testnamespace", gvisorRuntimeClass, node.Resource("runtimeclasses").WithVersion("version"), "", admission.Create, &metav1.CreateOptions{}, false, nil)
		err := gvisor.Validate(context.TODO(), attrs, nil)
		assert.Error(t, err)
	})
}

func TestValidateEphemeral(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pod     core.Pod
		wantErr string
	}{
		{
			name: "happy",
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr("other"),
					Containers:       []core.Container{{Name: "main"}},
					EphemeralContainers: []core.EphemeralContainer{
						{
							EphemeralContainerCommon: core.EphemeralContainerCommon{Name: "ephemeral"},
						},
					},
				},
			},
		},
		{
			name: "multiple",
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr("other"),
					Containers:       []core.Container{{Name: "main"}},
					EphemeralContainers: []core.EphemeralContainer{
						{
							EphemeralContainerCommon: core.EphemeralContainerCommon{Name: "ephemeral1"},
						},
						{
							EphemeralContainerCommon: core.EphemeralContainerCommon{Name: "ephemeral2"},
						},
						{
							EphemeralContainerCommon: core.EphemeralContainerCommon{Name: "ephemeral3"},
						},
					},
				},
			},
		},
		{
			// Other invalid variations are tested in TestValidateContainer.
			name: "invalid",
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					Containers:       []core.Container{{Name: "main"}},
					EphemeralContainers: []core.EphemeralContainer{
						{
							EphemeralContainerCommon: core.EphemeralContainerCommon{
								Name: "ephemeral",
								VolumeDevices: []core.VolumeDevice{
									{Name: "forbidden"},
								},
							},
						},
					},
				},
			},
			wantErr: "VolumeDevices is not supported",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldPod := tc.pod.DeepCopy()
			oldPod.Spec.EphemeralContainers = nil
			attrs := makePodUpdateAttrs(&tc.pod, oldPod, subresEphemeralContainers)
			gvisor := new()
			if err := gvisor.Validate(context.TODO(), attrs, nil); len(tc.wantErr) == 0 {
				assert.NoError(t, err)
			} else if assert.Error(t, err) {
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

// non-pod
// no runtimeclass or difference runtimeclass
// some subset of validation tests
func TestValidatePodCreate(t *testing.T) {
	tests := map[string]struct {
		pod       core.Pod
		expectErr bool
	}{
		"create regular pod": {
			pod:       core.Pod{},
			expectErr: false,
		},
		"pod with deprecated annotation": {
			pod: core.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "gvisor-pod",
					Annotations: map[string]string{
						"runtime-handler.cri.kubernetes.io":    "gvisor",
						"io.kubernetes.cri.untrusted-workload": "true",
					},
				},
				Spec: core.PodSpec{
					Containers: []core.Container{{Image: "my-image:v1"}},
				},
			},
			expectErr: true,
		},
		"create pod with gvisor runtimeclass": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
				},
			},
			expectErr: false,
		},
		"create pod with non-gvisor runtimeclass": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr("other"),
				},
			},
			expectErr: false,
		},
		"create gvisor pod with existing node selector": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					NodeSelector:     map[string]string{"other": "selector"},
				},
			},
			expectErr: false,
		},
		"create gvisor pod with non-gvisor runtime node selector": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					NodeSelector:     map[string]string{gvisorNodeKey: "other"},
				},
			},
			expectErr: true,
		},
		"gvisor pod with host path": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					Volumes: []core.Volume{
						{
							Name: "test-host-path",
							VolumeSource: core.VolumeSource{
								HostPath: &core.HostPathVolumeSource{
									Path: "/test/host/path",
								},
							},
						},
					},
				},
			},
			expectErr: true,
		},
		"gvisor pod with disallowed security context options": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					SecurityContext: &core.PodSecurityContext{
						HostNetwork: true,
						HostPID:     true,
						HostIPC:     true,
						SELinuxOptions: &core.SELinuxOptions{
							User:  "user",
							Role:  "role",
							Type:  "type",
							Level: "level",
						},
						FSGroup: toPtr[int64](1234),
						Sysctls: []core.Sysctl{
							{
								Name:  "kernel.shm_rmid_forced",
								Value: "0",
							},
						},
					},
				},
			},
			expectErr: true,
		},
		"gvisor pod with Privileged container": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					Containers: []core.Container{
						{
							Name: "container",
							SecurityContext: &core.SecurityContext{
								Privileged: toPtr(true),
							},
						},
					},
				},
			},
			expectErr: true,
		},
		"gvisor pod with Privileged init container": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					InitContainers: []core.Container{
						{
							Name: "container",
							SecurityContext: &core.SecurityContext{
								Privileged: toPtr(true),
							},
						},
					},
				},
			},
			expectErr: true,
		},
		"gvisor pod with AllowPrivilegeEscalation container": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					Containers: []core.Container{
						{
							Name: "container",
							SecurityContext: &core.SecurityContext{
								AllowPrivilegeEscalation: toPtr(true),
							},
						},
					},
				},
			},
			expectErr: true,
		},
		"gvisor pod with VolumeDevices container": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
					Containers: []core.Container{
						{
							Name: "container",
							VolumeDevices: []core.VolumeDevice{
								{
									Name:       "dev1",
									DevicePath: "/dev/dev1",
								},
							},
						},
					},
				},
			},
			expectErr: true,
		},
		"gvisor pod with disallowed annotations": {
			pod: core.Pod{
				Spec: core.PodSpec{
					RuntimeClassName: toPtr(gvisorRuntimeClass),
				},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"seccomp.security.alpha.kubernetes.io/pod":            "test",
						"container.seccomp.security.alpha.kubernetes.io/test": "test",
						"container.apparmor.security.beta.kubernetes.io/test": "test",
					},
				},
			},
			expectErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := validatePod(makePodCreateAttrs(&test.pod, ""))
			if test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePodUpdate(t *testing.T) {
	gvisorPod := &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gvisor-pod",
		},
		Spec: core.PodSpec{
			Containers:       []core.Container{{Image: "my-image:v1"}},
			RuntimeClassName: toPtr("gvisor"),
		},
	}
	deprecatedGvisorPod := &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gvisor-pod",
			Annotations: map[string]string{
				"runtime-handler.cri.kubernetes.io":    "gvisor",
				"io.kubernetes.cri.untrusted-workload": "true",
			},
		},
		Spec: core.PodSpec{
			Containers: []core.Container{{Image: "my-image:v1"}},
		},
	}
	nativePod := &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "native-pod",
		},
		Spec: core.PodSpec{
			Containers: []core.Container{{Image: "my-image:v1"}},
		},
	}
	gvisorPodNewImage := gvisorPod.DeepCopy()
	gvisorPodNewImage.Spec.Containers[0].Image = "my-image:v2"

	tests := map[string]struct {
		oldPod, newPod *core.Pod
		expectErr      bool
	}{
		"non-gvisor->non-gvisor": {
			oldPod:    nativePod.DeepCopy(),
			newPod:    nativePod.DeepCopy(),
			expectErr: false,
		},
		"gvisor->deprecated-gvisor": {
			oldPod:    gvisorPod.DeepCopy(),
			newPod:    deprecatedGvisorPod.DeepCopy(),
			expectErr: true,
		},
		"gvisor->modified-image": {
			oldPod:    gvisorPod.DeepCopy(),
			newPod:    gvisorPodNewImage.DeepCopy(),
			expectErr: false,
		},
		"non-gvisor->gvisor": {
			oldPod:    nativePod.DeepCopy(),
			newPod:    gvisorPod.DeepCopy(),
			expectErr: true,
		},
		"gvisor->non-gvisor": {
			oldPod:    nativePod.DeepCopy(),
			newPod:    gvisorPod.DeepCopy(),
			expectErr: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			attrs := makePodUpdateAttrs(test.newPod, test.oldPod, "")
			err := validatePod(attrs)
			if test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRuntimeClass(t *testing.T) {
	tests := []struct {
		name, handler string
		expectErr     bool
	}{
		{"", "gvisor", false},
		{"foo", "gvisor", false},
		{"foo", "bar", false},
		{"foo", "", false},
		{"gvisor", "gvisor", false},
		{"gvisor", "bar", true},
		{"gvisor", "", true},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%s-%s-beta", test.name, test.handler), func(t *testing.T) {

			rc := &node.RuntimeClass{
				ObjectMeta: metav1.ObjectMeta{Name: test.name},
				Handler:    test.handler,
			}
			attrs := makeRuntimeClassCreateAttrs(rc)
			err := validateRuntimeClass(attrs)
			if test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSeccomp(t *testing.T) {
	for _, tc := range []struct {
		name string
		pod  core.Pod
		want core.Pod
	}{
		{
			name: "no seccomp",
			pod: core.Pod{
				Spec: core.PodSpec{
					Containers: []core.Container{
						{Name: "cont1"},
					},
				},
			},
			want: core.Pod{
				Spec: core.PodSpec{
					Containers: []core.Container{
						{Name: "cont1"},
					},
				},
			},
		},
		{
			name: "container seccomp",
			pod: core.Pod{
				Spec: core.PodSpec{
					Containers: []core.Container{
						{
							Name: "cont1",
							SecurityContext: &core.SecurityContext{
								SeccompProfile: &core.SeccompProfile{
									Type: core.SeccompProfileTypeRuntimeDefault,
								},
							},
						},
					},
				},
			},
			want: core.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"dev.gvisor.internal.seccomp.cont1": "RuntimeDefault",
					},
				},
				Spec: core.PodSpec{
					Containers: []core.Container{
						{
							Name: "cont1",
							SecurityContext: &core.SecurityContext{
								SeccompProfile: &core.SeccompProfile{
									Type: core.SeccompProfileTypeRuntimeDefault,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "simple pod",
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []core.Container{
						{Name: "cont"},
					},
				},
			},
			want: core.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"dev.gvisor.internal.seccomp.cont": "RuntimeDefault",
					},
				},
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []core.Container{
						{Name: "cont"},
					},
				},
			},
		},
		{
			name: "pod seccomp",
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []core.Container{
						{Name: "cont1"},
						{Name: "cont2"},
					},
					InitContainers: []core.Container{
						{Name: "init"},
					},
				},
			},
			want: core.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"dev.gvisor.internal.seccomp.cont1": "RuntimeDefault",
						"dev.gvisor.internal.seccomp.cont2": "RuntimeDefault",
						"dev.gvisor.internal.seccomp.init":  "RuntimeDefault",
					},
				},
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []core.Container{
						{Name: "cont1"},
						{Name: "cont2"},
					},
					InitContainers: []core.Container{
						{Name: "init"},
					},
				},
			},
		},
		{
			name: "pod not default",
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeLocalhost,
						},
					},
					Containers: []core.Container{
						{Name: "cont1"},
					},
					InitContainers: []core.Container{
						{Name: "init"},
					},
				},
			},
			want: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeLocalhost,
						},
					},
					Containers: []core.Container{
						{Name: "cont1"},
					},
					InitContainers: []core.Container{
						{Name: "init"},
					},
				},
			},
		},
		{
			name: "container override seccomp",
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []core.Container{
						{
							Name: "cont-localhost",
							SecurityContext: &core.SecurityContext{
								SeccompProfile: &core.SeccompProfile{
									Type: core.SeccompProfileTypeLocalhost,
								},
							},
						},
						{Name: "cont-default"},
					},
					InitContainers: []core.Container{
						{Name: "init-default"},
						{
							Name: "init-localhost",
							SecurityContext: &core.SecurityContext{
								SeccompProfile: &core.SeccompProfile{
									Type: core.SeccompProfileTypeLocalhost,
								},
							},
						},
					},
				},
			},
			want: core.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"dev.gvisor.internal.seccomp.cont-default": "RuntimeDefault",
						"dev.gvisor.internal.seccomp.init-default": "RuntimeDefault",
					},
				},
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []core.Container{
						{
							Name: "cont-localhost",
							SecurityContext: &core.SecurityContext{
								SeccompProfile: &core.SeccompProfile{
									Type: core.SeccompProfileTypeLocalhost,
								},
							},
						},
						{Name: "cont-default"},
					},
					InitContainers: []core.Container{
						{Name: "init-default"},
						{
							Name: "init-localhost",
							SecurityContext: &core.SecurityContext{
								SeccompProfile: &core.SeccompProfile{
									Type: core.SeccompProfileTypeLocalhost,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "container override seccomp reverse",
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeLocalhost,
						},
					},
					Containers: []core.Container{
						{
							Name: "cont-default",
							SecurityContext: &core.SecurityContext{
								SeccompProfile: &core.SeccompProfile{
									Type: core.SeccompProfileTypeRuntimeDefault,
								},
							},
						},
						{Name: "cont-locahost"},
					},
					InitContainers: []core.Container{
						{Name: "init-localhost"},
						{
							Name: "init-default",
							SecurityContext: &core.SecurityContext{
								SeccompProfile: &core.SeccompProfile{
									Type: core.SeccompProfileTypeRuntimeDefault,
								},
							},
						},
					},
				},
			},
			want: core.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"dev.gvisor.internal.seccomp.cont-default": "RuntimeDefault",
						"dev.gvisor.internal.seccomp.init-default": "RuntimeDefault",
					},
				},
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeLocalhost,
						},
					},
					Containers: []core.Container{
						{
							Name: "cont-default",
							SecurityContext: &core.SecurityContext{
								SeccompProfile: &core.SeccompProfile{
									Type: core.SeccompProfileTypeRuntimeDefault,
								},
							},
						},
						{Name: "cont-locahost"},
					},
					InitContainers: []core.Container{
						{Name: "init-localhost"},
						{
							Name: "init-default",
							SecurityContext: &core.SecurityContext{
								SeccompProfile: &core.SeccompProfile{
									Type: core.SeccompProfileTypeRuntimeDefault,
								},
							},
						},
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			updateSeccompAnnotations(&tc.pod)
			assert.Equal(t, tc.want, tc.pod)
		})
	}
}

func TestCheckAnnotations(t *testing.T) {
	for _, tc := range []struct {
		name string
		pod  core.Pod
		add  map[string]string
		del  map[string]string
		all  []bool
		err  string
	}{
		{
			name: "empty",
		},
		{
			name: "other annotation",
			add: map[string]string{
				"dev.gvisor.other": "foo",
			},
			del: map[string]string{
				"dev.gvisor.another": "bar",
			},
		},
		{
			name: "seccomp",
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []core.Container{
						{Name: "cont"},
					},
				},
			},
			add: map[string]string{
				"dev.gvisor.internal.seccomp.cont": "RuntimeDefault",
			},
		},
		{
			name: "wrong value",
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []core.Container{
						{Name: "cont"},
					},
				},
			},
			add: map[string]string{
				"dev.gvisor.internal.seccomp.cont": "Unconfined",
			},
			err: `expected value: "RuntimeDefault"`,
		},
		{
			name: "invalid name",
			pod:  core.Pod{},
			add: map[string]string{
				"dev.gvisor.internal.foo": "bar",
			},
			err: `annotations starting with "dev.gvisor.internal." are not allowed`,
		},
		{
			name: "wrong value",
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []core.Container{
						{Name: "cont"},
					},
				},
			},
			add: map[string]string{
				"dev.gvisor.internal.seccomp.cont": "Unconfined",
			},
			err: `expected value: "RuntimeDefault"`,
		},
		{
			name: "missing",
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []core.Container{
						{Name: "cont"},
					},
				},
			},
			add: map[string]string{
				"other.annotations": "true",
			},
			all: []bool{true},
			err: "annotation was removed from pod",
		},
		{
			name: "removal",
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []core.Container{
						{Name: "cont"},
					},
				},
			},
			del: map[string]string{
				"dev.gvisor.internal.seccomp.cont": "Unconfined",
			},
			err: "annotation was removed from pod",
		},
		{
			name: "removal other",
			del: map[string]string{
				"dev.gvisor.other": "foo",
			},
		},
		{
			// Check that only what has been removed is validated. The missing seccomp
			// annotation is ignored on update.
			name: "removal other update",
			pod: core.Pod{
				Spec: core.PodSpec{
					SecurityContext: &core.PodSecurityContext{
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []core.Container{
						{Name: "cont"},
					},
				},
			},
			del: map[string]string{
				"dev.gvisor.other": "foo",
			},
			all: []bool{false},
		},
		{
			name: "mount wrong key",
			pod: core.Pod{
				Spec: core.PodSpec{
					Containers: []core.Container{
						{
							Name: "cont",
							VolumeMounts: []core.VolumeMount{
								{Name: "empty"},
							},
						},
					},
					Volumes: []core.Volume{
						createEmptyDir("empty", core.StorageMediumDefault),
					},
				},
			},
			add: map[string]string{
				"dev.gvisor.spec.mount.foo.share": "container",
			},
			err: `user annotations starting with "dev.gvisor.spec.mount." are not allowed`,
		},
		{
			name: "mount wrong value",
			pod: core.Pod{
				Spec: core.PodSpec{
					Containers: []core.Container{
						{
							Name: "cont",
							VolumeMounts: []core.VolumeMount{
								{Name: "empty"},
							},
						},
					},
					Volumes: []core.Volume{
						createEmptyDir("empty", core.StorageMediumDefault),
					},
				},
			},
			add: map[string]string{
				"dev.gvisor.spec.mount.empty.type":    "bind",
				"dev.gvisor.spec.mount.empty.share":   "foo",
				"dev.gvisor.spec.mount.empty.options": "rw,rprivate",
			},
			err: `expected value: "container"`,
		},
		{
			name: "mount missing",
			pod: core.Pod{
				Spec: core.PodSpec{
					Containers: []core.Container{
						{
							Name: "cont",
							VolumeMounts: []core.VolumeMount{
								{Name: "empty"},
							},
						},
					},
					Volumes: []core.Volume{
						createEmptyDir("empty", core.StorageMediumDefault),
					},
				},
			},
			all: []bool{true},
			err: "annotation was removed from pod",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.all == nil {
				tc.all = []bool{true, false}
			}
			for _, all := range tc.all {
				t.Run(fmt.Sprintf("%t", all), func(t *testing.T) {
					err := checkAnnotations(&tc.pod, tc.add, tc.del, all)
					if len(tc.err) == 0 {
						assert.NoError(t, err)
					} else if assert.Error(t, err) {
						assert.Contains(t, err.Error(), tc.err)
					}
				})
			}
		})
	}
}

func TestAnnotationDiff(t *testing.T) {
	for _, tc := range []struct {
		name string
		old  map[string]string
		new  map[string]string
		add  map[string]string
		del  map[string]string
	}{
		{
			name: "empty",
			add:  map[string]string{},
			del:  map[string]string{},
		},
		{
			name: "add",
			new:  map[string]string{"foo": "val"},
			add:  map[string]string{"foo": "val"},
			del:  map[string]string{},
		},
		{
			name: "del",
			old:  map[string]string{"foo": "val"},
			add:  map[string]string{},
			del:  map[string]string{"foo": "val"},
		},
		{
			name: "same",
			old:  map[string]string{"foo": "val"},
			new:  map[string]string{"foo": "val"},
			add:  map[string]string{},
			del:  map[string]string{},
		},
		{
			name: "change",
			old:  map[string]string{"foo": "valOld"},
			new:  map[string]string{"foo": "valNew"},
			add:  map[string]string{"foo": "valNew"},
			del:  map[string]string{},
		},
		{
			name: "multiple",
			old: map[string]string{
				"same":    "val",
				"change1": "old1",
				"change2": "old2",
				"del1":    "val",
				"del2":    "val",
			},
			new: map[string]string{
				"same":    "val",
				"change1": "new1",
				"change2": "new2",
				"add1":    "val",
				"add2":    "val",
				"add3":    "val",
			},
			add: map[string]string{
				"change1": "new1",
				"change2": "new2",
				"add1":    "val",
				"add2":    "val",
				"add3":    "val",
			},
			del: map[string]string{
				"del1": "val",
				"del2": "val",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := core.Pod{
				ObjectMeta: metav1.ObjectMeta{Annotations: tc.old},
			}
			new := core.Pod{
				ObjectMeta: metav1.ObjectMeta{Annotations: tc.new},
			}
			gotAdd, gotDel := annotationDiff(&old, &new)
			assert.Equal(t, tc.add, gotAdd)
			assert.Equal(t, tc.del, gotDel)
		})
	}
}

func TestFindNewContainers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		old, new []string
		want     []int
	}{
		{
			name: "single",
			new:  []string{"cont1"},
			want: []int{0},
		},
		{
			name: "multiple",
			new:  []string{"cont1", "cont2", "cont3"},
			want: []int{0, 1, 2},
		},
		{
			name: "remove-all",
			old:  []string{"cont1", "cont2", "cont3"},
		},
		{
			name: "remove-one",
			old:  []string{"cont1", "cont2"},
			new:  []string{"cont1"},
		},
		{
			name: "add-remove",
			old:  []string{"cont1", "cont-rm", "cont3"},
			new:  []string{"cont1", "cont-add1", "cont3", "cont-add2"},
			want: []int{1, 3},
		},
		{
			name: "out-of-order",
			old:  []string{"cont1", "cont2", "cont3"},
			new:  []string{"cont3", "cont1", "cont-add1", "cont2", "cont-add2"},
			want: []int{2, 4},
		},
		{
			name: "empty",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Prepare ephemeral container slices.
			var old, new []core.EphemeralContainer
			for _, name := range tc.old {
				old = append(old, core.EphemeralContainer{
					EphemeralContainerCommon: core.EphemeralContainerCommon{Name: name},
				})
			}
			for _, name := range tc.new {
				new = append(new, core.EphemeralContainer{
					EphemeralContainerCommon: core.EphemeralContainerCommon{Name: name},
				})
			}

			got := findNewContainers(old, new)
			assert.Equal(t, tc.want, got)
		})
	}
}

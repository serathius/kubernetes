/*
Copyright 2024 The Kubernetes Authors.

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

package reconciler

import (
	"context"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/record"
	"k8s.io/component-base/metrics/legacyregistry"
	metricstestutil "k8s.io/component-base/metrics/testutil"
	"k8s.io/klog/v2/ktesting"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/controller/volume/attachdetach/cache"
	"k8s.io/kubernetes/pkg/controller/volume/attachdetach/metrics"
	"k8s.io/kubernetes/pkg/controller/volume/attachdetach/statusupdater"
	controllervolumetesting "k8s.io/kubernetes/pkg/controller/volume/attachdetach/testing"
	volumetesting "k8s.io/kubernetes/pkg/volume/testing"
	"k8s.io/kubernetes/pkg/volume/util/operationexecutor"
	"k8s.io/kubernetes/pkg/volume/util/types"
)

// Populates desiredStateOfWorld cache with one node/volume/pod tuple.
// The node starts as healthy.
//
// Calls Run()
// Verifies there is one attach call and no detach calls.
// Deletes the pod from desiredStateOfWorld cache without first marking the node/volume as unmounted.
// Verifies that the volume is NOT detached after maxWaitForUnmountDuration.
// Marks the node as unhealthy.
// Sets forceDetachOnUmountDisabled to true.
// Verifies that the volume is not detached after maxWaitForUnmountDuration.
//
// Then applies the node.kubernetes.io/out-of-service taint.
// Verifies that there is still just one attach call.
// Verifies there is now one detach call.
func Test_Run_OneVolumeDetachOnUnhealthyNodeWithForceDetachOnUnmountDisabled(t *testing.T) {
	originalValue := DisableForceDetachOnTimeout
	DisableForceDetachOnTimeout = true // change the option we're testing
	t.Cleanup(func() {
		DisableForceDetachOnTimeout = originalValue
	})

	registerMetrics.Do(func() {
		legacyregistry.MustRegister(metrics.ForceDetachMetricCounter)
	})
	// NOTE: This value is being pulled from a global variable, so it won't necessarily be 0 at the start of the test
	// For example, if Test_Run_OneVolumeDetachOnOutOfServiceTaintedNode runs before this test, then it will be 1
	initialForceDetachCount, err := metricstestutil.GetCounterMetricValue(metrics.ForceDetachMetricCounter.WithLabelValues(metrics.ForceDetachReasonOutOfService))
	if err != nil {
		t.Errorf("Error getting initialForceDetachCount")
	}

	// Arrange
	volumePluginMgr, fakePlugin := volumetesting.GetTestVolumePluginMgr(t)
	dsw := cache.NewDesiredStateOfWorld(volumePluginMgr)
	asw := cache.NewActualStateOfWorld(volumePluginMgr)
	fakeKubeClient := controllervolumetesting.CreateTestClient()
	fakeRecorder := &record.FakeRecorder{}
	fakeHandler := volumetesting.NewBlockVolumePathHandler()
	ad := operationexecutor.NewOperationExecutor(operationexecutor.NewOperationGenerator(
		fakeKubeClient,
		volumePluginMgr,
		fakeRecorder,
		fakeHandler))
	informerFactory := informers.NewSharedInformerFactory(fakeKubeClient, controller.NoResyncPeriodFunc())
	nsu := statusupdater.NewFakeNodeStatusUpdater(false /* returnError */)
	nodeLister := informerFactory.Core().V1().Nodes().Lister()
	reconciler := NewReconciler(
		reconcilerLoopPeriod, maxWaitForUnmountDuration, syncLoopPeriod, false, dsw, asw, ad,
		nsu, nodeLister, fakeRecorder)
	podName1 := "pod-uid1"
	volumeName1 := v1.UniqueVolumeName("volume-name1")
	volumeSpec1 := controllervolumetesting.GetTestVolumeSpec(string(volumeName1), volumeName1)
	nodeName1 := k8stypes.NodeName("worker-0")
	node1 := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: string(nodeName1)},
		Status: v1.NodeStatus{
			Conditions: []v1.NodeCondition{
				{
					Type:   v1.NodeReady,
					Status: v1.ConditionTrue,
				},
			},
		},
	}
	addErr := informerFactory.Core().V1().Nodes().Informer().GetStore().Add(node1)
	if addErr != nil {
		t.Fatalf("Add node failed. Expected: <no error> Actual: <%v>", addErr)
	}
	dsw.AddNode(nodeName1, false /*keepTerminatedPodVolumes*/)
	volumeExists := dsw.VolumeExists(volumeName1, nodeName1)
	if volumeExists {
		t.Fatalf(
			"Volume %q/node %q should not exist, but it does.",
			volumeName1,
			nodeName1)
	}

	generatedVolumeName, podErr := dsw.AddPod(types.UniquePodName(podName1), controllervolumetesting.NewPod(podName1,
		podName1), volumeSpec1, nodeName1)
	if podErr != nil {
		t.Fatalf("AddPod failed. Expected: <no error> Actual: <%v>", podErr)
	}

	// Act
	_, ctx := ktesting.NewTestContext(t)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go reconciler.Run(ctx)

	// Assert
	waitForNewAttacherCallCount(t, 1 /* expectedCallCount */, fakePlugin)
	verifyNewAttacherCallCount(t, false /* expectZeroNewAttacherCallCount */, fakePlugin)
	waitForAttachCallCount(t, 1 /* expectedAttachCallCount */, fakePlugin)
	verifyNewDetacherCallCount(t, true /* expectZeroNewDetacherCallCount */, fakePlugin)
	waitForDetachCallCount(t, 0 /* expectedDetachCallCount */, fakePlugin)

	// Act
	// Delete the pod and the volume will be detached even after the maxWaitForUnmountDuration expires as volume is
	// not unmounted and the node is healthy.
	dsw.DeletePod(types.UniquePodName(podName1), generatedVolumeName, nodeName1)
	time.Sleep(maxWaitForUnmountDuration * 5)
	// Assert
	waitForNewDetacherCallCount(t, 0 /* expectedCallCount */, fakePlugin)
	verifyNewAttacherCallCount(t, false /* expectZeroNewAttacherCallCount */, fakePlugin)
	waitForAttachCallCount(t, 1 /* expectedAttachCallCount */, fakePlugin)
	verifyNewDetacherCallCount(t, true /* expectZeroNewDetacherCallCount */, fakePlugin)
	waitForDetachCallCount(t, 0 /* expectedDetachCallCount */, fakePlugin)

	// Act
	// Mark the node unhealthy
	node2 := node1.DeepCopy()
	node2.Status.Conditions[0].Status = v1.ConditionFalse
	updateErr := informerFactory.Core().V1().Nodes().Informer().GetStore().Update(node2)
	if updateErr != nil {
		t.Fatalf("Update node failed. Expected: <no error> Actual: <%v>", updateErr)
	}
	// Assert -- Detach was not triggered after maxWaitForUnmountDuration
	waitForNewDetacherCallCount(t, 0 /* expectedCallCount */, fakePlugin)
	verifyNewAttacherCallCount(t, false /* expectZeroNewAttacherCallCount */, fakePlugin)
	waitForAttachCallCount(t, 1 /* expectedAttachCallCount */, fakePlugin)
	verifyNewDetacherCallCount(t, true /* expectZeroNewDetacherCallCount */, fakePlugin)
	waitForDetachCallCount(t, 0 /* expectedDetachCallCount */, fakePlugin)

	// Force detach metric due to out-of-service taint
	// We shouldn't see any additional force detaches, so only consider the initial count
	testForceDetachMetric(t, int(initialForceDetachCount), metrics.ForceDetachReasonOutOfService)

	// Act
	// Taint the node
	node3 := node2.DeepCopy()
	node3.Spec.Taints = append(node3.Spec.Taints, v1.Taint{Key: v1.TaintNodeOutOfService, Effect: v1.TaintEffectNoExecute})
	updateErr = informerFactory.Core().V1().Nodes().Informer().GetStore().Update(node3)
	if updateErr != nil {
		t.Fatalf("Update node failed. Expected: <no error> Actual: <%v>", updateErr)
	}
	// Assert -- Detach was triggered after maxWaitForUnmountDuration
	waitForNewDetacherCallCount(t, 1 /* expectedCallCount */, fakePlugin)
	verifyNewAttacherCallCount(t, false /* expectZeroNewAttacherCallCount */, fakePlugin)
	waitForAttachCallCount(t, 1 /* expectedAttachCallCount */, fakePlugin)
	verifyNewDetacherCallCount(t, false /* expectZeroNewDetacherCallCount */, fakePlugin)
	waitForDetachCallCount(t, 1 /* expectedDetachCallCount */, fakePlugin)

	// Force detach metric due to out-of-service taint
	// We should see one more force detach, so consider the initial count + 1
	testForceDetachMetric(t, int(initialForceDetachCount)+1, metrics.ForceDetachReasonOutOfService)
}

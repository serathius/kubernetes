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

package replicaset

import (
	"context"
	"fmt"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	clientfeatures "k8s.io/client-go/features"
	clientfeaturestesting "k8s.io/client-go/features/testing"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/ktesting"
	clientset "k8s.io/client-go/kubernetes"
	appsv1listers "k8s.io/client-go/listers/apps/v1"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/kubernetes/pkg/controller/replicaset"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/test/utils/robustness"
	"k8s.io/utils/ptr"
)

// TestReplicaSetReconcileRobustnessMatrix runs the ReplicaSet controller
// against the standard chaos matrix plus ESR scenarios (410 Gone watch
// compaction relist, stale single-resource cache snapshot, and mid-reconcile
// controller restart) and verifies post-convergence stability and write
// quiescence.
func TestReplicaSetReconcileRobustnessMatrix(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.StaleControllerConsistencyReplicaSet, true)
	clientfeaturestesting.SetFeatureDuringTest(t, clientfeatures.AtomicFIFO, true)

	tCtx := ktesting.Init(t)
	const rsName = "rs-1"
	const desiredReplicas = 2

	suite := robustness.NewTestSuite(tCtx, robustness.ControllerProfile{
		Name: "replicaset",
		Root: robustness.ResourceRef{
			Group:     "apps",
			Resource:  "replicasets",
			Namespace: "default",
			Name:      rsName,
		},
		WritesRootStatus: true,
		UsesExpectations: true,
		Child: &robustness.ChildResource{
			Resource:            "pods",
			CreatedByController: true,
		},
	})

	var scenarios []robustness.ChaosScenario
	for _, sc := range robustness.StandardChaosMatrix() {
		if sc.Name == "ExpectationsTimeout" {
			// KEP-5647 EnsureReady short-circuits syncReplicaSet before SatisfiedExpectations
			// is reached, so ShiftExpectationsClock never fires during ChildWatchDeath.
			continue
		}
		scenarios = append(scenarios, sc)
	}
	for _, sc := range robustness.ESRChaosMatrix() {
		if sc.Name == "LostWriteResponse" {
			continue // covered separately in open-bug reproducers
		}
		scenarios = append(scenarios, sc)
	}
	suite.SetScenarios(scenarios)
	suite.CheckStability(1 * time.Second)

	suite.SetControllerSetup(func(tCtx ktesting.TContext, fixture *robustness.RobustnessTestFixture) {
		ctrlCtx := fixture.ControllerContext()
		informerFactory := informers.NewSharedInformerFactory(fixture.ClientSet(), 0)
		rsInformer := robustness.WrapInformer(fixture, informerFactory.Apps().V1().ReplicaSets().Informer(), "replicasets", appsv1listers.NewReplicaSetLister)
		podInformer := fixture.WrapPodInformer(informerFactory.Core().V1().Pods())

		rsc, err := replicaset.NewReplicaSetController(
			ctrlCtx,
			rsInformer,
			podInformer,
			nil,
			nil,
			fixture.ClientSet(),
			replicaset.BurstReplicas,
		)
		if err != nil {
			tCtx.Fatalf("Failed to create ReplicaSet controller: %v", err)
		}
		fixture.StartInformers(informerFactory)
		fixture.GoController(func(ctx context.Context) { rsc.Run(ctx, 2) })
	})

	suite.SetScenarioAction(func(ctx context.Context, fixture *robustness.RobustnessTestFixture) error {
		rs := &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Name: rsName, Namespace: "default"},
			Spec: appsv1.ReplicaSetSpec{
				Replicas: ptr.To[int32](desiredReplicas),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				Template: v1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}},
					Spec: v1.PodSpec{
						Containers: []v1.Container{{Name: "web", Image: "nginx"}},
					},
				},
			},
		}
		_, err := fixture.AdminClientSet().AppsV1().ReplicaSets("default").Create(ctx, rs, metav1.CreateOptions{})
		return err
	})

	suite.AddSafetyInvariant("MaxDesiredPods", robustness.CountAtMost(desiredReplicas, "Pod",
		func(ctx context.Context, c clientset.Interface) (int, error) {
			pods, err := c.CoreV1().Pods("default").List(ctx, metav1.ListOptions{})
			if err != nil {
				return 0, err
			}
			return len(pods.Items), nil
		}))

	suite.AddLivenessInvariant("ReplicaSetConverged", robustness.ObjectSatisfies(
		func(ctx context.Context, c clientset.Interface) (*appsv1.ReplicaSet, error) {
			return c.AppsV1().ReplicaSets("default").Get(ctx, rsName, metav1.GetOptions{})
		},
		func(rs *appsv1.ReplicaSet) error {
			if rs.Status.Replicas != desiredReplicas {
				return fmt.Errorf("expected Status.Replicas=%d, got %d", desiredReplicas, rs.Status.Replicas)
			}
			return nil
		}))

	suite.Run()
}

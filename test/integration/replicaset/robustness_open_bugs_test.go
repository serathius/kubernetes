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
	"os"
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
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/kubernetes/pkg/controller/replicaset"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/test/utils/robustness"
	"k8s.io/utils/ptr"
)

// TestReplicaSetLostCreateResponseF29 reproduces F-29 on unfixed HEAD:
// even with KEP-5647 (StaleControllerConsistencyReplicaSet=true), losing a
// committed POST /pods response while the pods watch lags causes
// ReplicaSetController to skip consistencyStore.WroteAt and decrement
// expectations, creating duplicate active pods (2 > 1).
func TestReplicaSetLostCreateResponseF29(t *testing.T) {
	if os.Getenv("KUBE_ROBUSTNESS_REPRO_OPEN_BUGS") == "" {
		t.Skip("skipping open upstream bug reproducer (set KUBE_ROBUSTNESS_REPRO_OPEN_BUGS=1 to run)")
	}

	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.StaleControllerConsistencyReplicaSet, true)
	clientfeaturestesting.SetFeatureDuringTest(t, clientfeatures.AtomicFIFO, true)

	tCtx := ktesting.Init(t)
	const rsName = "rs-f29"

	suite := robustness.NewTestSuite(tCtx, robustness.ControllerProfile{
		Name: "replicaset-f29",
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

	suite.SetScenarios([]robustness.ChaosScenario{{
		Name: "LostCreateResponseWithWatchLag",
		Faults: func(p robustness.ControllerProfile, _ *robustness.FaultRegistry) []robustness.FaultRule {
			return []robustness.FaultRule{
				{
					Name:            "LosePodCreateResponse",
					Match:           p.ChildCreateMatch(),
					Condition:       robustness.TriggerOnOccurrence(1),
					Action:          robustness.LoseResponseAfterCommit{},
					ExpectTriggered: true,
				},
				{
					Name:            "StallPodWatch",
					Match:           p.ChildWatchMatch(),
					Condition:       robustness.TriggerOnOccurrence(1),
					Action:          robustness.InjectDelay{Duration: 2 * time.Second},
					ExpectTriggered: true,
				},
			}
		},
	}})

	suite.SetControllerSetup(func(tCtx ktesting.TContext, fixture *robustness.RobustnessTestFixture) {
		informerFactory := informers.NewSharedInformerFactory(fixture.ClientSet(), 0)
		podInformer := fixture.WrapPodInformer(informerFactory.Core().V1().Pods())
		rsc, err := replicaset.NewReplicaSetController(
			fixture.ControllerContext(),
			informerFactory.Apps().V1().ReplicaSets(),
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
				Replicas: ptr.To[int32](1),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "f29"}},
				Template: v1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "f29"}},
					Spec: v1.PodSpec{
						Containers: []v1.Container{{Name: "web", Image: "nginx"}},
					},
				},
			},
		}
		_, err := fixture.AdminClientSet().AppsV1().ReplicaSets("default").Create(ctx, rs, metav1.CreateOptions{})
		return err
	})

	suite.AddSafetyInvariant("MaxOnePod", robustness.CountAtMost(1, "Pod",
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
			if rs.Status.Replicas != 1 {
				return fmt.Errorf("expected Status.Replicas=1, got %d", rs.Status.Replicas)
			}
			return nil
		}))

	suite.Run()
}

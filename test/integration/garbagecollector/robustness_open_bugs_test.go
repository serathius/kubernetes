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

package garbagecollector

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	cacheddiscovery "k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/ktesting"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/restmapper"
	"k8s.io/controller-manager/pkg/informerfactory"
	"k8s.io/kubernetes/pkg/controller/garbagecollector"
	"k8s.io/kubernetes/test/utils/robustness"
	"k8s.io/utils/ptr"
)

// TestGarbageCollectorRelistSameNameRecreateL4004 reproduces L4-004 on unfixed
// HEAD: when a 410 Gone watch relist hides a same-name delete+recreate of an
// owner ReplicaSet (UID_1 -> UID_2), GraphBuilder's UpdateFunc ignores the UID
// change, permanently leaking UID_1 and stranding dep-old.
func TestGarbageCollectorRelistSameNameRecreateL4004(t *testing.T) {
	if os.Getenv("KUBE_ROBUSTNESS_REPRO_OPEN_BUGS") == "" {
		t.Skip("skipping open upstream bug reproducer (set KUBE_ROBUSTNESS_REPRO_OPEN_BUGS=1 to run)")
	}

	tCtx := ktesting.Init(t)
	const ownerName = "owner-rs"
	const depOldName = "dep-old"

	suite := robustness.NewTestSuite(tCtx, robustness.ControllerProfile{
		Name: "garbagecollector-l4004",
		Root: robustness.ResourceRef{
			Group:     "apps",
			Resource:  "replicasets",
			Namespace: "default",
			Name:      ownerName,
		},
		Child: &robustness.ChildResource{
			Resource: "pods",
		},
	})
	suite.SetLivenessTimeout(6 * time.Second)

	suite.SetScenarios([]robustness.ChaosScenario{{
		Name: "RelistHidesSameNameRecreate",
		Faults: func(p robustness.ControllerProfile, _ *robustness.FaultRegistry) []robustness.FaultRule {
			return []robustness.FaultRule{{
				Name:            "CompactRelistOnRSDelete",
				Match:           robustness.ClientMatch{Verbs: []string{robustness.VerbWatch}, EventTypes: []watch.EventType{watch.Deleted}, Group: "apps", Resource: "replicasets", Namespace: "default", Name: ownerName},
				Condition:       robustness.TriggerOnOccurrence(1),
				Action:          robustness.ForceWatchCompactionRelist{},
				ExpectTriggered: true,
			}}
		},
	}})

	suite.SetControllerSetup(func(tCtx ktesting.TContext, fixture *robustness.RobustnessTestFixture) {
		wrappedClient := fixture.ClientSet()
		metaClient := metadata.NewForConfigOrDie(fixture.KubeConfig())
		discoveryClient := cacheddiscovery.NewMemCacheClient(wrappedClient.Discovery())
		restMapper := restmapper.NewDeferredDiscoveryRESTMapper(discoveryClient)
		restMapper.Reset()

		sharedInformers := informers.NewSharedInformerFactory(wrappedClient, 0)
		metadataInformers := metadatainformer.NewSharedInformerFactory(metaClient, 0)
		alwaysStarted := make(chan struct{})
		close(alwaysStarted)

		gc, err := garbagecollector.NewGarbageCollector(
			fixture.ControllerContext(),
			wrappedClient,
			metaClient,
			restMapper,
			garbagecollector.DefaultIgnoredResources(),
			informerfactory.NewInformerFactory(sharedInformers, metadataInformers),
			alwaysStarted,
		)
		if err != nil {
			tCtx.Fatalf("Failed to create GarbageCollector: %v", err)
		}
		fixture.GoController(func(ctx context.Context) { gc.Run(ctx, 2, 30*time.Second) })
		fixture.GoController(func(ctx context.Context) { gc.Sync(ctx, wrappedClient.Discovery(), 30*time.Second) })
		if err := wait.PollUntilContextTimeout(fixture.ControllerContext(), 50*time.Millisecond, 10*time.Second, true, func(context.Context) (bool, error) {
			return gc.IsSynced(tCtx.Logger()), nil
		}); err != nil {
			tCtx.Fatalf("GarbageCollector did not sync: %v", err)
		}
	})

	suite.SetScenarioAction(func(ctx context.Context, fixture *robustness.RobustnessTestFixture) error {
		admin := fixture.AdminClientSet()
		rs := func() *appsv1.ReplicaSet {
			return &appsv1.ReplicaSet{
				ObjectMeta: metav1.ObjectMeta{Name: ownerName, Namespace: "default"},
				Spec: appsv1.ReplicaSetSpec{
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "l4004"}},
					Template: v1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "l4004"}},
						Spec:       v1.PodSpec{Containers: []v1.Container{{Name: "c", Image: "nginx"}}},
					},
				},
			}
		}
		created1, err := admin.AppsV1().ReplicaSets("default").Create(ctx, rs(), metav1.CreateOptions{})
		if err != nil {
			return err
		}
		dep := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      depOldName,
				Namespace: "default",
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1",
					Kind:       "ReplicaSet",
					Name:       ownerName,
					UID:        created1.UID,
				}},
			},
			Spec: v1.PodSpec{Containers: []v1.Container{{Name: "c", Image: "nginx"}}},
		}
		if _, err := admin.CoreV1().Pods("default").Create(ctx, dep, metav1.CreateOptions{}); err != nil {
			return err
		}
		// Allow GraphBuilder to observe UID_1 and dep-old before delete+recreate.
		time.Sleep(500 * time.Millisecond)

		bg := metav1.DeletePropagationBackground
		if err := admin.AppsV1().ReplicaSets("default").Delete(ctx, ownerName, metav1.DeleteOptions{PropagationPolicy: ptr.To(bg)}); err != nil {
			return err
		}
		if _, err := admin.AppsV1().ReplicaSets("default").Create(ctx, rs(), metav1.CreateOptions{}); err != nil {
			return err
		}
		return nil
	})

	suite.AddLivenessInvariant("OldDependentGarbageCollected", func(ctx context.Context, c clientset.Interface) error {
		_, err := c.CoreV1().Pods("default").Get(ctx, depOldName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("dependent pod %q of deleted owner UID_1 is still stranded", depOldName)
	})

	suite.Run()
}

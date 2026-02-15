package v1

import (
	fmt "fmt"
	"os"
	"sync"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestInternPodSpec_Race(t *testing.T) {
	// Load Pod
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	podPath := "/testdata/pod.yaml"
	data, err := os.ReadFile(wd + podPath)
	if err != nil {
		t.Fatalf("Failed to read pod yaml: %v", err)
	}

	var pod Pod
	if err := yaml.Unmarshal(data, &pod); err != nil {
		t.Fatalf("Failed to unmarshal yaml: %v", err)
	}

	protoData, err := pod.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal pod: %v", err)
	}

	// Enable interning
	SetInternPodSpec(t, true)

	var wg sync.WaitGroup
	concurrency := 100
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(i int) {
			defer wg.Done()

			// Marshal repeatedly
			for j := 0; j < 10000; j++ {
				// Simulate defaulting on a fresh object (which shares interned maps)
				p := &Pod{}
				if err := p.UnmarshalIntern(protoData); err != nil {
					t.Errorf("Failed to unmarshal: %v", err)
				}
				simulateDefaulter(p)
			}
		}(i)
	}
	wg.Wait()
}

func simulateDefaulter(pod *Pod) {
	for i := range pod.Spec.Containers {
		// mimic SetDefaults_Pod logic: if limits exist but requests don't, copy limits to requests
		if pod.Spec.Containers[i].Resources.Limits != nil {
			if pod.Spec.Containers[i].Resources.Requests == nil {
				pod.Spec.Containers[i].Resources.Requests = make(ResourceList)
			}
			for k, v := range pod.Spec.Containers[i].Resources.Limits {
				if _, exists := pod.Spec.Containers[i].Resources.Requests[k]; !exists {
					// This write races with readers of other interned pods
					pod.Spec.Containers[i].Resources.Requests[k] = v.DeepCopy()
				}
			}
		}
	}
}

func TestInternPodSpec_ConcurrentWrite(t *testing.T) {
	// Load Pod
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	podPath := "/testdata/pod.yaml"
	data, err := os.ReadFile(wd + podPath)
	if err != nil {
		t.Fatalf("Failed to read pod yaml: %v", err)
	}

	var pod Pod
	if err := yaml.Unmarshal(data, &pod); err != nil {
		t.Fatalf("Failed to unmarshal yaml: %v", err)
	}
	// Ensure we have a map to write to
	if pod.Spec.NodeSelector == nil {
		pod.Spec.NodeSelector = make(map[string]string)
	}
	pod.Spec.NodeSelector["foo"] = "bar"

	protoData, err := pod.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal pod: %v", err)
	}

	// Enable interning
	SetInternPodSpec(t, true)

	var wg sync.WaitGroup
	concurrency := 100
	wg.Add(concurrency)

	pods := make([]*Pod, concurrency)
	for i := 0; i < concurrency; i++ {
		pods[i] = &Pod{}
		if err := pods[i].UnmarshalIntern(protoData); err != nil {
			t.Errorf("Failed to unmarshal: %v", err)
		}
	}

	// Concurrently write to the map
	for i := 0; i < concurrency; i++ {
		go func(i int) {
			defer wg.Done()
			// Write to the map
			pods[i].Spec.NodeSelector["foo"] = fmt.Sprintf("bar-%d", i)
			// Read from the map (DeepCopy iterates)
			_ = pods[i].DeepCopy()
		}(i)
	}
	wg.Wait()
}

func TestInternPodSpec_ResourceRequirements_DeepCopy(t *testing.T) {
	// Create a Pod with ResourceRequirements
	pod := &Pod{
		Spec: PodSpec{
			Containers: []Container{
				{
					Name: "c1",
					Resources: ResourceRequirements{
						Limits: ResourceList{
							"cpu": resource.MustParse("1"),
						},
						Requests: ResourceList{
							"memory": resource.MustParse("1Gi"),
						},
					},
				},
			},
		},
	}

	data, err := pod.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal pod: %v", err)
	}

	// Enable interning
	SetInternPodSpec(t, true)

	// Unmarshal twice to get two Pods sharing the same interned Spec (initially)
	pod1 := &Pod{}
	if err := pod1.UnmarshalIntern(data); err != nil {
		t.Fatalf("Failed to unmarshal pod1: %v", err)
	}

	pod2 := &Pod{}
	if err := pod2.UnmarshalIntern(data); err != nil {
		t.Fatalf("Failed to unmarshal pod2: %v", err)
	}

	// Verify they share the same Spec pointer structure initially (before we modify maps, but wait, we deep copied maps on hit)
	// Actually, internPodSpec does *target = *cached, so they share the same underlying pointers for slices/maps unless we changed them.
	// But we DID change them in deepCopyResourceRequirements.
	// So pod1 and pod2 should have DIFFERENT map pointers for Resources.

	if pod1.Spec.Containers[0].Resources.Limits == nil {
		t.Fatal("pod1 limits nil")
	}
	if pod2.Spec.Containers[0].Resources.Limits == nil {
		t.Fatal("pod2 limits nil")
	}

	// Check if maps are distinct
	// We can't easily compare map pointers in Go without reflection or unsafe, but we can modify one and check the other.
	pod1.Spec.Containers[0].Resources.Limits["cpu"] = resource.MustParse("2")

	// Check if pod2 is unaffected
	val, ok := pod2.Spec.Containers[0].Resources.Limits["cpu"]
	if !ok {
		t.Fatal("pod2 limits missing cpu")
	}
	if val.String() != "1" {
		t.Errorf("pod2 limits changed when pod1 was modified! Shared map detected. Got %v, want 1", val.String())
	}
}

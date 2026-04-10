package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/kube-openapi/pkg/validation/spec"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func getTypeConverter(t *testing.T) managedfields.TypeConverter {
	path := filepath.Join("..", "..", "api", "openapi-spec", "swagger.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read openapi spec: %v", err)
	}
	var swagger spec.Swagger
	if err := json.Unmarshal(data, &swagger); err != nil {
		t.Fatalf("Failed to unmarshal openapi spec: %v", err)
	}
	definitions := map[string]*spec.Schema{}
	for k, v := range swagger.Definitions {
		p := v
		definitions[k] = &p
	}
	typeConverter, err := managedfields.NewTypeConverter(definitions, false)
	if err != nil {
		t.Fatalf("Failed to create type converter: %v", err)
	}
	return typeConverter
}

func TestDirectEtcdPodWrite(t *testing.T) {
	if etcdEndpoint == "" {
		etcdEndpoint = "https://192.168.8.2:2379"
	}

	// Build k8s client
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		t.Fatalf("Failed to build config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("Failed to create clientset: %v", err)
	}

	// Build etcd client
	etcdClient, err := newEtcdClient()
	if err != nil {
		t.Fatalf("Failed to create etcd client: %v", err)
	}
	defer etcdClient.Close()

	serializer := createProtobufSerializer()

	typeConverter := getTypeConverter(t)
	podName := "test-direct-etcd-pod"
	pod := generateSpecificPod(podName, 0, typeConverter) // Use base size
	podData, _ := pod.Marshal()
	t.Logf("Base pod size: %d bytes", len(podData))

	key := "/registry/pods/default/" + podName

	ctx := context.Background()

	// Encode to Protobuf
	unk := &runtime.Unknown{
		TypeMeta: runtime.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		Raw: podData,
	}
	var buf bytes.Buffer
	if err := serializer.Encode(unk, &buf); err != nil {
		t.Fatalf("Failed to encode pod: %v", err)
	}

	// Write to etcd
	rv, _, err := write(ctx, etcdClient, key, buf.String())
	if err != nil {
		t.Fatalf("Failed to write pod to etcd: %v", err)
	}
	t.Logf("Successfully wrote pod to etcd, revision: %d", rv)

	// Wait a bit for apiserver to observe it
	time.Sleep(100 * time.Millisecond)

	// Read from API server
	readPod, err := clientset.CoreV1().Pods("default").Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to read pod from API server: %v", err)
	}

	t.Logf("Successfully read pod from API server. ResourceVersion: %s", readPod.Name)

	if readPod.Name != podName {
		t.Errorf("Expected pod name %s, got %s", podName, readPod.Name)
	}

	// Clean up
	// _, err = etcdClient.KV.Delete(ctx, key)
	// if err != nil {
	// 	t.Logf("Failed to clean up pod from etcd: %v", err)
	// }
}

func TestPodProportionalGrowth(t *testing.T) {
	typeConverter := getTypeConverter(t)
	pod1 := generateSpecificPod("pod1", 1500, typeConverter)
	pod2 := generateSpecificPod("pod2", 5000, typeConverter)
	pod3 := generateSpecificPod("pod3", 15000, typeConverter)

	if len(pod1.ManagedFields) != 1 {
		t.Errorf("Expected 1 managed fields entries, got %d", len(pod1.ManagedFields))
	}

	data1, _ := pod1.Marshal()
	data2, _ := pod2.Marshal()
	data3, _ := pod3.Marshal()

	t.Logf("Pod1 size (requested 1500): %d", len(data1))
	t.Logf("Pod2 size (requested 5000): %d", len(data2))
	t.Logf("Pod3 size (requested 15000): %d", len(data3))

	if len(data2) <= len(data1) {
		t.Errorf("Pod2 size (%d) should be greater than Pod1 size (%d)", len(data2), len(data1))
	}
	if len(data3) <= len(data2) {
		t.Errorf("Pod3 size (%d) should be greater than Pod2 size (%d)", len(data3), len(data2))
	}

	// Verify structural growth between pod1 and pod2
	if len(pod2.Spec.Containers) < len(pod1.Spec.Containers) {
		t.Errorf("Pod2 containers (%d) should be >= Pod1 containers (%d)", len(pod2.Spec.Containers), len(pod1.Spec.Containers))
	}
	if len(pod2.Spec.Volumes) < len(pod1.Spec.Volumes) {
		t.Errorf("Pod2 volumes (%d) should be >= Pod1 volumes (%d)", len(pod2.Spec.Volumes), len(pod1.Spec.Volumes))
	}
}

func TestPrepareObjects(t *testing.T) {
	keys, values := prepareObjects(1, 8000, "pod")
	if len(keys) != 1 || len(values) != 1 {
		t.Fatalf("Expected 1 key and value, got %d keys and %d values", len(keys), len(values))
	}
	t.Logf("Encoded pod size for target 8000: %d bytes", len(values[0]))
}

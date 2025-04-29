package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	flag "github.com/spf13/pflag"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/client-go/util/homedir"
	"k8s.io/kubectl/pkg/util/slice"
)

var objectCount = 1
var listers = 100
var testDuration = 20 * time.Second

func main() {
	contentType := flag.String("content-type", "", "json or protobuf")
	resource := flag.String("resource", "", "configmap, pod, or cr")
	qps := flag.Float32("qps", 0, "")
	objectSize := flag.Int("object-size", 0, "")
	objectCount := flag.Int("object-count", 0, "")
	serviceAccount := flag.String("service-account", "", "")
	flag.Parse()
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		fmt.Printf("failed to read kube config: %s\n", err)
		os.Exit(1)
	}
	switch *contentType {
	case "json":
		config.ContentType = "application/json"
	case "protobuf":
		config.ContentType = "application/vnd.kubernetes.protobuf"
	case "cbor":
		config.ContentType = "application/cbor"
	case "yaml":
		config.ContentType = "application/yaml"
	default:
		fmt.Printf("--content-type should be set to \"json\" or \"protobuf\"\n")
		os.Exit(1)
	}
	config.QPS = -1
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Printf("failed to create client: %s\n", err)
		os.Exit(1)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		fmt.Printf("failed to create dynamic client: %s\n", err)
		os.Exit(1)
	}
	if *qps == 0 {
		fmt.Printf("--qps needs to be set\n")
		os.Exit(1)
	}
	if *objectSize == 0 {
		fmt.Printf("--object-size needs to be set\n")
		os.Exit(1)
	}
	if *objectCount == 0 {
		fmt.Printf("--object-count needs to be set\n")
		os.Exit(1)
	}
	if *serviceAccount != "" {
		token, err := createToken(clientset, "default", *serviceAccount)
		if err != nil {
			fmt.Printf("failed to create token: %s\n", err)
			os.Exit(1)
		}
		config.BearerToken = token
		config.TLSClientConfig.KeyData = []byte("")
		clientset, err = kubernetes.NewForConfig(config)
		if err != nil {
			fmt.Printf("failed to create client: %s\n", err)
			os.Exit(1)
		}
	}
	switch *resource {
	case "configmap":
		createConfigmaps(clientset, *objectSize, *objectCount, *qps)
	case "pod":
		createPods(clientset, *objectSize, *objectCount)
	case "cr":
		createCRs(dynamicClient, *objectSize, *objectCount)
	default:
		print("--resource should be set to \"configmap\", \"pod\" or \"cr\"\n")
		os.Exit(1)
	}
	fmt.Printf("Done\n")
}

func createToken(clientset kubernetes.Interface, namespace, name string) (string, error) {
	request := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{},
	}
	response, err := clientset.CoreV1().ServiceAccounts(namespace).CreateToken(context.TODO(), name, request, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	return response.Status.Token, nil
}

func createConfigmaps(clientset kubernetes.Interface, objectSize, objectCount int, qps float32) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	latencies := []int64{}
	var latencySum int64
	start := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), start.Add(testDuration))
	defer cancel()
	index := 0
	rateLimiter := flowcontrol.NewTokenBucketRateLimiter(qps, 10)

	resp, err := clientset.CoreV1().ConfigMaps("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		panic(err)
	}
	for _, item := range resp.Items {
		maybeIndex, err := strconv.ParseInt(item.Name, 10, 64)
		if err != nil {
			continue
		}
		index = max(index, int(maybeIndex)+1)
	}
	items := []string{}
	done := false

	for time.Since(start) < testDuration {
		err := rateLimiter.Wait(ctx)
		if err != nil {
			continue
		}
		if index < objectCount {
			name := fmt.Sprintf("%d", index)
			wg.Add(1)
			// Handle failure
			go func(name string) {
				defer wg.Done()
				t := time.Now()
				_, err := clientset.CoreV1().ConfigMaps("default").Create(ctx, randomConfigmap(name, objectSize), metav1.CreateOptions{})
				latency := time.Since(t)
				if err != nil {
					if strings.Contains(err.Error(), "already exists") {
						return
					}
					if errors.Is(err, context.DeadlineExceeded) {
						return
					}
					if errors.Is(err, context.Canceled) {
						return
					}
					if strings.Contains(err.Error(), "would exceed context deadline") {
						return
					}
					panic(err)
				}
				mu.Lock()
				items = append(items, name)
				if len(items) == objectCount {
					done = true
				}
				latencySum += int64(latency)
				latencies = append(latencies, int64(latency))
				mu.Unlock()
			}(name)
			index++
		} else {
			var name string
			if done {
				name = fmt.Sprintf("%d", rand.Int()%objectCount)
			} else {
				mu.Lock()
				if len(items) == 0 {
					mu.Unlock()
					continue
				}
				name = items[rand.Int()%len(items)]
				mu.Unlock()
			}
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				t := time.Now()
				_, err := clientset.CoreV1().ConfigMaps("default").Update(ctx, randomConfigmap(name, objectSize), metav1.UpdateOptions{})
				latency := time.Since(t)
				if err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						return
					}
					if errors.Is(err, context.Canceled) {
						return
					}
					if strings.Contains(err.Error(), "would exceed context deadline") {
						return
					}
					panic(err)
				}
				mu.Lock()
				latencySum += int64(latency)
				latencies = append(latencies, int64(latency))
				mu.Unlock()
			}(name)
		}

	}
	wg.Wait()
	fmt.Printf("QPS: %.2f\n", float64(len(latencies))/testDuration.Seconds())
	if len(latencies) == 0 {
		return
	}
	fmt.Printf("Request Count: %v\n", len(latencies))
	fmt.Printf("Latency Average: %v\n", time.Duration(latencySum/int64(len(latencies))))
	slice.SortInts64(latencies)
	fmt.Printf("Latency 50%%ile: %v\n", time.Duration(latencies[len(latencies)/2]))
	fmt.Printf("Latency 90%%ile: %v\n", time.Duration(latencies[len(latencies)*9/10]))
	if len(latencies) > 20 {
		fmt.Printf("Latency 95%%ile: %v\n", time.Duration(latencies[len(latencies)*19/20]))
	}
	if len(latencies) > 100 {
		fmt.Printf("Latency 99%%ile: %v\n", time.Duration(latencies[len(latencies)*99/100]))
	}
	fmt.Printf("Created configmaps\n")
}

func createPods(clientset kubernetes.Interface, objectSize, objectCount int) {
	var wg sync.WaitGroup
	for i := 0; i < objectCount; i++ {
		name := fmt.Sprintf("%d", i)
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			_, err := clientset.CoreV1().Pods("default").Create(context.TODO(), randomPod(name, objectSize), metav1.CreateOptions{})
			if err != nil {
				panic(err)
			}
		}(name)
	}
	wg.Wait()
	fmt.Printf("Created pods\n")
}

func createCRs(clientset *dynamic.DynamicClient, objectSize, objectCount int) {
	resource := schema.GroupVersionResource{
		Group:    "stable.example.com",
		Version:  "v1",
		Resource: "crontabs",
	}
	var wg sync.WaitGroup
	for i := 0; i < objectCount; i++ {
		name := fmt.Sprintf("%d", i)
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			_, err := clientset.Resource(resource).Namespace("default").Create(context.TODO(), randomCR(name, objectSize), metav1.CreateOptions{})
			if err != nil {
				panic(err)
			}
		}(name)
	}
	wg.Wait()
	fmt.Printf("Created crs\n")
}

func randomNamespace(name string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
}

func randomConfigmap(name string, objectSize int) *v1.ConfigMap {
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Immutable: nil,
		Data: map[string]string{
			"random": rand.String(objectSize),
		},
		BinaryData: nil,
	}
}

func randomCR(name string, objectSize int) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "stable.example.com/v1",
			"kind":       "CronTab",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": "default",
			},
			"value": rand.String(objectSize),
		},
	}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "stable.example.com",
		Version: "v1",
		Kind:    "CronTab",
	})
	return obj
}

func randomPod(name string, objectSize int) *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1.PodSpec{
			NodeName:      rand.String(253),
			Hostname:      rand.String(63),
			Subdomain:     rand.String(63),
			SchedulerName: rand.String(1000),
		},
		Status: v1.PodStatus{
			Message:           rand.String(1000),
			Reason:            rand.String(1000),
			NominatedNodeName: rand.String(1000),
			HostIP:            rand.String(1000),
			PodIP:             rand.String(1000),
		},
	}
	for pod.Size() < objectSize {
		pod.Spec.Containers = append(pod.Spec.Containers, v1.Container{
			Name:                   rand.String(63),
			Image:                  rand.String(1000),
			WorkingDir:             rand.String(1000),
			TerminationMessagePath: rand.String(1000),
		})
		pod.Spec.InitContainers = append(pod.Spec.InitContainers, v1.Container{
			Name:                   rand.String(63),
			Image:                  rand.String(1000),
			WorkingDir:             rand.String(1000),
			TerminationMessagePath: rand.String(1000),
		})
		pod.Spec.Volumes = append(pod.Spec.Volumes, v1.Volume{
			Name: rand.String(63),
			VolumeSource: v1.VolumeSource{
				HostPath: &v1.HostPathVolumeSource{
					Path: rand.String(1000),
				},
			},
		})
		pod.Status.Conditions = append(pod.Status.Conditions, v1.PodCondition{
			Reason: rand.String(1000),
		})
	}
	return pod
}

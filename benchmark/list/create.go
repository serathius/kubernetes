package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

func createResources(clientset kubernetes.Interface, dynamicClient *dynamic.DynamicClient, resource string, objectSize, objectCount, namespaces int, qps float32) {
	gvr := schema.GroupVersionResource{
		Group:    "stable.example.com",
		Version:  "v1",
		Resource: "crontabs",
	}
	var wg sync.WaitGroup
	rateLimiter := rate.NewLimiter(rate.Limit(qps), 1)
	pb := NewProgressBar(namespaces * objectCount)
	for i := 0; i < namespaces; i++ {
		namespace := fmt.Sprintf("%d", i)
		if err := ensureNamespace(clientset, namespace); err != nil {
			fmt.Printf("failed to create namespace %s: %v\n", namespace, err)
			continue
		}
		for j := 0; j < objectCount; j++ {
			_ = rateLimiter.WaitN(context.Background(), 1)
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				name := fmt.Sprintf("%d", j)
				if err := createObject(clientset, dynamicClient, resource, namespace, name, objectSize, gvr); err != nil {
					fmt.Printf("failed to create %s %s: %v\n", resource, name, err)
				}
				pb.Add(1)
			}(j)
		}
	}
	wg.Wait()
	pb.Finish()
	fmt.Printf("Created %ss\n", resource)
}

func ensureNamespace(clientset kubernetes.Interface, namespace string) error {
	return retry(func() error {
		_, err := clientset.CoreV1().Namespaces().Create(context.TODO(), randomNamespace(namespace), metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return err
	}, 5, time.Second)
}

func createObject(clientset kubernetes.Interface, dynamicClient *dynamic.DynamicClient, resource, namespace, name string, objectSize int, gvr schema.GroupVersionResource) error {
	return retry(func() error {
		var err error
		switch resource {
		case "pod":
			_, err = clientset.CoreV1().Pods(namespace).Create(context.TODO(), randomPod(name, objectSize), metav1.CreateOptions{})
		case "cr":
			_, err = dynamicClient.Resource(gvr).Namespace(namespace).Create(context.TODO(), randomCR(name, objectSize), metav1.CreateOptions{})
		case "secret":
			_, err = clientset.CoreV1().Secrets(namespace).Create(context.TODO(), randomSecret(name, objectSize), metav1.CreateOptions{})
		case "configmap":
			_, err = clientset.CoreV1().ConfigMaps(namespace).Create(context.TODO(), randomConfigmap(name, objectSize), metav1.CreateOptions{})
		default:
			return fmt.Errorf("--resource should be set to \"configmap\", \"pod\" or \"cr\"")
		}
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return err
	}, 5, time.Second)
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

func randomSecret(name string, objectSize int) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app": "0",
			},
		},
		Immutable: nil,
		StringData: map[string]string{
			"random": rand.String(objectSize),
		},
	}
}

func randomCR(name string, objectSize int) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "stable.example.com/v1",
			"kind":       "CronTab",
			"metadata": map[string]interface{}{
				"name": name,
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

func retry(fn func() error, attempts int, delay time.Duration) error {
	var err error
	for i := 0; i < attempts; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		time.Sleep(delay)
	}
	return err
}

type SimpleProgressBar struct {
	total   int
	current int
	mu      sync.Mutex
}

func NewProgressBar(total int) *SimpleProgressBar {
	return &SimpleProgressBar{
		total: total,
	}
}

func (p *SimpleProgressBar) Add(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current += n
	p.render()
}

func (p *SimpleProgressBar) render() {
	percent := float64(p.current) / float64(p.total) * 100
	fmt.Printf("\rProgress: [%d/%d] %.2f%%", p.current, p.total, percent)
}

func (p *SimpleProgressBar) Finish() {
	fmt.Println()
}

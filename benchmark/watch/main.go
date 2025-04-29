package main

import (
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var objectSize = 5000
var objectCount = 10
var timeBetweenRequests = time.Millisecond * 100
var maxQPS float32 = 100

var initResourceVersion = ""
var watchers = 1000
var watcherSleep = time.Second * 1

func main() {
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		panic(err.Error())
	}
	config.QPS = maxQPS
	config.Burst = 100

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	var wg sync.WaitGroup
	var events atomic.Int64
	startWriters(clientset, &wg)
	startWatchers(clientset, &wg, &events)
	start := time.Now()
	events.Store(0)

	fmt.Printf("Start %s\n", start)
	for range time.Tick(time.Second) {
		fmt.Printf("%s events: %d\n", time.Since(start), events.Load())
	}
	wg.Wait()
}

func startWriters(clientset kubernetes.Interface, wg *sync.WaitGroup) {
	for i := 0; i < objectCount; i++ {
		name := fmt.Sprintf("%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			clientset.CoreV1().ConfigMaps("default").Delete(context.TODO(), name, metav1.DeleteOptions{})
			_, err := clientset.CoreV1().ConfigMaps("default").Create(context.TODO(), randomConfigmap(name), metav1.CreateOptions{})
			if err != nil {
				panic(err)
			}
			time.Sleep(timeBetweenRequests)
			for {
				_, err := clientset.CoreV1().ConfigMaps("default").Update(context.TODO(), randomConfigmap(name), metav1.UpdateOptions{})
				if err != nil {
					panic(err)
				}
				time.Sleep(timeBetweenRequests)
			}
		}()
	}
}
func startWatchers(clientset kubernetes.Interface, wg *sync.WaitGroup, events *atomic.Int64) {
	for i := 0; i < watchers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				watch, err := clientset.CoreV1().ConfigMaps("default").Watch(context.TODO(), metav1.ListOptions{ResourceVersion: initResourceVersion})
				if err != nil {
					panic(err)
				}
				for event := range watch.ResultChan() {
					switch event.Object.(type) {
					case *v1.ConfigMap:
						events.Add(1)
					case *metav1.Status:
					default:
						fmt.Printf("Event, type: %s, obj: %+v\n", event.Type, event.Object)
					}
					time.Sleep(watcherSleep)
				}
			}
		}()
	}
}

func randomConfigmap(name string) *v1.ConfigMap {
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Immutable: nil,
		Data: map[string]string{
			"random": RandString(objectSize),
		},
		BinaryData: nil,
	}
}

const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func RandString(l int) string {
	s := make([]byte, l)
	for i := 0; i < l; i++ {
		s[i] = chars[rand.Intn(len(chars))]
	}
	return string(s)
}

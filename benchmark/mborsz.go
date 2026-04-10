package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func patchPods(ctx context.Context, clientset *kubernetes.Clientset) {
	fmt.Printf("Starting patching cycle...\n")
	var wg sync.WaitGroup
	for a := 0; a <= 4000; a++ {
		for b := 0; b < 4; b++ {
			podName := fmt.Sprintf("nginx-%d-%d", a, b)
			wg.Add(1)
			go func(podName string) {
				defer wg.Done()
				patch := fmt.Sprintf(`{"metadata":{"annotations":{"benchmark-patch-timestamp":"%d"}}}`, time.Now().Unix())
				_, err := clientset.CoreV1().Pods("default").Patch(ctx, podName, types.MergePatchType, []byte(patch), metav1.PatchOptions{})
				if err != nil {
					fmt.Printf("Failed to patch pod %s: %v\n", podName, err)
				} else {
					fmt.Printf("Patched pod %s\n", podName)
				}
			}(podName)

	}
	wg.Wait()
	fmt.Printf("Finished patching cycle\n")
}

func main() {
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		fmt.Printf("failed to read kube config: %s\n", err)
		os.Exit(1)
	}
	config.QPS = 400
	config.Burst = 400

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Printf("failed to initialize clientset: %v\n", err.Error())
		return
	}

	ctx := context.Background()

	for range time.Tick(10 * time.Second) {
		patchPods(ctx, clientset)
	}
}

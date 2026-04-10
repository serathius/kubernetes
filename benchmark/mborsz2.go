package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/time/rate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// Define constants for configuration.
const (
	// maxA and maxB define the range for pod names.
	maxA = 27000
	maxB = 4

	// patchBurst is the maximum number of tokens that can be accumulated.
	patchRate  = 1000
	patchBurst = 1000
)

// patchRandomPod performs the actual patch operation for a randomly selected pod.
func patchRandomPod(ctx context.Context, clientset *kubernetes.Clientset) {
	// Randomize 'a' and 'b' for each request.
	a := rand.Intn(maxA + 1) // +1 to include 4000
	b := rand.Intn(maxB)
	podName := fmt.Sprintf("nginx-%d-%d", a, b)

	patch := fmt.Sprintf(`{"metadata":{"annotations":{"benchmark-patch-timestamp":"%d"}}}`, time.Now().Unix())
	_, err := clientset.CoreV1().Pods("default").Patch(ctx, podName, types.MergePatchType, []byte(patch), metav1.PatchOptions{})

	if err != nil {
		// We check for context cancellation to avoid logging errors on graceful shutdown.
		if ctx.Err() == nil {
			fmt.Printf("Failed to patch pod %s: %v\n", podName, err)
		}
	} else {
		fmt.Printf("Patched pod %s\n", podName)
	}
}

func main() {
	// --- Graceful Shutdown Setup ---
	// Create a context that is cancelled when an OS interrupt signal is received.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- Kubernetes Client Setup ---
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		fmt.Printf("failed to read kube config: %s\n", err)
		os.Exit(1)
	}
	config.QPS = 1000
	config.Burst = 1000

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Printf("failed to initialize clientset: %v\n", err.Error())
		return
	}
	fmt.Println("Kubernetes client initialized. Starting patch loop... (Press Ctrl+C to stop)")

	// --- Continuous Loop with Rate Limiting ---
	// The rate limiter will dictate the pace of the loop.
	limiter := rate.NewLimiter(patchRate, patchBurst)

	// This is now an infinite loop that runs as long as the program is alive.
	for {
		// Wait() blocks until a token is available, or the context is cancelled.
		if err := limiter.Wait(ctx); err != nil {
			// This error will trigger on context cancellation (e.g., Ctrl+C).
			fmt.Println("\nContext cancelled. Shutting down gracefully.")
			return // Exit the main function.
		}

		// Fire and forget: launch the goroutine and immediately loop back to wait again.
		go patchRandomPod(ctx, clientset)
	}
}

package app

import (
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	k8smetrics "k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

func init() {
	var (
		podsRegistered atomic.Bool

		fifoQueuedItems = k8smetrics.NewGaugeVec(
			&k8smetrics.GaugeOpts{
				Subsystem:      "informer",
				Name:           "queued_items",
				Help:           "Number of items currently queued in the FIFO.",
				StabilityLevel: k8smetrics.ALPHA,
			},
			[]string{"name", "group", "version", "resource"},
		)
	)

	legacyregistry.MustRegister(fifoQueuedItems)

	cache.GetInformerLengthReporter = func(objType runtime.Object) func(length float64) {
		// Only report for Pod informer
		if _, ok := objType.(*corev1.Pod); !ok {
			return nil
		}

		// Prevent duplicate registration
		if podsRegistered.Swap(true) {
			return nil
		}

		// Hardcoded GVR for pods
		metric := fifoQueuedItems.WithLabelValues(
			"kube-controller-manager", // name
			"",                        // group (core API)
			"v1",                      // version
			"pods",                    // resource
		)

		return func(length float64) {
			metric.Set(length)
		}
	}
}

package cache

import "k8s.io/apimachinery/pkg/runtime"

// GetInformerLengthReporter is a hook that can be set to report FIFO queue length.
// It receives the object type and returns a reporter function (or nil to skip metrics).
var GetInformerLengthReporter = func(objType runtime.Object) func(length float64) {
	return nil
}

type fifoMetrics struct {
	numberOfQueuedItem fifoGaugeMetric
}

type fifoGaugeMetric struct {
	reporter func(float64)
}

func (f fifoGaugeMetric) Set(value float64) {
	if f.reporter != nil {
		f.reporter(value)
	}
}

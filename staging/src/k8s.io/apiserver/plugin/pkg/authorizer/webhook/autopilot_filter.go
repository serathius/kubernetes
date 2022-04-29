/*
Copyright 2021 The Kubernetes Authors.

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

package webhook

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/rest"
	compbasemetrics "k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

func init() {
	legacyregistry.MustRegister(requestTotal)
	legacyregistry.MustRegister(requestLatency)
}

var (
	requestTotal = compbasemetrics.NewCounterVec(
		&compbasemetrics.CounterOpts{
			Name:           "apiserver_autopilot_authz_request_total",
			Help:           "Number of Autopilot Authz requests.",
			StabilityLevel: compbasemetrics.ALPHA,
		},
		[]string{"code"},
	)

	requestLatency = compbasemetrics.NewHistogramVec(
		&compbasemetrics.HistogramOpts{
			Name:           "apiserver_autopilot_authz_request_duration_seconds",
			Help:           "Request latency for Autopilot Authz requests in seconds.",
			Buckets:        []float64{0.25, 0.5, 0.7, 1, 1.5, 3, 5, 10},
			StabilityLevel: compbasemetrics.ALPHA,
		},
		[]string{"code"},
	)
)

// recordRequestTotal increments the total number of requests for the GKE Warden
// authorization webhook.
func recordRequestTotal(ctx context.Context, code string) {
	requestTotal.WithContext(ctx).WithLabelValues(code).Add(1)
}

// recordRequestLatency measures request latency in seconds for the GKE Warden
// authorization webhook. Broken down by status code.
func recordRequestLatency(ctx context.Context, code string, latency float64) {
	requestLatency.WithContext(ctx).WithLabelValues(code).Observe(latency)
}

// NewWithDecisionOnError creates a new WebhookAuthorizer with an option for
// setting decideOnError.
func NewWithDecisionOnError(config *rest.Config, version string, authorizedTTL, unauthorizedTTL time.Duration, retryBackoff wait.Backoff, decisionOnError authorizer.Decision) (*WebhookAuthorizer, error) {
	subjectAccessReview, err := subjectAccessReviewInterfaceFromConfig(config, version, retryBackoff)
	if err != nil {
		return nil, err
	}
	return &WebhookAuthorizer{
		subjectAccessReview: subjectAccessReview,
		responseCache:       cache.NewLRUExpireCache(8192),
		authorizedTTL:       authorizedTTL,
		unauthorizedTTL:     unauthorizedTTL,
		retryBackoff:        retryBackoff,
		decisionOnError:     decisionOnError,
		metrics: AuthorizerMetrics{
			RecordRequestTotal:   recordRequestTotal,
			RecordRequestLatency: recordRequestLatency,
		},
	}, nil
}

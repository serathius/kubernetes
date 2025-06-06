/*
Copyright 2025 The Kubernetes Authors.

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

package delegator

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/storage"
	etcdfeature "k8s.io/apiserver/pkg/storage/feature"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
)

func ShouldDelegateListMeta(opts *metav1.ListOptions, cache Helper) (Result, error) {
	return ShouldDelegateList(
		storage.ListOptions{
			ResourceVersionMatch: opts.ResourceVersionMatch,
			ResourceVersion:      opts.ResourceVersion,
			Predicate: storage.SelectionPredicate{
				Continue: opts.Continue,
				Limit:    opts.Limit,
			},
			Recursive: true,
		}, cache)
}

func ShouldDelegateList(opts storage.ListOptions, cache Helper) (Result, error) {
	semantic, err := storage.ValidateListOptions("", storage.APIObjectVersioner{}, opts)
	if err != nil {
		return Result{}, err
	}

	switch semantic.Consistency {
	case storage.ResourceVersionExact:
		return cache.ShouldDelegateExactRV(opts.ResourceVersion, opts.Recursive)
	case storage.ResourceVersionNotOlderThan:
		return Result{ShouldDelegate: false}, nil
	case storage.ResourceVersionAny:
		return Result{ShouldDelegate: false}, nil
	case storage.ResourceVersionQuorum:
		return cache.ShouldDelegateConsistentRead()
	default:
		return Result{}, fmt.Errorf("Unknown")
	}
}

type Helper interface {
	ShouldDelegateExactRV(rv string, recursive bool) (Result, error)
	ShouldDelegateConsistentRead() (Result, error)
}

// Result of delegator decision.
type Result struct {
	// Whether a request cannot be served by cache and should be delegated to etcd.
	ShouldDelegate bool
	// Whether a request is a consistent read, used by delegator to decide if it should call GetCurrentResourceVersion to get RV.
	// Included in interface as only cacher has keyPrefix needed to parse continue token.
	ConsistentRead bool
}

type CacheWithoutSnapshots struct{}

var _ Helper = CacheWithoutSnapshots{}

func (c CacheWithoutSnapshots) ShouldDelegateExactRV(rv string, recursive bool) (Result, error) {
	return Result{
		ShouldDelegate: true,
		ConsistentRead: false,
	}, nil
}

func (c CacheWithoutSnapshots) ShouldDelegateConsistentRead() (Result, error) {
	return Result{
		ShouldDelegate: !ConsistentReadSupported(),
		ConsistentRead: true,
	}, nil
}

// ConsistentReadSupported returns whether cache can be used to serve reads with RV not yet observed by cache, including both consistent reads.
// Function is located here to avoid import cycles between staging/src/k8s.io/apiserver/pkg/storage/cacher/delegator.go and staging/src/k8s.io/apiserver/pkg/util/flow_control/request/list_work_estimator.go.
func ConsistentReadSupported() bool {
	consistentListFromCacheEnabled := utilfeature.DefaultFeatureGate.Enabled(features.ConsistentListFromCache)
	requestWatchProgressSupported := etcdfeature.DefaultFeatureSupportChecker.Supports(storage.RequestWatchProgress)
	return consistentListFromCacheEnabled && requestWatchProgressSupported
}

/*
Copyright The Kubernetes Authors.

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

package metrics

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
	k8smetrics "k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/testutil"
)

func TestRecordStorageListMetrics(t *testing.T) {
	registry := k8smetrics.NewKubeRegistry()
	defer registry.Reset()

	registry.MustRegister(listStorageCount)
	registry.MustRegister(listStorageNumFetched)
	registry.MustRegister(listStorageNumSelectorEvals)
	registry.MustRegister(listStorageNumReturned)

	groupResource := schema.GroupResource{Group: "apps", Resource: "deployments"}

	RecordStorageListMetrics(groupResource, StorageBackendEtcd, "", 4, 3, 1)
	RecordStorageListMetrics(groupResource, StorageBackendWatchCache, "f:spec.nodeName", 2, 0, 2)

	expected := `# HELP apiserver_storage_list_evaluated_objects_total [ALPHA] Number of objects tested in the course of serving a LIST request from storage
# TYPE apiserver_storage_list_evaluated_objects_total counter
apiserver_storage_list_evaluated_objects_total{group="apps",resource="deployments",storage="etcd"} 3
apiserver_storage_list_evaluated_objects_total{group="apps",resource="deployments",storage="watchcache"} 0
# HELP apiserver_storage_list_fetched_objects_total [ALPHA] Number of objects read from storage in the course of serving a LIST request
# TYPE apiserver_storage_list_fetched_objects_total counter
apiserver_storage_list_fetched_objects_total{group="apps",index="",resource="deployments",storage="etcd"} 4
apiserver_storage_list_fetched_objects_total{group="apps",index="f:spec.nodeName",resource="deployments",storage="watchcache"} 2
# HELP apiserver_storage_list_returned_objects_total [ALPHA] Number of objects returned for a LIST request from storage
# TYPE apiserver_storage_list_returned_objects_total counter
apiserver_storage_list_returned_objects_total{group="apps",resource="deployments",storage="etcd"} 1
apiserver_storage_list_returned_objects_total{group="apps",resource="deployments",storage="watchcache"} 2
# HELP apiserver_storage_list_total [ALPHA] Number of LIST requests served from storage
# TYPE apiserver_storage_list_total counter
apiserver_storage_list_total{group="apps",index="",resource="deployments",storage="etcd"} 1
apiserver_storage_list_total{group="apps",index="f:spec.nodeName",resource="deployments",storage="watchcache"} 1
`

	if err := testutil.GatherAndCompare(registry, strings.NewReader(expected),
		"apiserver_storage_list_total",
		"apiserver_storage_list_fetched_objects_total",
		"apiserver_storage_list_evaluated_objects_total",
		"apiserver_storage_list_returned_objects_total",
	); err != nil {
		t.Fatal(err)
	}
}

func TestRecordStorageUpdateMetrics(t *testing.T) {
	registry := k8smetrics.NewKubeRegistry()
	defer registry.Reset()

	registry.MustRegister(updateAttempts)
	registry.MustRegister(updateConflicts)

	groupResource := schema.GroupResource{Group: "", Resource: "pods"}

	RecordStorageUpdateAttempts(groupResource, StorageBackendEtcd, StatusSuccess, 1)
	RecordStorageUpdateAttempts(groupResource, StorageBackendEtcd, StatusSuccess, 2)
	RecordStorageUpdateAttempts(groupResource, StorageBackendWatchCache, StatusSuccess, 1)
	RecordStorageUpdateConflict(groupResource, StorageBackendEtcd)
	RecordStorageUpdateConflict(groupResource, StorageBackendWatchCache)

	expected := `# HELP apiserver_storage_update_attempts [ALPHA] Number of attempts made to complete a GuaranteedUpdate operation in storage.
# TYPE apiserver_storage_update_attempts histogram
apiserver_storage_update_attempts_bucket{group="",resource="pods",status="success",storage="etcd",le="1"} 1
apiserver_storage_update_attempts_bucket{group="",resource="pods",status="success",storage="etcd",le="2"} 2
apiserver_storage_update_attempts_bucket{group="",resource="pods",status="success",storage="etcd",le="3"} 2
apiserver_storage_update_attempts_bucket{group="",resource="pods",status="success",storage="etcd",le="4"} 2
apiserver_storage_update_attempts_bucket{group="",resource="pods",status="success",storage="etcd",le="5"} 2
apiserver_storage_update_attempts_bucket{group="",resource="pods",status="success",storage="etcd",le="10"} 2
apiserver_storage_update_attempts_bucket{group="",resource="pods",status="success",storage="etcd",le="+Inf"} 2
apiserver_storage_update_attempts_sum{group="",resource="pods",status="success",storage="etcd"} 3
apiserver_storage_update_attempts_count{group="",resource="pods",status="success",storage="etcd"} 2
apiserver_storage_update_attempts_bucket{group="",resource="pods",status="success",storage="watchcache",le="1"} 1
apiserver_storage_update_attempts_bucket{group="",resource="pods",status="success",storage="watchcache",le="2"} 1
apiserver_storage_update_attempts_bucket{group="",resource="pods",status="success",storage="watchcache",le="3"} 1
apiserver_storage_update_attempts_bucket{group="",resource="pods",status="success",storage="watchcache",le="4"} 1
apiserver_storage_update_attempts_bucket{group="",resource="pods",status="success",storage="watchcache",le="5"} 1
apiserver_storage_update_attempts_bucket{group="",resource="pods",status="success",storage="watchcache",le="10"} 1
apiserver_storage_update_attempts_bucket{group="",resource="pods",status="success",storage="watchcache",le="+Inf"} 1
apiserver_storage_update_attempts_sum{group="",resource="pods",status="success",storage="watchcache"} 1
apiserver_storage_update_attempts_count{group="",resource="pods",status="success",storage="watchcache"} 1
# HELP apiserver_storage_update_conflicts_total [ALPHA] Number of optimistic concurrency update conflicts encountered in storage.
# TYPE apiserver_storage_update_conflicts_total counter
apiserver_storage_update_conflicts_total{group="",resource="pods",storage="etcd"} 1
apiserver_storage_update_conflicts_total{group="",resource="pods",storage="watchcache"} 1
`

	if err := testutil.GatherAndCompare(registry, strings.NewReader(expected),
		"apiserver_storage_update_attempts",
		"apiserver_storage_update_conflicts_total",
	); err != nil {
		t.Fatal(err)
	}
}


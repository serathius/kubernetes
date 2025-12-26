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

package cacher

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	examplev1 "k8s.io/apiserver/pkg/apis/example/v1"
	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/storage"
	cachertesting "k8s.io/apiserver/pkg/storage/cacher/testing"
	etcd3testing "k8s.io/apiserver/pkg/storage/etcd3/testing"
	storagetesting "k8s.io/apiserver/pkg/storage/testing"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	clientfeatures "k8s.io/client-go/features"
)

func SetupCacher(t testing.TB, opts ...cachertesting.SetupOption) (context.Context, *CacheDelegator, *etcd3testing.EtcdTestServer, cachertesting.TearDownFunc) {
	setupOpts := cachertesting.SetupOptions{}
	opts = append([]cachertesting.SetupOption{cachertesting.WithDefaults}, opts...)
	for _, opt := range opts {
		opt(&setupOpts)
	}

	server, etcdStorage := cachertesting.NewEtcdTestStorage(t, etcd3testing.PathPrefix())
	// Inject one list error to make sure we test the relist case.
	listErrors := 1
	if clientfeatures.FeatureGates().Enabled(clientfeatures.WatchListClient) {
		// The WatchListClient feature changes the reflector to use WATCH
		// instead of LIST, therefore we don't expect any errors
		listErrors = 0
	}
	wrappedStorage := &storagetesting.StorageInjectingListErrors{
		Interface: etcdStorage,
		Errors:    listErrors,
	}

	config := Config{
		Storage:             wrappedStorage,
		Versioner:           storage.APIObjectVersioner{},
		GroupResource:       schema.GroupResource{Resource: "pods"},
		EventsHistoryWindow: DefaultEventFreshDuration,
		ResourcePrefix:      setupOpts.ResourcePrefix,
		KeyFunc:             setupOpts.KeyFunc,
		GetAttrsFunc:        cachertesting.GetPodAttrs,
		NewFunc:             cachertesting.NewPod,
		NewListFunc:         cachertesting.NewPodList,
		IndexerFuncs:        setupOpts.IndexerFuncs,
		Indexers:            &setupOpts.Indexers,
		Codec:               cachertesting.Codecs.LegacyCodec(examplev1.SchemeGroupVersion),
		Clock:               setupOpts.Clock,
	}
	cacherInstance, err := NewCacherFromConfig(config)
	if err != nil {
		t.Fatalf("Failed to initialize cacher: %v", err)
	}
	ctx := context.Background()

	// Since some tests depend on the fact that GetList shouldn't fail,
	// we wait until the error from the underlying storage is consumed.
	if err := wait.PollInfinite(100*time.Millisecond, wrappedStorage.ErrorsConsumed); err != nil {
		t.Fatalf("Failed to inject list errors: %v", err)
	}

	if utilfeature.DefaultFeatureGate.Enabled(features.ResilientWatchCacheInitialization) {
		// The tests assume that Get/GetList/Watch calls shouldn't fail.
		// However, 429 error can now be returned if watchcache is under initialization.
		// To avoid rewriting all tests, we wait for watchcache to initialize.
		if err := cacherInstance.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	delegator := NewCacheDelegator(cacherInstance, wrappedStorage)
	terminate := func() {
		delegator.Stop()
		cacherInstance.Stop()
		server.Terminate(t)
	}

	return ctx, delegator, server, terminate
}

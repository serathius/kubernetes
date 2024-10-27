/*
Copyright 2018 The Kubernetes Authors.

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

package storage

import (
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage"
	storageerr "k8s.io/apiserver/pkg/storage/errors"
	coordinationapi "k8s.io/kubernetes/pkg/apis/coordination"
	"k8s.io/kubernetes/pkg/printers"
	printersinternal "k8s.io/kubernetes/pkg/printers/internalversion"
	printerstorage "k8s.io/kubernetes/pkg/printers/storage"
	"k8s.io/kubernetes/pkg/registry/coordination/lease"
	"k8s.io/apimachinery/pkg/api/errors"
)

// LeaseStorage implements a RESTStorage for leases against etcd
type LeaseStorage struct {
	Lease        *REST
	LeaseRefresh *RefreshREST
}

// NewStorage returns a RESTStorage object that will work against leases.
func NewStorage(optsGetter generic.RESTOptionsGetter) (*LeaseStorage, error) {
	store := &genericregistry.Store{
		NewFunc:                   func() runtime.Object { return &coordinationapi.Lease{} },
		NewListFunc:               func() runtime.Object { return &coordinationapi.LeaseList{} },
		DefaultQualifiedResource:  coordinationapi.Resource("leases"),
		SingularQualifiedResource: coordinationapi.Resource("lease"),

		CreateStrategy: lease.Strategy,
		UpdateStrategy: lease.Strategy,
		DeleteStrategy: lease.Strategy,

		TableConvertor: printerstorage.TableConvertor{TableGenerator: printers.NewTableGenerator().With(printersinternal.AddHandlers)},
	}
	options := &generic.StoreOptions{RESTOptions: optsGetter}
	if err := store.CompleteWithOptions(options); err != nil {
		return nil, err
	}

	return &LeaseStorage{
		Lease:        &REST{store},
		LeaseRefresh: &RefreshREST{store},
	}, nil
}

type REST struct {
	*genericregistry.Store
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	_, ok := obj.(*coordinationapi.Lease)
	if !ok {
		return nil, fmt.Errorf("not right type")
	}
	// TODO: Implement lease handling here
	return r.Store.Create(ctx, obj, createValidation, options)
}

type RefreshREST struct {
	store *genericregistry.Store
}

func (r *RefreshREST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	key, err := r.store.KeyFunc(ctx, name)
	if err != nil {
		return nil, err
	}
	obj := r.store.NewFunc()
	// Try to fetch from cache, as long as lease should not change.
	if err = r.store.Storage.Get(ctx, key, storage.GetOptions{ResourceVersion: "0"}, obj); err != nil {
		if !errors.IsNotFound(err) {
			return nil, storageerr.InterpretGetError(err, r.store.DefaultQualifiedResource, name)
		}
		// Lease was not yet observed by cache or already deleted. Let's confirm with etcd.
		err = r.store.Storage.Get(ctx, key, storage.GetOptions{}, obj)
		if err != nil {
			return nil, storageerr.InterpretGetError(err, r.store.DefaultQualifiedResource, name)
		}
	}
	lease, ok := obj.(*coordinationapi.Lease)
	if !ok {
		return nil, fmt.Errorf("not right type")
	}
	if lease.Spec.LeaseID == nil {
		return nil, fmt.Errorf("lease with no lease")
	}
	err = r.store.Storage.Refresh(ctx, *lease.Spec.LeaseID)
	return obj, err
}

func (r *RefreshREST) New() runtime.Object {
	return &coordinationapi.Lease{}
}

func (r *RefreshREST) Destroy() {
}

var _ rest.Getter = (*RefreshREST)(nil)

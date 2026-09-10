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

package direct

import (
	"net/http"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core"
	corev1informers "k8s.io/client-go/informers/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// NewSharedInformerFactory wraps a SharedInformerFactory so that calling Lister()
// returns a Lister that reads directly from the watch cache (RV=0) via the
// apiserver HTTP serving stack without registering or starting a client-go informer.
func NewSharedInformerFactory(base informers.SharedInformerFactory) informers.SharedInformerFactory {
	if base == nil {
		return nil
	}
	return &directSharedInformerFactory{
		SharedInformerFactory: base,
	}
}

// SetHandler binds the apiserver HTTP serving handler and loopback credentials
// if f was wrapped with NewSharedInformerFactory.
func SetHandler(f informers.SharedInformerFactory, handler http.Handler, loopbackConfig *rest.Config) {
	if d, ok := f.(*directSharedInformerFactory); ok {
		d.setHandler(handler, loopbackConfig)
	}
}

type directSharedInformerFactory struct {
	informers.SharedInformerFactory

	lock        sync.RWMutex
	handler     http.Handler
	bearerToken string
	userAgent   string
}

func (f *directSharedInformerFactory) setHandler(handler http.Handler, loopbackConfig *rest.Config) {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.handler = handler
	if loopbackConfig != nil {
		f.bearerToken = loopbackConfig.BearerToken
		f.userAgent = loopbackConfig.UserAgent
	}
}

func (f *directSharedInformerFactory) getHandler() (http.Handler, string, string) {
	f.lock.RLock()
	defer f.lock.RUnlock()
	return f.handler, f.bearerToken, f.userAgent
}

func (f *directSharedInformerFactory) clientFor(gvr schema.GroupVersionResource) Client {
	return &httpClient{
		factory: f,
		gvr:     gvr,
	}
}

func (f *directSharedInformerFactory) Core() coreinformers.Interface {
	return &directCoreInformers{
		Interface: f.SharedInformerFactory.Core(),
		factory:   f,
	}
}

func (f *directSharedInformerFactory) ForResource(resource schema.GroupVersionResource) (informers.GenericInformer, error) {
	if resource.GroupResource() == corev1.Resource("pods") {
		return &directGenericInformer{
			base:   f.SharedInformerFactory,
			gvr:    resource,
			lister: NewLister[runtime.Object](f.clientFor(resource)),
		}, nil
	}
	return f.SharedInformerFactory.ForResource(resource)
}

type directGenericInformer struct {
	base   informers.SharedInformerFactory
	gvr    schema.GroupVersionResource
	lister cache.GenericLister
}

func (g *directGenericInformer) Informer() cache.SharedIndexInformer {
	inf, err := g.base.ForResource(g.gvr)
	if err != nil {
		return nil
	}
	return inf.Informer()
}

func (g *directGenericInformer) Lister() cache.GenericLister {
	return g.lister
}

type directCoreInformers struct {
	coreinformers.Interface
	factory *directSharedInformerFactory
}

func (c *directCoreInformers) V1() corev1informers.Interface {
	return &directCoreV1Informers{
		Interface: c.Interface.V1(),
		factory:   c.factory,
	}
}

type directCoreV1Informers struct {
	corev1informers.Interface
	factory *directSharedInformerFactory
}

func (v *directCoreV1Informers) Pods() corev1informers.TypedPodInformer {
	return &directPodInformer{
		TypedPodInformer: v.Interface.Pods(),
		lister:           NewPodLister(v.factory.clientFor(corev1.SchemeGroupVersion.WithResource("pods"))),
	}
}

type directPodInformer struct {
	corev1informers.TypedPodInformer
	lister corev1listers.PodLister
}

var _ corev1informers.TypedPodInformer = &directPodInformer{}

func (d *directPodInformer) Lister() corev1listers.PodLister {
	return d.lister
}

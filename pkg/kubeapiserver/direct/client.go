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
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Client executes Get and List requests in-process through the apiserver
// HTTP serving stack (authentication, authorization, APF, audit, HTTP logging)
// while receiving versioned objects directly in memory without wire serialization.
type Client interface {
	Get(ctx context.Context, namespace, name string, options metav1.GetOptions) (runtime.Object, error)
	List(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error)
}

type httpClient struct {
	factory *directSharedInformerFactory
	gvr     schema.GroupVersionResource
}

var _ Client = &httpClient{}

func (c *httpClient) Get(ctx context.Context, namespace, name string, options metav1.GetOptions) (runtime.Object, error) {
	query := url.Values{}
	if options.ResourceVersion != "" {
		query.Set("resourceVersion", options.ResourceVersion)
	}
	return c.do(ctx, c.buildPath(namespace, name), query)
}

func (c *httpClient) List(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
	query := url.Values{}
	if options.ResourceVersion != "" {
		query.Set("resourceVersion", options.ResourceVersion)
	}
	if options.LabelSelector != "" {
		query.Set("labelSelector", options.LabelSelector)
	}
	if options.FieldSelector != "" {
		query.Set("fieldSelector", options.FieldSelector)
	}
	return c.do(ctx, c.buildPath(namespace, ""), query)
}

func (c *httpClient) buildPath(namespace, name string) string {
	var b strings.Builder
	if c.gvr.Group == "" {
		b.WriteString("/api/")
		b.WriteString(c.gvr.Version)
	} else {
		b.WriteString("/apis/")
		b.WriteString(c.gvr.Group)
		b.WriteByte('/')
		b.WriteString(c.gvr.Version)
	}
	if namespace != "" {
		b.WriteString("/namespaces/")
		b.WriteString(url.PathEscape(namespace))
	}
	b.WriteByte('/')
	b.WriteString(c.gvr.Resource)
	if name != "" {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(name))
	}
	return b.String()
}

func (c *httpClient) do(ctx context.Context, path string, query url.Values) (runtime.Object, error) {
	handler, bearerToken, userAgent := c.factory.getHandler()
	if handler == nil {
		return nil, errors.New("apiserver HTTP handler is not yet initialized")
	}
	reqCtx, cancel := detachedRequestContext(ctx)
	defer cancel()

	u := &url.URL{
		Path:     path,
		RawQuery: query.Encode(),
	}
	header := make(http.Header, 3)
	header.Set("Accept", "application/vnd.kubernetes.protobuf,application/json")
	if bearerToken != "" {
		header.Set("Authorization", "Bearer "+bearerToken)
	}
	if userAgent != "" {
		header.Set("User-Agent", userAgent)
	}

	req := &http.Request{
		Method:     http.MethodGet,
		URL:        u,
		RequestURI: u.RequestURI(),
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     header,
		RemoteAddr: "127.0.0.1:0",
	}
	req = req.WithContext(reqCtx)

	w := newObjectResponseWriter()
	handler.ServeHTTP(w, req)
	return w.result(c.gvr.GroupResource())
}

// detachedRequestContext creates a clean request context for in-process HTTP dispatch
// so outer request values (such as AuditContext, RequestInfo, and LatencyTrackers)
// do not collide with the inner request's handler chain, while still propagating
// cancellation and deadlines from ctx.
func detachedRequestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		return context.Background(), func() {}
	}
	base := context.Background()
	if deadline, ok := ctx.Deadline(); ok {
		reqCtx, cancel := context.WithDeadline(base, deadline)
		stop := context.AfterFunc(ctx, cancel)
		return reqCtx, func() {
			stop()
			cancel()
		}
	}
	if ctx.Done() != nil {
		reqCtx, cancel := context.WithCancel(base)
		stop := context.AfterFunc(ctx, cancel)
		return reqCtx, func() {
			stop()
			cancel()
		}
	}
	return base, func() {}
}

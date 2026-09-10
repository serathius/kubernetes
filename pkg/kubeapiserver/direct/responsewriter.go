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
	"bytes"
	"fmt"
	"net/http"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
)

// objectResponseWriter implements http.ResponseWriter and responsewriters.ObjectResponseWriter
// so in-process requests dispatched through GenericAPIServer.Handler receive versioned
// runtime.Objects directly in memory without wire marshaling/unmarshaling.
type objectResponseWriter struct {
	header     http.Header
	statusCode int
	wroteCode  bool
	obj        runtime.Object
	body       bytes.Buffer
}

var _ responsewriters.ObjectResponseWriter = &objectResponseWriter{}

func newObjectResponseWriter() *objectResponseWriter {
	return &objectResponseWriter{
		header:     make(http.Header),
		statusCode: http.StatusOK,
	}
}

func (w *objectResponseWriter) Header() http.Header {
	return w.header
}

func (w *objectResponseWriter) WriteHeader(statusCode int) {
	if !w.wroteCode {
		w.statusCode = statusCode
		w.wroteCode = true
	}
}

func (w *objectResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteCode {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(b)
}

func (w *objectResponseWriter) WriteObject(statusCode int, obj runtime.Object) {
	if !w.wroteCode {
		w.WriteHeader(statusCode)
	}
	if w.obj == nil {
		w.obj = obj
	}
}

func (w *objectResponseWriter) result(gr schema.GroupResource) (runtime.Object, error) {
	if status, ok := w.obj.(*metav1.Status); ok {
		return nil, &apierrors.StatusError{ErrStatus: *status}
	}
	if w.statusCode < http.StatusOK || w.statusCode >= http.StatusBadRequest {
		return nil, apierrors.NewGenericServerResponse(w.statusCode, "get", gr, "", strings.TrimSpace(w.body.String()), 0, false)
	}
	if w.obj == nil {
		return nil, fmt.Errorf("no object written by apiserver handler (status=%d)", w.statusCode)
	}
	return w.obj, nil
}

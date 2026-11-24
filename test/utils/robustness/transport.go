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

package robustness

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/endpoints/request"
)

// VerbWatch is the ClientFacts.Verb for watch streams. Watch rules are evaluated
// per event with Name and Namespace from the event's object. A BlockingFault
// there stalls the reflector and leaves the informer cache stale.
const VerbWatch = "WATCH"

// HTTPStatusError represents a structured API error status that should be converted
// into a valid HTTP response with the given status code and serializable metav1.Status payload.
type HTTPStatusError struct {
	StatusCode int
	Status     metav1.Status
}

func (e HTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP Status Error %d: %s", e.StatusCode, e.Status.Message)
}

// ApplyTransport implements TransportFault by returning a synthetic API error response.
func (e HTTPStatusError) ApplyTransport() *HTTPStatusError {
	return &e
}

// NewHTTPStatusError creates an HTTPStatusError representing common API server failures.
func NewHTTPStatusError(statusCode int, reason metav1.StatusReason, message string) HTTPStatusError {
	return HTTPStatusError{
		StatusCode: statusCode,
		Status: metav1.Status{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Status",
				APIVersion: "v1",
			},
			Status:  metav1.StatusFailure,
			Message: message,
			Reason:  reason,
			Code:    int32(statusCode),
		},
	}
}

// LoseResponseAfterCommit forwards the request to the real transport and, if
// the server returns a 2xx status (write committed in etcd), closes the real
// response and returns either Response/StatusCode or Err (defaulting to
// context.DeadlineExceeded). Non-2xx responses pass through untouched.
type LoseResponseAfterCommit struct {
	StatusCode int
	Response   *HTTPStatusError
	Err        error
}

// ApplyPostTransport implements PostTransportFault.
func (a LoseResponseAfterCommit) ApplyPostTransport(resp *http.Response, err error) (*http.Response, error) {
	if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, err
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	if a.Response != nil {
		return synthesizeResponse(*a.Response)
	}
	if a.StatusCode != 0 {
		return synthesizeResponse(NewHTTPStatusError(a.StatusCode, metav1.StatusReasonTimeout, "injected post-commit response loss"))
	}
	if a.Err != nil {
		return nil, a.Err
	}
	return nil, context.DeadlineExceeded
}

// DropEvent discards a matched watch event without closing the stream.
type DropEvent struct{}

// ApplyWatch implements WatchFault.
func (DropEvent) ApplyWatch(context.Context) WatchAction {
	return WatchAction{Drop: true}
}

// TerminateWatch closes the watch stream when an event matches, optionally
// forwarding the triggering event first and/or emitting a synthetic watch.Error.
type TerminateWatch struct {
	StatusCode          int
	Reason              metav1.StatusReason
	Message             string
	ForwardTriggerEvent bool
}

// ApplyWatch implements WatchFault.
func (a TerminateWatch) ApplyWatch(context.Context) WatchAction {
	act := WatchAction{
		Terminate:              true,
		ForwardBeforeTerminate: a.ForwardTriggerEvent,
	}
	if a.StatusCode != 0 {
		msg := a.Message
		if msg == "" {
			msg = fmt.Sprintf("injected watch termination (%d)", a.StatusCode)
		}
		errStatus := NewHTTPStatusError(a.StatusCode, a.Reason, msg).Status
		act.Status = &errStatus
	}
	return act
}

// ForceWatchCompactionRelist optionally invokes Compact(ctx) (e.g. to compact
// embedded etcd), drops the triggering watch event, and closes the stream with
// a 410 Gone (StatusReasonExpired) watch.Error so the Reflector relists.
type ForceWatchCompactionRelist struct {
	Compact func(ctx context.Context) error
	Message string
}

// ApplyWatch implements WatchFault.
func (a ForceWatchCompactionRelist) ApplyWatch(ctx context.Context) WatchAction {
	if a.Compact != nil {
		_ = a.Compact(ctx)
	}
	msg := a.Message
	if msg == "" {
		msg = "too old resource version: injected compaction relist"
	}
	errStatus := NewHTTPStatusError(http.StatusGone, metav1.StatusReasonExpired, msg).Status
	return WatchAction{
		Terminate: true,
		Status:    &errStatus,
	}
}

// FaultInjectingTransport wraps http.RoundTripper and triggers faults on matching REST API calls.
type FaultInjectingTransport struct {
	realTransport http.RoundTripper
	registry      *FaultRegistry
	activity      *activityTracker // may be nil, records mutating traffic for settle detection
	resolver      *request.RequestInfoFactory
}

// NewFaultInjectingTransport creates a wrapped http.RoundTripper that routes request
// hooks to the registry. activity may be nil when settle detection is not needed.
func NewFaultInjectingTransport(realTransport http.RoundTripper, registry *FaultRegistry, activity *activityTracker) http.RoundTripper {
	return &FaultInjectingTransport{
		realTransport: realTransport,
		registry:      registry,
		activity:      activity,
		resolver: &request.RequestInfoFactory{
			APIPrefixes:          sets.NewString("api", "apis"),
			GrouplessAPIPrefixes: sets.NewString("api"),
		},
	}
}

func (t *FaultInjectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	info, _ := t.resolver.NewRequestInfo(req)
	if info == nil || !info.IsResourceRequest {
		return t.realTransport.RoundTrip(req)
	}

	// Watches are faulted per event because they are already open when rules register.
	if info.Verb == "watch" {
		return t.roundTripWatch(req, info)
	}

	switch req.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		t.activity.recordMutation()
	}

	httpErr, post := t.registry.resolveTransport(req.Context(), ClientFacts{
		Verb:        req.Method,
		Group:       info.APIGroup,
		Resource:    info.Resource,
		Subresource: info.Subresource,
		Namespace:   info.Namespace,
		Name:        info.Name,
	})
	if httpErr != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return synthesizeResponse(*httpErr)
	}

	resp, err := t.realTransport.RoundTrip(req)
	if post != nil {
		return post.ApplyPostTransport(resp, err)
	}
	return resp, err
}

func (t *FaultInjectingTransport) roundTripWatch(req *http.Request, info *request.RequestInfo) (*http.Response, error) {
	resp, err := t.realTransport.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	// Only newline-delimited JSON streams are intercepted (the fixture pins JSON).
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		return resp, nil
	}
	resp.Body = &watchEventReader{
		ctx:      req.Context(),
		body:     resp.Body,
		reader:   bufio.NewReader(resp.Body),
		registry: t.registry,
		facts: ClientFacts{
			Verb:        VerbWatch,
			Group:       info.APIGroup,
			Resource:    info.Resource,
			Subresource: info.Subresource,
		},
	}
	return resp, nil
}

// watchEventReader resolves the registry for each JSON watch event before
// passing the bytes through unchanged (or dropping/terminating on a WatchFault).
type watchEventReader struct {
	ctx        context.Context
	body       io.ReadCloser
	reader     *bufio.Reader
	buffer     bytes.Buffer
	terminated bool
	registry   *FaultRegistry
	facts      ClientFacts // Name, Namespace, EventType are filled per event
}

func (r *watchEventReader) Read(p []byte) (int, error) {
	for {
		if r.buffer.Len() > 0 {
			return r.buffer.Read(p)
		}
		if r.terminated {
			return 0, io.EOF
		}
		line, err := r.reader.ReadBytes('\n')
		if len(line) > 0 {
			act := r.onEvent(line)
			if act.Terminate {
				r.terminated = true
				_ = r.body.Close()
				if act.ForwardBeforeTerminate {
					r.buffer.Write(line)
				}
				if act.Status != nil {
					errLine, mErr := marshalWatchErrorEvent(act.Status)
					if mErr != nil {
						return 0, mErr
					}
					r.buffer.Write(errLine)
				}
				if r.buffer.Len() > 0 {
					return r.buffer.Read(p)
				}
				return 0, io.EOF
			}
			if act.Drop {
				if err != nil {
					return 0, err
				}
				continue
			}
			r.buffer.Write(line)
			return r.buffer.Read(p)
		}
		return 0, err
	}
}

func (r *watchEventReader) onEvent(line []byte) WatchAction {
	var event metav1.WatchEvent
	if json.Unmarshal(line, &event) != nil {
		return WatchAction{}
	}
	if event.Type == string(watch.Error) {
		return WatchAction{}
	}
	facts := r.facts
	facts.EventType = watch.EventType(event.Type)
	if event.Type != string(watch.Bookmark) {
		var meta metav1.PartialObjectMetadata
		if json.Unmarshal(event.Object.Raw, &meta) != nil {
			return WatchAction{}
		}
		facts.Name = meta.Name
		facts.Namespace = meta.Namespace
	}
	return r.registry.ResolveWatchEvent(r.ctx, facts)
}

func marshalWatchErrorEvent(status *metav1.Status) ([]byte, error) {
	s := *status
	if s.Kind == "" {
		s.Kind = "Status"
	}
	if s.APIVersion == "" {
		s.APIVersion = "v1"
	}
	if s.Status == "" {
		s.Status = metav1.StatusFailure
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	ev := metav1.WatchEvent{
		Type:   string(watch.Error),
		Object: runtime.RawExtension{Raw: raw},
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func (r *watchEventReader) Close() error {
	return r.body.Close()
}

func synthesizeResponse(httpErr HTTPStatusError) (*http.Response, error) {
	status := httpErr.Status
	if status.Kind == "" {
		status.Kind = "Status"
	}
	if status.APIVersion == "" {
		status.APIVersion = "v1"
	}
	bodyBytes, jsonErr := json.Marshal(status)
	if jsonErr != nil {
		return nil, fmt.Errorf("failed to marshal injected status error: %w", jsonErr)
	}

	// Set Content-Type so client-go decodes the full metav1.Status payload
	// (Message, Details, RetryAfterSeconds) into *apierrors.StatusError.
	header := make(http.Header)
	header.Set("Content-Type", "application/json")

	return &http.Response{
		StatusCode:    httpErr.StatusCode,
		Status:        fmt.Sprintf("%d %s", httpErr.StatusCode, http.StatusText(httpErr.StatusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(bytes.NewReader(bodyBytes)),
		ContentLength: int64(len(bodyBytes)),
		Header:        header,
	}, nil
}

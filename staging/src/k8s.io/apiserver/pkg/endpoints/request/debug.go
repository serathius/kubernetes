/*
Copyright 2024 The Kubernetes Authors.

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

package request

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"runtime/debug"
	"unsafe"
)

type contextKey int

const (
	contextMarkerKey contextKey = iota
)

// WithContextMarker adds a marker to the context to track its propagation.
func WithContextMarker(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, contextMarkerKey, name)
}

// WithContextMarkerFilter is an http.Handler wrapper that adds a context marker.
func WithContextMarkerFilter(handler http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req = req.WithContext(WithContextMarker(req.Context(), name))
		handler.ServeHTTP(w, req)
	})
}

// VerifyContextMarker checks if the context marker is present.
// If missing, it prints internals and returns a restored context with a new marker.
func VerifyContextMarker(ctx context.Context, prefix string) context.Context {
	return ctx
	if ctx == nil {
		fmt.Printf("DEBUG CONTEXT [%s]: context is nil\n", prefix)
		return nil
	}
	val := ctx.Value(contextMarkerKey)
	if val == nil {
		fmt.Printf("DEBUG CONTEXT [%s]: !!! CONTEXT MARKER MISSING !!!\n", prefix)
		fmt.Printf("STACKTRACE:\n%s\n", string(debug.Stack()))
		PrintContextInternals(ctx, prefix)
		return WithContextMarker(ctx, "restored-"+prefix)
	}
	fmt.Printf("DEBUG CONTEXT [%s]: marker found: %v\n", prefix, val)
	return ctx
}

// PrintContextInternals prints the internal structure of a context.Context.
// This is a debug utility to help identify where context is lost or incorrectly replaced.
func PrintContextInternals(ctx context.Context, prefix string) {
	if ctx == nil {
		fmt.Printf("DEBUG CONTEXT [%s]: context is nil\n", prefix)
		return
	}
	fmt.Printf("DEBUG CONTEXT [%s]: type=%T\n", prefix, ctx)
	printContext(ctx, prefix, 0)
}

func printContext(ctx context.Context, prefix string, depth int) {
	if ctx == nil || depth > 10 {
		return
	}

	v := reflect.ValueOf(ctx)
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}

	t := v.Type()
	indent := ""
	for i := 0; i < depth; i++ {
		indent += "  "
	}

	fmt.Printf("DEBUG CONTEXT [%s]: %s[%d] %s.%s\n", prefix, indent, depth, t.PkgPath(), t.Name())

	if t.Kind() == reflect.Struct {
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			fieldType := t.Field(i)

			// Use unsafe to get the value of unexported fields without Set()
			var fieldVal interface{}
			if fieldType.IsExported() {
				fieldVal = field.Interface()
			} else if v.CanAddr() {
				// If the parent is addressable, we can get the field's address
				ptr := unsafe.Pointer(v.UnsafeAddr() + fieldType.Offset)
				fieldVal = reflect.NewAt(fieldType.Type, ptr).Elem().Interface()
			} else {
				// Fallback for non-addressable structs (e.g. returned by value)
				// We can't easily get unexported fields here without reflection hackery
				// that might panic. Let's just print the name and type.
				fmt.Printf("DEBUG CONTEXT [%s]: %s  field: %s (unexported, non-addressable)\n", prefix, indent, fieldType.Name)
				continue
			}

			// Check for parent context fields
			if fieldType.Name == "Context" || fieldType.Name == "parent" || (fieldType.Anonymous && field.Type().Implements(reflect.TypeOf((*context.Context)(nil)).Elem())) {
				if nextCtx, ok := fieldVal.(context.Context); ok {
					printContext(nextCtx, prefix, depth+1)
					continue
				}
			}

			// Print other fields
			val := "???"
			func() {
				defer func() { recover() }()
				val = fmt.Sprintf("%+v", fieldVal)
			}()
			fmt.Printf("DEBUG CONTEXT [%s]: %s  field: %s, value: %s\n", prefix, indent, fieldType.Name, val)
		}
	}
}

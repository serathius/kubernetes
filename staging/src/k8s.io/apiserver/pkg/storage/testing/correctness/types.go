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

package correctness

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/storage"
)

// Operation represents a single operation recorded in a concurrent execution history.
type Operation struct {
	ClientID int
	Request  Request
	Response Response
	Start    time.Time
	End      time.Time
}

// Request represents an input invocation to the storage interface.
type Request struct {
	Op            OpType
	Key           string
	Object        runtime.Object
	GetOptions    storage.GetOptions
	Preconditions *storage.Preconditions
}

// Describe formats the operation for debugging and visualization.
func (r Request) Describe(output Response) string {
	if output.Err != nil {
		return fmt.Sprintf("%s(%s) -> Err: %v", r.Op, r.Key, output.Err)
	}
	accessor, err := meta.Accessor(output.Object)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s(%s) -> RV: %s", r.Op, r.Key, accessor.GetResourceVersion())
}

// OpType identifies the storage interface operation.
type OpType string

const (
	OpCreate OpType = "Create"
	OpDelete OpType = "Delete"
	OpGet    OpType = "Get"
)

// Response represents the output/result from the storage interface invocation.
type Response struct {
	Object runtime.Object
	Err    error
}

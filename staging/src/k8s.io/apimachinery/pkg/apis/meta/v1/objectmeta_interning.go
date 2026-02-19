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

package v1

import (
	"sync"
	"weak"

	"k8s.io/component-base/featuregate/testing"
)

var (
	fieldsV1Cache     = make(map[string]weak.Pointer[FieldsV1])
	fieldsV1CacheLock sync.RWMutex
)
var enableInternFieldsV1 = true

func SetInternFieldsV1(tb testing.TB, new bool) {
	old := enableInternFieldsV1
	tb.Cleanup(func() {
		enableInternFieldsV1 = old
	})
	enableInternFieldsV1 = new
}

// internFieldsV1 handles unmarshaling with deduplication.
func internFieldsV1(data []byte, target *FieldsV1) error {
	if !enableInternFieldsV1 {
		return target.Unmarshal(data)
	}
	// Try lock-free lookup
	fieldsV1CacheLock.RLock()
	weakPtr, ok := fieldsV1Cache[string(data)]
	fieldsV1CacheLock.RUnlock()

	if ok {
		if cached := weakPtr.Value(); cached != nil {
			*target = *cached
			return nil
		}
	}

	// Miss: Unmarshal normally
	if err := target.Unmarshal(data); err != nil {
		return err
	}

	// Double check with lock
	fieldsV1CacheLock.Lock()
	defer fieldsV1CacheLock.Unlock()

	if weakPtr, ok := fieldsV1Cache[string(data)]; ok {
		if cached := weakPtr.Value(); cached != nil {
			*target = *cached
			return nil
		}
	}

	// Cache it.
	// We allocate a new ManagedFieldsEntry on the heap to keep in cache.
	heapEntry := new(FieldsV1)
	*heapEntry = *target

	fieldsV1Cache[string(data)] = weak.Make(heapEntry)

	return nil
}

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
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/storage"
)

var versioner = storage.APIObjectVersioner{}

// NewEmptyState returns a new State with no items.
func NewEmptyState(prefix string) *State {
	return &State{
		Prefix: prefix,
		Items:  make(map[string]runtime.Object),
	}
}

// NewStateFromStorage initializes a State from storage by listing all objects under prefix.
func NewStateFromStorage(prefix string, list runtime.Object, keyFunc func(runtime.Object) (string, error)) (*State, error) {
	state := NewEmptyState(prefix)
	accessor, err := meta.ListAccessor(list)
	if err != nil {
		return nil, err
	}
	rvStr := accessor.GetResourceVersion()
	if len(rvStr) > 0 {
		state.ResourceVersion, err = versioner.ParseResourceVersion(rvStr)
		if err != nil {
			return nil, err
		}
	}
	objs, err := meta.ExtractList(list)
	if err != nil {
		return nil, err
	}
	for _, obj := range objs {
		key, err := keyFunc(obj)
		if err != nil {
			return nil, err
		}
		state.Items[key] = obj.DeepCopyObject()
	}
	return state, nil
}

// State represents the sequential specification state for storage linearizability testing.
type State struct {
	Items           map[string]runtime.Object
	ResourceVersion uint64
	Prefix          string
}

// Step applies an operation to the sequential state machine.
func (s *State) Step(input Request, output Response) (ok bool, next *State) {
	switch input.Op {
	case OpCreate:
		return s.stepCreate(input, output)
	case OpDelete:
		return s.stepDelete(input, output)
	case OpGet:
		return s.stepGet(input, output)
	default:
		panic(fmt.Sprintf("unknown operation: %v", input.Op))
	}
}

func (s *State) Equal(other *State) bool {
	if s.ResourceVersion != other.ResourceVersion || s.Prefix != other.Prefix || len(s.Items) != len(other.Items) {
		return false
	}
	for k, v1 := range s.Items {
		v2, ok := other.Items[k]
		if !ok {
			return false
		}
		acc1, err1 := meta.Accessor(v1)
		acc2, err2 := meta.Accessor(v2)
		if err1 != nil || err2 != nil || acc1.GetUID() != acc2.GetUID() || acc1.GetResourceVersion() != acc2.GetResourceVersion() {
			return false
		}
	}
	return true
}

func (s *State) stepCreate(input Request, output Response) (ok bool, next *State) {
	next = s.Clone()
	expectedObj, expectedErr := next.create(input.Key, input.Object)
	if !matchResponse(expectedObj, expectedErr, output.Object, output.Err) {
		return false, s
	}
	return true, next
}

func (s *State) stepDelete(input Request, output Response) (ok bool, next *State) {
	next = s.Clone()
	expectedObj, expectedErr := next.delete(context.Background(), input.Key, input.Preconditions, nil)
	if !matchResponse(expectedObj, expectedErr, output.Object, output.Err) {
		return false, s
	}
	return true, next
}

func (s *State) stepGet(input Request, output Response) (ok bool, next *State) {
	expectedObj, expectedErr := s.get(input.Key, input.GetOptions)
	if !matchResponse(expectedObj, expectedErr, output.Object, output.Err) {
		return false, s
	}
	return true, s
}

func matchResponse(expectedObj runtime.Object, expectedErr error, actualObj runtime.Object, actualErr error) bool {
	if expectedErr != nil || actualErr != nil {
		if expectedErr == nil || actualErr == nil {
			return false
		}
		return expectedErr.Error() == actualErr.Error() || reflect.DeepEqual(expectedErr, actualErr)
	}

	if expectedObj == nil || actualObj == nil {
		return expectedObj == nil && actualObj == nil
	}

	accExp, err1 := meta.Accessor(expectedObj)
	accAct, err2 := meta.Accessor(actualObj)
	if err1 != nil || err2 != nil {
		return false
	}

	// Strictly match ResourceVersion (forces RV to increase by exactly 1 on mutation)
	if accExp.GetResourceVersion() != accAct.GetResourceVersion() {
		return false
	}
	if accExp.GetUID() != "" && accAct.GetUID() != "" && accExp.GetUID() != accAct.GetUID() {
		return false
	}
	if accExp.GetName() != accAct.GetName() || accExp.GetNamespace() != accAct.GetNamespace() {
		return false
	}
	return true
}

func (s *State) prepareKey(key string) string {
	if s.Prefix == "" {
		return key
	}
	p := s.Prefix
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimSuffix(p, "/")
	if !strings.HasPrefix(key, "/") {
		key = "/" + key
	}
	return p + key
}

func (s *State) create(key string, obj runtime.Object) (runtime.Object, error) {
	if _, exists := s.Items[key]; exists {
		return nil, storage.NewKeyExistsError(s.prepareKey(key), 0)
	}
	s.ResourceVersion++
	copied := obj.DeepCopyObject()
	accessor, err := meta.Accessor(copied)
	if err != nil {
		return nil, err
	}
	accessor.SetResourceVersion(strconv.FormatUint(s.ResourceVersion, 10))
	s.Items[key] = copied
	return copied, nil
}

func (s *State) get(key string, opts storage.GetOptions) (runtime.Object, error) {
	stored, exists := s.Items[key]
	if !exists {
		if opts.IgnoreNotFound {
			return nil, nil
		}
		return nil, storage.NewKeyNotFoundError(s.prepareKey(key), 0)
	}
	return stored.DeepCopyObject(), nil
}

func (s *State) delete(ctx context.Context, key string, preconditions *storage.Preconditions, validateDeletion storage.ValidateObjectFunc) (runtime.Object, error) {
	stored, exists := s.Items[key]
	if !exists {
		return nil, storage.NewKeyNotFoundError(s.prepareKey(key), 0)
	}
	if !matchesPreconditions(stored, preconditions) {
		return nil, storage.NewInvalidObjError(s.prepareKey(key), "preconditions failed")
	}
	if validateDeletion != nil && stored != nil {
		if err := validateDeletion(ctx, stored); err != nil {
			return nil, err
		}
	}
	s.ResourceVersion++
	deletedObj := stored.DeepCopyObject()
	accessor, err := meta.Accessor(deletedObj)
	if err != nil {
		return nil, err
	}
	accessor.SetResourceVersion(strconv.FormatUint(s.ResourceVersion, 10))
	delete(s.Items, key)
	return deletedObj, nil
}

func (s *State) Describe() string {
	return fmt.Sprintf("RV: %d, Prefix: %q, ItemCount: %d", s.ResourceVersion, s.Prefix, len(s.Items))
}

func (s *State) Clone() *State {
	clone := &State{
		Items:           make(map[string]runtime.Object, len(s.Items)),
		ResourceVersion: s.ResourceVersion,
		Prefix:          s.Prefix,
	}
	for k, v := range s.Items {
		if v != nil {
			clone.Items[k] = v.DeepCopyObject()
		}
	}
	return clone
}

func matchesPreconditions(obj runtime.Object, p *storage.Preconditions) bool {
	if p == nil {
		return true
	}
	acc, err := meta.Accessor(obj)
	if err != nil {
		return false
	}
	if p.UID != nil && *p.UID != acc.GetUID() {
		return false
	}
	if p.ResourceVersion != nil {
		reqRV, err := versioner.ParseResourceVersion(*p.ResourceVersion)
		objRV, err2 := versioner.ParseResourceVersion(acc.GetResourceVersion())
		if err != nil || err2 != nil || reqRV != objRV {
			return false
		}
	}
	return true
}

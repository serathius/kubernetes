/*
Copyright 2015 The Kubernetes Authors.

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

package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

func TestNewIdentifier(t *testing.T) {
	resetIdentity()
	id1 := NewIdentifier("a", &v1.Pod{})
	id2 := NewIdentifier("a", &v1.Pod{})

	assert.Equal(t, "a", id1.Name())
	assert.Equal(t, "v1.Pod", id1.ItemType())
	assert.True(t, id1.IsUnique())

	assert.Equal(t, "a", id2.Name())
	assert.Equal(t, "v1.Pod", id2.ItemType())
	assert.True(t, id1.IsUnique())
}

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

package storage

import (
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPreconditionsCheckWithNilObject(t *testing.T) {
	p := &Preconditions{}
	err := p.Check("foo", nil)
	if err == nil {
		t.Fatalf("expected an error")
	}

	var internalErr InternalError
	if !errors.As(err, &internalErr) {
		t.Fatalf("expected error to be of type: %T, but got: %#v", InternalError{}, err)
	}
	if want := "can't enforce preconditions"; !strings.Contains(internalErr.Error(), want) {
		t.Errorf("expected error to contain %q", want)
	}
}

func TestValidateListOptions(t *testing.T) {
	testCases := []struct {
		name          string
		opts          ListOptions
		expectedError string
		expectedList  ListSemantic
	}{
		{
			name: "invalid resource version",
			opts: ListOptions{
				ResourceVersion: "invalid",
			},
			expectedError: "invalid resource version",
		},
		{
			name: "unknown ResourceVersionMatch value",
			opts: ListOptions{
				ResourceVersion:      "200",
				ResourceVersionMatch: "unknown",
			},
			expectedError: "unknown ResourceVersionMatch value",
		},
		{
			name: "use continueRV",
			opts: ListOptions{
				ResourceVersion: "0",
				Recursive:       true,
				Predicate: SelectionPredicate{
					Continue: encodeContinueOrDie("meta.k8s.io/v1", 100, "continue"),
				},
			},
			expectedList: ListSemantic{
				Consistency:     ResourceVersionExact,
				ResourceVersion: 100,
				ContinueKey:     "continue",
			},
		},
		{
			name: "use continueRV with empty rv",
			opts: ListOptions{
				ResourceVersion: "",
				Recursive:       true,
				Predicate: SelectionPredicate{
					Continue: encodeContinueOrDie("meta.k8s.io/v1", 100, "continue"),
				},
			},
			expectedList: ListSemantic{
				Consistency:     ResourceVersionExact,
				ResourceVersion: 100,
				ContinueKey:     "continue",
			},
		},
		{
			name: "continueRV = 0",
			opts: ListOptions{
				ResourceVersion: "",
				Recursive:       true,
				Predicate: SelectionPredicate{
					Continue: encodeContinueOrDie("meta.k8s.io/v1", 0, "continue"),
				},
			},
			expectedError: "invalid continue token",
		},
		{
			name: "continueRV < 0",
			opts: ListOptions{
				ResourceVersion: "",
				Recursive:       true,
				Predicate: SelectionPredicate{
					Continue: encodeContinueOrDie("meta.k8s.io/v1", -1, "continue"),
				},
			},
			expectedList: ListSemantic{
				Consistency:     ResourceVersionQuorum,
				ResourceVersion: 0,
				ContinueKey:     "continue",
			},
		},
		{
			name: "default quorum read",
			opts: ListOptions{},
			expectedList: ListSemantic{
				Consistency: ResourceVersionQuorum,
			},
		},
		{
			name: "ResourceVersionMatchNotOlderThan",
			opts: ListOptions{
				ResourceVersion:      "200",
				ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
			},
			expectedList: ListSemantic{
				Consistency:     ResourceVersionNotOlderThan,
				ResourceVersion: 200,
			},
		},
		{
			name: "ResourceVersionMatchExact",
			opts: ListOptions{
				ResourceVersion:      "200",
				ResourceVersionMatch: metav1.ResourceVersionMatchExact,
			},
			expectedList: ListSemantic{
				Consistency:     ResourceVersionExact,
				ResourceVersion: 200,
			},
		},
		{
			name: "not older than if limit unspecified",
			opts: ListOptions{
				ResourceVersion: "200",
				Recursive:       true,
			},
			expectedList: ListSemantic{
				Consistency:     ResourceVersionNotOlderThan,
				ResourceVersion: 200,
			},
		},
		{
			name: "not older than if not recursive",
			opts: ListOptions{
				ResourceVersion: "200",
				Predicate: SelectionPredicate{
					Limit: 1,
				},
			},
			expectedList: ListSemantic{
				Consistency:     ResourceVersionNotOlderThan,
				ResourceVersion: 200,
			},
		},
		{
			name: "legacy exact",
			opts: ListOptions{
				ResourceVersion: "200",
				Recursive:       true,
				Predicate: SelectionPredicate{
					Limit: 1,
				},
			},
			expectedList: ListSemantic{
				Consistency:     ResourceVersionExact,
				ResourceVersion: 200,
			},
		},
	}
	for _, tt := range testCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			semantic, err := ValidateListOptions("", APIObjectVersioner{}, tt.opts)
			if len(tt.expectedError) > 0 {
				if err == nil || !strings.Contains(err.Error(), tt.expectedError) {
					t.Fatalf("expected error: %s, but got: %v", tt.expectedError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveRevForGetList failed: %v", err)
			}
			if *semantic != tt.expectedList {
				t.Errorf("expecting = %+v, but get %+v", tt.expectedList, semantic)
			}
		})
	}
}

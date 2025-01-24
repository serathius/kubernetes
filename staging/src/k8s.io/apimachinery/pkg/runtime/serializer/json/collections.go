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

package json

import (
	"io"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	jsonv1 "github.com/go-json-experiment/json/v1"

	"k8s.io/apimachinery/pkg/runtime"
)

func streamingEncode(obj runtime.Object, w io.Writer) error {
	err := json.MarshalWrite(w, obj,
		json.Deterministic(true),
		jsontext.EscapeForHTML(true),
		json.FormatNilSliceAsNull(true),
		json.OmitZeroStructFields(false),
		jsonv1.OmitEmptyWithLegacyDefinition(true),
	)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}

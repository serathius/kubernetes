/*
Copyright 2026 Google

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

package main

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func intPtr(i int) *int {
	return &i
}

func TestParsePath(t *testing.T) {
	tests := []struct {
		name        string
		pathStr     string
		want        []segment
		wantErr     bool
	}{
		{
			name:    "empty path",
			pathStr: "",
			want:    nil,
		},
		{
			name:    "simple single key",
			pathStr: "a",
			want:    []segment{{key: "a"}},
		},
		{
			name:    "simple dotted keys",
			pathStr: "a.b.c",
			want:    []segment{{key: "a"}, {key: "b"}, {key: "c"}},
		},
		{
			name:    "key with index",
			pathStr: "a[0]",
			want:    []segment{{key: "a", index: intPtr(0)}},
		},
		{
			name:    "dotted keys with index",
			pathStr: "a.b[12].c",
			want:    []segment{{key: "a"}, {key: "b", index: intPtr(12)}, {key: "c"}},
		},
		{
			name:    "multiple indexes in sequence",
			pathStr: "a[1][2]",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty segment ignored",
			pathStr: "a..b",
			want:    []segment{{key: "a"}, {key: "b"}},
		},
		{
			name:    "invalid array index",
			pathStr: "a[xyz]",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePath(tt.pathStr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parsePath() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parsePath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMerge(t *testing.T) {
	tests := []struct {
		name string
		dst  map[string]interface{}
		src  map[string]interface{}
		want map[string]interface{}
	}{
		{
			name: "flat merge with no conflict",
			dst:  map[string]interface{}{"a": 1},
			src:  map[string]interface{}{"b": 2},
			want: map[string]interface{}{"a": 1, "b": 2},
		},
		{
			name: "flat merge with override",
			dst:  map[string]interface{}{"a": 1, "b": 2},
			src:  map[string]interface{}{"b": 3},
			want: map[string]interface{}{"a": 1, "b": 3},
		},
		{
			name: "nested map merge",
			dst: map[string]interface{}{
				"a": map[string]interface{}{
					"x": 1,
					"y": 2,
				},
			},
			src: map[string]interface{}{
				"a": map[string]interface{}{
					"y": 3,
					"z": 4,
				},
			},
			want: map[string]interface{}{
				"a": map[string]interface{}{
					"x": 1,
					"y": 3,
					"z": 4,
				},
			},
		},
		{
			name: "override type (map override with non-map)",
			dst: map[string]interface{}{
				"a": map[string]interface{}{"x": 1},
			},
			src: map[string]interface{}{
				"a": 123,
			},
			want: map[string]interface{}{
				"a": 123,
			},
		},
		{
			name: "array override replaces entirely",
			dst: map[string]interface{}{
				"a": []interface{}{1, 2, 3},
			},
			src: map[string]interface{}{
				"a": []interface{}{4, 5},
			},
			want: map[string]interface{}{
				"a": []interface{}{4, 5},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			merge(tt.dst, tt.src)
			if !reflect.DeepEqual(tt.dst, tt.want) {
				t.Errorf("merge() result = %v, want %v", tt.dst, tt.want)
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	data := map[string]interface{}{
		"a": map[string]interface{}{
			"b": "value_b",
			"c": []interface{}{"c0", "c1", "c2"},
			"d": map[string]interface{}{
				"e": 123,
			},
		},
		"x": []interface{}{
			map[string]interface{}{"name": "x0"},
			map[string]interface{}{"name": "x1"},
		},
	}

	tests := []struct {
		name     string
		segments []segment
		want     interface{}
	}{
		{
			name:     "get simple string",
			segments: []segment{{key: "a"}, {key: "b"}},
			want:     "value_b",
		},
		{
			name:     "get simple integer",
			segments: []segment{{key: "a"}, {key: "d"}, {key: "e"}},
			want:     123,
		},
		{
			name:     "get slice element",
			segments: []segment{{key: "a"}, {key: "c", index: intPtr(1)}},
			want:     "c1",
		},
		{
			name:     "get map inside slice",
			segments: []segment{{key: "x", index: intPtr(0)}, {key: "name"}},
			want:     "x0",
		},
		{
			name:     "slice out of bounds returns nil",
			segments: []segment{{key: "a"}, {key: "c", index: intPtr(5)}},
			want:     nil,
		},
		{
			name:     "slice negative index returns nil",
			segments: []segment{{key: "a"}, {key: "c", index: intPtr(-1)}},
			want:     nil,
		},
		{
			name:     "key not found returns nil",
			segments: []segment{{key: "nonexistent"}},
			want:     nil,
		},
		{
			name:     "nested key not found returns nil",
			segments: []segment{{key: "a"}, {key: "nonexistent"}},
			want:     nil,
		},
		{
			name:     "traverse non-map returns nil",
			segments: []segment{{key: "a"}, {key: "b"}, {key: "nonexistent"}},
			want:     nil,
		},
		{
			name:     "index non-slice returns nil",
			segments: []segment{{key: "a"}, {key: "b", index: intPtr(0)}},
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluate(data, tt.segments)
			if err != nil {
				t.Fatalf("evaluate() unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantPath   string
		wantFiles  []string
		wantLength bool
		wantErr    bool
	}{
		{
			name:       "valid with length flag at end",
			args:       []string{"a.b", "file1.yaml", "-l"},
			wantPath:   "a.b",
			wantFiles:  []string{"file1.yaml"},
			wantLength: true,
		},
		{
			name:       "valid with length flag at beginning",
			args:       []string{"-l", "a.b", "file1.yaml", "file2.yaml"},
			wantPath:   "a.b",
			wantFiles:  []string{"file1.yaml", "file2.yaml"},
			wantLength: true,
		},
		{
			name:       "valid without length flag",
			args:       []string{"a.b", "file1.yaml"},
			wantPath:   "a.b",
			wantFiles:  []string{"file1.yaml"},
			wantLength: false,
		},
		{
			name:    "missing files",
			args:    []string{"a.b"},
			wantErr: true,
		},
		{
			name:    "empty args",
			args:    []string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, files, length, err := parseArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if path != tt.wantPath {
					t.Errorf("parseArgs() gotPath = %q, want %q", path, tt.wantPath)
				}
				if !reflect.DeepEqual(files, tt.wantFiles) {
					t.Errorf("parseArgs() gotFiles = %v, want %v", files, tt.wantFiles)
				}
				if length != tt.wantLength {
					t.Errorf("parseArgs() gotLength = %v, want %v", length, tt.wantLength)
				}
			}
		})
	}
}

func TestMergeYAMLs(t *testing.T) {
	tests := []struct {
		name     string
		contents [][]byte
		want     map[string]interface{}
		wantErr  bool
	}{
		{
			name: "merge valid yamls",
			contents: [][]byte{
				[]byte("a: 1\nb: 2"),
				[]byte("b: 3\nc: 4"),
			},
			want: map[string]interface{}{
				"a": float64(1),
				"b": float64(3),
				"c": float64(4),
			},
		},
		{
			name: "invalid yaml error",
			contents: [][]byte{
				[]byte("a: 1"),
				[]byte("invalid_yaml: : :"),
			},
			wantErr: true,
		},
		{
			name:     "empty contents skipped",
			contents: [][]byte{nil, []byte("a: 1")},
			want:     map[string]interface{}{"a": float64(1)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mergeYAMLs(tt.contents)
			if (err != nil) != tt.wantErr {
				t.Fatalf("mergeYAMLs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("mergeYAMLs() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestFormatOutput(t *testing.T) {
	tests := []struct {
		name       string
		val        interface{}
		lengthFlag bool
		want       string
		wantErr    bool
	}{
		{
			name:       "nil value returns empty string",
			val:        nil,
			lengthFlag: false,
			want:       "",
		},
		{
			name:       "nil value with length returns empty string",
			val:        nil,
			lengthFlag: true,
			want:       "",
		},
		{
			name:       "string value",
			val:        "hello",
			lengthFlag: false,
			want:       "hello",
		},
		{
			name:       "string value length",
			val:        "hello",
			lengthFlag: true,
			want:       "5",
		},
		{
			name:       "boolean value",
			val:        true,
			lengthFlag: false,
			want:       "true",
		},
		{
			name:       "boolean value length",
			val:        true,
			lengthFlag: true,
			want:       "4",
		},
		{
			name:       "slice value length",
			val:        []interface{}{"a", "b", "c"},
			lengthFlag: true,
			want:       "3",
		},
		{
			name:       "slice value JSON formatted",
			val:        []interface{}{"a", "b"},
			lengthFlag: false,
			want:       `["a","b"]`,
		},
		{
			name:       "map value length",
			val:        map[string]interface{}{"a": 1, "b": 2},
			lengthFlag: true,
			want:       "2",
		},
		{
			name:       "map value JSON formatted",
			val:        map[string]interface{}{"a": 1},
			lengthFlag: false,
			want:       `{"a":1}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := formatOutput(tt.val, tt.lengthFlag)
			if (err != nil) != tt.wantErr {
				t.Fatalf("formatOutput() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("formatOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRun(t *testing.T) {
	mockFiles := map[string][]byte{
		"file1.yaml": []byte("a:\n  b: value_b\n  c: [1, 2]\n"),
		"file2.yaml": []byte("a:\n  c: [3, 4]\n"),
	}

	mockReadFile := func(name string) ([]byte, error) {
		content, ok := mockFiles[name]
		if !ok {
			return nil, errors.New("file not found")
		}
		return content, nil
	}

	tests := []struct {
		name       string
		args       []string
		wantStdout string
		wantStderr string
		wantErr    bool
	}{
		{
			name:       "successful eval",
			args:       []string{"a.b", "file1.yaml"},
			wantStdout: "value_b\n",
		},
		{
			name:       "successful override and length",
			args:       []string{"-l", "a.c", "file1.yaml", "file2.yaml"},
			wantStdout: "2\n",
		},
		{
			name:    "file not found error",
			args:    []string{"a.b", "missing.yaml"},
			wantErr: true,
		},
		{
			name:    "arg parsing error",
			args:    []string{"a.b"},
			wantErr: true,
		},
		{
			name:    "invalid yaml format",
			args:    []string{"a.b", "file1.yaml"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rf func(string) ([]byte, error)
			if tt.name == "invalid yaml format" {
				rf = func(name string) ([]byte, error) {
					return []byte("invalid_yaml: : :"), nil
				}
			} else {
				rf = mockReadFile
			}

			var stdout bytes.Buffer
			var stderr bytes.Buffer

			err := run(tt.args, rf, &stdout, &stderr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if stdout.String() != tt.wantStdout {
					t.Errorf("run() stdout = %q, want %q", stdout.String(), tt.wantStdout)
				}
			}
		})
	}
}

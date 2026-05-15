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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"sigs.k8s.io/yaml"
)

type segment struct {
	key   string
	index *int
}

func parsePath(pathStr string) ([]segment, error) {
	if pathStr == "" {
		return nil, nil
	}
	parts := strings.Split(pathStr, ".")
	var segments []segment
	for _, part := range parts {
		if part == "" {
			continue
		}
		if strings.HasSuffix(part, "]") && strings.Contains(part, "[") {
			openIdx := strings.Index(part, "[")
			closeIdx := len(part) - 1
			idxStr := part[openIdx+1 : closeIdx]
			idx, err := strconv.Atoi(idxStr)
			if err != nil {
				return nil, fmt.Errorf("invalid array index %q: %w", idxStr, err)
			}
			segments = append(segments, segment{
				key:   part[:openIdx],
				index: &idx,
			})
		} else {
			segments = append(segments, segment{
				key: part,
			})
		}
	}
	return segments, nil
}

func merge(dst, src map[string]interface{}) {
	for k, v := range src {
		if dstVal, exists := dst[k]; exists {
			dstMap, okDst := dstVal.(map[string]interface{})
			srcMap, okSrc := v.(map[string]interface{})
			if okDst && okSrc {
				merge(dstMap, srcMap)
				continue
			}
		}
		dst[k] = v
	}
}

func evaluate(obj interface{}, segments []segment) (interface{}, error) {
	curr := obj
	for _, seg := range segments {
		if curr == nil {
			return nil, nil
		}
		m, ok := curr.(map[string]interface{})
		if !ok {
			return nil, nil
		}
		val, exists := m[seg.key]
		if !exists {
			return nil, nil
		}
		if seg.index != nil {
			slice, ok := val.([]interface{})
			if !ok {
				return nil, nil
			}
			idx := *seg.index
			if idx < 0 || idx >= len(slice) {
				return nil, nil
			}
			curr = slice[idx]
		} else {
			curr = val
		}
	}
	return curr, nil
}

func parseArgs(args []string) (path string, files []string, lengthFlag bool, err error) {
	var filteredArgs []string
	for _, arg := range args {
		if arg == "-l" || arg == "--length" {
			lengthFlag = true
		} else {
			filteredArgs = append(filteredArgs, arg)
		}
	}

	if len(filteredArgs) < 2 {
		return "", nil, false, fmt.Errorf("usage: get_val [-l] <path_expression> <yaml_file1> [<yaml_file2> ...]")
	}

	path = filteredArgs[0]
	files = filteredArgs[1:]
	return path, files, lengthFlag, nil
}

func mergeYAMLs(contents [][]byte) (map[string]interface{}, error) {
	var merged map[string]interface{}
	for i, content := range contents {
		var data map[string]interface{}
		if err := yaml.Unmarshal(content, &data); err != nil {
			return nil, fmt.Errorf("failed to parse YAML at index %d: %w", i, err)
		}
		if data == nil {
			continue
		}
		if merged == nil {
			merged = data
		} else {
			merge(merged, data)
		}
	}
	return merged, nil
}

func formatOutput(val interface{}, lengthFlag bool) (string, error) {
	if val == nil {
		return "", nil
	}

	if lengthFlag {
		switch v := val.(type) {
		case []interface{}:
			return fmt.Sprintf("%d", len(v)), nil
		case map[string]interface{}:
			return fmt.Sprintf("%d", len(v)), nil
		default:
			s := fmt.Sprintf("%v", v)
			return fmt.Sprintf("%d", len(s)), nil
		}
	}

	switch v := val.(type) {
	case string:
		return v, nil
	case bool, int, int64, float64:
		return fmt.Sprintf("%v", v), nil
	case []interface{}, map[string]interface{}:
		b, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("failed to marshal value: %w", err)
		}
		return string(b), nil
	default:
		return fmt.Sprintf("%v", v), nil
	}
}

func run(args []string, readFile func(string) ([]byte, error), stdout, stderr io.Writer) error {
	pathStr, files, lengthFlag, err := parseArgs(args)
	if err != nil {
		return err
	}

	var contents [][]byte
	for _, file := range files {
		content, err := readFile(file)
		if err != nil {
			return fmt.Errorf("failed to read file %q: %w", file, err)
		}
		contents = append(contents, content)
	}

	merged, err := mergeYAMLs(contents)
	if err != nil {
		return fmt.Errorf("failed to merge YAMLs: %w", err)
	}

	segments, err := parsePath(pathStr)
	if err != nil {
		return fmt.Errorf("failed to parse path %q: %w", pathStr, err)
	}

	val, err := evaluate(merged, segments)
	if err != nil {
		return fmt.Errorf("failed to evaluate path %q: %w", pathStr, err)
	}

	output, err := formatOutput(val, lengthFlag)
	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	if output != "" {
		fmt.Fprintln(stdout, output)
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.ReadFile, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

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

package gci

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestInstallableIntegrationTests(t *testing.T) {
	args := "python3 installable/installable_test.py InstallableTests"
	cmd := exec.Command("bash", "-c", args)

	result, err := cmd.CombinedOutput()
	if err != nil {
		printOutput(t, result)
		t.Fatalf("Failed to run %q: %v", cmd.Args, err)
	}
}

func TestAppPkgIntegrationTests(t *testing.T) {
	args := "python3 installable/installable_test.py AppPkgTests"
	cmd := exec.Command("bash", "-c", args)

	result, err := cmd.CombinedOutput()
	if err != nil {
		printOutput(t, result)
		t.Fatalf("Failed to run %q: %v", cmd.Args, err)
	}
}

func TestContainerIntegrationTests(t *testing.T) {
	// We use the "--fake" argument here to fake calls to "ctr" both because it isn't on the
	// container and because containerd cannot be reached.
	args := "python3 installable/installable_test.py --fake=True ContainerTests.test_parse"
	cmd := exec.Command("bash", "-c", args)

	result, err := cmd.CombinedOutput()
	if err != nil {
		printOutput(t, result)
		t.Fatalf("Failed to run %q: %v", cmd.Args, err)
	}
}

func TestBasicAppPkg(t *testing.T) {
	appPkg := installableSpec{
		kind:       "apppkg",
		name:       "npd",
		version:    "v0.8.13-57-gc3c5389",
		url:        "https://storage.googleapis.com/gke-release/node-problem-detector/node-problem-detector-v0.8.13-57-gc3c5389-linux_amd64.tar.gz",
		digest:     "2cb0f1610adb5d8d3c077d8ce7a65fb4066f419e82c3ed4ce72a7c4b337bcef7ab9e53d006d97bea70acd980565e2df80466858e6b5291cb1d10587bf0fb9d6c",
		digestAlgo: "SHA512",
	}
	spec, err := appPkg.makeSpec()
	if err != nil {
		t.Fatalf("failed to make spec: %v", err)
	}

	t.Logf("Testing preload workflow")

	preloadFile, err := os.CreateTemp("", "preload_info")
	if err != nil {
		t.Fatalf("failed to create preload file: %v", err)
	}
	defer os.Remove(preloadFile.Name())
	if err := preloadFile.Close(); err != nil {
		t.Fatalf("failed to close preload file: %v", err)
	}

	outFile, err := os.CreateTemp("", "installable")
	if err != nil {
		t.Fatalf("failed to create output file: %v", err)
	}
	defer os.Remove(outFile.Name())
	if err := outFile.Close(); err != nil {
		t.Fatalf("failed to close output file: %v", err)
	}

	args := fmt.Sprintf("python3 installable/installable.py -d -i '%s' -o %s -p %s", string(spec), outFile.Name(), preloadFile.Name())
	result, err := exec.Command("/bin/sh", "-c", args).CombinedOutput()
	if err != nil {
		printOutput(t, result)
		t.Fatalf("failed to run preload step: %v", err)
	}

	content, err := os.ReadFile(outFile.Name())
	if err != nil {
		t.Fatalf("failed to read content file: %v", err)
	}

	hash := sha512.New()
	if _, err := hash.Write(content); err != nil {
		t.Fatalf("failed to write hash: %v", err)
	}
	checksum := fmt.Sprintf("%x", hash.Sum(nil))

	if diff := cmp.Diff(checksum, appPkg.digest); diff != "" {
		t.Errorf("mismatch checksum: %s", diff)
	}

	content, err = os.ReadFile(preloadFile.Name())
	if err != nil {
		t.Fatalf("failed to read preload file: %v", err)
	}

	expected := fmt.Sprintf("%s,%s", appPkg.name, appPkg.digest)
	if !strings.Contains(string(content), expected) {
		t.Fatalf("could not find expected string %q in preload file: %q", expected, string(content))
	}

	t.Logf("Running boot workflow")
	args = fmt.Sprintf("python3 installable/installable.py -i '%s' -p %s", string(spec), preloadFile.Name())
	result, err = exec.Command("/bin/sh", "-c", args).CombinedOutput()
	if err != nil {
		printOutput(t, result)
		t.Fatalf("failed to run preload step: %v", err)
	}
}

type installableSpec struct {
	kind       string
	name       string
	version    string
	url        string
	digest     string
	digestAlgo string
}

func (i *installableSpec) makeSpec() ([]byte, error) {
	spec := map[string]any{
		"kind":       i.kind,
		"apiVersion": "installable.gke.io/v1",
		"metadata": map[string]string{
			"name": i.name,
		},
		"version":    i.version,
		"os":         "linux",
		"arch":       "x86",
		"remoteURL":  i.url,
		"digest":     i.digest,
		"digestAlgo": i.digestAlgo,
	}
	return json.Marshal(spec)
}

func printOutput(t *testing.T, result []byte) {
	t.Helper()
	t.Log("Results.....")
	for _, l := range strings.Split(string(result), "\n") {
		t.Log(l)
	}
}

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

// Package installable_test holds unit tests for the installable script. The tests use fakes
// to call key workflows to allow for the unit test jobs to be hermetic. This can also be
// run on local machines over slower integration tests which require COS machines.
package installable_test

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

const (
	testPath = "installable_test.py"
)

func TestGetMetadataTests(t *testing.T) {
	args := fmt.Sprintf("python3 %s --fake GetMetadataTests", testPath)
	cmd := exec.Command("bash", "-c", args)

	result, err := cmd.CombinedOutput()
	if err != nil {
		printOutput(t, result)
		t.Fatalf("Failed to run %q: %v", cmd.Args, err)
	}
}

func TestInstallableTests(t *testing.T) {
	args := fmt.Sprintf("python3 %s --fake InstallableTests", testPath)
	cmd := exec.Command("bash", "-c", args)

	result, err := cmd.CombinedOutput()
	if err != nil {
		printOutput(t, result)
		t.Fatalf("Failed to run %q: %v", cmd.Args, err)
	}
}

func TestInstallableContainerTests(t *testing.T) {
	args := fmt.Sprintf("python3 %s --fake ContainerTests", testPath)
	cmd := exec.Command("bash", "-c", args)

	result, err := cmd.CombinedOutput()
	if err != nil {
		printOutput(t, result)
		t.Fatalf("Failed to run %q: %v", cmd.Args, err)
	}
}

func TestInstallableAppPkgTests(t *testing.T) {
	args := fmt.Sprintf("python3 %s --fake AppPkgTests", testPath)
	cmd := exec.Command("bash", "-c", args)

	result, err := cmd.CombinedOutput()
	if err != nil {
		printOutput(t, result)
		t.Fatalf("Failed to run %q: %v", cmd.Args, err)
	}
}

func printOutput(t *testing.T, result []byte) {
	t.Helper()
	t.Log("Results.....")
	for _, l := range strings.Split(string(result), "\n") {
		t.Log(l)
	}
}

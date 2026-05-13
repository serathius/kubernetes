/*
Copyright 2026 The Kubernetes Authors.

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
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoEnvFlagsDirect(t *testing.T) {
	testCases := []struct {
		desc           string
		memoryLimit    string
		goMemLimit     string
		goGC           string
		wantGOMEMLIMIT string
		wantGOGC       string
	}{
		{
			desc:           "All vars set (bytes)",
			memoryLimit:    "1000000000",
			goMemLimit:     "80",
			goGC:           "90",
			wantGOMEMLIMIT: "800000000",
			wantGOGC:       "90",
		},
		{
			desc:           "All vars set (Ti)",
			memoryLimit:    "1Ti",
			goMemLimit:     "80",
			goGC:           "90",
			wantGOMEMLIMIT: "838860MiB",
			wantGOGC:       "90",
		},
		{
			desc:           "All vars set (Gi)",
			memoryLimit:    "10Gi",
			goMemLimit:     "80",
			goGC:           "90",
			wantGOMEMLIMIT: "8192MiB",
			wantGOGC:       "90",
		},
		{
			desc:           "Missing MEMORY_LIMIT",
			memoryLimit:    "",
			goMemLimit:     "80",
			goGC:           "90",
			wantGOMEMLIMIT: "",
			wantGOGC:       "90",
		},
		{
			desc:           "Missing GOMEMLIMIT",
			memoryLimit:    "1Ti",
			goMemLimit:     "",
			goGC:           "90",
			wantGOMEMLIMIT: "",
			wantGOGC:       "90",
		},
		{
			desc:           "Missing GOGC",
			memoryLimit:    "1Ti",
			goMemLimit:     "80",
			goGC:           "",
			wantGOMEMLIMIT: "838860MiB",
			wantGOGC:       "",
		},
		{
			desc:           "All missing",
			memoryLimit:    "",
			goMemLimit:     "",
			goGC:           "",
			wantGOMEMLIMIT: "",
			wantGOGC:       "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			d, err := ioutil.TempDir("", "goenv-test")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(d)

			// Create a mock script that sources configure-kubeapiserver.sh and calls start-kube-apiserver, but mocks out everything that needs root or external files.
			mockScript := filepath.Join(d, "test.sh")
			scriptContent := fmt.Sprintf(`
KUBE_HOME="%s"
mkdir -p "${KUBE_HOME}/etc/srv/kubernetes/kube-apiserver"
mkdir -p "${KUBE_HOME}/etc/srv/sshproxy"
mkdir -p "${KUBE_HOME}/etc/kubernetes/manifests"
mkdir -p "${KUBE_HOME}/var/log"
mkdir -p "${KUBE_HOME}/kube-manifests/kubernetes/gci-trusty"

# Mock functions to avoid root requirements
function mkdir {
  local args=("$@")
  local new_args=()
  for arg in "${args[@]}"; do
    if [[ "$arg" == "/etc/srv"* || "$arg" == "/var/log"* || "$arg" == "/etc/kubernetes"* ]]; then
      new_args+=("${KUBE_HOME}$arg")
    else
      new_args+=("$arg")
    fi
  done
  command mkdir "${new_args[@]}"
}
function chown { :; }
function chgrp { :; }
function chmod { :; }
function cp {
  local args=("$@")
  local new_args=()
  for arg in "${args[@]}"; do
    if [[ "$arg" == "/etc/srv"* || "$arg" == "/etc/kubernetes"* ]]; then
      new_args+=("${KUBE_HOME}$arg")
    else
      new_args+=("$arg")
    fi
  done
  command cp "${new_args[@]}"
}
function prepare-log-file { :; }
function configure-etcd-params { :; }
function setup-etcd-encryption { :; }
function convert-manifest-params { echo "$1"; }

# Mock manifest file
src_dir="${KUBE_HOME}/kube-manifests/kubernetes/gci-trusty"
src_file="${src_dir}/kube-apiserver.manifest"
cat << 'MANIFEST' > "${src_file}"
{
  "spec": {
    "containers": [
      {
        "name": "kube-apiserver",
        {{container_env}}
        "command": [ "/usr/local/bin/kube-apiserver", "{{params}}" ]
      }
    ]
  }
}
MANIFEST

# Mock docker tag file if needed, though sed might fail if it's not there and KUBE_API_SERVER_DOCKER_TAG is not set.
export KUBE_API_SERVER_DOCKER_TAG="v1.35.0"

# Set environment variables for the test
export KUBE_APISERVER_MEMORY_LIMIT="%s"
export KUBE_APISERVER_GOMEMLIMIT="%s"
export KUBE_APISERVER_GOGC="%s"
export KUBE_API_SERVER_RUNASUSER=$(id -u)
export ETC_MANIFESTS="${KUBE_HOME}/etc/kubernetes/manifests"

source configure-kubeapiserver.sh
start-kube-apiserver
`, d, tc.memoryLimit, tc.goMemLimit, tc.goGC)

			if err := ioutil.WriteFile(mockScript, []byte(scriptContent), 0755); err != nil {
				t.Fatalf("Failed to write mock script: %v", err)
			}

			cmd := exec.Command("bash", mockScript)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("Failed to run mock script: %v\nOutput:\n%s", err, out)
			}

			manifestPath := filepath.Join(d, "etc/kubernetes/manifests/kube-apiserver.manifest")
			content, err := ioutil.ReadFile(manifestPath)
			if err != nil {
				t.Fatalf("Failed to read generated manifest: %v", err)
			}
			manifestStr := string(content)

			// Check GOMEMLIMIT
			if tc.wantGOMEMLIMIT != "" {
				expectedEnv := fmt.Sprintf(`{"name": "GOMEMLIMIT", "value": "%s"}`, tc.wantGOMEMLIMIT)
				if !strings.Contains(manifestStr, expectedEnv) {
					t.Errorf("Manifest does not contain expected GOMEMLIMIT env %q.\nManifest content:\n%s", expectedEnv, manifestStr)
				}
			} else {
				if strings.Contains(manifestStr, `"name": "GOMEMLIMIT"`) {
					t.Errorf("Manifest unexpectedly contains GOMEMLIMIT.\nManifest content:\n%s", manifestStr)
				}
			}

			// Check GOGC
			if tc.wantGOGC != "" {
				expectedEnv := fmt.Sprintf(`{"name": "GOGC", "value": "%s"}`, tc.wantGOGC)
				if !strings.Contains(manifestStr, expectedEnv) {
					t.Errorf("Manifest does not contain expected GOGC env %q.\nManifest content:\n%s", expectedEnv, manifestStr)
				}
			} else {
				if strings.Contains(manifestStr, `"name": "GOGC"`) {
					t.Errorf("Manifest unexpectedly contains GOGC.\nManifest content:\n%s", manifestStr)
				}
			}
		})
	}
}

/*
Copyright 2024 Google

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
	"bufio"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

type testFlags struct {
	linuxScript     string
	windowsScript   string
	storageEndpoint string
	storageBucket   string
}

func (tf *testFlags) addFlags(fs *flag.FlagSet) {
	fs.StringVar(&tf.linuxScript, "configure-script-linux", "configure.sh", "path to linux configure.sh")
	fs.StringVar(&tf.windowsScript, "configure-script-windows", "../windows/k8s-node-setup.psm1", "path to windows configure script")
	fs.StringVar(&tf.storageEndpoint, "storage-endpoint", "https://storage.googleapis.com", "GCS endpoint")
	fs.StringVar(&tf.storageBucket, "storageBucket", "gke-prod-binaries", "storage bucket")
}

func verifyURL(t *testing.T, binurl, expectedSha512 string) error {
	t.Logf("verifying hash for %q", binurl)
	resp, err := http.Get(binurl)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected http status: %q", resp.Status)
	}

	h512 := sha512.New()
	if _, err := io.Copy(h512, resp.Body); err != nil {
		return err
	}

	actualSha512 := hex.EncodeToString(h512.Sum(nil))
	t.Logf("actual sha512 hash: %q", actualSha512)
	t.Logf("expected sha512 hash: %q", expectedSha512)
	if expectedSha512 != "" && actualSha512 != expectedSha512 {
		return fmt.Errorf("unexpected checksum for %q, got %q, want %q", binurl, actualSha512, expectedSha512)
	}
	return nil
}

var shellVarRegex = regexp.MustCompile(`(\w+)="(.+)"`)

func parseConfigure(t *testing.T, fname string) (map[string]string, error) {
	t.Helper()
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}

	m := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		match := shellVarRegex.FindStringSubmatch(s.Text())
		if match == nil {
			continue
		}

		if !strings.HasPrefix(match[1], "EXEC_AUTH_PLUGIN_") {
			continue
		}

		if len(match[1]) == 0 || len(match[2]) == 0 {
			return nil, fmt.Errorf("invalid empty var(match[1]) or value (match[2]), match: %#v", match)
		}

		m[match[1]] = match[2]
	}

	if len(m) == 0 {
		return nil, fmt.Errorf("shell var map cannot be empty")
	}

	j, _ := json.MarshalIndent(m, "", "  ")
	t.Logf("parseConfigure(%q):\n%s", fname, string(j))

	return m, nil
}

const (
	versionVarName          = "EXEC_AUTH_PLUGIN_VERSION"
	linuxAmd64HashVarName   = "EXEC_AUTH_PLUGIN_LINUX_AMD64_HASH"
	linuxArm64HashVarName   = "EXEC_AUTH_PLUGIN_LINUX_ARM64_HASH"
	windowsAmd64HashVarName = "EXEC_AUTH_PLUGIN_WINDOWS_AMD64_HASH"
)

func TestExecAuthPlugin(t *testing.T) {
	linuxVars, err := parseConfigure(t, defaultFlags.linuxScript)
	if err != nil {
		t.Fatalf("linux parseConfigure: %+v", err)
	}

	windowsVars, err := parseConfigure(t, defaultFlags.windowsScript)
	if err != nil {
		t.Fatalf("windows parseConfigure: %+v", err)
	}

	linuxVersion := linuxVars[versionVarName]
	windowsVersion := windowsVars[versionVarName]

	t.Run("verifying version matches across platforms", func(t *testing.T) {
		if linuxVersion == "" || windowsVersion == "" {
			t.Fatalf("linux or windows version is empty, linux=%q, windows=%q", linuxVersion, windowsVersion)
		}
		if linuxVersion != windowsVersion {
			t.Fatalf("plugin version mismatch: linux=%q != windows=%q", linuxVersion, windowsVersion)
		}
	})

	pluginVersion := linuxVersion

	testCases := []struct {
		platform string
		wantHash string
		filename string
	}{
		{
			platform: "linux_amd64",
			wantHash: linuxVars[linuxAmd64HashVarName],
			filename: "gke-exec-auth-plugin",
		},
		{
			platform: "linux_arm64",
			wantHash: linuxVars[linuxArm64HashVarName],
			filename: "gke-exec-auth-plugin",
		},
		{
			platform: "windows_amd64",
			wantHash: windowsVars[windowsAmd64HashVarName],
			filename: "gke-exec-auth-plugin.exe",
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("download/%s", tc.platform), func(t *testing.T) {
			urlPath := path.Join([]string{
				defaultFlags.storageBucket,
				"gke-exec-auth-plugin",
				pluginVersion,
				tc.platform,
			}...)
			pluginUrl := fmt.Sprintf("%s/%s/%s", defaultFlags.storageEndpoint, urlPath, tc.filename)
			if err := verifyURL(t, pluginUrl, tc.wantHash); err != nil {
				t.Fatalf("verifyURL failed: %v", err)
			}
		})
	}
}

var defaultFlags testFlags

func TestMain(m *testing.M) {
	tf := &defaultFlags
	tf.addFlags(flag.CommandLine)
	flag.Parse()

	os.Exit(m.Run())
}

/*
Copyright 2023 The Kubernetes Authors.

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

package cadvisor

import (
	"testing"

	cadvisorapi "github.com/google/cadvisor/info/v1"

	"github.com/stretchr/testify/assert"
)

func TestOverrideNodeCapacity(t *testing.T) {
	testCases := []struct {
		desc        string
		machineInfo *cadvisorapi.MachineInfo
		cpuOverride int
		expectedCpu int
	}{
		{
			desc: "no override",
			machineInfo: &cadvisorapi.MachineInfo{
				NumCores:       4,
				MemoryCapacity: 17179869184,
			},
			cpuOverride: 0,
			expectedCpu: 4,
		},
		{
			desc: "override cpu",
			machineInfo: &cadvisorapi.MachineInfo{
				NumCores:       4,
				MemoryCapacity: 17179869184,
			},
			cpuOverride: 32,
			expectedCpu: 32,
		},
	}
	for _, tc := range testCases {
		overrideNodeCapacity(tc.machineInfo, tc.cpuOverride)

		assert.Equal(t, tc.expectedCpu, tc.machineInfo.NumCores)
	}
}

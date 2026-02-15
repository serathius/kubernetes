/*
Copyright 2021 The Kubernetes Authors.

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

package v1

import (
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func TestPodSpecInterning(t *testing.T) {
	// Create a Pod with all interned fields populated
	pod := &Pod{
		Spec: PodSpec{
			RestartPolicy:            RestartPolicyAlways,
			DNSPolicy:                DNSClusterFirst,
			NodeSelector:             map[string]string{"key": "value"},
			ServiceAccountName:       "sa-name",
			DeprecatedServiceAccount: "dep-sa-name",
			NodeName:                 "node-name",
			Hostname:                 "hostname",
			Subdomain:                "subdomain",
			SchedulerName:            "scheduler",
			PriorityClassName:        "priority-class",
			RuntimeClassName:         func() *string { s := "runtime-class"; return &s }(),
			PreemptionPolicy:         func() *PreemptionPolicy { p := PreemptLowerPriority; return &p }(),
		},
	}

	data1, err := pod.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	data2, err := pod.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal twice to check if strings are interned (shared memory)
	p1 := &Pod{}
	if err := p1.Unmarshal(data1); err != nil {
		t.Fatalf("Failed to unmarshal p1: %v", err)
	}

	p2 := &Pod{}
	if err := p2.Unmarshal(data2); err != nil {
		t.Fatalf("Failed to unmarshal p2: %v", err)
	}

	sharesMemory := func(s1, s2 string) bool {
		return unsafe.StringData(s1) == unsafe.StringData(s2)
	}

	if !sharesMemory(string(p1.Spec.RestartPolicy), string(p2.Spec.RestartPolicy)) {
		t.Errorf("RestartPolicy not interned")
	}
	if !sharesMemory(string(p1.Spec.DNSPolicy), string(p2.Spec.DNSPolicy)) {
		t.Errorf("DNSPolicy not interned")
	}
	// Check NodeSelector key and value
	for k1, v1 := range p1.Spec.NodeSelector {
		found := false
		for k2, v2 := range p2.Spec.NodeSelector {
			if k1 == k2 {
				found = true
				if !sharesMemory(k1, k2) {
					t.Errorf("NodeSelector key not interned")
				}
				if !sharesMemory(v1, v2) {
					t.Errorf("NodeSelector value not interned")
				}
			}
		}
		if !found {
			t.Errorf("NodeSelector key %s not found in p2", k1)
		}
	}
	if !sharesMemory(p1.Spec.ServiceAccountName, p2.Spec.ServiceAccountName) {
		t.Errorf("ServiceAccountName not interned")
	}
	if !sharesMemory(p1.Spec.DeprecatedServiceAccount, p2.Spec.DeprecatedServiceAccount) {
		t.Errorf("DeprecatedServiceAccount not interned")
	}
	if !sharesMemory(p1.Spec.NodeName, p2.Spec.NodeName) {
		t.Errorf("NodeName not interned")
	}
	if !sharesMemory(p1.Spec.Hostname, p2.Spec.Hostname) {
		t.Errorf("Hostname not interned")
	}
	if !sharesMemory(p1.Spec.Subdomain, p2.Spec.Subdomain) {
		t.Errorf("Subdomain not interned")
	}
	if !sharesMemory(p1.Spec.SchedulerName, p2.Spec.SchedulerName) {
		t.Errorf("SchedulerName not interned")
	}
	if !sharesMemory(p1.Spec.PriorityClassName, p2.Spec.PriorityClassName) {
		t.Errorf("PriorityClassName not interned")
	}
	if p1.Spec.RuntimeClassName != nil && p2.Spec.RuntimeClassName != nil {
		if !sharesMemory(*p1.Spec.RuntimeClassName, *p2.Spec.RuntimeClassName) {
			t.Errorf("RuntimeClassName not interned")
		}
	}
	if p1.Spec.PreemptionPolicy != nil && p2.Spec.PreemptionPolicy != nil {
		if !sharesMemory(string(*p1.Spec.PreemptionPolicy), string(*p2.Spec.PreemptionPolicy)) {
			t.Errorf("PreemptionPolicy not interned")
		}
	}
}

// Test_ServiceSpecRemovedFieldProtobufNumberReservation tests that the reserved protobuf field numbers
// for removed fields are not re-used. DO NOT remove this test for any reason, this ensures that tombstoned
// protobuf field numbers are not accidentally reused by other fields.
func Test_ServiceSpecRemovedFieldProtobufNumberReservation(t *testing.T) {
	obj := reflect.ValueOf(ServiceSpec{}).Type()
	for i := 0; i < obj.NumField(); i++ {
		f := obj.Field(i)

		protobufNum := strings.Split(f.Tag.Get("protobuf"), ",")[1]
		if protobufNum == "15" {
			t.Errorf("protobuf 15 in ServiceSpec is reserved for removed ipFamily field")
		}
		if protobufNum == "16" {
			t.Errorf("protobuf 16 in ServiceSpec is reserved for removed topologyKeys field")
		}
	}
}

// TestEphemeralContainer ensures that the tags of Container and EphemeralContainerCommon are kept in sync.
func TestEphemeralContainer(t *testing.T) {
	ephemeralType := reflect.TypeOf(EphemeralContainerCommon{})
	containerType := reflect.TypeOf(Container{})

	ephemeralFields := ephemeralType.NumField()
	containerFields := containerType.NumField()
	if containerFields != ephemeralFields {
		t.Fatalf("%v has %d fields, %v has %d fields", ephemeralType, ephemeralFields, containerType, containerFields)
	}
	for i := 0; i < ephemeralFields; i++ {
		ephemeralField := ephemeralType.Field(i)
		containerField := containerType.Field(i)
		if !reflect.DeepEqual(ephemeralField, containerField) {
			t.Errorf("field %v differs:\n\t%#v\n\t%#v", ephemeralField.Name, ephemeralField, containerField)
		}
	}
}

func TestNoBindingDeprecation(t *testing.T) {
	var binding any = new(Binding)
	if _, ok := binding.(interface {
		APILifecycleDeprecated(major, minor int)
	}); ok {
		t.Fatal("The Binding type must not marked as deprecated, it is still used for the binding sub-resource which is not deprecated.")
	}
}

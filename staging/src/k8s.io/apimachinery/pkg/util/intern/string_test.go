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

package intern

import (
	"testing"
	"unsafe"
)

func TestInternStrings(t *testing.T) {
	// Helper to check if two strings share the same backing array
	sharesMemory := func(s1, s2 string) bool {
		return unsafe.StringData(s1) == unsafe.StringData(s2)
	}

	t.Run("InternsStringsInStruct", func(t *testing.T) {
		// Ensure they are different memory initially
		b1 := []byte("test-string-struct")
		b2 := []byte("test-string-struct")
		s1 := string(b1)
		s2 := string(b2)

		if sharesMemory(s1, s2) {
			t.Errorf("Compiler already interned these strings, cannot test interning")
		}

		type MyStruct struct {
			Name  string
			Label string
		}

		obj := &MyStruct{
			Name:  s1,
			Label: s2,
		}

		InternObjectStrings(obj)

		if !sharesMemory(obj.Name, obj.Label) {
			t.Errorf("Expected Name and Label to share memory after interning")
		}
	})

	t.Run("InternsMapKeys", func(t *testing.T) {
		k1 := string([]byte("key1"))
		
		m := map[string]string{
			k1: "value",
		}
		
		InternObjectStrings(m)
		
		for k := range m {
			// We can't easily check against another string without interning that one too,
			// but we can check if it's stable.
			// Ideally we'd check if it matches a known interned string.
			_ = k
		}
	})
	
	t.Run("InternsSlice", func(t *testing.T) {
		s1 := string([]byte("item1"))
		s2 := string([]byte("item1"))
		
		slice := []string{s1, s2}
		
		InternObjectStrings(slice)
		
		if !sharesMemory(slice[0], slice[1]) {
			t.Errorf("Expected slice elements to share memory")
		}
	})
	
	t.Run("InternsInterface", func(t *testing.T) {
		s1 := string([]byte("val1"))
		
		type MyStruct struct {
			Field interface{}
		}
		
		obj := &MyStruct{
			Field: s1,
		}
		
		InternObjectStrings(obj)
		
		if obj.Field.(string) != "val1" {
			t.Errorf("Expected value to be preserved")
		}
	})

	t.Run("InternsMapWithNamedStringType", func(t *testing.T) {
		type ResourceName string
		k1 := "key1"
		v1 := ResourceName("value1")
		
		m := map[string]ResourceName{
			k1: v1,
		}
		
		InternObjectStrings(m)
		
		if m[k1] != v1 {
			t.Errorf("Expected value to be preserved")
		}
	})

	t.Run("InternsInterfaceWithNamedStringType", func(t *testing.T) {
		type ResourceName string
		v1 := ResourceName("value1")
		
		type MyStruct struct {
			Field interface{}
		}
		
		obj := &MyStruct{
			Field: v1,
		}
		
		InternObjectStrings(obj)
		
		if _, ok := obj.Field.(ResourceName); !ok {
			t.Errorf("Expected Field to still be ResourceName, got %T", obj.Field)
		}
		if obj.Field.(ResourceName) != v1 {
			t.Errorf("Expected value to be preserved")
		}
	})

	t.Run("InternsNamedStringTypeMemory", func(t *testing.T) {
		type MyString1 string
		type MyString2 string
		b1 := []byte("test-named-string")
		b2 := []byte("test-named-string")
		s1 := MyString1(b1)
		s2 := MyString2(b2)

		if sharesMemory(string(s1), string(s2)) {
			t.Errorf("Compiler already interned these strings")
		}

		type Container struct {
			A MyString1
			B MyString2
		}
		c := &Container{A: s1, B: s2}

		InternObjectStrings(c)

		if !sharesMemory(string(c.A), string(c.B)) {
			t.Errorf("Expected named strings to share memory after interning")
		}
	})
}

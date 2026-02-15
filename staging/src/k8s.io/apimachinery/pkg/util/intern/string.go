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
	"reflect"
	"unique"

	"k8s.io/component-base/featuregate/testing"
)


var enableInternObjectStrings = true

func SetInternObjectStrings(tb testing.TB, new bool) {
	old := enableInternObjectStrings
	tb.Cleanup(func() {
		enableInternObjectStrings = old
	})
	enableInternObjectStrings = new
}

func InternObjectStrings(obj interface{}) {
	if !enableInternObjectStrings {
		return
	}
	if obj == nil {
		return
	}
	v := reflect.ValueOf(obj)
	internValue(v)
}

func internValue(v reflect.Value) {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return
		}
		internValue(v.Elem())
	case reflect.Interface:
		if v.IsNil() {
			return
		}
		elem := v.Elem()
		if elem.Kind() == reflect.String {
			if v.CanSet() {
				s := elem.String()
				if len(s) > 0 {
					v.Set(reflect.ValueOf(unique.Make(s).Value()).Convert(elem.Type()))
				}
			}
		} else {
			internValue(elem)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			internValue(v.Field(i))
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			internValue(v.Index(i))
		}
	case reflect.Map:
		if v.IsNil() || v.Len() == 0 {
			return
		}

		// We need to collect updates to avoid modifying the map while iterating
		type mapUpdate struct {
			key    reflect.Value
			newKey reflect.Value
			val    reflect.Value
			newVal reflect.Value
			delete bool
		}
		var updates []mapUpdate

		iter := v.MapRange()
		for iter.Next() {
			key := iter.Key()
			val := iter.Value()

			var newKey, newVal reflect.Value
			keyChanged := false
			valChanged := false

			// Handle Key
			if key.Kind() == reflect.String {
				s := key.String()
				if len(s) > 0 {
					interned := unique.Make(s).Value()
					newKey = reflect.ValueOf(interned).Convert(key.Type())
					keyChanged = true
				}
			}

			// Handle Value
			if val.Kind() == reflect.String {
				s := val.String()
				if len(s) > 0 {
					interned := unique.Make(s).Value()
					newVal = reflect.ValueOf(interned).Convert(val.Type())
					valChanged = true
				}
			} else if val.Kind() == reflect.Interface || val.Kind() == reflect.Ptr || val.Kind() == reflect.Slice || val.Kind() == reflect.Map || val.Kind() == reflect.Struct {
				// We need to recurse.
				if val.Kind() == reflect.Ptr {
					// Pointer in map value: just recurse
					internValue(val)
				} else {
					// Value in map: copy, recurse, set back
					// We need to create a new addressable copy
					copyVal := reflect.New(val.Type()).Elem()
					copyVal.Set(val)
					internValue(copyVal)
					newVal = copyVal
					valChanged = true
				}
			}

			if keyChanged || valChanged {
				u := mapUpdate{key: key}
				if keyChanged {
					u.newKey = newKey
					u.delete = true // We need to delete old key if key changed
				} else {
					u.newKey = key
				}

				if valChanged {
					u.newVal = newVal
				} else {
					u.newVal = val
				}
				updates = append(updates, u)
			}
		}

		for _, u := range updates {
			if u.delete {
				v.SetMapIndex(u.key, reflect.Value{})
			}
			v.SetMapIndex(u.newKey, u.newVal)
		}

	case reflect.String:
		if v.CanSet() {
			s := v.String()
			if len(s) > 0 {
				v.SetString(unique.Make(s).Value())
			}
		}
	}
}

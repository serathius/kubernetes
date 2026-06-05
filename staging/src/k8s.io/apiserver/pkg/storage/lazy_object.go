/*
Copyright The Kubernetes Authors.

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

package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)


// LazyObject is implemented by wrappers that store serialized bytes and only
// decode the full structure on demand.
type LazyObject interface {
	Decode() (runtime.Object, error)
}

// DecodeLazyObject decodes the object if it implements LazyObject.
func DecodeLazyObject(obj runtime.Object) (runtime.Object, error) {
	if lazy, ok := obj.(LazyObject); ok {
		return lazy.Decode()
	}
	return obj, nil
}

// PanicOnLazyDecode is used in tests to assert that lazy decoding was triggered.
var PanicOnLazyDecode bool

type extractedPodAttrs struct {
	nodeName           string
	restartPolicy      string
	schedulerName      string
	serviceAccountName string
	hostNetwork        bool
	phase              string
	nominatedNodeName  string
	podIPs             []string
}

type lazyObjectWrapper struct {
	metav1.Object

	codec          runtime.Codec
	versioner      Versioner
	data           []byte
	rev            int64
	underlyingType reflect.Type

	podAttrs *extractedPodAttrs

	once    sync.Once
	fullObj runtime.Object
	err     error
}

var _ runtime.Object = &lazyObjectWrapper{}
var _ runtime.TypedObject = &lazyObjectWrapper{}
var _ LazyObject = &lazyObjectWrapper{}

func NewLazyObjectWrapper(codec runtime.Codec, versioner Versioner, data []byte, rev int64, underlyingType reflect.Type) (runtime.Object, error) {
	meta, err := decodeMetadata(data)
	if err != nil {
		return nil, err
	}
	if err := versioner.UpdateObject(meta, uint64(rev)); err != nil {
		return nil, fmt.Errorf("failure to version api object metadata (%d) %#v: %v", rev, meta, err)
	}

	isPod := false
	if underlyingType != nil {
		t := underlyingType
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		if t.Kind() == reflect.Struct && t.Name() == "Pod" {
			isPod = true
		}
	}

	var podAttrs *extractedPodAttrs
	if isPod {
		attrs, err := extractPodAttrs(data)
		if err != nil {
			return nil, fmt.Errorf("failed to extract pod attributes: %v", err)
		}
		podAttrs = attrs
	}

	return &lazyObjectWrapper{
		Object:         meta,
		codec:          codec,
		versioner:      versioner,
		data:           data,
		rev:            rev,
		underlyingType: underlyingType,
		podAttrs:       podAttrs,
	}, nil
}


func decodeMetadata(data []byte) (*metav1.PartialObjectMetadata, error) {
	if bytes.HasPrefix(data, []byte{0x6b, 0x38, 0x73, 0x00}) {
		unk := &runtime.Unknown{}
		if err := unk.Unmarshal(data[4:]); err != nil {
			return nil, err
		}
		meta := &metav1.PartialObjectMetadata{}
		if err := meta.Unmarshal(unk.Raw); err != nil {
			return nil, err
		}
		return meta, nil
	}

	meta := &metav1.PartialObjectMetadata{}
	if err := json.Unmarshal(data, meta); err != nil {
		return nil, err
	}
	return meta, nil
}

func (l *lazyObjectWrapper) GetObjectKind() schema.ObjectKind {
	return l.Object.(runtime.Object).GetObjectKind()
}

func (l *lazyObjectWrapper) GetUnderlyingType() reflect.Type {
	return l.underlyingType
}

func (l *lazyObjectWrapper) DeepCopyObject() runtime.Object {
	full, err := l.Decode()
	if err != nil {
		panic(fmt.Sprintf("failed to decode lazy object during DeepCopyObject: %v", err))
	}
	return full.DeepCopyObject()
}

func (l *lazyObjectWrapper) Decode() (runtime.Object, error) {
	l.once.Do(func() {
		if PanicOnLazyDecode {
			panic("lazy decoding triggered")
		}
		obj, err := runtime.Decode(l.codec, l.data)
		if err != nil {
			l.err = err
			return
		}
		if err := l.versioner.UpdateObject(obj, uint64(l.rev)); err != nil {
			l.err = err
			return
		}
		l.fullObj = obj
	})
	return l.fullObj, l.err
}

func extractPodAttrs(data []byte) (*extractedPodAttrs, error) {
	if bytes.HasPrefix(data, []byte{0x6b, 0x38, 0x73, 0x00}) {
		unk := &runtime.Unknown{}
		if err := unk.Unmarshal(data[4:]); err != nil {
			return nil, err
		}
		return extractAttrsFromPodProto(unk.Raw)
	}
	return extractAttrsFromPodJSON(data)
}

func readVarint(data []byte) (uint64, int) {
	var val uint64
	var shift uint
	for i, b := range data {
		val |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return val, i + 1
		}
		shift += 7
	}
	return 0, 0
}

func skipField(wireType uint64, data []byte) int {
	switch wireType {
	case 0: // varint
		_, n := readVarint(data)
		return n
	case 1: // 64-bit
		return 8
	case 2: // length-delimited
		length, n := readVarint(data)
		return n + int(length)
	case 5: // 32-bit
		return 4
	default:
		return 0
	}
}

func extractAttrsFromPodProto(data []byte) (*extractedPodAttrs, error) {
	attrs := &extractedPodAttrs{}
	idx := 0
	for idx < len(data) {
		key, n := readVarint(data[idx:])
		if n == 0 {
			return nil, fmt.Errorf("invalid proto data")
		}
		idx += n
		fieldNum := key >> 3
		wireType := key & 0x7
		if fieldNum == 2 && wireType == 2 { // Spec field
			specLen, n := readVarint(data[idx:])
			if n == 0 {
				return nil, fmt.Errorf("invalid spec length")
			}
			idx += n
			specEnd := idx + int(specLen)
			for idx < specEnd {
				specKey, sn := readVarint(data[idx:])
				if sn == 0 {
					return nil, fmt.Errorf("invalid spec field key")
				}
				idx += sn
				specFieldNum := specKey >> 3
				specWireType := specKey & 0x7
				switch specFieldNum {
				case 10: // nodeName
					if specWireType == 2 {
						nameLen, ssn := readVarint(data[idx:])
						idx += ssn
						attrs.nodeName = string(data[idx : idx+int(nameLen)])
						idx += int(nameLen)
					}
				case 3: // restartPolicy
					if specWireType == 2 {
						rpLen, ssn := readVarint(data[idx:])
						idx += ssn
						attrs.restartPolicy = string(data[idx : idx+int(rpLen)])
						idx += int(rpLen)
					}
				case 19: // schedulerName
					if specWireType == 2 {
						snLen, ssn := readVarint(data[idx:])
						idx += ssn
						attrs.schedulerName = string(data[idx : idx+int(snLen)])
						idx += int(snLen)
					}
				case 8: // serviceAccountName
					if specWireType == 2 {
						saLen, ssn := readVarint(data[idx:])
						idx += ssn
						attrs.serviceAccountName = string(data[idx : idx+int(saLen)])
						idx += int(saLen)
					}
				case 11: // hostNetwork
					if specWireType == 0 {
						val, ssn := readVarint(data[idx:])
						idx += ssn
						attrs.hostNetwork = val != 0
					}
				default:
					skipLen := skipField(specWireType, data[idx:])
					idx += skipLen
				}
			}
		} else if fieldNum == 3 && wireType == 2 { // Status field
			statusLen, n := readVarint(data[idx:])
			idx += n
			statusEnd := idx + int(statusLen)
			for idx < statusEnd {
				statusKey, sn := readVarint(data[idx:])
				idx += sn
				statusFieldNum := statusKey >> 3
				statusWireType := statusKey & 0x7
				switch statusFieldNum {
				case 1: // phase
					if statusWireType == 2 {
						phaseLen, ssn := readVarint(data[idx:])
						idx += ssn
						attrs.phase = string(data[idx : idx+int(phaseLen)])
						idx += int(phaseLen)
					}
				case 11: // nominatedNodeName
					if statusWireType == 2 {
						nnLen, ssn := readVarint(data[idx:])
						idx += ssn
						attrs.nominatedNodeName = string(data[idx : idx+int(nnLen)])
						idx += int(nnLen)
					}
				case 12: // podIPs
					if statusWireType == 2 {
						ipLen, ssn := readVarint(data[idx:])
						idx += ssn
						ipEnd := idx + int(ipLen)
						for idx < ipEnd {
							ipKey, ipn := readVarint(data[idx:])
							idx += ipn
							ipFieldNum := ipKey >> 3
							ipWireType := ipKey & 0x7
							if ipFieldNum == 1 && ipWireType == 2 { // ip
								ipStrLen, ipssn := readVarint(data[idx:])
								idx += ipssn
								attrs.podIPs = append(attrs.podIPs, string(data[idx:idx+int(ipStrLen)]))
								idx += int(ipStrLen)
							} else {
								skipLen := skipField(ipWireType, data[idx:])
								idx += skipLen
							}
						}
					}
				default:
					skipLen := skipField(statusWireType, data[idx:])
					idx += skipLen
				}
			}
		} else {
			skipLen := skipField(wireType, data[idx:])
			idx += skipLen
		}
	}
	return attrs, nil
}

type podSpecSubset struct {
	Spec struct {
		NodeName           string `json:"nodeName,omitempty"`
		RestartPolicy      string `json:"restartPolicy,omitempty"`
		SchedulerName      string `json:"schedulerName,omitempty"`
		ServiceAccountName string `json:"serviceAccountName,omitempty"`
		HostNetwork        bool   `json:"hostNetwork,omitempty"`
	} `json:"spec,omitempty"`
	Status struct {
		Phase             string `json:"phase,omitempty"`
		NominatedNodeName string `json:"nominatedNodeName,omitempty"`
		PodIPs            []struct {
			IP string `json:"ip,omitempty"`
		} `json:"podIPs,omitempty"`
	} `json:"status,omitempty"`
}

func extractAttrsFromPodJSON(data []byte) (*extractedPodAttrs, error) {
	pod := &podSpecSubset{}
	if err := json.Unmarshal(data, pod); err != nil {
		return nil, err
	}
	attrs := &extractedPodAttrs{
		nodeName:           pod.Spec.NodeName,
		restartPolicy:      pod.Spec.RestartPolicy,
		schedulerName:      pod.Spec.SchedulerName,
		serviceAccountName: pod.Spec.ServiceAccountName,
		hostNetwork:        pod.Spec.HostNetwork,
		phase:              pod.Status.Phase,
		nominatedNodeName:  pod.Status.NominatedNodeName,
	}
	for _, ip := range pod.Status.PodIPs {
		attrs.podIPs = append(attrs.podIPs, ip.IP)
	}
	return attrs, nil
}

func GetPodAttrsFromLazyObject(obj runtime.Object) (labels.Set, fields.Set, bool) {
	lazy, ok := obj.(*lazyObjectWrapper)
	if !ok || lazy.podAttrs == nil {
		return nil, nil, false
	}
	attrs := lazy.podAttrs

	podSpecificFieldsSet := make(fields.Set, 10)
	podSpecificFieldsSet["spec.nodeName"] = attrs.nodeName
	podSpecificFieldsSet["spec.restartPolicy"] = attrs.restartPolicy
	podSpecificFieldsSet["spec.schedulerName"] = attrs.schedulerName
	podSpecificFieldsSet["spec.serviceAccountName"] = attrs.serviceAccountName
	podSpecificFieldsSet["spec.hostNetwork"] = strconv.FormatBool(attrs.hostNetwork)
	podSpecificFieldsSet["status.phase"] = attrs.phase

	podIP := ""
	if len(attrs.podIPs) > 0 {
		podIP = attrs.podIPs[0]
	}
	podSpecificFieldsSet["status.podIP"] = podIP
	podSpecificFieldsSet["status.nominatedNodeName"] = attrs.nominatedNodeName

	podSpecificFieldsSet["metadata.name"] = lazy.GetName()
	podSpecificFieldsSet["metadata.namespace"] = lazy.GetNamespace()

	return labels.Set(lazy.GetLabels()), podSpecificFieldsSet, true
}

// PodAttrsGetter can be implemented by lazy wrappers to expose pod attributes
// without triggering full deserialization.
type PodAttrsGetter interface {
	GetPodAttrs() (nodeName string, restartPolicy string, schedulerName string, serviceAccountName string, hostNetwork bool, phase string, nominatedNodeName string, podIPs []string, ok bool)
}

func (l *lazyObjectWrapper) GetPodAttrs() (string, string, string, string, bool, string, string, []string, bool) {
	if l.podAttrs == nil {
		return "", "", "", "", false, "", "", nil, false
	}
	a := l.podAttrs
	return a.nodeName, a.restartPolicy, a.schedulerName, a.serviceAccountName, a.hostNetwork, a.phase, a.nominatedNodeName, a.podIPs, true
}



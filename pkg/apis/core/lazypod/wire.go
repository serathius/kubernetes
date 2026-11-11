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

package lazypod

import (
	"fmt"
	"strings"
	"unsafe"

	"google.golang.org/protobuf/encoding/protowire"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf/lazy"
	"k8s.io/kubernetes/pkg/apis/core"
	corev1 "k8s.io/kubernetes/pkg/apis/core/v1"
)

// Protobuf wire field numbers for v1.Pod, v1.PodSpec, v1.PodStatus, and nested messages.
const (
	podFieldMetadata = 1
	podFieldSpec     = 2
	podFieldStatus   = 3

	specFieldVolumes                       = 1
	specFieldContainers                    = 2
	specFieldRestartPolicy                 = 3
	specFieldTerminationGracePeriodSeconds = 4
	specFieldActiveDeadlineSeconds         = 5
	specFieldDNSPolicy                     = 6
	specFieldServiceAccountName            = 8
	specFieldDeprecatedServiceAccount      = 9
	specFieldNodeName                      = 10
	specFieldHostNetwork                   = 11
	specFieldSecurityContext               = 14
	specFieldSchedulerName                 = 19
	specFieldInitContainers                = 20
	specFieldTolerations                   = 22
	specFieldReadinessGates                = 28
	specFieldEnableServiceLinks            = 30
	specFieldEphemeralContainers           = 34
	specFieldSchedulingGates               = 38
	specFieldOS                            = 39

	statusFieldPhase                 = 1
	statusFieldConditions            = 2
	statusFieldReason                = 4
	statusFieldHostIP                = 5
	statusFieldPodIP                 = 6
	statusFieldContainerStatuses     = 8
	statusFieldQOSClass              = 9
	statusFieldInitContainerStatuses = 10
	statusFieldNominatedNodeName     = 11
	statusFieldPodIPs                = 12
	statusFieldHostIPs               = 16

	podIPFieldIP  = 1
	hostIPFieldIP = 1

	containerFieldName                     = 1
	containerFieldImage                    = 2
	containerFieldPorts                    = 6
	containerFieldResources                = 8
	containerFieldTerminationMessagePath   = 13
	containerFieldImagePullPolicy          = 14
	containerFieldTerminationMessagePolicy = 20
	containerFieldRestartPolicy            = 24

	portFieldHostPort      = 2
	portFieldContainerPort = 3
	portFieldProtocol      = 4

	resFieldLimits   = 1
	resFieldRequests = 2

	volumeFieldSource             = 2
	volumeSourceFieldHostPath     = 1
	volumeSourceFieldEmptyDir     = 2
	volumeSourceFieldSecret       = 6
	volumeSourceFieldDownwardAPI  = 16
	volumeSourceFieldConfigMap    = 19
	volumeSourceFieldProjected    = 26
	hostPathFieldType             = 2
	secretFieldDefaultMode        = 3
	downwardFieldDefaultMode      = 2
	configMapFieldDefaultMode     = 3
	projectedFieldSources         = 1
	projectedFieldDefaultMode     = 2
	volProjectionFieldDownwardAPI = 2
	downwardProjFieldItems        = 1
	downwardFileFieldMode         = 4

	osFieldName = 1

	csFieldName         = 1
	csFieldState        = 2
	csFieldLastState    = 3
	csFieldReady        = 4
	csFieldRestartCount = 5
	csFieldStarted      = 9
)

// WirePod wraps raw Protobuf-encoded v1.Pod bytes and provides lazy, on-demand extraction
// of ObjectMeta, Spec, and Status fields alongside wire-level defaulting and splicing.
//
// +k8s:deepcopy-gen=false
type WirePod struct {
	raw  []byte
	meta lazy.WireObjectMeta

	specBytes   []byte
	statusBytes []byte

	nodeName            string
	hasNodeNameMod      bool
	nominatedNodeName   string
	hasNominatedNodeMod bool

	hasConditionsMod  bool
	statusEmptySlices uint8
	conditionsEncoded []byte
	cachedStatus      *v1.PodStatus

	defaults *wireDefaultPlan
}

const (
	statusEmptyResourceClaimStatuses uint8 = 1 << iota
	statusEmptyNodeAllocatableClaimStatuses
)

func scanPodTopLevel(raw []byte) (metaBytes, specBytes, statusBytes []byte) {
	offset := 0
	for offset < len(raw) {
		num, typ, tagLen := protowire.ConsumeTag(raw[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, raw[offset:])
		if valLen < 0 {
			break
		}
		if typ == protowire.BytesType {
			content, _ := protowire.ConsumeBytes(raw[offset : offset+valLen])
			switch num {
			case podFieldMetadata:
				metaBytes = content
			case podFieldSpec:
				specBytes = content
			case podFieldStatus:
				statusBytes = content
			}
		}
		offset += valLen
	}
	return metaBytes, specBytes, statusBytes
}

// NewWirePod creates a WirePod over raw v1.Pod Protobuf bytes (without the k8s\x00 magic prefix).
func NewWirePod(raw []byte) *WirePod {
	w := &WirePod{raw: raw}
	metaBytes, specBytes, statusBytes := scanPodTopLevel(raw)
	w.specBytes = specBytes
	w.statusBytes = statusBytes
	w.meta.InitFromParentWithBytes(raw, metaBytes, podFieldMetadata)
	return w
}

// Clone returns a copy of WirePod suitable for DeepCopy without decoding into a Go struct.
// Because w.raw, w.specBytes, and w.statusBytes are never mutated in place, clones share the
// immutable backing wire slice while cloning mutable override state.
func (w *WirePod) Clone() *WirePod {
	if w == nil {
		return nil
	}
	cp := &WirePod{
		raw:                 w.raw,
		meta:                w.meta.Clone(),
		specBytes:           w.specBytes,
		statusBytes:         w.statusBytes,
		nodeName:            w.nodeName,
		hasNodeNameMod:      w.hasNodeNameMod,
		nominatedNodeName:   w.nominatedNodeName,
		hasNominatedNodeMod: w.hasNominatedNodeMod,
		hasConditionsMod:    w.hasConditionsMod,
		statusEmptySlices:   w.statusEmptySlices,
		cachedStatus:        w.cachedStatus,
		defaults:            w.defaults.clone(),
	}
	if w.hasConditionsMod && w.conditionsEncoded != nil {
		cp.conditionsEncoded = append([]byte(nil), w.conditionsEncoded...)
	}
	return cp
}

// Reset clears the WirePod and reinitializes it over raw.
func (w *WirePod) Reset(raw []byte) {
	metaBytes, specBytes, statusBytes := scanPodTopLevel(raw)
	*w = WirePod{
		raw:         raw,
		specBytes:   specBytes,
		statusBytes: statusBytes,
	}
	w.meta.InitFromParentWithBytes(raw, metaBytes, podFieldMetadata)
}

func (w *WirePod) subMessage(topField protowire.Number) []byte {
	switch topField {
	case podFieldSpec:
		return w.specBytes
	case podFieldStatus:
		return w.statusBytes
	default:
		return lazy.SubMessage(w.raw, topField)
	}
}

// EffectiveSubMessage returns the current wire bytes for topField (1=metadata, 2=spec, 3=status),
// splicing any pending defaults or lazy modifications for that section.
func (w *WirePod) EffectiveSubMessage(topField protowire.Number) []byte {
	if w == nil {
		return nil
	}
	if topField == podFieldMetadata {
		if !w.meta.IsDirty() {
			return w.meta.Bytes()
		}
		return w.meta.SpliceMetaFields(w.meta.Bytes())
	}
	base := w.subMessage(topField)
	if topField == podFieldSpec {
		if w.defaults != nil && w.defaults.specDirty {
			base = w.spliceSpecDefaults(base)
		}
		if w.hasNodeNameMod {
			base = spliceSingleStringField(base, specFieldNodeName, w.nodeName)
		}
		return base
	}
	if topField == podFieldStatus {
		if w.defaults != nil && w.defaults.statusDirty {
			base = w.spliceStatusDefaults(base)
		}
		if w.hasNominatedNodeMod {
			base = spliceSingleStringField(base, statusFieldNominatedNodeName, w.nominatedNodeName)
		}
		if w.hasConditionsMod {
			base = spliceRepeatedRawField(base, statusFieldConditions, w.conditionsEncoded)
		}
		return base
	}
	return base
}

func spliceSingleStringField(msgBytes []byte, targetNum protowire.Number, val string) []byte {
	out := make([]byte, 0, len(msgBytes)+len(val)+8)
	emitted := false
	offset := 0
	for offset < len(msgBytes) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(msgBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, msgBytes[offset:])
		if valLen < 0 {
			break
		}
		offset += valLen

		if !emitted && num >= targetNum {
			if val != "" {
				out = protowire.AppendTag(out, targetNum, protowire.BytesType)
				out = protowire.AppendString(out, val)
			}
			emitted = true
		}
		if num == targetNum {
			continue
		}
		out = append(out, msgBytes[fieldStart:offset]...)
	}
	if !emitted && val != "" {
		out = protowire.AppendTag(out, targetNum, protowire.BytesType)
		out = protowire.AppendString(out, val)
	}
	return out
}

func spliceRepeatedRawField(msgBytes []byte, targetNum protowire.Number, encoded []byte) []byte {
	out := make([]byte, 0, len(msgBytes)+len(encoded)+8)
	emitted := false
	offset := 0
	for offset < len(msgBytes) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(msgBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, msgBytes[offset:])
		if valLen < 0 {
			break
		}
		offset += valLen

		if !emitted && num >= targetNum {
			out = append(out, encoded...)
			emitted = true
		}
		if num == targetNum {
			continue
		}
		out = append(out, msgBytes[fieldStart:offset]...)
	}
	if !emitted {
		out = append(out, encoded...)
	}
	return out
}

// NodeName extracts spec.nodeName from the wire.
func (w *WirePod) NodeName() string {
	if w.hasNodeNameMod {
		return w.nodeName
	}
	return lazy.ExtractFirstStringField(w.subMessage(podFieldSpec), specFieldNodeName)
}

// SetNodeName updates spec.nodeName on the wire without decoding the pod.
func (w *WirePod) SetNodeName(n string) {
	w.nodeName = n
	w.hasNodeNameMod = true
}

// Phase extracts status.phase from the wire.
func (w *WirePod) Phase() core.PodPhase {
	return core.PodPhase(lazy.ExtractFirstStringField(w.subMessage(podFieldStatus), statusFieldPhase))
}

// PodIP extracts status.podIP from the wire, falling back to status.podIPs[0].ip when defaulted.
func (w *WirePod) PodIP() string {
	if w.defaults != nil && w.defaults.status.hasPodIP {
		return w.defaults.status.podIP
	}
	st := w.subMessage(podFieldStatus)
	ip := lazy.ExtractFirstStringField(st, statusFieldPodIP)
	if ip == "" {
		ip = extractFirstPodIPFromList(st)
	}
	return ip
}

// StatusFirstPodIP returns status.podIPs[0].ip without falling back to status.podIP.
func (w *WirePod) StatusFirstPodIP() string {
	if w == nil {
		return ""
	}
	if w.defaults != nil && w.defaults.status.hasSinglePodIP {
		return w.defaults.status.singlePodIP
	}
	return extractFirstPodIPFromList(w.subMessage(podFieldStatus))
}

func extractFirstPodIPFromList(statusBytes []byte) string {
	offset := 0
	for offset < len(statusBytes) {
		num, typ, tagLen := protowire.ConsumeTag(statusBytes[offset:])
		if tagLen < 0 {
			return ""
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, statusBytes[offset:])
		if valLen < 0 {
			return ""
		}
		if num == statusFieldPodIPs && typ == protowire.BytesType {
			ipMsg, _ := protowire.ConsumeBytes(statusBytes[offset : offset+valLen])
			return lazy.ExtractFirstStringField(ipMsg, podIPFieldIP)
		}
		offset += valLen
	}
	return ""
}

// NominatedNodeName extracts status.nominatedNodeName from the wire.
func (w *WirePod) NominatedNodeName() string {
	if w.hasNominatedNodeMod {
		return w.nominatedNodeName
	}
	return lazy.ExtractFirstStringField(w.subMessage(podFieldStatus), statusFieldNominatedNodeName)
}

// SetNominatedNodeName updates status.nominatedNodeName on the wire without decoding the pod.
func (w *WirePod) SetNominatedNodeName(n string) {
	w.nominatedNodeName = n
	w.hasNominatedNodeMod = true
}

// RestartPolicy extracts spec.restartPolicy from the wire, including any pending wire defaults.
func (w *WirePod) RestartPolicy() core.RestartPolicy {
	if w.defaults != nil && w.defaults.spec.hasRestartPolicy {
		return core.RestartPolicy(w.defaults.spec.restartPolicy)
	}
	return core.RestartPolicy(lazy.ExtractFirstStringField(w.subMessage(podFieldSpec), specFieldRestartPolicy))
}

// SchedulerName extracts spec.schedulerName from the wire, including any pending wire defaults.
func (w *WirePod) SchedulerName() string {
	if w.defaults != nil && w.defaults.spec.hasSchedulerName {
		return w.defaults.spec.schedulerName
	}
	return lazy.ExtractFirstStringField(w.subMessage(podFieldSpec), specFieldSchedulerName)
}

// ServiceAccountName extracts spec.serviceAccountName from the wire, including any pending wire defaults.
func (w *WirePod) ServiceAccountName() string {
	if w.defaults != nil && w.defaults.spec.hasServiceAccountName {
		return w.defaults.spec.serviceAccountName
	}
	return lazy.ExtractFirstStringField(w.subMessage(podFieldSpec), specFieldServiceAccountName)
}

// HostNetwork extracts spec.hostNetwork from the wire.
func (w *WirePod) HostNetwork() bool {
	return lazy.ExtractVarintField(w.subMessage(podFieldSpec), specFieldHostNetwork) != 0
}

// TerminationGracePeriodSeconds extracts spec.terminationGracePeriodSeconds from the wire, including any pending wire defaults.
func (w *WirePod) TerminationGracePeriodSeconds() *int64 {
	if w.defaults != nil && w.defaults.spec.hasTerminationGracePeriodSeconds {
		v := w.defaults.spec.terminationGracePeriodSeconds
		return &v
	}
	return extractOptionalInt64Field(w.subMessage(podFieldSpec), specFieldTerminationGracePeriodSeconds)
}

// ActiveDeadlineSeconds extracts spec.activeDeadlineSeconds from the wire.
func (w *WirePod) ActiveDeadlineSeconds() *int64 {
	return extractOptionalInt64Field(w.subMessage(podFieldSpec), specFieldActiveDeadlineSeconds)
}

func extractOptionalInt64Field(msg []byte, targetNum protowire.Number) *int64 {
	offset := 0
	for offset < len(msg) {
		num, typ, tagLen := protowire.ConsumeTag(msg[offset:])
		if tagLen < 0 {
			return nil
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, msg[offset:])
		if valLen < 0 {
			return nil
		}
		if num == targetNum && typ == protowire.VarintType {
			v, _ := protowire.ConsumeVarint(msg[offset : offset+valLen])
			iv := int64(v)
			return &iv
		}
		offset += valLen
	}
	return nil
}

// HasSchedulingGates reports whether spec.schedulingGates is non-empty on the wire.
func (w *WirePod) HasSchedulingGates() bool {
	return lazy.HasField(w.subMessage(podFieldSpec), specFieldSchedulingGates)
}

// IsPodReady reports whether status.conditions contains a Ready=True condition and every spec.readinessGates condition is True.
func (w *WirePod) IsPodReady() bool {
	if w == nil {
		return false
	}
	statusBytes := w.subMessage(podFieldStatus)
	if w.hasConditionsMod {
		statusBytes = w.conditionsEncoded
	}
	podReadyTrue := false
	offset := 0
	for offset < len(statusBytes) {
		num, typ, tagLen := protowire.ConsumeTag(statusBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, statusBytes[offset:])
		if valLen < 0 {
			break
		}
		if num == statusFieldConditions && typ == protowire.BytesType {
			condBytes, _ := protowire.ConsumeBytes(statusBytes[offset : offset+valLen])
			cType := lazy.ExtractFirstStringFieldNoCopy(condBytes, 1)
			cStatus := lazy.ExtractFirstStringFieldNoCopy(condBytes, 2)
			if cType == string(v1.PodReady) && cStatus == string(v1.ConditionTrue) {
				podReadyTrue = true
				break
			}
		}
		offset += valLen
	}
	if !podReadyTrue {
		return false
	}
	specBytes := w.subMessage(podFieldSpec)
	sOff := 0
	for sOff < len(specBytes) {
		num, typ, tagLen := protowire.ConsumeTag(specBytes[sOff:])
		if tagLen < 0 {
			break
		}
		sOff += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, specBytes[sOff:])
		if valLen < 0 {
			break
		}
		if num == specFieldReadinessGates && typ == protowire.BytesType {
			gateBytes, _ := protowire.ConsumeBytes(specBytes[sOff : sOff+valLen])
			gateType := lazy.ExtractFirstStringFieldNoCopy(gateBytes, 1)
			if gateType != "" {
				gateReady := false
				cOff := 0
				for cOff < len(statusBytes) {
					cNum, cTyp, cTagLen := protowire.ConsumeTag(statusBytes[cOff:])
					if cTagLen < 0 {
						break
					}
					cOff += cTagLen
					cValLen := protowire.ConsumeFieldValue(cNum, cTyp, statusBytes[cOff:])
					if cValLen < 0 {
						break
					}
					if cNum == statusFieldConditions && cTyp == protowire.BytesType {
						condBytes, _ := protowire.ConsumeBytes(statusBytes[cOff : cOff+cValLen])
						if lazy.ExtractFirstStringFieldNoCopy(condBytes, 1) == gateType &&
							lazy.ExtractFirstStringFieldNoCopy(condBytes, 2) == string(v1.ConditionTrue) {
							gateReady = true
							break
						}
					}
					cOff += cValLen
				}
				if !gateReady {
					return false
				}
			}
		}
		sOff += valLen
	}
	return true
}

// UpsertStatusCondition updates an existing pod condition of the same Type or appends a new one on the wire.
func (w *WirePod) UpsertStatusCondition(cond core.PodCondition) bool {
	if w == nil {
		return false
	}
	statusBytes := w.subMessage(podFieldStatus)
	if w.hasConditionsMod {
		statusBytes = w.conditionsEncoded
	}

	v1Cond := v1.PodCondition{
		Type:               v1.PodConditionType(cond.Type),
		Status:             v1.ConditionStatus(cond.Status),
		LastProbeTime:      cond.LastProbeTime,
		LastTransitionTime: cond.LastTransitionTime,
		Reason:             cond.Reason,
		Message:            cond.Message,
		ObservedGeneration: cond.ObservedGeneration,
	}

	var condEncoded []byte
	found := false
	changed := false
	offset := 0
	for offset < len(statusBytes) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(statusBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, statusBytes[offset:])
		if valLen < 0 {
			break
		}
		if num == statusFieldConditions && typ == protowire.BytesType {
			condPayload, _ := protowire.ConsumeBytes(statusBytes[offset : offset+valLen])
			if lazy.ExtractFirstStringFieldNoCopy(condPayload, 1) == string(v1Cond.Type) {
				var oldCond v1.PodCondition
				_ = oldCond.Unmarshal(condPayload)
				if oldCond.Status == v1Cond.Status {
					v1Cond.LastTransitionTime = oldCond.LastTransitionTime
				} else if v1Cond.LastTransitionTime.IsZero() {
					v1Cond.LastTransitionTime = metav1.Now()
				}
				changed = oldCond.Status != v1Cond.Status ||
					oldCond.LastTransitionTime != v1Cond.LastTransitionTime ||
					oldCond.LastProbeTime != v1Cond.LastProbeTime ||
					oldCond.Reason != v1Cond.Reason ||
					oldCond.Message != v1Cond.Message ||
					oldCond.ObservedGeneration != v1Cond.ObservedGeneration
				if b, err := v1Cond.Marshal(); err == nil {
					condEncoded = protowire.AppendTag(condEncoded, statusFieldConditions, protowire.BytesType)
					condEncoded = protowire.AppendBytes(condEncoded, b)
				}
				found = true
			} else {
				condEncoded = append(condEncoded, statusBytes[fieldStart:offset+valLen]...)
			}
		}
		offset += valLen
	}
	if !found {
		if v1Cond.LastTransitionTime.IsZero() {
			v1Cond.LastTransitionTime = metav1.Now()
		}
		if b, err := v1Cond.Marshal(); err == nil {
			condEncoded = protowire.AppendTag(condEncoded, statusFieldConditions, protowire.BytesType)
			condEncoded = protowire.AppendBytes(condEncoded, b)
		}
		changed = true
	}
	w.hasConditionsMod = true
	w.conditionsEncoded = condEncoded
	return changed
}

// FirstContainerPort returns the first containerPort > 0 across spec.containers on the wire, or 0 if none exists.
func (w *WirePod) FirstContainerPort() int32 {
	if w == nil {
		return 0
	}
	specBytes := w.subMessage(podFieldSpec)
	offset := 0
	for offset < len(specBytes) {
		num, typ, tagLen := protowire.ConsumeTag(specBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, specBytes[offset:])
		if valLen < 0 {
			break
		}
		if num == specFieldContainers && typ == protowire.BytesType {
			cBytes, _ := protowire.ConsumeBytes(specBytes[offset : offset+valLen])
			cOff := 0
			for cOff < len(cBytes) {
				cNum, cTyp, cTagLen := protowire.ConsumeTag(cBytes[cOff:])
				if cTagLen < 0 {
					break
				}
				cOff += cTagLen
				cValLen := protowire.ConsumeFieldValue(cNum, cTyp, cBytes[cOff:])
				if cValLen < 0 {
					break
				}
				if cNum == containerFieldPorts && cTyp == protowire.BytesType {
					pBytes, _ := protowire.ConsumeBytes(cBytes[cOff : cOff+cValLen])
					port := int32(lazy.ExtractVarintField(pBytes, portFieldContainerPort))
					if port > 0 {
						return port
					}
				}
				cOff += cValLen
			}
		}
		offset += valLen
	}
	return 0
}

// ResolveContainer resolves or validates a container name across initContainers, containers, and ephemeralContainers on the wire.
func (w *WirePod) ResolveContainer(container string) (string, bool, []string) {
	if w == nil {
		return "", false, nil
	}
	specBytes := w.EffectiveSubMessage(podFieldSpec)
	if container == "" {
		var firstContainer string
		containerCount := 0
		offset := 0
		for offset < len(specBytes) {
			num, typ, tagLen := protowire.ConsumeTag(specBytes[offset:])
			if tagLen < 0 {
				break
			}
			offset += tagLen
			valLen := protowire.ConsumeFieldValue(num, typ, specBytes[offset:])
			if valLen < 0 {
				break
			}
			if num == specFieldContainers && typ == protowire.BytesType {
				cBytes, _ := protowire.ConsumeBytes(specBytes[offset : offset+valLen])
				if containerCount == 0 {
					firstContainer = lazy.ExtractFirstStringField(cBytes, containerFieldName)
				}
				containerCount++
			}
			offset += valLen
		}
		if containerCount == 1 {
			return firstContainer, true, nil
		}
		if containerCount == 0 {
			return "", false, nil
		}
		var initNames, appNames, ephNames []string
		offset = 0
		for offset < len(specBytes) {
			num, typ, tagLen := protowire.ConsumeTag(specBytes[offset:])
			if tagLen < 0 {
				break
			}
			offset += tagLen
			valLen := protowire.ConsumeFieldValue(num, typ, specBytes[offset:])
			if valLen < 0 {
				break
			}
			if typ == protowire.BytesType {
				switch num {
				case specFieldInitContainers:
					cBytes, _ := protowire.ConsumeBytes(specBytes[offset : offset+valLen])
					initNames = append(initNames, lazy.ExtractFirstStringField(cBytes, containerFieldName))
				case specFieldContainers:
					cBytes, _ := protowire.ConsumeBytes(specBytes[offset : offset+valLen])
					appNames = append(appNames, lazy.ExtractFirstStringField(cBytes, containerFieldName))
				case specFieldEphemeralContainers:
					eBytes, _ := protowire.ConsumeBytes(specBytes[offset : offset+valLen])
					commonBytes := lazy.SubMessage(eBytes, 1)
					ephNames = append(ephNames, lazy.ExtractFirstStringField(commonBytes, containerFieldName))
				}
			}
			offset += valLen
		}
		allNames := make([]string, 0, len(initNames)+len(appNames)+len(ephNames))
		allNames = append(allNames, initNames...)
		allNames = append(allNames, appNames...)
		allNames = append(allNames, ephNames...)
		return "", false, allNames
	}

	offset := 0
	for offset < len(specBytes) {
		num, typ, tagLen := protowire.ConsumeTag(specBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, specBytes[offset:])
		if valLen < 0 {
			break
		}
		if typ == protowire.BytesType {
			switch num {
			case specFieldInitContainers, specFieldContainers:
				cBytes, _ := protowire.ConsumeBytes(specBytes[offset : offset+valLen])
				if lazy.ExtractFirstStringFieldNoCopy(cBytes, containerFieldName) == container {
					return container, true, nil
				}
			case specFieldEphemeralContainers:
				eBytes, _ := protowire.ConsumeBytes(specBytes[offset : offset+valLen])
				commonBytes := lazy.SubMessage(eBytes, 1)
				if lazy.ExtractFirstStringFieldNoCopy(commonBytes, containerFieldName) == container {
					return container, true, nil
				}
			}
		}
		offset += valLen
	}
	return "", false, nil
}

type wireContainerStateInfo struct {
	kind           int // 0=none, 1=waiting, 2=running, 3=terminated
	waitingReason  string
	termReason     string
	termSignal     int32
	termExitCode   int32
	termFinishedAt metav1.Time
}

func parseWireContainerState(stateBytes []byte) wireContainerStateInfo {
	var info wireContainerStateInfo
	offset := 0
	for offset < len(stateBytes) {
		num, typ, tagLen := protowire.ConsumeTag(stateBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, stateBytes[offset:])
		if valLen < 0 {
			break
		}
		if typ == protowire.BytesType {
			sub, _ := protowire.ConsumeBytes(stateBytes[offset : offset+valLen])
			switch num {
			case 1: // waiting
				info.kind = 1
				info.waitingReason = lazy.ExtractFirstStringField(sub, 1)
			case 2: // running
				info.kind = 2
			case 3: // terminated
				info.kind = 3
				tOff := 0
				for tOff < len(sub) {
					tNum, tTyp, tTagLen := protowire.ConsumeTag(sub[tOff:])
					if tTagLen < 0 {
						break
					}
					tOff += tTagLen
					tValLen := protowire.ConsumeFieldValue(tNum, tTyp, sub[tOff:])
					if tValLen < 0 {
						break
					}
					switch tNum {
					case 1: // exitCode
						if tTyp == protowire.VarintType {
							v, _ := protowire.ConsumeVarint(sub[tOff : tOff+tValLen])
							info.termExitCode = int32(v)
						}
					case 2: // signal
						if tTyp == protowire.VarintType {
							v, _ := protowire.ConsumeVarint(sub[tOff : tOff+tValLen])
							info.termSignal = int32(v)
						}
					case 3: // reason
						if tTyp == protowire.BytesType {
							info.termReason, _ = protowire.ConsumeString(sub[tOff : tOff+tValLen])
						}
					case 6: // finishedAt
						if tTyp == protowire.BytesType {
							tb, _ := protowire.ConsumeBytes(sub[tOff : tOff+tValLen])
							_ = info.termFinishedAt.Unmarshal(tb)
						}
					}
					tOff += tValLen
				}
			}
		}
		offset += valLen
	}
	return info
}

type wireContainerStatusInfo struct {
	name           string
	state          wireContainerStateInfo
	lastFinishedAt metav1.Time
	ready          bool
	restartCount   int32
	started        bool
}

func parseWireContainerStatus(csBytes []byte) wireContainerStatusInfo {
	var cs wireContainerStatusInfo
	offset := 0
	for offset < len(csBytes) {
		num, typ, tagLen := protowire.ConsumeTag(csBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, csBytes[offset:])
		if valLen < 0 {
			break
		}
		switch num {
		case csFieldName:
			if typ == protowire.BytesType {
				cs.name, _ = protowire.ConsumeString(csBytes[offset : offset+valLen])
			}
		case csFieldState:
			if typ == protowire.BytesType {
				sub, _ := protowire.ConsumeBytes(csBytes[offset : offset+valLen])
				cs.state = parseWireContainerState(sub)
			}
		case csFieldLastState:
			if typ == protowire.BytesType {
				sub, _ := protowire.ConsumeBytes(csBytes[offset : offset+valLen])
				ls := parseWireContainerState(sub)
				cs.lastFinishedAt = ls.termFinishedAt
			}
		case csFieldReady:
			if typ == protowire.VarintType {
				v, _ := protowire.ConsumeVarint(csBytes[offset : offset+valLen])
				cs.ready = v != 0
			}
		case csFieldRestartCount:
			if typ == protowire.VarintType {
				v, _ := protowire.ConsumeVarint(csBytes[offset : offset+valLen])
				cs.restartCount = int32(v)
			}
		case csFieldStarted:
			if typ == protowire.VarintType {
				v, _ := protowire.ConsumeVarint(csBytes[offset : offset+valLen])
				cs.started = v != 0
			}
		}
		offset += valLen
	}
	return cs
}

type wireInitSpecInfo struct {
	name        string
	restartable bool
}

// TableSummary extracts the fields required by printPod directly from the wire without decoding a *core.Pod.
func (w *WirePod) TableSummary(wide bool) core.PodTableSummary {
	var sum core.PodTableSummary
	if w == nil {
		return sum
	}

	specBytes := w.EffectiveSubMessage(podFieldSpec)
	var initSpecs []wireInitSpecInfo
	var readinessGates []string
	sOff := 0
	for sOff < len(specBytes) {
		num, typ, tagLen := protowire.ConsumeTag(specBytes[sOff:])
		if tagLen < 0 {
			break
		}
		sOff += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, specBytes[sOff:])
		if valLen < 0 {
			break
		}
		switch num {
		case specFieldContainers:
			if typ == protowire.BytesType {
				sum.TotalContainers++
			}
		case specFieldInitContainers:
			if typ == protowire.BytesType {
				cBytes, _ := protowire.ConsumeBytes(specBytes[sOff : sOff+valLen])
				name := lazy.ExtractFirstStringField(cBytes, containerFieldName)
				rp := lazy.ExtractFirstStringFieldNoCopy(cBytes, containerFieldRestartPolicy)
				restartable := rp == string(v1.ContainerRestartPolicyAlways)
				if restartable {
					sum.TotalContainers++
				}
				initSpecs = append(initSpecs, wireInitSpecInfo{name: name, restartable: restartable})
			}
		case specFieldNodeName:
			if wide && typ == protowire.BytesType {
				sum.NodeName, _ = protowire.ConsumeString(specBytes[sOff : sOff+valLen])
			}
		case specFieldReadinessGates:
			if wide && typ == protowire.BytesType {
				gBytes, _ := protowire.ConsumeBytes(specBytes[sOff : sOff+valLen])
				readinessGates = append(readinessGates, lazy.ExtractFirstStringField(gBytes, 1))
			}
		}
		sOff += valLen
	}

	statusBytes := w.EffectiveSubMessage(podFieldStatus)
	var phase string
	var statusReason string
	var firstPodIP string
	var nominatedNode string
	var initStatuses []wireContainerStatusInfo
	var appStatuses []wireContainerStatusInfo
	var condStatuses map[string]string
	podScheduledGated := false
	hasPodReadyTrue := false
	hasPodInitializedTrue := false

	stOff := 0
	for stOff < len(statusBytes) {
		num, typ, tagLen := protowire.ConsumeTag(statusBytes[stOff:])
		if tagLen < 0 {
			break
		}
		stOff += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, statusBytes[stOff:])
		if valLen < 0 {
			break
		}
		switch num {
		case statusFieldPhase:
			if typ == protowire.BytesType {
				phase, _ = protowire.ConsumeString(statusBytes[stOff : stOff+valLen])
			}
		case statusFieldReason:
			if typ == protowire.BytesType {
				statusReason, _ = protowire.ConsumeString(statusBytes[stOff : stOff+valLen])
			}
		case statusFieldPodIPs:
			if wide && typ == protowire.BytesType && firstPodIP == "" {
				ipMsg, _ := protowire.ConsumeBytes(statusBytes[stOff : stOff+valLen])
				firstPodIP = lazy.ExtractFirstStringField(ipMsg, podIPFieldIP)
			}
		case statusFieldNominatedNodeName:
			if wide && typ == protowire.BytesType {
				nominatedNode, _ = protowire.ConsumeString(statusBytes[stOff : stOff+valLen])
			}
		case statusFieldConditions:
			if typ == protowire.BytesType {
				cBytes, _ := protowire.ConsumeBytes(statusBytes[stOff : stOff+valLen])
				cType := lazy.ExtractFirstStringFieldNoCopy(cBytes, 1)
				cStatus := lazy.ExtractFirstStringFieldNoCopy(cBytes, 2)
				cReason := lazy.ExtractFirstStringFieldNoCopy(cBytes, 5)
				if cType == string(v1.PodScheduled) && cReason == v1.PodReasonSchedulingGated {
					podScheduledGated = true
				}
				if cType == string(v1.PodReady) && cStatus == string(v1.ConditionTrue) {
					hasPodReadyTrue = true
				}
				if cType == string(v1.PodInitialized) && cStatus == string(v1.ConditionTrue) {
					hasPodInitializedTrue = true
				}
				if len(readinessGates) > 0 {
					if condStatuses == nil {
						condStatuses = make(map[string]string, 4)
					}
					if _, exists := condStatuses[cType]; !exists {
						condStatuses[strings.Clone(cType)] = strings.Clone(cStatus)
					}
				}
			}
		case statusFieldInitContainerStatuses:
			if typ == protowire.BytesType {
				csBytes, _ := protowire.ConsumeBytes(statusBytes[stOff : stOff+valLen])
				initStatuses = append(initStatuses, parseWireContainerStatus(csBytes))
			}
		case statusFieldContainerStatuses:
			if typ == protowire.BytesType {
				csBytes, _ := protowire.ConsumeBytes(statusBytes[stOff : stOff+valLen])
				appStatuses = append(appStatuses, parseWireContainerStatus(csBytes))
			}
		}
		stOff += valLen
	}

	sum.Phase = core.PodPhase(phase)
	sum.RawStatusReason = statusReason

	reason := phase
	if statusReason != "" {
		reason = statusReason
	}
	if podScheduledGated {
		reason = v1.PodReasonSchedulingGated
	}

	var lastRestartDate metav1.Time
	var lastRestartableInitRestartDate metav1.Time
	var restartableInitRestarts int
	initializing := false
	for i := range initStatuses {
		container := &initStatuses[i]
		sum.Restarts += int(container.restartCount)
		if !container.lastFinishedAt.IsZero() && lastRestartDate.Before(&container.lastFinishedAt) {
			lastRestartDate = container.lastFinishedAt
		}
		var restartable bool
		if i < len(initSpecs) && initSpecs[i].name == container.name {
			restartable = initSpecs[i].restartable
		} else {
			for j := range initSpecs {
				if initSpecs[j].name == container.name {
					restartable = initSpecs[j].restartable
					break
				}
			}
		}
		if restartable {
			restartableInitRestarts += int(container.restartCount)
			if !container.lastFinishedAt.IsZero() && lastRestartableInitRestartDate.Before(&container.lastFinishedAt) {
				lastRestartableInitRestartDate = container.lastFinishedAt
			}
		}
		switch {
		case container.state.kind == 3 && container.state.termExitCode == 0:
			continue
		case restartable && container.started:
			if container.ready {
				sum.ReadyContainers++
			}
			continue
		case container.state.kind == 3:
			if len(container.state.termReason) == 0 {
				if container.state.termSignal != 0 {
					reason = fmt.Sprintf("Init:Signal:%d", container.state.termSignal)
				} else {
					reason = fmt.Sprintf("Init:ExitCode:%d", container.state.termExitCode)
				}
			} else {
				reason = "Init:" + container.state.termReason
			}
			initializing = true
		case container.state.kind == 1 && len(container.state.waitingReason) > 0 && container.state.waitingReason != "PodInitializing":
			reason = "Init:" + container.state.waitingReason
			initializing = true
		default:
			reason = fmt.Sprintf("Init:%d/%d", i, len(initSpecs))
			initializing = true
		}
		break
	}

	if !initializing || hasPodInitializedTrue {
		sum.Restarts = restartableInitRestarts
		lastRestartDate = lastRestartableInitRestartDate
		hasRunning := false
		errorReason := ""
		for i := len(appStatuses) - 1; i >= 0; i-- {
			container := &appStatuses[i]
			sum.Restarts += int(container.restartCount)
			if !container.lastFinishedAt.IsZero() && lastRestartDate.Before(&container.lastFinishedAt) {
				lastRestartDate = container.lastFinishedAt
			}
			switch {
			case container.state.kind == 1 && container.state.waitingReason != "":
				reason = container.state.waitingReason
			case container.state.kind == 3:
				if len(container.state.termReason) > 0 {
					reason = container.state.termReason
				} else if container.state.termSignal != 0 {
					reason = fmt.Sprintf("Signal:%d", container.state.termSignal)
				} else {
					reason = fmt.Sprintf("ExitCode:%d", container.state.termExitCode)
				}
				if container.state.termExitCode != 0 {
					errorReason = reason
				}
			case container.ready && container.state.kind == 2:
				hasRunning = true
				sum.ReadyContainers++
			}
		}
		if reason == "Completed" {
			if hasRunning && hasPodReadyTrue {
				reason = "Running"
			} else if errorReason != "" {
				reason = errorReason
			} else if hasRunning {
				reason = "NotReady"
			}
		}
	}

	sum.StatusReason = reason
	sum.LastRestartTime = lastRestartDate
	if wide {
		if firstPodIP == "" && w.defaults != nil && w.defaults.status.hasSinglePodIP {
			firstPodIP = w.defaults.status.singlePodIP
		}
		sum.PodIP = firstPodIP
		sum.NominatedNode = nominatedNode
		if len(readinessGates) > 0 {
			trueConditions := 0
			for _, gate := range readinessGates {
				if condStatuses[gate] == string(v1.ConditionTrue) {
					trueConditions++
				}
			}
			sum.ReadinessGates = fmt.Sprintf("%d/%d", trueConditions, len(readinessGates))
		}
	}
	return sum
}

// ============================================================================
// Wire-level Defaulting (implements corev1.PodDefaulter)
// ============================================================================

type wireDefaultPlan struct {
	specDirty   bool
	statusDirty bool
	spec        specOverrides
	status      statusOverrides
}

type specOverrides struct {
	hasRestartPolicy                 bool
	restartPolicy                    v1.RestartPolicy
	hasTerminationGracePeriodSeconds bool
	terminationGracePeriodSeconds    int64
	hasDNSPolicy                     bool
	dnsPolicy                        v1.DNSPolicy
	hasServiceAccountName            bool
	serviceAccountName               string
	hasDeprecatedServiceAccount      bool
	deprecatedServiceAccount         string
	initEmptySecurityContext         bool
	hasSchedulerName                 bool
	schedulerName                    string
	hasEnableServiceLinks            bool
	enableServiceLinks               bool

	containers     map[int]*containerOverrides
	initContainers map[int]*containerOverrides
	volumes        map[int]*volumeOverrides
}

type containerOverrides struct {
	hasImagePullPolicy          bool
	imagePullPolicy             v1.PullPolicy
	hasTerminationMessagePath   bool
	terminationMessagePath      string
	hasTerminationMessagePolicy bool
	terminationMessagePolicy    v1.TerminationMessagePolicy
	copyLimitsToRequests        bool
	ports                       map[int]*portOverrides
}

type portOverrides struct {
	hasHostPort bool
	hostPort    int32
	hasProtocol bool
	protocol    v1.Protocol
}

type volumeOverrides struct {
	setEmptyDir              bool
	setHostPathType          bool
	hostPathType             v1.HostPathType
	setSecretDefaultMode     bool
	secretDefaultMode        int32
	setDownwardDefaultMode   bool
	downwardDefaultMode      int32
	setConfigMapDefaultMode  bool
	configMapDefaultMode     int32
	setProjectedDefaultMode  bool
	projectedDefaultMode     int32
	projectedDownwardDefault map[int]map[int]bool
}

type statusOverrides struct {
	hasPodIP       bool
	podIP          string
	hasSinglePodIP bool
	singlePodIP    string
}

func (p *wireDefaultPlan) clone() *wireDefaultPlan {
	if p == nil {
		return nil
	}
	cp := *p
	if p.spec.containers != nil {
		cp.spec.containers = make(map[int]*containerOverrides, len(p.spec.containers))
		for k, v := range p.spec.containers {
			co := *v
			if v.ports != nil {
				co.ports = make(map[int]*portOverrides, len(v.ports))
				for pk, pv := range v.ports {
					po := *pv
					co.ports[pk] = &po
				}
			}
			cp.spec.containers[k] = &co
		}
	}
	if p.spec.initContainers != nil {
		cp.spec.initContainers = make(map[int]*containerOverrides, len(p.spec.initContainers))
		for k, v := range p.spec.initContainers {
			co := *v
			if v.ports != nil {
				co.ports = make(map[int]*portOverrides, len(v.ports))
				for pk, pv := range v.ports {
					po := *pv
					co.ports[pk] = &po
				}
			}
			cp.spec.initContainers[k] = &co
		}
	}
	if p.spec.volumes != nil {
		cp.spec.volumes = make(map[int]*volumeOverrides, len(p.spec.volumes))
		for k, v := range p.spec.volumes {
			vo := *v
			if v.projectedDownwardDefault != nil {
				vo.projectedDownwardDefault = make(map[int]map[int]bool, len(v.projectedDownwardDefault))
				for sk, sv := range v.projectedDownwardDefault {
					im := make(map[int]bool, len(sv))
					for ik, iv := range sv {
						im[ik] = iv
					}
					vo.projectedDownwardDefault[sk] = im
				}
			}
			cp.spec.volumes[k] = &vo
		}
	}
	return &cp
}

func (w *WirePod) ensureDefaultPlan() *wireDefaultPlan {
	if w.defaults == nil {
		w.defaults = &wireDefaultPlan{}
	}
	return w.defaults
}

func (w *WirePod) markSpecDefaultDirty() *specOverrides {
	p := w.ensureDefaultPlan()
	p.specDirty = true
	return &p.spec
}

func (w *WirePod) markStatusDefaultDirty() *statusOverrides {
	p := w.ensureDefaultPlan()
	p.statusDirty = true
	return &p.status
}

// DefaultOnWire runs corev1.DefaultObjectPod directly on the WirePod without decoding into a *v1.Pod.
func (w *WirePod) DefaultOnWire() {
	if w == nil {
		return
	}
	var scratch wireDefaulterScratch
	corev1.DefaultObjectPod(newWirePodDefaulter(w, &scratch))
}

type wireDefaulterScratch struct {
	pod       wirePodDefaulter
	container wireContainerDefaulter
	port      wirePortDefaulter
	volume    wireVolumeDefaulter
	portsBuf  [4][]byte
}

type wirePodDefaulter struct {
	w        *WirePod
	scratch  *wireDefaulterScratch
	specInit bool

	volumes        [][]byte
	containers     [][]byte
	initContainers [][]byte

	restartPolicy                    v1.RestartPolicy
	hasTerminationGracePeriodSeconds bool
	terminationGracePeriodSeconds    int64
	dnsPolicy                        v1.DNSPolicy
	serviceAccountName               string
	deprecatedServiceAccount         string
	hostNetwork                      bool
	hasSecurityContext               bool
	schedulerName                    string
	hasEnableServiceLinks            bool
	enableServiceLinks               bool
	osName                           v1.OSName

	statusInit  bool
	statusPodIP string
	firstPodIP  string
	numPodIPs   int
}

func newWirePodDefaulter(w *WirePod, scratch *wireDefaulterScratch) *wirePodDefaulter {
	if scratch != nil {
		scratch.pod = wirePodDefaulter{w: w, scratch: scratch}
		return &scratch.pod
	}
	return &wirePodDefaulter{w: w}
}

func (d *wirePodDefaulter) Spec() corev1.PodSpecDefaulter     { return d }
func (d *wirePodDefaulter) Status() corev1.PodStatusDefaulter { return d }

func (d *wirePodDefaulter) ensureSpecScanned() {
	if d.specInit {
		return
	}
	d.specInit = true
	specBytes := d.w.subMessage(podFieldSpec)
	offset := 0
	for offset < len(specBytes) {
		num, typ, tagLen := protowire.ConsumeTag(specBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, specBytes[offset:])
		if valLen < 0 {
			break
		}
		valBytes := specBytes[offset : offset+valLen]
		offset += valLen

		switch num {
		case specFieldVolumes:
			if typ == protowire.BytesType {
				vContent, _ := protowire.ConsumeBytes(valBytes)
				d.volumes = append(d.volumes, vContent)
			}
		case specFieldContainers:
			if typ == protowire.BytesType {
				cContent, _ := protowire.ConsumeBytes(valBytes)
				d.containers = append(d.containers, cContent)
			}
		case specFieldInitContainers:
			if typ == protowire.BytesType {
				cContent, _ := protowire.ConsumeBytes(valBytes)
				d.initContainers = append(d.initContainers, cContent)
			}
		case specFieldRestartPolicy:
			d.restartPolicy = v1.RestartPolicy(lazy.ConsumeStringNoCopy(valBytes))
		case specFieldTerminationGracePeriodSeconds:
			v, _ := protowire.ConsumeVarint(valBytes)
			d.hasTerminationGracePeriodSeconds = true
			d.terminationGracePeriodSeconds = int64(v)
		case specFieldDNSPolicy:
			d.dnsPolicy = v1.DNSPolicy(lazy.ConsumeStringNoCopy(valBytes))
		case specFieldServiceAccountName:
			d.serviceAccountName = lazy.ConsumeStringNoCopy(valBytes)
		case specFieldDeprecatedServiceAccount:
			d.deprecatedServiceAccount = lazy.ConsumeStringNoCopy(valBytes)
		case specFieldHostNetwork:
			v, _ := protowire.ConsumeVarint(valBytes)
			d.hostNetwork = v != 0
		case specFieldSecurityContext:
			d.hasSecurityContext = true
		case specFieldSchedulerName:
			d.schedulerName = lazy.ConsumeStringNoCopy(valBytes)
		case specFieldEnableServiceLinks:
			v, _ := protowire.ConsumeVarint(valBytes)
			d.hasEnableServiceLinks = true
			d.enableServiceLinks = v != 0
		case specFieldOS:
			if typ == protowire.BytesType {
				osContent, _ := protowire.ConsumeBytes(valBytes)
				d.osName = v1.OSName(lazy.ExtractFirstStringFieldNoCopy(osContent, osFieldName))
			}
		}
	}
}

func (d *wirePodDefaulter) ensureStatusScanned() {
	if d.statusInit {
		return
	}
	d.statusInit = true
	statusBytes := d.w.subMessage(podFieldStatus)
	offset := 0
	for offset < len(statusBytes) {
		num, typ, tagLen := protowire.ConsumeTag(statusBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, statusBytes[offset:])
		if valLen < 0 {
			break
		}
		valBytes := statusBytes[offset : offset+valLen]
		offset += valLen

		switch num {
		case statusFieldPodIP:
			d.statusPodIP = lazy.ConsumeStringNoCopy(valBytes)
		case statusFieldPodIPs:
			if typ == protowire.BytesType {
				ipMsg, _ := protowire.ConsumeBytes(valBytes)
				if d.numPodIPs == 0 {
					d.firstPodIP = lazy.ExtractFirstStringFieldNoCopy(ipMsg, podIPFieldIP)
				}
				d.numPodIPs++
			}
		}
	}
}

func (d *wirePodDefaulter) GetHostNetwork() bool {
	d.ensureSpecScanned()
	return d.hostNetwork
}

func (d *wirePodDefaulter) GetRestartPolicy() v1.RestartPolicy {
	d.ensureSpecScanned()
	if d.w.defaults != nil && d.w.defaults.spec.hasRestartPolicy {
		return d.w.defaults.spec.restartPolicy
	}
	return d.restartPolicy
}

func (d *wirePodDefaulter) SetRestartPolicy(p v1.RestartPolicy) {
	sp := d.w.markSpecDefaultDirty()
	sp.hasRestartPolicy = true
	sp.restartPolicy = p
}

func (d *wirePodDefaulter) GetTerminationGracePeriodSeconds() (int64, bool) {
	d.ensureSpecScanned()
	if d.w.defaults != nil && d.w.defaults.spec.hasTerminationGracePeriodSeconds {
		return d.w.defaults.spec.terminationGracePeriodSeconds, true
	}
	return d.terminationGracePeriodSeconds, d.hasTerminationGracePeriodSeconds
}

func (d *wirePodDefaulter) SetTerminationGracePeriodSeconds(sec int64) {
	sp := d.w.markSpecDefaultDirty()
	sp.hasTerminationGracePeriodSeconds = true
	sp.terminationGracePeriodSeconds = sec
}

func (d *wirePodDefaulter) GetDNSPolicy() v1.DNSPolicy {
	d.ensureSpecScanned()
	if d.w.defaults != nil && d.w.defaults.spec.hasDNSPolicy {
		return d.w.defaults.spec.dnsPolicy
	}
	return d.dnsPolicy
}

func (d *wirePodDefaulter) SetDNSPolicy(p v1.DNSPolicy) {
	sp := d.w.markSpecDefaultDirty()
	sp.hasDNSPolicy = true
	sp.dnsPolicy = p
}

func (d *wirePodDefaulter) GetServiceAccountName() string {
	d.ensureSpecScanned()
	if d.w.defaults != nil && d.w.defaults.spec.hasServiceAccountName {
		return d.w.defaults.spec.serviceAccountName
	}
	return d.serviceAccountName
}

func (d *wirePodDefaulter) SetServiceAccountName(name string) {
	sp := d.w.markSpecDefaultDirty()
	sp.hasServiceAccountName = true
	sp.serviceAccountName = string([]byte(name))
}

func (d *wirePodDefaulter) GetDeprecatedServiceAccount() string {
	d.ensureSpecScanned()
	if d.w.defaults != nil && d.w.defaults.spec.hasDeprecatedServiceAccount {
		return d.w.defaults.spec.deprecatedServiceAccount
	}
	return d.deprecatedServiceAccount
}

func (d *wirePodDefaulter) SetDeprecatedServiceAccount(name string) {
	sp := d.w.markSpecDefaultDirty()
	sp.hasDeprecatedServiceAccount = true
	sp.deprecatedServiceAccount = string([]byte(name))
}

func (d *wirePodDefaulter) HasSecurityContext() bool {
	d.ensureSpecScanned()
	if d.w.defaults != nil && d.w.defaults.spec.initEmptySecurityContext {
		return true
	}
	return d.hasSecurityContext
}

func (d *wirePodDefaulter) InitEmptySecurityContext() {
	sp := d.w.markSpecDefaultDirty()
	sp.initEmptySecurityContext = true
}

func (d *wirePodDefaulter) GetSchedulerName() string {
	d.ensureSpecScanned()
	if d.w.defaults != nil && d.w.defaults.spec.hasSchedulerName {
		return d.w.defaults.spec.schedulerName
	}
	return d.schedulerName
}

func (d *wirePodDefaulter) SetSchedulerName(name string) {
	sp := d.w.markSpecDefaultDirty()
	sp.hasSchedulerName = true
	sp.schedulerName = name
}

func (d *wirePodDefaulter) HasEnableServiceLinks() bool {
	d.ensureSpecScanned()
	if d.w.defaults != nil && d.w.defaults.spec.hasEnableServiceLinks {
		return true
	}
	return d.hasEnableServiceLinks
}

func (d *wirePodDefaulter) SetEnableServiceLinks(val bool) {
	sp := d.w.markSpecDefaultDirty()
	sp.hasEnableServiceLinks = true
	sp.enableServiceLinks = val
}

func (d *wirePodDefaulter) GetPodIP() string {
	d.ensureStatusScanned()
	if d.w.defaults != nil && d.w.defaults.status.hasPodIP {
		return d.w.defaults.status.podIP
	}
	return d.statusPodIP
}

func (d *wirePodDefaulter) SetPodIP(ip string) {
	st := d.w.markStatusDefaultDirty()
	st.hasPodIP = true
	st.podIP = string([]byte(ip))
}

func (d *wirePodDefaulter) NumPodIPs() int {
	d.ensureStatusScanned()
	if d.w.defaults != nil && d.w.defaults.status.hasSinglePodIP {
		return 1
	}
	return d.numPodIPs
}

func (d *wirePodDefaulter) GetFirstPodIP() string {
	d.ensureStatusScanned()
	if d.w.defaults != nil && d.w.defaults.status.hasSinglePodIP {
		return d.w.defaults.status.singlePodIP
	}
	return d.firstPodIP
}

func (d *wirePodDefaulter) SetSinglePodIP(ip string) {
	st := d.w.markStatusDefaultDirty()
	st.hasSinglePodIP = true
	st.singlePodIP = string([]byte(ip))
}

func (d *wirePodDefaulter) NumContainers() int {
	d.ensureSpecScanned()
	return len(d.containers)
}

func (d *wirePodDefaulter) Container(i int) corev1.ContainerDefaulter {
	d.ensureSpecScanned()
	if d.scratch != nil {
		populateWireContainerDefaulter(&d.scratch.container, d.w, false, i, d.containers[i], d.scratch)
		return &d.scratch.container
	}
	return newWireContainerDefaulter(d.w, false, i, d.containers[i])
}

func (d *wirePodDefaulter) NumInitContainers() int {
	d.ensureSpecScanned()
	return len(d.initContainers)
}

func (d *wirePodDefaulter) InitContainer(i int) corev1.ContainerDefaulter {
	d.ensureSpecScanned()
	if d.scratch != nil {
		populateWireContainerDefaulter(&d.scratch.container, d.w, true, i, d.initContainers[i], d.scratch)
		return &d.scratch.container
	}
	return newWireContainerDefaulter(d.w, true, i, d.initContainers[i])
}

func (d *wirePodDefaulter) NumVolumes() int {
	d.ensureSpecScanned()
	return len(d.volumes)
}

func (d *wirePodDefaulter) Volume(i int) corev1.VolumeDefaulter {
	d.ensureSpecScanned()
	if d.scratch != nil {
		populateWireVolumeDefaulter(&d.scratch.volume, d.w, i, d.volumes[i])
		return &d.scratch.volume
	}
	return newWireVolumeDefaulter(d.w, i, d.volumes[i])
}

type wireContainerDefaulter struct {
	w       *WirePod
	scratch *wireDefaulterScratch
	isInit  bool
	index   int

	image                    string
	imagePullPolicy          v1.PullPolicy
	terminationMessagePath   string
	terminationMessagePolicy v1.TerminationMessagePolicy
	ports                    [][]byte
	resourcesBytes           []byte
}

func newWireContainerDefaulter(w *WirePod, isInit bool, index int, cBytes []byte) *wireContainerDefaulter {
	d := &wireContainerDefaulter{}
	populateWireContainerDefaulter(d, w, isInit, index, cBytes, nil)
	return d
}

func populateWireContainerDefaulter(d *wireContainerDefaulter, w *WirePod, isInit bool, index int, cBytes []byte, scratch *wireDefaulterScratch) {
	var portsSlice [][]byte
	if scratch != nil {
		portsSlice = scratch.portsBuf[:0]
	}
	*d = wireContainerDefaulter{
		w:       w,
		scratch: scratch,
		isInit:  isInit,
		index:   index,
		ports:   portsSlice,
	}
	offset := 0
	for offset < len(cBytes) {
		num, typ, tagLen := protowire.ConsumeTag(cBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, cBytes[offset:])
		if valLen < 0 {
			break
		}
		valBytes := cBytes[offset : offset+valLen]
		offset += valLen

		switch num {
		case containerFieldImage:
			d.image = lazy.ConsumeStringNoCopy(valBytes)
		case containerFieldPorts:
			if typ == protowire.BytesType {
				pContent, _ := protowire.ConsumeBytes(valBytes)
				d.ports = append(d.ports, pContent)
			}
		case containerFieldResources:
			if typ == protowire.BytesType {
				d.resourcesBytes, _ = protowire.ConsumeBytes(valBytes)
			}
		case containerFieldTerminationMessagePath:
			d.terminationMessagePath = lazy.ConsumeStringNoCopy(valBytes)
		case containerFieldImagePullPolicy:
			d.imagePullPolicy = v1.PullPolicy(lazy.ConsumeStringNoCopy(valBytes))
		case containerFieldTerminationMessagePolicy:
			d.terminationMessagePolicy = v1.TerminationMessagePolicy(lazy.ConsumeStringNoCopy(valBytes))
		}
	}
}

func (d *wireContainerDefaulter) getOverrides() *containerOverrides {
	if d.w.defaults == nil {
		return nil
	}
	m := d.w.defaults.spec.containers
	if d.isInit {
		m = d.w.defaults.spec.initContainers
	}
	if m == nil {
		return nil
	}
	return m[d.index]
}

func (d *wireContainerDefaulter) ensureOverrides() *containerOverrides {
	sp := d.w.markSpecDefaultDirty()
	if d.isInit {
		if sp.initContainers == nil {
			sp.initContainers = make(map[int]*containerOverrides)
		}
		co := sp.initContainers[d.index]
		if co == nil {
			co = &containerOverrides{}
			sp.initContainers[d.index] = co
		}
		return co
	}
	if sp.containers == nil {
		sp.containers = make(map[int]*containerOverrides)
	}
	co := sp.containers[d.index]
	if co == nil {
		co = &containerOverrides{}
		sp.containers[d.index] = co
	}
	return co
}

func (d *wireContainerDefaulter) GetImage() string {
	return d.image
}

func (d *wireContainerDefaulter) GetImagePullPolicy() v1.PullPolicy {
	if co := d.getOverrides(); co != nil && co.hasImagePullPolicy {
		return co.imagePullPolicy
	}
	return d.imagePullPolicy
}

func (d *wireContainerDefaulter) SetImagePullPolicy(p v1.PullPolicy) {
	co := d.ensureOverrides()
	co.hasImagePullPolicy = true
	co.imagePullPolicy = p
}

func (d *wireContainerDefaulter) GetTerminationMessagePath() string {
	if co := d.getOverrides(); co != nil && co.hasTerminationMessagePath {
		return co.terminationMessagePath
	}
	return d.terminationMessagePath
}

func (d *wireContainerDefaulter) SetTerminationMessagePath(p string) {
	co := d.ensureOverrides()
	co.hasTerminationMessagePath = true
	co.terminationMessagePath = p
}

func (d *wireContainerDefaulter) GetTerminationMessagePolicy() v1.TerminationMessagePolicy {
	if co := d.getOverrides(); co != nil && co.hasTerminationMessagePolicy {
		return co.terminationMessagePolicy
	}
	return d.terminationMessagePolicy
}

func (d *wireContainerDefaulter) SetTerminationMessagePolicy(p v1.TerminationMessagePolicy) {
	co := d.ensureOverrides()
	co.hasTerminationMessagePolicy = true
	co.terminationMessagePolicy = p
}

func (d *wireContainerDefaulter) NumPorts() int {
	return len(d.ports)
}

func (d *wireContainerDefaulter) Port(i int) corev1.ContainerPortDefaulter {
	if d.scratch != nil {
		populateWirePortDefaulter(&d.scratch.port, d, i, d.ports[i])
		return &d.scratch.port
	}
	return newWirePortDefaulter(d, i, d.ports[i])
}

func (d *wireContainerDefaulter) HasMissingResourceRequestsFromLimits() bool {
	if co := d.getOverrides(); co != nil && co.copyLimitsToRequests {
		return false
	}
	return resourcesNeedDefaulting(d.resourcesBytes)
}

func (d *wireContainerDefaulter) CopyMissingResourceLimitsToRequests() {
	co := d.ensureOverrides()
	co.copyLimitsToRequests = true
}

type wirePortDefaulter struct {
	c             *wireContainerDefaulter
	index         int
	hostPort      int32
	containerPort int32
	protocol      v1.Protocol
}

func newWirePortDefaulter(c *wireContainerDefaulter, index int, pBytes []byte) *wirePortDefaulter {
	d := &wirePortDefaulter{}
	populateWirePortDefaulter(d, c, index, pBytes)
	return d
}

func populateWirePortDefaulter(d *wirePortDefaulter, c *wireContainerDefaulter, index int, pBytes []byte) {
	*d = wirePortDefaulter{
		c:     c,
		index: index,
	}
	offset := 0
	for offset < len(pBytes) {
		num, typ, tagLen := protowire.ConsumeTag(pBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, pBytes[offset:])
		if valLen < 0 {
			break
		}
		valBytes := pBytes[offset : offset+valLen]
		offset += valLen

		switch num {
		case portFieldHostPort:
			v, _ := protowire.ConsumeVarint(valBytes)
			d.hostPort = int32(v)
		case portFieldContainerPort:
			v, _ := protowire.ConsumeVarint(valBytes)
			d.containerPort = int32(v)
		case portFieldProtocol:
			d.protocol = v1.Protocol(lazy.ConsumeStringNoCopy(valBytes))
		}
	}
}

func (d *wirePortDefaulter) getOverrides() *portOverrides {
	co := d.c.getOverrides()
	if co == nil || co.ports == nil {
		return nil
	}
	return co.ports[d.index]
}

func (d *wirePortDefaulter) ensureOverrides() *portOverrides {
	co := d.c.ensureOverrides()
	if co.ports == nil {
		co.ports = make(map[int]*portOverrides)
	}
	po := co.ports[d.index]
	if po == nil {
		po = &portOverrides{}
		co.ports[d.index] = po
	}
	return po
}

func (d *wirePortDefaulter) GetHostPort() int32 {
	if po := d.getOverrides(); po != nil && po.hasHostPort {
		return po.hostPort
	}
	return d.hostPort
}

func (d *wirePortDefaulter) SetHostPort(v int32) {
	po := d.ensureOverrides()
	po.hasHostPort = true
	po.hostPort = v
}

func (d *wirePortDefaulter) GetContainerPort() int32 {
	return d.containerPort
}

func (d *wirePortDefaulter) GetProtocol() v1.Protocol {
	if po := d.getOverrides(); po != nil && po.hasProtocol {
		return po.protocol
	}
	return d.protocol
}

func (d *wirePortDefaulter) SetProtocol(p v1.Protocol) {
	po := d.ensureOverrides()
	po.hasProtocol = true
	po.protocol = p
}

type wireVolumeDefaulter struct {
	w                       *WirePod
	index                   int
	vsBytes                 []byte
	hasHostPath             bool
	hasHostPathType         bool
	hasSecret               bool
	hasSecretDefaultMode    bool
	hasDownwardAPI          bool
	hasDownwardDefaultMode  bool
	hasConfigMap            bool
	hasConfigMapDefaultMode bool
	hasProjected            bool
	hasProjectedDefaultMode bool
}

func newWireVolumeDefaulter(w *WirePod, index int, vBytes []byte) *wireVolumeDefaulter {
	d := &wireVolumeDefaulter{}
	populateWireVolumeDefaulter(d, w, index, vBytes)
	return d
}

func populateWireVolumeDefaulter(d *wireVolumeDefaulter, w *WirePod, index int, vBytes []byte) {
	*d = wireVolumeDefaulter{
		w:     w,
		index: index,
	}
	offset := 0
	for offset < len(vBytes) {
		num, typ, tagLen := protowire.ConsumeTag(vBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, vBytes[offset:])
		if valLen < 0 {
			break
		}
		if num == volumeFieldSource && typ == protowire.BytesType {
			d.vsBytes, _ = protowire.ConsumeBytes(vBytes[offset : offset+valLen])
			break
		}
		offset += valLen
	}

	offset = 0
	for offset < len(d.vsBytes) {
		num, typ, tagLen := protowire.ConsumeTag(d.vsBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, d.vsBytes[offset:])
		if valLen < 0 {
			break
		}
		if typ == protowire.BytesType {
			subContent, _ := protowire.ConsumeBytes(d.vsBytes[offset : offset+valLen])
			switch num {
			case volumeSourceFieldHostPath:
				d.hasHostPath = true
				d.hasHostPathType = lazy.HasField(subContent, hostPathFieldType)
			case volumeSourceFieldSecret:
				d.hasSecret = true
				d.hasSecretDefaultMode = lazy.HasField(subContent, secretFieldDefaultMode)
			case volumeSourceFieldDownwardAPI:
				d.hasDownwardAPI = true
				d.hasDownwardDefaultMode = lazy.HasField(subContent, downwardFieldDefaultMode)
			case volumeSourceFieldConfigMap:
				d.hasConfigMap = true
				d.hasConfigMapDefaultMode = lazy.HasField(subContent, configMapFieldDefaultMode)
			case volumeSourceFieldProjected:
				d.hasProjected = true
				d.hasProjectedDefaultMode = lazy.HasField(subContent, projectedFieldDefaultMode)
			}
		}
		offset += valLen
	}
}

func (d *wireVolumeDefaulter) getOverrides() *volumeOverrides {
	if d.w.defaults == nil || d.w.defaults.spec.volumes == nil {
		return nil
	}
	return d.w.defaults.spec.volumes[d.index]
}

func (d *wireVolumeDefaulter) ensureOverrides() *volumeOverrides {
	sp := d.w.markSpecDefaultDirty()
	if sp.volumes == nil {
		sp.volumes = make(map[int]*volumeOverrides)
	}
	vo := sp.volumes[d.index]
	if vo == nil {
		vo = &volumeOverrides{}
		sp.volumes[d.index] = vo
	}
	return vo
}

func (d *wireVolumeDefaulter) IsVolumeSourceEmpty() bool {
	if vo := d.getOverrides(); vo != nil && vo.setEmptyDir {
		return false
	}
	return len(d.vsBytes) == 0
}

func (d *wireVolumeDefaulter) SetEmptyDirDefault() {
	vo := d.ensureOverrides()
	vo.setEmptyDir = true
}

func (d *wireVolumeDefaulter) HasHostPath() bool { return d.hasHostPath }
func (d *wireVolumeDefaulter) HasHostPathType() bool {
	if vo := d.getOverrides(); vo != nil && vo.setHostPathType {
		return true
	}
	return d.hasHostPathType
}
func (d *wireVolumeDefaulter) SetHostPathType(t v1.HostPathType) {
	vo := d.ensureOverrides()
	vo.setHostPathType = true
	vo.hostPathType = t
}

func (d *wireVolumeDefaulter) HasSecret() bool { return d.hasSecret }
func (d *wireVolumeDefaulter) HasSecretDefaultMode() bool {
	if vo := d.getOverrides(); vo != nil && vo.setSecretDefaultMode {
		return true
	}
	return d.hasSecretDefaultMode
}
func (d *wireVolumeDefaulter) SetSecretDefaultMode(m int32) {
	vo := d.ensureOverrides()
	vo.setSecretDefaultMode = true
	vo.secretDefaultMode = m
}

func (d *wireVolumeDefaulter) HasDownwardAPI() bool { return d.hasDownwardAPI }
func (d *wireVolumeDefaulter) HasDownwardAPIDefaultMode() bool {
	if vo := d.getOverrides(); vo != nil && vo.setDownwardDefaultMode {
		return true
	}
	return d.hasDownwardDefaultMode
}
func (d *wireVolumeDefaulter) SetDownwardAPIDefaultMode(m int32) {
	vo := d.ensureOverrides()
	vo.setDownwardDefaultMode = true
	vo.downwardDefaultMode = m
}

func (d *wireVolumeDefaulter) HasConfigMap() bool { return d.hasConfigMap }
func (d *wireVolumeDefaulter) HasConfigMapDefaultMode() bool {
	if vo := d.getOverrides(); vo != nil && vo.setConfigMapDefaultMode {
		return true
	}
	return d.hasConfigMapDefaultMode
}
func (d *wireVolumeDefaulter) SetConfigMapDefaultMode(m int32) {
	vo := d.ensureOverrides()
	vo.setConfigMapDefaultMode = true
	vo.configMapDefaultMode = m
}

func (d *wireVolumeDefaulter) HasProjected() bool { return d.hasProjected }
func (d *wireVolumeDefaulter) HasProjectedDefaultMode() bool {
	if vo := d.getOverrides(); vo != nil && vo.setProjectedDefaultMode {
		return true
	}
	return d.hasProjectedDefaultMode
}
func (d *wireVolumeDefaulter) SetProjectedDefaultMode(m int32) {
	vo := d.ensureOverrides()
	vo.setProjectedDefaultMode = true
	vo.projectedDefaultMode = m
}

// ============================================================================
// Wire Splicing for Spec & Status Defaulting + Mutations
// ============================================================================

func (w *WirePod) effectiveRaw() []byte {
	hasSpecDef := w.defaults != nil && w.defaults.specDirty
	hasStatDef := w.defaults != nil && w.defaults.statusDirty
	if !hasSpecDef && !hasStatDef && !w.hasNodeNameMod && !w.hasNominatedNodeMod && !w.hasConditionsMod {
		return w.raw
	}

	b := w.raw
	out := make([]byte, 0, len(b)+128)

	needSpec := hasSpecDef || w.hasNodeNameMod
	needStatus := hasStatDef || w.hasNominatedNodeMod || w.hasConditionsMod
	emittedSpec := false
	emittedStatus := false

	offset := 0
	for offset < len(b) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(b[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, b[offset:])
		if valLen < 0 {
			break
		}
		valBytes := b[offset : offset+valLen]
		offset += valLen

		if num == podFieldSpec && typ == protowire.BytesType && needSpec {
			specContent, _ := protowire.ConsumeBytes(valBytes)
			if hasSpecDef {
				specContent = w.spliceSpecDefaults(specContent)
			}
			if w.hasNodeNameMod {
				specContent = spliceSingleStringField(specContent, specFieldNodeName, w.nodeName)
			}
			out = protowire.AppendTag(out, podFieldSpec, protowire.BytesType)
			out = protowire.AppendBytes(out, specContent)
			emittedSpec = true
			continue
		}

		if num > podFieldSpec && needSpec && !emittedSpec {
			var specContent []byte
			if hasSpecDef {
				specContent = w.spliceSpecDefaults(nil)
			}
			if w.hasNodeNameMod {
				specContent = spliceSingleStringField(specContent, specFieldNodeName, w.nodeName)
			}
			out = protowire.AppendTag(out, podFieldSpec, protowire.BytesType)
			out = protowire.AppendBytes(out, specContent)
			emittedSpec = true
		}

		if num == podFieldStatus && typ == protowire.BytesType && needStatus {
			statusContent, _ := protowire.ConsumeBytes(valBytes)
			if hasStatDef {
				statusContent = w.spliceStatusDefaults(statusContent)
			}
			if w.hasNominatedNodeMod {
				statusContent = spliceSingleStringField(statusContent, statusFieldNominatedNodeName, w.nominatedNodeName)
			}
			if w.hasConditionsMod {
				statusContent = spliceRepeatedRawField(statusContent, statusFieldConditions, w.conditionsEncoded)
			}
			out = protowire.AppendTag(out, podFieldStatus, protowire.BytesType)
			out = protowire.AppendBytes(out, statusContent)
			emittedStatus = true
			continue
		}

		out = append(out, b[fieldStart:offset]...)
	}

	if needSpec && !emittedSpec {
		var specContent []byte
		if hasSpecDef {
			specContent = w.spliceSpecDefaults(nil)
		}
		if w.hasNodeNameMod {
			specContent = spliceSingleStringField(specContent, specFieldNodeName, w.nodeName)
		}
		out = protowire.AppendTag(out, podFieldSpec, protowire.BytesType)
		out = protowire.AppendBytes(out, specContent)
	}
	if needStatus && !emittedStatus {
		var statusContent []byte
		if hasStatDef {
			statusContent = w.spliceStatusDefaults(nil)
		}
		if w.hasNominatedNodeMod {
			statusContent = spliceSingleStringField(statusContent, statusFieldNominatedNodeName, w.nominatedNodeName)
		}
		if w.hasConditionsMod {
			statusContent = spliceRepeatedRawField(statusContent, statusFieldConditions, w.conditionsEncoded)
		}
		out = protowire.AppendTag(out, podFieldStatus, protowire.BytesType)
		out = protowire.AppendBytes(out, statusContent)
	}

	return out
}

func (w *WirePod) spliceSpecDefaults(specBytes []byte) []byte {
	sp := &w.defaults.spec
	out := make([]byte, 0, len(specBytes)+96)

	var (
		emittedRestartPolicy      bool
		emittedTermGrace          bool
		emittedDNSPolicy          bool
		emittedServiceAccountName bool
		emittedDeprecatedSA       bool
		emittedSecurityContext    bool
		emittedSchedulerName      bool
		emittedEnableServiceLinks bool
	)

	emitDirtyUpTo := func(limitNum protowire.Number) {
		if sp.hasRestartPolicy && !emittedRestartPolicy && limitNum >= specFieldRestartPolicy {
			out = protowire.AppendTag(out, specFieldRestartPolicy, protowire.BytesType)
			out = protowire.AppendString(out, string(sp.restartPolicy))
			emittedRestartPolicy = true
		}
		if sp.hasTerminationGracePeriodSeconds && !emittedTermGrace && limitNum >= specFieldTerminationGracePeriodSeconds {
			out = protowire.AppendTag(out, specFieldTerminationGracePeriodSeconds, protowire.VarintType)
			out = protowire.AppendVarint(out, uint64(sp.terminationGracePeriodSeconds))
			emittedTermGrace = true
		}
		if sp.hasDNSPolicy && !emittedDNSPolicy && limitNum >= specFieldDNSPolicy {
			out = protowire.AppendTag(out, specFieldDNSPolicy, protowire.BytesType)
			out = protowire.AppendString(out, string(sp.dnsPolicy))
			emittedDNSPolicy = true
		}
		if sp.hasServiceAccountName && !emittedServiceAccountName && limitNum >= specFieldServiceAccountName {
			out = protowire.AppendTag(out, specFieldServiceAccountName, protowire.BytesType)
			out = protowire.AppendString(out, sp.serviceAccountName)
			emittedServiceAccountName = true
		}
		if sp.hasDeprecatedServiceAccount && !emittedDeprecatedSA && limitNum >= specFieldDeprecatedServiceAccount {
			out = protowire.AppendTag(out, specFieldDeprecatedServiceAccount, protowire.BytesType)
			out = protowire.AppendString(out, sp.deprecatedServiceAccount)
			emittedDeprecatedSA = true
		}
		if sp.initEmptySecurityContext && !emittedSecurityContext && limitNum >= specFieldSecurityContext {
			out = protowire.AppendTag(out, specFieldSecurityContext, protowire.BytesType)
			out = protowire.AppendVarint(out, 0)
			emittedSecurityContext = true
		}
		if sp.hasSchedulerName && !emittedSchedulerName && limitNum >= specFieldSchedulerName {
			out = protowire.AppendTag(out, specFieldSchedulerName, protowire.BytesType)
			out = protowire.AppendString(out, sp.schedulerName)
			emittedSchedulerName = true
		}
		if sp.hasEnableServiceLinks && !emittedEnableServiceLinks && limitNum >= specFieldEnableServiceLinks {
			out = protowire.AppendTag(out, specFieldEnableServiceLinks, protowire.VarintType)
			if sp.enableServiceLinks {
				out = protowire.AppendVarint(out, 1)
			} else {
				out = protowire.AppendVarint(out, 0)
			}
			emittedEnableServiceLinks = true
		}
	}

	var volIdx, cIdx, initIdx int
	offset := 0
	for offset < len(specBytes) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(specBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, specBytes[offset:])
		if valLen < 0 {
			break
		}
		valBytes := specBytes[offset : offset+valLen]
		offset += valLen

		emitDirtyUpTo(num)

		switch num {
		case specFieldVolumes:
			idx := volIdx
			volIdx++
			if typ == protowire.BytesType && sp.volumes != nil && sp.volumes[idx] != nil {
				volContent, _ := protowire.ConsumeBytes(valBytes)
				newVol := spliceVolume(volContent, sp.volumes[idx])
				out = protowire.AppendTag(out, specFieldVolumes, protowire.BytesType)
				out = protowire.AppendBytes(out, newVol)
				continue
			}
		case specFieldContainers:
			idx := cIdx
			cIdx++
			if typ == protowire.BytesType && sp.containers != nil && sp.containers[idx] != nil {
				cContent, _ := protowire.ConsumeBytes(valBytes)
				newC := spliceContainer(cContent, sp.containers[idx])
				out = protowire.AppendTag(out, specFieldContainers, protowire.BytesType)
				out = protowire.AppendBytes(out, newC)
				continue
			}
		case specFieldInitContainers:
			idx := initIdx
			initIdx++
			if typ == protowire.BytesType && sp.initContainers != nil && sp.initContainers[idx] != nil {
				cContent, _ := protowire.ConsumeBytes(valBytes)
				newC := spliceContainer(cContent, sp.initContainers[idx])
				out = protowire.AppendTag(out, specFieldInitContainers, protowire.BytesType)
				out = protowire.AppendBytes(out, newC)
				continue
			}
		case specFieldRestartPolicy:
			if sp.hasRestartPolicy {
				continue
			}
		case specFieldTerminationGracePeriodSeconds:
			if sp.hasTerminationGracePeriodSeconds {
				continue
			}
		case specFieldDNSPolicy:
			if sp.hasDNSPolicy {
				continue
			}
		case specFieldServiceAccountName:
			if sp.hasServiceAccountName {
				continue
			}
		case specFieldDeprecatedServiceAccount:
			if sp.hasDeprecatedServiceAccount {
				continue
			}
		case specFieldSecurityContext:
			if sp.initEmptySecurityContext {
				continue
			}
		case specFieldSchedulerName:
			if sp.hasSchedulerName {
				continue
			}
		case specFieldEnableServiceLinks:
			if sp.hasEnableServiceLinks {
				continue
			}
		}

		out = append(out, specBytes[fieldStart:offset]...)
	}

	emitDirtyUpTo(protowire.MaxValidNumber)
	return out
}

func spliceContainer(cBytes []byte, co *containerOverrides) []byte {
	out := make([]byte, 0, len(cBytes)+48)
	var (
		emittedTermMsgPath   bool
		emittedPullPolicy    bool
		emittedTermMsgPolicy bool
	)

	emitDirtyUpTo := func(limitNum protowire.Number) {
		if co.hasTerminationMessagePath && !emittedTermMsgPath && limitNum >= containerFieldTerminationMessagePath {
			out = protowire.AppendTag(out, containerFieldTerminationMessagePath, protowire.BytesType)
			out = protowire.AppendString(out, co.terminationMessagePath)
			emittedTermMsgPath = true
		}
		if co.hasImagePullPolicy && !emittedPullPolicy && limitNum >= containerFieldImagePullPolicy {
			out = protowire.AppendTag(out, containerFieldImagePullPolicy, protowire.BytesType)
			out = protowire.AppendString(out, string(co.imagePullPolicy))
			emittedPullPolicy = true
		}
		if co.hasTerminationMessagePolicy && !emittedTermMsgPolicy && limitNum >= containerFieldTerminationMessagePolicy {
			out = protowire.AppendTag(out, containerFieldTerminationMessagePolicy, protowire.BytesType)
			out = protowire.AppendString(out, string(co.terminationMessagePolicy))
			emittedTermMsgPolicy = true
		}
	}

	var portIdx int
	offset := 0
	for offset < len(cBytes) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(cBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, cBytes[offset:])
		if valLen < 0 {
			break
		}
		valBytes := cBytes[offset : offset+valLen]
		offset += valLen

		emitDirtyUpTo(num)

		switch num {
		case containerFieldPorts:
			idx := portIdx
			portIdx++
			if typ == protowire.BytesType && co.ports != nil && co.ports[idx] != nil {
				pContent, _ := protowire.ConsumeBytes(valBytes)
				newP := spliceContainerPort(pContent, co.ports[idx])
				out = protowire.AppendTag(out, containerFieldPorts, protowire.BytesType)
				out = protowire.AppendBytes(out, newP)
				continue
			}
		case containerFieldResources:
			if typ == protowire.BytesType && co.copyLimitsToRequests {
				rContent, _ := protowire.ConsumeBytes(valBytes)
				newR := spliceResourceRequirements(rContent)
				out = protowire.AppendTag(out, containerFieldResources, protowire.BytesType)
				out = protowire.AppendBytes(out, newR)
				continue
			}
		case containerFieldTerminationMessagePath:
			if co.hasTerminationMessagePath {
				continue
			}
		case containerFieldImagePullPolicy:
			if co.hasImagePullPolicy {
				continue
			}
		case containerFieldTerminationMessagePolicy:
			if co.hasTerminationMessagePolicy {
				continue
			}
		}

		out = append(out, cBytes[fieldStart:offset]...)
	}

	emitDirtyUpTo(protowire.MaxValidNumber)
	return out
}

func spliceContainerPort(pBytes []byte, po *portOverrides) []byte {
	out := make([]byte, 0, len(pBytes)+8)
	var (
		emittedHostPort bool
		emittedProtocol bool
	)

	emitDirtyUpTo := func(limitNum protowire.Number) {
		if po.hasHostPort && !emittedHostPort && limitNum >= portFieldHostPort {
			out = protowire.AppendTag(out, portFieldHostPort, protowire.VarintType)
			out = protowire.AppendVarint(out, uint64(po.hostPort))
			emittedHostPort = true
		}
		if po.hasProtocol && !emittedProtocol && limitNum >= portFieldProtocol {
			out = protowire.AppendTag(out, portFieldProtocol, protowire.BytesType)
			out = protowire.AppendString(out, string(po.protocol))
			emittedProtocol = true
		}
	}

	offset := 0
	for offset < len(pBytes) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(pBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, pBytes[offset:])
		if valLen < 0 {
			break
		}
		offset += valLen

		emitDirtyUpTo(num)

		switch num {
		case portFieldHostPort:
			if po.hasHostPort {
				continue
			}
		case portFieldProtocol:
			if po.hasProtocol {
				continue
			}
		}
		out = append(out, pBytes[fieldStart:offset]...)
	}

	emitDirtyUpTo(protowire.MaxValidNumber)
	return out
}

type rawMapEntry struct {
	key     string
	payload []byte
}

func resourcesNeedDefaulting(rBytes []byte) bool {
	if len(rBytes) == 0 {
		return false
	}
	offset := 0
	for offset < len(rBytes) {
		num, typ, tagLen := protowire.ConsumeTag(rBytes[offset:])
		if tagLen < 0 {
			return false
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, rBytes[offset:])
		if valLen < 0 {
			return false
		}
		valBytes := rBytes[offset : offset+valLen]
		offset += valLen

		if num == resFieldLimits && typ == protowire.BytesType {
			entry, _ := protowire.ConsumeBytes(valBytes)
			k := lazy.ExtractFirstStringFieldNoCopy(entry, lazy.MapEntryKeyFieldNumber)
			if !hasResourceEntryKey(rBytes, resFieldRequests, k) {
				return true
			}
		}
	}
	return false
}

func hasResourceEntryKey(rBytes []byte, fieldNum protowire.Number, targetKey string) bool {
	offset := 0
	for offset < len(rBytes) {
		num, typ, tagLen := protowire.ConsumeTag(rBytes[offset:])
		if tagLen < 0 {
			return false
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, rBytes[offset:])
		if valLen < 0 {
			return false
		}
		if num == fieldNum && typ == protowire.BytesType {
			entry, _ := protowire.ConsumeBytes(rBytes[offset : offset+valLen])
			if lazy.ExtractFirstStringFieldNoCopy(entry, lazy.MapEntryKeyFieldNumber) == targetKey {
				return true
			}
		}
		offset += valLen
	}
	return false
}

func spliceResourceRequirements(rBytes []byte) []byte {
	if len(rBytes) == 0 {
		return rBytes
	}
	var limits []rawMapEntry
	requests := make(map[string][]byte)

	offset := 0
	for offset < len(rBytes) {
		num, typ, tagLen := protowire.ConsumeTag(rBytes[offset:])
		if tagLen < 0 {
			return rBytes
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, rBytes[offset:])
		if valLen < 0 {
			return rBytes
		}
		valBytes := rBytes[offset : offset+valLen]
		offset += valLen

		switch num {
		case resFieldLimits:
			if typ == protowire.BytesType {
				entry, _ := protowire.ConsumeBytes(valBytes)
				k := lazy.ExtractFirstStringFieldNoCopy(entry, lazy.MapEntryKeyFieldNumber)
				limits = append(limits, rawMapEntry{key: k, payload: entry})
			}
		case resFieldRequests:
			if typ == protowire.BytesType {
				entry, _ := protowire.ConsumeBytes(valBytes)
				k := lazy.ExtractFirstStringFieldNoCopy(entry, lazy.MapEntryKeyFieldNumber)
				requests[k] = entry
			}
		}
	}

	var missing []rawMapEntry
	for _, lim := range limits {
		if _, ok := requests[lim.key]; !ok {
			missing = append(missing, lim)
		}
	}
	if len(missing) == 0 {
		return rBytes
	}

	out := make([]byte, 0, len(rBytes)+len(missing)*24)
	out = append(out, rBytes...)
	for _, m := range missing {
		out = protowire.AppendTag(out, resFieldRequests, protowire.BytesType)
		out = protowire.AppendBytes(out, m.payload)
	}
	return out
}

func spliceVolume(vBytes []byte, vo *volumeOverrides) []byte {
	out := make([]byte, 0, len(vBytes)+24)
	hasVS := false
	offset := 0
	for offset < len(vBytes) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(vBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, vBytes[offset:])
		if valLen < 0 {
			break
		}
		valBytes := vBytes[offset : offset+valLen]
		offset += valLen

		if num == volumeFieldSource && typ == protowire.BytesType {
			hasVS = true
			vsContent, _ := protowire.ConsumeBytes(valBytes)
			newVS := spliceVolumeSource(vsContent, vo)
			out = protowire.AppendTag(out, volumeFieldSource, protowire.BytesType)
			out = protowire.AppendBytes(out, newVS)
			continue
		}
		out = append(out, vBytes[fieldStart:offset]...)
	}
	if !hasVS && vo.setEmptyDir {
		newVS := spliceVolumeSource(nil, vo)
		out = protowire.AppendTag(out, volumeFieldSource, protowire.BytesType)
		out = protowire.AppendBytes(out, newVS)
	}
	return out
}

func spliceVolumeSource(vsBytes []byte, vo *volumeOverrides) []byte {
	if vo.setEmptyDir {
		var out []byte
		out = protowire.AppendTag(out, volumeSourceFieldEmptyDir, protowire.BytesType)
		out = protowire.AppendBytes(out, []byte{0x0a, 0x00})
		return out
	}

	out := make([]byte, 0, len(vsBytes)+16)
	offset := 0
	for offset < len(vsBytes) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(vsBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, vsBytes[offset:])
		if valLen < 0 {
			break
		}
		valBytes := vsBytes[offset : offset+valLen]
		offset += valLen

		if typ == protowire.BytesType {
			subContent, _ := protowire.ConsumeBytes(valBytes)
			switch num {
			case volumeSourceFieldHostPath:
				if vo.setHostPathType {
					newSub := append([]byte(nil), subContent...)
					newSub = protowire.AppendTag(newSub, hostPathFieldType, protowire.BytesType)
					newSub = protowire.AppendString(newSub, string(vo.hostPathType))
					out = protowire.AppendTag(out, volumeSourceFieldHostPath, protowire.BytesType)
					out = protowire.AppendBytes(out, newSub)
					continue
				}
			case volumeSourceFieldSecret:
				if vo.setSecretDefaultMode {
					newSub := spliceInt32FieldInOrder(subContent, secretFieldDefaultMode, vo.secretDefaultMode)
					out = protowire.AppendTag(out, volumeSourceFieldSecret, protowire.BytesType)
					out = protowire.AppendBytes(out, newSub)
					continue
				}
			case volumeSourceFieldDownwardAPI:
				if vo.setDownwardDefaultMode {
					newSub := spliceInt32FieldInOrder(subContent, downwardFieldDefaultMode, vo.downwardDefaultMode)
					out = protowire.AppendTag(out, volumeSourceFieldDownwardAPI, protowire.BytesType)
					out = protowire.AppendBytes(out, newSub)
					continue
				}
			case volumeSourceFieldConfigMap:
				if vo.setConfigMapDefaultMode {
					newSub := spliceInt32FieldInOrder(subContent, configMapFieldDefaultMode, vo.configMapDefaultMode)
					out = protowire.AppendTag(out, volumeSourceFieldConfigMap, protowire.BytesType)
					out = protowire.AppendBytes(out, newSub)
					continue
				}
			case volumeSourceFieldProjected:
				if vo.setProjectedDefaultMode || len(vo.projectedDownwardDefault) > 0 {
					newSub := spliceProjectedVolumeSource(subContent, vo)
					out = protowire.AppendTag(out, volumeSourceFieldProjected, protowire.BytesType)
					out = protowire.AppendBytes(out, newSub)
					continue
				}
			}
		}
		out = append(out, vsBytes[fieldStart:offset]...)
	}
	return out
}

func spliceInt32FieldInOrder(msgBytes []byte, fieldNum protowire.Number, val int32) []byte {
	out := make([]byte, 0, len(msgBytes)+8)
	emitted := false
	offset := 0
	for offset < len(msgBytes) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(msgBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, msgBytes[offset:])
		if valLen < 0 {
			break
		}
		offset += valLen

		if !emitted && num >= fieldNum {
			out = protowire.AppendTag(out, fieldNum, protowire.VarintType)
			out = protowire.AppendVarint(out, uint64(val))
			emitted = true
		}
		if num == fieldNum {
			continue
		}
		out = append(out, msgBytes[fieldStart:offset]...)
	}
	if !emitted {
		out = protowire.AppendTag(out, fieldNum, protowire.VarintType)
		out = protowire.AppendVarint(out, uint64(val))
	}
	return out
}

func spliceProjectedVolumeSource(projBytes []byte, vo *volumeOverrides) []byte {
	out := make([]byte, 0, len(projBytes)+16)
	emittedDefaultMode := false
	srcIdx := 0
	offset := 0
	for offset < len(projBytes) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(projBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, projBytes[offset:])
		if valLen < 0 {
			break
		}
		valBytes := projBytes[offset : offset+valLen]
		offset += valLen

		if vo.setProjectedDefaultMode && !emittedDefaultMode && num >= projectedFieldDefaultMode {
			out = protowire.AppendTag(out, projectedFieldDefaultMode, protowire.VarintType)
			out = protowire.AppendVarint(out, uint64(vo.projectedDefaultMode))
			emittedDefaultMode = true
		}

		if num == projectedFieldSources && typ == protowire.BytesType {
			idx := srcIdx
			srcIdx++
			if vo.projectedDownwardDefault != nil && len(vo.projectedDownwardDefault[idx]) > 0 {
				srcContent, _ := protowire.ConsumeBytes(valBytes)
				newSrc := spliceProjectedSourceDownward(srcContent, vo.projectedDownwardDefault[idx])
				out = protowire.AppendTag(out, projectedFieldSources, protowire.BytesType)
				out = protowire.AppendBytes(out, newSrc)
				continue
			}
		}
		if num == projectedFieldDefaultMode && vo.setProjectedDefaultMode {
			continue
		}
		out = append(out, projBytes[fieldStart:offset]...)
	}
	if vo.setProjectedDefaultMode && !emittedDefaultMode {
		out = protowire.AppendTag(out, projectedFieldDefaultMode, protowire.VarintType)
		out = protowire.AppendVarint(out, uint64(vo.projectedDefaultMode))
	}
	return out
}

func spliceProjectedSourceDownward(srcBytes []byte, itemModes map[int]bool) []byte {
	out := make([]byte, 0, len(srcBytes)+16)
	offset := 0
	for offset < len(srcBytes) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(srcBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, srcBytes[offset:])
		if valLen < 0 {
			break
		}
		valBytes := srcBytes[offset : offset+valLen]
		offset += valLen

		if num == volProjectionFieldDownwardAPI && typ == protowire.BytesType {
			downContent, _ := protowire.ConsumeBytes(valBytes)
			newDown := spliceDownwardProjectionItems(downContent, itemModes)
			out = protowire.AppendTag(out, volProjectionFieldDownwardAPI, protowire.BytesType)
			out = protowire.AppendBytes(out, newDown)
			continue
		}
		out = append(out, srcBytes[fieldStart:offset]...)
	}
	return out
}

func spliceDownwardProjectionItems(downBytes []byte, itemModes map[int]bool) []byte {
	out := make([]byte, 0, len(downBytes)+16)
	itemIdx := 0
	offset := 0
	for offset < len(downBytes) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(downBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, downBytes[offset:])
		if valLen < 0 {
			break
		}
		valBytes := downBytes[offset : offset+valLen]
		offset += valLen

		if num == downwardProjFieldItems && typ == protowire.BytesType {
			idx := itemIdx
			itemIdx++
			if itemModes[idx] {
				itemContent, _ := protowire.ConsumeBytes(valBytes)
				newItem := spliceInt32FieldInOrder(itemContent, downwardFileFieldMode, v1.DownwardAPIVolumeSourceDefaultMode)
				out = protowire.AppendTag(out, downwardProjFieldItems, protowire.BytesType)
				out = protowire.AppendBytes(out, newItem)
				continue
			}
		}
		out = append(out, downBytes[fieldStart:offset]...)
	}
	return out
}

func (w *WirePod) spliceStatusDefaults(statusBytes []byte) []byte {
	st := &w.defaults.status
	out := make([]byte, 0, len(statusBytes)+32)
	emittedPodIP := false
	emittedPodIPs := false

	emitDirtyUpTo := func(limitNum protowire.Number) {
		if st.hasPodIP && !emittedPodIP && limitNum >= statusFieldPodIP {
			out = protowire.AppendTag(out, statusFieldPodIP, protowire.BytesType)
			out = protowire.AppendString(out, st.podIP)
			emittedPodIP = true
		}
		if st.hasSinglePodIP && !emittedPodIPs && limitNum >= statusFieldPodIPs {
			var ipMsg []byte
			ipMsg = protowire.AppendTag(ipMsg, podIPFieldIP, protowire.BytesType)
			ipMsg = protowire.AppendString(ipMsg, st.singlePodIP)
			out = protowire.AppendTag(out, statusFieldPodIPs, protowire.BytesType)
			out = protowire.AppendBytes(out, ipMsg)
			emittedPodIPs = true
		}
	}

	offset := 0
	for offset < len(statusBytes) {
		fieldStart := offset
		num, typ, tagLen := protowire.ConsumeTag(statusBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, statusBytes[offset:])
		if valLen < 0 {
			break
		}
		offset += valLen

		emitDirtyUpTo(num)

		if num == statusFieldPodIP && st.hasPodIP {
			continue
		}
		if num == statusFieldPodIPs && st.hasSinglePodIP {
			continue
		}
		out = append(out, statusBytes[fieldStart:offset]...)
	}

	emitDirtyUpTo(protowire.MaxValidNumber)
	return out
}

// SerializedSize returns the exact Protobuf wire size of the Pod, accounting for any pending
// defaults, modifications, and ObjectMeta mutations without mutating w.
func (w *WirePod) SerializedSize() int {
	if w == nil {
		return 0
	}
	return w.meta.SerializedSize(w.effectiveRaw())
}

// MarshalToSizedBuffer writes the v1.Pod wire bytes to the end of dAtA, splicing pending
// defaults, modifications, and ObjectMeta mutations directly into dAtA without mutating w.
func (w *WirePod) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	if w == nil {
		return 0, nil
	}
	return w.meta.MarshalToSizedBuffer(dAtA, w.effectiveRaw())
}

// Bytes returns the v1.Pod Protobuf wire bytes with any modified fields spliced in without mutating w.
func (w *WirePod) Bytes() []byte {
	if w == nil {
		return nil
	}
	raw := w.effectiveRaw()
	if !w.meta.IsDirty() {
		return raw
	}
	buf := make([]byte, w.meta.SerializedSize(raw))
	_, _ = w.meta.MarshalToSizedBuffer(buf, raw)
	return buf
}

// DecodeToV1Pod unmarshals the wire bytes into a *v1.Pod, applying any pending ObjectMeta mutations.
func (w *WirePod) DecodeToV1Pod() (*v1.Pod, error) {
	raw := w.effectiveRaw()
	v1Pod := &v1.Pod{}
	if err := v1Pod.Unmarshal(raw); err != nil {
		return nil, err
	}
	w.meta.ApplyToObjectMeta(&v1Pod.ObjectMeta)
	if w.statusEmptySlices&statusEmptyResourceClaimStatuses != 0 && v1Pod.Status.ResourceClaimStatuses == nil {
		v1Pod.Status.ResourceClaimStatuses = []v1.PodResourceClaimStatus{}
	}
	if w.statusEmptySlices&statusEmptyNodeAllocatableClaimStatuses != 0 && v1Pod.Status.NodeAllocatableResourceClaimStatuses == nil {
		v1Pod.Status.NodeAllocatableResourceClaimStatuses = []v1.NodeAllocatableResourceClaimStatus{}
	}
	return v1Pod, nil
}

// AssembleWirePod constructs a WirePod directly from pre-encoded metadata, spec, and status sub-messages
// using the canonical v1.Pod Protobuf tag layout without decoding or re-encoding specBytes.
func AssembleWirePod(metaBytes, specBytes, statusBytes []byte) *WirePod {
	raw := make([]byte, 0, len(metaBytes)+len(specBytes)+len(statusBytes)+18)
	raw = protowire.AppendTag(raw, podFieldMetadata, protowire.BytesType)
	raw = protowire.AppendBytes(raw, metaBytes)
	raw = protowire.AppendTag(raw, podFieldSpec, protowire.BytesType)
	raw = protowire.AppendBytes(raw, specBytes)
	raw = protowire.AppendTag(raw, podFieldStatus, protowire.BytesType)
	raw = protowire.AppendBytes(raw, statusBytes)
	return NewWirePod(raw)
}

// ReplaceSubMessages builds a new WirePod replacing metadata and/or status when non-nil while keeping specBytes intact.
func (w *WirePod) ReplaceSubMessages(meta *metav1.ObjectMeta, specBytes []byte, status *v1.PodStatus) (*WirePod, error) {
	var metaBytes []byte
	var err error
	if meta != nil {
		metaBytes, err = meta.Marshal()
		if err != nil {
			return nil, err
		}
	} else {
		metaBytes = w.EffectiveSubMessage(podFieldMetadata)
	}
	var statusBytes []byte
	var emptySlices uint8
	var cachedSt *v1.PodStatus
	if status != nil {
		if status.ResourceClaimStatuses != nil && len(status.ResourceClaimStatuses) == 0 {
			emptySlices |= statusEmptyResourceClaimStatuses
		}
		if status.NodeAllocatableResourceClaimStatuses != nil && len(status.NodeAllocatableResourceClaimStatuses) == 0 {
			emptySlices |= statusEmptyNodeAllocatableClaimStatuses
		}
		statusBytes, err = status.Marshal()
		if err != nil {
			return nil, err
		}
		cachedSt = status.DeepCopy()
	} else {
		statusBytes = w.EffectiveSubMessage(podFieldStatus)
		emptySlices = w.statusEmptySlices
		if (w.defaults == nil || !w.defaults.statusDirty) && !w.hasNominatedNodeMod && !w.hasConditionsMod {
			cachedSt = w.cachedStatus
		}
	}
	nw := AssembleWirePod(metaBytes, specBytes, statusBytes)
	nw.statusEmptySlices = emptySlices
	nw.cachedStatus = cachedSt
	return nw, nil
}

// ExtractObjectMetaForUpdate unmarshals ObjectMeta from the wire, eliding ManagedFields (tag 17)
// on both wire bytes and dirty overrides when dropManagedFields is true.
func (w *WirePod) ExtractObjectMetaForUpdate(out *metav1.ObjectMeta, dropManagedFields bool) {
	if w == nil {
		return
	}
	if dropManagedFields {
		w.meta.ExtractObjectMetaWithoutManagedFieldsInto(w.meta.Bytes(), out)
		return
	}
	w.meta.ExtractObjectMetaInto(w.meta.Bytes(), out)
}

// CacheDecodedStatus stores a decoded PodStatus on w for reuse across validation steps when
// w has no pending wire-level status overrides.
func (w *WirePod) CacheDecodedStatus(status *v1.PodStatus) {
	if w == nil || status == nil || w.cachedStatus != nil {
		return
	}
	if (w.defaults != nil && w.defaults.statusDirty) || w.hasNominatedNodeMod || w.hasConditionsMod {
		return
	}
	w.cachedStatus = status
}

// ExtractV1StatusInto unmarshals only PodStatus (tag 3) from w without decoding PodSpec.
func (w *WirePod) ExtractV1StatusInto(out *v1.PodStatus) error {
	if w == nil {
		return nil
	}
	if w.cachedStatus != nil && (w.defaults == nil || !w.defaults.statusDirty) && !w.hasNominatedNodeMod && !w.hasConditionsMod {
		w.cachedStatus.DeepCopyInto(out)
		return nil
	}
	statusBytes := w.EffectiveSubMessage(podFieldStatus)
	if len(statusBytes) > 0 {
		if err := out.Unmarshal(statusBytes); err != nil {
			return err
		}
	}
	if w.statusEmptySlices&statusEmptyResourceClaimStatuses != 0 && out.ResourceClaimStatuses == nil {
		out.ResourceClaimStatuses = []v1.PodResourceClaimStatus{}
	}
	if w.statusEmptySlices&statusEmptyNodeAllocatableClaimStatuses != 0 && out.NodeAllocatableResourceClaimStatuses == nil {
		out.NodeAllocatableResourceClaimStatuses = []v1.NodeAllocatableResourceClaimStatus{}
	}
	return nil
}

// ExtractCoreStatusInto unmarshals only PodStatus (tag 3) into a core.PodStatus without decoding PodSpec.
func (w *WirePod) ExtractCoreStatusInto(out *core.PodStatus) error {
	return w.ExtractV1StatusInto((*v1.PodStatus)(unsafe.Pointer(out)))
}

// SpecOS extracts spec.os from the wire without decoding PodSpec.
func (w *WirePod) SpecOS() *core.PodOS {
	if w == nil {
		return nil
	}
	specBytes := w.subMessage(podFieldSpec)
	offset := 0
	for offset < len(specBytes) {
		num, typ, tagLen := protowire.ConsumeTag(specBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, specBytes[offset:])
		if valLen < 0 {
			break
		}
		if num == specFieldOS && typ == protowire.BytesType {
			osBytes, _ := protowire.ConsumeBytes(specBytes[offset : offset+valLen])
			return &core.PodOS{Name: core.OSName(lazy.ExtractFirstStringField(osBytes, osFieldName))}
		}
		offset += valLen
	}
	return nil
}

// StatusPodIPs extracts status.podIPs from the wire without decoding the pod.
func (w *WirePod) StatusPodIPs() []core.PodIP {
	if w == nil {
		return nil
	}
	if w.defaults != nil && w.defaults.status.hasSinglePodIP {
		return []core.PodIP{{IP: w.defaults.status.singlePodIP}}
	}
	statusBytes := w.subMessage(podFieldStatus)
	var ips []core.PodIP
	offset := 0
	for offset < len(statusBytes) {
		num, typ, tagLen := protowire.ConsumeTag(statusBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, statusBytes[offset:])
		if valLen < 0 {
			break
		}
		if num == statusFieldPodIPs && typ == protowire.BytesType {
			sub, _ := protowire.ConsumeBytes(statusBytes[offset : offset+valLen])
			ips = append(ips, core.PodIP{IP: lazy.ExtractFirstStringField(sub, podIPFieldIP)})
		}
		offset += valLen
	}
	return ips
}

// StatusHostIPs extracts status.hostIPs from the wire without decoding the pod.
func (w *WirePod) StatusHostIPs() []core.HostIP {
	if w == nil {
		return nil
	}
	statusBytes := w.subMessage(podFieldStatus)
	var ips []core.HostIP
	offset := 0
	for offset < len(statusBytes) {
		num, typ, tagLen := protowire.ConsumeTag(statusBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, statusBytes[offset:])
		if valLen < 0 {
			break
		}
		if num == statusFieldHostIPs && typ == protowire.BytesType {
			sub, _ := protowire.ConsumeBytes(statusBytes[offset : offset+valLen])
			ips = append(ips, core.HostIP{IP: lazy.ExtractFirstStringField(sub, hostIPFieldIP)})
		}
		offset += valLen
	}
	return ips
}

// HasDefaultFaultTolerations reports whether spec.tolerations on the wire already tolerates
// both notReadyKey:NoExecute and unreachableKey:NoExecute without decoding PodSpec.
func (w *WirePod) HasDefaultFaultTolerations(notReadyKey, unreachableKey string) bool {
	if w == nil {
		return false
	}
	specBytes := w.EffectiveSubMessage(podFieldSpec)
	hasNotReady := false
	hasUnreachable := false
	offset := 0
	for offset < len(specBytes) {
		num, typ, tagLen := protowire.ConsumeTag(specBytes[offset:])
		if tagLen < 0 {
			break
		}
		offset += tagLen
		valLen := protowire.ConsumeFieldValue(num, typ, specBytes[offset:])
		if valLen < 0 {
			break
		}
		if num == specFieldTolerations && typ == protowire.BytesType {
			tBytes, _ := protowire.ConsumeBytes(specBytes[offset : offset+valLen])
			key := lazy.ExtractFirstStringFieldNoCopy(tBytes, 1)
			effect := lazy.ExtractFirstStringFieldNoCopy(tBytes, 4)
			if effect == string(core.TaintEffectNoExecute) || len(effect) == 0 {
				if key == notReadyKey || len(key) == 0 {
					hasNotReady = true
				}
				if key == unreachableKey || len(key) == 0 {
					hasUnreachable = true
				}
				if hasNotReady && hasUnreachable {
					return true
				}
			}
		}
		offset += valLen
	}
	return false
}

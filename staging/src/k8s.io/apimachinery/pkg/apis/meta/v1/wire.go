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

package v1

// RawStorageWire holds pre-parsed protobuf wire slices of a stored object so
// Get and metadata-scoped Patch can splice wire bytes directly without
// unmarshaling or marshaling untouched sub-messages (Annotations, Spec, Status).
type RawStorageWire struct {
	Envelope       []byte
	EnvelopePrefix []byte
	EnvelopeSuffix []byte
	MetaRaw        []byte
	MetaFixedRaw   []byte
	RestRaw        []byte
	MetaModified   bool
	DecodeFullInto func(obj interface{}) error
}

// WithMetaModified returns a shallow copy marked as having modified Labels/ManagedFields.
func (w *RawStorageWire) WithMetaModified() *RawStorageWire {
	if w == nil {
		return nil
	}
	cp := *w
	cp.MetaModified = true
	return &cp
}

// MarshalToEnvelope splices the current ObjectMeta (ResourceVersion, and if MetaModified,
// Labels + ManagedFields) with the untouched wire slices (Annotations, Spec, Status) into
// a complete Kubernetes protobuf envelope (k8s\x00 + runtime.Unknown).
func (w *RawStorageWire) MarshalToEnvelope(meta *ObjectMeta, alloc func(uint64) []byte) ([]byte, error) {
	metaRaw := w.MetaRaw
	if w.MetaModified {
		labelsSize := 0
		for k, v := range meta.Labels {
			entryLen := 1 + sovWire(uint64(len(k))) + len(k) + 1 + sovWire(uint64(len(v))) + len(v)
			labelsSize += 1 + sovWire(uint64(entryLen)) + entryLen
		}
		mfSizeTotal := 0
		for i := range meta.ManagedFields {
			sz := meta.ManagedFields[i].Size()
			mfSizeTotal += 2 + sovWire(uint64(sz)) + sz
		}
		newMetaRawLen := len(w.MetaFixedRaw) + labelsSize + mfSizeTotal
		newMetaRaw := make([]byte, newMetaRawLen)
		pos := copy(newMetaRaw, w.MetaFixedRaw)
		for k, v := range meta.Labels {
			entryLen := 1 + sovWire(uint64(len(k))) + len(k) + 1 + sovWire(uint64(len(v))) + len(v)
			newMetaRaw[pos] = 0x5a // field 11 (labels), wireType 2
			pos++
			pos = putVarintWire(newMetaRaw, pos, uint64(entryLen))
			newMetaRaw[pos] = 0x0a // field 1 (key), wireType 2
			pos++
			pos = putVarintWire(newMetaRaw, pos, uint64(len(k)))
			pos += copy(newMetaRaw[pos:], k)
			newMetaRaw[pos] = 0x12 // field 2 (value), wireType 2
			pos++
			pos = putVarintWire(newMetaRaw, pos, uint64(len(v)))
			pos += copy(newMetaRaw[pos:], v)
		}
		for i := range meta.ManagedFields {
			sz := meta.ManagedFields[i].Size()
			newMetaRaw[pos] = 0x8a // field 17 (managedFields), wireType 2 (2-byte tag: 0x8a 0x01)
			newMetaRaw[pos+1] = 0x01
			pos += 2
			pos = putVarintWire(newMetaRaw, pos, uint64(sz))
			n, err := meta.ManagedFields[i].MarshalToSizedBuffer(newMetaRaw[pos : pos+sz])
			if err != nil {
				return nil, err
			}
			pos += n
		}
		metaRaw = newMetaRaw
	}

	rv := meta.ResourceVersion
	if !w.MetaModified && rv == "" && len(w.Envelope) > 0 {
		return w.Envelope, nil
	}

	rvFieldLen := 0
	if rv != "" {
		rvFieldLen = 1 + sovWire(uint64(len(rv))) + len(rv)
	}
	totalMetaLen := len(metaRaw) + rvFieldLen
	totalRawLen := 1 + sovWire(uint64(totalMetaLen)) + totalMetaLen + len(w.RestRaw)
	totalEnvelopeLen := len(w.EnvelopePrefix) + 1 + sovWire(uint64(totalRawLen)) + totalRawLen + len(w.EnvelopeSuffix)

	var buf []byte
	if alloc != nil {
		buf = alloc(uint64(totalEnvelopeLen))
	} else {
		buf = make([]byte, totalEnvelopeLen)
	}

	pos := copy(buf, w.EnvelopePrefix)
	buf[pos] = 0x12 // field 2 of Unknown (Raw), wireType 2
	pos++
	pos = putVarintWire(buf, pos, uint64(totalRawLen))
	buf[pos] = 0x0a // field 1 of Pod (ObjectMeta), wireType 2
	pos++
	pos = putVarintWire(buf, pos, uint64(totalMetaLen))
	pos += copy(buf[pos:], metaRaw)
	if rv != "" {
		buf[pos] = 0x32 // field 6 of ObjectMeta (resourceVersion), wireType 2
		pos++
		pos = putVarintWire(buf, pos, uint64(len(rv)))
		pos += copy(buf[pos:], rv)
	}
	pos += copy(buf[pos:], w.RestRaw)
	pos += copy(buf[pos:], w.EnvelopeSuffix)

	if w.MetaModified && rv == "" {
		meta.LazyWire = &RawStorageWire{
			Envelope:       buf[:pos],
			EnvelopePrefix: w.EnvelopePrefix,
			EnvelopeSuffix: w.EnvelopeSuffix,
			MetaRaw:        metaRaw,
			MetaFixedRaw:   w.MetaFixedRaw,
			RestRaw:        w.RestRaw,
			MetaModified:   false,
			DecodeFullInto: w.DecodeFullInto,
		}
	}
	return buf[:pos], nil
}

func sovWire(x uint64) int {
	n := 1
	for x >= 1<<7 {
		x >>= 7
		n++
	}
	return n
}

func putVarintWire(buf []byte, pos int, v uint64) int {
	for v >= 1<<7 {
		buf[pos] = uint8(v&0x7f | 0x80)
		v >>= 7
		pos++
	}
	buf[pos] = uint8(v)
	return pos + 1
}

// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package viewtypes

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	binaryMagic     byte = 0x56 // 'V'
	binaryVersion   byte = 0x01
	typeIDConfigMap byte = 0x01
	typeIDSecret    byte = 0x02
	typeIDHTTPRoute byte = 0x03
)

// binWriter is a helper for serializing fields into a byte buffer.
type binWriter struct {
	buf []byte
}

func (w *binWriter) writeByte(b byte) {
	w.buf = append(w.buf, b)
}

func (w *binWriter) writeUvarint(v uint64) {
	var tmp [10]byte
	n := binary.PutUvarint(tmp[:], v)
	w.buf = append(w.buf, tmp[:n]...)
}

func (w *binWriter) writeVarint(v int64) {
	var tmp [10]byte
	n := binary.PutVarint(tmp[:], v)
	w.buf = append(w.buf, tmp[:n]...)
}

func (w *binWriter) writeString(s string) {
	w.writeUvarint(uint64(len(s)))
	w.buf = append(w.buf, s...)
}

func (w *binWriter) writeBytes(b []byte) {
	w.writeUvarint(uint64(len(b)))
	w.buf = append(w.buf, b...)
}

func (w *binWriter) writeStringMap(m map[string]string) {
	w.writeUvarint(uint64(len(m)))
	for k, v := range m {
		w.writeString(k)
		w.writeString(v)
	}
}

func (w *binWriter) writeBytesMap(m map[string][]byte) {
	w.writeUvarint(uint64(len(m)))
	for k, v := range m {
		w.writeString(k)
		w.writeBytes(v)
	}
}

// binReader is a bounds-checked helper for deserializing fields from a byte slice.
type binReader struct {
	data []byte
	pos  int
}

func (r *binReader) readByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}
	b := r.data[r.pos]
	r.pos++
	return b, nil
}

func (r *binReader) readUvarint() (uint64, error) {
	v, n := binary.Uvarint(r.data[r.pos:])
	if n <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	r.pos += n
	return v, nil
}

func (r *binReader) readVarint() (int64, error) {
	v, n := binary.Varint(r.data[r.pos:])
	if n <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	r.pos += n
	return v, nil
}

func (r *binReader) readString() (string, error) {
	length, err := r.readUvarint()
	if err != nil {
		return "", err
	}
	end := r.pos + int(length)
	if end > len(r.data) {
		return "", io.ErrUnexpectedEOF
	}
	s := string(r.data[r.pos:end])
	r.pos = end
	return s, nil
}

func (r *binReader) readBytes() ([]byte, error) {
	length, err := r.readUvarint()
	if err != nil {
		return nil, err
	}
	end := r.pos + int(length)
	if end > len(r.data) {
		return nil, io.ErrUnexpectedEOF
	}
	b := make([]byte, length)
	copy(b, r.data[r.pos:end])
	r.pos = end
	return b, nil
}

func (r *binReader) readStringMap() (map[string]string, error) {
	count, err := r.readUvarint()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	m := make(map[string]string, count)
	for i := uint64(0); i < count; i++ {
		k, err := r.readString()
		if err != nil {
			return nil, err
		}
		v, err := r.readString()
		if err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, nil
}

func (r *binReader) readBytesMap() (map[string][]byte, error) {
	count, err := r.readUvarint()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	m := make(map[string][]byte, count)
	for i := uint64(0); i < count; i++ {
		k, err := r.readString()
		if err != nil {
			return nil, err
		}
		v, err := r.readBytes()
		if err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, nil
}

func writeCommonMeta(w *binWriter, name, namespace string, uid types.UID, rv string, gen int64, ct metav1.Time, labels, annotations map[string]string) {
	w.writeString(name)
	w.writeString(namespace)
	w.writeString(string(uid))
	w.writeString(rv)
	w.writeVarint(gen)
	w.writeVarint(ct.Unix())
	w.writeVarint(int64(ct.Nanosecond()))
	w.writeStringMap(labels)
	w.writeStringMap(annotations)
}

func readCommonMeta(r *binReader) (name, namespace string, uid types.UID, rv string, gen int64, ct metav1.Time, labels, annotations map[string]string, err error) {
	if name, err = r.readString(); err != nil {
		return
	}
	if namespace, err = r.readString(); err != nil {
		return
	}
	uidStr, err := r.readString()
	if err != nil {
		return
	}
	uid = types.UID(uidStr)
	if rv, err = r.readString(); err != nil {
		return
	}
	if gen, err = r.readVarint(); err != nil {
		return
	}
	sec, err := r.readVarint()
	if err != nil {
		return
	}
	nano, err := r.readVarint()
	if err != nil {
		return
	}
	if sec != 0 || nano != 0 {
		ct = metav1.Time{Time: time.Unix(sec, nano).UTC()}
	}
	if labels, err = r.readStringMap(); err != nil {
		return
	}
	if annotations, err = r.readStringMap(); err != nil {
		return
	}
	return
}

// EncodeConfigMapBinary serializes a ConfigMapView into compact binary form.
func EncodeConfigMapBinary(v *ConfigMapView) ([]byte, error) {
	w := binWriter{buf: make([]byte, 0, 256)}
	w.writeByte(binaryMagic)
	w.writeByte(binaryVersion)
	w.writeByte(typeIDConfigMap)
	writeCommonMeta(&w, v.name, v.namespace, v.uid, v.resourceVersion, v.generation, v.creationTimestamp, v.labels, v.annotations)
	w.writeStringMap(v.data)
	w.writeBytesMap(v.binaryData)
	return w.buf, nil
}

// DecodeConfigMapBinary deserializes compact binary bytes into a ConfigMapView.
func DecodeConfigMapBinary(data []byte) (*ConfigMapView, error) {
	r := binReader{data: data}
	magic, err := r.readByte()
	if err != nil {
		return nil, err
	}
	if magic != binaryMagic {
		return nil, fmt.Errorf("invalid binary magic byte: 0x%x", magic)
	}
	ver, err := r.readByte()
	if err != nil {
		return nil, err
	}
	if ver != binaryVersion {
		return nil, fmt.Errorf("unsupported binary version: %d", ver)
	}
	typeID, err := r.readByte()
	if err != nil {
		return nil, err
	}
	if typeID != typeIDConfigMap {
		return nil, fmt.Errorf("unexpected type ID for ConfigMap: %d", typeID)
	}

	name, namespace, uid, rv, gen, ct, labels, annotations, err := readCommonMeta(&r)
	if err != nil {
		return nil, err
	}

	dataMap, err := r.readStringMap()
	if err != nil {
		return nil, err
	}
	binDataMap, err := r.readBytesMap()
	if err != nil {
		return nil, err
	}

	return &ConfigMapView{
		name:              name,
		namespace:         namespace,
		uid:               uid,
		resourceVersion:   rv,
		generation:        gen,
		creationTimestamp: ct,
		labels:            labels,
		annotations:       annotations,
		data:              dataMap,
		binaryData:        binDataMap,
	}, nil
}

// EncodeSecretBinary serializes a SecretView into compact binary form.
func EncodeSecretBinary(v *SecretView) ([]byte, error) {
	w := binWriter{buf: make([]byte, 0, 256)}
	w.writeByte(binaryMagic)
	w.writeByte(binaryVersion)
	w.writeByte(typeIDSecret)
	writeCommonMeta(&w, v.name, v.namespace, v.uid, v.resourceVersion, v.generation, v.creationTimestamp, v.labels, v.annotations)
	w.writeString(string(v.secretType))
	w.writeBytesMap(v.data)
	return w.buf, nil
}

// DecodeSecretBinary deserializes compact binary bytes into a SecretView.
func DecodeSecretBinary(data []byte) (*SecretView, error) {
	r := binReader{data: data}
	magic, err := r.readByte()
	if err != nil {
		return nil, err
	}
	if magic != binaryMagic {
		return nil, fmt.Errorf("invalid binary magic byte: 0x%x", magic)
	}
	ver, err := r.readByte()
	if err != nil {
		return nil, err
	}
	if ver != binaryVersion {
		return nil, fmt.Errorf("unsupported binary version: %d", ver)
	}
	typeID, err := r.readByte()
	if err != nil {
		return nil, err
	}
	if typeID != typeIDSecret {
		return nil, fmt.Errorf("unexpected type ID for Secret: %d", typeID)
	}

	name, namespace, uid, rv, gen, ct, labels, annotations, err := readCommonMeta(&r)
	if err != nil {
		return nil, err
	}

	secType, err := r.readString()
	if err != nil {
		return nil, err
	}
	dataMap, err := r.readBytesMap()
	if err != nil {
		return nil, err
	}

	return &SecretView{
		name:              name,
		namespace:         namespace,
		uid:               uid,
		resourceVersion:   rv,
		generation:        gen,
		creationTimestamp: ct,
		labels:            labels,
		annotations:       annotations,
		secretType:        corev1.SecretType(secType),
		data:              dataMap,
	}, nil
}

// EncodeHTTPRouteBinary serializes an HTTPRouteView into compact binary form.
func EncodeHTTPRouteBinary(v *HTTPRouteView) ([]byte, error) {
	w := binWriter{buf: make([]byte, 0, 512)}
	w.writeByte(binaryMagic)
	w.writeByte(binaryVersion)
	w.writeByte(typeIDHTTPRoute)
	writeCommonMeta(&w, v.name, v.namespace, v.uid, v.resourceVersion, v.generation, v.creationTimestamp, v.labels, v.annotations)

	// Hostnames
	w.writeUvarint(uint64(len(v.hostnames)))
	for _, h := range v.hostnames {
		w.writeString(h)
	}

	// ParentRefs
	w.writeUvarint(uint64(len(v.parentRefs)))
	for _, p := range v.parentRefs {
		w.writeString(p.group)
		w.writeString(p.kind)
		w.writeString(p.namespace)
		w.writeString(p.name)
		w.writeString(p.sectionName)
		w.writeVarint(int64(p.port))
	}

	// Rules
	w.writeUvarint(uint64(len(v.rules)))
	for _, r := range v.rules {
		w.writeString(r.name)

		// Matches
		w.writeUvarint(uint64(len(r.matches)))
		for _, m := range r.matches {
			w.writeString(m.path.matchType)
			w.writeString(m.path.value)
			w.writeUvarint(uint64(len(m.headers)))
			for _, h := range m.headers {
				w.writeString(h.matchType)
				w.writeString(h.name)
				w.writeString(h.value)
			}
			w.writeUvarint(uint64(len(m.queryParams)))
			for _, q := range m.queryParams {
				w.writeString(q.matchType)
				w.writeString(q.name)
				w.writeString(q.value)
			}
			w.writeString(m.method)
		}

		// Filters
		w.writeUvarint(uint64(len(r.filters)))
		for _, f := range r.filters {
			w.writeString(f.filterType)
			// RequestHeaderModifier
			w.writeUvarint(uint64(len(f.requestHeaderModifier.set)))
			for _, s := range f.requestHeaderModifier.set {
				w.writeString(s.name)
				w.writeString(s.value)
			}
			w.writeUvarint(uint64(len(f.requestHeaderModifier.add)))
			for _, a := range f.requestHeaderModifier.add {
				w.writeString(a.name)
				w.writeString(a.value)
			}
			w.writeUvarint(uint64(len(f.requestHeaderModifier.remove)))
			for _, rem := range f.requestHeaderModifier.remove {
				w.writeString(rem)
			}

			// ResponseHeaderModifier
			w.writeUvarint(uint64(len(f.responseHeaderModifier.set)))
			for _, s := range f.responseHeaderModifier.set {
				w.writeString(s.name)
				w.writeString(s.value)
			}
			w.writeUvarint(uint64(len(f.responseHeaderModifier.add)))
			for _, a := range f.responseHeaderModifier.add {
				w.writeString(a.name)
				w.writeString(a.value)
			}
			w.writeUvarint(uint64(len(f.responseHeaderModifier.remove)))
			for _, rem := range f.responseHeaderModifier.remove {
				w.writeString(rem)
			}

			// RequestRedirect
			w.writeString(f.requestRedirect.scheme)
			w.writeString(f.requestRedirect.hostname)
			w.writeString(f.requestRedirect.path.modifierType)
			w.writeString(f.requestRedirect.path.replaceFullPath)
			w.writeString(f.requestRedirect.path.replacePrefixMatch)
			w.writeVarint(int64(f.requestRedirect.port))
			w.writeVarint(int64(f.requestRedirect.statusCode))

			// URLRewrite
			w.writeString(f.urlRewrite.hostname)
			w.writeString(f.urlRewrite.path.modifierType)
			w.writeString(f.urlRewrite.path.replaceFullPath)
			w.writeString(f.urlRewrite.path.replacePrefixMatch)

			// RequestMirror
			w.writeString(f.requestMirror.backendRef.group)
			w.writeString(f.requestMirror.backendRef.kind)
			w.writeString(f.requestMirror.backendRef.namespace)
			w.writeString(f.requestMirror.backendRef.name)
			w.writeVarint(int64(f.requestMirror.backendRef.port))
		}

		// BackendRefs
		w.writeUvarint(uint64(len(r.backendRefs)))
		for _, b := range r.backendRefs {
			w.writeString(b.group)
			w.writeString(b.kind)
			w.writeString(b.namespace)
			w.writeString(b.name)
			w.writeVarint(int64(b.port))
			w.writeVarint(int64(b.weight))
			w.writeUvarint(uint64(len(b.filters)))
			for _, bf := range b.filters {
				w.writeString(bf.filterType)
			}
		}

		// Timeouts
		w.writeString(r.timeouts.request)
		w.writeString(r.timeouts.backendRequest)
	}

	return w.buf, nil
}

// DecodeHTTPRouteBinary deserializes compact binary bytes into an HTTPRouteView.
func DecodeHTTPRouteBinary(data []byte) (*HTTPRouteView, error) {
	r := binReader{data: data}
	magic, err := r.readByte()
	if err != nil {
		return nil, err
	}
	if magic != binaryMagic {
		return nil, fmt.Errorf("invalid binary magic byte: 0x%x", magic)
	}
	ver, err := r.readByte()
	if err != nil {
		return nil, err
	}
	if ver != binaryVersion {
		return nil, fmt.Errorf("unsupported binary version: %d", ver)
	}
	typeID, err := r.readByte()
	if err != nil {
		return nil, err
	}
	if typeID != typeIDHTTPRoute {
		return nil, fmt.Errorf("unexpected type ID for HTTPRoute: %d", typeID)
	}

	name, namespace, uid, rv, gen, ct, labels, annotations, err := readCommonMeta(&r)
	if err != nil {
		return nil, err
	}

	// Hostnames
	hCount, err := r.readUvarint()
	if err != nil {
		return nil, err
	}
	var hostnames []string
	if hCount > 0 {
		hostnames = make([]string, hCount)
		for i := uint64(0); i < hCount; i++ {
			if hostnames[i], err = r.readString(); err != nil {
				return nil, err
			}
		}
	}

	// ParentRefs
	pCount, err := r.readUvarint()
	if err != nil {
		return nil, err
	}
	var parentRefs []ParentReferenceView
	if pCount > 0 {
		parentRefs = make([]ParentReferenceView, pCount)
		for i := uint64(0); i < pCount; i++ {
			p := ParentReferenceView{}
			if p.group, err = r.readString(); err != nil {
				return nil, err
			}
			if p.kind, err = r.readString(); err != nil {
				return nil, err
			}
			if p.namespace, err = r.readString(); err != nil {
				return nil, err
			}
			if p.name, err = r.readString(); err != nil {
				return nil, err
			}
			if p.sectionName, err = r.readString(); err != nil {
				return nil, err
			}
			port, err := r.readVarint()
			if err != nil {
				return nil, err
			}
			p.port = int32(port)
			parentRefs[i] = p
		}
	}

	// Rules
	rCount, err := r.readUvarint()
	if err != nil {
		return nil, err
	}
	var rules []HTTPRouteRuleView
	if rCount > 0 {
		rules = make([]HTTPRouteRuleView, rCount)
		for i := uint64(0); i < rCount; i++ {
			rule := HTTPRouteRuleView{}
			if rule.name, err = r.readString(); err != nil {
				return nil, err
			}

			// Matches
			mCount, err := r.readUvarint()
			if err != nil {
				return nil, err
			}
			if mCount > 0 {
				rule.matches = make([]HTTPRouteMatchView, mCount)
				for j := uint64(0); j < mCount; j++ {
					m := HTTPRouteMatchView{}
					if m.path.matchType, err = r.readString(); err != nil {
						return nil, err
					}
					if m.path.value, err = r.readString(); err != nil {
						return nil, err
					}
					hdrCount, err := r.readUvarint()
					if err != nil {
						return nil, err
					}
					if hdrCount > 0 {
						m.headers = make([]HTTPHeaderMatchView, hdrCount)
						for k := uint64(0); k < hdrCount; k++ {
							if m.headers[k].matchType, err = r.readString(); err != nil {
								return nil, err
							}
							if m.headers[k].name, err = r.readString(); err != nil {
								return nil, err
							}
							if m.headers[k].value, err = r.readString(); err != nil {
								return nil, err
							}
						}
					}
					qpCount, err := r.readUvarint()
					if err != nil {
						return nil, err
					}
					if qpCount > 0 {
						m.queryParams = make([]HTTPQueryParamMatchView, qpCount)
						for k := uint64(0); k < qpCount; k++ {
							if m.queryParams[k].matchType, err = r.readString(); err != nil {
								return nil, err
							}
							if m.queryParams[k].name, err = r.readString(); err != nil {
								return nil, err
							}
							if m.queryParams[k].value, err = r.readString(); err != nil {
								return nil, err
							}
						}
					}
					if m.method, err = r.readString(); err != nil {
						return nil, err
					}
					rule.matches[j] = m
				}
			}

			// Filters
			fCount, err := r.readUvarint()
			if err != nil {
				return nil, err
			}
			if fCount > 0 {
				rule.filters = make([]HTTPRouteFilterView, fCount)
				for j := uint64(0); j < fCount; j++ {
					f := HTTPRouteFilterView{}
					if f.filterType, err = r.readString(); err != nil {
						return nil, err
					}
					// ReqHeaderMod
					setCount, err := r.readUvarint()
					if err != nil {
						return nil, err
					}
					for k := uint64(0); k < setCount; k++ {
						n, err := r.readString()
						if err != nil {
							return nil, err
						}
						v, err := r.readString()
						if err != nil {
							return nil, err
						}
						f.requestHeaderModifier.set = append(f.requestHeaderModifier.set, HTTPHeaderView{name: n, value: v})
					}
					addCount, err := r.readUvarint()
					if err != nil {
						return nil, err
					}
					for k := uint64(0); k < addCount; k++ {
						n, err := r.readString()
						if err != nil {
							return nil, err
						}
						v, err := r.readString()
						if err != nil {
							return nil, err
						}
						f.requestHeaderModifier.add = append(f.requestHeaderModifier.add, HTTPHeaderView{name: n, value: v})
					}
					remCount, err := r.readUvarint()
					if err != nil {
						return nil, err
					}
					for k := uint64(0); k < remCount; k++ {
						rem, err := r.readString()
						if err != nil {
							return nil, err
						}
						f.requestHeaderModifier.remove = append(f.requestHeaderModifier.remove, rem)
					}

					// RespHeaderMod
					setCount, err = r.readUvarint()
					if err != nil {
						return nil, err
					}
					for k := uint64(0); k < setCount; k++ {
						n, err := r.readString()
						if err != nil {
							return nil, err
						}
						v, err := r.readString()
						if err != nil {
							return nil, err
						}
						f.responseHeaderModifier.set = append(f.responseHeaderModifier.set, HTTPHeaderView{name: n, value: v})
					}
					addCount, err = r.readUvarint()
					if err != nil {
						return nil, err
					}
					for k := uint64(0); k < addCount; k++ {
						n, err := r.readString()
						if err != nil {
							return nil, err
						}
						v, err := r.readString()
						if err != nil {
							return nil, err
						}
						f.responseHeaderModifier.add = append(f.responseHeaderModifier.add, HTTPHeaderView{name: n, value: v})
					}
					remCount, err = r.readUvarint()
					if err != nil {
						return nil, err
					}
					for k := uint64(0); k < remCount; k++ {
						rem, err := r.readString()
						if err != nil {
							return nil, err
						}
						f.responseHeaderModifier.remove = append(f.responseHeaderModifier.remove, rem)
					}

					// ReqRedirect
					if f.requestRedirect.scheme, err = r.readString(); err != nil {
						return nil, err
					}
					if f.requestRedirect.hostname, err = r.readString(); err != nil {
						return nil, err
					}
					if f.requestRedirect.path.modifierType, err = r.readString(); err != nil {
						return nil, err
					}
					if f.requestRedirect.path.replaceFullPath, err = r.readString(); err != nil {
						return nil, err
					}
					if f.requestRedirect.path.replacePrefixMatch, err = r.readString(); err != nil {
						return nil, err
					}
					port, err := r.readVarint()
					if err != nil {
						return nil, err
					}
					f.requestRedirect.port = int32(port)
					status, err := r.readVarint()
					if err != nil {
						return nil, err
					}
					f.requestRedirect.statusCode = int(status)

					// URLRewrite
					if f.urlRewrite.hostname, err = r.readString(); err != nil {
						return nil, err
					}
					if f.urlRewrite.path.modifierType, err = r.readString(); err != nil {
						return nil, err
					}
					if f.urlRewrite.path.replaceFullPath, err = r.readString(); err != nil {
						return nil, err
					}
					if f.urlRewrite.path.replacePrefixMatch, err = r.readString(); err != nil {
						return nil, err
					}

					// ReqMirror
					if f.requestMirror.backendRef.group, err = r.readString(); err != nil {
						return nil, err
					}
					if f.requestMirror.backendRef.kind, err = r.readString(); err != nil {
						return nil, err
					}
					if f.requestMirror.backendRef.namespace, err = r.readString(); err != nil {
						return nil, err
					}
					if f.requestMirror.backendRef.name, err = r.readString(); err != nil {
						return nil, err
					}
					mPort, err := r.readVarint()
					if err != nil {
						return nil, err
					}
					f.requestMirror.backendRef.port = int32(mPort)

					rule.filters[j] = f
				}
			}

			// BackendRefs
			bCount, err := r.readUvarint()
			if err != nil {
				return nil, err
			}
			if bCount > 0 {
				rule.backendRefs = make([]HTTPBackendRefView, bCount)
				for j := uint64(0); j < bCount; j++ {
					b := HTTPBackendRefView{}
					if b.group, err = r.readString(); err != nil {
						return nil, err
					}
					if b.kind, err = r.readString(); err != nil {
						return nil, err
					}
					if b.namespace, err = r.readString(); err != nil {
						return nil, err
					}
					if b.name, err = r.readString(); err != nil {
						return nil, err
					}
					bPort, err := r.readVarint()
					if err != nil {
						return nil, err
					}
					b.port = int32(bPort)
					bWeight, err := r.readVarint()
					if err != nil {
						return nil, err
					}
					b.weight = int32(bWeight)
					bfCount, err := r.readUvarint()
					if err != nil {
						return nil, err
					}
					if bfCount > 0 {
						b.filters = make([]HTTPRouteFilterView, bfCount)
						for k := uint64(0); k < bfCount; k++ {
							if b.filters[k].filterType, err = r.readString(); err != nil {
								return nil, err
							}
						}
					}
					rule.backendRefs[j] = b
				}
			}

			// Timeouts
			if rule.timeouts.request, err = r.readString(); err != nil {
				return nil, err
			}
			if rule.timeouts.backendRequest, err = r.readString(); err != nil {
				return nil, err
			}

			rules[i] = rule
		}
	}

	return &HTTPRouteView{
		name:              name,
		namespace:         namespace,
		uid:               uid,
		resourceVersion:   rv,
		generation:        gen,
		creationTimestamp: ct,
		labels:            labels,
		annotations:       annotations,
		hostnames:         hostnames,
		parentRefs:        parentRefs,
		rules:             rules,
	}, nil
}

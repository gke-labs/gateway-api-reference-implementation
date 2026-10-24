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
	"bytes"
	"fmt"
	"time"

	pb "github.com/gke-labs/gateway-api-reference-implementation/experiments/viewtypes/proto"
	googleproto "google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

var protoEnvelopePrefix = []byte{0x6b, 0x38, 0x73, 0x00} // "k8s\x00"

// unwrapProtobufEnvelope extracts the raw inner protobuf payload from an API server protobuf response.
func unwrapProtobufEnvelope(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty protobuf data")
	}
	if bytes.HasPrefix(data, protoEnvelopePrefix) {
		data = data[len(protoEnvelopePrefix):]
		unk := &runtime.Unknown{}
		if err := unk.Unmarshal(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal runtime.Unknown envelope: %w", err)
		}
		return unk.Raw, nil
	}
	// Data without prefix is assumed to be raw message bytes.
	return data, nil
}

// wrapProtobufEnvelope wraps the inner protobuf payload with runtime.Unknown and the k8s\x00 prefix.
func wrapProtobufEnvelope(apiVersion, kind string, rawPayload []byte) ([]byte, error) {
	unk := &runtime.Unknown{
		TypeMeta: runtime.TypeMeta{
			APIVersion: apiVersion,
			Kind:       kind,
		},
		Raw: rawPayload,
	}
	rawUnk, err := unk.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal runtime.Unknown: %w", err)
	}

	buf := make([]byte, len(protoEnvelopePrefix)+len(rawUnk))
	copy(buf, protoEnvelopePrefix)
	copy(buf[len(protoEnvelopePrefix):], rawUnk)
	return buf, nil
}

// DecodeConfigMapProtobuf decodes API server protobuf bytes into an immutable ConfigMapView.
func DecodeConfigMapProtobuf(data []byte) (*ConfigMapView, error) {
	raw, err := unwrapProtobufEnvelope(data)
	if err != nil {
		return nil, err
	}

	var m pb.ConfigMap
	if err := googleproto.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal trimmed ConfigMap proto: %w", err)
	}

	cm := &ConfigMapView{
		data:       m.GetData(),
		binaryData: m.GetBinaryData(),
	}

	if meta := m.GetMetadata(); meta != nil {
		cm.name = meta.GetName()
		cm.namespace = meta.GetNamespace()
		cm.uid = types.UID(meta.GetUid())
		cm.resourceVersion = meta.GetResourceVersion()
		cm.generation = meta.GetGeneration()
		cm.labels = meta.GetLabels()
		cm.annotations = meta.GetAnnotations()
		if ts := meta.GetCreationTimestamp(); ts != nil {
			cm.creationTimestamp = metav1.Time{Time: time.Unix(ts.GetSeconds(), int64(ts.GetNanos())).UTC()}
		}
	}

	return cm, nil
}

// DecodeConfigMapListProtobuf decodes API server protobuf bytes into a ConfigMapViewList.
func DecodeConfigMapListProtobuf(data []byte) (*ConfigMapViewList, error) {
	raw, err := unwrapProtobufEnvelope(data)
	if err != nil {
		return nil, err
	}

	var l pb.ConfigMapList
	if err := googleproto.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("failed to unmarshal trimmed ConfigMapList proto: %w", err)
	}

	list := &ConfigMapViewList{}
	if meta := l.GetMetadata(); meta != nil {
		list.metadata.ResourceVersion = meta.GetResourceVersion()
	}

	list.Items = make([]*ConfigMapView, len(l.GetItems()))
	for i, item := range l.GetItems() {
		cm := &ConfigMapView{
			data:       item.GetData(),
			binaryData: item.GetBinaryData(),
		}
		if meta := item.GetMetadata(); meta != nil {
			cm.name = meta.GetName()
			cm.namespace = meta.GetNamespace()
			cm.uid = types.UID(meta.GetUid())
			cm.resourceVersion = meta.GetResourceVersion()
			cm.generation = meta.GetGeneration()
			cm.labels = meta.GetLabels()
			cm.annotations = meta.GetAnnotations()
			if ts := meta.GetCreationTimestamp(); ts != nil {
				cm.creationTimestamp = metav1.Time{Time: time.Unix(ts.GetSeconds(), int64(ts.GetNanos())).UTC()}
			}
		}
		list.Items[i] = cm
	}

	return list, nil
}

// DecodeSecretProtobuf decodes API server protobuf bytes into an immutable SecretView.
func DecodeSecretProtobuf(data []byte) (*SecretView, error) {
	raw, err := unwrapProtobufEnvelope(data)
	if err != nil {
		return nil, err
	}

	var m pb.Secret
	if err := googleproto.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal trimmed Secret proto: %w", err)
	}

	sec := &SecretView{
		secretType: corev1.SecretType(m.GetType()),
		data:       m.GetData(),
	}

	if meta := m.GetMetadata(); meta != nil {
		sec.name = meta.GetName()
		sec.namespace = meta.GetNamespace()
		sec.uid = types.UID(meta.GetUid())
		sec.resourceVersion = meta.GetResourceVersion()
		sec.generation = meta.GetGeneration()
		sec.labels = meta.GetLabels()
		sec.annotations = meta.GetAnnotations()
		if ts := meta.GetCreationTimestamp(); ts != nil {
			sec.creationTimestamp = metav1.Time{Time: time.Unix(ts.GetSeconds(), int64(ts.GetNanos())).UTC()}
		}
	}

	return sec, nil
}

// DecodeSecretListProtobuf decodes API server protobuf bytes into a SecretViewList.
func DecodeSecretListProtobuf(data []byte) (*SecretViewList, error) {
	raw, err := unwrapProtobufEnvelope(data)
	if err != nil {
		return nil, err
	}

	var l pb.SecretList
	if err := googleproto.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("failed to unmarshal trimmed SecretList proto: %w", err)
	}

	list := &SecretViewList{}
	if meta := l.GetMetadata(); meta != nil {
		list.metadata.ResourceVersion = meta.GetResourceVersion()
	}

	list.Items = make([]*SecretView, len(l.GetItems()))
	for i, item := range l.GetItems() {
		sec := &SecretView{
			secretType: corev1.SecretType(item.GetType()),
			data:       item.GetData(),
		}
		if meta := item.GetMetadata(); meta != nil {
			sec.name = meta.GetName()
			sec.namespace = meta.GetNamespace()
			sec.uid = types.UID(meta.GetUid())
			sec.resourceVersion = meta.GetResourceVersion()
			sec.generation = meta.GetGeneration()
			sec.labels = meta.GetLabels()
			sec.annotations = meta.GetAnnotations()
			if ts := meta.GetCreationTimestamp(); ts != nil {
				sec.creationTimestamp = metav1.Time{Time: time.Unix(ts.GetSeconds(), int64(ts.GetNanos())).UTC()}
			}
		}
		list.Items[i] = sec
	}

	return list, nil
}

// EncodeConfigMapProtobufEnvelope serializes a ConfigMapView into the Kubernetes API server protobuf envelope.
func EncodeConfigMapProtobufEnvelope(v *ConfigMapView) ([]byte, error) {
	m := &pb.ConfigMap{
		Metadata: &pb.ObjectMeta{
			Name:            &v.name,
			Namespace:       &v.namespace,
			ResourceVersion: &v.resourceVersion,
			Generation:      &v.generation,
			Labels:          v.labels,
			Annotations:     v.annotations,
		},
		Data:       v.data,
		BinaryData: v.binaryData,
	}
	if v.uid != "" {
		uidStr := string(v.uid)
		m.Metadata.Uid = &uidStr
	}
	if !v.creationTimestamp.IsZero() {
		sec := v.creationTimestamp.Unix()
		nanos := int32(v.creationTimestamp.Nanosecond())
		m.Metadata.CreationTimestamp = &pb.Time{Seconds: &sec, Nanos: &nanos}
	}

	raw, err := googleproto.Marshal(m)
	if err != nil {
		return nil, err
	}
	return wrapProtobufEnvelope("v1", "ConfigMap", raw)
}

// EncodeSecretProtobufEnvelope serializes a SecretView into the Kubernetes API server protobuf envelope.
func EncodeSecretProtobufEnvelope(v *SecretView) ([]byte, error) {
	secType := string(v.secretType)
	m := &pb.Secret{
		Metadata: &pb.ObjectMeta{
			Name:            &v.name,
			Namespace:       &v.namespace,
			ResourceVersion: &v.resourceVersion,
			Generation:      &v.generation,
			Labels:          v.labels,
			Annotations:     v.annotations,
		},
		Type: &secType,
		Data: v.data,
	}
	if v.uid != "" {
		uidStr := string(v.uid)
		m.Metadata.Uid = &uidStr
	}
	if !v.creationTimestamp.IsZero() {
		sec := v.creationTimestamp.Unix()
		nanos := int32(v.creationTimestamp.Nanosecond())
		m.Metadata.CreationTimestamp = &pb.Time{Seconds: &sec, Nanos: &nanos}
	}

	raw, err := googleproto.Marshal(m)
	if err != nil {
		return nil, err
	}
	return wrapProtobufEnvelope("v1", "Secret", raw)
}

// EncodeConfigMapListProtobufEnvelope serializes a ConfigMapViewList into the Kubernetes API server protobuf envelope.
func EncodeConfigMapListProtobufEnvelope(l *ConfigMapViewList) ([]byte, error) {
	list := &pb.ConfigMapList{
		Metadata: &pb.ListMeta{
			ResourceVersion: &l.metadata.ResourceVersion,
		},
		Items: make([]*pb.ConfigMap, len(l.Items)),
	}
	for i, v := range l.Items {
		item := &pb.ConfigMap{
			Metadata: &pb.ObjectMeta{
				Name:            &v.name,
				Namespace:       &v.namespace,
				ResourceVersion: &v.resourceVersion,
				Generation:      &v.generation,
				Labels:          v.labels,
				Annotations:     v.annotations,
			},
			Data:       v.data,
			BinaryData: v.binaryData,
		}
		if v.uid != "" {
			uidStr := string(v.uid)
			item.Metadata.Uid = &uidStr
		}
		if !v.creationTimestamp.IsZero() {
			sec := v.creationTimestamp.Unix()
			nanos := int32(v.creationTimestamp.Nanosecond())
			item.Metadata.CreationTimestamp = &pb.Time{Seconds: &sec, Nanos: &nanos}
		}
		list.Items[i] = item
	}

	raw, err := googleproto.Marshal(list)
	if err != nil {
		return nil, err
	}
	return wrapProtobufEnvelope("v1", "ConfigMapList", raw)
}

// EncodeSecretListProtobufEnvelope serializes a SecretViewList into the Kubernetes API server protobuf envelope.
func EncodeSecretListProtobufEnvelope(l *SecretViewList) ([]byte, error) {
	list := &pb.SecretList{
		Metadata: &pb.ListMeta{
			ResourceVersion: &l.metadata.ResourceVersion,
		},
		Items: make([]*pb.Secret, len(l.Items)),
	}
	for i, v := range l.Items {
		secType := string(v.secretType)
		item := &pb.Secret{
			Metadata: &pb.ObjectMeta{
				Name:            &v.name,
				Namespace:       &v.namespace,
				ResourceVersion: &v.resourceVersion,
				Generation:      &v.generation,
				Labels:          v.labels,
				Annotations:     v.annotations,
			},
			Type: &secType,
			Data: v.data,
		}
		if v.uid != "" {
			uidStr := string(v.uid)
			item.Metadata.Uid = &uidStr
		}
		if !v.creationTimestamp.IsZero() {
			sec := v.creationTimestamp.Unix()
			nanos := int32(v.creationTimestamp.Nanosecond())
			item.Metadata.CreationTimestamp = &pb.Time{Seconds: &sec, Nanos: &nanos}
		}
		list.Items[i] = item
	}

	raw, err := googleproto.Marshal(list)
	if err != nil {
		return nil, err
	}
	return wrapProtobufEnvelope("v1", "SecretList", raw)
}

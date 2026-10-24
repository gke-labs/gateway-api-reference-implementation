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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

type fakeWatchEvent struct {
	Type      watch.EventType
	RawObject map[string]any
}

func waitForCondition(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

func TestInformer_ConfigMapView(t *testing.T) {
	watchCh := make(chan fakeWatchEvent, 10)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/configmaps" {
			http.NotFound(w, r)
			return
		}

		if r.URL.Query().Get("sendInitialEvents") == "true" {
			http.Error(w, "watch-list not supported", http.StatusBadRequest)
			return
		}

		if r.URL.Query().Get("watch") == "true" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Transfer-Encoding", "chunked")
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "Flushing not supported", http.StatusInternalServerError)
				return
			}

			enc := json.NewEncoder(w)
			for {
				select {
				case <-r.Context().Done():
					return
				case event, ok := <-watchCh:
					if !ok {
						return
					}
					rawObj, _ := json.Marshal(event.RawObject)
					_ = enc.Encode(struct {
						Type   string          `json:"type"`
						Object json.RawMessage `json:"object"`
					}{
						Type:   string(event.Type),
						Object: rawObj,
					})
					flusher.Flush()
				}
			}
		}

		// List response
		listJSON := `{
			"apiVersion": "v1",
			"kind": "ConfigMapList",
			"metadata": {"resourceVersion": "100"},
			"items": [
				{
					"apiVersion": "v1",
					"kind": "ConfigMap",
					"metadata": {
						"name": "cm-init",
						"namespace": "default",
						"resourceVersion": "100",
						"managedFields": [{"manager": "test"}]
					},
					"data": {"config.key": "initial-value"}
				}
			]
		}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(listJSON))
	}))
	defer server.Close()

	scheme := NewScheme()
	client, err := NewRESTClient(server.URL, CoreGroupVersion, scheme, server.Client())
	if err != nil {
		t.Fatalf("failed to create REST client: %v", err)
	}

	lw := cache.NewListWatchFromClient(client, "configmaps", metav1.NamespaceAll, fields.Everything())
	store := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	reflector := cache.NewReflector(lw, &ConfigMapView{}, store, 0)

	stopCh := make(chan struct{})
	defer close(stopCh)
	go reflector.Run(stopCh)

	// Verify List items populated in store
	ok := waitForCondition(3*time.Second, func() bool {
		item, exists, _ := store.GetByKey("default/cm-init")
		if !exists {
			return false
		}
		cm, ok := item.(*ConfigMapView)
		return ok && cm.Name() == "cm-init" && cm.Data().Len() == 1
	})
	if !ok {
		t.Fatalf("timed out waiting for cm-init to be listed into store")
	}

	item, _, _ := store.GetByKey("default/cm-init")
	cm := item.(*ConfigMapView)
	val, _ := cm.Data().Get("config.key")
	if val != "initial-value" {
		t.Errorf("initial value mismatch: %s", val)
	}

	// Send Watch Event: ADDED
	watchCh <- fakeWatchEvent{
		Type: watch.Added,
		RawObject: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name":            "cm-watch-add",
				"namespace":       "default",
				"resourceVersion": "101",
			},
			"data": map[string]string{"watch": "added"},
		},
	}

	ok = waitForCondition(3*time.Second, func() bool {
		item, exists, _ := store.GetByKey("default/cm-watch-add")
		return exists && item.(*ConfigMapView).Name() == "cm-watch-add"
	})
	if !ok {
		t.Fatalf("timed out waiting for watch ADDED event")
	}

	// Send Watch Event: MODIFIED
	watchCh <- fakeWatchEvent{
		Type: watch.Modified,
		RawObject: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name":            "cm-init",
				"namespace":       "default",
				"resourceVersion": "102",
			},
			"data": map[string]string{"config.key": "updated-value"},
		},
	}

	ok = waitForCondition(3*time.Second, func() bool {
		item, exists, _ := store.GetByKey("default/cm-init")
		if !exists {
			return false
		}
		cm := item.(*ConfigMapView)
		v, _ := cm.Data().Get("config.key")
		return v == "updated-value"
	})
	if !ok {
		t.Fatalf("timed out waiting for watch MODIFIED event")
	}

	// Send Watch Event: DELETED
	watchCh <- fakeWatchEvent{
		Type: watch.Deleted,
		RawObject: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name":            "cm-watch-add",
				"namespace":       "default",
				"resourceVersion": "103",
			},
		},
	}

	ok = waitForCondition(3*time.Second, func() bool {
		_, exists, _ := store.GetByKey("default/cm-watch-add")
		return !exists
	})
	if !ok {
		t.Fatalf("timed out waiting for watch DELETED event")
	}
}

func TestInformer_SecretView(t *testing.T) {
	watchCh := make(chan fakeWatchEvent, 10)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/secrets" {
			http.NotFound(w, r)
			return
		}

		if r.URL.Query().Get("sendInitialEvents") == "true" {
			http.Error(w, "watch-list not supported", http.StatusBadRequest)
			return
		}

		if r.URL.Query().Get("watch") == "true" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Transfer-Encoding", "chunked")
			flusher := w.(http.Flusher)
			enc := json.NewEncoder(w)

			for {
				select {
				case <-r.Context().Done():
					return
				case event, ok := <-watchCh:
					if !ok {
						return
					}
					rawObj, _ := json.Marshal(event.RawObject)
					_ = enc.Encode(struct {
						Type   string          `json:"type"`
						Object json.RawMessage `json:"object"`
					}{
						Type:   string(event.Type),
						Object: rawObj,
					})
					flusher.Flush()
				}
			}
		}

		listJSON := `{
			"apiVersion": "v1",
			"kind": "SecretList",
			"metadata": {"resourceVersion": "200"},
			"items": [
				{
					"apiVersion": "v1",
					"kind": "Secret",
					"metadata": {
						"name": "sec-init",
						"namespace": "prod",
						"resourceVersion": "200"
					},
					"type": "Opaque",
					"data": {"password": "c2VjcmV0LXB3ZA=="}
				}
			]
		}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(listJSON))
	}))
	defer server.Close()

	scheme := NewScheme()
	client, err := NewRESTClient(server.URL, CoreGroupVersion, scheme, server.Client())
	if err != nil {
		t.Fatalf("failed to create REST client: %v", err)
	}

	lw := cache.NewListWatchFromClient(client, "secrets", metav1.NamespaceAll, fields.Everything())
	store := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	reflector := cache.NewReflector(lw, &SecretView{}, store, 0)

	stopCh := make(chan struct{})
	defer close(stopCh)
	go reflector.Run(stopCh)

	ok := waitForCondition(3*time.Second, func() bool {
		item, exists, _ := store.GetByKey("prod/sec-init")
		if !exists {
			return false
		}
		sec := item.(*SecretView)
		return sec.Name() == "sec-init" && sec.Data().Len() == 1
	})
	if !ok {
		t.Fatalf("timed out waiting for sec-init in store")
	}

	// Watch: ADDED
	watchCh <- fakeWatchEvent{
		Type: watch.Added,
		RawObject: map[string]any{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]any{
				"name":            "sec-new",
				"namespace":       "prod",
				"resourceVersion": "201",
			},
			"type": "kubernetes.io/tls",
			"data": map[string]string{"tls.crt": "Y3J0"},
		},
	}

	ok = waitForCondition(3*time.Second, func() bool {
		item, exists, _ := store.GetByKey("prod/sec-new")
		return exists && item.(*SecretView).Name() == "sec-new"
	})
	if !ok {
		t.Fatalf("timed out waiting for sec-new via watch")
	}

	// Watch: DELETED
	watchCh <- fakeWatchEvent{
		Type: watch.Deleted,
		RawObject: map[string]any{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]any{
				"name":            "sec-new",
				"namespace":       "prod",
				"resourceVersion": "202",
			},
		},
	}

	ok = waitForCondition(3*time.Second, func() bool {
		_, exists, _ := store.GetByKey("prod/sec-new")
		return !exists
	})
	if !ok {
		t.Fatalf("timed out waiting for sec-new DELETED via watch")
	}
}

func TestInformer_HTTPRouteView(t *testing.T) {
	watchCh := make(chan fakeWatchEvent, 10)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/gateway.networking.k8s.io/v1/httproutes" {
			http.NotFound(w, r)
			return
		}

		if r.URL.Query().Get("sendInitialEvents") == "true" {
			http.Error(w, "watch-list not supported", http.StatusBadRequest)
			return
		}

		if r.URL.Query().Get("watch") == "true" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Transfer-Encoding", "chunked")
			flusher := w.(http.Flusher)
			enc := json.NewEncoder(w)

			for {
				select {
				case <-r.Context().Done():
					return
				case event, ok := <-watchCh:
					if !ok {
						return
					}
					rawObj, _ := json.Marshal(event.RawObject)
					_ = enc.Encode(struct {
						Type   string          `json:"type"`
						Object json.RawMessage `json:"object"`
					}{
						Type:   string(event.Type),
						Object: rawObj,
					})
					flusher.Flush()
				}
			}
		}

		listJSON := `{
			"apiVersion": "gateway.networking.k8s.io/v1",
			"kind": "HTTPRouteList",
			"metadata": {"resourceVersion": "300"},
			"items": [
				{
					"apiVersion": "gateway.networking.k8s.io/v1",
					"kind": "HTTPRoute",
					"metadata": {
						"name": "route-init",
						"namespace": "gateway-ns",
						"resourceVersion": "300"
					},
					"spec": {
						"hostnames": ["init.example.com"],
						"rules": [
							{"name": "r1"}
						]
					}
				}
			]
		}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(listJSON))
	}))
	defer server.Close()

	scheme := NewScheme()
	client, err := NewRESTClient(server.URL, GatewayGroupVersion, scheme, server.Client())
	if err != nil {
		t.Fatalf("failed to create REST client: %v", err)
	}

	lw := cache.NewListWatchFromClient(client, "httproutes", metav1.NamespaceAll, fields.Everything())
	store := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	reflector := cache.NewReflector(lw, &HTTPRouteView{}, store, 0)

	stopCh := make(chan struct{})
	defer close(stopCh)
	go reflector.Run(stopCh)

	ok := waitForCondition(3*time.Second, func() bool {
		item, exists, _ := store.GetByKey("gateway-ns/route-init")
		if !exists {
			return false
		}
		route := item.(*HTTPRouteView)
		return route.Name() == "route-init" && route.Hostnames().Len() == 1
	})
	if !ok {
		t.Fatalf("timed out waiting for route-init in store")
	}

	// Watch: ADDED
	watchCh <- fakeWatchEvent{
		Type: watch.Added,
		RawObject: map[string]any{
			"apiVersion": "gateway.networking.k8s.io/v1",
			"kind":       "HTTPRoute",
			"metadata": map[string]any{
				"name":            "route-watch",
				"namespace":       "gateway-ns",
				"resourceVersion": "301",
			},
			"spec": map[string]any{
				"hostnames": []string{"watch.example.com"},
			},
		},
	}

	ok = waitForCondition(3*time.Second, func() bool {
		item, exists, _ := store.GetByKey("gateway-ns/route-watch")
		return exists && item.(*HTTPRouteView).Name() == "route-watch"
	})
	if !ok {
		t.Fatalf("timed out waiting for route-watch via watch")
	}

	// Watch: DELETED
	watchCh <- fakeWatchEvent{
		Type: watch.Deleted,
		RawObject: map[string]any{
			"apiVersion": "gateway.networking.k8s.io/v1",
			"kind":       "HTTPRoute",
			"metadata": map[string]any{
				"name":            "route-watch",
				"namespace":       "gateway-ns",
				"resourceVersion": "302",
			},
		},
	}

	ok = waitForCondition(3*time.Second, func() bool {
		_, exists, _ := store.GetByKey("gateway-ns/route-watch")
		return !exists
	})
	if !ok {
		t.Fatalf("timed out waiting for route-watch DELETED via watch")
	}
}

// TestInformer_Protobuf_ConfigMapView tests an informer decoding list and watch from protobuf envelopes.
func TestInformer_Protobuf_ConfigMapView(t *testing.T) {
	watchCh := make(chan watch.Event, 10)

	cmInitial := &ConfigMapView{
		name:            "cm-proto-init",
		namespace:       "default",
		resourceVersion: "500",
		data:            map[string]string{"proto.key": "proto-init-val"},
	}

	initialList := &ConfigMapViewList{
		metadata: metav1.ListMeta{ResourceVersion: "500"},
		Items:    []*ConfigMapView{cmInitial},
	}

	protoListBytes, err := EncodeConfigMapListProtobufEnvelope(initialList)
	if err != nil {
		t.Fatalf("failed to encode initial proto list: %v", err)
	}

	fakeLW := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return DecodeConfigMapListProtobuf(protoListBytes)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			if options.SendInitialEvents != nil && *options.SendInitialEvents {
				return nil, fmt.Errorf("watch-list not supported: %w", apierrors.NewBadRequest("not supported"))
			}
			fakeWatcher := watch.NewFake()
			go func() {
				for ev := range watchCh {
					fakeWatcher.Action(ev.Type, ev.Object)
				}
			}()
			return fakeWatcher, nil
		},
	}

	store := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	reflector := cache.NewReflector(fakeLW, &ConfigMapView{}, store, 0)

	stopCh := make(chan struct{})
	defer close(stopCh)
	go reflector.Run(stopCh)

	ok := waitForCondition(3*time.Second, func() bool {
		item, exists, _ := store.GetByKey("default/cm-proto-init")
		if !exists {
			return false
		}
		cm := item.(*ConfigMapView)
		v, _ := cm.Data().Get("proto.key")
		return v == "proto-init-val"
	})
	if !ok {
		t.Fatalf("timed out waiting for cm-proto-init in store")
	}

	// Watch: ADDED encoded through protobuf envelope
	addedCM := &ConfigMapView{
		name:            "cm-proto-added",
		namespace:       "default",
		resourceVersion: "501",
		data:            map[string]string{"added": "proto"},
	}
	addedBytes, err := EncodeConfigMapProtobufEnvelope(addedCM)
	if err != nil {
		t.Fatalf("failed to encode added proto: %v", err)
	}
	decodedAdded, err := DecodeConfigMapProtobuf(addedBytes)
	if err != nil {
		t.Fatalf("failed to decode added proto: %v", err)
	}

	watchCh <- watch.Event{Type: watch.Added, Object: decodedAdded}

	ok = waitForCondition(3*time.Second, func() bool {
		item, exists, _ := store.GetByKey("default/cm-proto-added")
		return exists && item.(*ConfigMapView).Name() == "cm-proto-added"
	})
	if !ok {
		t.Fatalf("timed out waiting for cm-proto-added in store")
	}
}

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

package kubecache

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/experiments/diskstore/engine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	toolscache "k8s.io/client-go/tools/cache"
)

// TestAdapterFailure_EngineError tests that an engine error calls OnFatal exactly once
// and List, ListKeys, and ByIndex never return partial results.
func TestAdapterFailure_EngineError(t *testing.T) {
	memFS := engine.NewMemFS()
	eng, err := engine.Open(engine.WithFS(memFS), engine.WithDir("fail_engine_err"), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer eng.Close()

	var fatalCount atomic.Int32
	fatalCh := make(chan error, 10)
	onFatal := func(err error) {
		fatalCount.Add(1)
		fatalCh <- err
	}

	idx, err := New(eng, &corev1.ConfigMap{}, onFatal,
		WithIndexers(toolscache.Indexers{
			"namespace": toolscache.MetaNamespaceIndexFunc,
		}),
	)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer idx.Close()

	// Pre-populate with valid objects
	cm1 := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-1"}}
	cm2 := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-2"}}
	if err := idx.Add(cm1); err != nil {
		t.Fatalf("Add cm1 failed: %v", err)
	}
	if err := idx.Add(cm2); err != nil {
		t.Fatalf("Add cm2 failed: %v", err)
	}

	// Trigger engine failure
	engine.TestHookFail(eng, errors.New("simulated fatal disk failure"))

	// An operation encountering the engine error calls onFatal
	cm3 := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-3"}}
	updateErr := idx.Update(cm3)
	if updateErr == nil {
		t.Fatalf("expected error on Update after engine failure")
	}

	// Check onFatal called exactly once
	if c := fatalCount.Load(); c != 1 {
		t.Fatalf("expected OnFatal called exactly once, got %d", c)
	}
	var fatalErr error
	select {
	case fatalErr = <-fatalCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for error on fatalCh")
	}
	if fatalErr == nil || !errors.Is(fatalErr, engine.ErrFailed) {
		t.Fatalf("expected ErrFailed in OnFatal, got %v", fatalErr)
	}

	// Call again to verify OnFatal is not called again
	_ = idx.Delete(cm1)
	if c := fatalCount.Load(); c != 1 {
		t.Fatalf("expected OnFatal still exactly once, got %d", c)
	}

	// Invariant: List, ListKeys, ByIndex must NEVER return partial data
	list := idx.List()
	if len(list) != 0 {
		t.Fatalf("expected empty List after failure, got %d items", len(list))
	}

	keys := idx.ListKeys()
	if len(keys) != 0 {
		t.Fatalf("expected empty ListKeys after failure, got %d keys", len(keys))
	}

	byIdx, err := idx.ByIndex("namespace", "default")
	if err == nil {
		t.Fatalf("expected error from ByIndex after failure")
	}
	if len(byIdx) != 0 {
		t.Fatalf("expected empty ByIndex after failure, got %d items", len(byIdx))
	}
}

// TestAdapterFailure_BackgroundFailureNotification tests that background engine failures
// notify the adapter and call OnFatal exactly once without returning partial results.
func TestAdapterFailure_BackgroundFailureNotification(t *testing.T) {
	memFS := engine.NewMemFS()
	eng, err := engine.Open(engine.WithFS(memFS), engine.WithDir("fail_bg_err"), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer eng.Close()

	var fatalCount atomic.Int32
	fatalCh := make(chan error, 10)
	onFatal := func(err error) {
		fatalCount.Add(1)
		fatalCh <- err
	}

	idx, err := New(eng, &corev1.ConfigMap{}, onFatal,
		WithIndexers(toolscache.Indexers{
			"namespace": toolscache.MetaNamespaceIndexFunc,
		}),
	)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer idx.Close()

	cm1 := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-1"}}
	if err := idx.Add(cm1); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Simulate background engine failure
	engine.TestHookFail(eng, errors.New("simulated background flush error"))

	// Wait for background notification to reach adapter
	select {
	case <-fatalCh:
		// Received notification
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for background failure notification")
	}

	if c := fatalCount.Load(); c != 1 {
		t.Fatalf("expected OnFatal called exactly once from background notification, got %d", c)
	}

	// Invariant: Never return partial data
	if len(idx.List()) != 0 {
		t.Fatalf("expected empty List after background failure")
	}
	if len(idx.ListKeys()) != 0 {
		t.Fatalf("expected empty ListKeys after background failure")
	}
	items, err := idx.ByIndex("namespace", "default")
	if err == nil || len(items) != 0 {
		t.Fatalf("expected error and empty ByIndex after background failure")
	}
}

// TestAdapterFailure_DecodeFailure tests that a decode error calls OnFatal exactly once
// and List, ListKeys, and ByIndex never return partial results.
func TestAdapterFailure_DecodeFailure(t *testing.T) {
	memFS := engine.NewMemFS()
	eng, err := engine.Open(engine.WithFS(memFS), engine.WithDir("fail_decode_err"), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer eng.Close()

	var fatalCount atomic.Int32
	var fatalErr error
	onFatal := func(err error) {
		fatalCount.Add(1)
		fatalErr = err
	}

	idx, err := New(eng, &corev1.ConfigMap{}, onFatal,
		WithIndexers(toolscache.Indexers{
			"namespace": toolscache.MetaNamespaceIndexFunc,
		}),
	)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer idx.Close()

	// Pre-populate with valid ConfigMap
	cm1 := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-1"}}
	if err := idx.Add(cm1); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Put corrupted non-decodable bytes directly into engine for this bucket
	bucketName := fmt.Sprintf("%T", &corev1.ConfigMap{})
	corruptBytes := []byte("this is corrupt raw non-protobuf non-json data")
	if err := eng.Put(bucketName, "default/cm-corrupt", corruptBytes); err != nil {
		t.Fatalf("eng.Put corrupt failed: %v", err)
	}

	// List encounters the corrupt object during scan
	list := idx.List()
	if len(list) != 0 {
		t.Fatalf("expected empty List on decode error, got %d items", len(list))
	}

	if c := fatalCount.Load(); c != 1 {
		t.Fatalf("expected OnFatal called exactly once on decode error, got %d", c)
	}
	if fatalErr == nil {
		t.Fatalf("expected non-nil fatalErr on decode error")
	}

	// Invariant: ByIndex and ListKeys never return partial data
	if len(idx.ListKeys()) != 0 {
		t.Fatalf("expected empty ListKeys after decode failure")
	}
	items, err := idx.ByIndex("namespace", "default")
	if err == nil || len(items) != 0 {
		t.Fatalf("expected error and empty ByIndex after decode failure")
	}
}

// TestAdapterFailure_DecryptFailure tests that a decrypt failure in the engine
// calls OnFatal exactly once and List, ListKeys, and ByIndex never return partial results.
func TestAdapterFailure_DecryptFailure(t *testing.T) {
	memFS := engine.NewMemFS()
	cipher, err := engine.NewEphemeralAESGCMCipher()
	if err != nil {
		t.Fatalf("NewEphemeralAESGCMCipher failed: %v", err)
	}

	eng, err := engine.Open(engine.WithFS(memFS), engine.WithCipher(cipher), engine.WithDir("fail_decrypt_err"), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer eng.Close()

	var fatalCount atomic.Int32
	var fatalErr error
	onFatal := func(err error) {
		fatalCount.Add(1)
		fatalErr = err
	}

	idx, err := New(eng, &corev1.Secret{}, onFatal,
		WithIndexers(toolscache.Indexers{
			"namespace": toolscache.MetaNamespaceIndexFunc,
		}),
	)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer idx.Close()

	// Pre-populate with valid secret
	sec1 := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "sec-1"}}
	if err := idx.Add(sec1); err != nil {
		t.Fatalf("Add sec1 failed: %v", err)
	}

	// Close engine and reopen with a different cipher key so that reading stored objects triggers decrypt failure
	_ = idx.Close()
	_ = eng.Close()

	differentCipher, err := engine.NewEphemeralAESGCMCipher()
	if err != nil {
		t.Fatalf("NewEphemeralAESGCMCipher 2 failed: %v", err)
	}

	engWrongKey, err := engine.Open(engine.WithFS(memFS), engine.WithCipher(differentCipher), engine.WithDir("fail_decrypt_err"))
	if err != nil {
		t.Fatalf("Open with different cipher failed: %v", err)
	}
	defer engWrongKey.Close()

	// Reopen adapter with the wrong-key engine
	fatalCount.Store(0)
	fatalErr = nil
	idxWrongKey, err := New(engWrongKey, &corev1.Secret{}, onFatal,
		WithIndexers(toolscache.Indexers{
			"namespace": toolscache.MetaNamespaceIndexFunc,
		}),
	)
	// New attempts to scan and rebuild secondary indexes, which hits decrypt failure!
	if err == nil {
		t.Fatalf("expected New to fail on decrypt error during index rebuild")
	}

	if c := fatalCount.Load(); c != 1 {
		t.Fatalf("expected OnFatal called exactly once on decrypt failure, got %d", c)
	}
	if fatalErr == nil {
		t.Fatalf("expected non-nil fatalErr on decrypt failure")
	}

	if idxWrongKey != nil {
		if len(idxWrongKey.List()) != 0 {
			t.Fatalf("expected empty List on decrypt failure")
		}
		if len(idxWrongKey.ListKeys()) != 0 {
			t.Fatalf("expected empty ListKeys on decrypt failure")
		}
		items, bErr := idxWrongKey.ByIndex("namespace", "default")
		if bErr == nil || len(items) != 0 {
			t.Fatalf("expected error and empty ByIndex on decrypt failure")
		}
	}
}

// TestAdapterFailure_IndexFunctionError tests that an index-function error calls OnFatal
// exactly once and List, ListKeys, and ByIndex never return partial results.
func TestAdapterFailure_IndexFunctionError(t *testing.T) {
	memFS := engine.NewMemFS()
	eng, err := engine.Open(engine.WithFS(memFS), engine.WithDir("fail_index_err"), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer eng.Close()

	var fatalCount atomic.Int32
	var fatalErr error
	onFatal := func(err error) {
		fatalCount.Add(1)
		fatalErr = err
	}

	shouldFail := atomic.Bool{}
	failingIndexFunc := func(obj any) ([]string, error) {
		if shouldFail.Load() {
			return nil, errors.New("simulated fatal index function error")
		}
		cm, ok := obj.(*corev1.ConfigMap)
		if !ok {
			return nil, fmt.Errorf("unexpected type %T", obj)
		}
		return []string{cm.Namespace}, nil
	}

	idx, err := New(eng, &corev1.ConfigMap{}, onFatal,
		WithIndexers(toolscache.Indexers{
			"namespace": failingIndexFunc,
		}),
	)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer idx.Close()

	cm1 := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-1"}}
	if err := idx.Add(cm1); err != nil {
		t.Fatalf("Add cm1 failed: %v", err)
	}

	// Trigger index function failure
	shouldFail.Store(true)

	cm2 := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-2"}}
	addErr := idx.Add(cm2)
	if addErr == nil {
		t.Fatalf("expected Add to fail when index function returns error")
	}

	if c := fatalCount.Load(); c != 1 {
		t.Fatalf("expected OnFatal called exactly once on index function error, got %d", c)
	}
	if fatalErr == nil {
		t.Fatalf("expected non-nil fatalErr on index function error")
	}

	// Subsequent operations must not call OnFatal again
	_ = idx.Delete(cm1)
	if c := fatalCount.Load(); c != 1 {
		t.Fatalf("expected OnFatal still exactly once, got %d", c)
	}

	// Invariant: List, ListKeys, ByIndex never return partial results
	if len(idx.List()) != 0 {
		t.Fatalf("expected empty List after index function failure")
	}
	if len(idx.ListKeys()) != 0 {
		t.Fatalf("expected empty ListKeys after index function failure")
	}
	items, err := idx.ByIndex("namespace", "default")
	if err == nil || len(items) != 0 {
		t.Fatalf("expected error and empty ByIndex after index function failure")
	}
}

// TestForcedFatalVisibility asserts that a forced fatal error in a kubecache test
// shows up as a named test failure rather than a silent process exit via os.Exit.
func TestForcedFatalVisibility(t *testing.T) {
	if os.Getenv("TEST_KUBECACHE_FORCED_FATAL") == "1" {
		memFS := engine.NewMemFS()
		eng, err := engine.Open(engine.WithFS(memFS), engine.WithDir("forced_fatal_proc"), engine.WithCreate())
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer eng.Close()

		idx, err := New(eng, &corev1.ConfigMap{}, testOnFatal(t))
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		defer idx.Close()

		// Force a fatal error into the engine
		engine.TestHookFail(eng, errors.New("simulated fatal disk failure"))

		// Operation triggering the fatal error
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-fail"}}
		_ = idx.Update(cm)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestForcedFatalVisibility$")
	cmd.Env = append(os.Environ(), "TEST_KUBECACHE_FORCED_FATAL=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected subprocess to fail, but it exited successfully")
	}

	outStr := string(out)
	if !strings.Contains(outStr, "--- FAIL: TestForcedFatalVisibility") {
		t.Fatalf("expected named test failure '--- FAIL: TestForcedFatalVisibility' in output, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "kubecache fatal error: engine failed: simulated fatal disk failure") {
		t.Fatalf("expected fatal error details in output, got:\n%s", outStr)
	}
}

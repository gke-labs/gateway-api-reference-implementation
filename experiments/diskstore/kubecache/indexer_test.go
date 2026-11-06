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
	"bytes"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/experiments/diskstore/engine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	toolscache "k8s.io/client-go/tools/cache"
)

// testOnFatal returns an OnFatal callback that fails the test with t.Errorf,
// ensuring fatal errors in tests are visible and name the failing test.
func testOnFatal(t testing.TB) func(error) {
	return func(err error) {
		t.Errorf("kubecache fatal error: %v", err)
	}
}

func TestIndexer_CRUD(t *testing.T) {
	memFS := engine.NewMemFS()
	store, err := engine.Open(engine.WithFS(memFS), engine.WithDir("idx_crud_store"), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	indexer, err := New(store, &corev1.ConfigMap{}, testOnFatal(t))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer indexer.Close()

	cm1 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns-a",
			Name:      "cm-1",
		},
		Data: map[string]string{"key": "value1"},
	}

	// Add
	if err := indexer.Add(cm1); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// GetByKey
	obj, exists, err := indexer.GetByKey("ns-a/cm-1")
	if err != nil || !exists {
		t.Fatalf("GetByKey failed: exists=%v, err=%v", exists, err)
	}
	retrievedCM, ok := obj.(*corev1.ConfigMap)
	if !ok || retrievedCM.Data["key"] != "value1" {
		t.Fatalf("unexpected object data: %+v", retrievedCM)
	}

	// Update
	cm1Updated := cm1.DeepCopy()
	cm1Updated.Data["key"] = "value1-updated"
	if err := indexer.Update(cm1Updated); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	obj, exists, err = indexer.Get(cm1)
	if err != nil || !exists {
		t.Fatalf("Get failed: exists=%v, err=%v", exists, err)
	}
	if obj.(*corev1.ConfigMap).Data["key"] != "value1-updated" {
		t.Fatalf("update was not reflected: %+v", obj)
	}

	// List
	list := indexer.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 item, got %d", len(list))
	}

	// ListKeys
	keys := indexer.ListKeys()
	if len(keys) != 1 || keys[0] != "ns-a/cm-1" {
		t.Fatalf("expected [ns-a/cm-1], got %v", keys)
	}

	// Delete
	if err := indexer.Delete(cm1); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	_, exists, err = indexer.GetByKey("ns-a/cm-1")
	if err != nil || exists {
		t.Fatalf("expected deleted, exists=%v, err=%v", exists, err)
	}
}

func TestIndexer_SecondaryIndexing(t *testing.T) {
	memFS := engine.NewMemFS()
	store, err := engine.Open(engine.WithFS(memFS), engine.WithDir("idx_sec_store"), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	customIndexers := toolscache.Indexers{
		"by-annotation": func(obj any) ([]string, error) {
			cm, ok := obj.(*corev1.ConfigMap)
			if !ok {
				return nil, fmt.Errorf("unexpected type %T", obj)
			}
			if val, ok := cm.Annotations["target-ann"]; ok {
				return []string{val}, nil
			}
			return nil, nil
		},
	}

	indexer, err := New(store, &corev1.ConfigMap{}, testOnFatal(t), WithIndexers(customIndexers))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer indexer.Close()

	cm1 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "ns-1",
			Name:        "cm-1",
			Annotations: map[string]string{"target-ann": "foo"},
		},
	}
	cm2 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "ns-1",
			Name:        "cm-2",
			Annotations: map[string]string{"target-ann": "foo"},
		},
	}
	cm3 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "ns-2",
			Name:        "cm-3",
			Annotations: map[string]string{"target-ann": "bar"},
		},
	}

	_ = indexer.Add(cm1)
	_ = indexer.Add(cm2)
	_ = indexer.Add(cm3)

	// ByIndex
	fooItems, err := indexer.ByIndex("by-annotation", "foo")
	if err != nil {
		t.Fatalf("ByIndex failed: %v", err)
	}
	if len(fooItems) != 2 {
		t.Fatalf("expected 2 items for foo, got %d", len(fooItems))
	}

	// IndexKeys
	fooKeys, err := indexer.IndexKeys("by-annotation", "foo")
	if err != nil {
		t.Fatalf("IndexKeys failed: %v", err)
	}
	if len(fooKeys) != 2 || fooKeys[0] != "ns-1/cm-1" || fooKeys[1] != "ns-1/cm-2" {
		t.Fatalf("unexpected keys for foo: %v", fooKeys)
	}

	// ListIndexFuncValues
	vals := indexer.ListIndexFuncValues("by-annotation")
	if len(vals) != 2 {
		t.Fatalf("expected 2 distinct values, got %v", vals)
	}

	// Update cm2 annotation from foo to bar
	cm2Updated := cm2.DeepCopy()
	cm2Updated.Annotations["target-ann"] = "bar"
	_ = indexer.Update(cm2Updated)

	fooKeys, _ = indexer.IndexKeys("by-annotation", "foo")
	if len(fooKeys) != 1 || fooKeys[0] != "ns-1/cm-1" {
		t.Fatalf("expected 1 item for foo after update, got %v", fooKeys)
	}

	barKeys, _ := indexer.IndexKeys("by-annotation", "bar")
	if len(barKeys) != 2 {
		t.Fatalf("expected 2 items for bar after update, got %v", barKeys)
	}
}

func TestIndexer_WithEncryption(t *testing.T) {
	memFS := engine.NewMemFS()
	cipher, err := engine.NewEphemeralAESGCMCipher()
	if err != nil {
		t.Fatalf("NewEphemeralAESGCMCipher failed: %v", err)
	}

	store, err := engine.Open(engine.WithFS(memFS), engine.WithCipher(cipher), engine.WithDir("idx_crypto_store"), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	indexer, err := New(store, &corev1.Secret{}, testOnFatal(t))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer indexer.Close()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "sensitive-secret",
		},
		Data: map[string][]byte{"token": []byte("super-secret-token-12345")},
	}

	if err := indexer.Add(secret); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Decrypt through indexer
	obj, exists, err := indexer.GetByKey("kube-system/sensitive-secret")
	if err != nil || !exists {
		t.Fatalf("GetByKey failed: %v", err)
	}
	decryptedSecret := obj.(*corev1.Secret)
	if string(decryptedSecret.Data["token"]) != "super-secret-token-12345" {
		t.Fatalf("decrypted secret mismatch: %s", string(decryptedSecret.Data["token"]))
	}

	// Close store to flush to disk
	_ = indexer.Close()
	_ = store.Close()

	// Verify reading through store without cipher fails to decompress ciphertext
	storeNoCipher, err := engine.Open(engine.WithFS(memFS), engine.WithDir("idx_crypto_store"))
	if err != nil {
		t.Fatalf("Open without cipher failed: %v", err)
	}
	defer storeNoCipher.Close()

	_, _, err = storeNoCipher.Get(fmt.Sprintf("%T", secret), "kube-system/sensitive-secret")
	if err == nil {
		t.Fatalf("expected Get without cipher to fail on ciphertext, but succeeded")
	}

	// Verify on-disk files do not contain the plaintext token
	for _, sub := range []string{"", "wal"} {
		dir := filepath.Join("idx_crypto_store", sub)
		entries, err := memFS.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			f, err := memFS.Open(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			sz, _ := f.Size()
			buf := make([]byte, sz)
			_, _ = f.ReadAt(buf, 0)
			_ = f.Close()
			if bytes.Contains(buf, []byte("super-secret-token-12345")) {
				t.Fatalf("secret token was found in plaintext in file %s!", filepath.Join(dir, e.Name()))
			}
		}
	}
}

func TestIndexer_ReplaceAndResourceVersion(t *testing.T) {
	memFS := engine.NewMemFS()
	store, err := engine.Open(engine.WithFS(memFS), engine.WithDir("idx_rv_store"), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	indexer, err := New(store, &corev1.ConfigMap{}, testOnFatal(t))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer indexer.Close()

	list := []any{
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-1"}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-2"}},
	}

	if err := indexer.Replace(list, "45678"); err != nil {
		t.Fatalf("Replace failed: %v", err)
	}

	if rv := indexer.LastStoreSyncResourceVersion(); rv != "45678" {
		t.Fatalf("expected RV 45678, got %s", rv)
	}

	keys := indexer.ListKeys()
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	indexer.Bookmark("50000")
	if rv := indexer.LastStoreSyncResourceVersion(); rv != "50000" {
		t.Fatalf("expected Bookmark RV 50000, got %s", rv)
	}
}

// TestRegression_Item20_SecondaryIndexesRebuiltOnReopen asserts secondary indexes work immediately on reopen.
func TestRegression_Item20_SecondaryIndexesRebuiltOnReopen(t *testing.T) {
	memFS := engine.NewMemFS()
	dir := "test_secondary_rebuild"

	store, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	cmExample := &corev1.ConfigMap{}
	indexer, err := New(store, cmExample, testOnFatal(t),
		WithBucketName("ConfigMap"),
		WithIndexers(toolscache.Indexers{
			"namespace": toolscache.MetaNamespaceIndexFunc,
		}),
	)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	cm1 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns-a", Name: "cm-1"},
		Data:       map[string]string{"foo": "bar"},
	}
	cm2 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns-a", Name: "cm-2"},
		Data:       map[string]string{"foo": "baz"},
	}
	_ = indexer.Add(cm1)
	_ = indexer.Add(cm2)
	_ = store.Close()

	// Reopen store with a new indexer instance
	store2, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir))
	if err != nil {
		t.Fatalf("Reopen Open failed: %v", err)
	}
	defer store2.Close()

	indexer2, err := New(store2, cmExample, testOnFatal(t),
		WithBucketName("ConfigMap"),
		WithIndexers(toolscache.Indexers{
			"namespace": toolscache.MetaNamespaceIndexFunc,
		}),
	)
	if err != nil {
		t.Fatalf("New 2 failed: %v", err)
	}
	defer indexer2.Close()

	// ByIndex must find both objects immediately without requiring any rewrite
	objs, err := indexer2.ByIndex("namespace", "ns-a")
	if err != nil {
		t.Fatalf("ByIndex failed: %v", err)
	}
	if len(objs) != 2 {
		t.Fatalf("expected 2 objects for namespace ns-a, got %d", len(objs))
	}
}

// TestRegression_Item21_ReplaceAsDiff asserts Replace operates as a diff and sets RV only once complete.
func TestRegression_Item21_ReplaceAsDiff(t *testing.T) {
	memFS := engine.NewMemFS()
	dir := "test_replace_as_diff"

	store, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	indexer, _ := New(store, &corev1.ConfigMap{}, testOnFatal(t), WithBucketName("ConfigMap"))
	defer indexer.Close()

	cmA := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "a", ResourceVersion: "1"}}
	cmB := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "b", ResourceVersion: "1"}}
	_ = indexer.Add(cmA)
	_ = indexer.Add(cmB)

	// Replace with B and C (A should be deleted, B updated, C added)
	cmBUpdated := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "b", ResourceVersion: "2"}, Data: map[string]string{"k": "v"}}
	cmC := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "c", ResourceVersion: "2"}}

	if err := indexer.Replace([]any{cmBUpdated, cmC}, "rv-list-100"); err != nil {
		t.Fatalf("Replace failed: %v", err)
	}

	// A must be gone
	if _, exists, _ := indexer.Get(cmA); exists {
		t.Fatalf("cmA should have been removed by Replace diff")
	}

	// B must have updated data
	bItem, exists, err := indexer.Get(cmB)
	if err != nil || !exists {
		t.Fatalf("cmB missing after replace: %v", err)
	}
	if bItem.(*corev1.ConfigMap).Data["k"] != "v" {
		t.Fatalf("cmB data not updated")
	}

	// C must be present
	if _, exists, _ := indexer.Get(cmC); !exists {
		t.Fatalf("cmC missing after replace")
	}

	// LastStoreSyncResourceVersion must be rv-list-100
	if indexer.LastStoreSyncResourceVersion() != "rv-list-100" {
		t.Fatalf("last sync RV mismatch: got %q, want %q", indexer.LastStoreSyncResourceVersion(), "rv-list-100")
	}
}

// TestRegression_Round2_Item5_BookmarkNoFakeObject asserts that bookmarks do not store fake objects in buckets.
func TestRegression_Round2_Item5_BookmarkNoFakeObject(t *testing.T) {
	memFS := engine.NewMemFS()
	dir := "test_bookmark_fake_obj"

	store, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	indexer, _ := New(store, &corev1.ConfigMap{}, testOnFatal(t), WithBucketName("ConfigMap"))
	defer indexer.Close()

	// Record bookmark
	indexer.Bookmark("99999")

	// ListKeys must be empty
	keys := indexer.ListKeys()
	for _, k := range keys {
		if strings.Contains(k, "bookmark") {
			t.Fatalf("fake bookmark object leaked into ListKeys: %q", k)
		}
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys in indexer, got %d", len(keys))
	}

	// List must return empty
	objs := indexer.List()
	if len(objs) != 0 {
		t.Fatalf("expected 0 objects in indexer, got %d", len(objs))
	}

	// Replace should succeed without attempting to delete fake bookmark
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "real-cm"}}
	if err := indexer.Replace([]any{cm}, "100000"); err != nil {
		t.Fatalf("Replace failed: %v", err)
	}
	if len(indexer.ListKeys()) != 1 {
		t.Fatalf("expected exactly 1 real object after replace, got %d", len(indexer.ListKeys()))
	}
}

// TestRegression_Round2_Item6_ResourceVersionPerBucket asserts resourceVersions are isolated per bucket.
func TestRegression_Round2_Item6_ResourceVersionPerBucket(t *testing.T) {
	memFS := engine.NewMemFS()
	dir := "test_rv_per_bucket"

	store, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	cmIndexer, _ := New(store, &corev1.ConfigMap{}, testOnFatal(t), WithBucketName("ConfigMap"))
	secretIndexer, _ := New(store, &corev1.Secret{}, testOnFatal(t), WithBucketName("Secret"))
	defer cmIndexer.Close()
	defer secretIndexer.Close()

	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-1", ResourceVersion: "cm-rv-100"}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "sec-1", ResourceVersion: "secret-rv-500"}}

	_ = cmIndexer.Add(cm)
	_ = secretIndexer.Add(secret)

	// Secret watch is ahead of ConfigMap watch
	secretIndexer.Bookmark("secret-rv-600")

	if err := cmIndexer.Close(); err != nil {
		t.Fatalf("cmIndexer.Close failed: %v", err)
	}
	if err := secretIndexer.Close(); err != nil {
		t.Fatalf("secretIndexer.Close failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("store.Close failed: %v", err)
	}

	// Reopen store and create new indexers
	store2, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	cmIndexer2, _ := New(store2, &corev1.ConfigMap{}, testOnFatal(t), WithBucketName("ConfigMap"))
	secretIndexer2, _ := New(store2, &corev1.Secret{}, testOnFatal(t), WithBucketName("Secret"))
	defer cmIndexer2.Close()
	defer secretIndexer2.Close()

	// ConfigMap must recover cm-rv-100 (NOT secret-rv-600!)
	if cmIndexer2.LastStoreSyncResourceVersion() != "cm-rv-100" {
		t.Fatalf("ConfigMap recovered wrong RV: got %q, want %q", cmIndexer2.LastStoreSyncResourceVersion(), "cm-rv-100")
	}

	// Secret must recover secret-rv-600
	if secretIndexer2.LastStoreSyncResourceVersion() != "secret-rv-600" {
		t.Fatalf("Secret recovered wrong RV: got %q, want %q", secretIndexer2.LastStoreSyncResourceVersion(), "secret-rv-600")
	}
}

// TestIndexer_NoGoroutineLeakOnEngineClose verifies that closing the underlying engine alone
// terminates the adapter's failure-watch goroutine without leaking goroutines.
func TestIndexer_NoGoroutineLeakOnEngineClose(t *testing.T) {
	// Let existing background goroutines settle
	for i := 0; i < 5; i++ {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	baseline := runtime.NumGoroutine()

	memFS := engine.NewMemFS()
	store, err := engine.Open(engine.WithFS(memFS), engine.WithDir("idx_leak_store"), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	indexer, err := New(store, &corev1.ConfigMap{}, testOnFatal(t))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	_ = indexer

	// Verify goroutine was spawned
	if runtime.NumGoroutine() <= baseline {
		t.Fatalf("expected goroutine count to exceed baseline %d, got %d", baseline, runtime.NumGoroutine())
	}

	// Close ONLY the engine without calling indexer.Close()
	if err := store.Close(); err != nil {
		t.Fatalf("store.Close failed: %v", err)
	}

	// Verify the goroutine count returns to baseline
	var current int
	returnedToBaseline := false
	for attempt := 0; attempt < 50; attempt++ {
		time.Sleep(10 * time.Millisecond)
		runtime.GC()
		current = runtime.NumGoroutine()
		if current <= baseline {
			returnedToBaseline = true
			break
		}
	}
	if !returnedToBaseline {
		t.Fatalf("goroutine leak: expected goroutine count to return to baseline %d, got %d", baseline, current)
	}
}

func openTestStoreAndIndexer(t *testing.T, dir string, opts ...engine.Option) (*engine.Engine, *Indexer, engine.FS) {
	t.Helper()
	memFS := engine.NewMemFS()
	allOpts := append([]engine.Option{engine.WithFS(memFS), engine.WithDir(dir), engine.WithCreate()}, opts...)
	store, err := engine.Open(allOpts...)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	idx, err := New(store, &corev1.ConfigMap{}, testOnFatal(t), WithBucketName("ConfigMap"))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return store, idx, memFS
}

func TestNew_RejectsReservedBucketName(t *testing.T) {
	memFS := engine.NewMemFS()
	store, err := engine.Open(engine.WithFS(memFS), engine.WithDir("test_reserved_bucket"), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	if _, err := New(store, &corev1.ConfigMap{}, testOnFatal(t), WithBucketName(reservedResourceVersionWatch)); err == nil {
		t.Fatalf("expected New with reserved bucket name to fail")
	}
}

// TestIndexer_ReplaceResourceVersionAtomicity verifies that items with out-of-order resourceVersions
// in Replace never cause the persisted resourceVersion to move until Replace returns.
func TestIndexer_ReplaceResourceVersionAtomicity(t *testing.T) {
	memFS := engine.NewMemFS()
	store, err := engine.Open(engine.WithFS(memFS), engine.WithDir("test_replace_rv_atomicity"), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	var checkedDuringReplace bool
	idx, err := New(store, &corev1.ConfigMap{}, testOnFatal(t),
		WithBucketName("ConfigMap"),
		WithIndexers(toolscache.Indexers{
			"check": func(obj any) ([]string, error) {
				payload, exists, err := store.Get(reservedResourceVersionWatch, "ConfigMap")
				if err == nil && exists {
					checkedDuringReplace = true
					if string(payload) != "100" {
						t.Errorf("persisted RV moved mid-re-list: got %q, want '100'", string(payload))
					}
				}
				return nil, nil
			},
		}),
	)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer idx.Close()

	if err := idx.Add(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-0", ResourceVersion: "100"}}); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	payload, exists, err := store.Get(reservedResourceVersionWatch, "ConfigMap")
	if err != nil || !exists || string(payload) != "100" {
		t.Fatalf("expected initial persisted RV '100', got %q", string(payload))
	}

	// List with items whose resourceVersions are out of order (500 then 300)
	list := []any{
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-1", ResourceVersion: "500"}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-2", ResourceVersion: "300"}},
	}

	if err := idx.Replace(list, "600"); err != nil {
		t.Fatalf("Replace failed: %v", err)
	}

	if !checkedDuringReplace {
		t.Fatalf("expected check to run during Replace")
	}

	payload, exists, err = store.Get(reservedResourceVersionWatch, "ConfigMap")
	if err != nil || !exists || string(payload) != "600" {
		t.Fatalf("expected persisted RV to equal list RV '600', got %q", string(payload))
	}
	if got := idx.LastStoreSyncResourceVersion(); got != "600" {
		t.Fatalf("expected LastStoreSyncResourceVersion '600', got %q", got)
	}
}

// TestIndexer_CrashBeforeLazyResourceVersionWrite verifies that if a crash occurs before
// the next lazy resourceVersion write, the recovered resourceVersion is at or behind the data, never ahead.
func TestIndexer_CrashBeforeLazyResourceVersionWrite(t *testing.T) {
	store, idx, memFS := openTestStoreAndIndexer(t, "test_crash_lazy_rv")

	// 1. Initial write: persists initial resourceVersion "100"
	if err := idx.Add(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-1", ResourceVersion: "100"}}); err != nil {
		t.Fatalf("Add cm1 failed: %v", err)
	}

	// 2. Write newer objects with resourceVersions "101" and "102".
	// Within lazyResourceVersionSyncInterval, these are kept in memory and not yet persisted.
	if err := idx.Add(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-2", ResourceVersion: "101"}}); err != nil {
		t.Fatalf("Add cm2 failed: %v", err)
	}
	if err := idx.Add(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-3", ResourceVersion: "102"}}); err != nil {
		t.Fatalf("Add cm3 failed: %v", err)
	}

	// 3. Simulate crash before the lazy write occurs: close store directly without idx.Close()
	if err := store.Close(); err != nil {
		t.Fatalf("store.Close failed: %v", err)
	}

	// 4. Reopen and verify recovered resourceVersion is at or behind data ("100"), never ahead
	store2, err := engine.Open(engine.WithFS(memFS), engine.WithDir("test_crash_lazy_rv"))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	idx2, err := New(store2, &corev1.ConfigMap{}, testOnFatal(t), WithBucketName("ConfigMap"))
	if err != nil {
		t.Fatalf("New reopened failed: %v", err)
	}
	defer idx2.Close()

	if got := idx2.LastStoreSyncResourceVersion(); got != "100" {
		t.Fatalf("expected recovered RV to be '100' (at or behind data), got %q", got)
	}
	if len(idx2.ListKeys()) != 3 {
		t.Fatalf("expected 3 objects present after crash recovery, got %d", len(idx2.ListKeys()))
	}
}

// TestIndexer_ResourceVersionSurvivesCheckpointTruncation verifies that the watch resourceVersion
// survives across a checkpoint that truncates WAL segments (Issue #968).
func TestIndexer_ResourceVersionSurvivesCheckpointTruncation(t *testing.T) {
	store, idx, memFS := openTestStoreAndIndexer(t, "test_checkpoint_rv_truncation", engine.WithCompressionCodec(engine.CodecNone))

	if err := idx.Add(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-survive", ResourceVersion: "rv-checkpoint-100"}}); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("idx.Close failed: %v", err)
	}
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint 1 failed: %v", err)
	}

	// Write ~18 MB across checkpoints to roll the 16 MiB WAL segment and truncate segment 1
	putPads := func(start, end int) {
		pad := bytes.Repeat([]byte("p"), 30*1024)
		for i := start; i < end; i++ {
			if err := store.Put("PaddingBucket", fmt.Sprintf("pad-%d", i), pad); err != nil {
				t.Fatalf("Put pad %d failed: %v", i, err)
			}
		}
	}
	putPads(0, 560)
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint 2 failed: %v", err)
	}
	putPads(560, 580)
	if _, err := store.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint 3 failed: %v", err)
	}

	walEntries, err := memFS.ReadDir("test_checkpoint_rv_truncation/wal")
	if err != nil {
		t.Fatalf("ReadDir wal failed: %v", err)
	}
	for _, e := range walEntries {
		if e.Name() == "00000000000000000001.wal" {
			t.Fatalf("expected segment 1 to be truncated after checkpoint")
		}
	}

	if err := store.Close(); err != nil {
		t.Fatalf("store.Close failed: %v", err)
	}

	store2, err := engine.Open(engine.WithFS(memFS), engine.WithDir("test_checkpoint_rv_truncation"))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	idx2, err := New(store2, &corev1.ConfigMap{}, testOnFatal(t), WithBucketName("ConfigMap"))
	if err != nil {
		t.Fatalf("New reopened failed: %v", err)
	}
	defer idx2.Close()

	if got := idx2.LastStoreSyncResourceVersion(); got != "rv-checkpoint-100" {
		t.Fatalf("expected recovered RV to survive checkpoint truncation, got %q, want 'rv-checkpoint-100'", got)
	}
}

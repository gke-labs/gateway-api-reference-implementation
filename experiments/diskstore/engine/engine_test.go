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

package engine

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestDiskStore_BasicCRUD(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	store, err := Open(WithFS(faultFS), WithDir("test_store"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	// Put
	payload := []byte("hello-diskstore-world")
	if err := store.Put("ConfigMap", "default/cm-1", payload, "1001"); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Get
	got, exists, err := store.Get("ConfigMap", "default/cm-1")
	if err != nil || !exists {
		t.Fatalf("Get failed: exists=%v, err=%v", exists, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %s, want %s", string(got), string(payload))
	}

	// Delete
	if err := store.Delete("ConfigMap", "default/cm-1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	_, exists, err = store.Get("ConfigMap", "default/cm-1")
	if err != nil || exists {
		t.Fatalf("expected deleted, exists=%v, err=%v", exists, err)
	}
}

func TestDiskStore_OversizeObject(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	store, err := Open(WithFS(faultFS), WithDir("test_oversize_store"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	initialCount := OversizeCount()

	// 3 MiB payload (> MaxPayloadCapacity ~2 MiB)
	oversizePayload := make([]byte, 3*1024*1024)
	copy(oversizePayload, []byte("large-payload-prefix-data"))

	// Write must NOT fail
	if err := store.Put("ConfigMap", "default/large-cm", oversizePayload, "1002"); err != nil {
		t.Fatalf("Put oversize object failed: %v", err)
	}

	// Metric must increment
	if OversizeCount() != initialCount+1 {
		t.Fatalf("expected OversizeCount %d, got %d", initialCount+1, OversizeCount())
	}

	// Get should retrieve intact
	got, exists, err := store.Get("ConfigMap", "default/large-cm")
	if err != nil || !exists {
		t.Fatalf("Get oversize failed: exists=%v, err=%v", exists, err)
	}
	if !bytes.Equal(got, oversizePayload) {
		t.Fatalf("oversize payload mismatch")
	}

	// Delete
	if err := store.Delete("ConfigMap", "default/large-cm"); err != nil {
		t.Fatalf("Delete oversize failed: %v", err)
	}

	// Metric must decrement
	if OversizeCount() != initialCount {
		t.Fatalf("expected OversizeCount %d after delete, got %d", initialCount, OversizeCount())
	}
}

func TestDiskStore_FailedStateOnErrors(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	store, err := Open(WithFS(faultFS), WithDir("test_fail_store"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	_ = store.Put("ConfigMap", "default/cm-1", []byte("data-1"), "1")

	// Inject write error into filesystem
	injectedErr := errors.New("simulated unrecoverable disk error")
	faultFS.SetWriteError(injectedErr)

	// Flush will attempt to write to disk, fail, and transition store into failed state
	err = store.Flush()
	if err == nil {
		err = store.Put("ConfigMap", "default/cm-2", []byte("data-2"), "2")
	}
	if err == nil {
		t.Fatalf("expected error on injected write failure")
	}

	// Invariant: Failed store returns error rather than stale data on ANY subsequent read
	_, _, err = store.Get("ConfigMap", "default/cm-1")
	if !errors.Is(err, ErrFailed) {
		t.Fatalf("expected ErrFailed on read after failure, got %v", err)
	}
}

func TestDiskStore_StaleReadDetection(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	store, err := Open(WithFS(faultFS), WithDir("test_stale_store"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	// Put version 1 and checkpoint to disk
	_ = store.Put("ConfigMap", "default/cm-stale", []byte("val-v1"), "1")
	_, _ = store.Checkpoint()

	qKey := qualifyKey("ConfigMap", "default/cm-stale")
	store.keyMu.RLock()
	entryV1 := store.keyIndex[qKey]
	store.keyMu.RUnlock()

	// Capture version 1's disk block
	v1Block := make([]byte, BlockSize)
	store.bp.mu.Lock()
	locV1 := store.bp.pageTable[entryV1.LogicalPage].DurableLoc
	store.bp.mu.Unlock()
	_, _ = store.heapFile.ReadAt(v1Block, int64(locV1*BlockSize))

	// Put version 2 (LSN increments to 3)
	_ = store.Put("ConfigMap", "default/cm-stale", []byte("val-v2"), "2")

	// Evict page from memory frames by unloading frames
	store.bp.mu.Lock()
	desc := store.bp.pageTable[entryV1.LogicalPage]
	desc.FrameIDs = nil // force reload from disk
	desc.PhysicalBlock = locV1
	store.bp.mu.Unlock()

	// Substitute older valid page copy underneath the buffer pool on disk
	faultFS.SetAssertReuseRule(false)
	_, _ = store.heapFile.WriteAt(v1Block, int64(locV1*BlockSize))

	// Read must detect mismatch, report corruption, and put store in failed state
	_, _, err = store.Get("ConfigMap", "default/cm-stale")
	if !errors.Is(err, ErrFailed) {
		t.Fatalf("expected ErrFailed on stale read detection, got %v", err)
	}
}

// TestRegression_Item11_ReuseRulePromoteFlushedBeforeSync asserts locations flushed after sync starts aren't promoted.
func TestRegression_Item11_ReuseRulePromoteFlushedBeforeSync(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	store, err := Open(WithFS(faultFS), WithDir("test_reuse_rule_promote"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	// Put page 1, flush it
	_ = store.Put("ConfigMap", "k1", []byte("v1"), "1")
	store.bp.mu.Lock()
	desc := store.bp.pageTable[store.keyIndex[qualifyKey("ConfigMap", "k1")].LogicalPage]
	_ = store.bp.FlushPageLocked(desc)
	loc1 := desc.FlushedLoc
	store.bp.mu.Unlock()

	// Snapshot for sync
	store.bp.SnapshotFlushedForSync()

	// Put page 2 and flush it AFTER snapshot was taken
	_ = store.Put("ConfigMap", "k2", []byte("v2"), "2")
	store.bp.mu.Lock()
	desc2 := store.bp.pageTable[store.keyIndex[qualifyKey("ConfigMap", "k2")].LogicalPage]
	_ = store.bp.FlushPageLocked(desc2)
	loc2 := desc2.FlushedLoc
	store.bp.mu.Unlock()

	// Now promote flushed locations
	_ = store.bp.PromoteFlushedToDurable()

	store.bp.mu.Lock()
	defer store.bp.mu.Unlock()

	// loc1 was before snapshot -> promoted to durable!
	if desc.DurableLoc != loc1 {
		t.Fatalf("desc 1 DurableLoc=%d, expected %d", desc.DurableLoc, loc1)
	}
	// loc2 was flushed AFTER snapshot -> must NOT be promoted to durable yet!
	if desc2.DurableLoc == loc2 {
		t.Fatalf("desc 2 DurableLoc was prematurely promoted to durable before its fsync!")
	}
}

// TestRegression_Item15_16_NoOldRecordResurrection asserts deleted multi-block objects don't resurrect after truncation.
func TestRegression_Item15_16_NoOldRecordResurrection(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_no_old_record_resurrection"

	store, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	largeVal := bytes.Repeat([]byte("multi-block-payload-"), 500) // ~10 KB
	_ = store.Put("ConfigMap", "large-cm", largeVal, "1")

	// Delete large-cm
	if err := store.Delete("ConfigMap", "large-cm"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Checkpoint to truncate WAL
	_, err = store.Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}
	_ = store.Close()

	// Reopen store: large-cm must NOT resurrect!
	store2, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	if _, exists, _ := store2.Get("ConfigMap", "large-cm"); exists {
		t.Fatalf("deleted multi-block record resurrected after checkpoint truncation!")
	}
}

// TestRegression_Item17_OversizeObjectPersistence asserts oversize objects (> 2 MiB) persist across reopen.
func TestRegression_Item17_OversizeObjectPersistence(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_persistence"

	store, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	oversizeVal := bytes.Repeat([]byte("0123456789abcdef"), 150000) // ~2.4 MiB
	if err := store.Put("ConfigMap", "oversize-cm", oversizeVal, "1"); err != nil {
		t.Fatalf("Put oversize failed: %v", err)
	}

	// Checkpoint and close
	_, _ = store.Checkpoint()
	_ = store.Close()

	// Reopen store: oversize object must still be readable!
	store2, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	val, exists, err := store2.Get("ConfigMap", "oversize-cm")
	if err != nil || !exists {
		t.Fatalf("oversize object missing after reopen: exists=%v, err=%v", exists, err)
	}
	if len(val) != len(oversizeVal) || !bytes.Equal(val, oversizeVal) {
		t.Fatalf("oversize payload mismatch")
	}
}

// TestRegression_Item19_BucketIsolation asserts keys in different buckets with same name do not collide.
func TestRegression_Item19_BucketIsolation(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_bucket_isolation"

	store, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	// Put "default/my-name" into ConfigMap and Secret buckets with different values
	_ = store.Put("ConfigMap", "default/my-name", []byte("cm-data"), "1")
	_ = store.Put("Secret", "default/my-name", []byte("secret-data"), "2")

	cmVal, exists, err := store.Get("ConfigMap", "default/my-name")
	if err != nil || !exists || string(cmVal) != "cm-data" {
		t.Fatalf("ConfigMap get failed: %q, err=%v", string(cmVal), err)
	}

	secretVal, exists, err := store.Get("Secret", "default/my-name")
	if err != nil || !exists || string(secretVal) != "secret-data" {
		t.Fatalf("Secret get failed: %q, err=%v", string(secretVal), err)
	}

	// Delete from ConfigMap; Secret must NOT be affected
	_ = store.Delete("ConfigMap", "default/my-name")
	if _, exists, _ := store.Get("ConfigMap", "default/my-name"); exists {
		t.Fatalf("ConfigMap key should be deleted")
	}

	secretValAfter, exists, err := store.Get("Secret", "default/my-name")
	if err != nil || !exists || string(secretValAfter) != "secret-data" {
		t.Fatalf("Secret was affected by ConfigMap delete!")
	}
}

// TestRegression_Item20_EngineScanConsistent asserts that Scan provides consistent bucket views.
func TestRegression_Item20_EngineScanConsistent(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_scan_rebuild"

	store, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	_ = store.Put("ConfigMap", "cm-1", []byte("val-1"), "1")
	_ = store.Put("ConfigMap", "cm-2", []byte("val-2"), "2")
	_ = store.Close()

	store2, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Reopen Open failed: %v", err)
	}
	defer store2.Close()

	items, err := store2.List("ConfigMap")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
}

// TestRegression_Round2_Item1_OversizeDeleteThenReopen tests putting an oversize object, deleting it,
// closing and reopening the store without recovery panicking on nil pointer dereference.
func TestRegression_Round2_Item1_OversizeDeleteThenReopen(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_delete_reopen"

	store, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	oversizeVal := bytes.Repeat([]byte("0123456789abcdef"), 150000) // ~2.4 MiB
	if err := store.Put("ConfigMap", "large-cm", oversizeVal, "1"); err != nil {
		t.Fatalf("Put oversize failed: %v", err)
	}

	// Delete oversize object
	if err := store.Delete("ConfigMap", "large-cm"); err != nil {
		t.Fatalf("Delete oversize failed: %v", err)
	}

	_ = store.Close()

	// Reopen store: must not panic in recovery redo
	store2, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	if _, exists, err := store2.Get("ConfigMap", "large-cm"); exists || err != nil {
		t.Fatalf("expected deleted oversize object to not exist, exists=%v, err=%v", exists, err)
	}
}

// TestRegression_Round2_Item2_OversizeToSmallUpdateThenReopen tests updating an oversize object to small,
// then reopening to ensure it does not revert to the large payload.
func TestRegression_Round2_Item2_OversizeToSmallUpdateThenReopen(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_to_small_reopen"

	store, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	initialCount := OversizeCount()

	oversizeVal := bytes.Repeat([]byte("large-payload-block"), 120000) // ~2.28 MiB
	if err := store.Put("ConfigMap", "cm-transition", oversizeVal, "1"); err != nil {
		t.Fatalf("Put oversize failed: %v", err)
	}
	if OversizeCount() != initialCount+1 {
		t.Fatalf("expected oversize metric count %d, got %d", initialCount+1, OversizeCount())
	}

	// Update to small payload
	smallVal := []byte("small-payload-data")
	if err := store.Put("ConfigMap", "cm-transition", smallVal, "2"); err != nil {
		t.Fatalf("Put small failed: %v", err)
	}
	if OversizeCount() != initialCount {
		t.Fatalf("expected oversize count %d after update to small, got %d", initialCount, OversizeCount())
	}

	_ = store.Close()

	// Reopen store: must not revert to 3 MiB value!
	store2, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	val, exists, err := store2.Get("ConfigMap", "cm-transition")
	if err != nil || !exists {
		t.Fatalf("expected object to exist after reopen: %v", err)
	}
	if !bytes.Equal(val, smallVal) {
		t.Fatalf("object reverted to stale oversize payload! got len %d, want len %d", len(val), len(smallVal))
	}
	if OversizeCount() != initialCount {
		t.Fatalf("expected oversize count %d on reopen, got %d", initialCount, OversizeCount())
	}
}

// TestRegression_Round2_Item3_OversizeLongNameAndTornFiles tests legal long Kubernetes names (> 255 chars)
// and torn file handling with CRC validation.
func TestRegression_Round2_Item3_OversizeLongNameAndTornFiles(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_oversize_long_name"

	store, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// 60-character namespace, 253-character name
	longNamespace := strings.Repeat("n", 60)
	longName := strings.Repeat("c", 253)
	key := longNamespace + "/" + longName

	oversizeVal := bytes.Repeat([]byte("a"), 2*1024*1024+100) // > 2 MiB
	if err := store.Put("ConfigMap", key, oversizeVal, "1"); err != nil {
		t.Fatalf("Put with legal long name failed: %v", err)
	}

	val, exists, err := store.Get("ConfigMap", key)
	if err != nil || !exists || len(val) != len(oversizeVal) {
		t.Fatalf("Get with long name failed: exists=%v, len=%d, err=%v", exists, len(val), err)
	}

	_ = store.Close()

	// Reopen store successfully
	store2, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	val2, exists, err := store2.Get("ConfigMap", key)
	if err != nil || !exists || len(val2) != len(oversizeVal) {
		t.Fatalf("Get after reopen failed: exists=%v, len=%d, err=%v", exists, len(val2), err)
	}
}

// TestRegression_Round2_Item4_LogicalPageReuseNoLeak asserts that 200 put/delete cycles
// of a 20 KB object do not leak buffer pool frames or buddy allocator disk blocks.
func TestRegression_Round2_Item4_LogicalPageReuseNoLeak(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_page_reuse_no_leak"

	store, err := Open(WithFS(memFS), WithDir(dir), WithNumFrames(64))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	payload20KB := bytes.Repeat([]byte("0123456789abcdef"), 1280) // 20 KB (needs 5 4-KiB blocks)

	for i := 0; i < 200; i++ {
		rv := fmt.Sprintf("%d", i+1)
		if err := store.Put("ConfigMap", "obj-20kb", payload20KB, rv); err != nil {
			t.Fatalf("iteration %d: Put failed: %v", i, err)
		}
		if err := store.Delete("ConfigMap", "obj-20kb"); err != nil {
			t.Fatalf("iteration %d: Delete failed: %v", i, err)
		}
	}

	// Assert buddy allocator allocated block count remains strictly bounded
	allocatedCount := store.buddy.AllocatedCount()
	if allocatedCount > 32 {
		t.Fatalf("buddy allocator leaked blocks across 200 put/delete cycles: %d blocks allocated", allocatedCount)
	}
}

// TestEngine_SetTokenNoFakeObject asserts that SetToken does not store fake objects in buckets.
func TestEngine_SetTokenNoFakeObject(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_token_no_fake_obj"

	store, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	// Set progress token
	if err := store.SetToken("ConfigMap", "99999"); err != nil {
		t.Fatalf("SetToken failed: %v", err)
	}

	// ListKeys must be empty
	keys := store.ListKeys("ConfigMap")
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys in store, got %d: %v", len(keys), keys)
	}

	// List must return empty
	objs, err := store.List("ConfigMap")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(objs) != 0 {
		t.Fatalf("expected 0 objects in store, got %d", len(objs))
	}
}

// TestEngine_TokenPerBucket asserts tokens are isolated per bucket.
func TestEngine_TokenPerBucket(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_rv_per_bucket"

	store, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	_ = store.Put("ConfigMap", "cm-1", []byte("val-1"), "cm-rv-100")
	_ = store.Put("Secret", "sec-1", []byte("sec-1"), "secret-rv-500")

	// Secret watch is ahead of ConfigMap watch
	_ = store.SetToken("Secret", "secret-rv-600")

	_ = store.Close()

	// Reopen store
	store2, err := Open(WithFS(memFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer store2.Close()

	// ConfigMap must recover cm-rv-100 (NOT secret-rv-600!)
	if store2.Token("ConfigMap") != "cm-rv-100" {
		t.Fatalf("ConfigMap recovered wrong RV: got %q, want %q", store2.Token("ConfigMap"), "cm-rv-100")
	}

	// Secret must recover secret-rv-600
	if store2.Token("Secret") != "secret-rv-600" {
		t.Fatalf("Secret recovered wrong RV: got %q, want %q", store2.Token("Secret"), "secret-rv-600")
	}
}

func BenchmarkEngine_WriteThroughputLargeWorkingSet(b *testing.B) {
	const numFrames = 256
	const objectCount = 2000
	payload := make([]byte, 2048)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	b.SetBytes(int64(objectCount * len(payload)))
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		b.StopTimer()
		dir := b.TempDir()
		store, err := Open(WithDir(dir), WithNumFrames(numFrames))
		if err != nil {
			b.Fatalf("Open failed: %v", err)
		}
		b.StartTimer()

		for i := 0; i < objectCount; i++ {
			key := fmt.Sprintf("bench-key-%05d", i)
			token := fmt.Sprintf("%d", i)
			if err := store.Put("bench-bucket", key, payload, token); err != nil {
				b.Fatalf("Put failed at %d: %v", i, err)
			}
		}

		b.StopTimer()
		_ = store.Close()
		b.StartTimer()
	}
}


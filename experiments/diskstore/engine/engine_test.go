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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
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
	_, _ = rand.Read(oversizePayload[len("large-payload-prefix-data"):])

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

	// Evict page from memory pool blocks by unloading pool blocks
	store.bp.mu.Lock()
	desc := store.bp.pageTable[entryV1.LogicalPage]
	desc.PoolBlocks = nil // force reload from disk
	desc.PhysicalBlock = locV1
	store.bp.mu.Unlock()

	// Substitute older valid page copy underneath the block pool on disk
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

	oversizeVal := make([]byte, 2300000) // ~2.2 MiB
	copy(oversizeVal, []byte("large-payload-block"))
	_, _ = rand.Read(oversizeVal[len("large-payload-block"):])
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
// of a 20 KB object do not leak block pool blocks or buddy allocator disk blocks.
func TestRegression_Round2_Item4_LogicalPageReuseNoLeak(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_page_reuse_no_leak"

	store, err := Open(WithFS(memFS), WithDir(dir), WithNumPoolBlocks(64))
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

func TestKeyBoundaries_TableTest(t *testing.T) {
	keys := []struct {
		name string
		key  string
	}{
		{"Key1B", strings.Repeat("a", 1)},
		{"Key64B", strings.Repeat("b", 64)},
		{"Key65B", strings.Repeat("c", 65)},
		{"Key300B", strings.Repeat("d", 300)},
		{"Key65535B", strings.Repeat("e", 65535)},
	}

	bucket := "b"

	for _, tc := range keys {
		t.Run(tc.name, func(t *testing.T) {
			qKey := qualifyKey(bucket, tc.key)
			qKeyLen := len(qKey)

			// Collect boundary payload sizes
			payloadSizes := make(map[int]bool)

			// 1. Slotted limit (±1 byte)
			slottedLimit := MaxSlottedRecordSize - PageRecordHeaderSize - qKeyLen
			for _, delta := range []int{-1, 0, 1} {
				sz := slottedLimit + delta
				if sz >= 0 {
					payloadSizes[sz] = true
				}
			}

			// 2. Each power-of-two multi-block limit (±1 byte)
			for numBlocks := 1; numBlocks <= MaxMultiBlockCount; numBlocks *= 2 {
				mbLimit := (numBlocks * BlockUsableSize) - PageRecordHeaderSize - qKeyLen
				for _, delta := range []int{-1, 0, 1} {
					sz := mbLimit + delta
					if sz >= 0 {
						payloadSizes[sz] = true
					}
				}
			}

			// Sort payload sizes
			sortedSizes := make([]int, 0, len(payloadSizes))
			for sz := range payloadSizes {
				sortedSizes = append(sortedSizes, sz)
			}
			sort.Ints(sortedSizes)

			for _, pLen := range sortedSizes {
				pLen := pLen
				t.Run(fmt.Sprintf("Payload_%d", pLen), func(t *testing.T) {
					memFS := NewMemFS()
					dir := "test_boundary_store"

					store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
					if err != nil {
						t.Fatalf("Open failed: %v", err)
					}
					defer func() {
						if !store.closed.Load() {
							_ = store.Close()
						}
					}()

					payload := make([]byte, pLen)
					for i := range payload {
						payload[i] = byte((i*37 + 11) % 256)
					}

					putErr := store.Put(bucket, tc.key, payload, "rv-1")
					if putErr != nil {
						// Must be a non-sticky "too large" error
						if !errors.Is(putErr, ErrObjectOversize) {
							t.Fatalf("expected ErrObjectOversize, got %v", putErr)
						}
						if store.isFailed() {
							t.Fatalf("store unexpectedly entered failed state: %v", store.failErr())
						}

						// Subsequent operations must succeed
						probeVal := []byte("probe-value")
						if err := store.Put(bucket, "probe", probeVal, "rv-probe"); err != nil {
							t.Fatalf("Put after non-sticky error failed: %v", err)
						}
						got, exists, err := store.Get(bucket, "probe")
						if err != nil || !exists || !bytes.Equal(got, probeVal) {
							t.Fatalf("Get after non-sticky error failed: exists=%v, err=%v", exists, err)
						}

						// Reopen must succeed
						_ = store.Close()
						store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
						if err != nil {
							t.Fatalf("reopen after non-sticky error failed: %v", err)
						}
						_ = store2.Close()
					} else {
						// Must round-trip through Get
						got, exists, err := store.Get(bucket, tc.key)
						if err != nil || !exists {
							t.Fatalf("Get failed: exists=%v, err=%v", exists, err)
						}
						if !bytes.Equal(got, payload) {
							t.Fatalf("payload mismatch: len(got)=%d, len(want)=%d", len(got), len(payload))
						}

						// Must round-trip through close and reopen
						if err := store.Close(); err != nil {
							t.Fatalf("Close failed: %v", err)
						}
						store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
						if err != nil {
							t.Fatalf("reopen failed: %v", err)
						}
						defer store2.Close()

						got2, exists2, err := store2.Get(bucket, tc.key)
						if err != nil || !exists2 {
							t.Fatalf("Get after reopen failed: exists=%v, err=%v", exists2, err)
						}
						if !bytes.Equal(got2, payload) {
							t.Fatalf("payload mismatch after reopen: len(got)=%d, len(want)=%d", len(got2), len(payload))
						}
					}
				})
			}
		})
	}
}

func TestSlottedPage_KeyOver64BytesNearBoundary(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_slotted_boundary"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	key100 := strings.Repeat("k", 100)
	for _, sz := range []int{3928, 3938, 3939, 3950, 3999} {
		payload := make([]byte, sz)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		if err := store.Put("ConfigMap", key100, payload, fmt.Sprintf("%d", sz)); err != nil {
			t.Fatalf("Put for size %d failed: %v", sz, err)
		}
		got, exists, err := store.Get("ConfigMap", key100)
		if err != nil || !exists || !bytes.Equal(got, payload) {
			t.Fatalf("Get for size %d failed: exists=%v, err=%v", sz, exists, err)
		}
	}

	_ = store.Close()
	store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer store2.Close()

	lastPayload := make([]byte, 3999)
	for i := range lastPayload {
		lastPayload[i] = byte(i % 251)
	}
	got2, exists2, err := store2.Get("ConfigMap", key100)
	if err != nil || !exists2 || !bytes.Equal(got2, lastPayload) {
		t.Fatalf("Get after reopen failed: exists=%v, err=%v", exists2, err)
	}
}

func TestMultiBlockPage_KeyOver64BytesNearBoundary(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_multiblock_boundary"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	key300 := strings.Repeat("m", 300)
	for _, sz := range []int{7800, 7814, 7815, 7900, 8000, 8050} {
		payload := make([]byte, sz)
		for i := range payload {
			payload[i] = byte((i * 13) % 256)
		}
		if err := store.Put("ConfigMap", key300, payload, fmt.Sprintf("%d", sz)); err != nil {
			t.Fatalf("Put for size %d failed: %v", sz, err)
		}
		got, exists, err := store.Get("ConfigMap", key300)
		if err != nil || !exists || !bytes.Equal(got, payload) {
			t.Fatalf("Get for size %d failed: exists=%v, err=%v", sz, exists, err)
		}
	}

	_ = store.Close()
	store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer store2.Close()

	lastPayload := make([]byte, 8050)
	for i := range lastPayload {
		lastPayload[i] = byte((i * 13) % 256)
	}
	got2, exists2, err := store2.Get("ConfigMap", key300)
	if err != nil || !exists2 || !bytes.Equal(got2, lastPayload) {
		t.Fatalf("Get after reopen failed: exists=%v, err=%v", exists2, err)
	}
}

func TestMultiBlockPage_RecordSizesBetweenSlottedAndBlockLimitRoundTrip(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_multiblock_transition_store"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	bucket := "b"
	key := "k"
	qKey := qualifyKey(bucket, key)
	overhead := PageRecordHeaderSize + len(qKey) // 14 + 3 = 17 bytes

	// Record sizes 4053 and 4064 fall between the max slotted record limit (4052)
	// and the 1-block usable capacity (4064). They must allocate 2 blocks (order 1)
	// so crash recovery and Get (which assume NumBlocks == 1 is slotted) decode them as multi-block.
	recordSizes := []int{4053, 4064}
	payloads := make(map[int][]byte)

	for _, recSize := range recordSizes {
		pLen := recSize - overhead
		payload := make([]byte, pLen)
		for i := range payload {
			payload[i] = byte((i*41 + 7) % 256)
		}
		payloads[recSize] = payload

		k := fmt.Sprintf("k-%d", recSize)
		if err := store.Put(bucket, k, payload, fmt.Sprintf("%d", recSize)); err != nil {
			t.Fatalf("Put for record size %d failed: %v", recSize, err)
		}

		// Verify keyIndex entry has NumBlocks == 2
		store.keyMu.RLock()
		entry, ok := store.keyIndex[qualifyKey(bucket, k)]
		store.keyMu.RUnlock()
		if !ok || entry.NumBlocks != 2 {
			t.Fatalf("expected NumBlocks == 2 for record size %d, got ok=%v, numBlocks=%d", recSize, ok, entry.NumBlocks)
		}

		got, exists, err := store.Get(bucket, k)
		if err != nil || !exists || !bytes.Equal(got, payload) {
			t.Fatalf("Get for record size %d failed: exists=%v, err=%v", recSize, exists, err)
		}
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Reopen and verify crash recovery decodes both records correctly
	store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer store2.Close()

	for _, recSize := range recordSizes {
		k := fmt.Sprintf("k-%d", recSize)
		got, exists, err := store2.Get(bucket, k)
		if err != nil || !exists || !bytes.Equal(got, payloads[recSize]) {
			t.Fatalf("Get after reopen for record size %d failed: exists=%v, err=%v", recSize, exists, err)
		}
	}
}

func makeIncompressible(size int) []byte {
	b := make([]byte, size)
	state := uint64(0xdeadbeefcafebabe)
	for i := range b {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		b[i] = byte(state)
	}
	return b
}

func TestPageTransitions_NoResurrection(t *testing.T) {
	type transitionCase struct {
		name       string
		codec      CompressionCodec
		setup      func(t *testing.T, store *Engine, bucket string)
		val1       []byte
		val2       []byte
		verifyPost func(t *testing.T, store *Engine, bucket, key string, oldEntry KeyIndexEntry)
	}

	cases := []transitionCase{
		{
			name:  "slotted_to_slotted_another_page",
			codec: CodecNone,
			setup: func(t *testing.T, store *Engine, bucket string) {
				// Fill active slotted page mostly full with a sibling record
				if err := store.Put(bucket, "sibling", makeIncompressible(3500), "s-1"); err != nil {
					t.Fatalf("Put sibling failed: %v", err)
				}
			},
			val1: makeIncompressible(400),
			val2: makeIncompressible(800), // cannot fit in page 1 with sibling, must allocate page 2
			verifyPost: func(t *testing.T, store *Engine, bucket, key string, oldEntry KeyIndexEntry) {
				store.keyMu.RLock()
				newEntry := store.keyIndex[qualifyKey(bucket, key)]
				store.keyMu.RUnlock()
				if newEntry.LogicalPage == oldEntry.LogicalPage {
					t.Fatalf("expected record to move to another page, but stayed on %d", newEntry.LogicalPage)
				}
				// Verify slot on old page was deleted
				handle, err := store.bp.PinPage(oldEntry.LogicalPage)
				if err != nil {
					t.Fatalf("PinPage failed: %v", err)
				}
				defer handle.Unpin()
				handle.Desc.Mu.Lock()
				defer handle.Desc.Mu.Unlock()
				slotted, _ := WrapSlottedPage(handle.Block(0))
				if _, _, _, err := slotted.Get(oldEntry.Slot); !errors.Is(err, ErrSlotNotFound) {
					t.Fatalf("expected old slot %d to be deleted, got err=%v", oldEntry.Slot, err)
				}
			},
		},
		{
			name:  "slotted_to_multiblock",
			codec: CodecNone,
			val1:  makeIncompressible(500),
			val2:  makeIncompressible(10 * 1024),
			verifyPost: func(t *testing.T, store *Engine, bucket, key string, oldEntry KeyIndexEntry) {
				store.keyMu.RLock()
				newEntry := store.keyIndex[qualifyKey(bucket, key)]
				store.keyMu.RUnlock()
				if newEntry.NumBlocks <= 1 {
					t.Fatalf("expected multi-block page, got NumBlocks=%d", newEntry.NumBlocks)
				}
				// If old page was not reused as targetPage, it should be in emptyLogicalPages
				if newEntry.LogicalPage != oldEntry.LogicalPage && !store.emptyPages.Contains(oldEntry.LogicalPage) {
					t.Fatalf("expected old slotted page %d to be in emptyPages %v", oldEntry.LogicalPage, store.emptyPages.Pages())
				}
			},
		},
		{
			name:  "multiblock_to_slotted",
			codec: CodecNone,
			val1:  makeIncompressible(20 * 1024),
			val2:  makeIncompressible(500),
			verifyPost: func(t *testing.T, store *Engine, bucket, key string, oldEntry KeyIndexEntry) {
				store.keyMu.RLock()
				newEntry := store.keyIndex[qualifyKey(bucket, key)]
				store.keyMu.RUnlock()
				if newEntry.NumBlocks != 1 {
					t.Fatalf("expected slotted page (NumBlocks=1), got %d", newEntry.NumBlocks)
				}
				if !store.emptyPages.Contains(oldEntry.LogicalPage) {
					t.Fatalf("expected old multi-block page %d to be in emptyPages %v", oldEntry.LogicalPage, store.emptyPages.Pages())
				}
			},
		},
		{
			name:  "multiblock_to_multiblock_shrink",
			codec: CodecNone,
			val1:  makeIncompressible(25 * 1024), // 8 blocks
			val2:  makeIncompressible(6 * 1024),  // 2 blocks
			verifyPost: func(t *testing.T, store *Engine, bucket, key string, oldEntry KeyIndexEntry) {
				store.keyMu.RLock()
				newEntry := store.keyIndex[qualifyKey(bucket, key)]
				store.keyMu.RUnlock()
				if newEntry.NumBlocks >= oldEntry.NumBlocks {
					t.Fatalf("expected block count to shrink: old=%d, new=%d", oldEntry.NumBlocks, newEntry.NumBlocks)
				}
				if newEntry.LogicalPage != oldEntry.LogicalPage && !store.emptyPages.Contains(oldEntry.LogicalPage) {
					t.Fatalf("expected old multi-block page %d to be in emptyPages", oldEntry.LogicalPage)
				}
			},
		},
		{
			name:  "multiblock_to_multiblock_grow",
			codec: CodecNone,
			val1:  makeIncompressible(6 * 1024),  // 2 blocks
			val2:  makeIncompressible(25 * 1024), // 8 blocks
			verifyPost: func(t *testing.T, store *Engine, bucket, key string, oldEntry KeyIndexEntry) {
				store.keyMu.RLock()
				newEntry := store.keyIndex[qualifyKey(bucket, key)]
				store.keyMu.RUnlock()
				if newEntry.NumBlocks <= oldEntry.NumBlocks {
					t.Fatalf("expected block count to grow: old=%d, new=%d", oldEntry.NumBlocks, newEntry.NumBlocks)
				}
				if newEntry.LogicalPage != oldEntry.LogicalPage && !store.emptyPages.Contains(oldEntry.LogicalPage) {
					t.Fatalf("expected old multi-block page %d to be in emptyPages", oldEntry.LogicalPage)
				}
			},
		},
		{
			name:  "slotted_to_oversize",
			codec: CodecNone,
			val1:  makeIncompressible(500),
			val2:  makeIncompressible(MaxPayloadCapacity + 1024),
			verifyPost: func(t *testing.T, store *Engine, bucket, key string, oldEntry KeyIndexEntry) {
				store.keyMu.RLock()
				newEntry := store.keyIndex[qualifyKey(bucket, key)]
				store.keyMu.RUnlock()
				if !newEntry.IsOversize {
					t.Fatalf("expected oversize object")
				}
				if !store.emptyPages.Contains(oldEntry.LogicalPage) {
					t.Fatalf("expected old slotted page %d to be in emptyPages", oldEntry.LogicalPage)
				}
			},
		},
		{
			name:  "multiblock_to_oversize",
			codec: CodecNone,
			val1:  makeIncompressible(20 * 1024),
			val2:  makeIncompressible(MaxPayloadCapacity + 1024),
			verifyPost: func(t *testing.T, store *Engine, bucket, key string, oldEntry KeyIndexEntry) {
				store.keyMu.RLock()
				newEntry := store.keyIndex[qualifyKey(bucket, key)]
				store.keyMu.RUnlock()
				if !newEntry.IsOversize {
					t.Fatalf("expected oversize object")
				}
				if !store.emptyPages.Contains(oldEntry.LogicalPage) {
					t.Fatalf("expected old multi-block page %d to be in emptyPages", oldEntry.LogicalPage)
				}
			},
		},
		{
			name:  "oversize_to_slotted",
			codec: CodecNone,
			val1:  makeIncompressible(MaxPayloadCapacity + 1024),
			val2:  makeIncompressible(500),
			verifyPost: func(t *testing.T, store *Engine, bucket, key string, oldEntry KeyIndexEntry) {
				store.keyMu.RLock()
				newEntry := store.keyIndex[qualifyKey(bucket, key)]
				store.keyMu.RUnlock()
				if newEntry.IsOversize || newEntry.NumBlocks != 1 {
					t.Fatalf("expected slotted object, got isOversize=%v, numBlocks=%d", newEntry.IsOversize, newEntry.NumBlocks)
				}
				// Verify oversize file was removed
				p := store.oversizeFilePath(qualifyKey(bucket, key))
				if f, err := store.fs.Open(p); err == nil {
					_ = f.Close()
					t.Fatalf("expected oversize file %s to be removed, but still exists", p)
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("unexpected error checking oversize file: %v", err)
				}
			},
		},
		{
			name:  "oversize_to_multiblock",
			codec: CodecNone,
			val1:  makeIncompressible(MaxPayloadCapacity + 1024),
			val2:  makeIncompressible(20 * 1024),
			verifyPost: func(t *testing.T, store *Engine, bucket, key string, oldEntry KeyIndexEntry) {
				store.keyMu.RLock()
				newEntry := store.keyIndex[qualifyKey(bucket, key)]
				store.keyMu.RUnlock()
				if newEntry.IsOversize || newEntry.NumBlocks <= 1 {
					t.Fatalf("expected multi-block object, got isOversize=%v, numBlocks=%d", newEntry.IsOversize, newEntry.NumBlocks)
				}
				// Verify oversize file was removed
				p := store.oversizeFilePath(qualifyKey(bucket, key))
				if f, err := store.fs.Open(p); err == nil {
					_ = f.Close()
					t.Fatalf("expected oversize file %s to be removed, but still exists", p)
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("unexpected error checking oversize file: %v", err)
				}
			},
		},
		{
			name:  "same_raw_size_different_compressibility",
			codec: CodecZstd,
			val1:  makeIncompressible(20 * 1024), // incompressible -> multi-block
			val2:  make([]byte, 20*1024),         // all zeros -> compressible to ~50 B -> slotted
			verifyPost: func(t *testing.T, store *Engine, bucket, key string, oldEntry KeyIndexEntry) {
				store.keyMu.RLock()
				newEntry := store.keyIndex[qualifyKey(bucket, key)]
				store.keyMu.RUnlock()
				if oldEntry.NumBlocks <= 1 {
					t.Fatalf("expected incompressible payload to be multi-block, got %d", oldEntry.NumBlocks)
				}
				if newEntry.NumBlocks != 1 {
					t.Fatalf("expected compressed zero payload to be slotted (NumBlocks=1), got %d", newEntry.NumBlocks)
				}
				if !store.emptyPages.Contains(oldEntry.LogicalPage) {
					t.Fatalf("expected old multi-block page %d to be in emptyPages", oldEntry.LogicalPage)
				}
			},
		},
	}

	modes := []struct {
		name                 string
		checkpointPostDelete bool
	}{
		{"HeapScan_CheckpointBeforeReopen", true},
		{"RedoReplay_NoCheckpointBeforeReopen", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			for _, m := range modes {
				m := m
				t.Run(m.name, func(t *testing.T) {
					memFS := NewMemFS()
					dir := fmt.Sprintf("test_transition_%s_%s", tc.name, m.name)

					store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(tc.codec))
					if err != nil {
						t.Fatalf("Open failed: %v", err)
					}

					bucket := "testb"
					key := "target-key"

					if tc.setup != nil {
						tc.setup(t, store, bucket)
					}

					// 1. Put val1
					if err := store.Put(bucket, key, tc.val1, "rv-1"); err != nil {
						t.Fatalf("Put val1 failed: %v", err)
					}

					// Checkpoint so val1 is durable on disk
					if _, err := store.Checkpoint(); err != nil {
						t.Fatalf("Checkpoint 1 failed: %v", err)
					}

					// Capture location of val1
					store.keyMu.RLock()
					oldEntry := store.keyIndex[qualifyKey(bucket, key)]
					store.keyMu.RUnlock()

					// 2. Put val2 (transition)
					if err := store.Put(bucket, key, tc.val2, "rv-2"); err != nil {
						t.Fatalf("Put val2 failed: %v", err)
					}

					// Verify val2 is readable
					gotVal2, exists, err := store.Get(bucket, key)
					if err != nil || !exists || !bytes.Equal(gotVal2, tc.val2) {
						t.Fatalf("Get after Put val2 failed: exists=%v, err=%v", exists, err)
					}

					// Run verifyPost on old location
					if tc.verifyPost != nil {
						tc.verifyPost(t, store, bucket, key, oldEntry)
					}

					// 3. Delete key
					if err := store.Delete(bucket, key); err != nil {
						t.Fatalf("Delete failed: %v", err)
					}

					// 4. Reopen either after Checkpoint (Heap scan) or without Checkpoint (Redo replay)
					if m.checkpointPostDelete {
						if _, err := store.Checkpoint(); err != nil {
							t.Fatalf("Checkpoint 2 failed: %v", err)
						}
						if err := store.Close(); err != nil {
							t.Fatalf("Close failed: %v", err)
						}
					} else {
						// Ensure WAL is synced
						if err := store.wal.Sync(); err != nil {
							t.Fatalf("wal.Sync failed: %v", err)
						}
						// Prevent checkpoint during Close
						store.cp = nil
						if err := store.Close(); err != nil {
							t.Fatalf("Close without checkpoint failed: %v", err)
						}
					}

					store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(tc.codec))
					if err != nil {
						t.Fatalf("reopen failed: %v", err)
					}
					defer store2.Close()

					// 5. Verify deleted key does NOT resurrect
					resVal, found, err := store2.Get(bucket, key)
					if err != nil {
						t.Fatalf("Get after reopen failed: %v", err)
					}
					if found {
						t.Fatalf("KEY RESURRECTED! Got len=%d, expected found=false", len(resVal))
					}

					// If sibling existed, verify sibling is still intact
					if tc.setup != nil {
						sVal, sFound, sErr := store2.Get(bucket, "sibling")
						if sErr != nil || !sFound {
							t.Fatalf("sibling key missing after reopen: found=%v, err=%v", sFound, sErr)
						}
						if len(sVal) != 3500 {
							t.Fatalf("sibling key corrupted: len=%d, want 3500", len(sVal))
						}
					}
				})
			}
		})
	}
}

func TestRecovery_MultiBlockRedoIdempotency(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_mb_redo_idempotent"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	bucket := "test"
	key := "mb-key"
	val := makeIncompressible(20 * 1024)

	if err := store.Put(bucket, key, val, "rv-1"); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	store.keyMu.RLock()
	entry1 := store.keyIndex[qualifyKey(bucket, key)]
	store.keyMu.RUnlock()

	// Flush the multi-block page to the heap file so the heap already reflects the write,
	// but do NOT checkpoint. WAL records remain durable so redo will replay them.
	if err := store.bp.FlushPage(entry1.LogicalPage); err != nil {
		t.Fatalf("FlushPage failed: %v", err)
	}
	if err := store.heapFile.Sync(); err != nil {
		t.Fatalf("heapFile.Sync failed: %v", err)
	}
	if err := store.wal.Sync(); err != nil {
		t.Fatalf("wal.Sync failed: %v", err)
	}

	// Prevent checkpoint on Close
	store.cp = nil
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// First reopen
	store2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen 1 failed: %v", err)
	}
	store2.keyMu.RLock()
	entry2 := store2.keyIndex[qualifyKey(bucket, key)]
	store2.keyMu.RUnlock()

	if entry2.LogicalPage != entry1.LogicalPage {
		t.Fatalf("Reopen 1 moved key to logical page %d, want %d", entry2.LogicalPage, entry1.LogicalPage)
	}
	if entry2.NumBlocks != entry1.NumBlocks {
		t.Fatalf("Reopen 1 changed NumBlocks to %d, want %d", entry2.NumBlocks, entry1.NumBlocks)
	}

	// Close again without checkpoint
	store2.cp = nil
	if err := store2.Close(); err != nil {
		t.Fatalf("Close 2 failed: %v", err)
	}

	// Second reopen
	store3, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen 2 failed: %v", err)
	}
	defer store3.Close()

	store3.keyMu.RLock()
	entry3 := store3.keyIndex[qualifyKey(bucket, key)]
	store3.keyMu.RUnlock()

	if entry3.LogicalPage != entry1.LogicalPage {
		t.Fatalf("Reopen 2 moved key to logical page %d, want %d", entry3.LogicalPage, entry1.LogicalPage)
	}
	if entry3.NumBlocks != entry1.NumBlocks {
		t.Fatalf("Reopen 2 changed NumBlocks to %d, want %d", entry3.NumBlocks, entry1.NumBlocks)
	}

	// Verify allocated blocks in buddy allocator match expected count.
	// A single 20 KB object uses 8 blocks (order 3). Reopening must not leak blocks.
	store3.buddy.mu.Lock()
	numAllocated := len(store3.buddy.allocated)
	store3.buddy.mu.Unlock()
	if numAllocated != 1 {
		t.Fatalf("expected exactly 1 allocated buddy block run, got %d", numAllocated)
	}

	got, found, err := store3.Get(bucket, key)
	if err != nil || !found || !bytes.Equal(got, val) {
		t.Fatalf("Get after reopens failed: found=%v, err=%v", found, err)
	}
}

func BenchmarkEngine_WriteThroughputLargeWorkingSet(b *testing.B) {
	const numPoolBlocks = 256
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
		store, err := Open(WithDir(dir), WithNumPoolBlocks(numPoolBlocks))
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

		if store.DirectIOFallbackCount() != 0 {
			b.Fatalf("expected direct I/O active, but fallback count was %d", store.DirectIOFallbackCount())
		}

		b.StopTimer()
		_ = store.Close()
		b.StartTimer()
	}
}

// TestStress_ReadersWritersAndCheckpoints tests that many concurrent readers calling Get on
// keys that writers rewrite continuously with checkpoints running complete with no read errors.
func TestStress_ReadersWritersAndCheckpoints(t *testing.T) {
	memFS := NewMemFS()
	store, err := Open(WithFS(memFS), WithDir("stress_store"), WithNumPoolBlocks(64))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	const numKeys = 10
	bucket := "StressBucket"

	// Seed keys
	for i := 0; i < numKeys; i++ {
		key := fmt.Sprintf("k-%d", i)
		if err := store.Put(bucket, key, []byte("initial"), "0"); err != nil {
			t.Fatalf("initial Put failed: %v", err)
		}
	}

	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	// Writers
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			step := 0
			for {
				select {
				case <-stopCh:
					return
				default:
					key := fmt.Sprintf("k-%d", step%numKeys)
					val := fmt.Sprintf("w%d-%d", writerID, step)
					_ = store.Put(bucket, key, []byte(val), fmt.Sprintf("%d", step))
					step++
				}
			}
		}(w)
	}

	// Checkpointer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
				_, _ = store.Checkpoint()
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()

	// Readers
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					key := fmt.Sprintf("k-%d", mathrand.Intn(numKeys))
					val, exists, err := store.Get(bucket, key)
					if err != nil {
						t.Errorf("concurrent Get failed: %v", err)
						return
					}
					if !exists || len(val) == 0 {
						t.Errorf("Get returned exists=%v, len(val)=%d", exists, len(val))
						return
					}
				}
			}
		}()
	}

	time.Sleep(500 * time.Millisecond)
	close(stopCh)
	wg.Wait()
}

// TestGet_MissingOversizeObjectReturnsNotFound verifies that a missing oversize object
// returns exists=false and does not cause a fatal corruption error.
func TestGet_MissingOversizeObjectReturnsNotFound(t *testing.T) {
	memFS := NewMemFS()
	store, err := Open(WithFS(memFS), WithDir("missing_oversize_test"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	bucket := "TestBucket"
	key := "oversize-key"
	payload := makeIncompressible(MaxPayloadCapacity + 1024)

	if err := store.Put(bucket, key, payload, "0"); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Remove from in-memory oversizeObjects map while leaving keyIndex entry
	qKey := qualifyKey(bucket, key)
	store.keyMu.Lock()
	delete(store.oversizeObjects, qKey)
	store.keyMu.Unlock()

	// Get should return not found (exists=false, err=nil) without failing the engine
	val, exists, err := store.Get(bucket, key)
	if err != nil {
		t.Fatalf("expected nil error on missing oversize object, got: %v", err)
	}
	if exists || val != nil {
		t.Fatalf("expected exists=false, got exists=%v val=%v", exists, val)
	}
	if store.isFailed() {
		t.Fatalf("engine unexpectedly transitioned to failed state")
	}
}

// TestGet_PinPageFailurePreservesCause verifies that when PinPage fails under locked read,
// the engine failure error includes the cause.
func TestGet_PinPageFailurePreservesCause(t *testing.T) {
	memFS := NewMemFS()
	store, err := Open(WithFS(memFS), WithDir("pin_fail_test"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	bucket := "TestBucket"
	key := "pin-fail-key"
	if err := store.Put(bucket, key, []byte("val"), "0"); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	qKey := qualifyKey(bucket, key)
	store.keyMu.RLock()
	entry := store.keyIndex[qKey]
	store.keyMu.RUnlock()

	// Remove page descriptor from pageTable so PinPage fails with ErrPageNotFound
	store.bp.mu.Lock()
	delete(store.bp.pageTable, entry.LogicalPage)
	store.bp.mu.Unlock()

	_, _, err = store.Get(bucket, key)
	if err == nil {
		t.Fatalf("expected error when PinPage fails")
	}
	if !strings.Contains(err.Error(), "failed to pin page") {
		t.Fatalf("expected error to contain 'failed to pin page', got: %v", err)
	}
	if !strings.Contains(err.Error(), ErrPageNotFound.Error()) {
		t.Fatalf("expected error to contain cause %q, got: %v", ErrPageNotFound.Error(), err)
	}
}

func TestRegression_OversizePutAfterWipe(t *testing.T) {
	oversizePayload := make([]byte, 3*1024*1024)
	copy(oversizePayload, []byte("large-payload-after-wipe"))
	if _, err := rand.Read(oversizePayload[len("large-payload-after-wipe"):]); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	testWipe := func(t *testing.T, corrupt func(dir string)) {
		fs := NewOSFS()
		dir := t.TempDir()

		store, err := Open(WithFS(fs), WithDir(dir))
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		corrupt(dir)

		store2, err := Open(WithFS(fs), WithDir(dir))
		if err != nil {
			t.Fatalf("Open after wipe failed: %v", err)
		}
		defer func() {
			if err := store2.Close(); err != nil {
				t.Errorf("store2.Close failed: %v", err)
			}
		}()

		if err := store2.Put("ConfigMap", "largeKey", oversizePayload, "1"); err != nil {
			t.Fatalf("Put oversize object failed after wipe: %v", err)
		}
		val, exists, err := store2.Get("ConfigMap", "largeKey")
		if err != nil || !exists || !bytes.Equal(val, oversizePayload) {
			t.Fatalf("Get oversize object mismatch after wipe: exists=%v, err=%v", exists, err)
		}
	}

	t.Run("FailureMarker", func(t *testing.T) {
		testWipe(t, func(dir string) {
			if err := os.WriteFile(filepath.Join(dir, "FAILED"), []byte("simulated-failure"), 0644); err != nil {
				t.Fatalf("failed to write FAILED marker: %v", err)
			}
		})
	})

	t.Run("VersionMismatch", func(t *testing.T) {
		testWipe(t, func(dir string) {
			buf := make([]byte, metaFileSize)
			binary.BigEndian.PutUint32(buf[16:20], StoreFormatVersion+99)
			if err := os.WriteFile(filepath.Join(dir, "meta.db"), buf, 0644); err != nil {
				t.Fatalf("failed to write incompatible version: %v", err)
			}
		})
	})

	t.Run("OrphanedFiles", func(t *testing.T) {
		testWipe(t, func(dir string) {
			if err := os.Remove(filepath.Join(dir, "meta.db")); err != nil {
				t.Fatalf("failed to remove meta.db: %v", err)
			}
		})
	})
}

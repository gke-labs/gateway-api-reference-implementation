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
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Acceptance Criteria 3: Self-checks for each fault model and invariant.
// Each test breaks the store or environment on purpose and proves that the suite catches it.

func TestSelfCheck_FaultModels_UnsyncedWrites(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "selfcheck_unsynced"

	store, err := Open(WithFS(faultFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	_ = store.Put("ConfigMap", "durableKey", []byte("durableVal"), "1")
	chkLSN, _ := store.Checkpoint()

	// Break on purpose: skip fsync on subsequent writes
	faultFS.SetSkipSync(true)
	defer faultFS.SetSkipSync(false)

	_ = store.Put("ConfigMap", "unsyncedKey", []byte("unsyncedVal"), "2")

	// Power loss drops unsynced disk writes and rejects subsequent I/O
	_ = faultFS.PowerLoss(PowerLossOptions{DropUnsynced: true})
	faultFS.SetCrashed(true)
	_ = store.Close()
	faultFS.ResetCrash()

	faultFS.SetSkipSync(false)
	recStore, err := Open(WithFS(faultFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Recovery failed: %v", err)
	}
	defer recStore.Close()

	// Since WAL sync was skipped, LSN 2 was dropped; recovered LSN must be chkLSN
	if recStore.wal.MaxLSN() != chkLSN {
		t.Fatalf("self-check failed: expected recovered LSN %d, got %d", chkLSN, recStore.wal.MaxLSN())
	}
}

func TestSelfCheck_FaultModels_SectorTearing(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "selfcheck_tearing"

	store, err := Open(WithFS(faultFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	_ = store.Put("ConfigMap", "tearKey", bytes.Repeat([]byte("tear-data-"), 100), "1")
	_, _ = store.Checkpoint()
	_ = store.Close()

	// Break on purpose: tear a 512-byte sector inside the block
	heapPath := fmt.Sprintf("%s/heap.db", dir)
	if err := faultFS.CorruptBlock(heapPath, 0, 512, 0xff); err != nil {
		t.Fatalf("CorruptBlock failed: %v", err)
	}

	// Recovery or read must detect CRC mismatch and not serve corrupt data
	blockBuf := make([]byte, BlockSize)
	f, _ := faultFS.Open(heapPath)
	_, _ = f.ReadAt(blockBuf, 0)
	_ = f.Close()

	_, decErr := DecodeBlockHeader(blockBuf)
	if decErr == nil {
		t.Fatalf("self-check failed: expected CRC mismatch on torn sector, got nil")
	}
	if !errors.Is(decErr, ErrBlockCRCMismatch) {
		t.Fatalf("expected ErrBlockCRCMismatch, got %v", decErr)
	}
}

func TestSelfCheck_FaultModels_VolatileCache(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "selfcheck_volatile"

	store, err := Open(WithFS(faultFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	_ = store.Put("ConfigMap", "durableKey", []byte("dVal"), "1")
	_, _ = store.Checkpoint()

	// 1. ProcessCrash: completed writes in OS buffer cache survive
	_ = store.Put("ConfigMap", "crashKey", []byte("crashVal"), "2")
	_ = faultFS.ProcessCrash()
	faultFS.SetCrashed(true)
	_ = store.Close()
	faultFS.ResetCrash()

	recStore1, err := Open(WithFS(faultFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Reopen after ProcessCrash failed: %v", err)
	}
	if recStore1.wal.MaxLSN() < 2 {
		t.Fatalf("self-check failed: write did not survive ProcessCrash")
	}
	_ = recStore1.Close()

	// 2. PowerLoss: unsynced writes are lost
	memFS2 := NewMemFS()
	faultFS2 := NewFaultFS(memFS2)
	dir2 := "selfcheck_volatile_powerloss"

	store2, _ := Open(WithFS(faultFS2), WithDir(dir2))
	_ = store2.Put("ConfigMap", "durableKey", []byte("dVal"), "1")
	chkLSN2, _ := store2.Checkpoint()

	faultFS2.SetSkipSync(true)
	_ = store2.Put("ConfigMap", "lossKey", []byte("lossVal"), "2")

	_ = faultFS2.PowerLoss(PowerLossOptions{DropUnsynced: true})
	faultFS2.SetCrashed(true)
	_ = store2.Close()
	faultFS2.ResetCrash()
	faultFS2.SetSkipSync(false)

	recStore2, _ := Open(WithFS(faultFS2), WithDir(dir2))
	if recStore2.wal.MaxLSN() != chkLSN2 {
		t.Fatalf("self-check failed: un-fsynced write survived PowerLoss (expected %d, got %d)",
			chkLSN2, recStore2.wal.MaxLSN())
	}
	_ = recStore2.Close()
}

func TestSelfCheck_FaultModels_LostMetadata(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	_ = faultFS.MkdirAll("unsynced_dir", 0755)
	file, err := faultFS.Create("unsynced_dir/file.txt")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	_, _ = file.WriteAt([]byte("content"), 0)
	_ = file.Close()

	// PowerLoss with LostMetadata: true reverts non-fsynced directory creations
	_ = faultFS.PowerLoss(PowerLossOptions{LostMetadata: true})

	_, err = faultFS.Open("unsynced_dir/file.txt")
	if err == nil || !os.IsNotExist(err) {
		t.Fatalf("self-check failed: file created without SyncDir survived PowerLoss with LostMetadata")
	}
}

func TestSelfCheck_FaultModels_IOErrors(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "selfcheck_io_errors"

	store, err := Open(WithFS(faultFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	// 1. Write error on sync transitions store to failed
	_ = store.Put("ConfigMap", "k", []byte("v"), "1")
	faultFS.SetWriteErrorSticky(ErrInjectedFault, true)
	err = store.Sync()
	if err == nil {
		t.Fatalf("expected write error on sync, got nil")
	}
	if !store.isFailed() {
		t.Fatalf("self-check failed: store did not enter failed state on write error")
	}

	// 2. Read error on disk read transitions store to failed
	memFS2 := NewMemFS()
	faultFS2 := NewFaultFS(memFS2)
	dir2 := "selfcheck_io_read_errors"
	store2, _ := Open(WithFS(faultFS2), WithDir(dir2))
	_ = store2.Put("ConfigMap", "k", []byte("v"), "1")
	_ = store2.Close() // Close flushes to disk and clears memory pool

	// Reopen and inject read error to force disk read on Get
	store2Reopened, rErr := Open(WithFS(faultFS2), WithDir(dir2))
	if rErr != nil {
		t.Fatalf("Open failed: %v", rErr)
	}
	defer store2Reopened.Close()

	faultFS2.SetReadErrorSticky(ErrInjectedFault, true)
	_, _, getErr := store2Reopened.Get("ConfigMap", "k")
	if getErr == nil {
		t.Fatalf("self-check failed: expected read error on Get, got nil")
	}
	if !errors.Is(getErr, ErrInjectedFault) && !store2Reopened.isFailed() {
		t.Fatalf("expected ErrInjectedFault or failed state on Get, got %v", getErr)
	}

	// 3. Sync error transitions store to failed
	memFS3 := NewMemFS()
	faultFS3 := NewFaultFS(memFS3)
	dir3 := "selfcheck_io_sync_errors"
	store3, _ := Open(WithFS(faultFS3), WithDir(dir3))
	defer store3.Close()

	_ = store3.Put("ConfigMap", "k", []byte("v"), "1")
	faultFS3.SetSyncErrorSticky(ErrInjectedFault, true)
	err = store3.Sync()
	if err == nil {
		t.Fatalf("expected sync error, got nil")
	}
	if !store3.isFailed() {
		t.Fatalf("self-check failed: store did not enter failed state on sync error")
	}
}

func TestSelfCheck_FaultModels_ShortReadsWritesAndENOSPC(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "selfcheck_short_rw"

	store, err := Open(WithFS(faultFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	// Short write
	faultFS.SetShortWrite(10)
	_ = store.Put("ConfigMap", "k", bytes.Repeat([]byte("x"), 1000), "1")
	faultFS.SetShortWrite(0)

	// ENOSPC on write
	_ = store.Put("ConfigMap", "k2", []byte("v2"), "2")
	faultFS.SetWriteErrorSticky(syscall.ENOSPC, true)
	err = store.Sync()
	if err == nil {
		t.Fatalf("expected ENOSPC error on sync, got nil")
	}
	faultFS.SetWriteErrorSticky(nil, false)

	// Short read
	faultFS.SetShortRead(8)
	f, _ := faultFS.Open(fmt.Sprintf("%s/meta.db", dir))
	buf := make([]byte, 64)
	n, _ := f.ReadAt(buf, 0)
	_ = f.Close()
	if n > 8 {
		t.Fatalf("self-check failed: short read returned %d bytes > 8", n)
	}
}

func TestSelfCheck_FaultModels_SilentCorruption(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "selfcheck_corruption"

	store, err := Open(WithFS(faultFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	_ = store.Put("ConfigMap", "corruptKey", bytes.Repeat([]byte("payload"), 20), "1")
	_ = store.Sync()
	_ = store.Close()

	// Corrupt a byte in WAL record 1
	walPath := fmt.Sprintf("%s/wal/%020d.wal", dir, 1)
	if err := faultFS.CorruptWALRecord(walPath, 1); err != nil {
		t.Fatalf("CorruptWALRecord failed: %v", err)
	}

	// 1. DecodeRecord must detect corrupt CRC
	f, _ := faultFS.Open(walPath)
	recBuf := make([]byte, 1024)
	n, _ := f.ReadAt(recBuf, SegmentHeaderSize)
	_ = f.Close()

	_, decErr := DecodeRecord(bytes.NewReader(recBuf[:n]))
	if decErr == nil {
		t.Fatalf("self-check failed: expected CRC mismatch on corrupted WAL record, got nil")
	}
	if !errors.Is(decErr, ErrBadCRC) {
		t.Fatalf("expected ErrBadCRC on corrupted WAL record, got %v", decErr)
	}

	// 2. WAL iterator must reject corrupted record and treat tail corruption as EOF (not served)
	it, itErr := NewWALIterator(faultFS, fmt.Sprintf("%s/wal", dir), store.dbID, 1)
	if itErr != nil {
		t.Fatalf("NewWALIterator failed: %v", itErr)
	}
	rec, nextErr := it.Next()
	if nextErr == nil && rec.LSN == 1 {
		t.Fatalf("self-check failed: corrupted WAL record was served as valid data")
	}
}

func TestSelfCheck_FaultModels_StaleReads(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "selfcheck_stale_reads"

	store, err := Open(WithFS(faultFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	_ = store.Put("ConfigMap", "staleKey", []byte("val1"), "1")
	_ = store.Flush()

	// Capture block for val1
	heapPath := fmt.Sprintf("%s/heap.db", dir)
	f, _ := faultFS.Open(heapPath)
	v1Block := make([]byte, BlockSize)
	_, _ = f.ReadAt(v1Block, 0)
	_ = f.Close()

	// Update to val2
	_ = store.Put("ConfigMap", "staleKey", []byte("val2"), "2")
	_ = store.Flush()
	_ = store.Close()

	// Break on purpose: inject stale block on read
	faultFS.SetStaleBlock(heapPath, 0, v1Block)

	recStore, err := Open(WithFS(faultFS), WithDir(dir))
	if err == nil {
		_, _, gErr := recStore.Get("ConfigMap", "staleKey")
		// Stale read detection must either reject the stale page or fail the store
		if gErr == nil && !recStore.isFailed() {
			val, _, _ := recStore.Get("ConfigMap", "staleKey")
			if bytes.Equal(val, []byte("val1")) {
				t.Fatalf("self-check failed: stale value val1 was served as valid data")
			}
		}
		_ = recStore.Close()
	}
}

func TestSelfCheck_Invariants_ModelChecker(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "selfcheck_model"

	store, err := Open(WithFS(faultFS), WithDir(dir))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	model := NewReferenceModel()
	_ = store.Put("ConfigMap", "k1", []byte("v1"), "1")
	model.RecordPut("ConfigMap", "k1", []byte("v1"), "1", store.wal.MaxLSN())

	// Break model expectation on purpose
	model.RecordPut("ConfigMap", "k1", []byte("wrongValue"), "1", store.wal.MaxLSN())

	err = model.ValidateCurrentWithErr(store)
	if err == nil {
		t.Fatalf("self-check failed: model checker did not detect value mismatch")
	}
}

func TestSelfCheck_Invariants_Watchdog(t *testing.T) {
	var ops atomic.Int64
	timedOut := false
	watchdog := NewWatchdog(t, &ops, 200*time.Millisecond, func(msg string) {
		timedOut = true
	})

	// Stalled progress: do not increment ops
	time.Sleep(400 * time.Millisecond)
	watchdog.Stop()

	if !timedOut {
		t.Fatalf("self-check failed: watchdog did not detect stalled progress")
	}
}

func TestSelfCheck_Invariants_StructuralChecker(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)
	dir := "selfcheck_structural"

	store, err := Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(64))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	_ = store.Put("ConfigMap", "k1", []byte("v1"), "1")
	_ = store.Put("ConfigMap", "k2", []byte("v2"), "2")

	// Baseline structural check should pass
	if err := store.CheckStructuralInvariants(); err != nil {
		t.Fatalf("baseline CheckStructuralInvariants failed: %v", err)
	}

	// 1. Break on purpose: inject buffer pool frame leak
	store.InjectFrameLeak()
	if err := store.CheckStructuralInvariants(); err == nil {
		t.Fatalf("self-check failed: structural checker did not detect buffer-pool frame leak")
	}

	// 2. Break on purpose: inject buddy allocator overlap
	store.InjectBuddyOverlap()
	if err := store.CheckStructuralInvariants(); err == nil {
		t.Fatalf("self-check failed: structural checker did not detect buddy allocator overlap")
	}

	// 3. Break on purpose: inject buddy allocator leak
	store.InjectBuddyLeak()
	if err := store.CheckStructuralInvariants(); err == nil {
		t.Fatalf("self-check failed: structural checker did not detect buddy allocator block leak")
	}

	// 4. Break on purpose: inject corrupt key index entry
	store.InjectCorruptIndex("ConfigMap\x00k1")
	if err := store.CheckStructuralInvariants(); err == nil {
		t.Fatalf("self-check failed: structural checker did not detect corrupted key index entry")
	}
}

func TestSelfCheck_Invariants_ReuseAndWriteAheadRules(t *testing.T) {
	memFS := NewMemFS()
	faultFS := NewFaultFS(memFS)

	// 1. Write-ahead rule self-check
	faultFS.SetMaxFsyncedLSN(10)
	f, _ := faultFS.Create("heap.db")

	blockBuf := make([]byte, BlockSize)
	hdr := BlockHeader{LogicalPage: 1, LSN: 20, BlockIndex: 0, NumBlocks: 1} // 20 > 10
	EncodeBlockHeader(hdr, blockBuf)
	FinalizeBlockCRC(blockBuf)

	var walPanic string
	func() {
		defer func() {
			if r := recover(); r != nil {
				walPanic = fmt.Sprintf("%v", r)
			}
		}()
		_, _ = f.WriteAt(blockBuf, 0)
	}()

	if !strings.Contains(walPanic, "write-ahead rule violation") {
		t.Fatalf("self-check failed: expected write-ahead rule violation panic, got: %s", walPanic)
	}

	// 2. Reuse rule self-check
	// Fsync block 0 as durable copy of page 1 at LSN 10
	faultFS.SetMaxFsyncedLSN(30)
	hdr.LSN = 10
	EncodeBlockHeader(hdr, blockBuf)
	FinalizeBlockCRC(blockBuf)
	_, _ = f.WriteAt(blockBuf, 0)
	_ = f.Sync() // Now block 0 holds durable copy of page 1 at LSN 10

	var reusePanic string
	func() {
		defer func() {
			if r := recover(); r != nil {
				reusePanic = fmt.Sprintf("%v", r)
			}
		}()
		// Attempt to overwrite block 0 with another write -> must trigger reuse rule violation
		_, _ = f.WriteAt(blockBuf, 0)
	}()

	if !strings.Contains(reusePanic, "reuse rule violation") {
		t.Fatalf("self-check failed: expected reuse rule violation panic, got: %s", reusePanic)
	}
	_ = f.Close()
}

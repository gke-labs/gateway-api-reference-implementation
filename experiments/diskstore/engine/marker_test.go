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

package engine_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gke-labs/gateway-api-reference-implementation/experiments/diskstore/engine"
)

func TestEngine_FailureMarkerRecovery(t *testing.T) {
	memFS := engine.NewMemFS()
	dir := "test_failure_marker_dir"

	// 1. Initial run: write objects
	eng1, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if eng1.Wiped() {
		t.Fatalf("initial open should not report Wiped()")
	}

	origDBID := eng1.DBID()

	if err := eng1.Put("bucketA", "k1", []byte("val1")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := eng1.Put("bucketB", "k2", []byte("val2")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := eng1.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	// 2. Simulate a failure: transition into failed state, which writes the failure marker
	eng1.SimulateFailure(errors.New("simulated fatal corruption"))

	select {
	case <-eng1.Failed():
		// Success: channel closed
	default:
		t.Fatalf("expected Failed() channel to be closed after failure")
	}

	if err := eng1.Err(); err == nil || !errors.Is(err, engine.ErrFailed) {
		t.Fatalf("expected ErrFailed, got %v", err)
	}

	// Any operation on failed engine must fail
	if err := eng1.Put("bucketA", "k3", []byte("val3")); !errors.Is(err, engine.ErrFailed) {
		t.Fatalf("expected ErrFailed on Put after failure, got %v", err)
	}

	_ = eng1.Close()

	// 3. Reopen: engine must detect the failure marker, wipe the store, report the wipe,
	// and generate a new DB ID.
	eng2, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir), engine.WithEraseOnError())
	if err != nil {
		t.Fatalf("reopening store after failure failed: %v", err)
	}
	defer eng2.Close()

	if !eng2.Wiped() {
		t.Fatalf("expected eng2.Wiped() to be true after failure marker detection")
	}

	if eng2.DBID() == origDBID {
		t.Fatalf("expected new database ID after wipe, got same ID %x", origDBID)
	}

	keys := eng2.ListKeys()
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys after wipe, got %v", keys)
	}

	// 4. Verify fresh engine works normally
	if err := eng2.Put("bucketC", "k4", []byte("val4")); err != nil {
		t.Fatalf("Put on wiped store failed: %v", err)
	}
	if err := eng2.Sync(); err != nil {
		t.Fatalf("Sync on wiped store failed: %v", err)
	}

	// 5. Subsequent clean reopen must NOT report wiped and must preserve data
	_ = eng2.Close()

	eng3, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir))
	if err != nil {
		t.Fatalf("second reopen failed: %v", err)
	}
	defer eng3.Close()

	if eng3.Wiped() {
		t.Fatalf("clean reopen should NOT report Wiped()")
	}
	val, exists, err := eng3.Get("bucketC", "k4")
	if err != nil || !exists || !bytes.Equal(val, []byte("val4")) {
		t.Fatalf("expected val4 after clean reopen, got %s (exists=%v, err=%v)", string(val), exists, err)
	}
}

func TestEngine_FailureMarkerPreservesUnrelatedFiles(t *testing.T) {
	memFS := engine.NewMemFS()
	dir := "test_preserve_unrelated"

	eng1, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if err := eng1.Put("bucket1", "k1", []byte("val1")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := eng1.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	// Create an unrelated file and directory inside the store directory
	unrelatedFilePath := filepath.Join(dir, "user_data.txt")
	f1, err := memFS.OpenFile(unrelatedFilePath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("create user_data.txt failed: %v", err)
	}
	if _, err := f1.WriteAt([]byte("important user payload"), 0); err != nil {
		t.Fatalf("write user_data.txt failed: %v", err)
	}
	_ = f1.Close()

	unrelatedDirPath := filepath.Join(dir, "other_dir")
	if err := memFS.MkdirAll(unrelatedDirPath, 0755); err != nil {
		t.Fatalf("mkdir other_dir failed: %v", err)
	}
	unrelatedSubFilePath := filepath.Join(unrelatedDirPath, "other.json")
	f2, err := memFS.OpenFile(unrelatedSubFilePath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("create other.json failed: %v", err)
	}
	if _, err := f2.WriteAt([]byte(`{"unrelated": true}`), 0); err != nil {
		t.Fatalf("write other.json failed: %v", err)
	}
	_ = f2.Close()

	// Simulate failure
	eng1.SimulateFailure(errors.New("simulated crash"))
	_ = eng1.Close()

	// Reopen
	eng2, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir), engine.WithEraseOnError())
	if err != nil {
		t.Fatalf("Open after failure failed: %v", err)
	}
	defer eng2.Close()

	if !eng2.Wiped() {
		t.Fatalf("expected Wiped() == true")
	}

	// Verify that unrelated file survived
	fCheck, err := memFS.OpenFile(unrelatedFilePath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("unrelated file user_data.txt was deleted during wipe: %v", err)
	}
	buf := make([]byte, 22)
	n, _ := fCheck.ReadAt(buf, 0)
	_ = fCheck.Close()
	if !bytes.Equal(buf[:n], []byte("important user payload")) {
		t.Fatalf("unrelated file content corrupted: %s", string(buf[:n]))
	}

	// Verify that unrelated directory and subfile survived
	fSubCheck, err := memFS.OpenFile(unrelatedSubFilePath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("unrelated subfile other_dir/other.json was deleted during wipe: %v", err)
	}
	subBuf := make([]byte, 19)
	sn, _ := fSubCheck.ReadAt(subBuf, 0)
	_ = fSubCheck.Close()
	if !bytes.Equal(subBuf[:sn], []byte(`{"unrelated": true}`)) {
		t.Fatalf("unrelated subfile content corrupted: %s", string(subBuf[:sn]))
	}
}

type failRemoveFS struct {
	engine.FS
	failOnSuffix string
	callCount    int
}

func (f *failRemoveFS) Remove(name string) error {
	if f.failOnSuffix != "" && strings.HasSuffix(name, f.failOnSuffix) {
		f.callCount++
		return errors.New("injected fault removing file during wipe")
	}
	return f.FS.Remove(name)
}

func TestEngine_InterruptedWipe_FailurePartWay(t *testing.T) {
	baseFS := engine.NewMemFS()
	faultyFS := &failRemoveFS{FS: baseFS}
	dir := "test_interrupted_wipe"

	// 1. Initialize store with data
	eng1, err := engine.Open(engine.WithFS(faultyFS), engine.WithDir(dir), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := eng1.Put("bucketA", "k1", []byte("val1")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := eng1.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	// 2. Trigger failure, creating FAILED marker
	eng1.SimulateFailure(errors.New("simulated crash before wipe"))
	_ = eng1.Close()

	// 3. Inject failure when removing heap.db during wipe
	faultyFS.failOnSuffix = "heap.db"

	// Open must attempt wipe, fail on heap.db, and return error
	_, err = engine.Open(engine.WithFS(faultyFS), engine.WithDir(dir), engine.WithEraseOnError())
	if err == nil {
		t.Fatalf("expected Open to fail when wipe fails")
	}
	if faultyFS.callCount == 0 {
		t.Fatalf("expected injected fault to be called")
	}

	// Because wipe failed, FAILED marker must still be present on disk
	markerPath := filepath.Join(dir, "FAILED")
	mf, mErr := faultyFS.OpenFile(markerPath, os.O_RDONLY, 0)
	if mErr != nil {
		t.Fatalf("FAILED marker was prematurely removed when wipe failed: %v", mErr)
	}
	_ = mf.Close()

	// 4. Clear the fault and reopen: next Open must complete the wipe and produce a clean store
	faultyFS.failOnSuffix = ""
	eng2, err := engine.Open(engine.WithFS(faultyFS), engine.WithDir(dir), engine.WithEraseOnError())
	if err != nil {
		t.Fatalf("reopening store after interrupted wipe failed: %v", err)
	}
	defer eng2.Close()

	if !eng2.Wiped() {
		t.Fatalf("expected Wiped() == true on successful recovery from interrupted wipe")
	}
	if keys := eng2.ListKeys(); len(keys) != 0 {
		t.Fatalf("expected 0 keys after wipe, got %v", keys)
	}

	// Verify fresh store can write and read normally
	if err := eng2.Put("bucketA", "k2", []byte("val2")); err != nil {
		t.Fatalf("Put on recovered store failed: %v", err)
	}
	val, exists, err := eng2.Get("bucketA", "k2")
	if err != nil || !exists || !bytes.Equal(val, []byte("val2")) {
		t.Fatalf("Get on recovered store failed: exists=%v, val=%s, err=%v", exists, string(val), err)
	}
}

func TestEngine_OrphanedStoreFilesWithoutMeta_TreatedAsCorrupt(t *testing.T) {
	memFS := engine.NewMemFS()
	dir := "test_orphaned_store"

	// 1. Set up a store, write data, sync
	eng, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	_ = eng.Put("bucketA", "k1", []byte("val1"))
	_ = eng.Sync()
	_ = eng.Close()

	// 2. Simulate a crash that removed meta.db (e.g. partial wipe or corruption) but left heap.db and wal/
	metaPath := filepath.Join(dir, "meta.db")
	if err := memFS.Remove(metaPath); err != nil {
		t.Fatalf("remove meta.db failed: %v", err)
	}

	// 3. Reopen without meta.db: Open must detect existing heap.db/wal, wipe them, and report Wiped()
	eng2, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir), engine.WithEraseOnError())
	if err != nil {
		t.Fatalf("Open on orphaned store failed: %v", err)
	}
	defer eng2.Close()

	if !eng2.Wiped() {
		t.Fatalf("expected Wiped() == true when opening orphaned store without meta.db")
	}
	if keys := eng2.ListKeys(); len(keys) != 0 {
		t.Fatalf("expected 0 keys from orphaned store, got %v", keys)
	}
}

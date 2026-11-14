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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWAL_LostFoundQuarantineBound(t *testing.T) {
	memFS := NewMemFS()
	var dbID [16]byte
	copy(dbID[:], []byte("wal-bound-test-1"))
	walDir := "wal"
	if err := memFS.MkdirAll(walDir, StoreDirMode); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	writeSeg := func(startLSN uint64) string {
		name := segmentFileName(startLSN)
		p := filepath.Join(walDir, name)
		f, err := memFS.OpenFile(p, os.O_CREATE|os.O_RDWR, StoreFileMode)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
		return name
	}

	seg2 := writeSeg(2)
	seg3 := writeSeg(3)
	seg4 := writeSeg(4)

	wal, err := OpenWAL(memFS, walDir, dbID, 1, WALOptions{
		Quarantine: QuarantineOptions{
			MaxQuarantinedFiles: 2,
		},
	})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	defer wal.Close()

	lostDir := filepath.Join(walDir, "lost+found")
	entries, err := memFS.ReadDir(lostDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 quarantined files in lost+found, got %d", len(entries))
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), seg2) {
			t.Fatalf("oldest segment %s was not removed from lost+found", seg2)
		}
	}
	var found3, found4 bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), seg3) {
			found3 = true
		}
		if strings.HasPrefix(e.Name(), seg4) {
			found4 = true
		}
	}
	if !found3 || !found4 {
		t.Fatalf("expected segments %s and %s in lost+found, found3=%v, found4=%v", seg3, seg4, found3, found4)
	}
}

func TestWAL_LostFoundMinRetention(t *testing.T) {
	memFS := NewMemFS()
	var dbID [16]byte
	copy(dbID[:], []byte("wal-retention-t1"))
	walDir := "wal"
	if err := memFS.MkdirAll(walDir, StoreDirMode); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	writeSeg := func(startLSN uint64) string {
		name := segmentFileName(startLSN)
		p := filepath.Join(walDir, name)
		f, err := memFS.OpenFile(p, os.O_CREATE|os.O_RDWR, StoreFileMode)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
		return name
	}

	writeSeg(2)
	writeSeg(3)
	writeSeg(4)

	// Open with default 7d retention: all 3 should be kept
	wal, err := OpenWAL(memFS, walDir, dbID, 1, WALOptions{
		Quarantine: QuarantineOptions{
			MaxQuarantinedFiles:     2,
			MinQuarantinedRetention: 7 * 24 * time.Hour,
		},
	})
	if err != nil {
		t.Fatalf("OpenWAL failed: %v", err)
	}
	_ = wal.Close()

	lostDir := filepath.Join(walDir, "lost+found")
	entries, err := memFS.ReadDir(lostDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected all 3 segments retained under 7d retention, got %d", len(entries))
	}

	// Prune with clock advanced 8 days: oldest should be removed
	err = pruneLostFound(memFS, QuarantineOptions{
		Dir:                     lostDir,
		MaxQuarantinedFiles:     2,
		MinQuarantinedRetention: 7 * 24 * time.Hour,
		Now: func() time.Time {
			return time.Now().Add(8 * 24 * time.Hour)
		},
	})
	if err != nil {
		t.Fatalf("pruneLostFound failed: %v", err)
	}

	entriesAfter, err := memFS.ReadDir(lostDir)
	if err != nil {
		t.Fatalf("ReadDir after pruning failed: %v", err)
	}
	if len(entriesAfter) != 2 {
		t.Fatalf("expected 2 segments remaining after retention expired, got %d", len(entriesAfter))
	}
}

func TestLostFound_QuarantineBound(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_lost_found_bound"

	// Open with bound of 2 quarantined files
	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone), WithQuarantine(QuarantineOptions{MaxQuarantinedFiles: 2}))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := store.Put("ConfigMap", "durableKey", []byte("val")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	walDir := filepath.Join(dir, "wal")
	lostDir := filepath.Join(walDir, "lost+found")

	writeAbandoned := func(startLSN uint64) string {
		fileName := segmentFileName(startLSN)
		filePath := filepath.Join(walDir, fileName)
		f, err := memFS.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, StoreFileMode)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		_ = f.Close()
		return fileName
	}

	// 1. First uncommitted file quarantined
	f1 := writeAbandoned(101)
	s1, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithQuarantine(QuarantineOptions{MaxQuarantinedFiles: 2, MinQuarantinedRetention: -1}))
	if err != nil {
		t.Fatalf("Open 1 failed: %v", err)
	}
	_ = s1.Close()

	// 2. Second uncommitted file quarantined
	f2 := writeAbandoned(102)
	s2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithQuarantine(QuarantineOptions{MaxQuarantinedFiles: 2, MinQuarantinedRetention: -1}))
	if err != nil {
		t.Fatalf("Open 2 failed: %v", err)
	}
	_ = s2.Close()

	// 3. Third uncommitted file quarantined (exceeds bound of 2)
	f3 := writeAbandoned(103)
	s3, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithQuarantine(QuarantineOptions{MaxQuarantinedFiles: 2, MinQuarantinedRetention: -1}))
	if err != nil {
		t.Fatalf("Open 3 failed: %v", err)
	}
	defer s3.Close()

	// Verify that lost+found contains exactly 2 files and oldest (f1) was removed
	entries, err := memFS.ReadDir(lostDir)
	if err != nil {
		t.Fatalf("ReadDir lost+found failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 files in lost+found, got %d", len(entries))
	}

	// f1 was the oldest quarantined file; it should have been deleted
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), f1) {
			t.Fatalf("oldest file %s was not removed from lost+found", f1)
		}
	}

	// Newer files f2 and f3 should remain
	var found2, found3 bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), f2) {
			found2 = true
		}
		if strings.HasPrefix(e.Name(), f3) {
			found3 = true
		}
	}
	if !found2 || !found3 {
		t.Fatalf("expected newer files %s and %s in lost+found; found2=%v, found3=%v", f2, f3, found2, found3)
	}
}

func TestLostFound_MinRetentionProtected(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_lost_found_retention"

	// Open with bound of 2 quarantined files and default 7d retention
	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone), WithQuarantine(QuarantineOptions{MaxQuarantinedFiles: 2}))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := store.Put("ConfigMap", "durableKey", []byte("val")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	walDir := filepath.Join(dir, "wal")
	lostDir := filepath.Join(walDir, "lost+found")

	writeAbandoned := func(startLSN uint64) string {
		fileName := segmentFileName(startLSN)
		filePath := filepath.Join(walDir, fileName)
		f, err := memFS.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, StoreFileMode)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		_ = f.Close()
		return fileName
	}

	// Quarantine 3 files under default 7-day retention
	writeAbandoned(101)
	s1, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithQuarantine(QuarantineOptions{MaxQuarantinedFiles: 2}))
	if err != nil {
		t.Fatalf("Open 1 failed: %v", err)
	}
	_ = s1.Close()

	writeAbandoned(102)
	s2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithQuarantine(QuarantineOptions{MaxQuarantinedFiles: 2}))
	if err != nil {
		t.Fatalf("Open 2 failed: %v", err)
	}
	_ = s2.Close()

	writeAbandoned(103)
	s3, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithQuarantine(QuarantineOptions{MaxQuarantinedFiles: 2}))
	if err != nil {
		t.Fatalf("Open 3 failed: %v", err)
	}
	_ = s3.Close()

	// Verify all 3 files are retained because they are younger than 7 days
	entries, err := memFS.ReadDir(lostDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected all 3 quarantined files retained under 7d retention, got %d", len(entries))
	}

	// Prune with clock advanced 8 days into the future: oldest should now be removed
	err = pruneLostFound(memFS, QuarantineOptions{
		Dir:                     lostDir,
		MaxQuarantinedFiles:     2,
		MinQuarantinedRetention: 7 * 24 * time.Hour,
		Now: func() time.Time {
			return time.Now().Add(8 * 24 * time.Hour)
		},
	})
	if err != nil {
		t.Fatalf("pruneLostFound failed: %v", err)
	}

	entriesAfter, err := memFS.ReadDir(lostDir)
	if err != nil {
		t.Fatalf("ReadDir after pruning failed: %v", err)
	}
	if len(entriesAfter) != 2 {
		t.Fatalf("expected 2 files remaining after retention expired, got %d", len(entriesAfter))
	}
}

func TestLostFound_UnparseableTimestampIgnored(t *testing.T) {
	memFS := NewMemFS()
	lostDir := "test_unparseable_lost_found"
	if err := memFS.MkdirAll(lostDir, StoreDirMode); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Create an unparseable file in lost+found
	unparseableFile := filepath.Join(lostDir, "corrupted_file_without_timestamp")
	f, err := memFS.OpenFile(unparseableFile, os.O_CREATE|os.O_WRONLY, StoreFileMode)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	_ = f.Close()

	// Prune with max files = 1
	err = pruneLostFound(memFS, QuarantineOptions{
		Dir:                 lostDir,
		MaxQuarantinedFiles: 1,
	})
	if err != nil {
		t.Fatalf("pruneLostFound failed: %v", err)
	}

	// Verify unparseable file was not removed
	entries, err := memFS.ReadDir(lostDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "corrupted_file_without_timestamp" {
		t.Fatalf("expected unparseable file preserved, got %v", entries)
	}
}

func TestEngine_WithQuarantineDefaults(t *testing.T) {
	memFS := NewMemFS()

	// 1. Default Open without WithQuarantine
	store1, err := Open(WithFS(memFS), WithDir("d1"), WithCreate())
	if err != nil {
		t.Fatalf("Open 1 failed: %v", err)
	}
	defer store1.Close()

	if store1.quarantine.MaxQuarantinedFiles != DefaultMaxQuarantinedFiles {
		t.Errorf("expected default MaxQuarantinedFiles %d, got %d", DefaultMaxQuarantinedFiles, store1.quarantine.MaxQuarantinedFiles)
	}
	if store1.quarantine.MinQuarantinedRetention != DefaultMinQuarantinedRetention {
		t.Errorf("expected default MinQuarantinedRetention %v, got %v", DefaultMinQuarantinedRetention, store1.quarantine.MinQuarantinedRetention)
	}
	expectedWALDir1 := filepath.Join("d1", "wal", "lost+found")
	if store1.wal.quarantine.Dir != expectedWALDir1 {
		t.Errorf("expected WAL quarantine Dir %s, got %s", expectedWALDir1, store1.wal.quarantine.Dir)
	}

	// 2. Unset retention gets defaulted
	store2, err := Open(WithFS(memFS), WithDir("d2"), WithCreate(), WithQuarantine(QuarantineOptions{
		MaxQuarantinedFiles: 5,
	}))
	if err != nil {
		t.Fatalf("Open 2 failed: %v", err)
	}
	defer store2.Close()

	if store2.quarantine.MaxQuarantinedFiles != 5 {
		t.Errorf("expected MaxQuarantinedFiles 5, got %d", store2.quarantine.MaxQuarantinedFiles)
	}
	if store2.quarantine.MinQuarantinedRetention != DefaultMinQuarantinedRetention {
		t.Errorf("expected defaulted MinQuarantinedRetention %v, got %v", DefaultMinQuarantinedRetention, store2.quarantine.MinQuarantinedRetention)
	}

	// 3. Unset max files gets defaulted
	store3, err := Open(WithFS(memFS), WithDir("d3"), WithCreate(), WithQuarantine(QuarantineOptions{
		MinQuarantinedRetention: 12 * time.Hour,
	}))
	if err != nil {
		t.Fatalf("Open 3 failed: %v", err)
	}
	defer store3.Close()

	if store3.quarantine.MaxQuarantinedFiles != DefaultMaxQuarantinedFiles {
		t.Errorf("expected defaulted MaxQuarantinedFiles %d, got %d", DefaultMaxQuarantinedFiles, store3.quarantine.MaxQuarantinedFiles)
	}
	if store3.quarantine.MinQuarantinedRetention != 12*time.Hour {
		t.Errorf("expected MinQuarantinedRetention 12h, got %v", store3.quarantine.MinQuarantinedRetention)
	}

	// 4. Negative retention disabled check, caller-supplied Dir overridden per lost+found directory
	store4, err := Open(WithFS(memFS), WithDir("d4"), WithCreate(), WithQuarantine(QuarantineOptions{
		Dir:                     "caller/custom/dir",
		MaxQuarantinedFiles:     3,
		MinQuarantinedRetention: -1,
	}))
	if err != nil {
		t.Fatalf("Open 4 failed: %v", err)
	}
	defer store4.Close()

	if store4.quarantine.MaxQuarantinedFiles != 3 {
		t.Errorf("expected MaxQuarantinedFiles 3, got %d", store4.quarantine.MaxQuarantinedFiles)
	}
	if store4.quarantine.MinQuarantinedRetention != -1 {
		t.Errorf("expected MinQuarantinedRetention -1, got %v", store4.quarantine.MinQuarantinedRetention)
	}
	expectedWALDir4 := filepath.Join("d4", "wal", "lost+found")
	if store4.wal.quarantine.Dir != expectedWALDir4 {
		t.Errorf("expected WAL quarantine Dir %s, got %s", expectedWALDir4, store4.wal.quarantine.Dir)
	}
}

func TestQuarantineFiles_EmptyList(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_empty_quarantine"
	if err := memFS.MkdirAll(dir, StoreDirMode); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	_, err := quarantineFiles(t.Context(), memFS, dir, nil, QuarantineOptions{}, false)
	if err != nil {
		t.Fatalf("quarantineFiles with empty list failed: %v", err)
	}

	lostDir := filepath.Join(dir, "lost+found")
	// Creating a file in lostDir must fail because lostDir was not created
	if _, err := memFS.OpenFile(filepath.Join(lostDir, "probe"), os.O_CREATE|os.O_WRONLY, StoreFileMode); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected lost+found directory not to be created, but OpenFile returned err: %v", err)
	}
	if c := memFS.DirSyncCount(dir); c != 0 {
		t.Fatalf("expected 0 dir syncs, got %d", c)
	}
}

func TestQuarantineFiles_MovesFilesAndSyncsBothDirs(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_quarantine_moves"
	if err := memFS.MkdirAll(dir, StoreDirMode); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	for _, name := range []string{"file1.bin", "file2.bin"} {
		f, err := memFS.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY, StoreFileMode)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		_ = f.Close()
	}

	_, err := quarantineFiles(t.Context(), memFS, dir, []string{"file1.bin", "file2.bin"}, QuarantineOptions{}, false)
	if err != nil {
		t.Fatalf("quarantineFiles failed: %v", err)
	}

	// Verify original files no longer exist in dir
	for _, name := range []string{"file1.bin", "file2.bin"} {
		if _, err := memFS.Open(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected %s to be moved out of %s", name, dir)
		}
	}

	lostDir := filepath.Join(dir, "lost+found")
	entries, err := memFS.ReadDir(lostDir)
	if err != nil {
		t.Fatalf("ReadDir lost+found failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 files in lost+found, got %d", len(entries))
	}

	// Verify both directories were synced
	if c := memFS.DirSyncCount(lostDir); c < 1 {
		t.Fatalf("expected lost+found to be synced, got count %d", c)
	}
	if c := memFS.DirSyncCount(dir); c < 1 {
		t.Fatalf("expected parent dir to be synced, got count %d", c)
	}
}

func TestQuarantineFiles_RenameError_ReturnsFirstErrorAndDeletesNothing(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_quarantine_err"
	if err := memFS.MkdirAll(dir, StoreDirMode); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	fileName := "orphan.dat"
	filePath := filepath.Join(dir, fileName)
	f, err := memFS.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, StoreFileMode)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	_ = f.Close()

	injectedErr := errors.New("simulated rename failure")
	hookFS := &oversizeHookFS{
		FS: memFS,
		renameErr: func(oldpath, newpath string) error {
			return injectedErr
		},
	}

	_, err = quarantineFiles(t.Context(), hookFS, dir, []string{fileName}, QuarantineOptions{}, false)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, injectedErr) {
		t.Fatalf("expected injected error %v, got %v", injectedErr, err)
	}

	// File must still exist at original path (never deleted)
	f, err = memFS.Open(filePath)
	if err != nil {
		t.Fatalf("expected file %s to still exist after rename failure: %v", filePath, err)
	}
	_ = f.Close()
}

func TestQuarantineFiles_PruningAndBoundsApplied(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_quarantine_prune"
	if err := memFS.MkdirAll(dir, StoreDirMode); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	var names []string
	for i := 1; i <= 3; i++ {
		name := fmt.Sprintf("file%d.bin", i)
		names = append(names, name)
		f, err := memFS.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY, StoreFileMode)
		if err != nil {
			t.Fatalf("OpenFile failed: %v", err)
		}
		_ = f.Close()
	}

	_, err := quarantineFiles(t.Context(), memFS, dir, names, QuarantineOptions{
		MaxQuarantinedFiles:     2,
		MinQuarantinedRetention: -1,
	}, false)
	if err != nil {
		t.Fatalf("quarantineFiles failed: %v", err)
	}

	lostDir := filepath.Join(dir, "lost+found")
	entries, err := memFS.ReadDir(lostDir)
	if err != nil {
		t.Fatalf("ReadDir lost+found failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected exactly 2 files in lost+found after pruning, got %d", len(entries))
	}
}

func TestQuarantineFiles_SkipNotExistParameter(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_quarantine_skip_not_exist"
	if err := memFS.MkdirAll(dir, StoreDirMode); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Create one existing file and reference one missing file
	f, err := memFS.OpenFile(filepath.Join(dir, "present.dat"), os.O_CREATE|os.O_WRONLY, StoreFileMode)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	files := []string{"nonexistent.dat", "present.dat"}

	// When skipNotExist is false (offline recovery/WAL cleanup), missing file is an error
	_, err = quarantineFiles(t.Context(), memFS, dir, files, QuarantineOptions{}, false)
	if err == nil {
		t.Fatalf("expected error when skipNotExist=false and file is missing, got nil")
	}

	// When skipNotExist is true (live sweep), missing file is skipped and existing file is moved
	moved, err := quarantineFiles(t.Context(), memFS, dir, files, QuarantineOptions{}, true)
	if err != nil {
		t.Fatalf("quarantineFiles with skipNotExist=true failed: %v", err)
	}
	if len(moved) != 1 || moved[0] != "present.dat" {
		t.Fatalf("expected [present.dat] moved, got %v", moved)
	}
}

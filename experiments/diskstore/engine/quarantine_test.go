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
	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone), WithMaxQuarantinedFiles(2))
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
	s1, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithMaxQuarantinedFiles(2), WithMinQuarantinedRetention(-1))
	if err != nil {
		t.Fatalf("Open 1 failed: %v", err)
	}
	_ = s1.Close()

	// 2. Second uncommitted file quarantined
	f2 := writeAbandoned(102)
	s2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithMaxQuarantinedFiles(2), WithMinQuarantinedRetention(-1))
	if err != nil {
		t.Fatalf("Open 2 failed: %v", err)
	}
	_ = s2.Close()

	// 3. Third uncommitted file quarantined (exceeds bound of 2)
	f3 := writeAbandoned(103)
	s3, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithMaxQuarantinedFiles(2), WithMinQuarantinedRetention(-1))
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
	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone), WithMaxQuarantinedFiles(2))
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
	s1, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithMaxQuarantinedFiles(2))
	if err != nil {
		t.Fatalf("Open 1 failed: %v", err)
	}
	_ = s1.Close()

	writeAbandoned(102)
	s2, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithMaxQuarantinedFiles(2))
	if err != nil {
		t.Fatalf("Open 2 failed: %v", err)
	}
	_ = s2.Close()

	writeAbandoned(103)
	s3, err := Open(WithFS(memFS), WithDir(dir), WithCompressionCodec(CodecNone), WithMaxQuarantinedFiles(2))
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

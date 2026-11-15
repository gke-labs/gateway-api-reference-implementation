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
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// FileKind categorizes files managed by the store engine.
type FileKind string

const (
	KindHeap     FileKind = "heap"
	KindWAL      FileKind = "wal"
	KindOversize FileKind = "oversize"
	KindOther    FileKind = "other"
)

// FileKindStats tracks write I/O metrics for a particular kind of file.
type FileKindStats struct {
	BytesWritten int64
	Writes       int64
	Syncs        int64
}

func kindIndex(k FileKind) int {
	switch k {
	case KindHeap:
		return 0
	case KindWAL:
		return 1
	case KindOversize:
		return 2
	default:
		return 3
	}
}

// classifyPath determines the FileKind based on path conventions.
func classifyPath(name string) FileKind {
	clean := filepath.Clean(name)
	base := filepath.Base(clean)
	dir := filepath.Base(filepath.Dir(clean))

	if base == "heap.db" || filepath.Ext(base) == ".heap" {
		return KindHeap
	}
	if filepath.Ext(base) == ".wal" || dir == "wal" || strings.Contains(filepath.ToSlash(clean), "/wal/") {
		return KindWAL
	}
	if dir == "oversize" || strings.Contains(filepath.ToSlash(clean), "/oversize/") {
		return KindOversize
	}
	return KindOther
}

// measureFile wraps File to track write volume and sync operations.
type measureFile struct {
	File
	fs   *MeasureFS
	kind FileKind
}

func (f *measureFile) WriteAt(p []byte, off int64) (int, error) {
	n, err := f.File.WriteAt(p, off)
	if n > 0 {
		idx := kindIndex(f.kind)
		f.fs.stats[idx].bytesWritten.Add(int64(n))
		f.fs.stats[idx].writes.Add(1)
	}
	return n, err
}

func (f *measureFile) Sync() error {
	idx := kindIndex(f.kind)
	f.fs.stats[idx].syncs.Add(1)
	return f.File.Sync()
}

// MeasureFS wraps an underlying FS and counts write volume, write operations,
// and sync operations for each kind of file (heap, WAL, oversize, other).
type MeasureFS struct {
	FS
	stats [4]struct {
		bytesWritten atomic.Int64
		writes       atomic.Int64
		syncs        atomic.Int64
	}
}

// NewMeasureFS returns a new filesystem wrapper tracking write metrics.
func NewMeasureFS(underlying FS) *MeasureFS {
	return &MeasureFS{FS: underlying}
}

func (m *MeasureFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	f, err := m.FS.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &measureFile{File: f, fs: m, kind: classifyPath(name)}, nil
}

func (m *MeasureFS) Create(name string) (File, error) {
	f, err := m.FS.Create(name)
	if err != nil {
		return nil, err
	}
	return &measureFile{File: f, fs: m, kind: classifyPath(name)}, nil
}

func (m *MeasureFS) Open(name string) (File, error) {
	f, err := m.FS.Open(name)
	if err != nil {
		return nil, err
	}
	return &measureFile{File: f, fs: m, kind: classifyPath(name)}, nil
}

// Stats returns the recorded write metrics for a given file kind.
func (m *MeasureFS) Stats(k FileKind) FileKindStats {
	idx := kindIndex(k)
	return FileKindStats{
		BytesWritten: m.stats[idx].bytesWritten.Load(),
		Writes:       m.stats[idx].writes.Load(),
		Syncs:        m.stats[idx].syncs.Load(),
	}
}

// TotalBytesWritten returns total bytes written across all file kinds.
func (m *MeasureFS) TotalBytesWritten() int64 {
	var total int64
	for i := 0; i < 4; i++ {
		total += m.stats[i].bytesWritten.Load()
	}
	return total
}

// TotalWrites returns total write operations across all file kinds.
func (m *MeasureFS) TotalWrites() int64 {
	var total int64
	for i := 0; i < 4; i++ {
		total += m.stats[i].writes.Load()
	}
	return total
}

// TotalSyncs returns total sync operations across all file kinds.
func (m *MeasureFS) TotalSyncs() int64 {
	var total int64
	for i := 0; i < 4; i++ {
		total += m.stats[i].syncs.Load()
	}
	return total
}

// Reset resets all tracked metrics.
func (m *MeasureFS) Reset() {
	for i := 0; i < 4; i++ {
		m.stats[i].bytesWritten.Store(0)
		m.stats[i].writes.Store(0)
		m.stats[i].syncs.Store(0)
	}
}

type measureResult struct {
	valueSize          int
	checkpointInterval int
	payloadBytesPut    int64
	walBytes           int64
	heapBytes          int64
	oversizeBytes      int64
	otherBytes         int64
	totalBytesWritten  int64
	ratio              float64
	syncsPerOp         float64
	totalOps           int
	puts               int
	deletes            int
	checkpoints        int
}

// checkModel verifies that the durable store contents match the model map for all keys.
func checkModel(store *Engine, tableName string, keys []string, model map[string][]byte) error {
	for _, key := range keys {
		got, exists, err := store.Get(tableName, key)
		if err != nil {
			return fmt.Errorf("Get(%q) failed: %w", key, err)
		}
		expected, expectedExists := model[key]
		if expectedExists {
			if !exists {
				return fmt.Errorf("key %q missing after reopen", key)
			}
			if !bytes.Equal(got, expected) {
				return fmt.Errorf("key %q value mismatch: got len=%d, want len=%d", key, len(got), len(expected))
			}
		} else {
			if exists {
				return fmt.Errorf("key %q should be deleted but exists after reopen", key)
			}
		}
	}
	return nil
}

func runMeasureCase(t *testing.T, valueSize int, checkpointInterval int, totalOps int, seed int64) measureResult {
	t.Helper()
	random := rand.New(rand.NewSource(seed))

	const numKeys = 20
	keys := make([]string, numKeys)
	for i := range keys {
		keys[i] = fmt.Sprintf("k%d", i)
	}
	model := make(map[string][]byte)

	memFS := NewMemFS()
	measureFS := NewMeasureFS(memFS)
	dir := "measure_store"
	const tableName = "measure_table"

	// Pool of 4096 blocks (16 MiB) is large enough not to evict 20 keys up to 256 KiB
	// (20 keys * 64 blocks = 1,280 blocks max working set).
	const poolBlocks = 4096
	store, err := Open(
		WithFS(measureFS),
		WithDir(dir),
		WithNumPoolBlocks(poolBlocks),
		WithCompressionCodec(CodecNone),
		WithCreate(),
	)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	var payloadBytesPut int64
	var puts, deletes, checkpoints int

	for op := 0; op < totalOps; op++ {
		action := random.Intn(10)
		if len(model) == 0 {
			action = 0 // force put when empty
		}

		if action >= 7 {
			key := keys[random.Intn(len(keys))]
			if err := store.Delete(tableName, key); err != nil {
				t.Fatalf("op %d: Delete(%q) failed: %v", op, key, err)
			}
			delete(model, key)
			deletes++
		} else {
			key := keys[random.Intn(len(keys))]
			val := make([]byte, valueSize)
			random.Read(val)
			if err := store.Put(tableName, key, val); err != nil {
				t.Fatalf("op %d: Put(%q) failed: %v", op, key, err)
			}
			model[key] = val
			payloadBytesPut += int64(valueSize)
			puts++
		}

		if checkpointInterval > 0 && (op+1)%checkpointInterval == 0 {
			if _, err := store.Checkpoint(); err != nil {
				t.Fatalf("op %d: Checkpoint failed: %v", op, err)
			}
			checkpoints++
		}
	}

	// Clean close with Sync before close
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync before close failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Reopen store and verify model
	reopened, err := Open(
		WithFS(measureFS),
		WithDir(dir),
		WithNumPoolBlocks(poolBlocks),
		WithCompressionCodec(CodecNone),
	)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer reopened.Close()

	if err := checkModel(reopened, tableName, keys, model); err != nil {
		t.Fatalf("model check failed: %v", err)
	}

	walStats := measureFS.Stats(KindWAL)
	heapStats := measureFS.Stats(KindHeap)
	oversizeStats := measureFS.Stats(KindOversize)
	otherStats := measureFS.Stats(KindOther)
	totalWritten := measureFS.TotalBytesWritten()
	totalSyncs := measureFS.TotalSyncs()

	ratio := 0.0
	if payloadBytesPut > 0 {
		ratio = float64(totalWritten) / float64(payloadBytesPut)
	}
	syncsPerOp := float64(totalSyncs) / float64(totalOps)

	return measureResult{
		valueSize:          valueSize,
		checkpointInterval: checkpointInterval,
		payloadBytesPut:    payloadBytesPut,
		walBytes:           walStats.BytesWritten,
		heapBytes:          heapStats.BytesWritten,
		oversizeBytes:      oversizeStats.BytesWritten,
		otherBytes:         otherStats.BytesWritten,
		totalBytesWritten:  totalWritten,
		ratio:              ratio,
		syncsPerOp:         syncsPerOp,
		totalOps:           totalOps,
		puts:               puts,
		deletes:            deletes,
		checkpoints:        checkpoints,
	}
}

func TestMeasureFS(t *testing.T) {
	memFS := NewMemFS()
	mFS := NewMeasureFS(memFS)

	paths := map[string]FileKind{
		"test/heap.db":            KindHeap,
		"heap.db":                 KindHeap,
		"data.heap":               KindHeap,
		"test/wal/00000001.wal":   KindWAL,
		"wal/00000002.wal":        KindWAL,
		"test/oversize/test.obj":  KindOversize,
		"test/oversize/.tmp-x-1":  KindOversize,
		"test/meta.db":            KindOther,
		"test/FAILED":             KindOther,
	}

	for p, expectedKind := range paths {
		if got := classifyPath(p); got != expectedKind {
			t.Errorf("classifyPath(%q) = %v, want %v", p, got, expectedKind)
		}
	}

	if err := mFS.MkdirAll("test/wal", StoreDirMode); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	walFile, err := mFS.Create("test/wal/00000001.wal")
	if err != nil {
		t.Fatalf("Create WAL file failed: %v", err)
	}
	data := []byte("hello wal")
	if _, err := walFile.WriteAt(data, 0); err != nil {
		t.Fatalf("WriteAt failed: %v", err)
	}
	if err := walFile.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if err := walFile.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	walStats := mFS.Stats(KindWAL)
	if walStats.BytesWritten != int64(len(data)) || walStats.Writes != 1 || walStats.Syncs != 1 {
		t.Errorf("unexpected WAL stats: %+v", walStats)
	}

	if mFS.Stats(KindHeap).BytesWritten != 0 {
		t.Errorf("expected 0 heap bytes, got %d", mFS.Stats(KindHeap).BytesWritten)
	}
}

func TestModelCheck_DetectsMismatch(t *testing.T) {
	memFS := NewMemFS()
	dir := "test_model_check"
	const tableName = "table"

	store, err := Open(WithFS(memFS), WithDir(dir), WithCreate(), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	if err := store.Put(tableName, "k0", []byte("val0")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	keys := []string{"k0", "k1"}

	// 1. Matches model
	model := map[string][]byte{"k0": []byte("val0")}
	if err := checkModel(store, tableName, keys, model); err != nil {
		t.Errorf("expected match, got error: %v", err)
	}

	// 2. Missing key expected by model
	missingModel := map[string][]byte{"k0": []byte("val0"), "k1": []byte("val1")}
	if err := checkModel(store, tableName, keys, missingModel); err == nil {
		t.Errorf("expected error for missing key k1, got nil")
	}

	// 3. Value mismatch
	mismatchModel := map[string][]byte{"k0": []byte("wrong_value")}
	if err := checkModel(store, tableName, keys, mismatchModel); err == nil {
		t.Errorf("expected error for value mismatch, got nil")
	}

	// 4. Deleted key resurrected (exists in store but not in model)
	deletedModel := map[string][]byte{}
	if err := checkModel(store, tableName, keys, deletedModel); err == nil {
		t.Errorf("expected error for unexpected existing key k0, got nil")
	}
}

func formatWithCommas(n int64) string {
	in := strconv.FormatInt(n, 10)
	var out []byte
	l := len(in)
	for i := 0; i < l; i++ {
		if i > 0 && (l-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, in[i])
	}
	return string(out)
}

func TestWriteMeasurement(t *testing.T) {
	if os.Getenv("DISKSTORE_MEASURE") != "1" {
		t.Skip("skipping write measurement test; enable with DISKSTORE_MEASURE=1")
	}

	valueSizes := []struct {
		name string
		size int
	}{
		{"256 B", 256},
		{"2 KiB", 2 * 1024},
		{"16 KiB", 16 * 1024},
		{"256 KiB", 256 * 1024},
	}

	checkpoints := []struct {
		name     string
		interval int
	}{
		{"No Checkpoint", 0},
		{"Checkpoint / 1k ops", 1000},
	}

	totalOps := 2000
	if envOps := os.Getenv("DISKSTORE_MEASURE_OPS"); envOps != "" {
		if parsed, err := strconv.Atoi(envOps); err == nil && parsed > 0 {
			totalOps = parsed
		}
	}
	const seed = 42

	var results []measureResult

	for _, vs := range valueSizes {
		for _, cp := range checkpoints {
			caseName := fmt.Sprintf("%s_%s", vs.name, cp.name)
			t.Run(caseName, func(t *testing.T) {
				res := runMeasureCase(t, vs.size, cp.interval, totalOps, seed)
				results = append(results, res)
			})
		}
	}

	fmt.Printf("\n### Write Amplification Measurements (total_ops=%d)\n\n", totalOps)
	fmt.Println("| Value Size | Checkpoint Mode | Payload Put | WAL Bytes | Heap Bytes | Write Ratio | Syncs / Op |")
	fmt.Println("| :--- | :--- | :---: | :---: | :---: | :---: | :---: |")

	for _, r := range results {
		vsName := ""
		for _, vs := range valueSizes {
			if vs.size == r.valueSize {
				vsName = vs.name
				break
			}
		}
		cpName := "No Checkpoint"
		if r.checkpointInterval > 0 {
			cpName = "Checkpoint / 1k ops"
		}

		fmt.Printf("| %s | %s | %s B | %s B | %s B | %.2f | %.4f |\n",
			vsName, cpName,
			formatWithCommas(r.payloadBytesPut),
			formatWithCommas(r.walBytes),
			formatWithCommas(r.heapBytes),
			r.ratio, r.syncsPerOp)
	}
	fmt.Println()
}

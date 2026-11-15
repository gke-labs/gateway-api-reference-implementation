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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// fileKind categorizes files managed by the store engine.
type fileKind string

const (
	kindHeap     fileKind = "heap"
	kindWAL      fileKind = "wal"
	kindOversize fileKind = "oversize"
	kindOther    fileKind = "other"
)

// fileKindStats tracks write I/O metrics for a particular kind of file.
type fileKindStats struct {
	bytesWritten int64
	writes       int64
	syncs        int64
}

func kindIndex(kind fileKind) int {
	switch kind {
	case kindHeap:
		return 0
	case kindWAL:
		return 1
	case kindOversize:
		return 2
	default:
		return 3
	}
}

// classifyPath determines the fileKind based on path conventions.
func classifyPath(name string) fileKind {
	clean := filepath.Clean(name)
	base := filepath.Base(clean)
	dir := filepath.Base(filepath.Dir(clean))

	if base == "heap.db" {
		return kindHeap
	}
	if dir == "wal" || strings.Contains(filepath.ToSlash(clean), "/wal/") {
		return kindWAL
	}
	if dir == "oversize" || strings.Contains(filepath.ToSlash(clean), "/oversize/") {
		return kindOversize
	}
	return kindOther
}

// measureFile wraps File to track write volume and sync operations.
type measureFile struct {
	File
	filesystem *measureFS
	kind       fileKind
}

func (file *measureFile) WriteAt(payload []byte, offset int64) (int, error) {
	bytesWritten, err := file.File.WriteAt(payload, offset)
	if bytesWritten > 0 {
		index := kindIndex(file.kind)
		file.filesystem.stats[index].bytesWritten.Add(int64(bytesWritten))
		file.filesystem.stats[index].writes.Add(1)
	}
	return bytesWritten, err
}

func (file *measureFile) Sync() error {
	index := kindIndex(file.kind)
	file.filesystem.stats[index].syncs.Add(1)
	return file.File.Sync()
}

// measureFS wraps an underlying FS and counts write volume, write operations,
// and sync operations for each kind of file (heap, WAL, oversize, other).
type measureFS struct {
	FS
	stats [4]struct {
		bytesWritten atomic.Int64
		writes       atomic.Int64
		syncs        atomic.Int64
	}
}

// newMeasureFS returns a new filesystem wrapper tracking write metrics.
func newMeasureFS(underlying FS) *measureFS {
	return &measureFS{FS: underlying}
}

func (filesystem *measureFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	file, err := filesystem.FS.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &measureFile{File: file, filesystem: filesystem, kind: classifyPath(name)}, nil
}

func (filesystem *measureFS) Create(name string) (File, error) {
	file, err := filesystem.FS.Create(name)
	if err != nil {
		return nil, err
	}
	return &measureFile{File: file, filesystem: filesystem, kind: classifyPath(name)}, nil
}

func (filesystem *measureFS) Open(name string) (File, error) {
	file, err := filesystem.FS.Open(name)
	if err != nil {
		return nil, err
	}
	return &measureFile{File: file, filesystem: filesystem, kind: classifyPath(name)}, nil
}

// Stats returns the recorded write metrics for a given file kind.
func (filesystem *measureFS) Stats(kind fileKind) fileKindStats {
	index := kindIndex(kind)
	return fileKindStats{
		bytesWritten: filesystem.stats[index].bytesWritten.Load(),
		writes:       filesystem.stats[index].writes.Load(),
		syncs:        filesystem.stats[index].syncs.Load(),
	}
}

// TotalBytesWritten returns total bytes written across all file kinds.
func (filesystem *measureFS) TotalBytesWritten() int64 {
	var total int64
	for index := 0; index < 4; index++ {
		total += filesystem.stats[index].bytesWritten.Load()
	}
	return total
}

// TotalSyncs returns total sync operations across all file kinds.
func (filesystem *measureFS) TotalSyncs() int64 {
	var total int64
	for index := 0; index < 4; index++ {
		total += filesystem.stats[index].syncs.Load()
	}
	return total
}

func formatWithCommas(number int64) string {
	input := strconv.FormatInt(number, 10)
	var output []byte
	length := len(input)
	for index := 0; index < length; index++ {
		if index > 0 && (length-index)%3 == 0 {
			output = append(output, ',')
		}
		output = append(output, input[index])
	}
	return string(output)
}

func TestWriteMeasurement(t *testing.T) {
	if os.Getenv("DISKSTORE_MEASURE") != "1" {
		t.Skip("skipping write measurement test; enable with DISKSTORE_MEASURE=1")
	}

	valueSizeCases := []struct {
		name string
		size int
	}{
		{"256 B", 256},
		{"2 KiB", 2 * 1024},
		{"16 KiB", 16 * 1024},
		{"256 KiB", 256 * 1024},
	}

	durabilityModes := []struct {
		name               string
		checkpointInterval int
		syncAfterOp        bool
	}{
		{name: "No Checkpoint", checkpointInterval: 0, syncAfterOp: false},
		{name: "Checkpoint / 1k ops", checkpointInterval: 1000, syncAfterOp: false},
		{name: "Sync after each op", checkpointInterval: 0, syncAfterOp: true},
	}

	totalOps := 2000
	if envOps := os.Getenv("DISKSTORE_MEASURE_OPS"); envOps != "" {
		if parsed, err := strconv.Atoi(envOps); err == nil && parsed > 0 {
			totalOps = parsed
		}
	}
	const seed = 42

	type measureResult struct {
		valueSizeName     string
		durabilityMode    string
		payloadBytesPut   int64
		walBytes          int64
		heapBytes         int64
		oversizeBytes     int64
		totalBytesWritten int64
		writeRatio        float64
		syncsPerOp        float64
	}

	var results []measureResult

	for _, valueSizeCase := range valueSizeCases {
		for _, durabilityModeCase := range durabilityModes {
			caseName := fmt.Sprintf("%s_%s", valueSizeCase.name, durabilityModeCase.name)
			t.Run(caseName, func(t *testing.T) {
				var measuredFS *measureFS
				config := tortureConfig{
					name:               caseName,
					poolBlocks:         4096,
					maxValueBlocks:     (valueSizeCase.size + BlockSize - 1) / BlockSize,
					numKeys:            20,
					operationsPerCycle: totalOps,
					numCycles:          1,
					cycleEnd:           cycleEndClean,
					fixedValueSize:     valueSizeCase.size,
					checkpointInterval: durabilityModeCase.checkpointInterval,
					syncAfterOp:        durabilityModeCase.syncAfterOp,
					noCheckpoint:       durabilityModeCase.checkpointInterval == 0,
					wrapFS: func(underlying FS) FS {
						measuredFS = newMeasureFS(underlying)
						return measuredFS
					},
				}

				stats := runTortureWorkload(t, config, seed)

				walStats := measuredFS.Stats(kindWAL)
				heapStats := measuredFS.Stats(kindHeap)
				oversizeStats := measuredFS.Stats(kindOversize)
				totalWritten := measuredFS.TotalBytesWritten()
				totalSyncs := measuredFS.TotalSyncs()

				writeRatio := 0.0
				if stats.payloadBytesPut > 0 {
					writeRatio = float64(totalWritten) / float64(stats.payloadBytesPut)
				}
				syncsPerOperation := float64(totalSyncs) / float64(stats.totalOps)

				results = append(results, measureResult{
					valueSizeName:     valueSizeCase.name,
					durabilityMode:    durabilityModeCase.name,
					payloadBytesPut:   stats.payloadBytesPut,
					walBytes:          walStats.bytesWritten,
					heapBytes:         heapStats.bytesWritten,
					oversizeBytes:     oversizeStats.bytesWritten,
					totalBytesWritten: totalWritten,
					writeRatio:        writeRatio,
					syncsPerOp:        syncsPerOperation,
				})
			})
		}
	}

	fmt.Printf("\n### Write Amplification Measurements (total_ops=%d)\n\n", totalOps)
	fmt.Println("| Value Size | Durability Mode | Payload Put | WAL Bytes | Heap Bytes | Oversize Bytes | Write Ratio | Syncs / Op |")
	fmt.Println("| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |")

	for _, result := range results {
		fmt.Printf("| %s | %s | %s B | %s B | %s B | %s B | %.2f | %.4f |\n",
			result.valueSizeName,
			result.durabilityMode,
			formatWithCommas(result.payloadBytesPut),
			formatWithCommas(result.walBytes),
			formatWithCommas(result.heapBytes),
			formatWithCommas(result.oversizeBytes),
			result.writeRatio,
			result.syncsPerOp)
	}
	fmt.Println()
}

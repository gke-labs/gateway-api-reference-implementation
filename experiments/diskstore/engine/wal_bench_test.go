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
	"crypto/rand"
	"fmt"
	"path/filepath"
	"testing"
)

func BenchmarkWAL_AppendThroughput(b *testing.B) {
	sizes := []int{1024, 4096, 16384, 65536}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size=%dB", size), func(b *testing.B) {
			dir := filepath.Join(b.TempDir(), "bench_wal")
			var dbID [16]byte
			copy(dbID[:], []byte("bench-db-0000001"))

			wal, err := OpenWAL(NewOSFS(), dir, dbID, 0, WALOptions{
				MaxSegmentSize: 64 * 1024 * 1024,
			})
			if err != nil {
				b.Fatalf("OpenWAL failed: %v", err)
			}
			defer wal.Close()

			payload := make([]byte, size)
			_, _ = rand.Read(payload)

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				rec := Record{
					Type:    RecordTypePut,
					Key:     "bench-key",
					Payload: payload,
					Token:   "tok",
				}
				if err := wal.Append(rec); err != nil {
					b.Fatalf("Append failed: %v", err)
				}
				if i%100 == 0 {
					if err := wal.Sync(); err != nil {
						b.Fatalf("Sync failed: %v", err)
					}
				}
			}
			_ = wal.Sync()
		})
	}
}

func BenchmarkWAL_AppendThroughput_Parallel(b *testing.B) {
	sizes := []int{4096, 16384, 65536}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size=%dB", size), func(b *testing.B) {
			dir := filepath.Join(b.TempDir(), "bench_wal_par")
			var dbID [16]byte
			copy(dbID[:], []byte("bench-db-0000002"))

			wal, err := OpenWAL(NewOSFS(), dir, dbID, 0, WALOptions{
				MaxSegmentSize: 128 * 1024 * 1024,
			})
			if err != nil {
				b.Fatalf("OpenWAL failed: %v", err)
			}
			defer wal.Close()

			payload := make([]byte, size)
			_, _ = rand.Read(payload)

			b.ResetTimer()
			b.SetBytes(int64(size))

			b.RunParallel(func(pb *testing.PB) {
				rec := Record{
					Type:    RecordTypePut,
					Key:     "bench-key",
					Payload: payload,
					Token:   "tok",
				}
				for pb.Next() {
					if err := wal.Append(rec); err != nil {
						b.Errorf("Append failed: %v", err)
						return
					}
				}
			})
			_ = wal.Sync()
		})
	}
}

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
	"testing"
)

// TestSmallBlockPool_MultiBlockDeterministic tests that when a multi-block page takes most
// of a small block pool and is updated/replaced, it is not flushed to disk as a tombstone or stale copy
// with the new allocation's LSN, ensuring every key written is readable after clean close and reopen.
func TestSmallBlockPool_MultiBlockDeterministic(t *testing.T) {
	faultFS := NewFaultFS(NewMemFS())
	dir := "test_small_pool_deterministic"

	store, err := Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(9), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// 1. Put k1 with 4 blocks (11000 bytes) -> Page 1
	val1 := bytes.Repeat([]byte("a"), 11000)
	if err := store.Put("t1", "k1", val1); err != nil {
		t.Fatalf("Put k1 failed: %v", err)
	}

	// 2. Put k2 with 1 block -> Page 2
	val2 := []byte("small-val")
	if err := store.Put("t1", "k2", val2); err != nil {
		t.Fatalf("Put k2 failed: %v", err)
	}

	// 3. Replace k1 with an 8-block value (19000 bytes) -> Reuses Page 1
	val1v2 := bytes.Repeat([]byte("b"), 19000)
	if err := store.Put("t1", "k1", val1v2); err != nil {
		t.Fatalf("Put k1 v2 failed: %v", err)
	}

	// 4. Put k3 with an 8-block value (19000 bytes) -> Page 3
	// In a 9-block pool, this evicts and flushes Page 1 so Page 1 is no longer dirty.
	val3 := bytes.Repeat([]byte("c"), 19000)
	if err := store.Put("t1", "k3", val3); err != nil {
		t.Fatalf("Put k3 failed: %v", err)
	}

	if err := store.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Reopen cleanly and verify all keys written are readable
	reopenStore, err := Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(9), WithCompressionCodec(CodecNone))
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer reopenStore.Close()

	got1, exists, err := reopenStore.Get("t1", "k1")
	if err != nil {
		t.Fatalf("Get k1 error: %v", err)
	}
	if !exists {
		t.Fatalf("Get k1 missing")
	}
	if !bytes.Equal(got1, val1v2) {
		t.Fatalf("Get k1 value mismatch: got len %d, want len %d", len(got1), len(val1v2))
	}

	got2, exists, err := reopenStore.Get("t1", "k2")
	if err != nil {
		t.Fatalf("Get k2 error: %v", err)
	}
	if !exists {
		t.Fatalf("Get k2 missing")
	}
	if !bytes.Equal(got2, val2) {
		t.Fatalf("Get k2 value mismatch")
	}

	got3, exists, err := reopenStore.Get("t1", "k3")
	if err != nil {
		t.Fatalf("Get k3 error: %v", err)
	}
	if !exists {
		t.Fatalf("Get k3 missing")
	}
	if !bytes.Equal(got3, val3) {
		t.Fatalf("Get k3 value mismatch")
	}
}

// TestSmallBlockPool_MultiBlockRandomized tests randomized puts, replacements, and deletes
// with multi-block values on a 9-block pool followed by checkpoint, sync, clean close, and reopen.
func TestSmallBlockPool_MultiBlockRandomized(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			faultFS := NewFaultFS(NewMemFS())
			dir := fmt.Sprintf("test_small_pool_rnd_%d", seed)

			store, err := Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(9), WithCompressionCodec(CodecNone), WithCreate())
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}

			model := make(map[string][]byte)
			keys := make([]string, 0)
			for i := 0; i < 20; i++ {
				keys = append(keys, fmt.Sprintf("key_%d", i))
			}

			for op := 0; op < 50; op++ {
				action := rng.Intn(3)
				key := keys[rng.Intn(len(keys))]
				switch action {
				case 0, 1: // Put or replace
					size := rng.Intn(25000) + 100
					val := make([]byte, size)
					for j := range val {
						val[j] = byte(rng.Intn(256))
					}
					if err := store.Put("t1", key, val); err != nil {
						t.Fatalf("Put failed: %v", err)
					}
					model[key] = val
				case 2: // Delete
					if err := store.Delete("t1", key); err != nil {
						t.Fatalf("Delete failed: %v", err)
					}
					delete(model, key)
				}
			}

			if err := store.Sync(); err != nil {
				t.Fatalf("Sync failed: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatalf("Close failed: %v", err)
			}

			reopenStore, err := Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(9), WithCompressionCodec(CodecNone))
			if err != nil {
				t.Fatalf("Reopen failed: %v", err)
			}
			defer reopenStore.Close()

			for k, expected := range model {
				got, exists, err := reopenStore.Get("t1", k)
				if err != nil {
					t.Fatalf("Get(%s) error: %v", k, err)
				}
				if !exists {
					t.Fatalf("Get(%s) missing", k)
				}
				if !bytes.Equal(got, expected) {
					t.Fatalf("Get(%s) value mismatch", k)
				}
			}
		})
	}
}

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
	"math/rand"
	"strings"
	"sync"
	"testing"
)

// TestSmallBlockPool_MultiBlockDeterministic checks that after a multi-block value is replaced
// in a pool that cannot hold both copies, every key is readable after a clean close and reopen.
func TestSmallBlockPool_MultiBlockDeterministic(t *testing.T) {
	faultFS := NewFaultFS(NewMemFS())
	dir := "test_small_pool_deterministic"

	store, err := Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(9), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	firstValue := bytes.Repeat([]byte("a"), 11000)
	if err := store.Put("t1", "key1", firstValue); err != nil {
		t.Fatalf("Put key1 failed: %v", err)
	}

	secondValue := []byte("small-val")
	if err := store.Put("t1", "key2", secondValue); err != nil {
		t.Fatalf("Put key2 failed: %v", err)
	}

	replacementValue := bytes.Repeat([]byte("b"), 19000)
	if err := store.Put("t1", "key1", replacementValue); err != nil {
		t.Fatalf("Put key1 replacement failed: %v", err)
	}

	thirdValue := bytes.Repeat([]byte("c"), 19000)
	if err := store.Put("t1", "key3", thirdValue); err != nil {
		t.Fatalf("Put key3 failed: %v", err)
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
	defer func() {
		if closeErr := reopenStore.Close(); closeErr != nil {
			t.Errorf("Close failed: %v", closeErr)
		}
	}()

	got1, exists, err := reopenStore.Get("t1", "key1")
	if err != nil {
		t.Fatalf("Get key1 error: %v", err)
	}
	if !exists {
		t.Fatalf("Get key1 missing")
	}
	if !bytes.Equal(got1, replacementValue) {
		t.Fatalf("Get key1 value mismatch: got len %d, want len %d", len(got1), len(replacementValue))
	}

	got2, exists, err := reopenStore.Get("t1", "key2")
	if err != nil {
		t.Fatalf("Get key2 error: %v", err)
	}
	if !exists {
		t.Fatalf("Get key2 missing")
	}
	if !bytes.Equal(got2, secondValue) {
		t.Fatalf("Get key2 value mismatch")
	}

	got3, exists, err := reopenStore.Get("t1", "key3")
	if err != nil {
		t.Fatalf("Get key3 error: %v", err)
	}
	if !exists {
		t.Fatalf("Get key3 missing")
	}
	if !bytes.Equal(got3, thirdValue) {
		t.Fatalf("Get key3 value mismatch")
	}
}

// TestSmallBlockPool_MultiBlockRandomized tests randomized puts, replacements, and deletes
// with multi-block values on a 9-block pool followed by sync, clean close, and reopen.
func TestSmallBlockPool_MultiBlockRandomized(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			random := rand.New(rand.NewSource(seed))
			faultFS := NewFaultFS(NewMemFS())
			dir := fmt.Sprintf("test_small_pool_rnd_%d", seed)

			store, err := Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(9), WithCompressionCodec(CodecNone), WithCreate())
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}

			model := make(map[string][]byte)
			keys := make([]string, 0, 20)
			for i := 0; i < 20; i++ {
				keys = append(keys, fmt.Sprintf("key_%d", i))
			}

			for operation := 0; operation < 50; operation++ {
				action := random.Intn(3)
				key := keys[random.Intn(len(keys))]
				switch action {
				case 0, 1: // Put or replace
					size := random.Intn(25000) + 100
					value := make([]byte, size)
					for j := range value {
						value[j] = byte(random.Intn(256))
					}
					if err := store.Put("t1", key, value); err != nil {
						t.Fatalf("Put failed: %v", err)
					}
					model[key] = value
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
			defer func() {
				if closeErr := reopenStore.Close(); closeErr != nil {
					t.Errorf("Close failed: %v", closeErr)
				}
			}()

			for key, expected := range model {
				got, exists, err := reopenStore.Get("t1", key)
				if err != nil {
					t.Fatalf("Get(%s) error: %v", key, err)
				}
				if !exists {
					t.Fatalf("Get(%s) missing", key)
				}
				if !bytes.Equal(got, expected) {
					t.Fatalf("Get(%s) value mismatch", key)
				}
			}
		})
	}
}

// TestSmallBlockPool_SweepBetweenWrites tests that concurrent background sweeps running
// between writes cannot flush a replaced multi-block page's tombstone at the same LSN.
func TestSmallBlockPool_SweepBetweenWrites(t *testing.T) {
	for _, poolBlocks := range []int{9, 12, 16, 24} {
		t.Run(fmt.Sprintf("pool_%d", poolBlocks), func(t *testing.T) {
			faultFS := NewFaultFS(NewMemFS())
			dir := fmt.Sprintf("test_small_pool_sweep_%d", poolBlocks)

			store, err := Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(poolBlocks), WithCompressionCodec(CodecNone), WithCreate())
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}

			stopSweep := make(chan struct{})
			var sweepWg sync.WaitGroup
			sweepWg.Add(1)
			go func() {
				defer sweepWg.Done()
				for {
					select {
					case <-stopSweep:
						return
					default:
						store.bp.sweepIdleDirtyPages()
					}
				}
			}()

			random := rand.New(rand.NewSource(42))
			model := make(map[string][]byte)
			keys := make([]string, 0, 10)
			for i := 0; i < 10; i++ {
				keys = append(keys, fmt.Sprintf("key_%d", i))
			}

			for operation := 0; operation < 60; operation++ {
				action := random.Intn(3)
				key := keys[random.Intn(len(keys))]
				switch action {
				case 0, 1:
					size := random.Intn(25000) + 100
					value := make([]byte, size)
					for j := range value {
						value[j] = byte(random.Intn(256))
					}
					if err := store.Put("t1", key, value); err != nil {
						t.Fatalf("Put failed: %v", err)
					}
					model[key] = value
				case 2:
					if err := store.Delete("t1", key); err != nil {
						t.Fatalf("Delete failed: %v", err)
					}
					delete(model, key)
				}
			}

			close(stopSweep)
			sweepWg.Wait()

			if err := store.Sync(); err != nil {
				t.Fatalf("Sync failed: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatalf("Close failed: %v", err)
			}

			reopenStore, err := Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(poolBlocks), WithCompressionCodec(CodecNone))
			if err != nil {
				t.Fatalf("Reopen failed: %v", err)
			}
			defer func() {
				if closeErr := reopenStore.Close(); closeErr != nil {
					t.Errorf("Close failed: %v", closeErr)
				}
			}()

			for key, expected := range model {
				got, exists, err := reopenStore.Get("t1", key)
				if err != nil {
					t.Fatalf("Get(%s) error: %v", key, err)
				}
				if !exists {
					t.Fatalf("Get(%s) missing", key)
				}
				if !bytes.Equal(got, expected) {
					t.Fatalf("Get(%s) value mismatch", key)
				}
			}
		})
	}
}

// TestSmallBlockPool_PoolSmallerThanPage tests that when the block pool is smaller than one page,
// Put returns ErrBlockPoolTooSmall stating the page's block count and the pool's size without
// failing the engine.
func TestSmallBlockPool_PoolSmallerThanPage(t *testing.T) {
	faultFS := NewFaultFS(NewMemFS())
	dir := "test_pool_smaller_than_page"

	// Pool of 4 blocks
	store, err := Open(WithFS(faultFS), WithDir(dir), WithNumPoolBlocks(4), WithCompressionCodec(CodecNone), WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("Close failed: %v", closeErr)
		}
	}()

	// Value requiring 8 blocks (19000 bytes)
	largeValue := bytes.Repeat([]byte("x"), 19000)
	putErr := store.Put("t1", "large-key", largeValue)
	if putErr == nil {
		t.Fatalf("expected Put to fail when page requires more blocks than pool capacity")
	}

	if !errors.Is(putErr, ErrBlockPoolTooSmall) {
		t.Fatalf("expected ErrBlockPoolTooSmall, got: %v", putErr)
	}

	// Verify error message states the page's block count (8) and the pool's size (4)
	errMsg := putErr.Error()
	if !strings.Contains(errMsg, "8 blocks") || !strings.Contains(errMsg, "4 blocks") {
		t.Fatalf("expected error message to state page's block count (8) and pool's size (4), got: %s", errMsg)
	}

	// Verify the engine is not failed: subsequent Put and Get of a fitting key succeed
	smallValue := []byte("fits-in-pool")
	if err := store.Put("t1", "small-key", smallValue); err != nil {
		t.Fatalf("Put small-key failed after pool-too-small error: %v", err)
	}

	got, exists, err := store.Get("t1", "small-key")
	if err != nil {
		t.Fatalf("Get small-key error: %v", err)
	}
	if !exists {
		t.Fatalf("Get small-key missing")
	}
	if !bytes.Equal(got, smallValue) {
		t.Fatalf("Get small-key value mismatch")
	}
}

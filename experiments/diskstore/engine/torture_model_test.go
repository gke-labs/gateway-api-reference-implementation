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
	"sync"
	"sync/atomic"
	"testing"
)

// ModelSnapshot records the exact logical database state at a specific LSN.
type ModelSnapshot struct {
	LSN    uint64
	Data   map[string]map[string][]byte // bucket -> key -> value
	Tokens map[string]string            // bucket -> resourceVersion / token
}

func cloneData(src map[string]map[string][]byte) map[string]map[string][]byte {
	dst := make(map[string]map[string][]byte, len(src))
	for b, keys := range src {
		dst[b] = make(map[string][]byte, len(keys))
		for k, v := range keys {
			dst[b][k] = bytes.Clone(v)
		}
	}
	return dst
}

func cloneTokens(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for b, t := range src {
		dst[b] = t
	}
	return dst
}

// ReferenceModel maintains the authoritative logical state history after every LSN.
type ReferenceModel struct {
	mu sync.RWMutex

	snapshots map[uint64]*ModelSnapshot

	currentData   map[string]map[string][]byte
	currentTokens map[string]string

	// keyHistory maps bucket -> key -> set of all values key has ever held
	keyHistory map[string]map[string]map[string]bool

	lastAckLSN     atomic.Uint64
	lastDurableLSN atomic.Uint64
	maxAllowedLSN  atomic.Uint64
}

// NewReferenceModel creates a reference model initialized to LSN 0 with empty state.
func NewReferenceModel() *ReferenceModel {
	m := &ReferenceModel{
		snapshots:     make(map[uint64]*ModelSnapshot),
		currentData:   make(map[string]map[string][]byte),
		currentTokens: make(map[string]string),
		keyHistory:    make(map[string]map[string]map[string]bool),
	}
	// Initial state at LSN 0
	m.snapshots[0] = &ModelSnapshot{
		LSN:    0,
		Data:   make(map[string]map[string][]byte),
		Tokens: make(map[string]string),
	}
	return m
}

// RollbackTo resets currentData, currentTokens, and lastAckLSN to match the recovered snapshot.
func (m *ReferenceModel) RollbackTo(recoveredLSN uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	targetSnapshot, exists := m.snapshots[recoveredLSN]
	if !exists {
		var closestLSN uint64
		for lsn := range m.snapshots {
			if lsn <= recoveredLSN && lsn >= closestLSN {
				closestLSN = lsn
			}
		}
		targetSnapshot = m.snapshots[closestLSN]
	}
	if targetSnapshot != nil {
		m.currentData = cloneData(targetSnapshot.Data)
		m.currentTokens = cloneTokens(targetSnapshot.Tokens)
		m.lastAckLSN.Store(targetSnapshot.LSN)
		m.lastDurableLSN.Store(targetSnapshot.LSN)

		// Prune any future snapshots past the rollback point
		for lsn := range m.snapshots {
			if lsn > targetSnapshot.LSN {
				delete(m.snapshots, lsn)
			}
		}
	}
}

// SetMaxAllowedLSN sets an upper bound on allowable recovered LSN (for in-flight operations).
func (m *ReferenceModel) SetMaxAllowedLSN(lsn uint64) {
	for {
		curr := m.maxAllowedLSN.Load()
		if lsn <= curr || m.maxAllowedLSN.CompareAndSwap(curr, lsn) {
			break
		}
	}
}

// SetLastDurableLSN updates the highest LSN confirmed durable.
func (m *ReferenceModel) SetLastDurableLSN(lsn uint64) {
	for {
		curr := m.lastDurableLSN.Load()
		if lsn <= curr || m.lastDurableLSN.CompareAndSwap(curr, lsn) {
			break
		}
	}
}

// LastDurableLSN returns the highest LSN confirmed durable.
func (m *ReferenceModel) LastDurableLSN() uint64 {
	return m.lastDurableLSN.Load()
}

// LastAckLSN returns the LSN of the last acknowledged write.
func (m *ReferenceModel) LastAckLSN() uint64 {
	return m.lastAckLSN.Load()
}

func (m *ReferenceModel) updateAckLSN(lsn uint64) {
	for {
		curr := m.lastAckLSN.Load()
		if lsn <= curr || m.lastAckLSN.CompareAndSwap(curr, lsn) {
			break
		}
	}
}

// AddKeyHistory records a payload in the historical values set before an in-flight write publishes it.
func (m *ReferenceModel) AddKeyHistory(bucket, key string, val []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.keyHistory[bucket] == nil {
		m.keyHistory[bucket] = make(map[string]map[string]bool)
	}
	if m.keyHistory[bucket][key] == nil {
		m.keyHistory[bucket][key] = make(map[string]bool)
	}
	m.keyHistory[bucket][key][string(val)] = true
}

// RecordPut records a Put operation at the given LSN.
func (m *ReferenceModel) RecordPut(bucket, key string, val []byte, token string, lsn uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.currentData[bucket] == nil {
		m.currentData[bucket] = make(map[string][]byte)
	}
	m.currentData[bucket][key] = bytes.Clone(val)

	if token != "" {
		m.currentTokens[bucket] = token
	}

	// Record in key history
	if m.keyHistory[bucket] == nil {
		m.keyHistory[bucket] = make(map[string]map[string]bool)
	}
	if m.keyHistory[bucket][key] == nil {
		m.keyHistory[bucket][key] = make(map[string]bool)
	}
	m.keyHistory[bucket][key][string(val)] = true

	m.snapshots[lsn] = &ModelSnapshot{
		LSN:    lsn,
		Data:   cloneData(m.currentData),
		Tokens: cloneTokens(m.currentTokens),
	}
	m.updateAckLSN(lsn)
}

// RecordDelete records a Delete operation at the given LSN.
func (m *ReferenceModel) RecordDelete(bucket, key string, token string, lsn uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.currentData[bucket] != nil {
		delete(m.currentData[bucket], key)
	}
	if token != "" {
		m.currentTokens[bucket] = token
	}

	m.snapshots[lsn] = &ModelSnapshot{
		LSN:    lsn,
		Data:   cloneData(m.currentData),
		Tokens: cloneTokens(m.currentTokens),
	}
	m.updateAckLSN(lsn)
}

// RecordSetToken records a SetToken operation at the given LSN.
func (m *ReferenceModel) RecordSetToken(bucket, token string, lsn uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.currentTokens[bucket] = token
	m.snapshots[lsn] = &ModelSnapshot{
		LSN:    lsn,
		Data:   cloneData(m.currentData),
		Tokens: cloneTokens(m.currentTokens),
	}
	m.updateAckLSN(lsn)
}

// RecordCheckpoint records a Checkpoint at the given LSN and marks it durable.
func (m *ReferenceModel) RecordCheckpoint(chkLSN uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.snapshots[chkLSN] = &ModelSnapshot{
		LSN:    chkLSN,
		Data:   cloneData(m.currentData),
		Tokens: cloneTokens(m.currentTokens),
	}
	m.updateAckLSN(chkLSN)
	m.SetLastDurableLSN(chkLSN)
}

// IsValueInHistory reports whether val is among the historical values for bucket and key.
func (m *ReferenceModel) IsValueInHistory(bucket, key string, val []byte) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.keyHistory[bucket] == nil || m.keyHistory[bucket][key] == nil {
		return false
	}
	return m.keyHistory[bucket][key][string(val)]
}

// ReproCommand formats a one-line command to reproduce a failure.
func ReproCommand(seed int64, opNum int) string {
	return fmt.Sprintf("TEST_TORTURE_SEED=%d TEST_TORTURE_OP=%d go test -v -run TestDiskStoreTorture ./experiments/diskstore/engine/...", seed, opNum)
}

// ValidateStore verifies the core crash consistency invariant:
// After every crash and recovery, the store's full contents and progress tokens must equal
// the model's state at some LSN between the last durable LSN and the last acknowledged write.
func (m *ReferenceModel) ValidateStore(t *testing.T, store *Engine, seed int64, opNum int) uint64 {
	t.Helper()
	m.mu.RLock()
	defer m.mu.RUnlock()

	lastDurable := m.lastDurableLSN.Load()
	lastAck := m.lastAckLSN.Load()
	maxAllowed := m.maxAllowedLSN.Load()

	recoveredLSN := store.wal.MaxLSN()

	maxExpected := lastAck
	if lastDurable > maxExpected {
		maxExpected = lastDurable
	}
	if maxAllowed > maxExpected {
		maxExpected = maxAllowed
	}

	// 1. Invariant: lastDurable <= recoveredLSN <= maxExpected
	if recoveredLSN < lastDurable || recoveredLSN > maxExpected {
		t.Fatalf("TORTURE FAILURE at op %d with seed %d: recovered LSN %d outside [%d..%d]\nRepro: %s",
			opNum, seed, recoveredLSN, lastDurable, maxExpected, ReproCommand(seed, opNum))
	}

	targetSnapshot, exists := m.snapshots[recoveredLSN]
	if !exists {
		// Find closest snapshot <= recoveredLSN
		var closestLSN uint64
		for lsn := range m.snapshots {
			if lsn <= recoveredLSN && lsn >= closestLSN {
				closestLSN = lsn
			}
		}
		targetSnapshot = m.snapshots[closestLSN]
		if targetSnapshot == nil {
			t.Fatalf("TORTURE FAILURE at op %d with seed %d: no model snapshot found for LSN %d (closest %d)\nRepro: %s",
				opNum, seed, recoveredLSN, closestLSN, ReproCommand(seed, opNum))
		}
	}

	// 2. Invariant: tokens match
	for bucket, expToken := range targetSnapshot.Tokens {
		actToken := store.Token(bucket)
		if actToken != expToken {
			t.Fatalf("TORTURE FAILURE at op %d with seed %d: token mismatch for bucket %s: expected %q, got %q\nRepro: %s",
				opNum, seed, bucket, expToken, actToken, ReproCommand(seed, opNum))
		}
	}

	// 3. Invariant: full contents match model snapshot
	// Check all keys in model exist in store with matching value
	for bucket, keys := range targetSnapshot.Data {
		for key, expVal := range keys {
			actVal, exists, err := store.Get(bucket, key)
			if err != nil {
				t.Fatalf("TORTURE FAILURE at op %d with seed %d: Get(%s, %s) failed: %v\nRepro: %s",
					opNum, seed, bucket, key, err, ReproCommand(seed, opNum))
			}
			if !exists {
				sKeyIndex := make(map[string]KeyIndexEntry)
				store.keyMu.RLock()
				for k, v := range store.keyIndex {
					sKeyIndex[k] = v
				}
				store.keyMu.RUnlock()
				t.Fatalf("TORTURE FAILURE at op %d with seed %d: key %s in bucket %s missing from store (recoveredLSN=%d, keyIndexEntry=%+v)\nRepro: %s",
					opNum, seed, key, bucket, recoveredLSN, sKeyIndex[qualifyKey(bucket, key)], ReproCommand(seed, opNum))
			}
			if !bytes.Equal(actVal, expVal) {
				t.Fatalf("TORTURE FAILURE at op %d with seed %d: value mismatch for key %s in bucket %s (len %d vs %d)\nRepro: %s",
					opNum, seed, key, bucket, len(actVal), len(expVal), ReproCommand(seed, opNum))
			}
		}
	}

	// Check store has no extraneous keys not in model
	for bucket := range targetSnapshot.Data {
		items, err := store.List(bucket)
		if err != nil {
			t.Fatalf("TORTURE FAILURE at op %d with seed %d: List(%s) failed: %v\nRepro: %s",
				opNum, seed, bucket, err, ReproCommand(seed, opNum))
		}
		expectedKeys := targetSnapshot.Data[bucket]
		if len(items) != len(expectedKeys) {
			var actualKeys []string
			for _, item := range items {
				actualKeys = append(actualKeys, item.Key)
			}
			var expKeyList []string
			for ek := range expectedKeys {
				expKeyList = append(expKeyList, ek)
			}
			t.Fatalf("TORTURE FAILURE at op %d with seed %d: bucket %s item count mismatch: expected %d (%v), got %d (%v)\nRepro: %s",
				opNum, seed, bucket, len(expectedKeys), expKeyList, len(items), actualKeys, ReproCommand(seed, opNum))
		}
		for _, item := range items {
			if _, ok := expectedKeys[item.Key]; !ok {
				t.Fatalf("TORTURE FAILURE at op %d with seed %d: extraneous key %s in bucket %s\nRepro: %s",
					opNum, seed, item.Key, bucket, ReproCommand(seed, opNum))
			}
		}
	}

	return recoveredLSN
}

// ValidateCurrentWithErr checks that every read from store matches current model value.
func (m *ReferenceModel) ValidateCurrentWithErr(store *Engine) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for bucket, keys := range m.currentData {
		for key, expVal := range keys {
			actVal, exists, err := store.Get(bucket, key)
			if err != nil {
				return fmt.Errorf("Get(%s, %s) failed: %w", bucket, key, err)
			}
			if !exists {
				return fmt.Errorf("key %s in bucket %s unexpectedly missing", key, bucket)
			}
			if !bytes.Equal(actVal, expVal) {
				return fmt.Errorf("current value mismatch for key %s in bucket %s", key, bucket)
			}
		}
	}
	return nil
}

// ValidateCurrent verifies that on an active, open store, every read equals the model's current value.
func (m *ReferenceModel) ValidateCurrent(t *testing.T, store *Engine, seed int64, opNum int) {
	t.Helper()
	if err := m.ValidateCurrentWithErr(store); err != nil {
		t.Fatalf("TORTURE FAILURE at op %d with seed %d: %v\nRepro: %s",
			opNum, seed, err, ReproCommand(seed, opNum))
	}
}

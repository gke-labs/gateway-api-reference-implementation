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

// SimulateFailure transitions the engine into the failed state and writes the failure marker for testing.
func (s *Engine) SimulateFailure(err error) {
	s.setFailed(err)
}

// InjectFrameLeak drops a free block from the pool to simulate a frame leak.
func (s *Engine) InjectFrameLeak() {
	s.bp.mu.Lock()
	defer s.bp.mu.Unlock()
	if len(s.bp.freePoolBlocks) > 0 {
		s.bp.freePoolBlocks = s.bp.freePoolBlocks[1:]
	}
}

// InjectBuddyOverlap adds an overlapping allocation to the buddy allocator.
func (s *Engine) InjectBuddyOverlap() {
	s.buddy.mu.Lock()
	defer s.buddy.mu.Unlock()
	// Find any allocated block and add an overlapping block
	for start := range s.buddy.allocated {
		s.buddy.allocated[start+1] = 0
		break
	}
}

// InjectBuddyLeak adds an unreferenced allocated block to simulate an allocator block leak.
func (s *Engine) InjectBuddyLeak() {
	s.buddy.mu.Lock()
	defer s.buddy.mu.Unlock()
	s.buddy.allocated[999999] = 0
}

// InjectCorruptIndex points an index entry to a non-existent logical page.
func (s *Engine) InjectCorruptIndex(qKey string) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	s.keyIndex[qKey] = KeyIndexEntry{
		LogicalPage: 888888,
		Slot:        0,
		LSN:         1,
		NumBlocks:   1,
	}
}

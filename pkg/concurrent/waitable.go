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

package concurrent

import (
	"context"
	"sync"
)

// WaitableBool holds a boolean that goroutines can set, read, and wait on.
// The zero value is ready to use and is false.
type WaitableBool struct {
	// mu guards val and cond.
	mu   sync.Mutex
	cond sync.Cond
	val  bool
}

func (b *WaitableBool) initLocked() {
	if b.cond.L == nil {
		b.cond.L = &b.mu
	}
}

// Set stores the value and wakes the waiters.
func (b *WaitableBool) Set(value bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.val = value
	b.initLocked()
	b.cond.Broadcast()
}

// Get returns the value.
func (b *WaitableBool) Get() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.val
}

// Wait returns nil when the value is true. It returns the context's error when
// the context ends first.
func (b *WaitableBool) Wait(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.initLocked()
	if b.val {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	stop := context.AfterFunc(ctx, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.cond.Broadcast()
	})
	defer stop()

	for !b.val {
		if err := ctx.Err(); err != nil {
			return err
		}
		b.cond.Wait()
	}
	return nil
}

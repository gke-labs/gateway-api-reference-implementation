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
	"errors"
	"runtime"
	"testing"
	"time"
)

func TestWaitableBool_AlreadyTrue(t *testing.T) {
	var b WaitableBool
	if b.Get() {
		t.Fatal("expected zero value to be false")
	}

	b.Set(true)
	if !b.Get() {
		t.Fatal("expected value to be true")
	}

	if err := b.Wait(t.Context()); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := b.Wait(canceledCtx); err != nil {
		t.Fatalf("expected nil error when already true, got %v", err)
	}
}

func TestWaitableBool_SetWakesWait(t *testing.T) {
	var b WaitableBool
	done := make(chan error, 1)
	go func() {
		done <- b.Wait(t.Context())
	}()

	time.Sleep(20 * time.Millisecond)
	b.Set(true)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Wait to return")
	}
}

func TestWaitableBool_ContextCancelled(t *testing.T) {
	var b WaitableBool
	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		done <- b.Wait(ctx)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Wait to return")
	}

	if err := b.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled for already-canceled context, got %v", err)
	}
}

func TestWaitableBool_NoGoroutineLeak(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	start := runtime.NumGoroutine()

	for i := 0; i < 500; i++ {
		var b WaitableBool
		go b.Set(true)
		if err := b.Wait(ctx); err != nil {
			t.Fatalf("Wait failed: %v", err)
		}
	}

	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	if diff := runtime.NumGoroutine() - start; diff > 5 {
		t.Fatalf("goroutines grew by %d", diff)
	}
}

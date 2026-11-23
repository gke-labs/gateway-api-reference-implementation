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
	"sync"
	"testing"
	"time"
)

func TestWaitableBool_ZeroValue(t *testing.T) {
	var b WaitableBool
	if b.Get() {
		t.Fatal("expected zero value to be false")
	}
}

func TestWaitableBool_AlreadyTrue(t *testing.T) {
	var b WaitableBool
	b.Set(true)
	if !b.Get() {
		t.Fatal("expected value to be true")
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	if err := b.Wait(ctx); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	// Wait should also return nil at once even if the context is already cancelled.
	canceledCtx, cancelImmediate := context.WithCancel(t.Context())
	cancelImmediate()

	if err := b.Wait(canceledCtx); err != nil {
		t.Fatalf("expected nil error when value is already true, got %v", err)
	}
}

func TestWaitableBool_SetWakesWait(t *testing.T) {
	var b WaitableBool
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	started := make(chan struct{})
	done := make(chan error, 1)

	go func() {
		close(started)
		done <- b.Wait(ctx)
	}()

	<-started
	// Give the goroutine a moment to enter Wait
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

	if !b.Get() {
		t.Fatal("expected Get() to return true")
	}
}

func TestWaitableBool_ContextCancelled(t *testing.T) {
	var b WaitableBool
	ctx, cancel := context.WithCancel(t.Context())

	started := make(chan struct{})
	done := make(chan error, 1)

	go func() {
		close(started)
		done <- b.Wait(ctx)
	}()

	<-started
	// Give the goroutine a moment to enter Wait
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
}

func TestWaitableBool_ContextAlreadyCancelled(t *testing.T) {
	var b WaitableBool
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := b.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestWaitableBool_NoGoroutineLeak(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Warm up runtime and let goroutines settle.
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	startGoroutines := runtime.NumGoroutine()

	const iterations = 500
	for i := 0; i < iterations; i++ {
		var b WaitableBool
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Set(true)
		}()
		if err := b.Wait(ctx); err != nil {
			t.Fatalf("Wait failed: %v", err)
		}
		wg.Wait()
	}

	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	endGoroutines := runtime.NumGoroutine()

	// Goroutine count should not have grown substantially (e.g. not 500 goroutines leaked).
	if diff := endGoroutines - startGoroutines; diff > 5 {
		t.Fatalf("goroutines grew by %d (start=%d, end=%d)", diff, startGoroutines, endGoroutines)
	}

	// Now cancel the long-lived context: if AfterFunc functions were not stopped,
	// this would spawn goroutines.
	cancel()
	time.Sleep(20 * time.Millisecond)
	afterCancelGoroutines := runtime.NumGoroutine()
	if diff := afterCancelGoroutines - endGoroutines; diff > 5 {
		t.Fatalf("goroutines grew on cancel by %d (before=%d, after=%d)", diff, endGoroutines, afterCancelGoroutines)
	}
}

func TestWaitableBool_MultipleWaiters(t *testing.T) {
	var b WaitableBool
	ctx1, cancel1 := context.WithCancel(t.Context())
	ctx2, cancel2 := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel2()

	err1Ch := make(chan error, 1)
	err2Ch := make(chan error, 1)

	go func() {
		err1Ch <- b.Wait(ctx1)
	}()
	go func() {
		err2Ch <- b.Wait(ctx2)
	}()

	// Wait for both to be waiting
	time.Sleep(20 * time.Millisecond)

	// Cancel ctx1 only
	cancel1()

	select {
	case err := <-err1Ch:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled for waiter 1, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for waiter 1 to cancel")
	}

	// Waiter 2 should still be waiting
	select {
	case err := <-err2Ch:
		t.Fatalf("waiter 2 finished unexpectedly with %v", err)
	default:
	}

	// Now wake waiter 2 by setting to true
	b.Set(true)

	select {
	case err := <-err2Ch:
		if err != nil {
			t.Fatalf("expected nil for waiter 2, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for waiter 2 to complete")
	}
}

func TestWaitableBool_SetFalse(t *testing.T) {
	var b WaitableBool
	b.Set(true)
	if !b.Get() {
		t.Fatal("expected Get() to be true")
	}

	b.Set(false)
	if b.Get() {
		t.Fatal("expected Get() to be false")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	if err := b.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

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

package kubecache

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/experiments/diskstore/engine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConcurrency_ReadersWritersAndCheckpoints(t *testing.T) {
	memFS := engine.NewMemFS()
	store, err := engine.Open(engine.WithFS(memFS), engine.WithDir("conc_store"), engine.WithNumPoolBlocks(64), engine.WithCreate())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	stopCh := make(chan struct{})
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			close(stopCh)
		})
	}
	onFatal := func(err error) {
		t.Errorf("kubecache fatal error: %v", err)
		stop()
	}

	indexer, err := New(store, &corev1.ConfigMap{}, onFatal)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer indexer.Close()

	// Pre-populate with 50 objects
	for i := 0; i < 50; i++ {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      fmt.Sprintf("cm-%03d", i),
			},
			Data: map[string]string{"val": fmt.Sprintf("initial-%d", i)},
		}
		if err := indexer.Add(cm); err != nil {
			t.Fatalf("pre-populate failed: %v", err)
		}
	}

	var wg sync.WaitGroup

	// Writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		step := 0
		for {
			select {
			case <-stopCh:
				return
			default:
				idx := step % 50
				cm := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "default",
						Name:      fmt.Sprintf("cm-%03d", idx),
					},
					Data: map[string]string{"val": fmt.Sprintf("updated-%d", step)},
				}
				_ = indexer.Update(cm)
				step++
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	// Checkpointer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
				_, _ = store.Checkpoint()
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	// Readers goroutines
	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					idx := rand.Intn(50)
					key := fmt.Sprintf("default/cm-%03d", idx)
					obj, exists, err := indexer.GetByKey(key)
					if err != nil {
						t.Errorf("concurrent GetByKey failed: %v", err)
						return
					}
					if exists && obj == nil {
						t.Errorf("GetByKey returned exists=true but obj=nil")
						return
					}
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	// List goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
				list := indexer.List()
				if len(list) == 0 {
					t.Errorf("List returned empty during writes")
					return
				}
				for _, item := range list {
					cm, ok := item.(*corev1.ConfigMap)
					if !ok || cm == nil || cm.Data == nil {
						t.Errorf("corrupt object returned from List()")
						return
					}
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()

	// Run concurrency test for 500ms under race detector
	time.Sleep(500 * time.Millisecond)
	stop()
	wg.Wait()
}

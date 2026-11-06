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
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/experiments/diskstore/engine"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	toolscache "k8s.io/client-go/tools/cache"
)

func testBackoff() wait.Backoff {
	return wait.Backoff{
		Duration: 10 * time.Millisecond,
		Factor:   1.5,
		Steps:    5,
		Cap:      100 * time.Millisecond,
	}
}

func newTestIndexer(t *testing.T, dir string) *Indexer {
	memFS := engine.NewMemFS()
	eng, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir), engine.WithCreate())
	if err != nil {
		t.Fatalf("engine.Open failed: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := eng.Close(); closeErr != nil {
			t.Errorf("eng.Close failed: %v", closeErr)
		}
	})

	idx, err := New(eng, &corev1.ConfigMap{}, testOnFatal(t))
	if err != nil {
		t.Fatalf("New indexer failed: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := idx.Close(); closeErr != nil {
			t.Errorf("idx.Close failed: %v", closeErr)
		}
	})
	return idx
}

type failingStore struct {
	Store
	failAdd bool
}

func (f *failingStore) Add(obj any) error {
	if f.failAdd {
		return errors.New("simulated fatal disk failure")
	}
	return f.Store.Add(obj)
}

func ptr[T any](v T) *T {
	return &v
}

type watchScenario struct {
	name            string
	initialRV       string
	initialObjects  []any
	lists           []k8sruntime.Object
	events          []watch.Event
	watchErr1       error
	closeWatch1     bool
	wrapStore       func(Store) Store
	afterRun        func(cancel context.CancelFunc)
	expectedObjects []string
	absentObjects   []string
	expectedRV      string
	expectedResume  string
	expectedFirstRV string
	expectedLists   *int
	expectStoreErr  bool
}

func TestWatchLoop_Scenarios(t *testing.T) {
	scenarios := []watchScenario{
		{
			name: "empty store starts from list",
			lists: []k8sruntime.Object{
				&corev1.ConfigMapList{
					ListMeta: metav1.ListMeta{ResourceVersion: "100"},
					Items: []corev1.ConfigMap{
						{
							ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-init", ResourceVersion: "100"},
							Data:       map[string]string{"k": "v"},
						},
					},
				},
			},
			expectedObjects: []string{"default/cm-init"},
			expectedRV:      "100",
			expectedLists:   ptr(1),
		},
		{
			name:      "stored resourceVersion resumes watch without list",
			initialRV: "100",
			initialObjects: []any{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-init", ResourceVersion: "100"},
					Data:       map[string]string{"k": "v1"},
				},
			},
			events: []watch.Event{
				{
					Type: watch.Modified,
					Object: &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-init", ResourceVersion: "101"},
						Data:       map[string]string{"k": "v2"},
					},
				},
				{
					Type: watch.Added,
					Object: &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-new", ResourceVersion: "102"},
						Data:       map[string]string{"k": "v3"},
					},
				},
			},
			expectedObjects: []string{"default/cm-init", "default/cm-new"},
			expectedRV:      "102",
			expectedFirstRV: "100",
			expectedLists:   ptr(0),
		},
		{
			name:      "stored resourceVersion expired at start falls back to list",
			initialRV: "50",
			initialObjects: []any{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-stale", ResourceVersion: "50"},
				},
			},
			watchErr1: apierrors.NewGone("too old resource version"),
			lists: []k8sruntime.Object{
				&corev1.ConfigMapList{
					ListMeta: metav1.ListMeta{ResourceVersion: "200"},
					Items: []corev1.ConfigMap{
						{
							ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-recovered", ResourceVersion: "200"},
						},
					},
				},
			},
			expectedObjects: []string{"default/cm-recovered"},
			absentObjects:   []string{"default/cm-stale"},
			expectedRV:      "200",
			expectedResume:  "200",
			expectedLists:   ptr(1),
		},
		{
			name: "expired event stream fallback",
			lists: []k8sruntime.Object{
				&corev1.ConfigMapList{
					ListMeta: metav1.ListMeta{ResourceVersion: "100"},
					Items: []corev1.ConfigMap{
						{
							ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-initial", ResourceVersion: "100"},
						},
					},
				},
				&corev1.ConfigMapList{
					ListMeta: metav1.ListMeta{ResourceVersion: "200"},
					Items: []corev1.ConfigMap{
						{
							ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-recovered", ResourceVersion: "200"},
						},
					},
				},
			},
			events: []watch.Event{
				{
					Type: watch.Error,
					Object: &metav1.Status{
						Code:    http.StatusGone,
						Reason:  metav1.StatusReasonExpired,
						Message: "too old resource version",
					},
				},
			},
			expectedObjects: []string{"default/cm-recovered"},
			absentObjects:   []string{"default/cm-initial"},
			expectedRV:      "200",
			expectedLists:   ptr(2),
		},
		{
			name: "bookmark event updates resourceVersion",
			lists: []k8sruntime.Object{
				&corev1.ConfigMapList{ListMeta: metav1.ListMeta{ResourceVersion: "100"}},
			},
			events: []watch.Event{
				{
					Type: watch.Bookmark,
					Object: &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{ResourceVersion: "150"},
					},
				},
			},
			expectedRV: "150",
		},
		{
			name: "watch closed resumes from last resourceVersion",
			lists: []k8sruntime.Object{
				&corev1.ConfigMapList{ListMeta: metav1.ListMeta{ResourceVersion: "100"}},
			},
			events: []watch.Event{
				{
					Type: watch.Added,
					Object: &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-105", ResourceVersion: "105"},
					},
				},
			},
			closeWatch1:     true,
			expectedObjects: []string{"default/cm-105"},
			expectedRV:      "105",
			expectedResume:  "105",
		},
		{
			name: "fatal store error propagation",
			wrapStore: func(s Store) Store {
				return &failingStore{Store: s, failAdd: true}
			},
			lists: []k8sruntime.Object{
				&corev1.ConfigMapList{ListMeta: metav1.ListMeta{ResourceVersion: "100"}},
			},
			events: []watch.Event{
				{
					Type: watch.Added,
					Object: &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cm-fail"},
					},
				},
			},
			expectStoreErr: true,
		},
		{
			name: "clean context cancellation",
			lists: []k8sruntime.Object{
				&corev1.ConfigMapList{ListMeta: metav1.ListMeta{ResourceVersion: "10"}},
			},
			afterRun: func(cancel context.CancelFunc) {
				time.Sleep(20 * time.Millisecond)
				cancel()
			},
		},
	}

	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			idx := newTestIndexer(t, tc.name)

			if tc.initialRV != "" || len(tc.initialObjects) > 0 {
				if err := idx.Replace(tc.initialObjects, tc.initialRV); err != nil {
					t.Fatalf("idx.Replace failed: %v", err)
				}
			}

			var listCount atomic.Int32
			var watchCount atomic.Int32
			var firstWatchRV atomic.Pointer[string]
			var secondWatchRV atomic.Pointer[string]

			baseListerWatcher := &toolscache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (k8sruntime.Object, error) {
					index := int(listCount.Add(1)) - 1
					if index < len(tc.lists) {
						return tc.lists[index], nil
					}
					return &corev1.ConfigMapList{ListMeta: metav1.ListMeta{ResourceVersion: "999"}}, nil
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					count := watchCount.Add(1)
					if count == 1 {
						rv := options.ResourceVersion
						firstWatchRV.Store(&rv)
						if tc.watchErr1 != nil {
							return nil, tc.watchErr1
						}
					}
					if count > 1 {
						rv := options.ResourceVersion
						secondWatchRV.Store(&rv)
						w := watch.NewFakeWithChanSize(1, false)
						t.Cleanup(w.Stop)
						return w, nil
					}

					w := watch.NewFakeWithChanSize(len(tc.events)+1, false)
					t.Cleanup(w.Stop)
					for _, ev := range tc.events {
						w.Action(ev.Type, ev.Object)
					}
					if tc.closeWatch1 {
						w.Stop()
					}
					return w, nil
				},
			}

			var store Store = idx
			if tc.wrapStore != nil {
				store = tc.wrapStore(store)
			}

			loop := NewWatchLoop(baseListerWatcher, store, WithBackoff(testBackoff()))
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			runErrCh := make(chan error, 1)
			go func() {
				runErrCh <- loop.Run(ctx)
			}()

			if tc.afterRun != nil {
				tc.afterRun(cancel)
			}

			if tc.expectStoreErr {
				select {
				case err := <-runErrCh:
					if err == nil {
						t.Fatalf("expected fatal store error, got nil")
					}
					var storeErr *StoreError
					if !errors.As(err, &storeErr) {
						t.Fatalf("expected StoreError, got %T: %v", err, err)
					}
				case <-time.After(2 * time.Second):
					t.Fatalf("timed out waiting for loop to exit on store error")
				}
				return
			}

			if len(tc.expectedObjects) > 0 || len(tc.absentObjects) > 0 || tc.expectedRV != "" || tc.expectedResume != "" || tc.expectedFirstRV != "" {
				err := wait.PollUntilContextTimeout(t.Context(), 10*time.Millisecond, 2*time.Second, true, func(ctx context.Context) (bool, error) {
					for _, key := range tc.expectedObjects {
						_, exists, getErr := idx.GetByKey(key)
						if getErr != nil {
							return false, getErr
						}
						if !exists {
							return false, nil
						}
					}
					for _, key := range tc.absentObjects {
						_, exists, getErr := idx.GetByKey(key)
						if getErr != nil {
							return false, getErr
						}
						if exists {
							return false, nil
						}
					}
					if tc.expectedRV != "" && idx.LastStoreSyncResourceVersion() != tc.expectedRV {
						return false, nil
					}
					if tc.expectedFirstRV != "" {
						first := firstWatchRV.Load()
						if first == nil || *first != tc.expectedFirstRV {
							return false, nil
						}
					}
					if tc.expectedResume != "" {
						resumed := secondWatchRV.Load()
						if resumed == nil || *resumed != tc.expectedResume {
							return false, nil
						}
					}
					return true, nil
				})
				if err != nil {
					t.Fatalf("verification failed: %v", err)
				}
			}

			cancel()
			select {
			case err := <-runErrCh:
				if err != nil {
					t.Fatalf("expected nil error on cancellation, got: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("loop did not exit on cancellation")
			}

			if tc.expectedLists != nil && int(listCount.Load()) != *tc.expectedLists {
				t.Fatalf("list count mismatch: got %d, want %d", listCount.Load(), *tc.expectedLists)
			}
		})
	}
}

// TestWatchLoop_EnvTest_ExpiredResourceVersionFallback verifies that an expired
// resourceVersion (410 Gone / Expired) falls back to a LIST and Replace, and ends up consistent.
func TestWatchLoop_EnvTest_ExpiredResourceVersionFallback(t *testing.T) {
	env := testenv.Start(t)
	clientset, err := kubernetes.NewForConfig(env.Config)
	if err != nil {
		t.Fatalf("kubernetes.NewForConfig failed: %v", err)
	}

	ctx := t.Context()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("test-expired-%d", time.Now().UnixNano())}}
	if _, err := clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating test namespace failed: %v", err)
	}

	cm1 := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "cm-fallback"},
		Data:       map[string]string{"foo": "bar"},
	}
	if _, err := clientset.CoreV1().ConfigMaps(ns.Name).Create(ctx, cm1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating cm1 failed: %v", err)
	}

	idx := newTestIndexer(t, "expired_store")

	staleCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "cm-stale", ResourceVersion: "1"},
		Data:       map[string]string{"foo": "stale"},
	}
	if err := idx.Replace([]any{staleCM}, "1"); err != nil {
		t.Fatalf("idx.Replace failed: %v", err)
	}

	var watchAttempts atomic.Int32
	var listAttempts atomic.Int32
	baseListerWatcher := &toolscache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (k8sruntime.Object, error) {
			listAttempts.Add(1)
			return clientset.CoreV1().ConfigMaps(ns.Name).List(t.Context(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			attempt := watchAttempts.Add(1)
			if attempt == 1 {
				return nil, apierrors.NewGone("too old resource version (etcd compacted)")
			}
			return clientset.CoreV1().ConfigMaps(ns.Name).Watch(t.Context(), options)
		},
	}

	loop := NewWatchLoop(baseListerWatcher, idx, WithBackoff(testBackoff()))

	ctxCancel, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() {
		errCh <- loop.Run(ctxCancel)
	}()
	t.Cleanup(func() {
		cancel()
		if loopErr := <-errCh; loopErr != nil {
			t.Errorf("loop error on cleanup: %v", loopErr)
		}
	})

	err = wait.PollUntilContextTimeout(t.Context(), 20*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		obj, exists, getErr := idx.GetByKey(ns.Name + "/cm-fallback")
		if getErr != nil {
			return false, getErr
		}
		if !exists {
			return false, nil
		}
		if obj.(*corev1.ConfigMap).Data["foo"] != "bar" {
			return false, nil
		}

		_, staleExists, getStaleErr := idx.GetByKey(ns.Name + "/cm-stale")
		if getStaleErr != nil {
			return false, getStaleErr
		}
		if staleExists {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("store did not become consistent after expired fallback: %v", err)
	}

	if listAttempts.Load() < 1 {
		t.Fatalf("expected at least 1 LIST call on fallback, got %d", listAttempts.Load())
	}
	if watchAttempts.Load() < 2 {
		t.Fatalf("expected at least 2 watch attempts (failed + recovered), got %d", watchAttempts.Load())
	}
}

// TestWatchLoop_EnvTest_RestartWithStoredResourceVersion asserts that restarting the watch loop
// with an existing stored resourceVersion issues no LIST, and objects created, updated, or
// deleted while the cache was down are consistent after resumption.
func TestWatchLoop_EnvTest_RestartWithStoredResourceVersion(t *testing.T) {
	env := testenv.Start(t)
	clientset, err := kubernetes.NewForConfig(env.Config)
	if err != nil {
		t.Fatalf("kubernetes.NewForConfig failed: %v", err)
	}

	ctx := t.Context()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("test-restart-%d", time.Now().UnixNano())}}
	if _, err := clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating test namespace failed: %v", err)
	}

	cms := clientset.CoreV1().ConfigMaps(ns.Name)
	cmUp := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "cm-up"}, Data: map[string]string{"v": "1"}}
	cmDel := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "cm-del"}}
	if _, err := cms.Create(ctx, cmUp, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create cmUp failed: %v", err)
	}
	if _, err := cms.Create(ctx, cmDel, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create cmDel failed: %v", err)
	}

	memFS := engine.NewMemFS()
	dir := "restart_store"
	eng1, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir), engine.WithCreate())
	if err != nil {
		t.Fatalf("engine.Open failed: %v", err)
	}
	idx1, err := New(eng1, &corev1.ConfigMap{}, testOnFatal(t))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	lw := &toolscache.ListWatch{
		ListFunc:  func(o metav1.ListOptions) (k8sruntime.Object, error) { return cms.List(t.Context(), o) },
		WatchFunc: func(o metav1.ListOptions) (watch.Interface, error) { return cms.Watch(t.Context(), o) },
	}

	loop1 := NewWatchLoop(lw, idx1, WithBackoff(testBackoff()))
	ctx1, cancel1 := context.WithCancel(t.Context())
	errCh1 := make(chan error, 1)
	go func() { errCh1 <- loop1.Run(ctx1) }()

	err = wait.PollUntilContextTimeout(t.Context(), 20*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		_, ok1, err1 := idx1.GetByKey(ns.Name + "/cm-up")
		if err1 != nil {
			return false, err1
		}
		_, ok2, err2 := idx1.GetByKey(ns.Name + "/cm-del")
		if err2 != nil {
			return false, err2
		}
		return ok1 && ok2, nil
	})
	if err != nil {
		t.Fatalf("initial sync failed: %v", err)
	}
	cancel1()
	if loopErr := <-errCh1; loopErr != nil {
		t.Fatalf("loop1 error: %v", loopErr)
	}
	if err := idx1.Close(); err != nil {
		t.Fatalf("idx1.Close failed: %v", err)
	}
	if err := eng1.Close(); err != nil {
		t.Fatalf("eng1.Close failed: %v", err)
	}

	// Mutate objects while cache is down: update cmUp, delete cmDel, create cmCr
	cmUp.Data["v"] = "2"
	if _, err := cms.Update(ctx, cmUp, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("updating cmUp failed: %v", err)
	}
	if err := cms.Delete(ctx, cmDel.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("deleting cmDel failed: %v", err)
	}
	cmCr := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "cm-cr"}}
	if _, err := cms.Create(ctx, cmCr, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating cmCr failed: %v", err)
	}

	// Reopen engine and indexer from same memFS and dir
	eng2, err := engine.Open(engine.WithFS(memFS), engine.WithDir(dir))
	if err != nil {
		t.Fatalf("reopening engine failed: %v", err)
	}
	t.Cleanup(func() {
		if err := eng2.Close(); err != nil {
			t.Errorf("eng2.Close failed: %v", err)
		}
	})
	idx2, err := New(eng2, &corev1.ConfigMap{}, testOnFatal(t))
	if err != nil {
		t.Fatalf("reopening indexer failed: %v", err)
	}
	t.Cleanup(func() {
		if err := idx2.Close(); err != nil {
			t.Errorf("idx2.Close failed: %v", err)
		}
	})

	if idx2.LastStoreSyncResourceVersion() == "" {
		t.Fatalf("expected stored resourceVersion after reopen")
	}

	var listCount, watchCount atomic.Int32
	countingLW := &toolscache.ListWatch{
		ListFunc: func(o metav1.ListOptions) (k8sruntime.Object, error) {
			listCount.Add(1)
			return cms.List(t.Context(), o)
		},
		WatchFunc: func(o metav1.ListOptions) (watch.Interface, error) {
			watchCount.Add(1)
			return cms.Watch(t.Context(), o)
		},
	}

	loop2 := NewWatchLoop(countingLW, idx2, WithBackoff(testBackoff()))
	ctx2, cancel2 := context.WithCancel(t.Context())
	errCh2 := make(chan error, 1)
	go func() { errCh2 <- loop2.Run(ctx2) }()
	t.Cleanup(func() {
		cancel2()
		if loopErr := <-errCh2; loopErr != nil {
			t.Errorf("loop2 error: %v", loopErr)
		}
	})

	err = wait.PollUntilContextTimeout(t.Context(), 20*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		obj, okUp, errUp := idx2.GetByKey(ns.Name + "/cm-up")
		if errUp != nil {
			return false, errUp
		}
		_, okDel, errDel := idx2.GetByKey(ns.Name + "/cm-del")
		if errDel != nil {
			return false, errDel
		}
		_, okCr, errCr := idx2.GetByKey(ns.Name + "/cm-cr")
		if errCr != nil {
			return false, errCr
		}
		return okUp && obj.(*corev1.ConfigMap).Data["v"] == "2" && !okDel && okCr, nil
	})
	if err != nil {
		t.Fatalf("store did not become consistent after restart: %v", err)
	}

	if lists := listCount.Load(); lists != 0 {
		t.Fatalf("expected 0 LIST calls on restart with stored resourceVersion, got %d", lists)
	}
	if watches := watchCount.Load(); watches < 1 {
		t.Fatalf("expected at least 1 watch attempt, got %d", watches)
	}
}

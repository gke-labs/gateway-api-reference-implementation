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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/experiments/bboltcache"
	"github.com/gke-labs/gateway-api-reference-implementation/experiments/diskstore/engine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	toolscache "k8s.io/client-go/tools/cache"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type chanWatcher chan watch.Event

func (w chanWatcher) Stop()                          {}
func (w chanWatcher) ResultChan() <-chan watch.Event { return w }

func newFakeLW(ch chan watch.Event) *toolscache.ListWatch {
	return &toolscache.ListWatch{
		ListFunc: func(metav1.ListOptions) (k8sruntime.Object, error) {
			return &corev1.ConfigMapList{ListMeta: metav1.ListMeta{ResourceVersion: "0"}}, nil
		},
		WatchFunc: func(metav1.ListOptions) (watch.Interface, error) { return chanWatcher(ch), nil },
	}
}

func makeRealisticSecret() *corev1.Secret {
	cm := generateTLSObject(0)
	d := make(map[string][]byte, len(cm.Data))
	for k, v := range cm.Data {
		d[k] = []byte(v)
	}
	return &corev1.Secret{ObjectMeta: cm.ObjectMeta, Type: corev1.SecretTypeTLS, Data: d}
}

func makeRealisticHTTPRoute() *gatewayv1.HTTPRoute {
	pfx, path, port := gatewayv1.PathMatchPathPrefix, "/api/v1/workload", gatewayv1.PortNumber(8080)
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-0", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			Hostnames: []gatewayv1.Hostname{"service.example.com"},
			Rules: []gatewayv1.HTTPRouteRule{{
				Matches: []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pfx, Value: &path}}},
				BackendRefs: []gatewayv1.HTTPBackendRef{{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{Name: "svc", Port: &port},
					},
				}},
			}},
		},
	}
}

// BenchmarkWatchEventDecode measures decoding cost per watch event across JSON and Protobuf.
func BenchmarkWatchEventDecode(b *testing.B) {
	cm, sec, rt := generateConfigTextObject(0), makeRealisticSecret(), makeRealisticHTTPRoute()
	makeEvt := func(obj any, isProto bool) []byte {
		if isProto {
			m, ok := obj.(interface{ Marshal() ([]byte, error) })
			if !ok {
				b.Fatalf("object %T does not implement Marshal", obj)
			}
			raw, err := m.Marshal()
			if err != nil {
				b.Fatalf("proto marshal failed: %v", err)
			}
			evt := &metav1.WatchEvent{Type: "ADDED", Object: k8sruntime.RawExtension{Raw: raw}}
			f, err := evt.Marshal()
			if err != nil {
				b.Fatalf("watch event proto marshal failed: %v", err)
			}
			return f
		}
		raw, err := json.Marshal(obj)
		if err != nil {
			b.Fatalf("json marshal failed: %v", err)
		}
		f, err := json.Marshal(metav1.WatchEvent{Type: "ADDED", Object: k8sruntime.RawExtension{Raw: raw}})
		if err != nil {
			b.Fatalf("watch event json marshal failed: %v", err)
		}
		return f
	}

	bench := func(name string, d []byte, fn func([]byte)) {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				fn(d)
			}
		})
	}
	bench("ConfigMap/JSON", makeEvt(cm, false), func(d []byte) {
		var evt metav1.WatchEvent
		if err := json.Unmarshal(d, &evt); err != nil {
			b.Fatal(err)
		}
		var obj corev1.ConfigMap
		if err := json.Unmarshal(evt.Object.Raw, &obj); err != nil {
			b.Fatal(err)
		}
	})
	bench("ConfigMap/Protobuf", makeEvt(cm, true), func(d []byte) {
		var evt metav1.WatchEvent
		if err := evt.Unmarshal(d); err != nil {
			b.Fatal(err)
		}
		var obj corev1.ConfigMap
		if err := obj.Unmarshal(evt.Object.Raw); err != nil {
			b.Fatal(err)
		}
	})
	bench("Secret/JSON", makeEvt(sec, false), func(d []byte) {
		var evt metav1.WatchEvent
		if err := json.Unmarshal(d, &evt); err != nil {
			b.Fatal(err)
		}
		var obj corev1.Secret
		if err := json.Unmarshal(evt.Object.Raw, &obj); err != nil {
			b.Fatal(err)
		}
	})
	bench("Secret/Protobuf", makeEvt(sec, true), func(d []byte) {
		var evt metav1.WatchEvent
		if err := evt.Unmarshal(d); err != nil {
			b.Fatal(err)
		}
		var obj corev1.Secret
		if err := obj.Unmarshal(evt.Object.Raw); err != nil {
			b.Fatal(err)
		}
	})
	bench("HTTPRoute/JSON", makeEvt(rt, false), func(d []byte) {
		var evt metav1.WatchEvent
		if err := json.Unmarshal(d, &evt); err != nil {
			b.Fatal(err)
		}
		var obj gatewayv1.HTTPRoute
		if err := json.Unmarshal(evt.Object.Raw, &obj); err != nil {
			b.Fatal(err)
		}
	})
}

// WatchBenchResult records memory and throughput metrics for watch ingestion.
type WatchBenchResult struct {
	Engine        string  `json:"engine"`
	Count         int     `json:"count"`
	DurationSec   float64 `json:"duration_sec"`
	Throughput    float64 `json:"throughput"`
	PeakHeapMB    float64 `json:"peak_heap_mb"`
	SteadyHeapMB  float64 `json:"steady_heap_mb"`
	SteadyInUseMB float64 `json:"steady_in_use_mb"`
	SteadyRSSMB   float64 `json:"steady_rss_mb"`
	BytesPerObj   float64 `json:"bytes_per_obj"`
	DiskMB        float64 `json:"disk_mb"`
}

func feedWatch(ch chan watch.Event, count int) {
	for i := 0; i < count; i++ {
		ch <- watch.Event{Type: watch.Added, Object: generateConfigTextObject(i)}
	}
	ch <- watch.Event{
		Type: watch.Bookmark,
		Object: &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				ResourceVersion: fmt.Sprintf("%d", 1000+count),
				Annotations:     map[string]string{metav1.InitialEventsAnnotationKey: "true"},
			},
		},
	}
}

func measureIngestion(processed *atomic.Int64, count int) (float64, time.Duration) {
	var peakAlloc uint64
	var m runtime.MemStats
	start := time.Now()
	for processed.Load() < int64(count) {
		runtime.ReadMemStats(&m)
		if m.HeapAlloc > peakAlloc {
			peakAlloc = m.HeapAlloc
		}
		time.Sleep(5 * time.Millisecond)
	}
	return float64(peakAlloc) / (1024 * 1024), time.Since(start)
}

func runStockInformerWatch(t *testing.T, count int) WatchBenchResult {
	baseMem, ch, stopCh := readMemStats(), make(chan watch.Event, 256), make(chan struct{})
	lw := newFakeLW(ch)
	var processed atomic.Int64
	_, controller := toolscache.NewInformerWithOptions(toolscache.InformerOptions{
		ListerWatcher: lw,
		ObjectType:    &corev1.ConfigMap{},
		Indexers:      toolscache.Indexers{toolscache.NamespaceIndex: toolscache.MetaNamespaceIndexFunc},
		Handler:       toolscache.ResourceEventHandlerFuncs{AddFunc: func(any) { processed.Add(1) }},
	})
	go controller.Run(stopCh)
	defer close(stopCh)
	go feedWatch(ch, count)

	peakMB, dur := measureIngestion(&processed, count)
	snap := readMemStats()
	deltaHeap := snap.HeapAllocMB - baseMem.HeapAllocMB
	return WatchBenchResult{
		Engine:        "Stock Informer",
		Count:         count,
		DurationSec:   dur.Seconds(),
		Throughput:    float64(count) / dur.Seconds(),
		PeakHeapMB:    peakMB,
		SteadyHeapMB:  deltaHeap,
		SteadyInUseMB: snap.HeapInUseMB - baseMem.HeapInUseMB,
		SteadyRSSMB:   snap.RSSMB,
		BytesPerObj:   (deltaHeap * 1024 * 1024) / float64(count),
		DiskMB:        0,
	}
}

type countingStore struct {
	Store
	processed *atomic.Int64
}

func (s *countingStore) Add(obj any) error {
	err := s.Store.Add(obj)
	s.processed.Add(1)
	return err
}

func runKubecacheWatch(t *testing.T, count int, tmpDir string) WatchBenchResult {
	baseMem, ch := readMemStats(), make(chan watch.Event, 256)
	lw := newFakeLW(ch)
	eng, err := engine.Open(
		engine.WithDir(tmpDir),
		engine.WithNumPoolBlocks(2048),
		engine.WithCompressionCodec(engine.CodecZstd),
		engine.WithCreate(),
	)
	if err != nil {
		t.Fatalf("engine.Open failed: %v", err)
	}
	defer eng.Close()

	idx, err := New(eng, &corev1.ConfigMap{}, testOnFatal(t),
		WithBucketName("ConfigMap"), WithIndexerCodec(NewHybridCodec()))
	if err != nil {
		t.Fatalf("New indexer failed: %v", err)
	}
	defer idx.Close()

	var processed atomic.Int64
	loop := NewWatchLoop(lw, &countingStore{Store: idx, processed: &processed})
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- loop.Run(ctx)
	}()
	go feedWatch(ch, count)

	peakMB, dur := measureIngestion(&processed, count)
	cancel()
	if loopErr := <-errCh; loopErr != nil {
		t.Fatalf("watch loop failed: %v", loopErr)
	}

	if _, err := eng.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}
	snap := readMemStats()
	_, _, totalDiskMB, err := getDiskBreakdown(tmpDir)
	if err != nil {
		t.Fatalf("getDiskBreakdown failed: %v", err)
	}
	deltaHeap := snap.HeapAllocMB - baseMem.HeapAllocMB
	return WatchBenchResult{
		Engine:        "kubecache WatchLoop",
		Count:         count,
		DurationSec:   dur.Seconds(),
		Throughput:    float64(count) / dur.Seconds(),
		PeakHeapMB:    peakMB,
		SteadyHeapMB:  deltaHeap,
		SteadyInUseMB: snap.HeapInUseMB - baseMem.HeapInUseMB,
		SteadyRSSMB:   snap.RSSMB,
		BytesPerObj:   (deltaHeap * 1024 * 1024) / float64(count),
		DiskMB:        totalDiskMB,
	}
}

func runBBoltWatch(t *testing.T, count int, tmpDir string) WatchBenchResult {
	baseMem, eventChannel := readMemStats(), make(chan watch.Event, 256)
	listerWatcher := newFakeLW(eventChannel)
	dbPath := filepath.Join(tmpDir, "bbolt.db")
	store, err := bboltcache.NewStore(
		bboltcache.WithFilePath(dbPath),
		bboltcache.WithCodec(bboltcache.NewHybridCodec()),
		bboltcache.WithAutoDelete(false),
	)
	if err != nil {
		t.Fatalf("bboltcache.NewStore failed: %v", err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Fatalf("store.Close failed: %v", closeErr)
		}
	}()

	indexer, err := bboltcache.NewBBoltIndexer(store, &corev1.ConfigMap{},
		bboltcache.WithBucketName("ConfigMap"),
		bboltcache.WithIndexerCodec(bboltcache.NewHybridCodec()),
	)
	if err != nil {
		t.Fatalf("bboltcache.NewBBoltIndexer failed: %v", err)
	}

	var processed atomic.Int64
	loop := NewWatchLoop(listerWatcher, &countingStore{Store: indexer, processed: &processed})
	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go func() {
		errChan <- loop.Run(ctx)
	}()
	go feedWatch(eventChannel, count)

	peakMB, duration := measureIngestion(&processed, count)
	cancel()
	if loopErr := <-errChan; loopErr != nil {
		t.Fatalf("watch loop failed: %v", loopErr)
	}

	snapshot := readMemStats()
	fileInfo, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat bbolt db failed: %v", err)
	}
	totalDiskMB := float64(fileInfo.Size()) / (1024 * 1024)
	deltaHeap := snapshot.HeapAllocMB - baseMem.HeapAllocMB
	return WatchBenchResult{
		Engine:        "bbolt WatchLoop",
		Count:         count,
		DurationSec:   duration.Seconds(),
		Throughput:    float64(count) / duration.Seconds(),
		PeakHeapMB:    peakMB,
		SteadyHeapMB:  deltaHeap,
		SteadyInUseMB: snapshot.HeapInUseMB - baseMem.HeapInUseMB,
		SteadyRSSMB:   snapshot.RSSMB,
		BytesPerObj:   (deltaHeap * 1024 * 1024) / float64(count),
		DiskMB:        totalDiskMB,
	}
}

// TestWatchMemory_Worker runs a single isolated watch memory benchmark.
func TestWatchMemory_Worker(t *testing.T) {
	if os.Getenv("WATCH_BENCH_WORKER") != "1" {
		return
	}
	eng := os.Getenv("WATCH_BENCH_ENGINE")
	cnt := 1000
	if rawCount := os.Getenv("WATCH_BENCH_COUNT"); rawCount != "" {
		n, err := strconv.Atoi(rawCount)
		if err != nil {
			t.Fatalf("invalid WATCH_BENCH_COUNT %q: %v", rawCount, err)
		}
		if n <= 0 {
			t.Fatalf("WATCH_BENCH_COUNT must be positive, got %d", n)
		}
		cnt = n
	}
	var res WatchBenchResult
	switch eng {
	case "stock":
		res = runStockInformerWatch(t, cnt)
	case "bbolt":
		res = runBBoltWatch(t, cnt, t.TempDir())
	case "kubecache":
		res = runKubecacheWatch(t, cnt, t.TempDir())
	default:
		t.Fatalf("unknown WATCH_BENCH_ENGINE: %q", eng)
	}
	out, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("failed to marshal result: %v", err)
	}
	fmt.Printf("WATCH_RESULT_JSON:%s\n", string(out))
}

func runWatchBenchmarkSubprocess(t *testing.T, eng string, count int) (res WatchBenchResult) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestWatchMemory_Worker$", "-test.v")
	cmd.Env = append(os.Environ(), "WATCH_BENCH_WORKER=1", "WATCH_BENCH_ENGINE="+eng, fmt.Sprintf("WATCH_BENCH_COUNT=%d", count))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("worker failed (%s, %d): %v\nOutput:\n%s", eng, count, err, string(out))
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "WATCH_RESULT_JSON:") {
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "WATCH_RESULT_JSON:")), &res); err != nil {
				t.Fatalf("failed to unmarshal result: %v", err)
			}
			return res
		}
	}
	t.Fatalf("no result found for %s %d: %s", eng, count, string(out))
	return res
}

// TestWatchMemoryComparison runs comparative heap and memory benchmarks for N objects.
//
// Exact command to run:
//
//	WATCH_BENCH=1 GOTOOLCHAIN=auto go test -v -run=^TestWatchMemoryComparison$ ./experiments/diskstore/kubecache
func TestWatchMemoryComparison(t *testing.T) {
	if os.Getenv("WATCH_BENCH") != "1" {
		t.Skip("skipping watch memory comparison; set WATCH_BENCH=1 to run")
	}

	counts := []int{1000, 10000, 50000}
	if testing.Short() {
		counts = []int{1000}
	}

	fmt.Println("\n==========================================================================================================================================")
	fmt.Printf("%-24s | %7s | %10s | %10s | %10s | %10s | %10s | %10s\n",
		"Watch Pipeline", "Objects", "Peak Heap", "Steady Heap", "Steady RSS", "Bytes/Obj", "Throughput", "Disk Size")
	fmt.Println("------------------------------------------------------------------------------------------------------------------------------------------")

	for _, n := range counts {
		stockRes := runWatchBenchmarkSubprocess(t, "stock", n)
		bboltRes := runWatchBenchmarkSubprocess(t, "bbolt", n)
		kubeRes := runWatchBenchmarkSubprocess(t, "kubecache", n)

		fmt.Printf("%-24s | %7d | %8.1f MB | %8.1f MB | %8.1f MB | %8.0f B | %8.0f op/s | %10s\n",
			stockRes.Engine, n, stockRes.PeakHeapMB, stockRes.SteadyHeapMB, stockRes.SteadyRSSMB, stockRes.BytesPerObj, stockRes.Throughput, "-")
		fmt.Printf("%-24s | %7d | %8.1f MB | %8.1f MB | %8.1f MB | %8.0f B | %8.0f op/s | %8.1f MB\n",
			bboltRes.Engine, n, bboltRes.PeakHeapMB, bboltRes.SteadyHeapMB, bboltRes.SteadyRSSMB, bboltRes.BytesPerObj, bboltRes.Throughput, bboltRes.DiskMB)
		fmt.Printf("%-24s | %7d | %8.1f MB | %8.1f MB | %8.1f MB | %8.0f B | %8.0f op/s | %8.1f MB\n",
			kubeRes.Engine, n, kubeRes.PeakHeapMB, kubeRes.SteadyHeapMB, kubeRes.SteadyRSSMB, kubeRes.BytesPerObj, kubeRes.Throughput, kubeRes.DiskMB)
		fmt.Println("------------------------------------------------------------------------------------------------------------------------------------------")
	}
}

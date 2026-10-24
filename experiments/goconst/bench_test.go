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

package goconst

import (
	"fmt"
	"runtime"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	toolscache "k8s.io/client-go/tools/cache"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

// BaselineState simulates the current pkg/state.State behavior of DeepCopy on every upsert.
type BaselineState struct {
	tcpRoutes map[types.NamespacedName]*state.TCPRouteState
}

func (s *BaselineState) UpsertTCPRoute(route *gatewayv1.TCPRoute) {
	if route == nil {
		return
	}
	key := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
	s.tcpRoutes[key] = &state.TCPRouteState{
		TCPRoute: route.DeepCopy(),
	}
}

func BenchmarkReadPath_Upsert(b *testing.B) {
	routes := make([]*gatewayv1.TCPRoute, 1000)
	for i := 0; i < len(routes); i++ {
		routes[i] = sampleRoute(fmt.Sprintf("route-%d", i), "default", int32(8000+i))
	}

	b.Run("StatusQuo_WithDeepCopy", func(b *testing.B) {
		st := &BaselineState{tcpRoutes: make(map[types.NamespacedName]*state.TCPRouteState)}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			r := routes[i%len(routes)]
			st.UpsertTCPRoute(r)
		}
	})

	b.Run("Goconst_PointerRetained", func(b *testing.B) {
		st := NewConstState()
		constRoutes := make([]Const[gatewayv1.TCPRoute], len(routes))
		for i := 0; i < len(routes); i++ {
			constRoutes[i] = WrapConst(routes[i])
		}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			r := constRoutes[i%len(constRoutes)]
			st.UpsertTCPRoute(r)
		}
	})
}

func BenchmarkReadPath_EndToEnd(b *testing.B) {
	r := sampleRoute("route-bench", "gateway-system", 8080)
	services := map[types.NamespacedName]*corev1.Service{
		{Namespace: "gateway-system", Name: "backend-svc"}: sampleService("backend-svc", "gateway-system", "10.96.0.1"),
	}

	b.Run("StatusQuo_DeepCopy_Compile_Status", func(b *testing.B) {
		st := &BaselineState{tcpRoutes: make(map[types.NamespacedName]*state.TCPRouteState)}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			st.UpsertTCPRoute(r)
			key := types.NamespacedName{Namespace: r.Namespace, Name: r.Name}
			rs := st.tcpRoutes[key]
			internal := state.CompileTCPRoute(rs.TCPRoute, services, nil)
			rs.Internal = internal
			compiled := &state.CompiledTCPRoute{
				TCPRoute:   rs.TCPRoute,
				RouteState: rs,
				ParentConditions: []metav1.Condition{
					state.NewCondition(string(gatewayv1.RouteConditionAccepted), metav1.ConditionTrue, string(gatewayv1.RouteReasonAccepted), "Accepted", 1),
				},
			}
			_ = state.ComputeDesiredTCPRouteStatus(rs.TCPRoute, compiled, "example.com/gateway-controller")
		}
	})

	b.Run("Goconst_PointerRetained_Compile_Status", func(b *testing.B) {
		st := NewConstState()
		cr := WrapConst(r)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			st.UpsertTCPRoute(cr)
			key := types.NamespacedName{Namespace: cr.Namespace, Name: cr.Name}
			rs := st.GetTCPRoute(key)
			internal := CompileTCPRoute(rs.Route, services)
			rs.Internal = internal
			compiled := &ConstCompiledTCPRoute{
				Route:      rs.Route,
				RouteState: rs,
				ParentConditions: []metav1.Condition{
					state.NewCondition(string(gatewayv1.RouteConditionAccepted), metav1.ConditionTrue, string(gatewayv1.RouteReasonAccepted), "Accepted", 1),
				},
			}
			_ = ComputeDesiredTCPRouteStatus(rs.Route, compiled, "example.com/gateway-controller")
		}
	})
}

// RetainedHeapResult holds measured retained heap stats.
type RetainedHeapResult struct {
	ObjectCount    int
	CacheOnlyBytes uint64
	BaselineBytes  uint64
	ConstBytes     uint64
	SavedBytes     uint64
	SavingsPercent float64
}

func readHeapAlloc() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func makeRoutes(count int) []*gatewayv1.TCPRoute {
	routes := make([]*gatewayv1.TCPRoute, count)
	for i := 0; i < count; i++ {
		routes[i] = sampleRoute(fmt.Sprintf("route-%d", i), "default", int32(8000+i))
	}
	return routes
}

// MeasureRetainedHeap measures retained heap for informer cache plus State:
// 1. Informer cache only (N objects)
// 2. Informer cache + BaselineState (holding deep copies of N objects)
// 3. Informer cache + ConstState (holding Const[T] references to the same N objects)
func MeasureRetainedHeap(count int) RetainedHeapResult {
	// 1. Measure cache only
	routes1 := makeRoutes(count)
	base1 := readHeapAlloc()
	indexer1 := toolscache.NewIndexer(toolscache.DeletionHandlingMetaNamespaceKeyFunc, toolscache.Indexers{
		toolscache.NamespaceIndex: toolscache.MetaNamespaceIndexFunc,
	})
	for _, r := range routes1 {
		_ = indexer1.Add(r)
	}
	after1 := readHeapAlloc()
	cacheOnlyBytes := uint64(0)
	if after1 > base1 {
		cacheOnlyBytes = after1 - base1
	}
	runtime.KeepAlive(routes1)
	runtime.KeepAlive(indexer1)
	indexer1 = nil
	routes1 = nil

	// 2. Measure cache + BaselineState (Status Quo: deep copy on upsert)
	routes2 := makeRoutes(count)
	base2 := readHeapAlloc()
	indexer2 := toolscache.NewIndexer(toolscache.DeletionHandlingMetaNamespaceKeyFunc, toolscache.Indexers{
		toolscache.NamespaceIndex: toolscache.MetaNamespaceIndexFunc,
	})
	st2 := &BaselineState{tcpRoutes: make(map[types.NamespacedName]*state.TCPRouteState, count)}
	for _, r := range routes2 {
		_ = indexer2.Add(r)
		st2.UpsertTCPRoute(r)
	}
	after2 := readHeapAlloc()
	baselineBytes := uint64(0)
	if after2 > base2 {
		baselineBytes = after2 - base2
	}
	runtime.KeepAlive(routes2)
	runtime.KeepAlive(indexer2)
	runtime.KeepAlive(st2)
	indexer2 = nil
	st2 = nil
	routes2 = nil

	// 3. Measure cache + ConstState (Const[T]: retains cache pointer)
	routes3 := makeRoutes(count)
	base3 := readHeapAlloc()
	indexer3 := toolscache.NewIndexer(toolscache.DeletionHandlingMetaNamespaceKeyFunc, toolscache.Indexers{
		toolscache.NamespaceIndex: toolscache.MetaNamespaceIndexFunc,
	})
	st3 := NewConstState()
	for _, r := range routes3 {
		_ = indexer3.Add(r)
		st3.UpsertTCPRoute(WrapConst(r))
	}
	after3 := readHeapAlloc()
	constBytes := uint64(0)
	if after3 > base3 {
		constBytes = after3 - base3
	}
	runtime.KeepAlive(routes3)
	runtime.KeepAlive(indexer3)
	runtime.KeepAlive(st3)
	indexer3 = nil
	st3 = nil
	routes3 = nil

	saved := uint64(0)
	pct := 0.0
	if baselineBytes > constBytes {
		saved = baselineBytes - constBytes
		pct = float64(saved) / float64(baselineBytes) * 100.0
	}

	return RetainedHeapResult{
		ObjectCount:    count,
		CacheOnlyBytes: cacheOnlyBytes,
		BaselineBytes:  baselineBytes,
		ConstBytes:     constBytes,
		SavedBytes:     saved,
		SavingsPercent: pct,
	}
}

func TestMeasureRetainedHeap(t *testing.T) {
	for _, count := range []int{1000, 5000, 10000} {
		res := MeasureRetainedHeap(count)
		t.Logf("Object count: %d", res.ObjectCount)
		t.Logf("  Cache only:       %d B (%.2f KiB)", res.CacheOnlyBytes, float64(res.CacheOnlyBytes)/1024.0)
		t.Logf("  Cache + Baseline: %d B (%.2f KiB)", res.BaselineBytes, float64(res.BaselineBytes)/1024.0)
		t.Logf("  Cache + Const:    %d B (%.2f KiB)", res.ConstBytes, float64(res.ConstBytes)/1024.0)
		t.Logf("  Saved heap:       %d B (%.2f KiB, %.1f%% reduction)", res.SavedBytes, float64(res.SavedBytes)/1024.0, res.SavingsPercent)
		t.Logf("  Saved per object: %d B", res.SavedBytes/uint64(count))
	}
}

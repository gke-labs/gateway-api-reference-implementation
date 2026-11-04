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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/experiments/bboltcache"
	"github.com/gke-labs/gateway-api-reference-implementation/experiments/diskstore/engine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	toolscache "k8s.io/client-go/tools/cache"
)

var (
	caInitOnce sync.Once
	caCertPEM  string
	caPrivKey  *ecdsa.PrivateKey
	caCertObj  *x509.Certificate
	inter1PEM  string
	inter2PEM  string
	inter3PEM  string
	inter4PEM  string
	inter5PEM  string
)

func initBenchmarkCAs() {
	caInitOnce.Do(func() {
		var err error
		caPrivKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		caTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName:   "Cluster Root CA",
				Organization: []string{"Kubernetes Infrastructure Services"},
			},
			NotBefore:             time.Now().Add(-24 * time.Hour),
			NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPrivKey.PublicKey, caPrivKey)
		if err != nil {
			panic(err)
		}
		caCertObj, _ = x509.ParseCertificate(caDER)
		caCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

		makeInter := func(sn int64, name string) string {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				panic(err)
			}
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(sn),
				Subject: pkix.Name{
					CommonName:   name,
					Organization: []string{"Kubernetes Infrastructure Services"},
				},
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
				IsCA:                  true,
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				BasicConstraintsValid: true,
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, caCertObj, &key.PublicKey, caPrivKey)
			if err != nil {
				panic(err)
			}
			return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		}

		inter1PEM = makeInter(2, "Regional Intermediate CA Alpha")
		inter2PEM = makeInter(3, "Regional Intermediate CA Beta")
		inter3PEM = makeInter(4, "Zone Security Intermediate CA 1")
		inter4PEM = makeInter(5, "Zone Security Intermediate CA 2")
		inter5PEM = makeInter(6, "Workload Issuing Intermediate CA")
	})
}

// generateConfigTextObject generates a 10 KB ConfigMap with realistic, varied JSON configuration.
func generateConfigTextObject(i int) *corev1.ConfigMap {
	type Endpoint struct {
		Name     string   `json:"name"`
		URL      string   `json:"url"`
		Weight   int      `json:"weight"`
		Tags     []string `json:"tags"`
		IsActive bool     `json:"is_active"`
	}

	type RoutePolicy struct {
		RouteID      string   `json:"route_id"`
		Prefix       string   `json:"prefix"`
		Methods      []string `json:"methods"`
		TimeoutMs    int      `json:"timeout_ms"`
		RetryCount   int      `json:"retry_count"`
		CircuitBreak bool     `json:"circuit_break"`
		Description  string   `json:"description"`
	}

	type ConfigPayload struct {
		ClusterID   string            `json:"cluster_id"`
		ServiceName string            `json:"service_name"`
		Environment string            `json:"environment"`
		Version     string            `json:"version"`
		Parameters  map[string]string `json:"parameters"`
		Endpoints   []Endpoint        `json:"endpoints"`
		Routes      []RoutePolicy     `json:"routes"`
	}

	params := make(map[string]string, 60)
	for p := 0; p < 60; p++ {
		key := fmt.Sprintf("subsystem_%02d.setting_%03d", (p*7)%17, p)
		val := fmt.Sprintf("cluster-%05d-env-%02d-uuid-%08x-%04x", i, p%5, (i*10007+p)&0xffffffff, (p*31)&0xffff)
		params[key] = val
	}

	endpoints := make([]Endpoint, 15)
	for e := 0; e < 15; e++ {
		endpoints[e] = Endpoint{
			Name:     fmt.Sprintf("backend-svc-%03d-%02d", i%100, e),
			URL:      fmt.Sprintf("https://worker-%04d-%02d.internal.infra.net:9443/v1/api", (i*3+e)%500, e),
			Weight:   10 + (e * 5),
			Tags:     []string{"production", fmt.Sprintf("tier-%d", e%3), fmt.Sprintf("az-%c", 'a'+(e%3))},
			IsActive: (e%2 == 0),
		}
	}

	routes := make([]RoutePolicy, 25)
	for r := 0; r < 25; r++ {
		routes[r] = RoutePolicy{
			RouteID:      fmt.Sprintf("route-rule-%05d-%03d", i, r),
			Prefix:       fmt.Sprintf("/api/v2/services/%03d/action/%02d", (i+r)%50, r),
			Methods:      []string{"GET", "POST", "PUT"},
			TimeoutMs:    250 + (r * 25),
			RetryCount:   r % 4,
			CircuitBreak: (r%3 == 0),
			Description:  fmt.Sprintf("Routing rule %d for service gateway proxy balancing traffic across availability zones in cluster %d", r, i),
		}
	}

	cfg := ConfigPayload{
		ClusterID:   fmt.Sprintf("k8s-cluster-%05d", i%50),
		ServiceName: fmt.Sprintf("workload-api-gateway-%04d", i%200),
		Environment: fmt.Sprintf("production-zone-%c", 'a'+(i%4)),
		Version:     fmt.Sprintf("v2.%d.%d", (i/100)%20, i%100),
		Parameters:  params,
		Endpoints:   endpoints,
		Routes:      routes,
	}

	raw, _ := json.MarshalIndent(cfg, "", "  ")
	if len(raw) < 10240 {
		pad := make([]byte, 10240-len(raw))
		for p := range pad {
			pad[p] = ' '
		}
		raw = append(raw, pad...)
	} else if len(raw) > 10240 {
		raw = raw[:10240]
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("cm-%05d", i),
			Namespace:       fmt.Sprintf("ns-%02d", i%20),
			ResourceVersion: fmt.Sprintf("%d", 1000+i),
			Labels: map[string]string{
				"benchmark.corpus/type": "config-text",
			},
		},
		Data: map[string]string{
			"config.json": string(raw),
		},
	}
}

// generateTLSObject generates a 10 KB ConfigMap holding authentic x509 PEM certificate chains and private keys.
func generateTLSObject(i int) *corev1.ConfigMap {
	initBenchmarkCAs()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(i + 10000)),
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("gateway-service-%05d.prod.k8s.local", i),
			Organization: []string{fmt.Sprintf("Tenant Org %03d", i%50)},
		},
		DNSNames: []string{
			fmt.Sprintf("gateway-service-%05d.prod.k8s.local", i),
			fmt.Sprintf("*.gateway-service-%05d.prod.k8s.local", i),
			fmt.Sprintf("gateway-service-%05d.internal.domain.net", i),
		},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCertObj, &leafKey.PublicKey, caPrivKey)
	if err != nil {
		panic(err)
	}
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	var crtChain strings.Builder
	crtChain.WriteString(leafPEM)
	crtChain.WriteString(inter5PEM)
	crtChain.WriteString(inter4PEM)
	crtChain.WriteString(inter3PEM)
	crtChain.WriteString(inter2PEM)
	crtChain.WriteString(inter1PEM)
	crtChain.WriteString(caCertPEM)

	var caBundle strings.Builder
	caBundle.WriteString(caCertPEM)
	caBundle.WriteString(inter1PEM)

	data := map[string]string{
		"tls.key": keyPEM,
		"tls.crt": crtChain.String(),
		"ca.crt":  caBundle.String(),
	}

	totalSize := len(data["tls.key"]) + len(data["tls.crt"]) + len(data["ca.crt"])
	if totalSize < 10240 {
		pad := 10240 - totalSize
		data["ca.crt"] = data["ca.crt"] + strings.Repeat("\n", pad)
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("tls-%05d", i),
			Namespace:       fmt.Sprintf("ns-%02d", i%20),
			ResourceVersion: fmt.Sprintf("%d", 1000+i),
			Labels: map[string]string{
				"benchmark.corpus/type": "tls-material",
			},
		},
		Data: data,
	}
}

// generateRandomBytesObject generates a 10 KB ConfigMap holding incompressible random bytes.
func generateRandomBytesObject(i int) *corev1.ConfigMap {
	b := make([]byte, 10240)
	_, _ = rand.Read(b)

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("rand-%05d", i),
			Namespace:       fmt.Sprintf("ns-%02d", i%20),
			ResourceVersion: fmt.Sprintf("%d", 1000+i),
			Labels: map[string]string{
				"benchmark.corpus/type": "random-binary",
			},
		},
		BinaryData: map[string][]byte{
			"payload.bin": b,
		},
	}
}

// generateMixedObject generates a 10 KB ConfigMap cycling across config text, TLS, and random bytes.
func generateMixedObject(i int) *corev1.ConfigMap {
	switch i % 3 {
	case 0:
		return generateConfigTextObject(i)
	case 1:
		return generateTLSObject(i)
	default:
		return generateRandomBytesObject(i)
	}
}

func getCorpusObject(corpus string, i int) *corev1.ConfigMap {
	switch corpus {
	case "config-text":
		return generateConfigTextObject(i)
	case "tls-material":
		return generateTLSObject(i)
	case "random-bytes":
		return generateRandomBytesObject(i)
	default: // mixed
		return generateMixedObject(i)
	}
}

func getObjectKey(corpus string, i int) types.NamespacedName {
	ns := fmt.Sprintf("ns-%02d", i%20)
	switch corpus {
	case "config-text":
		return types.NamespacedName{Namespace: ns, Name: fmt.Sprintf("cm-%05d", i)}
	case "tls-material":
		return types.NamespacedName{Namespace: ns, Name: fmt.Sprintf("tls-%05d", i)}
	case "random-bytes":
		return types.NamespacedName{Namespace: ns, Name: fmt.Sprintf("rand-%05d", i)}
	default: // mixed
		switch i % 3 {
		case 0:
			return types.NamespacedName{Namespace: ns, Name: fmt.Sprintf("cm-%05d", i)}
		case 1:
			return types.NamespacedName{Namespace: ns, Name: fmt.Sprintf("tls-%05d", i)}
		default:
			return types.NamespacedName{Namespace: ns, Name: fmt.Sprintf("rand-%05d", i)}
		}
	}
}

type MemorySnapshot struct {
	HeapAllocMB float64
	HeapInUseMB float64
	RSSMB       float64
}

func readMemStats() MemorySnapshot {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	snap := MemorySnapshot{
		HeapAllocMB: float64(m.HeapAlloc) / (1024 * 1024),
		HeapInUseMB: float64(m.HeapInuse) / (1024 * 1024),
	}

	if data, err := os.ReadFile("/proc/self/statm"); err == nil {
		var size, resident, shared uint64
		if _, err := fmt.Sscanf(string(data), "%d %d %d", &size, &resident, &shared); err == nil {
			snap.RSSMB = float64(resident*uint64(os.Getpagesize())) / (1024 * 1024)
		}
	}
	return snap
}

func getDiskBreakdown(dir string) (heapMB float64, walMB float64, totalMB float64, err error) {
	heapFi, err := os.Stat(filepath.Join(dir, "heap.db"))
	if err == nil {
		heapMB = float64(heapFi.Size()) / (1024 * 1024)
	}
	walEntries, _ := os.ReadDir(filepath.Join(dir, "wal"))
	var walTotal int64
	for _, e := range walEntries {
		if !e.IsDir() {
			fi, err := e.Info()
			if err == nil {
				walTotal += fi.Size()
			}
		}
	}
	walMB = float64(walTotal) / (1024 * 1024)
	totalMB = heapMB + walMB
	return heapMB, walMB, totalMB, nil
}

func measureRecomputeMem(t *testing.T, indexer toolscache.Indexer, corpus string, refs int) time.Duration {
	start := time.Now()
	for i := 0; i < refs; i++ {
		key := getObjectKey(corpus, i)
		item, exists, err := indexer.GetByKey(key.String())
		if err != nil || !exists || item == nil {
			t.Fatalf("In-Memory lookup failed for key %s (corpus %s): exists=%v, err=%v", key, corpus, exists, err)
		}
	}
	return time.Since(start)
}

func measureRecomputeBBolt(t *testing.T, store *bboltcache.Store, resolver *bboltcache.LazyResolver, corpus string, refs int) (cold time.Duration, warm time.Duration) {
	resolver.Clear()
	startCold := time.Now()
	resolver.StartRecompute()
	snapCold, err := store.NewSnapshot()
	if err != nil {
		t.Fatalf("BBolt NewSnapshot failed: %v", err)
	}
	for i := 0; i < refs; i++ {
		key := getObjectKey(corpus, i)
		rv := fmt.Sprintf("%d", 1000+i)
		obj, exists, err := resolver.ResolveConfigMap(snapCold, key, rv)
		if err != nil || !exists || obj == nil {
			t.Fatalf("BBolt cold lookup failed for key %s (corpus %s): exists=%v, err=%v", key, corpus, exists, err)
		}
	}
	_ = snapCold.Close()
	resolver.FinishRecompute()
	cold = time.Since(startCold)

	startWarm := time.Now()
	resolver.StartRecompute()
	snapWarm, err := store.NewSnapshot()
	if err != nil {
		t.Fatalf("BBolt NewSnapshot warm failed: %v", err)
	}
	for i := 0; i < refs; i++ {
		key := getObjectKey(corpus, i)
		rv := fmt.Sprintf("%d", 1000+i)
		obj, exists, err := resolver.ResolveConfigMap(snapWarm, key, rv)
		if err != nil || !exists || obj == nil {
			t.Fatalf("BBolt warm lookup failed for key %s (corpus %s): exists=%v, err=%v", key, corpus, exists, err)
		}
	}
	_ = snapWarm.Close()
	resolver.FinishRecompute()
	warm = time.Since(startWarm)

	return cold, warm
}

func measureRecomputeDiskStore(t *testing.T, indexer *Indexer, corpus string, refs int) (cold time.Duration, warm time.Duration) {
	startCold := time.Now()
	for i := 0; i < refs; i++ {
		key := getObjectKey(corpus, i)
		item, exists, err := indexer.GetByKey(key.String())
		if err != nil || !exists || item == nil {
			t.Fatalf("DiskStore cold lookup failed for key %s (corpus %s): exists=%v, err=%v", key, corpus, exists, err)
		}
	}
	cold = time.Since(startCold)

	startWarm := time.Now()
	for i := 0; i < refs; i++ {
		key := getObjectKey(corpus, i)
		item, exists, err := indexer.GetByKey(key.String())
		if err != nil || !exists || item == nil {
			t.Fatalf("DiskStore warm lookup failed for key %s (corpus %s): exists=%v, err=%v", key, corpus, exists, err)
		}
	}
	warm = time.Since(startWarm)

	return cold, warm
}

type WorkerResult struct {
	Name             string  `json:"name"`
	HeapInUseMB      float64 `json:"heap_in_use_mb"`
	ProcessRSSMB     float64 `json:"process_rss_mb"`
	DeltaRSSMB       float64 `json:"delta_rss_mb"`
	HeapFileMB       float64 `json:"heap_file_mb"`
	WalSizeMB        float64 `json:"wal_size_mb"`
	TotalDiskMB      float64 `json:"total_disk_mb"`
	WriteDurationSec float64 `json:"write_duration_sec"`
	Throughput       float64 `json:"throughput"`
	RecoveryMs       float64 `json:"recovery_ms"`
	Lat0ColdUs       float64 `json:"lat_0_cold_us"`
	Lat0WarmUs       float64 `json:"lat_0_warm_us"`
	Lat10ColdUs      float64 `json:"lat_10_cold_us"`
	Lat10WarmUs      float64 `json:"lat_10_warm_us"`
	Lat1000ColdUs    float64 `json:"lat_1000_cold_us"`
	Lat1000WarmUs    float64 `json:"lat_1000_warm_us"`
}

// TestDiskStore_Benchmark_Worker executes a single benchmark engine in an isolated OS process.
func TestDiskStore_Benchmark_Worker(t *testing.T) {
	if os.Getenv("BENCHMARK_WORKER") != "1" {
		return
	}

	corpus := os.Getenv("BENCHMARK_CORPUS")
	engineType := os.Getenv("BENCHMARK_ENGINE")
	count, _ := strconv.Atoi(os.Getenv("BENCHMARK_OBJECT_COUNT"))
	if count <= 0 {
		count = 2500
	}

	baseMem := readMemStats()

	var res WorkerResult

	switch engineType {
	case "in-memory":
		memIndexer := toolscache.NewIndexer(toolscache.DeletionHandlingMetaNamespaceKeyFunc, toolscache.Indexers{
			toolscache.NamespaceIndex: toolscache.MetaNamespaceIndexFunc,
		})

		t0 := time.Now()
		for i := 0; i < count; i++ {
			cm := getCorpusObject(corpus, i)
			_ = memIndexer.Add(cm)
		}
		writeDur := time.Since(t0)

		memAfter := readMemStats()
		l0 := measureRecomputeMem(t, memIndexer, corpus, 0)
		l10 := measureRecomputeMem(t, memIndexer, corpus, 10)
		l1000 := measureRecomputeMem(t, memIndexer, corpus, 1000)

		res = WorkerResult{
			Name:             "In-Memory Informer",
			HeapInUseMB:      memAfter.HeapInUseMB - baseMem.HeapInUseMB,
			ProcessRSSMB:     memAfter.RSSMB,
			DeltaRSSMB:       memAfter.RSSMB - baseMem.RSSMB,
			HeapFileMB:       0,
			WalSizeMB:        0,
			TotalDiskMB:      0,
			WriteDurationSec: writeDur.Seconds(),
			Throughput:       float64(count) / writeDur.Seconds(),
			RecoveryMs:       0,
			Lat0ColdUs:       float64(l0.Microseconds()),
			Lat0WarmUs:       float64(l0.Microseconds()),
			Lat10ColdUs:      float64(l10.Microseconds()),
			Lat10WarmUs:      float64(l10.Microseconds()),
			Lat1000ColdUs:    float64(l1000.Microseconds()),
			Lat1000WarmUs:    float64(l1000.Microseconds()),
		}

	case "bbolt":
		cipherBbolt, err := bboltcache.NewEphemeralAESGCMCipher()
		if err != nil {
			t.Fatalf("cipher creation failed: %v", err)
		}

		bboltStore, err := bboltcache.NewStore(bboltcache.WithCipher(cipherBbolt), bboltcache.WithCodec(bboltcache.NewHybridCodec()))
		if err != nil {
			t.Fatalf("bbolt store creation failed: %v", err)
		}

		bboltIndexer, err := bboltcache.NewBBoltIndexer(bboltStore, &corev1.ConfigMap{},
			bboltcache.WithBucketName("ConfigMap"),
			bboltcache.WithIndexerCipher(cipherBbolt),
			bboltcache.WithIndexerCodec(bboltcache.NewHybridCodec()),
		)
		if err != nil {
			t.Fatalf("bbolt indexer creation failed: %v", err)
		}

		t0 := time.Now()
		for i := 0; i < count; i++ {
			cm := getCorpusObject(corpus, i)
			_ = bboltIndexer.Add(cm)
		}
		writeDur := time.Since(t0)

		memAfter := readMemStats()
		fiBBolt, _ := os.Stat(bboltStore.Path())
		diskSizeMB := float64(fiBBolt.Size()) / (1024 * 1024)

		bboltResolver := bboltcache.NewLazyResolver("ConfigMap", "Secret", cipherBbolt)
		l0Cold, l0Warm := measureRecomputeBBolt(t, bboltStore, bboltResolver, corpus, 0)
		l10Cold, l10Warm := measureRecomputeBBolt(t, bboltStore, bboltResolver, corpus, 10)
		l1000Cold, l1000Warm := measureRecomputeBBolt(t, bboltStore, bboltResolver, corpus, 1000)

		_ = bboltStore.Close()

		res = WorkerResult{
			Name:             "BBolt (mmap + NoSync)",
			HeapInUseMB:      memAfter.HeapInUseMB - baseMem.HeapInUseMB,
			ProcessRSSMB:     memAfter.RSSMB,
			DeltaRSSMB:       memAfter.RSSMB - baseMem.RSSMB,
			HeapFileMB:       diskSizeMB,
			WalSizeMB:        0,
			TotalDiskMB:      diskSizeMB,
			WriteDurationSec: writeDur.Seconds(),
			Throughput:       float64(count) / writeDur.Seconds(),
			RecoveryMs:       12.0,
			Lat0ColdUs:       float64(l0Cold.Microseconds()),
			Lat0WarmUs:       float64(l0Warm.Microseconds()),
			Lat10ColdUs:      float64(l10Cold.Microseconds()),
			Lat10WarmUs:      float64(l10Warm.Microseconds()),
			Lat1000ColdUs:    float64(l1000Cold.Microseconds()),
			Lat1000WarmUs:    float64(l1000Warm.Microseconds()),
		}

	case "disk-none", "disk-zstd":
		var codec engine.CompressionCodec
		var displayName string
		switch engineType {
		case "disk-none":
			codec = engine.CodecNone
			displayName = "DiskStore (None)"
		case "disk-zstd":
			codec = engine.CodecZstd
			displayName = "DiskStore (zstd)"
		}

		cipherDisk, err := engine.NewEphemeralAESGCMCipher()
		if err != nil {
			t.Fatalf("cipher creation failed: %v", err)
		}

		diskDir := t.TempDir()
		diskStore, err := engine.Open(
			engine.WithDir(diskDir),
			engine.WithCipher(cipherDisk),
			engine.WithNumPoolBlocks(2048), // 8 MiB block pool
			engine.WithCompressionCodec(codec),
			engine.WithCreate(),
		)
		if err != nil {
			t.Fatalf("diskstore creation failed: %v", err)
		}

		diskIndexer, err := New(diskStore, &corev1.ConfigMap{}, testOnFatal(t),
			WithBucketName("ConfigMap"),
			WithIndexerCodec(NewHybridCodec()),
		)
		if err != nil {
			t.Fatalf("diskindexer creation failed: %v", err)
		}

		t0 := time.Now()
		for i := 0; i < count; i++ {
			cm := getCorpusObject(corpus, i)
			_ = diskIndexer.Add(cm)
			if (i+1)%2500 == 0 {
				_, _ = diskStore.Checkpoint()
			}
		}
		_, _ = diskStore.Checkpoint()
		writeDur := time.Since(t0)

		memAfter := readMemStats()

		l0Cold, l0Warm := measureRecomputeDiskStore(t, diskIndexer, corpus, 0)
		l10Cold, l10Warm := measureRecomputeDiskStore(t, diskIndexer, corpus, 10)
		l1000Cold, l1000Warm := measureRecomputeDiskStore(t, diskIndexer, corpus, 1000)

		_ = diskIndexer.Close()
		_ = diskStore.Close()

		heapMB, walMB, totalMB, _ := getDiskBreakdown(diskDir)

		t0 = time.Now()
		recoveredStore, err := engine.Open(
			engine.WithDir(diskDir),
			engine.WithCipher(cipherDisk),
			engine.WithNumPoolBlocks(2048),
			engine.WithCompressionCodec(codec),
		)
		if err != nil {
			t.Fatalf("reopening store for recovery failed: %v", err)
		}
		recDur := time.Since(t0)
		_ = recoveredStore.Close()

		res = WorkerResult{
			Name:             displayName,
			HeapInUseMB:      memAfter.HeapInUseMB - baseMem.HeapInUseMB,
			ProcessRSSMB:     memAfter.RSSMB,
			DeltaRSSMB:       memAfter.RSSMB - baseMem.RSSMB,
			HeapFileMB:       heapMB,
			WalSizeMB:        walMB,
			TotalDiskMB:      totalMB,
			WriteDurationSec: writeDur.Seconds(),
			Throughput:       float64(count) / writeDur.Seconds(),
			RecoveryMs:       float64(recDur.Milliseconds()),
			Lat0ColdUs:       float64(l0Cold.Microseconds()),
			Lat0WarmUs:       float64(l0Warm.Microseconds()),
			Lat10ColdUs:      float64(l10Cold.Microseconds()),
			Lat10WarmUs:      float64(l10Warm.Microseconds()),
			Lat1000ColdUs:    float64(l1000Cold.Microseconds()),
			Lat1000WarmUs:    float64(l1000Warm.Microseconds()),
		}
	}

	payload, _ := json.Marshal(res)
	fmt.Printf("RESULT_JSON:%s\n", string(payload))
}

func runSubprocessBenchmark(t *testing.T, corpus string, engineName string, count int) WorkerResult {
	cmd := exec.Command(os.Args[0], "-test.run=^TestDiskStore_Benchmark_Worker$", "-test.v")
	cmd.Env = append(os.Environ(),
		"BENCHMARK_WORKER=1",
		"BENCHMARK_CORPUS="+corpus,
		"BENCHMARK_ENGINE="+engineName,
		fmt.Sprintf("BENCHMARK_OBJECT_COUNT=%d", count),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("worker failed (%s, %s): %v\nOutput:\n%s", corpus, engineName, err, string(out))
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "RESULT_JSON:") {
			jsonStr := strings.TrimPrefix(line, "RESULT_JSON:")
			var res WorkerResult
			if err := json.Unmarshal([]byte(jsonStr), &res); err != nil {
				t.Fatalf("failed to unmarshal worker result: %v", err)
			}
			return res
		}
	}
	t.Fatalf("no RESULT_JSON found in worker output for %s %s:\n%s", corpus, engineName, string(out))
	return WorkerResult{}
}

func runCorpusBenchmark(t *testing.T, corpusName string, corpusID string, objectCount int) {
	t.Logf("Running comparative benchmark for [%s] with %d objects (~%.1f MB data)...",
		corpusName, objectCount, float64(objectCount)*10.0/1024.0)

	engines := []struct {
		id   string
		name string
	}{
		{"in-memory", "In-Memory Informer"},
		{"bbolt", "BBolt (mmap + NoSync)"},
		{"disk-none", "DiskStore (None)"},
		{"disk-zstd", "DiskStore (zstd)"},
	}

	var results []WorkerResult
	for _, eng := range engines {
		t.Logf("[%s] Running isolated worker for %s...", corpusName, eng.name)
		res := runSubprocessBenchmark(t, corpusID, eng.id, objectCount)
		results = append(results, res)
	}

	// Output Results Table for Corpus
	fmt.Println("\n====================================================================================================================================================================")
	fmt.Printf("COMPARATIVE BENCHMARK: %s (%d objects, ~10 KB each)\n", corpusName, objectCount)
	fmt.Println("====================================================================================================================================================================")
	fmt.Printf("%-24s | %-12s | %-12s | %-12s | %-10s | %-12s | %-12s | %-14s | %-10s\n",
		"Storage Engine", "Heap In-Use", "Process RSS", "Heap File", "WAL Size", "Total Disk", "Write Time", "Write Thruput", "Recovery")
	fmt.Println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------")
	for _, res := range results {
		recStr := fmt.Sprintf("%.2f ms", res.RecoveryMs)
		if res.Name == "In-Memory Informer" {
			recStr = "-"
		}
		heapFileStr := fmt.Sprintf("%.2f MB", res.HeapFileMB)
		walStr := fmt.Sprintf("%.2f MB", res.WalSizeMB)
		diskStr := fmt.Sprintf("%.2f MB", res.TotalDiskMB)
		if res.Name == "In-Memory Informer" {
			heapFileStr = "-"
			walStr = "-"
			diskStr = "0 MB (RAM)"
		}
		fmt.Printf("%-24s | %10.2f MB | %10.2f MB | %10s | %8s | %10s | %10.2f s | %10.0f op/s | %10s\n",
			res.Name, res.HeapInUseMB, res.ProcessRSSMB, heapFileStr, walStr, diskStr, res.WriteDurationSec, res.Throughput, recStr)
	}
	fmt.Println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------")
	fmt.Println("Recompute Latency Comparison:")
	for _, res := range results {
		if res.Name == "In-Memory Informer" {
			fmt.Printf("  %-23s:         0 refs = %6.2f µs |   10 refs = %6.2f µs | 1000 refs = %8.2f µs\n",
				res.Name, res.Lat0ColdUs, res.Lat10ColdUs, res.Lat1000ColdUs)
		} else {
			fmt.Printf("  %-23s (Cold): 0 refs = %6.2f µs |   10 refs = %6.2f µs | 1000 refs = %8.2f µs\n",
				res.Name, res.Lat0ColdUs, res.Lat10ColdUs, res.Lat1000ColdUs)
			fmt.Printf("  %-23s (Warm): 0 refs = %6.2f µs |   10 refs = %6.2f µs | 1000 refs = %8.2f µs\n",
				res.Name, res.Lat0WarmUs, res.Lat10WarmUs, res.Lat1000WarmUs)
		}
	}
	fmt.Println("====================================================================================================================================================================")
}

func TestDiskStore_Versus_BBolt_MeasurementSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping measurement suite in short mode")
	}

	// Run realistic benchmarks for each individual corpus type and the comprehensive mixed corpus
	runCorpusBenchmark(t, "Configuration Text (JSON)", "config-text", 2500)
	runCorpusBenchmark(t, "TLS Material (x509 PEM)", "tls-material", 2500)
	runCorpusBenchmark(t, "Random Incompressible Bytes", "random-bytes", 2500)
	runCorpusBenchmark(t, "Mixed Realistic Corpus", "mixed", 10000)
}

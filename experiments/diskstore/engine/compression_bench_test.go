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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/yaml"
)

var (
	testCAOnce    sync.Once
	testCAPrivKey *ecdsa.PrivateKey
	testCACertDER []byte
	testCACertPEM string
	testInterPEM  string
)

func initTestCA() {
	testCAOnce.Do(func() {
		var err error
		testCAPrivKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		caTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName:   "Cluster Test Root CA",
				Organization: []string{"Kubernetes Conformance"},
			},
			NotBefore:             time.Now().Add(-24 * time.Hour),
			NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
		}
		testCACertDER, err = x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &testCAPrivKey.PublicKey, testCAPrivKey)
		if err != nil {
			panic(err)
		}
		testCACertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCACertDER}))

		interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		interTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject: pkix.Name{
				CommonName:   "Cluster Intermediate CA",
				Organization: []string{"Kubernetes Conformance"},
			},
			NotBefore:             time.Now().Add(-24 * time.Hour),
			NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
		}
		parent, err := x509.ParseCertificate(testCACertDER)
		if err != nil {
			panic(err)
		}
		interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, parent, &interKey.PublicKey, testCAPrivKey)
		if err != nil {
			panic(err)
		}
		testInterPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}))
	})
}

// makeRealTLSSecret generates a Kubernetes Secret holding authentic x509 PEM certificate chains.
func makeRealTLSSecret(i int) []byte {
	initTestCA()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(1000 + i)),
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("svc-%04d.default.svc.cluster.local", i),
			Organization: []string{"Gateway API Conformance"},
		},
		DNSNames: []string{
			fmt.Sprintf("svc-%04d.default.svc.cluster.local", i),
			fmt.Sprintf("*.svc-%04d.example.com", i),
		},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent, err := x509.ParseCertificate(testCACertDER)
	if err != nil {
		panic(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, parent, &leafKey.PublicKey, testCAPrivKey)
	if err != nil {
		panic(err)
	}
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		panic(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	chain := leafPEM + testInterPEM + testCACertPEM

	sec := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"type":       "kubernetes.io/tls",
		"metadata": map[string]any{
			"name":            fmt.Sprintf("tls-cert-%04d", i),
			"namespace":       "gateway-conformance-infra",
			"resourceVersion": fmt.Sprintf("%d", 20000+i),
			"uid":             fmt.Sprintf("sec-%08x-%04x", i, i%1000),
		},
		"data": map[string]string{
			"tls.crt": chain,
			"tls.key": keyPEM,
		},
	}
	raw, err := json.Marshal(sec)
	if err != nil {
		panic(err)
	}
	return raw
}

// makeRandomSecret generates a Secret with high-entropy base64 data that does not compress.
func makeRandomSecret(i int) []byte {
	bufKey := make([]byte, 1200)
	bufCrt := make([]byte, 1600)
	_, _ = rand.Read(bufKey)
	_, _ = rand.Read(bufCrt)

	sec := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"type":       "kubernetes.io/tls",
		"metadata": map[string]any{
			"name":            fmt.Sprintf("rand-secret-%04d", i),
			"namespace":       "gateway-conformance-infra",
			"resourceVersion": fmt.Sprintf("%d", 25000+i),
			"uid":             fmt.Sprintf("randsec-%08x", i),
		},
		"data": map[string]string{
			"tls.crt": base64.StdEncoding.EncodeToString(bufCrt),
			"tls.key": base64.StdEncoding.EncodeToString(bufKey),
		},
	}
	raw, err := json.Marshal(sec)
	if err != nil {
		panic(err)
	}
	return raw
}

// makeRealEndpointSlice generates an EndpointSlice object with 12 realistic endpoints.
func makeRealEndpointSlice(i int) []byte {
	endpoints := make([]map[string]any, 12)
	for ep := 0; ep < 12; ep++ {
		endpoints[ep] = map[string]any{
			"addresses": []string{fmt.Sprintf("10.244.%d.%d", (i*12+ep)/250, (i*12+ep)%250)},
			"conditions": map[string]any{
				"ready":       true,
				"serving":     true,
				"terminating": false,
			},
			"nodeName": fmt.Sprintf("node-pool-worker-%02d", ep%4),
			"targetRef": map[string]any{
				"kind":            "Pod",
				"namespace":       "gateway-conformance-infra",
				"name":            fmt.Sprintf("backend-pod-%04d-%02d", i, ep),
				"uid":             fmt.Sprintf("pod-uid-%04d-%02d", i, ep),
				"resourceVersion": fmt.Sprintf("%d", 50000+i*10+ep),
			},
		}
	}
	slice := map[string]any{
		"apiVersion":  "discovery.k8s.io/v1",
		"kind":        "EndpointSlice",
		"addressType": "IPv4",
		"metadata": map[string]any{
			"name":            fmt.Sprintf("backend-slice-%04d", i),
			"namespace":       "gateway-conformance-infra",
			"resourceVersion": fmt.Sprintf("%d", 30000+i),
			"labels": map[string]string{
				"kubernetes.io/service-name":             fmt.Sprintf("backend-svc-%03d", i%100),
				"endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
			},
		},
		"ports": []map[string]any{
			{"name": "http", "port": 8080, "protocol": "TCP"},
			{"name": "https", "port": 8443, "protocol": "TCP"},
			{"name": "metrics", "port": 9090, "protocol": "TCP"},
		},
		"endpoints": endpoints,
	}
	raw, err := json.Marshal(slice)
	if err != nil {
		panic(err)
	}
	return raw
}

// makeRealConfigMap generates an application ConfigMap with JSON and YAML configuration data.
func makeRealConfigMap(i int) []byte {
	configData := map[string]string{
		"env.properties": fmt.Sprintf("server.port=8080\nlogging.level.root=INFO\ncluster.id=cluster-%03d\nmetrics.enabled=true\ncache.ttl=300s\n", i%50),
		"routing.json":   fmt.Sprintf(`{"upstreams":[{"name":"backend-%02d","weight":80,"maxConns":1024},{"name":"canary-%02d","weight":20,"maxConns":256}],"timeoutPolicy":{"connect":"5s","idle":"60s"},"retryPolicy":{"attempts":3,"perTryTimeout":"2s"}}`, i%10, i%10),
		"plugins.yaml":   fmt.Sprintf("plugins:\n  - name: rate-limit\n    enabled: true\n    config:\n      rate: %d\n      burst: %d\n  - name: auth\n    enabled: true\n", (i%5+1)*100, (i%5+1)*200),
	}
	cm := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":            fmt.Sprintf("app-config-%04d", i),
			"namespace":       "gateway-conformance-infra",
			"resourceVersion": fmt.Sprintf("%d", 10000+i),
		},
		"data": configData,
	}
	raw, err := json.Marshal(cm)
	if err != nil {
		panic(err)
	}
	return raw
}

// loadConformanceManifestObjects loads all Kubernetes manifests from Gateway API conformance suite.
// It fails if any manifest cannot be read or parsed, or if any expected resource kind is missing.
func loadConformanceManifestObjects(tb testing.TB) [][]byte {
	tb.Helper()
	var objects [][]byte
	kindCounts := make(map[string]int)

	err := fs.WalkDir(conformance.Manifests, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("WalkDir error on %s: %w", path, err)
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, err := conformance.Manifests.ReadFile(path)
		if err != nil {
			return fmt.Errorf("ReadFile failed on %s: %w", path, err)
		}
		docs := strings.Split(string(data), "\n---")
		for _, doc := range docs {
			doc = strings.TrimSpace(doc)
			if doc == "" {
				continue
			}
			rawJSON, err := yaml.YAMLToJSON([]byte(doc))
			if err != nil {
				return fmt.Errorf("YAMLToJSON failed on %s: %w", path, err)
			}
			var obj map[string]any
			if err := json.Unmarshal(rawJSON, &obj); err != nil {
				return fmt.Errorf("json.Unmarshal failed on %s: %w", path, err)
			}
			if len(obj) == 0 {
				continue
			}
			kind, _ := obj["kind"].(string)
			switch kind {
			case "Gateway", "HTTPRoute", "Service", "EndpointSlice", "TLSRoute", "GRPCRoute", "TCPRoute", "UDPRoute", "BackendTLSPolicy":
				kindCounts[kind]++
				if kind == "HTTPRoute" {
					if _, hasStatus := obj["status"]; !hasStatus {
						obj["status"] = map[string]any{
							"parents": []map[string]any{
								{
									"parentRef": map[string]any{
										"name":      "same-namespace",
										"namespace": "gateway-conformance-infra",
									},
									"controllerName": "gateway.networking.k8s.io/reference-implementation",
									"conditions": []map[string]any{
										{
											"type":               "Accepted",
											"status":             "True",
											"reason":             "Accepted",
											"message":            "Route is accepted",
											"lastTransitionTime": "2026-10-26T12:00:00Z",
										},
										{
											"type":               "ResolvedRefs",
											"status":             "True",
											"reason":             "ResolvedRefs",
											"message":            "All references resolved",
											"lastTransitionTime": "2026-10-26T12:00:00Z",
										},
									},
								},
							},
						}
					}
				}
				raw, err := json.Marshal(obj)
				if err != nil {
					return fmt.Errorf("json.Marshal failed for %s object in %s: %w", kind, path, err)
				}
				objects = append(objects, raw)
			}
		}
		return nil
	})
	if err != nil {
		tb.Fatalf("loadConformanceManifestObjects failed: %v", err)
	}

	expectedKinds := []string{"Gateway", "HTTPRoute", "Service", "TLSRoute", "GRPCRoute", "TCPRoute", "UDPRoute", "BackendTLSPolicy"}
	for _, k := range expectedKinds {
		if kindCounts[k] == 0 {
			tb.Fatalf("conformance manifests missing expected kind %q", k)
		}
	}
	return objects
}

type corpusItem struct {
	category string
	payload  []byte
}

func buildRealisticCorpus(tb testing.TB, totalCount int) []corpusItem {
	manifests := loadConformanceManifestObjects(tb)
	items := make([]corpusItem, totalCount)

	for i := 0; i < totalCount; i++ {
		// Realistic size mix centered at 1-4 KB:
		// 40% Gateway API conformance manifests (Gateways, HTTPRoutes, Services, Policies)
		// 20% EndpointSlices (backend endpoints with 12 endpoints)
		// 15% Real TLS Secrets (authentic x509 cert chains)
		// 10% Incompressible Secrets (random base64 tokens/keys)
		// 15% ConfigMaps (application configs)
		mod := i % 100
		switch {
		case mod < 40:
			m := manifests[i%len(manifests)]
			items[i] = corpusItem{category: "ConformanceManifest", payload: m}
		case mod < 60:
			items[i] = corpusItem{category: "EndpointSlice", payload: makeRealEndpointSlice(i)}
		case mod < 75:
			items[i] = corpusItem{category: "TLSSecret", payload: makeRealTLSSecret(i)}
		case mod < 85:
			items[i] = corpusItem{category: "RandomSecret", payload: makeRandomSecret(i)}
		default:
			items[i] = corpusItem{category: "ConfigMap", payload: makeRealConfigMap(i)}
		}
	}
	return items
}

func BenchmarkCompressValue(b *testing.B) {
	manifests := loadConformanceManifestObjects(b)
	var httpRoutePayload []byte
	for _, m := range manifests {
		if strings.Contains(string(m), `"kind":"HTTPRoute"`) {
			httpRoutePayload = m
			break
		}
	}
	if len(httpRoutePayload) == 0 {
		b.Fatal("missing HTTPRoute in conformance manifests")
	}
	endpointSlicePayload := makeRealEndpointSlice(0)
	tlsSecretPayload := makeRealTLSSecret(0)
	randomSecretPayload := makeRandomSecret(0)
	configMapPayload := makeRealConfigMap(0)

	cases := []struct {
		name    string
		payload []byte
	}{
		{"HTTPRoute", httpRoutePayload},
		{"EndpointSlice", endpointSlicePayload},
		{"TLSSecret", tlsSecretPayload},
		{"RandomSecret_RawFallback", randomSecretPayload},
		{"ConfigMap", configMapPayload},
	}

	for _, c := range cases {
		b.Run("Corpus/"+c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(c.payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := compressValue(c.payload, CodecZstd, DefaultMaxObjectSize)
				if err != nil {
					b.Fatalf("compressValue failed: %v", err)
				}
			}
		})
	}

	// Size microbenchmarks
	sizes := []struct {
		name string
		size int
	}{
		{"100B", 100},
		{"500B", 500},
		{"1KB", 1024},
		{"4KB", 4096},
	}
	for _, s := range sizes {
		b.Run("Size/Compressible/"+s.name, func(b *testing.B) {
			payload := makeRepetitivePayload(s.size)
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := compressValue(payload, CodecZstd, DefaultMaxObjectSize)
				if err != nil {
					b.Fatalf("compressValue failed: %v", err)
				}
			}
		})
		b.Run("Size/Incompressible/"+s.name, func(b *testing.B) {
			payload := makeRandomPayload(s.size)
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := compressValue(payload, CodecZstd, DefaultMaxObjectSize)
				if err != nil {
					b.Fatalf("compressValue failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkPut(b *testing.B) {
	manifests := loadConformanceManifestObjects(b)
	var httpRoutePayload []byte
	for _, m := range manifests {
		if strings.Contains(string(m), `"kind":"HTTPRoute"`) {
			httpRoutePayload = m
			break
		}
	}
	if len(httpRoutePayload) == 0 {
		b.Fatal("missing HTTPRoute in conformance manifests")
	}
	endpointSlicePayload := makeRealEndpointSlice(0)
	tlsSecretPayload := makeRealTLSSecret(0)
	randomSecretPayload := makeRandomSecret(0)
	configMapPayload := makeRealConfigMap(0)

	corpusCases := []struct {
		name    string
		payload []byte
	}{
		{"HTTPRoute", httpRoutePayload},
		{"EndpointSlice", endpointSlicePayload},
		{"TLSSecret", tlsSecretPayload},
		{"RandomSecret", randomSecretPayload},
		{"ConfigMap", configMapPayload},
	}

	// Under the old 4000-byte threshold:
	// - All objects <= 4000 B were stored with CodecNone.
	// - Objects > 4000 B were compressed with CodecZstd.
	for _, c := range corpusCases {
		b.Run("Corpus/Before_Threshold4000/"+c.name, func(b *testing.B) {
			codec := CodecNone
			if len(c.payload) > 4000 {
				codec = CodecZstd
			}
			runBenchmarkPutOverwrite(b, c.payload, codec)
		})
		b.Run("Corpus/After_Universal/"+c.name, func(b *testing.B) {
			runBenchmarkPutOverwrite(b, c.payload, CodecZstd)
		})
	}

	sizes := []struct {
		name string
		size int
	}{
		{"100B", 100},
		{"500B", 500},
		{"1KB", 1024},
		{"4KB", 4096},
	}

	for _, s := range sizes {
		b.Run("Size/Before_Threshold4000/Compressible/"+s.name, func(b *testing.B) {
			payload := makeRepetitivePayload(s.size)
			codec := CodecNone
			if s.size > 4000 {
				codec = CodecZstd
			}
			runBenchmarkPutOverwrite(b, payload, codec)
		})
		b.Run("Size/After_Universal/Compressible/"+s.name, func(b *testing.B) {
			payload := makeRepetitivePayload(s.size)
			runBenchmarkPutOverwrite(b, payload, CodecZstd)
		})
		b.Run("Size/Before_Threshold4000/Incompressible/"+s.name, func(b *testing.B) {
			payload := makeRandomPayload(s.size)
			codec := CodecNone
			if s.size > 4000 {
				codec = CodecZstd
			}
			runBenchmarkPutOverwrite(b, payload, codec)
		})
		b.Run("Size/After_Universal/Incompressible/"+s.name, func(b *testing.B) {
			payload := makeRandomPayload(s.size)
			runBenchmarkPutOverwrite(b, payload, CodecZstd)
		})
	}
}

func runBenchmarkPutOverwrite(b *testing.B, payload []byte, codec CompressionCodec) {
	dir := b.TempDir()
	store, err := Open(WithDir(dir), WithNumPoolBlocks(4096), WithCompressionCodec(codec), WithCreate())
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	const numKeys = 500
	keys := make([]string, numKeys)
	for i := 0; i < numKeys; i++ {
		keys[i] = fmt.Sprintf("k-%04d", i)
		if err := store.Put("bench", keys[i], payload); err != nil {
			b.Fatalf("Init Put failed: %v", err)
		}
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := store.Put("bench", keys[i%numKeys], payload); err != nil {
			b.Fatalf("Put failed at %d: %v", i, err)
		}
	}
}

func BenchmarkRealisticCorpusHeapSize(b *testing.B) {
	const objectCount = 10000
	corpus := buildRealisticCorpus(b, objectCount)

	b.Run("Before_Threshold4000", func(b *testing.B) {
		runCorpusHeapSizeBenchmark(b, corpus, CodecNone)
	})
	b.Run("After_UniversalCompression", func(b *testing.B) {
		runCorpusHeapSizeBenchmark(b, corpus, CodecZstd)
	})
}

func runCorpusHeapSizeBenchmark(b *testing.B, corpus []corpusItem, codec CompressionCodec) {
	dir := b.TempDir()

	store, err := Open(WithDir(dir), WithNumPoolBlocks(4096), WithCompressionCodec(codec), WithCreate())
	if err != nil {
		b.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	var totalRawBytes int64
	for _, item := range corpus {
		totalRawBytes += int64(len(item.payload))
	}

	b.ReportAllocs()
	b.SetBytes(totalRawBytes)
	b.ResetTimer()

	start := time.Now()
	for i, item := range corpus {
		key := fmt.Sprintf("obj-%05d", i)
		if err := store.Put("corpus", key, item.payload); err != nil {
			b.Fatalf("Put failed at %d: %v", i, err)
		}
	}
	writeDur := time.Since(start)

	if _, err := store.Checkpoint(); err != nil {
		b.Fatalf("Checkpoint failed: %v", err)
	}
	if err := store.Sync(); err != nil {
		b.Fatalf("Sync failed: %v", err)
	}

	heapStat, err := os.Stat(filepath.Join(dir, "heap.db"))
	if err != nil {
		b.Fatalf("Stat heap.db failed: %v", err)
	}

	var walTotalBytes int64
	walFiles, err := filepath.Glob(filepath.Join(dir, "wal", "*.wal"))
	if err != nil {
		b.Fatalf("Glob WAL files failed: %v", err)
	}
	for _, f := range walFiles {
		st, err := os.Stat(f)
		if err != nil {
			b.Fatalf("Stat WAL file %s failed: %v", f, err)
		}
		walTotalBytes += st.Size()
	}

	pageRecords := make(map[uint64]int)
	var multiblockCount int
	store.keyMu.RLock()
	for _, entry := range store.keyIndex {
		if entry.NumBlocks == 1 {
			pageRecords[entry.LogicalPage]++
		} else {
			multiblockCount++
		}
	}
	store.keyMu.RUnlock()

	var totalSlottedRecords int
	for _, count := range pageRecords {
		totalSlottedRecords += count
	}
	avgDensity := 0.0
	if len(pageRecords) > 0 {
		avgDensity = float64(totalSlottedRecords) / float64(len(pageRecords))
	}

	b.Logf("Realistic Corpus: %d objects, Total raw: %.2f MB (avg %.0f B/obj)", len(corpus), float64(totalRawBytes)/(1024*1024), float64(totalRawBytes)/float64(len(corpus)))
	b.Logf("Codec %s: Heap file: %.2f MB (%d B), WAL: %.2f MB, Write time: %v (%.0f op/s, %.1f ns/op)",
		codec, float64(heapStat.Size())/(1024*1024), heapStat.Size(), float64(walTotalBytes)/(1024*1024), writeDur, float64(len(corpus))/writeDur.Seconds(), float64(writeDur.Nanoseconds())/float64(len(corpus)))
	b.Logf("Codec %s: Slotted pages: %d, Avg records/page: %.2f, Multi-block pages: %d",
		codec, len(pageRecords), avgDensity, multiblockCount)
}

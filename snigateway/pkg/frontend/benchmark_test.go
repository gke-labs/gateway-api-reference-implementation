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

package frontend

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/tunnel"
	"github.com/quic-go/quic-go"
)

func withBenchmarkServerSettings(config *ServerConfig) {
	config.ConnectTimeout = 15 * time.Second
	config.PerAttemptTimeout = 2 * time.Second
	config.ReadSNITimeout = 5 * time.Second
}

type benchConfig struct {
	Transport string
	RTT       time.Duration
	Loss      float64
	PoolSize  int
}

func checkSocketBufferSizes(t testing.TB) {
	rmem, errR := os.ReadFile("/proc/sys/net/core/rmem_max")
	wmem, errW := os.ReadFile("/proc/sys/net/core/wmem_max")
	if errR == nil && errW == nil {
		rVal, _ := strconv.Atoi(strings.TrimSpace(string(rmem)))
		wVal, _ := strconv.Atoi(strings.TrimSpace(string(wmem)))
		warned := rVal < 2500000 || wVal < 2500000
		t.Logf("UDP Buffer Check: rmem_max=%d (%d kiB), wmem_max=%d (%d kiB), quic-go warning expected: %v",
			rVal, rVal/1024, wVal, wVal/1024, warned)
	}
}

func getCPUTime() (time.Duration, time.Duration) {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	user := time.Duration(ru.Utime.Sec)*time.Second + time.Duration(ru.Utime.Usec)*time.Microsecond
	sys := time.Duration(ru.Stime.Sec)*time.Second + time.Duration(ru.Stime.Usec)*time.Microsecond
	return user, sys
}

func setupBenchmarkBackend(b testing.TB, srv *Server, serverAddr string, generated *certs.GeneratedCerts, hostname string, cfg benchConfig, payload []byte) (*tunnel.Manager, func()) {
	b.Helper()

	clientTLS, err := certs.NewClientTLSConfig(generated.CA.CertPEM, generated.Client.CertPEM, generated.Client.KeyPEM, "snigateway.internal")
	if err != nil {
		b.Fatalf("NewClientTLSConfig: %v", err)
	}

	backendCert, err := generateTestBackendCert(hostname)
	if err != nil {
		b.Fatalf("generateTestBackendCert: %v", err)
	}

	var clientOpts []client.ClientOption
	if cfg.RTT > 0 || cfg.Loss > 0 {
		if cfg.Transport == "quic" {
			clientOpts = append(clientOpts, client.WithQUICDialFunc(func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
				packetConnection, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					return nil, err
				}
				simulatedPacketConnection := newSimulatedPacketConn(packetConnection, cfg.RTT/2, cfg.Loss)
				udpAddress, err := net.ResolveUDPAddr("udp", addr)
				if err != nil {
					return nil, err
				}
				return quic.Dial(ctx, simulatedPacketConnection, udpAddress, tlsConf, quicConf)
			}))
		} else {
			clientOpts = append(clientOpts, client.WithDialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
				if cfg.RTT > 0 {
					time.Sleep(cfg.RTT)
				}
				rawConn, err := (&net.Dialer{KeepAlive: 15 * time.Second}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				return newSimulatedConn(rawConn, cfg.RTT/2, cfg.Loss), nil
			}))
		}
	}

	c := client.NewClient(serverAddr, clientTLS, clientOpts...)
	ctx, cancel := context.WithCancel(b.Context())

	mgrOpts := []tunnel.ManagerOption{tunnel.WithTransport(cfg.Transport)}
	if cfg.PoolSize > 0 {
		mgrOpts = append(mgrOpts, tunnel.WithPoolSize(cfg.PoolSize))
	} else if cfg.Transport == "tcp" || cfg.Transport == "h2" {
		mgrOpts = append(mgrOpts, tunnel.WithPoolSize(16))
	}

	mgr := tunnel.NewManager(c, mgrOpts...)
	go func() {
		_ = mgr.Run(ctx)
	}()
	mgr.UpdateHostnames([]string{hostname})

	tlsLis := tls.NewListener(mgr.Listener(), &tls.Config{Certificates: []tls.Certificate{backendCert}})
	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(payload) > 0 {
				w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
				_, _ = w.Write(payload)
			} else {
				_, _ = w.Write([]byte("OK"))
			}
		}),
	}

	go func() {
		_ = httpSrv.Serve(tlsLis)
	}()

	// Wait for registration in frontend table
	deadline := time.Now().Add(10 * time.Second)
	registered := false
	for time.Now().Before(deadline) {
		if len(srv.RegistrationTable().MatchSessions(hostname)) > 0 {
			registered = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !registered {
		b.Fatalf("backend for %s failed to register within deadline", hostname)
	}

	cleanup := func() {
		cancel()
		_ = httpSrv.Close()
	}

	return mgr, cleanup
}

func runLatencyBenchmark(b *testing.B, cfg benchConfig, hostname string) {
	checkSocketBufferSizes(b)

	srv, serverAddr, generated, cleanupSrv := setupTestServerWithUDPAndClient(b, withBenchmarkServerSettings)
	defer cleanupSrv()

	_, cleanupBackend := setupBenchmarkBackend(b, srv, serverAddr, generated, hostname, cfg, nil)
	defer cleanupBackend()

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         hostname,
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         hostname,
					InsecureSkipVerify: true,
				})
			},
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}

	latencies := make([]time.Duration, 0, b.N)
	buf := make([]byte, 2)

	var memStart runtime.MemStats
	runtime.ReadMemStats(&memStart)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t0 := time.Now()
		resp, err := httpClient.Get("https://" + hostname + "/test")
		if err != nil {
			b.Fatalf("Get failed: %v", err)
		}
		_, _ = resp.Body.Read(buf)
		lat := time.Since(t0)
		latencies = append(latencies, lat)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	b.StopTimer()

	var memEnd runtime.MemStats
	runtime.ReadMemStats(&memEnd)

	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		p50 := latencies[len(latencies)*50/100]
		p99 := latencies[len(latencies)*99/100]
		b.ReportMetric(float64(p50.Microseconds())/1000.0, "p50-ms")
		b.ReportMetric(float64(p99.Microseconds())/1000.0, "p99-ms")
	}

	allocsPerConn := float64(memEnd.Mallocs-memStart.Mallocs) / float64(b.N)
	b.ReportMetric(allocsPerConn, "allocs/conn")
}

func runThroughputBenchmark(b *testing.B, cfg benchConfig, hostname string) {
	checkSocketBufferSizes(b)

	srv, serverAddr, generated, cleanupSrv := setupTestServerWithUDPAndClient(b, withBenchmarkServerSettings)
	defer cleanupSrv()

	payload := make([]byte, 10*1024*1024) // 10 MB
	_, cleanupBackend := setupBenchmarkBackend(b, srv, serverAddr, generated, hostname, cfg, payload)
	defer cleanupBackend()

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         hostname,
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         hostname,
					InsecureSkipVerify: true,
				})
			},
		},
		Timeout: 60 * time.Second,
	}

	b.SetBytes(int64(len(payload)))

	u0, s0 := getCPUTime()
	var mem0 runtime.MemStats
	runtime.ReadMemStats(&mem0)

	b.ResetTimer()
	t0 := time.Now()
	for i := 0; i < b.N; i++ {
		resp, err := httpClient.Get("https://" + hostname + "/test")
		if err != nil {
			b.Fatalf("Get failed: %v", err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if n != int64(len(payload)) {
			b.Fatalf("expected %d bytes, got %d", len(payload), n)
		}
	}
	b.StopTimer()
	wallElapsed := time.Since(t0)

	u1, s1 := getCPUTime()
	var mem1 runtime.MemStats
	runtime.ReadMemStats(&mem1)

	totalBytes := int64(len(payload)) * int64(b.N)
	gbTransferred := float64(totalBytes) / (1024 * 1024 * 1024)
	mbTransferred := float64(totalBytes) / (1024 * 1024)
	totalCPUSec := (u1 - u0).Seconds() + (s1 - s0).Seconds()

	if gbTransferred > 0 {
		b.ReportMetric(totalCPUSec/gbTransferred, "CPU-s/GB")
	}
	if mbTransferred > 0 {
		b.ReportMetric(float64(mem1.Mallocs-mem0.Mallocs)/mbTransferred, "allocs/MB")
		b.ReportMetric(mbTransferred/wallElapsed.Seconds(), "MB/s")
	}
}

func runConcurrentThroughputBenchmark(b *testing.B, cfg benchConfig, hostname string, concurrency int) {
	checkSocketBufferSizes(b)

	srv, serverAddr, generated, cleanupSrv := setupTestServerWithUDPAndClient(b, withBenchmarkServerSettings)
	defer cleanupSrv()

	payload := make([]byte, 5*1024*1024) // 5 MB per transfer
	_, cleanupBackend := setupBenchmarkBackend(b, srv, serverAddr, generated, hostname, cfg, payload)
	defer cleanupBackend()

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         hostname,
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         hostname,
					InsecureSkipVerify: true,
				})
			},
			MaxIdleConns:        concurrency * 2,
			MaxIdleConnsPerHost: concurrency * 2,
		},
		Timeout: 30 * time.Second,
	}

	b.SetBytes(int64(len(payload)) * int64(concurrency))

	u0, s0 := getCPUTime()
	var mem0 runtime.MemStats
	runtime.ReadMemStats(&mem0)

	b.ResetTimer()
	t0 := time.Now()

	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		wg.Add(concurrency)
		for c := 0; c < concurrency; c++ {
			go func() {
				defer wg.Done()
				resp, err := httpClient.Get("https://" + hostname + "/test")
				if err != nil {
					b.Errorf("Get failed: %v", err)
					return
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if n != int64(len(payload)) {
					b.Errorf("expected %d bytes, got %d", len(payload), n)
				}
			}()
		}
		wg.Wait()
	}

	b.StopTimer()
	wallElapsed := time.Since(t0)

	u1, s1 := getCPUTime()
	var mem1 runtime.MemStats
	runtime.ReadMemStats(&mem1)

	totalBytes := int64(len(payload)) * int64(concurrency) * int64(b.N)
	gbTransferred := float64(totalBytes) / (1024 * 1024 * 1024)
	mbTransferred := float64(totalBytes) / (1024 * 1024)
	totalCPUSec := (u1 - u0).Seconds() + (s1 - s0).Seconds()

	if gbTransferred > 0 {
		b.ReportMetric(totalCPUSec/gbTransferred, "CPU-s/GB")
	}
	if mbTransferred > 0 {
		b.ReportMetric(float64(mem1.Mallocs-mem0.Mallocs)/mbTransferred, "allocs/MB")
		b.ReportMetric(mbTransferred/wallElapsed.Seconds(), "MB/s")
	}
}

func BenchmarkLatency_QUIC(b *testing.B) {
	runLatencyBenchmark(b, benchConfig{Transport: "quic"}, "bench-quic.example.com")
}

func BenchmarkLatency_TCPPool(b *testing.B) {
	runLatencyBenchmark(b, benchConfig{Transport: "tcp", PoolSize: 16}, "bench-tcp.example.com")
}

func BenchmarkLatency_H2(b *testing.B) {
	runLatencyBenchmark(b, benchConfig{Transport: "h2", PoolSize: 4}, "bench-h2.example.com")
}

func BenchmarkThroughput_QUIC(b *testing.B) {
	runThroughputBenchmark(b, benchConfig{Transport: "quic"}, "tput-quic.example.com")
}

func BenchmarkThroughput_TCPPool(b *testing.B) {
	runThroughputBenchmark(b, benchConfig{Transport: "tcp", PoolSize: 16}, "tput-tcp.example.com")
}

func BenchmarkThroughput_H2(b *testing.B) {
	runThroughputBenchmark(b, benchConfig{Transport: "h2", PoolSize: 4}, "tput-h2.example.com")
}

func BenchmarkThroughput_Concurrent_QUIC(b *testing.B) {
	runConcurrentThroughputBenchmark(b, benchConfig{Transport: "quic"}, "c-tput-quic.example.com", 8)
}

func BenchmarkThroughput_Concurrent_TCPPool(b *testing.B) {
	runConcurrentThroughputBenchmark(b, benchConfig{Transport: "tcp", PoolSize: 16}, "c-tput-tcp.example.com", 8)
}

func BenchmarkThroughput_Concurrent_H2(b *testing.B) {
	runConcurrentThroughputBenchmark(b, benchConfig{Transport: "h2", PoolSize: 4}, "c-tput-h2.example.com", 8)
}

func BenchmarkMatrix(b *testing.B) {
	scenarios := []struct {
		name string
		cfg  benchConfig
	}{
		{"QUIC_RTT0ms_Loss0%", benchConfig{Transport: "quic", RTT: 0, Loss: 0}},
		{"QUIC_RTT20ms_Loss0%", benchConfig{Transport: "quic", RTT: 20 * time.Millisecond, Loss: 0}},
		{"QUIC_RTT50ms_Loss0%", benchConfig{Transport: "quic", RTT: 50 * time.Millisecond, Loss: 0}},
		{"QUIC_RTT20ms_Loss1%", benchConfig{Transport: "quic", RTT: 20 * time.Millisecond, Loss: 0.01}},
		{"QUIC_RTT50ms_Loss1%", benchConfig{Transport: "quic", RTT: 50 * time.Millisecond, Loss: 0.01}},

		{"TCPPool_RTT0ms_Loss0%", benchConfig{Transport: "tcp", RTT: 0, Loss: 0, PoolSize: 16}},
		{"TCPPool_RTT20ms_Loss0%", benchConfig{Transport: "tcp", RTT: 20 * time.Millisecond, Loss: 0, PoolSize: 16}},
		{"TCPPool_RTT50ms_Loss0%", benchConfig{Transport: "tcp", RTT: 50 * time.Millisecond, Loss: 0, PoolSize: 16}},
		{"TCPPool_RTT20ms_Loss1%", benchConfig{Transport: "tcp", RTT: 20 * time.Millisecond, Loss: 0.01, PoolSize: 16}},
		{"TCPPool_RTT50ms_Loss1%", benchConfig{Transport: "tcp", RTT: 50 * time.Millisecond, Loss: 0.01, PoolSize: 16}},

		{"H2_RTT0ms_Loss0%", benchConfig{Transport: "h2", RTT: 0, Loss: 0, PoolSize: 4}},
		{"H2_RTT20ms_Loss0%", benchConfig{Transport: "h2", RTT: 20 * time.Millisecond, Loss: 0, PoolSize: 4}},
		{"H2_RTT50ms_Loss0%", benchConfig{Transport: "h2", RTT: 50 * time.Millisecond, Loss: 0, PoolSize: 4}},
		{"H2_RTT20ms_Loss1%", benchConfig{Transport: "h2", RTT: 20 * time.Millisecond, Loss: 0.01, PoolSize: 4}},
		{"H2_RTT50ms_Loss1%", benchConfig{Transport: "h2", RTT: 50 * time.Millisecond, Loss: 0.01, PoolSize: 4}},
	}

	for _, sc := range scenarios {
		b.Run(sc.name+"_Latency", func(subB *testing.B) {
			runLatencyBenchmark(subB, sc.cfg, "mat-lat.example.com")
		})
		b.Run(sc.name+"_Throughput", func(subB *testing.B) {
			runThroughputBenchmark(subB, sc.cfg, "mat-tput.example.com")
		})
	}
}

func runBurstLatencyBenchmark(b *testing.B, cfg benchConfig, hostname string, burstSize int) {
	checkSocketBufferSizes(b)

	srv, serverAddr, generated, cleanupSrv := setupTestServerWithUDPAndClient(b, withBenchmarkServerSettings)
	defer cleanupSrv()

	_, cleanupBackend := setupBenchmarkBackend(b, srv, serverAddr, generated, hostname, cfg, nil)
	defer cleanupBackend()

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         hostname,
				InsecureSkipVerify: true,
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", serverAddr, &tls.Config{
					ServerName:         hostname,
					InsecureSkipVerify: true,
				})
			},
			DisableKeepAlives: true,
		},
		Timeout: 30 * time.Second,
	}

	allLatencies := make([]time.Duration, 0, b.N*burstSize)
	var mu sync.Mutex

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		wg.Add(burstSize)
		for j := 0; j < burstSize; j++ {
			go func() {
				defer wg.Done()
				t0 := time.Now()
				resp, err := httpClient.Get("https://" + hostname + "/test")
				if err != nil {
					b.Errorf("burst Get failed: %v", err)
					return
				}
				buf := make([]byte, 2)
				_, _ = resp.Body.Read(buf)
				dur := time.Since(t0)
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()

				mu.Lock()
				allLatencies = append(allLatencies, dur)
				mu.Unlock()
			}()
		}
		wg.Wait()
	}
	b.StopTimer()

	if len(allLatencies) > 0 {
		sort.Slice(allLatencies, func(i, j int) bool { return allLatencies[i] < allLatencies[j] })
		p50 := allLatencies[len(allLatencies)*50/100]
		p99 := allLatencies[len(allLatencies)*99/100]
		b.ReportMetric(float64(p50.Microseconds())/1000.0, "p50-ms")
		b.ReportMetric(float64(p99.Microseconds())/1000.0, "p99-ms")
	}
}

// BenchmarkLatency_Burst measures TTFB for a burst of new connections larger than the pool size,
// showing the latency advantage of 0-RTT/1-RTT QUIC multiplexing over TCP pool exhaustion under WAN latency.
func BenchmarkLatency_Burst(b *testing.B) {
	scenarios := []struct {
		name string
		cfg  benchConfig
	}{
		{"QUIC_RTT20ms", benchConfig{Transport: "quic", RTT: 20 * time.Millisecond}},
		{"QUIC_RTT50ms", benchConfig{Transport: "quic", RTT: 50 * time.Millisecond}},
		{"TCPPool_RTT20ms", benchConfig{Transport: "tcp", RTT: 20 * time.Millisecond, PoolSize: 8}},
		{"TCPPool_RTT50ms", benchConfig{Transport: "tcp", RTT: 50 * time.Millisecond, PoolSize: 8}},
		{"H2_RTT20ms", benchConfig{Transport: "h2", RTT: 20 * time.Millisecond, PoolSize: 4}},
		{"H2_RTT50ms", benchConfig{Transport: "h2", RTT: 50 * time.Millisecond, PoolSize: 4}},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(subB *testing.B) {
			runBurstLatencyBenchmark(subB, sc.cfg, "burst.example.com", 32)
		})
	}
}

// TestBenchmark_SeparateProcessCPU runs backend in a child process and frontend in parent
// to independently measure frontend CPU per GB and backend CPU per GB at saturation.
func TestBenchmark_SeparateProcessCPU(t *testing.T) {
	if os.Getenv("BENCH_CHILD_ROLE") == "backend" {
		runBenchmarkChildBackend(t)
		return
	}

	checkSocketBufferSizes(t)

	for _, transport := range []string{"quic", "tcp", "h2"} {
		t.Run(transport, func(t *testing.T) {
			srv, serverAddr, generated, cleanupSrv := setupTestServerWithUDPAndClient(t, withBenchmarkServerSettings)
			defer cleanupSrv()
			_ = srv

			hostname := fmt.Sprintf("subproc-%s.example.com", transport)
			transferBytes := 50 * 1024 * 1024 // 50 MB
			concurrency := 4

			// Spawn child process for backend
			cmd := exec.Command(os.Args[0], "-test.run=^TestBenchmark_SeparateProcessCPU$")
			cmd.Env = append(os.Environ(),
				"BENCH_CHILD_ROLE=backend",
				"BENCH_SERVER_ADDR="+serverAddr,
				"BENCH_TRANSPORT="+transport,
				"BENCH_HOSTNAME="+hostname,
				"BENCH_CA_CERT="+string(generated.CA.CertPEM),
				"BENCH_CLIENT_CERT="+string(generated.Client.CertPEM),
				"BENCH_CLIENT_KEY="+string(generated.Client.KeyPEM),
			)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			if err := cmd.Start(); err != nil {
				t.Fatalf("Failed to start backend child process: %v", err)
			}

			// Wait for backend child to register
			deadline := time.Now().Add(10 * time.Second)
			registered := false
			for time.Now().Before(deadline) {
				if len(srv.RegistrationTable().MatchSessions(hostname)) > 0 {
					registered = true
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !registered {
				t.Fatalf("backend child for %s failed to register within deadline", hostname)
			}

			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						ServerName:         hostname,
						InsecureSkipVerify: true,
					},
					DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return tls.Dial("tcp", serverAddr, &tls.Config{
							ServerName:         hostname,
							InsecureSkipVerify: true,
						})
					},
					MaxIdleConns: concurrency * 2,
				},
				Timeout: 30 * time.Second,
			}

			u0, s0 := getCPUTime()
			t0 := time.Now()

			var wg sync.WaitGroup
			bytesPerWorker := transferBytes / concurrency
			wg.Add(concurrency)
			for c := 0; c < concurrency; c++ {
				go func() {
					defer wg.Done()
					resp, err := httpClient.Get(fmt.Sprintf("https://%s/bench?size=%d", hostname, bytesPerWorker))
					if err != nil {
						t.Errorf("Get failed: %v", err)
						return
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}()
			}
			wg.Wait()

			wallDuration := time.Since(t0)
			u1, s1 := getCPUTime()
			feCPUTime := (u1 - u0) + (s1 - s0)

			// Signal child to terminate and get its process CPU time
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()

			beUser := cmd.ProcessState.UserTime()
			beSys := cmd.ProcessState.SystemTime()
			beCPUTime := beUser + beSys

			gb := float64(transferBytes) / (1024 * 1024 * 1024)
			feCPUPerGB := feCPUTime.Seconds() / gb
			beCPUPerGB := beCPUTime.Seconds() / gb
			mbPerSec := (float64(transferBytes) / (1024 * 1024)) / wallDuration.Seconds()

			t.Logf("[%s] Transferred: %d MB in %v (%.2f MB/s)", transport, transferBytes/1024/1024, wallDuration, mbPerSec)
			t.Logf("[%s] Frontend Process CPU: %v (%.2f CPU-s/GB)", transport, feCPUTime, feCPUPerGB)
			t.Logf("[%s] Backend Process CPU:  %v (%.2f CPU-s/GB)", transport, beCPUTime, beCPUPerGB)
		})
	}
}

func runBenchmarkChildBackend(t *testing.T) {
	serverAddr := os.Getenv("BENCH_SERVER_ADDR")
	transport := os.Getenv("BENCH_TRANSPORT")
	hostname := os.Getenv("BENCH_HOSTNAME")
	caPEM := []byte(os.Getenv("BENCH_CA_CERT"))
	clientPEM := []byte(os.Getenv("BENCH_CLIENT_CERT"))
	keyPEM := []byte(os.Getenv("BENCH_CLIENT_KEY"))

	clientTLS, err := certs.NewClientTLSConfig(caPEM, clientPEM, keyPEM, "snigateway.internal")
	if err != nil {
		os.Exit(1)
	}

	backendCert, err := generateTestBackendCert(hostname)
	if err != nil {
		os.Exit(1)
	}

	c := client.NewClient(serverAddr, clientTLS)
	ctx, cancel := signal.NotifyContext(t.Context(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	mgrOpts := []tunnel.ManagerOption{tunnel.WithTransport(transport)}
	if transport == "tcp" || transport == "h2" {
		mgrOpts = append(mgrOpts, tunnel.WithPoolSize(16))
	}

	mgr := tunnel.NewManager(c, mgrOpts...)
	go func() {
		_ = mgr.Run(ctx)
	}()
	mgr.UpdateHostnames([]string{hostname})

	tlsLis := tls.NewListener(mgr.Listener(), &tls.Config{Certificates: []tls.Certificate{backendCert}})
	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sizeStr := r.URL.Query().Get("size")
			size, _ := strconv.Atoi(sizeStr)
			if size <= 0 {
				size = 10 * 1024 * 1024
			}
			w.Header().Set("Content-Length", strconv.Itoa(size))
			chunk := make([]byte, 64*1024)
			written := 0
			for written < size {
				toWrite := len(chunk)
				if size-written < toWrite {
					toWrite = size - written
				}
				nw, err := w.Write(chunk[:toWrite])
				if err != nil {
					return
				}
				written += nw
			}
		}),
	}

	go func() {
		_ = httpSrv.Serve(tlsLis)
	}()

	<-ctx.Done()
	_ = httpSrv.Close()
	os.Exit(0)
}

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

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/client"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/frontend"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/tunnel"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/wireguard"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const requirePrivilegesEnv = "WIREGUARD_REQUIRE_PRIVILEGES"

type testNamespaceWorker struct {
	namespace     netns.NsHandle
	ownsNamespace bool
	work          chan func()
}

func newTestNamespaceWorker() (*testNamespaceWorker, error) {
	worker := &testNamespaceWorker{
		ownsNamespace: true,
		work:          make(chan func()),
	}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		namespace, err := netns.New()
		if err != nil {
			ready <- err
			return
		}
		worker.namespace = namespace
		close(ready)
		for workFunc := range worker.work {
			workFunc()
		}
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return worker, nil
}

func newWorkerInNamespace(namespace netns.NsHandle) (*testNamespaceWorker, error) {
	worker := &testNamespaceWorker{
		ownsNamespace: false,
		work:          make(chan func()),
		namespace:     namespace,
	}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := netns.Set(namespace); err != nil {
			ready <- err
			return
		}
		close(ready)
		for workFunc := range worker.work {
			workFunc()
		}
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return worker, nil
}

func (worker *testNamespaceWorker) Do(workFunc func() error) error {
	var err error
	done := make(chan struct{})
	worker.work <- func() {
		defer close(done)
		err = workFunc()
	}
	<-done
	return err
}

func (worker *testNamespaceWorker) Close() error {
	if worker.work != nil {
		close(worker.work)
	}
	if worker.ownsNamespace && worker.namespace.IsOpen() {
		return worker.namespace.Close()
	}
	return nil
}

type nsWireGuardDevice struct {
	tunnel.WireGuardDevice
	worker *testNamespaceWorker
}

func (d *nsWireGuardDevice) Close() error {
	var err error
	doErr := d.worker.Do(func() error {
		err = d.WireGuardDevice.Close()
		return err
	})
	if doErr != nil {
		return doErr
	}
	return err
}

func skipWithoutPrivilege(t *testing.T, err error, action string) {
	t.Helper()
	if err == nil {
		return
	}
	if os.Getenv(requirePrivilegesEnv) != "" {
		t.Fatalf("%s: required privileges missing: %v", action, err)
	}
	t.Skipf("skipping test: %s: %v", action, err)
}

func generateE2EBackendCert(hosts ...string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName: hosts[0],
		},
		DNSNames:              hosts,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

func TestSNIGateway_WireGuardTunnel(t *testing.T) {
	workerFrontend, err := newTestNamespaceWorker()
	if err != nil {
		skipWithoutPrivilege(t, err, "cannot create frontend network namespace")
		return
	}
	t.Cleanup(func() {
		if closeErr := workerFrontend.Close(); closeErr != nil {
			t.Logf("closing workerFrontend: %v", closeErr)
		}
	})

	workerController, err := newTestNamespaceWorker()
	if err != nil {
		skipWithoutPrivilege(t, err, "cannot create controller network namespace")
		return
	}
	t.Cleanup(func() {
		if closeErr := workerController.Close(); closeErr != nil {
			t.Logf("closing workerController: %v", closeErr)
		}
	})

	// Separate client worker in the frontend namespace to send client requests concurrently
	workerClient, err := newWorkerInNamespace(workerFrontend.namespace)
	if err != nil {
		skipWithoutPrivilege(t, err, "cannot create client worker in frontend namespace")
		return
	}
	t.Cleanup(func() {
		if closeErr := workerClient.Close(); closeErr != nil {
			t.Logf("closing workerClient: %v", closeErr)
		}
	})

	// Bring loopback interface up in both namespaces
	if err := workerFrontend.Do(func() error {
		link, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		return netlink.LinkSetUp(link)
	}); err != nil {
		t.Fatalf("bringing up lo in workerFrontend: %v", err)
	}

	if err := workerController.Do(func() error {
		link, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		return netlink.LinkSetUp(link)
	}); err != nil {
		t.Fatalf("bringing up lo in workerController: %v", err)
	}

	// Create veth pair inside workerFrontend's namespace and move peer to workerController's namespace
	if err := workerFrontend.Do(func() error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth-wg-fe"},
			PeerName:  "veth-wg-ctrl",
		}
		if err := netlink.LinkAdd(veth); err != nil {
			return err
		}
		peerLink, err := netlink.LinkByName("veth-wg-ctrl")
		if err != nil {
			return err
		}
		return netlink.LinkSetNsFd(peerLink, int(workerController.namespace))
	}); err != nil {
		skipWithoutPrivilege(t, err, "cannot create veth pair inside frontend namespace")
		return
	}

	// Configure veth-wg-fe in workerFrontend (10.100.0.1/24)
	if err := workerFrontend.Do(func() error {
		link, err := netlink.LinkByName("veth-wg-fe")
		if err != nil {
			return err
		}
		address, err := netlink.ParseAddr("10.100.0.1/24")
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, address); err != nil {
			return err
		}
		return netlink.LinkSetUp(link)
	}); err != nil {
		t.Fatalf("configuring veth in workerFrontend: %v", err)
	}

	// Configure veth-wg-ctrl in workerController (10.100.0.2/24)
	if err := workerController.Do(func() error {
		link, err := netlink.LinkByName("veth-wg-ctrl")
		if err != nil {
			return err
		}
		address, err := netlink.ParseAddr("10.100.0.2/24")
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, address); err != nil {
			return err
		}
		return netlink.LinkSetUp(link)
	}); err != nil {
		t.Fatalf("configuring veth in workerController: %v", err)
	}

	// Generate certificates for mTLS infrastructure
	tempDir := t.TempDir()
	if err := certs.GenerateAndWriteCertificates(tempDir, "snigateway.internal", "e2e-controller"); err != nil {
		t.Fatalf("GenerateAndWriteCertificates failed: %v", err)
	}
	caCertPEM, err := os.ReadFile(filepath.Join(tempDir, "ca.crt"))
	if err != nil {
		t.Fatalf("reading ca.crt: %v", err)
	}
	serverCertPEM, err := os.ReadFile(filepath.Join(tempDir, "server.crt"))
	if err != nil {
		t.Fatalf("reading server.crt: %v", err)
	}
	serverKeyPEM, err := os.ReadFile(filepath.Join(tempDir, "server.key"))
	if err != nil {
		t.Fatalf("reading server.key: %v", err)
	}
	clientCertPEM, err := os.ReadFile(filepath.Join(tempDir, "client.crt"))
	if err != nil {
		t.Fatalf("reading client.crt: %v", err)
	}
	clientKeyPEM, err := os.ReadFile(filepath.Join(tempDir, "client.key"))
	if err != nil {
		t.Fatalf("reading client.key: %v", err)
	}

	serverTLS, err := certs.NewServerTLSConfig(caCertPEM, serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("NewServerTLSConfig failed: %v", err)
	}

	clientTLS, err := certs.NewClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM, "snigateway.internal")
	if err != nil {
		t.Fatalf("NewClientTLSConfig failed: %v", err)
	}

	// Open WireGuard device for frontend inside workerFrontend
	fePrivateKey, fePublicKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	fePrefixNet, err := wireguard.GeneratePrefix()
	if err != nil {
		t.Fatalf("GeneratePrefix failed: %v", err)
	}
	feAddress := make(net.IP, 16)
	copy(feAddress, fePrefixNet.IP.To16())
	feAddress[15] = 1 // fd00:5182::1

	var feDevice *wireguard.Device
	if err := workerFrontend.Do(func() error {
		dev, err := wireguard.OpenDevice(t.Context(), wireguard.Config{
			InterfaceName: "wg-fe0",
			PrivateKey:    fePrivateKey,
			ListenPort:    51820,
			DeviceAddress: feAddress,
			TunnelPrefix:  fePrefixNet,
		})
		if err != nil {
			return err
		}
		feDevice = dev
		return nil
	}); err != nil {
		skipWithoutPrivilege(t, err, "OpenDevice in workerFrontend failed")
		return
	}
	t.Cleanup(func() {
		if err := workerFrontend.Do(func() error {
			if feDevice != nil {
				return feDevice.Close()
			}
			return nil
		}); err != nil {
			t.Logf("closing feDevice: %v", err)
		}
	})

	// Open TLS and HTTP listeners in workerFrontend
	var tlsListener, httpListener net.Listener
	if err := workerFrontend.Do(func() error {
		var err error
		tlsListener, err = net.Listen("tcp", "10.100.0.1:8443")
		if err != nil {
			return err
		}
		httpListener, err = net.Listen("tcp", "10.100.0.1:8080")
		return err
	}); err != nil {
		t.Fatalf("listening in workerFrontend: %v", err)
	}

	// Frontend dial inside workerFrontend namespace, counting successful dials
	var dialCount atomic.Int32
	feDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		var conn net.Conn
		var err error
		doErr := workerFrontend.Do(func() error {
			conn, err = (&net.Dialer{}).DialContext(ctx, network, address)
			return err
		})
		if doErr != nil {
			return nil, doErr
		}
		if err == nil {
			dialCount.Add(1)
		}
		return conn, err
	}

	srv, err := frontend.NewServer(frontend.ServerConfig{
		ServerTLSConfig:    serverTLS,
		InternalHostname:   "snigateway.internal",
		ConnectTimeout:     5 * time.Second,
		ReadSNITimeout:     2 * time.Second,
		WireGuardDevice:    feDevice,
		WireGuardPublicKey: fePublicKey,
		WireGuardPort:      51820,
		WireGuardPrefix:    fePrefixNet,
		DialContext:        feDial,
	})
	if err != nil {
		t.Fatalf("frontend NewServer failed: %v", err)
	}
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Logf("closing frontend server: %v", err)
		}
	})

	serverErrCh := make(chan error, 2)
	go func() {
		err := srv.ServeWithHTTP([]net.Listener{tlsListener}, []net.Listener{httpListener})
		if err != nil && !errors.Is(err, net.ErrClosed) {
			serverErrCh <- fmt.Errorf("frontend server: %w", err)
		}
	}()

	// Configure client and tunnel manager in workerController
	ctrlDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		var conn net.Conn
		var err error
		doErr := workerController.Do(func() error {
			conn, err = (&net.Dialer{}).DialContext(ctx, network, address)
			return err
		})
		if doErr != nil {
			return nil, doErr
		}
		return conn, err
	}

	ctrlClient := client.NewClient("10.100.0.1:8443", clientTLS,
		client.WithInternalHostname("snigateway.internal"),
		client.WithDialFunc(ctrlDial),
	)

	ctrlOpener := func(ctx context.Context, cfg wireguard.Config) (tunnel.WireGuardDevice, error) {
		var dev tunnel.WireGuardDevice
		var err error
		doErr := workerController.Do(func() error {
			device, openErr := wireguard.OpenDevice(ctx, cfg)
			if openErr != nil {
				return openErr
			}
			dev = &nsWireGuardDevice{WireGuardDevice: device, worker: workerController}
			return nil
		})
		if doErr != nil {
			return nil, doErr
		}
		return dev, err
	}

	ctrlListen := func(network, address string) (net.Listener, error) {
		var lis net.Listener
		var err error
		doErr := workerController.Do(func() error {
			lis, err = net.Listen(network, address)
			return err
		})
		if doErr != nil {
			return nil, doErr
		}
		return lis, err
	}

	// tunnel.WithPoolSize(0) disables reverse tunnel pooled connections, verifying traffic is over WireGuard
	mgr := tunnel.NewManager(ctrlClient,
		tunnel.WithWireGuard(true),
		tunnel.WithPoolSize(0),
		tunnel.WithWireGuardDeviceOpener(ctrlOpener),
		tunnel.WithListenFunc(ctrlListen),
	)

	backendCert, err := generateE2EBackendCert("app.example.com")
	if err != nil {
		t.Fatalf("generateE2EBackendCert failed: %v", err)
	}

	mgrCtx, cancelMgr := context.WithCancel(t.Context())
	defer cancelMgr()

	go func() {
		err := mgr.Run(mgrCtx)
		if err != nil && !errors.Is(err, context.Canceled) {
			serverErrCh <- fmt.Errorf("tunnel manager: %w", err)
		}
	}()

	var httpsRemoteAddress, httpRemoteAddress atomic.Pointer[string]

	// Serve HTTPS backend on mgr.HTTPSListener()
	go func() {
		lis := mgr.HTTPSListener()
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func(backendConn net.Conn) {
				defer backendConn.Close()
				remoteAddress := backendConn.RemoteAddr().String()
				httpsRemoteAddress.Store(&remoteAddress)
				tlsServer := tls.Server(backendConn, &tls.Config{
					Certificates: []tls.Certificate{backendCert},
				})
				defer tlsServer.Close()

				buffer := make([]byte, 1024)
				n, err := tlsServer.Read(buffer)
				if err != nil {
					return
				}
				reqStr := string(buffer[:n])
				respStr := fmt.Sprintf("ECHO-HTTPS:%s", reqStr)
				if _, err := tlsServer.Write([]byte(respStr)); err != nil {
					t.Logf("tlsServer.Write error: %v", err)
				}
			}(conn)
		}
	}()

	// Serve HTTP backend on mgr.HTTPListener()
	go func() {
		lis := mgr.HTTPListener()
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func(backendConn net.Conn) {
				defer backendConn.Close()
				remoteAddress := backendConn.RemoteAddr().String()
				httpRemoteAddress.Store(&remoteAddress)
				buffer := make([]byte, 1024)
				n, err := backendConn.Read(buffer)
				if err != nil || n == 0 {
					return
				}
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nECHO-HTTP"
				if _, err := backendConn.Write([]byte(resp)); err != nil {
					t.Logf("backendConn.Write error: %v", err)
				}
			}(conn)
		}
	}()

	mgr.UpdateHostnames([]string{"app.example.com", "plain.example.com"})

	// Wait for registration using waitFor helper
	waitFor(t, 10*time.Second, func() bool {
		return mgr.HasRegisteredHostnames([]string{"app.example.com", "plain.example.com"})
	})

	// Check if any server error occurred during setup
	select {
	case err := <-serverErrCh:
		t.Fatalf("server setup error: %v", err)
	default:
	}

	if initialDials := dialCount.Load(); initialDials != 0 {
		t.Fatalf("expected 0 tunnel dials initially, got %d", initialDials)
	}

	// 1. Send HTTPS request routed by SNI over WireGuard tunnel
	t.Run("HTTPS request over WireGuard tunnel", func(t *testing.T) {
		var clientAddress string
		if err := workerClient.Do(func() error {
			tlsConn, err := tls.Dial("tcp", "10.100.0.1:8443", &tls.Config{
				ServerName:         "app.example.com",
				InsecureSkipVerify: true,
			})
			if err != nil {
				return fmt.Errorf("tls.Dial failed: %w", err)
			}
			defer tlsConn.Close()
			clientAddress = tlsConn.LocalAddr().String()

			payload := "ping-wg-https"
			if _, err := tlsConn.Write([]byte(payload)); err != nil {
				return fmt.Errorf("writing to tlsConn: %w", err)
			}

			reply := make([]byte, 1024)
			n, err := tlsConn.Read(reply)
			if err != nil {
				return fmt.Errorf("reading from tlsConn: %w", err)
			}

			got := string(reply[:n])
			want := "ECHO-HTTPS:ping-wg-https"
			if got != want {
				return fmt.Errorf("got %q, want %q", got, want)
			}
			return nil
		}); err != nil {
			t.Fatalf("HTTPS request over tunnel failed: %v", err)
		}

		if gotDials := dialCount.Load(); gotDials != 1 {
			t.Errorf("expected 1 tunnel dial after HTTPS request, got %d", gotDials)
		}

		if gotRemote := httpsRemoteAddress.Load(); gotRemote == nil || *gotRemote != clientAddress {
			t.Errorf("expected backend remote address %q, got %v", clientAddress, gotRemote)
		}
	})

	// 2. Send plain HTTP request routed by Host over WireGuard tunnel
	t.Run("Plain HTTP request over WireGuard tunnel", func(t *testing.T) {
		var clientAddress string
		if err := workerClient.Do(func() error {
			conn, err := net.Dial("tcp", "10.100.0.1:8080")
			if err != nil {
				return fmt.Errorf("net.Dial failed: %w", err)
			}
			defer conn.Close()
			clientAddress = conn.LocalAddr().String()

			req := "GET /test HTTP/1.1\r\nHost: plain.example.com\r\n\r\n"
			if _, err := conn.Write([]byte(req)); err != nil {
				return fmt.Errorf("writing HTTP request: %w", err)
			}

			reply := make([]byte, 1024)
			n, err := conn.Read(reply)
			if err != nil {
				return fmt.Errorf("reading HTTP response: %w", err)
			}

			got := string(reply[:n])
			if !strings.Contains(got, "ECHO-HTTP") {
				return fmt.Errorf("got %q, want response containing ECHO-HTTP", got)
			}
			return nil
		}); err != nil {
			t.Fatalf("HTTP request over tunnel failed: %v", err)
		}

		if gotDials := dialCount.Load(); gotDials != 2 {
			t.Errorf("expected 2 tunnel dials after HTTP request, got %d", gotDials)
		}

		if gotRemote := httpRemoteAddress.Load(); gotRemote == nil || *gotRemote != clientAddress {
			t.Errorf("expected backend remote address %q, got %v", clientAddress, gotRemote)
		}
	})
}

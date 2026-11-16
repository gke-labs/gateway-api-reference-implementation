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

package wireguard

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const requirePrivilegesEnv = "WIREGUARD_REQUIRE_PRIVILEGES"

// lacksPrivilegeOrKernelSupport reports whether err represents a missing permission or
// lack of kernel WireGuard support needed to create namespaces or links.
func lacksPrivilegeOrKernelSupport(err error) bool {
	return errors.Is(err, ErrPermission) ||
		isPermissionError(err) ||
		errors.Is(err, ErrNotSupported) ||
		isNotSupportedError(err)
}

// skipWithoutPrivilegeOrKernelSupport checks err:
//   - If err is nil, it returns immediately.
//   - If err is a permission-denied or unsupported error, it skips the test unless
//     WIREGUARD_REQUIRE_PRIVILEGES is set, in which case it fails the test.
//   - If err is any other unexpected error, it fails the test immediately.
func skipWithoutPrivilegeOrKernelSupport(t *testing.T, err error, action string) {
	t.Helper()
	if err == nil {
		return
	}
	if !lacksPrivilegeOrKernelSupport(err) {
		t.Fatalf("%s: unexpected error: %v", action, err)
	}
	if os.Getenv(requirePrivilegesEnv) != "" {
		t.Fatalf("%s: required privileges missing: %v", action, err)
	}
	t.Skipf("skipping test: %s: %v", action, err)
}

func TestGenerateKey(t *testing.T) {
	privateKey, publicKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if privateKey == (Key{}) {
		t.Fatal("private key is all zeros")
	}
	if publicKey == (Key{}) {
		t.Fatal("public key is all zeros")
	}
	if publicKey != privateKey.PublicKey() {
		t.Fatalf("public key mismatch: got %s, want %s", publicKey, privateKey.PublicKey())
	}
}

func TestGeneratePrefix(t *testing.T) {
	prefix1, err := GeneratePrefix()
	if err != nil {
		t.Fatalf("GeneratePrefix failed: %v", err)
	}
	if prefix1 == nil {
		t.Fatal("GeneratePrefix returned nil prefix")
	}
	if len(prefix1.IP) != 16 {
		t.Fatalf("expected 16-byte IPv6 address, got %d bytes", len(prefix1.IP))
	}
	if prefix1.IP[0] != 0xfd {
		t.Fatalf("expected prefix inside fd00::/8 (first byte 0xfd), got 0x%02x", prefix1.IP[0])
	}
	ones, bits := prefix1.Mask.Size()
	if ones != 64 || bits != 128 {
		t.Fatalf("expected /64 mask, got /%d (bits=%d)", ones, bits)
	}
	for i := 8; i < 16; i++ {
		if prefix1.IP[i] != 0 {
			t.Fatalf("expected trailing interface bits to be 0, got byte %d = 0x%02x", i, prefix1.IP[i])
		}
	}

	prefix2, err := GeneratePrefix()
	if err != nil {
		t.Fatalf("GeneratePrefix second call failed: %v", err)
	}
	if prefix1.IP.Equal(prefix2.IP) {
		t.Fatalf("expected two generated prefixes to differ, both were %s", prefix1)
	}
}

func TestOpenDevice_InvalidInterfaceName(t *testing.T) {
	privateKey, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	_, prefix, err := net.ParseCIDR("fd00::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}

	testCases := []struct {
		name          string
		interfaceName string
	}{
		{
			name:          "empty",
			interfaceName: "",
		},
		{
			name:          "too long",
			interfaceName: "wg-interface-name-too-long",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := OpenDevice(t.Context(), Config{
				InterfaceName: tc.interfaceName,
				PrivateKey:    privateKey,
				ListenPort:    0,
				DeviceAddress: net.ParseIP("fd00::1"),
				TunnelPrefix:  prefix,
			})
			if err == nil {
				t.Fatalf("expected OpenDevice to fail with interface name %q, got nil", tc.interfaceName)
			}
		})
	}
}

type testNamespaceWorker struct {
	namespace netns.NsHandle
	work      chan func()
}

func newTestNamespaceWorker(t *testing.T) (*testNamespaceWorker, error) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("skipping test: network namespaces exist only on Linux")
	}
	worker := &testNamespaceWorker{
		work: make(chan func()),
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
	if worker.namespace.IsOpen() {
		return worker.namespace.Close()
	}
	return nil
}

func TestOpenDevice_MissingPermissionsOrUnsupported(t *testing.T) {
	privateKey, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	_, prefix, err := net.ParseCIDR("fd00::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}

	configuration := Config{
		InterfaceName: "wg-test-probe",
		PrivateKey:    privateKey,
		ListenPort:    0,
		DeviceAddress: net.ParseIP("fd00::1"),
		TunnelPrefix:  prefix,
	}

	runProbe := func() {
		device, openErr := OpenDevice(t.Context(), configuration)
		if openErr != nil {
			if !errors.Is(openErr, ErrPermission) && !errors.Is(openErr, ErrNotSupported) {
				t.Fatalf("expected ErrPermission or ErrNotSupported, got: %v", openErr)
			}
			errorMessage := openErr.Error()
			if !strings.Contains(errorMessage, "CAP_NET_ADMIN") && !strings.Contains(errorMessage, "WireGuard support") {
				t.Fatalf("error message does not indicate missing capability or WireGuard support: %v", openErr)
			}
			t.Logf("OpenDevice correctly reported error: %v", openErr)
			return
		}
		t.Cleanup(func() {
			if closeErr := device.Close(); closeErr != nil {
				t.Logf("cleanup error: %v", closeErr)
			}
		})
	}

	if runtime.GOOS != "linux" {
		// When unprivileged or without network namespace support (such as macOS),
		// run directly without touching host links because link creation will fail.
		runProbe()
		return
	}

	worker, err := newTestNamespaceWorker(t)
	if err != nil {
		// When unprivileged on Linux, run directly without touching host links because link creation will fail.
		runProbe()
		return
	}
	t.Cleanup(func() {
		if closeErr := worker.Close(); closeErr != nil {
			t.Errorf("closing worker namespace: %v", closeErr)
		}
	})

	if err := worker.Do(func() error {
		runProbe()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOpenDevice_LeavesNoLinkBehindOnFailure(t *testing.T) {
	worker, err := newTestNamespaceWorker(t)
	skipWithoutPrivilegeOrKernelSupport(t, err, "cannot create network namespace")
	t.Cleanup(func() {
		if closeErr := worker.Close(); closeErr != nil {
			t.Errorf("closing worker namespace: %v", closeErr)
		}
	})

	privateKey, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	_, prefix, err := net.ParseCIDR("fd00::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}

	const interfaceName = "wg-fail-cleanup"
	err = worker.Do(func() error {
		// Provide an invalid IP address to cause AddrAdd to fail after LinkAdd succeeds.
		configuration := Config{
			InterfaceName: interfaceName,
			PrivateKey:    privateKey,
			ListenPort:    0,
			DeviceAddress: net.IP{1, 2}, // invalid IP length
			TunnelPrefix:  prefix,
		}
		device, openErr := OpenDevice(t.Context(), configuration)
		if openErr == nil {
			if closeErr := device.Close(); closeErr != nil {
				t.Errorf("closing unexpected device: %v", closeErr)
			}
			return fmt.Errorf("expected OpenDevice to fail with invalid IP, but succeeded")
		}

		if lacksPrivilegeOrKernelSupport(openErr) {
			return openErr
		}

		// Verify the link was cleaned up and does not exist.
		_, getErr := netlink.LinkByName(interfaceName)
		if getErr == nil {
			return fmt.Errorf("link %q was left behind after OpenDevice failure", interfaceName)
		}
		return nil
	})

	skipWithoutPrivilegeOrKernelSupport(t, err, "opening device in namespace")
	if err != nil {
		t.Fatal(err)
	}
}

func configureVethInterface(worker *testNamespaceWorker, interfaceName string, address net.IP) error {
	return worker.Do(func() error {
		loopback, err := netlink.LinkByName("lo")
		if err != nil {
			return fmt.Errorf("getting lo link: %w", err)
		}
		if err := netlink.LinkSetUp(loopback); err != nil {
			return fmt.Errorf("bringing lo up: %w", err)
		}
		link, err := netlink.LinkByName(interfaceName)
		if err != nil {
			return fmt.Errorf("getting %q link: %w", interfaceName, err)
		}
		addr := &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   address,
				Mask: net.CIDRMask(24, 32),
			},
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("adding address to %q: %w", interfaceName, err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("bringing %q up: %w", interfaceName, err)
		}
		return nil
	})
}

func openTestDevice(t *testing.T, worker *testNamespaceWorker, interfaceName string, privateKey Key, deviceAddress net.IP, tunnelPrefix *net.IPNet) (*Device, int) {
	t.Helper()
	var device *Device
	var port int
	err := worker.Do(func() error {
		var openErr error
		device, openErr = OpenDevice(t.Context(), Config{
			InterfaceName: interfaceName,
			PrivateKey:    privateKey,
			ListenPort:    0,
			DeviceAddress: deviceAddress,
			TunnelPrefix:  tunnelPrefix,
		})
		if openErr != nil {
			return openErr
		}
		var portErr error
		port, portErr = device.Port()
		return portErr
	})
	skipWithoutPrivilegeOrKernelSupport(t, err, fmt.Sprintf("opening device %q", interfaceName))
	t.Cleanup(func() {
		if closeErr := worker.Do(func() error { return device.Close() }); closeErr != nil {
			t.Errorf("closing device %q: %v", interfaceName, closeErr)
		}
	})
	return device, port
}

func TestWireGuard_NamespaceCommunication(t *testing.T) {
	worker1, err := newTestNamespaceWorker(t)
	skipWithoutPrivilegeOrKernelSupport(t, err, "cannot create network namespace")
	t.Cleanup(func() {
		if closeErr := worker1.Close(); closeErr != nil {
			t.Errorf("closing worker1 namespace: %v", closeErr)
		}
	})

	worker2, err := newTestNamespaceWorker(t)
	skipWithoutPrivilegeOrKernelSupport(t, err, "cannot create second network namespace")
	t.Cleanup(func() {
		if closeErr := worker2.Close(); closeErr != nil {
			t.Errorf("closing worker2 namespace: %v", closeErr)
		}
	})

	// Create veth pair to link the two namespaces.
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth-test1"},
		PeerName:  "veth-test2",
	}
	skipWithoutPrivilegeOrKernelSupport(t, netlink.LinkAdd(veth), "cannot create veth pair")
	t.Cleanup(func() {
		if delErr := netlink.LinkDel(veth); delErr != nil && !errors.Is(delErr, syscall.ENODEV) {
			t.Errorf("deleting veth link: %v", delErr)
		}
	})

	veth1, err := netlink.LinkByName("veth-test1")
	if err != nil {
		t.Fatalf("finding veth-test1: %v", err)
	}
	veth2, err := netlink.LinkByName("veth-test2")
	if err != nil {
		t.Fatalf("finding veth-test2: %v", err)
	}

	if err := netlink.LinkSetNsFd(veth1, int(worker1.namespace)); err != nil {
		t.Fatalf("moving veth-test1 to ns1: %v", err)
	}
	if err := netlink.LinkSetNsFd(veth2, int(worker2.namespace)); err != nil {
		t.Fatalf("moving veth-test2 to ns2: %v", err)
	}

	if err := configureVethInterface(worker1, "veth-test1", net.ParseIP("10.0.0.1")); err != nil {
		t.Fatalf("configuring veth in ns1: %v", err)
	}
	if err := configureVethInterface(worker2, "veth-test2", net.ParseIP("10.0.0.2")); err != nil {
		t.Fatalf("configuring veth in ns2: %v", err)
	}

	// Generate keys.
	privateKey1, publicKey1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey 1 failed: %v", err)
	}
	privateKey2, publicKey2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey 2 failed: %v", err)
	}

	_, prefix, err := net.ParseCIDR("fd00::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}

	device1, port1 := openTestDevice(t, worker1, "wg0", privateKey1, net.ParseIP("fd00::1"), prefix)
	device2, port2 := openTestDevice(t, worker2, "wg0", privateKey2, net.ParseIP("fd00::2"), prefix)

	// Add peers.
	_, allowedPeer2, err := net.ParseCIDR("fd00::2/128")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}
	if err := worker1.Do(func() error {
		return device1.AddPeer(Peer{
			PublicKey:  publicKey2,
			Endpoint:   &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: port2},
			AllowedIPs: []net.IPNet{*allowedPeer2},
		})
	}); err != nil {
		t.Fatalf("device1 AddPeer: %v", err)
	}

	_, allowedPeer1, err := net.ParseCIDR("fd00::1/128")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}
	if err := worker2.Do(func() error {
		return device2.AddPeer(Peer{
			PublicKey:  publicKey1,
			Endpoint:   &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: port1},
			AllowedIPs: []net.IPNet{*allowedPeer1},
		})
	}); err != nil {
		t.Fatalf("device2 AddPeer: %v", err)
	}

	// Start TCP listener inside ns2 on tunnel address.
	var listener net.Listener
	if err := worker2.Do(func() error {
		var listenErr error
		listener, listenErr = net.Listen("tcp", "[fd00::2]:9999")
		return listenErr
	}); err != nil {
		t.Fatalf("Listen in ns2: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("closing listener: %v", closeErr)
		}
	})

	serverErrCh := make(chan error, 1)
	go func() {
		serverConnection, err := listener.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer func() {
			if closeErr := serverConnection.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				t.Errorf("closing server connection: %v", closeErr)
			}
		}()

		buffer := make([]byte, 5)
		if _, err := io.ReadFull(serverConnection, buffer); err != nil {
			serverErrCh <- fmt.Errorf("server read: %w", err)
			return
		}
		if string(buffer) != "ping!" {
			serverErrCh <- fmt.Errorf("unexpected server read: %q", string(buffer))
			return
		}
		if _, err := serverConnection.Write([]byte("pong!")); err != nil {
			serverErrCh <- fmt.Errorf("server write: %w", err)
			return
		}
		serverErrCh <- nil
	}()

	// Dial TCP from ns1 over tunnel.
	var clientConnection net.Conn
	if err := worker1.Do(func() error {
		var dialErr error
		clientConnection, dialErr = net.DialTimeout("tcp", "[fd00::2]:9999", 5*time.Second)
		return dialErr
	}); err != nil {
		t.Fatalf("Dial from ns1: %v", err)
	}

	if _, err := clientConnection.Write([]byte("ping!")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	response := make([]byte, 5)
	if _, err := io.ReadFull(clientConnection, response); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(response) != "pong!" {
		t.Fatalf("unexpected client response: %q", string(response))
	}
	if closeErr := clientConnection.Close(); closeErr != nil {
		t.Fatalf("closing client connection: %v", closeErr)
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server handler error: %v", err)
	}

	// Remove peer from device1.
	if err := worker1.Do(func() error {
		return device1.RemovePeer(publicKey2)
	}); err != nil {
		t.Fatalf("device1 RemovePeer: %v", err)
	}

	// Verify new connection fails after peer removal.
	if err := worker1.Do(func() error {
		failConnection, dialErr := net.DialTimeout("tcp", "[fd00::2]:9999", 500*time.Millisecond)
		if dialErr == nil {
			if closeErr := failConnection.Close(); closeErr != nil {
				t.Errorf("closing unexpected connection: %v", closeErr)
			}
			return fmt.Errorf("expected connection to fail after removing peer, but succeeded")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

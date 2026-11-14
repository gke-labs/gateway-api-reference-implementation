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
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestGenerateKey(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if priv == (Key{}) {
		t.Fatal("private key is all zeros")
	}
	if pub == (Key{}) {
		t.Fatal("public key is all zeros")
	}
	if pub != priv.PublicKey() {
		t.Fatalf("public key mismatch: got %s, want %s", pub, priv.PublicKey())
	}
}

func TestOpenDevice_MissingPermissionsOrUnsupported(t *testing.T) {
	priv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	_, prefix, err := net.ParseCIDR("fd00::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}

	cfg := Config{
		InterfaceName: "wg-test-probe",
		PrivateKey:    priv,
		ListenPort:    0,
		DeviceAddress: net.ParseIP("fd00::1"),
		TunnelPrefix:  prefix,
	}

	dev, err := OpenDevice(t.Context(), cfg)
	if err != nil {
		if !errors.Is(err, ErrPermission) && !errors.Is(err, ErrNotSupported) {
			t.Fatalf("expected ErrPermission or ErrNotSupported, got: %v", err)
		}
		errMsg := err.Error()
		if !strings.Contains(errMsg, "CAP_NET_ADMIN") && !strings.Contains(errMsg, "WireGuard support") {
			t.Fatalf("error message does not indicate missing capability or WireGuard support: %v", err)
		}
		t.Logf("OpenDevice correctly reported error: %v", err)
		return
	}
	// If it succeeded, clean up the device.
	if closeErr := dev.Close(); closeErr != nil {
		t.Logf("cleanup error: %v", closeErr)
	}
}

type testNSWorker struct {
	ns   netns.NsHandle
	work chan func()
}

func newTestNSWorker() (*testNSWorker, error) {
	w := &testNSWorker{
		work: make(chan func()),
	}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		ns, err := netns.New()
		if err != nil {
			ready <- err
			return
		}
		w.ns = ns
		close(ready)
		for fn := range w.work {
			fn()
		}
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return w, nil
}

func (w *testNSWorker) Do(fn func() error) error {
	var err error
	done := make(chan struct{})
	w.work <- func() {
		defer close(done)
		err = fn()
	}
	<-done
	return err
}

func (w *testNSWorker) Close() {
	if w.work != nil {
		close(w.work)
	}
	if w.ns.IsOpen() {
		_ = w.ns.Close()
	}
}

func TestOpenDevice_LeavesNoLinkBehindOnFailure(t *testing.T) {
	w, err := newTestNSWorker()
	if err != nil {
		t.Skipf("skipping test: cannot create network namespace: %v", err)
	}
	defer w.Close()

	priv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	_, prefix, err := net.ParseCIDR("fd00::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}

	const ifName = "wg-fail-cleanup"
	err = w.Do(func() error {
		// Provide an invalid IP address to cause AddrAdd to fail after LinkAdd succeeds.
		cfg := Config{
			InterfaceName: ifName,
			PrivateKey:    priv,
			ListenPort:    0,
			DeviceAddress: net.IP{1, 2}, // invalid IP length
			TunnelPrefix:  prefix,
		}
		dev, oErr := OpenDevice(t.Context(), cfg)
		if oErr == nil {
			_ = dev.Close()
			return fmt.Errorf("expected OpenDevice to fail with invalid IP, but succeeded")
		}

		if errors.Is(oErr, ErrPermission) || errors.Is(oErr, ErrNotSupported) {
			return oErr
		}

		// Verify the link was cleaned up and does not exist.
		_, getErr := netlink.LinkByName(ifName)
		if getErr == nil {
			return fmt.Errorf("link %q was left behind after OpenDevice failure", ifName)
		}
		return nil
	})

	if errors.Is(err, ErrPermission) || errors.Is(err, ErrNotSupported) {
		t.Skipf("skipping test: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestWireGuard_NamespaceCommunication(t *testing.T) {
	w1, err := newTestNSWorker()
	if err != nil {
		t.Skipf("skipping test: cannot create network namespace: %v", err)
	}
	defer w1.Close()

	w2, err := newTestNSWorker()
	if err != nil {
		t.Skipf("skipping test: cannot create second network namespace: %v", err)
	}
	defer w2.Close()

	// Create veth pair to link the two namespaces.
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth-test1"},
		PeerName:  "veth-test2",
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("skipping test: cannot create veth pair: %v", err)
	}
	defer func() {
		_ = netlink.LinkDel(veth)
	}()

	veth1, err := netlink.LinkByName("veth-test1")
	if err != nil {
		t.Fatalf("finding veth-test1: %v", err)
	}
	veth2, err := netlink.LinkByName("veth-test2")
	if err != nil {
		t.Fatalf("finding veth-test2: %v", err)
	}

	if err := netlink.LinkSetNsFd(veth1, int(w1.ns)); err != nil {
		t.Fatalf("moving veth-test1 to ns1: %v", err)
	}
	if err := netlink.LinkSetNsFd(veth2, int(w2.ns)); err != nil {
		t.Fatalf("moving veth-test2 to ns2: %v", err)
	}

	// Configure veth in ns1.
	if err := w1.Do(func() error {
		lo, _ := netlink.LinkByName("lo")
		if lo != nil {
			_ = netlink.LinkSetUp(lo)
		}
		link, err := netlink.LinkByName("veth-test1")
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   net.ParseIP("10.0.0.1"),
				Mask: net.CIDRMask(24, 32),
			},
		}); err != nil {
			return err
		}
		return netlink.LinkSetUp(link)
	}); err != nil {
		t.Fatalf("configuring veth in ns1: %v", err)
	}

	// Configure veth in ns2.
	if err := w2.Do(func() error {
		lo, _ := netlink.LinkByName("lo")
		if lo != nil {
			_ = netlink.LinkSetUp(lo)
		}
		link, err := netlink.LinkByName("veth-test2")
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   net.ParseIP("10.0.0.2"),
				Mask: net.CIDRMask(24, 32),
			},
		}); err != nil {
			return err
		}
		return netlink.LinkSetUp(link)
	}); err != nil {
		t.Fatalf("configuring veth in ns2: %v", err)
	}

	// Generate keys.
	priv1, pub1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey 1 failed: %v", err)
	}
	priv2, pub2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey 2 failed: %v", err)
	}

	_, prefix, err := net.ParseCIDR("fd00::/64")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}

	// Open wireguard device in ns1.
	var dev1 *Device
	var port1 int
	if err := w1.Do(func() error {
		var oErr error
		dev1, oErr = OpenDevice(t.Context(), Config{
			InterfaceName: "wg0",
			PrivateKey:    priv1,
			ListenPort:    0,
			DeviceAddress: net.ParseIP("fd00::1"),
			TunnelPrefix:  prefix,
		})
		if oErr != nil {
			return oErr
		}
		port1, oErr = dev1.Port()
		return oErr
	}); err != nil {
		if errors.Is(err, ErrPermission) || errors.Is(err, ErrNotSupported) {
			t.Skipf("skipping test: cannot create WireGuard link in ns1: %v", err)
		}
		t.Fatalf("opening device in ns1: %v", err)
	}
	defer func() {
		_ = w1.Do(func() error { return dev1.Close() })
	}()

	// Open wireguard device in ns2.
	var dev2 *Device
	var port2 int
	if err := w2.Do(func() error {
		var oErr error
		dev2, oErr = OpenDevice(t.Context(), Config{
			InterfaceName: "wg0",
			PrivateKey:    priv2,
			ListenPort:    0,
			DeviceAddress: net.ParseIP("fd00::2"),
			TunnelPrefix:  prefix,
		})
		if oErr != nil {
			return oErr
		}
		port2, oErr = dev2.Port()
		return oErr
	}); err != nil {
		if errors.Is(err, ErrPermission) || errors.Is(err, ErrNotSupported) {
			t.Skipf("skipping test: cannot create WireGuard link in ns2: %v", err)
		}
		t.Fatalf("opening device in ns2: %v", err)
	}
	defer func() {
		_ = w2.Do(func() error { return dev2.Close() })
	}()

	// Add peers.
	_, allowedPeer2, _ := net.ParseCIDR("fd00::2/128")
	if err := w1.Do(func() error {
		return dev1.AddPeer(Peer{
			PublicKey:  pub2,
			Endpoint:   &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: port2},
			AllowedIPs: []net.IPNet{*allowedPeer2},
		})
	}); err != nil {
		t.Fatalf("dev1 AddPeer: %v", err)
	}

	_, allowedPeer1, _ := net.ParseCIDR("fd00::1/128")
	if err := w2.Do(func() error {
		return dev2.AddPeer(Peer{
			PublicKey:  pub1,
			Endpoint:   &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: port1},
			AllowedIPs: []net.IPNet{*allowedPeer1},
		})
	}); err != nil {
		t.Fatalf("dev2 AddPeer: %v", err)
	}

	// Start TCP listener inside ns2 on tunnel address.
	var ln net.Listener
	if err := w2.Do(func() error {
		var lErr error
		ln, lErr = net.Listen("tcp", "[fd00::2]:9999")
		return lErr
	}); err != nil {
		t.Fatalf("Listen in ns2: %v", err)
	}
	defer ln.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverErrCh <- fmt.Errorf("server read: %w", err)
			return
		}
		if string(buf) != "ping!" {
			serverErrCh <- fmt.Errorf("unexpected server read: %q", string(buf))
			return
		}
		if _, err := conn.Write([]byte("pong!")); err != nil {
			serverErrCh <- fmt.Errorf("server write: %w", err)
			return
		}
		serverErrCh <- nil
	}()

	// Dial TCP from ns1 over tunnel.
	var conn net.Conn
	if err := w1.Do(func() error {
		var dErr error
		conn, dErr = net.DialTimeout("tcp", "[fd00::2]:9999", 5*time.Second)
		return dErr
	}); err != nil {
		t.Fatalf("Dial from ns1: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping!")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	resp := make([]byte, 5)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(resp) != "pong!" {
		t.Fatalf("unexpected client response: %q", string(resp))
	}
	_ = conn.Close()

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server handler error: %v", err)
	}

	// Remove peer from dev1.
	if err := w1.Do(func() error {
		return dev1.RemovePeer(pub2)
	}); err != nil {
		t.Fatalf("dev1 RemovePeer: %v", err)
	}

	// Verify new connection fails after peer removal.
	if err := w1.Do(func() error {
		failConn, dErr := net.DialTimeout("tcp", "[fd00::2]:9999", 500*time.Millisecond)
		if dErr == nil {
			failConn.Close()
			return fmt.Errorf("expected connection to fail after removing peer, but succeeded")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Compile-time interface checks.
var _ = wgtypes.Key{}

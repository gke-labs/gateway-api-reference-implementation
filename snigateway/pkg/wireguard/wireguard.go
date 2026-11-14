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
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Key is a 32-byte WireGuard key.
type Key = wgtypes.Key

var (
	// ErrPermission indicates that the process lacks CAP_NET_ADMIN.
	ErrPermission = errors.New("process lacks CAP_NET_ADMIN")
	// ErrNotSupported indicates that the kernel has no WireGuard support.
	ErrNotSupported = errors.New("kernel has no WireGuard support")
)

// GenerateKey returns a new private key and its corresponding public key.
func GenerateKey() (Key, Key, error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Key{}, Key{}, fmt.Errorf("generating private key: %w", err)
	}
	return priv, priv.PublicKey(), nil
}

// Config specifies the configuration for opening a kernel WireGuard device.
type Config struct {
	InterfaceName string
	Name          string // alias for InterfaceName
	PrivateKey    Key
	ListenPort    int // zero lets the kernel choose
	DeviceAddress net.IP
	Address       net.IP // alias for DeviceAddress
	TunnelPrefix  *net.IPNet
}

// Peer represents a WireGuard peer configuration.
type Peer struct {
	PublicKey                   Key
	Endpoint                    *net.UDPAddr
	AllowedIPs                  []net.IPNet
	PersistentKeepalive         *time.Duration
	PersistentKeepaliveInterval *time.Duration // alias for PersistentKeepalive
}

// Device manages a kernel WireGuard network interface.
type Device struct {
	name   string
	link   netlink.Link
	client *wgctrl.Client

	mu     sync.Mutex
	closed bool
}

// OpenDevice creates a link of type wireguard over rtnetlink, sets the private key
// and UDP listen port, assigns the device's address inside the tunnel prefix,
// brings the link up, and adds the route for the prefix.
// If a later step fails, any created link is cleaned up before returning.
func OpenDevice(ctx context.Context, config Config) (dev *Device, retErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	name := config.InterfaceName
	if name == "" {
		name = config.Name
	}
	if name == "" {
		return nil, fmt.Errorf("interface name is required")
	}
	devAddr := config.DeviceAddress
	if len(devAddr) == 0 {
		devAddr = config.Address
	}
	if len(devAddr) == 0 {
		return nil, fmt.Errorf("device address is required")
	}
	if config.TunnelPrefix == nil {
		return nil, fmt.Errorf("tunnel prefix is required")
	}

	var link netlink.Link = &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(link); err != nil {
		if isPermissionError(err) {
			return nil, fmt.Errorf("%w: %w", ErrPermission, err)
		}
		if isNotSupportedError(err) {
			return nil, fmt.Errorf("%w: %w", ErrNotSupported, err)
		}
		return nil, fmt.Errorf("creating wireguard link %q: %w", name, err)
	}

	var success bool
	defer func() {
		if !success {
			if delErr := netlink.LinkDel(link); delErr != nil {
				retErr = errors.Join(retErr, delErr)
			}
		}
	}()

	liveLink, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("getting link %q: %w", name, err)
	}
	link = liveLink

	wgClient, err := wgctrl.New()
	if err != nil {
		if isPermissionError(err) {
			return nil, fmt.Errorf("%w: %w", ErrPermission, err)
		}
		if isNotSupportedError(err) || errors.Is(err, syscall.ENOENT) {
			return nil, fmt.Errorf("%w: %w", ErrNotSupported, err)
		}
		return nil, fmt.Errorf("opening wgctrl client: %w", err)
	}
	defer func() {
		if !success {
			if closeErr := wgClient.Close(); closeErr != nil {
				retErr = errors.Join(retErr, closeErr)
			}
		}
	}()

	wgCfg := wgtypes.Config{PrivateKey: &config.PrivateKey}
	if config.ListenPort != 0 {
		wgCfg.ListenPort = &config.ListenPort
	}
	if err := wgClient.ConfigureDevice(name, wgCfg); err != nil {
		return nil, fmt.Errorf("configuring wireguard device %q: %w", name, err)
	}

	addr := &netlink.Addr{IPNet: &net.IPNet{IP: devAddr, Mask: config.TunnelPrefix.Mask}}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return nil, fmt.Errorf("assigning address %s to %q: %w", addr.IPNet, name, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("bringing link %q up: %w", name, err)
	}

	dstNet := &net.IPNet{
		IP:   config.TunnelPrefix.IP.Mask(config.TunnelPrefix.Mask),
		Mask: config.TunnelPrefix.Mask,
	}
	route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dstNet}
	if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("adding prefix route for %s on %q: %w", dstNet, name, err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	success = true
	return &Device{name: name, link: link, client: wgClient}, nil
}

// AddPeer adds or updates a WireGuard peer on the device.
func (d *Device) AddPeer(peer Peer) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return net.ErrClosed
	}

	keepalive := peer.PersistentKeepalive
	if keepalive == nil {
		keepalive = peer.PersistentKeepaliveInterval
	}
	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   peer.PublicKey,
			Endpoint:                    peer.Endpoint,
			AllowedIPs:                  peer.AllowedIPs,
			ReplaceAllowedIPs:           true,
			PersistentKeepaliveInterval: keepalive,
		}},
	}
	if err := d.client.ConfigureDevice(d.name, cfg); err != nil {
		return fmt.Errorf("adding peer %s to %q: %w", peer.PublicKey, d.name, err)
	}
	return nil
}

// RemovePeer removes a WireGuard peer from the device by its public key.
func (d *Device) RemovePeer(publicKey Key) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return net.ErrClosed
	}

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey: publicKey,
			Remove:    true,
		}},
	}
	if err := d.client.ConfigureDevice(d.name, cfg); err != nil {
		return fmt.Errorf("removing peer %s from %q: %w", publicKey, d.name, err)
	}
	return nil
}

// Close closes the WireGuard client and deletes the link.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true

	var errs []error
	if d.client != nil {
		if err := d.client.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := netlink.LinkDel(d.link); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Name returns the interface name of the device.
func (d *Device) Name() string {
	return d.name
}

// Port returns the UDP listen port of the WireGuard device.
func (d *Device) Port() (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, net.ErrClosed
	}
	dev, err := d.client.Device(d.name)
	if err != nil {
		return 0, fmt.Errorf("getting wireguard device %q: %w", d.name, err)
	}
	return dev.ListenPort, nil
}

// ListenPort is an alias for Port.
func (d *Device) ListenPort() (int, error) {
	return d.Port()
}

func isPermissionError(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
		strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "permission denied")
}

func isNotSupportedError(err error) bool {
	return errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENODEV) ||
		errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.ESOCKTNOSUPPORT) ||
		strings.Contains(err.Error(), "operation not supported") || strings.Contains(err.Error(), "not supported") ||
		strings.Contains(err.Error(), "no such device") || strings.Contains(err.Error(), "unknown device type")
}

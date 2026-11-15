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
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Key{}, Key{}, fmt.Errorf("generating private key: %w", err)
	}
	return privateKey, privateKey.PublicKey(), nil
}

// ParseKey parses a base64-encoded WireGuard key.
func ParseKey(encodedKey string) (Key, error) {
	return wgtypes.ParseKey(encodedKey)
}

// Config specifies the configuration for opening a kernel WireGuard device.
type Config struct {
	// InterfaceName is the name of the network interface to create (e.g. "wg0").
	InterfaceName string
	// PrivateKey is the WireGuard private key for the device.
	PrivateKey Key
	// ListenPort is the UDP port to listen on, or 0 to let the kernel choose.
	ListenPort int
	// DeviceAddress is the IP address assigned to the device inside the tunnel.
	DeviceAddress net.IP
	// TunnelPrefix is the network prefix and route for the tunnel.
	TunnelPrefix *net.IPNet
}

// Peer represents a WireGuard peer configuration.
type Peer struct {
	// PublicKey is the WireGuard public key of the remote peer.
	PublicKey Key
	// Endpoint is the UDP address of the remote peer, or nil if not yet known.
	Endpoint *net.UDPAddr
	// AllowedIPs specifies the IP networks routed to and accepted from this peer.
	AllowedIPs []net.IPNet
	// PersistentKeepalive is the interval between keepalive packets, or nil to disable.
	PersistentKeepalive *time.Duration
}

// Device manages a kernel WireGuard network interface.
type Device struct {
	// name is the network interface name (e.g. "wg0").
	name string
	// link is the netlink handle to the network interface.
	link netlink.Link
	// client is the WireGuard control client for device and peer configuration.
	client *wgctrl.Client

	// mu guards closed and serializes device configuration changes.
	mu sync.Mutex
	// closed indicates whether the device has been closed.
	closed bool
}

// OpenDevice creates a link of type wireguard over rtnetlink, sets the private key
// and UDP listen port, assigns the device's address inside the tunnel prefix,
// brings the link up, and adds the route for the prefix.
//
// The netlink calls can't be interrupted, so the context is checked once before
// the first call. If a later step fails, any created link is cleaned up before
// returning. Close must run in the network namespace that opened the device.
func OpenDevice(ctx context.Context, configuration Config) (device *Device, returnError error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	interfaceName := configuration.InterfaceName
	if len(interfaceName) == 0 {
		return nil, fmt.Errorf("interface name is required")
	}
	if len(interfaceName) > 15 {
		return nil, fmt.Errorf("interface name %q exceeds 15 bytes", interfaceName)
	}
	deviceAddress := configuration.DeviceAddress
	if len(deviceAddress) == 0 {
		return nil, fmt.Errorf("device address is required")
	}
	if configuration.TunnelPrefix == nil {
		return nil, fmt.Errorf("tunnel prefix is required")
	}

	var link netlink.Link = &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: interfaceName}}
	if err := netlink.LinkAdd(link); err != nil {
		if isPermissionError(err) {
			return nil, fmt.Errorf("%w: %w", ErrPermission, err)
		}
		if isNotSupportedError(err) {
			return nil, fmt.Errorf("%w: %w", ErrNotSupported, err)
		}
		return nil, fmt.Errorf("creating wireguard link %q: %w", interfaceName, err)
	}

	var success bool
	defer func() {
		if !success {
			if deleteErr := netlink.LinkDel(link); deleteErr != nil {
				returnError = errors.Join(returnError, deleteErr)
			}
		}
	}()

	liveLink, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("getting link %q: %w", interfaceName, err)
	}
	link = liveLink

	wgClient, err := wgctrl.New()
	if err != nil {
		if isPermissionError(err) {
			return nil, fmt.Errorf("%w: %w", ErrPermission, err)
		}
		if isNotSupportedError(err) {
			return nil, fmt.Errorf("%w: %w", ErrNotSupported, err)
		}
		return nil, fmt.Errorf("opening wgctrl client: %w", err)
	}
	defer func() {
		if !success {
			if closeErr := wgClient.Close(); closeErr != nil {
				returnError = errors.Join(returnError, closeErr)
			}
		}
	}()

	wireguardConfig := wgtypes.Config{PrivateKey: &configuration.PrivateKey}
	if configuration.ListenPort != 0 {
		wireguardConfig.ListenPort = &configuration.ListenPort
	}
	if err := wgClient.ConfigureDevice(interfaceName, wireguardConfig); err != nil {
		return nil, fmt.Errorf("configuring wireguard device %q: %w", interfaceName, err)
	}

	address := &netlink.Addr{IPNet: &net.IPNet{IP: deviceAddress, Mask: configuration.TunnelPrefix.Mask}}
	if err := netlink.AddrAdd(link, address); err != nil {
		return nil, fmt.Errorf("assigning address %s to %q: %w", address.IPNet, interfaceName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("bringing link %q up: %w", interfaceName, err)
	}

	destinationNetwork := &net.IPNet{
		IP:   configuration.TunnelPrefix.IP.Mask(configuration.TunnelPrefix.Mask),
		Mask: configuration.TunnelPrefix.Mask,
	}
	route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: destinationNetwork}
	if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("adding prefix route for %s on %q: %w", destinationNetwork, interfaceName, err)
	}

	success = true
	return &Device{name: interfaceName, link: link, client: wgClient}, nil
}

// AddPeer adds or updates a WireGuard peer on the device.
func (d *Device) AddPeer(peer Peer) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return net.ErrClosed
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey:                   peer.PublicKey,
		Endpoint:                    peer.Endpoint,
		AllowedIPs:                  peer.AllowedIPs,
		ReplaceAllowedIPs:           true,
		PersistentKeepaliveInterval: peer.PersistentKeepalive,
	}
	deviceConfig := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}
	if err := d.client.ConfigureDevice(d.name, deviceConfig); err != nil {
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

	peerConfig := wgtypes.PeerConfig{
		PublicKey: publicKey,
		Remove:    true,
	}
	deviceConfig := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}
	if err := d.client.ConfigureDevice(d.name, deviceConfig); err != nil {
		return fmt.Errorf("removing peer %s from %q: %w", publicKey, d.name, err)
	}
	return nil
}

// Close closes the WireGuard client and deletes the link.
// It must run in the network namespace that opened the device.
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
	wireguardDevice, err := d.client.Device(d.name)
	if err != nil {
		return 0, fmt.Errorf("getting wireguard device %q: %w", d.name, err)
	}
	return wireguardDevice.ListenPort, nil
}

func isPermissionError(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

func isNotSupportedError(err error) bool {
	// netlink.ErrNotImplemented is returned by vishvananda/netlink stubs on non-Linux platforms (e.g. macOS).
	return errors.Is(err, netlink.ErrNotImplemented) ||
		errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.ENODEV) ||
		errors.Is(err, syscall.ENOSYS) ||
		errors.Is(err, syscall.ESOCKTNOSUPPORT) ||
		errors.Is(err, syscall.ENOENT)
}

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

package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/quic-go/quic-go"
	"k8s.io/klog/v2"
)

func closeConn(c io.Closer) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		klog.V(2).Infof("failed to close: %v", err)
	}
}

// Client is a client for communicating with the snigateway frontend mTLS API and reverse tunnels.
type Client struct {
	serverAddr       string
	internalHostname string
	tlsConfig        *tls.Config
	httpClient       *http.Client
	dialFunc         func(ctx context.Context, network, addr string) (net.Conn, error)
	quicDialFunc     func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error)
	tokenFile        string
	tokenProvider    func() (string, error)
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithInternalHostname overrides the default internal hostname ("snigateway.internal").
func WithInternalHostname(hostname string) ClientOption {
	return func(c *Client) {
		c.internalHostname = hostname
	}
}

// WithDialFunc sets a custom network dialer function for establishing TCP connections.
func WithDialFunc(fn func(ctx context.Context, network, addr string) (net.Conn, error)) ClientOption {
	return func(c *Client) {
		c.dialFunc = fn
	}
}

// WithQUICDialFunc sets a custom dialer function for establishing QUIC connections.
func WithQUICDialFunc(fn func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error)) ClientOption {
	return func(c *Client) {
		c.quicDialFunc = fn
	}
}

// WithTokenFile configures the client to authenticate with a token file (re-read on each call).
func WithTokenFile(path string) ClientOption {
	return func(c *Client) {
		c.tokenFile = path
	}
}

// WithTokenProvider configures the client with a dynamic token provider function.
func WithTokenProvider(provider func() (string, error)) ClientOption {
	return func(c *Client) {
		c.tokenProvider = provider
	}
}

// GetToken reads and returns the current authentication token, re-reading the token file if configured.
func (c *Client) GetToken() (string, error) {
	if c.tokenProvider != nil {
		return c.tokenProvider()
	}
	if c.tokenFile != "" {
		data, err := os.ReadFile(c.tokenFile)
		if err != nil {
			return "", fmt.Errorf("reading token file %s: %w", c.tokenFile, err)
		}
		token := strings.TrimSpace(string(data))
		if token == "" {
			return "", fmt.Errorf("token file %s is empty", c.tokenFile)
		}
		return token, nil
	}
	return "", nil
}

// ServerAddr returns the configured server address.
func (c *Client) ServerAddr() string {
	return c.serverAddr
}

// NewClient creates a new Client connecting to serverAddr using mTLS.
func NewClient(serverAddr string, tlsConfig *tls.Config, opts ...ClientOption) *Client {
	c := &Client{
		serverAddr:       serverAddr,
		internalHostname: api.DefaultInternalHostname,
		tlsConfig:        tlsConfig.Clone(),
	}
	for _, opt := range opts {
		opt(c)
	}

	if c.tlsConfig.ServerName == "" {
		c.tlsConfig.ServerName = c.internalHostname
	}

	transport := &http.Transport{
		TLSClientConfig: c.tlsConfig,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if c.dialFunc != nil {
				rawConn, err := c.dialFunc(ctx, "tcp", c.serverAddr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(rawConn, c.tlsConfig)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					closeConn(rawConn)
					return nil, err
				}
				return tlsConn, nil
			}
			dialer := &tls.Dialer{
				NetDialer: &net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 15 * time.Second,
				},
				Config: c.tlsConfig,
			}
			return dialer.DialContext(ctx, "tcp", c.serverAddr)
		},
	}

	c.httpClient = &http.Client{
		Transport: transport,
	}

	return c
}

// StartSession opens a long-lived backend session with the frontend.
// It returns the assigned sessionID, a channel that receives an error if the session drops, and any startup error.
func (c *Client) StartSession(ctx context.Context) (string, <-chan error, error) {
	url := fmt.Sprintf("https://%s/v1/session", c.internalHostname)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, fmt.Errorf("creating session request: %w", err)
	}

	token, err := c.GetToken()
	if err != nil {
		return "", nil, fmt.Errorf("resolving token for session: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("opening session: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		closeConn(resp.Body)
		if err != nil {
			return "", nil, fmt.Errorf("session failed with status %d (failed to read body: %w)", resp.StatusCode, err)
		}
		return "", nil, fmt.Errorf("session failed with status %d: %s", resp.StatusCode, string(body))
	}

	reader := bufio.NewReader(resp.Body)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		closeConn(resp.Body)
		return "", nil, fmt.Errorf("reading session response: %w", err)
	}

	var sessResp api.SessionResponse
	if err := json.Unmarshal(bytes.TrimSpace(line), &sessResp); err != nil {
		closeConn(resp.Body)
		return "", nil, fmt.Errorf("decoding session response: %w", err)
	}

	if sessResp.SessionID == "" {
		closeConn(resp.Body)
		return "", nil, errors.New("empty session ID received from frontend")
	}

	errCh := make(chan error, 1)
	go func() {
		defer closeConn(resp.Body)
		buf := make([]byte, 1024)
		for {
			_, err := resp.Body.Read(buf)
			if err != nil {
				if errors.Is(err, io.EOF) || ctx.Err() != nil {
					errCh <- ctx.Err()
				} else {
					errCh <- err
				}
				return
			}
		}
	}()

	return sessResp.SessionID, errCh, nil
}

// Register registers the given hostnames with the frontend server for the specified session.
func (c *Client) Register(ctx context.Context, sessionID string, hostnames []string) (*api.RegistrationResponse, error) {
	token, err := c.GetToken()
	if err != nil {
		return nil, fmt.Errorf("resolving token for registration: %w", err)
	}

	reqBody, err := json.Marshal(api.RegistrationRequest{
		Type:      "registration",
		Hostnames: hostnames,
		Token:     token,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling registration request: %w", err)
	}

	url := fmt.Sprintf("https://%s/v1/registration", c.internalHostname)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("creating registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(api.HeaderSessionID, sessionID)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing registration request: %w", err)
	}
	defer closeConn(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("registration failed with status %d (failed to read body: %w)", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	var regResp api.RegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return nil, fmt.Errorf("decoding registration response: %w", err)
	}

	return &regResp, nil
}

// DialTunnel dials an mTLS pooled tunnel connection to the frontend for the given sessionID.
func (c *Client) DialTunnel(ctx context.Context, sessionID string) (net.Conn, error) {
	return c.dialTunnelWithProtocol(ctx, sessionID, api.UpgradeProtocol)
}

// DialH2Tunnel dials an mTLS HTTP/2 reverse tunnel connection to the frontend for the given sessionID.
func (c *Client) DialH2Tunnel(ctx context.Context, sessionID string) (net.Conn, error) {
	return c.dialTunnelWithProtocol(ctx, sessionID, api.UpgradeProtocolH2)
}

func (c *Client) dialTunnelWithProtocol(ctx context.Context, sessionID, upgradeProtocol string) (net.Conn, error) {
	var tlsConn *tls.Conn
	if c.dialFunc != nil {
		rawConn, err := c.dialFunc(ctx, "tcp", c.serverAddr)
		if err != nil {
			return nil, fmt.Errorf("dialing frontend: %w", err)
		}
		tlsConn = tls.Client(rawConn, c.tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			closeConn(rawConn)
			return nil, fmt.Errorf("handshake frontend mTLS: %w", err)
		}
	} else {
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{
				KeepAlive: 15 * time.Second,
			},
			Config: c.tlsConfig,
		}

		conn, err := dialer.DialContext(ctx, "tcp", c.serverAddr)
		if err != nil {
			return nil, fmt.Errorf("dialing frontend mTLS: %w", err)
		}

		var ok bool
		tlsConn, ok = conn.(*tls.Conn)
		if !ok {
			closeConn(conn)
			return nil, errors.New("expected tls.Conn")
		}
	}

	urlPath := "/v1/tunnel"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlPath, nil)
	if err != nil {
		closeConn(tlsConn)
		return nil, fmt.Errorf("creating tunnel upgrade request: %w", err)
	}
	req.Host = c.internalHostname
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", upgradeProtocol)
	req.Header.Set(api.HeaderSessionID, sessionID)

	token, err := c.GetToken()
	if err != nil {
		closeConn(tlsConn)
		return nil, fmt.Errorf("resolving token for tunnel dial: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	if err := req.Write(tlsConn); err != nil {
		closeConn(tlsConn)
		return nil, fmt.Errorf("writing upgrade request: %w", err)
	}

	bufReader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(bufReader, req)
	if err != nil {
		closeConn(tlsConn)
		return nil, fmt.Errorf("reading upgrade response: %w", err)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, err := io.ReadAll(resp.Body)
		closeConn(tlsConn)
		if err != nil {
			return nil, fmt.Errorf("unexpected upgrade status %d (failed to read body: %w)", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("unexpected upgrade status %d: %s", resp.StatusCode, string(body))
	}

	if !strings.EqualFold(resp.Header.Get("Upgrade"), upgradeProtocol) &&
		!strings.EqualFold(resp.Header.Get("Upgrade"), api.UpgradeProtocol) &&
		!strings.Contains(strings.ToLower(resp.Header.Get("Connection")), "upgrade") {
		closeConn(tlsConn)
		return nil, fmt.Errorf("invalid upgrade response headers: Upgrade=%s", resp.Header.Get("Upgrade"))
	}

	if bufReader.Buffered() > 0 {
		buffered := make([]byte, bufReader.Buffered())
		if _, err := io.ReadFull(bufReader, buffered); err != nil {
			closeConn(tlsConn)
			return nil, fmt.Errorf("reading buffered handshake bytes: %w", err)
		}
		return &bufferedClientConn{
			Conn:     tlsConn,
			buffered: buffered,
		}, nil
	}

	return tlsConn, nil
}

type bufferedClientConn struct {
	net.Conn
	buffered  []byte
	bufOffset int
}

func (c *bufferedClientConn) Read(b []byte) (int, error) {
	if c.buffered != nil {
		n := copy(b, c.buffered[c.bufOffset:])
		c.bufOffset += n
		if c.bufOffset >= len(c.buffered) {
			c.buffered = nil
		}
		return n, nil
	}
	return c.Conn.Read(b)
}

func (c *bufferedClientConn) ConnectionState() tls.ConnectionState {
	if tc, ok := c.Conn.(*tls.Conn); ok {
		return tc.ConnectionState()
	}
	return tls.ConnectionState{}
}

// DialQUIC dials an mTLS QUIC connection to the frontend server.
func (c *Client) DialQUIC(ctx context.Context) (*quic.Conn, error) {
	quicTLS := c.tlsConfig.Clone()
	if c.internalHostname != "" {
		quicTLS.ServerName = c.internalHostname
	}
	quicTLS.NextProtos = []string{api.TunnelALPN}
	if c.quicDialFunc != nil {
		return c.quicDialFunc(ctx, c.serverAddr, quicTLS, api.DefaultQUICConfig())
	}
	return quic.DialAddr(ctx, c.serverAddr, quicTLS, api.DefaultQUICConfig())
}

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
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"k8s.io/klog/v2"
)

// ErrWireGuardDisabled indicates that the frontend server returned HTTP 404 Not Found
// during WireGuard key exchange. This occurs when the frontend has WireGuard disabled,
// or when the session is unknown or has already ended.
var ErrWireGuardDisabled = errors.New("frontend wireguard is disabled")

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

// maxWireGuardResponseBytes limits the size of responses read during WireGuard key exchange.
const maxWireGuardResponseBytes = 64 * 1024

// ExchangeWireGuard registers the client WireGuard public key with the frontend for the session
// and returns the frontend's WireGuard configuration.
// If the frontend has WireGuard disabled or the session is unknown (returns HTTP 404), it returns ErrWireGuardDisabled.
func (client *Client) ExchangeWireGuard(ctx context.Context, sessionID, publicKey string) (*api.WireGuardResponse, error) {
	token, err := client.GetToken()
	if err != nil {
		return nil, fmt.Errorf("resolving token for wireguard exchange: %w", err)
	}

	requestBody, err := json.Marshal(api.WireGuardRequest{
		PublicKey: publicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling wireguard request: %w", err)
	}

	endpointURL := fmt.Sprintf("https://%s/v1/sessions/%s/wireguard", client.internalHostname, url.PathEscape(sessionID))
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpointURL, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("creating wireguard request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(api.HeaderSessionID, sessionID)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("performing wireguard exchange request: %w", err)
	}
	defer closeConn(response.Body)

	if response.StatusCode == http.StatusNotFound {
		return nil, ErrWireGuardDisabled
	}

	limitedReader := io.LimitReader(response.Body, maxWireGuardResponseBytes)
	if response.StatusCode != http.StatusOK {
		body, err := io.ReadAll(limitedReader)
		if err != nil {
			return nil, fmt.Errorf("wireguard exchange failed with status %d (failed to read body: %w)", response.StatusCode, err)
		}
		return nil, fmt.Errorf("wireguard exchange failed with status %d: %s", response.StatusCode, string(body))
	}

	var wireguardResponse api.WireGuardResponse
	if err := json.NewDecoder(limitedReader).Decode(&wireguardResponse); err != nil {
		return nil, fmt.Errorf("decoding wireguard response: %w", err)
	}

	return &wireguardResponse, nil
}

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
	"strings"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/quic-go/quic-go"
)

// Client is a client for communicating with the snigateway frontend mTLS API and reverse tunnels.
type Client struct {
	serverAddr       string
	internalHostname string
	tlsConfig        *tls.Config
	httpClient       *http.Client
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithInternalHostname overrides the default internal hostname ("snigateway.internal").
func WithInternalHostname(hostname string) ClientOption {
	return func(c *Client) {
		c.internalHostname = hostname
	}
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
			dialer := &tls.Dialer{
				NetDialer: &net.Dialer{
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

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("opening session: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return "", nil, fmt.Errorf("session failed with status %d: %s", resp.StatusCode, string(body))
	}

	reader := bufio.NewReader(resp.Body)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		_ = resp.Body.Close()
		return "", nil, fmt.Errorf("reading session response: %w", err)
	}

	var sessResp api.SessionResponse
	if err := json.Unmarshal(bytes.TrimSpace(line), &sessResp); err != nil {
		_ = resp.Body.Close()
		return "", nil, fmt.Errorf("decoding session response: %w", err)
	}

	if sessResp.SessionID == "" {
		_ = resp.Body.Close()
		return "", nil, errors.New("empty session ID received from frontend")
	}

	errCh := make(chan error, 1)
	go func() {
		defer resp.Body.Close()
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
	reqBody, err := json.Marshal(api.RegistrationRequest{
		Hostnames: hostnames,
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

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing registration request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
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
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			KeepAlive: 15 * time.Second,
		},
		Config: c.tlsConfig,
	}

	tlsConn, err := dialer.DialContext(ctx, "tcp", c.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("dialing frontend mTLS: %w", err)
	}

	urlPath := "/v1/tunnel"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlPath, nil)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("creating tunnel upgrade request: %w", err)
	}
	req.Host = c.internalHostname
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", api.UpgradeProtocol)
	req.Header.Set(api.HeaderSessionID, sessionID)

	if err := req.Write(tlsConn); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("writing upgrade request: %w", err)
	}

	bufReader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(bufReader, req)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("reading upgrade response: %w", err)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(resp.Body)
		_ = tlsConn.Close()
		return nil, fmt.Errorf("unexpected upgrade status %d: %s", resp.StatusCode, string(body))
	}

	if !strings.EqualFold(resp.Header.Get("Upgrade"), api.UpgradeProtocol) && !strings.Contains(strings.ToLower(resp.Header.Get("Connection")), "upgrade") {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("invalid upgrade response headers: Upgrade=%s", resp.Header.Get("Upgrade"))
	}

	if bufReader.Buffered() > 0 {
		return &bufferedClientConn{
			Conn:   tlsConn,
			reader: bufReader,
		}, nil
	}

	return tlsConn, nil
}

type bufferedClientConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedClientConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// DialQUIC dials an mTLS QUIC connection to the frontend server.
func (c *Client) DialQUIC(ctx context.Context) (*quic.Conn, error) {
	quicTLS := c.tlsConfig.Clone()
	if c.internalHostname != "" {
		quicTLS.ServerName = c.internalHostname
	}
	quicTLS.NextProtos = []string{api.TunnelALPN}
	return quic.DialAddr(ctx, c.serverAddr, quicTLS, api.DefaultQUICConfig())
}

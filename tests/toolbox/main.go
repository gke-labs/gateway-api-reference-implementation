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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: toolbox <server|client> [args]")
	}

	mode := os.Args[1]
	switch mode {
	case "server":
		runServer()
	case "client":
		runClientCLI(os.Args[2:])
	default:
		log.Fatalf("Unknown mode: %s", mode)
	}
}

func parseHostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func closeBody(c io.Closer) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil {
		log.Printf("Failed to close body: %v", err)
	}
}

func runServer() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request: %s %s %s", r.Method, r.URL.Path, r.Host)
		w.Header().Set("Content-Type", "application/json")

		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Failed to read body: %v", err)
			http.Error(w, "Failed to read body", http.StatusInternalServerError)
			return
		}

		resp := map[string]any{
			"headers":  headers,
			"body":     string(body),
			"method":   r.Method,
			"path":     r.URL.Path,
			"hostname": r.Host,
		}

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("Failed to encode response: %v", err)
			return
		}
	})

	log.Printf("Starting echo server on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func runClientCLI(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	connectTo := fs.String("connect-to", "", "Address to connect to (e.g. host:port or ip:port), overriding target URL host")
	sni := fs.String("sni", "", "SNI server name to send during TLS handshake")
	hostHeader := fs.String("host", "", "HTTP Host header")
	caCertPath := fs.String("ca-cert", "", "Path to CA cert PEM file to trust")
	insecure := fs.Bool("insecure", false, "Skip TLS verification")
	expectFail := fs.Bool("expect-fail", false, "Expect request / TLS connection to fail/be closed")
	http3Flag := fs.Bool("http3", false, "Use HTTP/3 (QUIC) protocol")
	tlsHandshakeOnly := fs.Bool("tls-handshake-only", false, "Only perform TLS handshake and verify peer certificates")
	timeout := fs.Duration("timeout", 10*time.Second, "Request timeout")
	retries := fs.Int("retries", 30, "Number of retries for request on failure")
	retryInterval := fs.Duration("retry-interval", 1*time.Second, "Interval between retries")

	if err := fs.Parse(args); err != nil {
		log.Fatalf("Failed to parse client flags: %v", err)
	}

	remaining := fs.Args()
	if len(remaining) < 1 {
		log.Fatal("Usage: toolbox client [flags] <url> [hostname]")
	}

	targetURL := remaining[0]
	if len(remaining) >= 2 && *hostHeader == "" {
		*hostHeader = remaining[1]
	}

	var rootCAs *x509.CertPool
	if *caCertPath != "" {
		caData, err := os.ReadFile(*caCertPath)
		if err != nil {
			log.Fatalf("Failed to read CA cert from %s: %v", *caCertPath, err)
		}
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(caData) {
			log.Fatalf("Failed to append CA cert from %s", *caCertPath)
		}
	}

	if *tlsHandshakeOnly {
		serverName := *sni
		if serverName == "" {
			serverName = parseHostname(targetURL)
		}
		tlsConfig := &tls.Config{
			ServerName:         serverName,
			RootCAs:            rootCAs,
			InsecureSkipVerify: *insecure,
		}
		u, err := url.Parse(targetURL)
		if err != nil {
			log.Fatalf("Failed to parse target URL %q: %v", targetURL, err)
		}
		dialAddr := u.Host
		if !strings.Contains(dialAddr, ":") {
			if u.Scheme == "https" {
				dialAddr += ":443"
			} else {
				dialAddr += ":80"
			}
		}
		if *connectTo != "" {
			dialAddr = *connectTo
		}

		maxAttempts := 1
		if !*expectFail && *retries > 0 {
			maxAttempts = *retries + 1
		}

		var lastErr error
		var capturedCerts []*x509.Certificate
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			if attempt > 1 {
				time.Sleep(*retryInterval)
				log.Printf("Retrying TLS handshake (attempt %d/%d)...", attempt, maxAttempts)
			}
			dialer := &net.Dialer{Timeout: *timeout}
			conn, err := tls.DialWithDialer(dialer, "tcp", dialAddr, tlsConfig)
			if err != nil {
				lastErr = err
				if *expectFail {
					fmt.Printf("TLS connection failed as expected: %v\n", err)
					return
				}
				continue
			}
			capturedCerts = conn.ConnectionState().PeerCertificates
			if closeErr := conn.Close(); closeErr != nil {
				log.Printf("Failed to close TLS connection: %v", closeErr)
			}
			lastErr = nil
			break
		}
		if *expectFail {
			log.Fatalf("Expected TLS connection to fail, but succeeded")
		}
		if lastErr != nil {
			log.Fatalf("TLS handshake failed: %v", lastErr)
		}
		fmt.Println("TLS handshake succeeded")
		if len(capturedCerts) > 0 {
			leaf := capturedCerts[0]
			fmt.Printf("PeerCertSubjectCN: %s\n", leaf.Subject.CommonName)
			fmt.Printf("PeerCertDNSNames: %s\n", strings.Join(leaf.DNSNames, ","))
			var uris []string
			for _, u := range leaf.URIs {
				uris = append(uris, u.String())
			}
			fmt.Printf("PeerCertURIs: %s\n", strings.Join(uris, ","))
			fmt.Printf("PeerCertIssuerCN: %s\n", leaf.Issuer.CommonName)
		}
		return
	}

	var capturedPeerCerts []*x509.Certificate
	var transport http.RoundTripper

	if *http3Flag {
		serverName := *sni
		if serverName == "" {
			serverName = parseHostname(targetURL)
		}
		tlsConfig := &tls.Config{
			ServerName:         serverName,
			RootCAs:            rootCAs,
			InsecureSkipVerify: *insecure,
		}
		h3Transport := &http3.Transport{
			TLSClientConfig: tlsConfig,
		}
		if *connectTo != "" {
			h3Transport.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				return quic.DialAddrEarly(ctx, *connectTo, tlsCfg, cfg)
			}
		}
		transport = h3Transport
	} else {
		transport = &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialAddr := addr
				if *connectTo != "" {
					dialAddr = *connectTo
				}
				serverName := *sni
				if serverName == "" {
					serverName = parseHostname(targetURL)
				}
				tlsConfig := &tls.Config{
					ServerName:         serverName,
					RootCAs:            rootCAs,
					InsecureSkipVerify: *insecure,
				}
				dialer := &net.Dialer{Timeout: *timeout}
				conn, err := tls.DialWithDialer(dialer, network, dialAddr, tlsConfig)
				if err != nil {
					return nil, err
				}
				cs := conn.ConnectionState()
				capturedPeerCerts = cs.PeerCertificates
				return conn, nil
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialAddr := addr
				if *connectTo != "" {
					dialAddr = *connectTo
				}
				dialer := &net.Dialer{Timeout: *timeout}
				return dialer.DialContext(ctx, network, dialAddr)
			},
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   *timeout,
	}

	log.Printf("Sending request to %s (Host: %s, ConnectTo: %s, SNI: %s, HTTP3: %v)", targetURL, *hostHeader, *connectTo, *sni, *http3Flag)

	var resp *http.Response
	var lastErr error

	maxAttempts := 1
	if !*expectFail && *retries > 0 {
		maxAttempts = *retries + 1
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			time.Sleep(*retryInterval)
			log.Printf("Retrying request (attempt %d/%d)...", attempt, maxAttempts)
		}

		capturedPeerCerts = nil
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}
		if *hostHeader != "" {
			req.Host = *hostHeader
		}

		resp, err = client.Do(req)
		if *expectFail {
			if err != nil {
				fmt.Printf("Connection rejected as expected: %v\n", err)
				return
			}
			closeBody(resp.Body)
			log.Fatalf("Expected connection to fail, but request succeeded with status %s", resp.Status)
		}

		if err == nil {
			if resp.StatusCode == http.StatusOK {
				lastErr = nil
				break
			}
			// If not 200 and we have attempts remaining, retry
			if attempt < maxAttempts {
				closeBody(resp.Body)
				lastErr = fmt.Errorf("unexpected status: %s", resp.Status)
				continue
			}
			lastErr = nil
			break
		}

		lastErr = err
	}

	if lastErr != nil {
		log.Fatalf("Request failed: %v", lastErr)
	}
	defer closeBody(resp.Body)

	if *expectFail {
		log.Fatalf("Expected connection to fail, but request succeeded with status %s", resp.Status)
	}

	if len(capturedPeerCerts) > 0 {
		leaf := capturedPeerCerts[0]
		fmt.Printf("PeerCertSubjectCN: %s\n", leaf.Subject.CommonName)
		fmt.Printf("PeerCertDNSNames: %s\n", strings.Join(leaf.DNSNames, ","))
		fmt.Printf("PeerCertIssuerCN: %s\n", leaf.Issuer.CommonName)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	fmt.Printf("Status: %s\n", resp.Status)
	for k, vv := range resp.Header {
		for _, v := range vv {
			fmt.Printf("Header-%s: %s\n", k, v)
		}
	}
	fmt.Printf("Body: %s\n", string(body))
}

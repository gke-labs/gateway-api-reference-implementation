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

package httphost

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/sni"
)

// maxHeadBytes is the maximum allowed size of an HTTP/1.1 request head (request line and headers).
// 8 KiB is standard across production HTTP servers (e.g. Apache, Nginx default) and ample
// for typical request headers while bounding memory consumption and peeking overhead.
const maxHeadBytes = 8 * 1024

var (
	// ErrNotHTTP11 is returned when the request is not HTTP/1.1.
	ErrNotHTTP11 = errors.New("not an HTTP/1.1 request")

	// ErrNoHost is returned when the request has no Host header or an empty Host.
	ErrNoHost = errors.New("no Host header found")

	// ErrMultipleHosts is returned when the request contains more than one Host header.
	ErrMultipleHosts = errors.New("multiple Host headers found")

	// ErrHeadTooLarge is returned when the request head exceeds the 8 KiB bound.
	ErrHeadTooLarge = errors.New("request head exceeds 8 KiB bound")

	// ErrInvalidHost is returned when the hostname contains invalid characters.
	ErrInvalidHost = errors.New("invalid hostname in request")
)

// SniffHost reads the head of an HTTP/1.1 request from conn within readTimeout, bounded at 8 KiB,
// and extracts the hostname with any port removed. It returns the hostname, a connection that
// replays the peeked bytes, and any error encountered.
func SniffHost(conn net.Conn, readTimeout time.Duration) (host string, peeked net.Conn, err error) {
	if readTimeout > 0 {
		if err = conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return "", conn, fmt.Errorf("setting read deadline: %w", err)
		}
		defer func() {
			if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil && err == nil {
				host = ""
				err = fmt.Errorf("clearing read deadline: %w", clearErr)
			}
		}()
	}

	var buf []byte
	tmp := make([]byte, maxHeadBytes)
	for {
		n, readErr := conn.Read(tmp[:maxHeadBytes-len(buf)])
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if bytes.Contains(buf, []byte("\r\n\r\n")) || bytes.Contains(buf, []byte("\n\n")) {
			break
		}
		if len(buf) >= maxHeadBytes {
			return "", sni.NewPeekedConn(conn, buf), ErrHeadTooLarge
		}
		if readErr != nil {
			return "", sni.NewPeekedConn(conn, buf), readErr
		}
	}

	req, parseErr := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))
	if parseErr != nil {
		if strings.Contains(parseErr.Error(), "too many Host headers") {
			return "", sni.NewPeekedConn(conn, buf), ErrMultipleHosts
		}
		return "", sni.NewPeekedConn(conn, buf), parseErr
	}
	if req.ProtoMajor != 1 || req.ProtoMinor != 1 {
		return "", sni.NewPeekedConn(conn, buf), ErrNotHTTP11
	}

	rawHost, port, splitErr := net.SplitHostPort(req.Host)
	if splitErr != nil {
		rawHost = req.Host
	} else {
		for i := 0; i < len(port); i++ {
			if port[i] < '0' || port[i] > '9' {
				return "", sni.NewPeekedConn(conn, buf), ErrInvalidHost
			}
		}
	}
	if rawHost == "" {
		return "", sni.NewPeekedConn(conn, buf), ErrNoHost
	}
	if !validHostname(rawHost) {
		return "", sni.NewPeekedConn(conn, buf), ErrInvalidHost
	}

	return rawHost, sni.NewPeekedConn(conn, buf), nil
}

func validHostname(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}

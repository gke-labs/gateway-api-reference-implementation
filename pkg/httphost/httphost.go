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
// The bound limits the memory and time one connection can hold before routing.
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

	// ErrNonPositiveTimeout is returned when readTimeout is zero or negative.
	ErrNonPositiveTimeout = errors.New("read timeout must be positive")
)

// SniffHost reads the head of an HTTP/1.1 request from conn within readTimeout, bounded at 8 KiB,
// and extracts the hostname with any port removed.
//
// The hostname is returned as sent, so upper case and a trailing dot are kept and the caller
// normalises before matching. Hostname validation checks characters only, not label structure
// or length. When the request target is in absolute form, it takes precedence over the Host header.
//
// SniffHost returns the replaying connection on error paths too.
func SniffHost(conn net.Conn, readTimeout time.Duration) (host string, peeked net.Conn, err error) {
	if readTimeout <= 0 {
		return "", sni.NewPeekedConn(conn, nil), ErrNonPositiveTimeout
	}

	if err = conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return "", sni.NewPeekedConn(conn, nil), fmt.Errorf("setting read deadline: %w", err)
	}
	defer func() {
		if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil && err == nil {
			host = ""
			err = fmt.Errorf("clearing read deadline: %w", clearErr)
		}
	}()

	var buffer []byte
	temporary := make([]byte, maxHeadBytes)
	for {
		bytesRead, readErr := conn.Read(temporary[:maxHeadBytes-len(buffer)])
		if bytesRead > 0 {
			buffer = append(buffer, temporary[:bytesRead]...)
		}
		if bytes.Contains(buffer, []byte("\r\n\r\n")) || bytes.Contains(buffer, []byte("\n\n")) {
			break
		}
		if len(buffer) >= maxHeadBytes {
			return "", sni.NewPeekedConn(conn, buffer), ErrHeadTooLarge
		}
		if readErr != nil {
			return "", sni.NewPeekedConn(conn, buffer), readErr
		}
	}

	request, parseErr := http.ReadRequest(bufio.NewReader(bytes.NewReader(buffer)))
	if parseErr != nil {
		if strings.Contains(parseErr.Error(), "too many Host headers") {
			return "", sni.NewPeekedConn(conn, buffer), ErrMultipleHosts
		}
		return "", sni.NewPeekedConn(conn, buffer), parseErr
	}
	if request.ProtoMajor != 1 || request.ProtoMinor != 1 {
		return "", sni.NewPeekedConn(conn, buffer), ErrNotHTTP11
	}

	rawHost, port, splitErr := net.SplitHostPort(request.Host)
	if splitErr != nil {
		rawHost = request.Host
	} else {
		for index := 0; index < len(port); index++ {
			if port[index] < '0' || port[index] > '9' {
				return "", sni.NewPeekedConn(conn, buffer), ErrInvalidHost
			}
		}
	}
	if rawHost == "" {
		return "", sni.NewPeekedConn(conn, buffer), ErrNoHost
	}
	if !validHostname(rawHost) {
		return "", sni.NewPeekedConn(conn, buffer), ErrInvalidHost
	}

	return rawHost, sni.NewPeekedConn(conn, buffer), nil
}

func validHostname(hostname string) bool {
	for index := 0; index < len(hostname); index++ {
		character := hostname[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

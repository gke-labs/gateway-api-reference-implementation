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
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSniffHost(t *testing.T) {
	prefix := "GET / HTTP/1.1\r\nHost: example.com\r\nX-Padding: "
	suffix := "\r\n\r\n"
	pad := strings.Repeat("A", maxHeadBytes-len(prefix)-len(suffix))
	head8k := []byte(prefix + pad + suffix)
	head8kOver := []byte(prefix + pad + "A" + suffix)

	tests := []struct {
		name     string
		input    []byte
		writeFn  func(net.Conn)
		timeout  time.Duration
		wantHost string
		wantErr  bool
		errCheck func(error) bool
	}{
		{
			name:     "plain request",
			input:    []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantHost: "example.com",
		},
		{
			name:     "Host with a port",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"),
			wantHost: "example.com",
		},
		{
			name:     "head of exactly 8 KiB",
			input:    head8k,
			wantHost: "example.com",
		},
		{
			name:     "one over it",
			input:    head8kOver,
			wantErr:  true,
			errCheck: func(err error) bool { return errors.Is(err, ErrHeadTooLarge) },
		},
		{
			name:     "HTTP/1.0",
			input:    []byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"),
			wantErr:  true,
			errCheck: func(err error) bool { return errors.Is(err, ErrNotHTTP11) },
		},
		{
			name:     "the HTTP/2 preface",
			input:    []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
			wantErr:  true,
			errCheck: func(err error) bool { return errors.Is(err, ErrNotHTTP11) },
		},
		{
			name:    "TLS bytes",
			input:   []byte("\x16\x03\x01\x00\x05hello"),
			wantErr: true,
		},
		{
			name:     "no Host",
			input:    []byte("GET / HTTP/1.1\r\nUser-Agent: curl\r\n\r\n"),
			wantErr:  true,
			errCheck: func(err error) bool { return errors.Is(err, ErrNoHost) },
		},
		{
			name:     "an empty one",
			input:    []byte("GET / HTTP/1.1\r\nHost:\r\n\r\n"),
			wantErr:  true,
			errCheck: func(err error) bool { return errors.Is(err, ErrNoHost) },
		},
		{
			name:     "two of them",
			input:    []byte("GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com\r\n\r\n"),
			wantErr:  true,
			errCheck: func(err error) bool { return errors.Is(err, ErrMultipleHosts) },
		},
		{
			name:     "an absolute-form target with a different Host",
			input:    []byte("GET http://target.com/path HTTP/1.1\r\nHost: header.com\r\n\r\n"),
			wantHost: "target.com",
		},
		{
			name:     "a folded Host header",
			input:    []byte("GET / HTTP/1.1\r\nHost: example\r\n .com\r\n\r\n"),
			wantErr:  true,
			errCheck: func(err error) bool { return errors.Is(err, ErrInvalidHost) },
		},
		{
			name:     "Host values that contain @",
			input:    []byte("GET / HTTP/1.1\r\nHost: user@example.com\r\n\r\n"),
			wantErr:  true,
			errCheck: func(err error) bool { return errors.Is(err, ErrInvalidHost) },
		},
		{
			name:     "Host values that contain /",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com/path\r\n\r\n"),
			wantErr:  true,
			errCheck: func(err error) bool { return errors.Is(err, ErrInvalidHost) },
		},
		{
			name:     "Host values that contain a comma",
			input:    []byte("GET / HTTP/1.1\r\nHost: a.com, b.com\r\n\r\n"),
			wantErr:  true,
			errCheck: func(err error) bool { return errors.Is(err, ErrInvalidHost) },
		},
		{
			name:     "Host values that contain a space",
			input:    []byte("GET / HTTP/1.1\r\nHost: example .com\r\n\r\n"),
			wantErr:  true,
			errCheck: func(err error) bool { return errors.Is(err, ErrInvalidHost) },
		},
		{
			name:     "bare LF line endings",
			input:    []byte("GET / HTTP/1.1\nHost: example.com\n\n"),
			wantHost: "example.com",
		},
		{
			name:     "a pipelined second request with another Host",
			input:    []byte("GET /first HTTP/1.1\r\nHost: first.com\r\n\r\nGET /second HTTP/1.1\r\nHost: second.com\r\n\r\n"),
			wantHost: "first.com",
		},
		{
			name:    "a sender that writes one byte at a time past the deadline",
			timeout: 50 * time.Millisecond,
			writeFn: func(conn net.Conn) {
				defer conn.Close()
				for i := 0; i < 20; i++ {
					if _, err := conn.Write([]byte("G")); err != nil {
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
			},
			wantErr: true,
			errCheck: func(err error) bool {
				var netErr net.Error
				return errors.As(err, &netErr) && netErr.Timeout()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			timeout := tc.timeout
			if timeout == 0 {
				timeout = 2 * time.Second
			}

			go func() {
				if tc.writeFn != nil {
					tc.writeFn(clientConn)
					return
				}
				if _, err := clientConn.Write(tc.input); err != nil && !tc.wantErr {
					t.Errorf("writing input: %v", err)
				}
				if tc.wantErr {
					_ = clientConn.Close()
				}
			}()

			host, peekedConn, err := SniffHost(serverConn, timeout)
			// Close client end after SniffHost to allow io.ReadAll to see EOF on the server side
			_ = clientConn.Close()

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got host %q", host)
				}
				if tc.errCheck != nil && !tc.errCheck(err) {
					t.Fatalf("error %v did not match expected check", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tc.wantHost {
				t.Fatalf("got host %q, want %q", host, tc.wantHost)
			}

			replayed, err := io.ReadAll(peekedConn)
			if err != nil {
				t.Fatalf("reading from peekedConn: %v", err)
			}
			if !bytes.Equal(replayed, tc.input) {
				t.Fatalf("replayed bytes mismatch: got %q, want %q", replayed, tc.input)
			}
		})
	}
}

type failClearDeadlineConn struct {
	net.Conn
}

func (c *failClearDeadlineConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		return errors.New("simulated error clearing read deadline")
	}
	return c.Conn.SetReadDeadline(t)
}

func TestSniffHost_ClearDeadlineError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	wrappedConn := &failClearDeadlineConn{Conn: serverConn}

	go func() {
		if _, err := clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
			t.Errorf("writing input: %v", err)
		}
	}()

	host, _, err := SniffHost(wrappedConn, time.Second)
	if err == nil {
		t.Fatalf("expected error clearing deadline, got host %q", host)
	}
	if !strings.Contains(err.Error(), "clearing read deadline") {
		t.Fatalf("expected clearing read deadline error, got %v", err)
	}
}

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

package api

import (
	"bufio"
	"errors"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	// MaxControlLineBytes is the maximum allowed size (64 KiB) for a single control-message JSON line.
	MaxControlLineBytes = 64 * 1024

	// QUICHandshakeTimeout is the maximum duration to complete control stream handshake.
	QUICHandshakeTimeout = 10 * time.Second

	// DefaultQUICKeepAlivePeriod is the keepalive ping frequency for UDP NAT traversal.
	DefaultQUICKeepAlivePeriod = 15 * time.Second

	// DefaultQUICMaxIdleTimeout is the maximum duration a QUIC connection can remain idle before being closed.
	DefaultQUICMaxIdleTimeout = 30 * time.Second

	// DefaultQUICMaxIncomingStreams is the maximum concurrent bidirectional streams allowed per QUIC connection.
	DefaultQUICMaxIncomingStreams = 10000

	// DefaultQUICInitialStreamReceiveWindow is the initial stream-level flow control receive window (2 MB).
	DefaultQUICInitialStreamReceiveWindow = 2 * 1024 * 1024

	// DefaultQUICMaxStreamReceiveWindow is the maximum stream-level flow control receive window (8 MB).
	DefaultQUICMaxStreamReceiveWindow = 8 * 1024 * 1024

	// DefaultQUICInitialConnReceiveWindow is the initial connection-level flow control receive window (4 MB).
	DefaultQUICInitialConnReceiveWindow = 4 * 1024 * 1024

	// DefaultQUICMaxConnReceiveWindow is the maximum connection-level flow control receive window (16 MB).
	DefaultQUICMaxConnReceiveWindow = 16 * 1024 * 1024
)

// ErrLineTooLong is returned when a control line exceeds MaxControlLineBytes.
var ErrLineTooLong = errors.New("control message line exceeds maximum allowed length")

// ReadControlLine reads a single newline-terminated line from reader, enforcing MaxControlLineBytes.
func ReadControlLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		line = append(line, chunk...)
		if len(line) > MaxControlLineBytes {
			return nil, ErrLineTooLong
		}
		if !isPrefix {
			break
		}
	}
	return line, nil
}

// DefaultQUICConfig returns a tuned quic.Config for snigateway high-bandwidth reverse tunnels.
func DefaultQUICConfig() *quic.Config {
	return &quic.Config{
		KeepAlivePeriod:                DefaultQUICKeepAlivePeriod,
		MaxIdleTimeout:                 DefaultQUICMaxIdleTimeout,
		MaxIncomingStreams:             DefaultQUICMaxIncomingStreams,
		InitialStreamReceiveWindow:     DefaultQUICInitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         DefaultQUICMaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: DefaultQUICInitialConnReceiveWindow,
		MaxConnectionReceiveWindow:     DefaultQUICMaxConnReceiveWindow,
		EnableDatagrams:                true,
	}
}

// QUICStreamConn wraps a *quic.Stream and *quic.Conn to satisfy net.Conn for tunnel proxying.
type QUICStreamConn struct {
	*quic.Stream
	Conn *quic.Conn
}

// NewQUICStreamConn creates a new QUICStreamConn wrapping a QUIC stream and connection.
func NewQUICStreamConn(stream *quic.Stream, conn *quic.Conn) *QUICStreamConn {
	return &QUICStreamConn{
		Stream: stream,
		Conn:   conn,
	}
}

func (c *QUICStreamConn) LocalAddr() net.Addr {
	if c.Conn != nil {
		return c.Conn.LocalAddr()
	}
	return nil
}

func (c *QUICStreamConn) RemoteAddr() net.Addr {
	if c.Conn != nil {
		return c.Conn.RemoteAddr()
	}
	return nil
}

func (c *QUICStreamConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}

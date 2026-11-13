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

//go:build linux || darwin

package custodian

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// PeerCred holds the caller's peer credentials on a Unix domain socket.
type PeerCred struct {
	UID uint32
	GID uint32
	PID int32
}

type credAddr struct {
	net.Addr
	peerCred *PeerCred
	credErr  error
}

type credConn struct {
	net.Conn
	addr *credAddr
}

func (credConnection *credConn) RemoteAddr() net.Addr {
	return credConnection.addr
}

type credListener struct {
	net.Listener
}

// NewCredListener wraps a net.Listener to inspect peer credentials on accepted connections.
func NewCredListener(underlyingListener net.Listener) net.Listener {
	return &credListener{Listener: underlyingListener}
}

func (listener *credListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	extractedCred, credErr := getPeerCred(connection)
	return &credConn{
		Conn: connection,
		addr: &credAddr{
			Addr:     connection.RemoteAddr(),
			peerCred: extractedCred,
			credErr:  credErr,
		},
	}, nil
}

// CredFromContext extracts the peer credentials from the gRPC context.
func CredFromContext(ctx context.Context) (*PeerCred, error) {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok || peerInfo == nil || peerInfo.Addr == nil {
		return nil, errors.New("no peer information in context")
	}
	credAddress, ok := peerInfo.Addr.(*credAddr)
	if !ok {
		return nil, errors.New("peer address does not contain peer credentials")
	}
	if credAddress.credErr != nil {
		return nil, credAddress.credErr
	}
	if credAddress.peerCred == nil {
		return nil, errors.New("missing peer credentials")
	}
	return credAddress.peerCred, nil
}

// isAllowed reports whether the peer credentials match any allowed UID or primary GID.
func isAllowed(credentials *PeerCred, allowedUIDs []uint32, allowedGIDs []uint32) bool {
	if credentials == nil {
		return false
	}
	for _, allowedUID := range allowedUIDs {
		if allowedUID == credentials.UID {
			return true
		}
	}
	for _, allowedGID := range allowedGIDs {
		if allowedGID == credentials.GID {
			return true
		}
	}
	return false
}

func auditLog(ctx context.Context, logger *slog.Logger, credentials *PeerCred, key string, hashAlgorithm string, method string, outcome string) {
	if logger == nil {
		return
	}
	attributes := make([]slog.Attr, 0, 5)
	if key != "" {
		attributes = append(attributes, slog.String("key", key))
	}
	if credentials != nil {
		attributes = append(attributes, slog.Uint64("caller_uid", uint64(credentials.UID)))
		if credentials.PID > 0 {
			attributes = append(attributes, slog.Int64("caller_pid", int64(credentials.PID)))
		}
	}
	if hashAlgorithm != "" {
		attributes = append(attributes, slog.String("hash_algorithm", hashAlgorithm))
	}
	if method != "" {
		attributes = append(attributes, slog.String("method", method))
	}
	attributes = append(attributes, slog.String("outcome", outcome))
	logger.LogAttrs(ctx, slog.LevelInfo, "audit", attributes...)
}

// UnaryAuthInterceptor returns a gRPC unary interceptor that rejects callers
// whose peer credentials are not in the allowed UID or primary GID list before any key lookup.
// If an audit logger is provided, denied callers are logged with outcome "denied".
func UnaryAuthInterceptor(allowedUIDs []uint32, allowedGIDs []uint32, auditLogger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, unaryServerInfo *grpc.UnaryServerInfo, unaryHandler grpc.UnaryHandler) (any, error) {
		credentials, err := CredFromContext(ctx)
		if err != nil {
			auditLog(ctx, auditLogger, nil, "", "", unaryServerInfo.FullMethod, AuditOutcomeDenied)
			return nil, status.Errorf(codes.PermissionDenied, "peer credentials unavailable: %v", err)
		}
		if !isAllowed(credentials, allowedUIDs, allowedGIDs) {
			auditLog(ctx, auditLogger, credentials, "", "", unaryServerInfo.FullMethod, AuditOutcomeDenied)
			return nil, status.Errorf(codes.PermissionDenied, "caller uid %d / gid %d not allowed", credentials.UID, credentials.GID)
		}
		return unaryHandler(ctx, request)
	}
}

// StreamAuthInterceptor returns a gRPC stream interceptor that rejects callers
// whose peer credentials are not in the allowed UID or primary GID list before any RPC handling.
// If an audit logger is provided, denied callers are logged with outcome "denied".
func StreamAuthInterceptor(allowedUIDs []uint32, allowedGIDs []uint32, auditLogger *slog.Logger) grpc.StreamServerInterceptor {
	return func(server any, serverStream grpc.ServerStream, streamServerInfo *grpc.StreamServerInfo, streamHandler grpc.StreamHandler) error {
		credentials, err := CredFromContext(serverStream.Context())
		if err != nil {
			auditLog(serverStream.Context(), auditLogger, nil, "", "", streamServerInfo.FullMethod, AuditOutcomeDenied)
			return status.Errorf(codes.PermissionDenied, "peer credentials unavailable: %v", err)
		}
		if !isAllowed(credentials, allowedUIDs, allowedGIDs) {
			auditLog(serverStream.Context(), auditLogger, credentials, "", "", streamServerInfo.FullMethod, AuditOutcomeDenied)
			return status.Errorf(codes.PermissionDenied, "caller uid %d / gid %d not allowed", credentials.UID, credentials.GID)
		}
		return streamHandler(server, serverStream)
	}
}

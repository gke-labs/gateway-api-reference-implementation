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

package custodian_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	keycustodianv1alpha1 "github.com/gke-labs/gateway-api-reference-implementation/experiments/keycustodian/api/v1alpha1"
	"github.com/gke-labs/gateway-api-reference-implementation/experiments/keycustodian/pkg/custodian"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func startSocketDaemon(t *testing.T, keysDirectory string, allowedUIDs []uint32, allowedGIDs []uint32, auditLoggers ...*slog.Logger) (keycustodianv1alpha1.KeyCustodianServiceClient, string) {
	t.Helper()
	var auditLogger *slog.Logger
	if len(auditLoggers) > 0 {
		auditLogger = auditLoggers[0]
	}

	socketDir, err := os.MkdirTemp("", "kc")
	if err != nil {
		t.Fatalf("failed to create temporary socket directory: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(socketDir)
	})

	socketPath := filepath.Join(socketDir, "custodian.sock")

	var serverOptions []custodian.ServerOption
	if auditLogger != nil {
		serverOptions = append(serverOptions, custodian.WithAuditLogger(auditLogger))
	}

	custodianServer, err := custodian.NewServer(keysDirectory, serverOptions...)
	if err != nil {
		t.Fatalf("failed to create custodian server: %v", err)
	}

	listener, err := custodian.ListenUnix(socketPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket %s: %v", socketPath, err)
	}

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(custodian.UnaryAuthInterceptor(allowedUIDs, allowedGIDs, auditLogger)),
		grpc.StreamInterceptor(custodian.StreamAuthInterceptor(allowedUIDs, allowedGIDs, auditLogger)),
	)
	keycustodianv1alpha1.RegisterKeyCustodianServiceServer(grpcServer, custodianServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	clientConnection, err := grpc.NewClient("unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		}),
	)
	if err != nil {
		t.Fatalf("failed to connect to unix socket: %v", err)
	}
	t.Cleanup(func() {
		_ = clientConnection.Close()
	})

	return keycustodianv1alpha1.NewKeyCustodianServiceClient(clientConnection), socketPath
}

func TestListenUnix_SocketPermissions(t *testing.T) {
	keysDirectory := t.TempDir()
	currentUID := uint32(os.Getuid())
	_, socketPath := startSocketDaemon(t, keysDirectory, []uint32{currentUID}, nil)

	fileInfo, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("failed to stat socket: %v", err)
	}
	permission := fileInfo.Mode().Perm()
	if permission != 0660 {
		t.Fatalf("expected socket permissions 0660, got %#o", permission)
	}
}

func TestListenUnix_RejectsNonSocketFile(t *testing.T) {
	tempDirectory := t.TempDir()
	filePath := filepath.Join(tempDirectory, "not-a-socket")
	if err := os.WriteFile(filePath, []byte("data"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err := custodian.ListenUnix(filePath)
	if err == nil {
		t.Fatal("expected ListenUnix to fail when path exists and is not a socket, but succeeded")
	}
}

func TestPeerCredentialCheck_AllowedCaller(t *testing.T) {
	keysDirectory := t.TempDir()
	generateECDSAKeyAndCertificate(t, keysDirectory, "p256")

	currentUID := uint32(os.Getuid())
	client, _ := startSocketDaemon(t, keysDirectory, []uint32{currentUID}, nil)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	listResponse, err := client.ListKeys(ctx, &keycustodianv1alpha1.ListKeysRequest{})
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(listResponse.Keys) != 1 || listResponse.Keys[0] != "p256" {
		t.Fatalf("unexpected keys listed: %v", listResponse.Keys)
	}
}

func TestPeerCredentialCheck_AllowedPrimaryGID(t *testing.T) {
	keysDirectory := t.TempDir()
	generateECDSAKeyAndCertificate(t, keysDirectory, "p256")

	currentGID := uint32(os.Getgid())
	// Allow only the caller's primary GID (no UIDs allowed)
	client, _ := startSocketDaemon(t, keysDirectory, nil, []uint32{currentGID})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	listResponse, err := client.ListKeys(ctx, &keycustodianv1alpha1.ListKeysRequest{})
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(listResponse.Keys) != 1 || listResponse.Keys[0] != "p256" {
		t.Fatalf("unexpected keys listed: %v", listResponse.Keys)
	}
}

func TestPeerCredentialCheck_UnauthorizedCallerRejectedBeforeKeyLookup(t *testing.T) {
	keysDirectory := t.TempDir()
	generateECDSAKeyAndCertificate(t, keysDirectory, "p256")

	// Allow an arbitrary UID that is NOT the caller's UID, and no GIDs
	allowedUID := uint32(os.Getuid()) + 9999
	client, _ := startSocketDaemon(t, keysDirectory, []uint32{allowedUID}, nil)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	digest := sha256.Sum256([]byte("test"))

	// Even when requesting an unknown key, it must be rejected with PermissionDenied
	// before any key lookup takes place.
	_, err := client.Sign(ctx, &keycustodianv1alpha1.SignRequest{
		Key:           "non-existent-key",
		HashAlgorithm: keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Digest:        digest[:],
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied before key lookup, got: %v", err)
	}

	_, err = client.ListKeys(ctx, &keycustodianv1alpha1.ListKeysRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied on ListKeys, got: %v", err)
	}

	_, err = client.GetCertificateChain(ctx, &keycustodianv1alpha1.GetCertificateChainRequest{Key: "p256"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied on GetCertificateChain, got: %v", err)
	}
}

type fakeServerStream struct {
	streamContext context.Context
}

func (stream *fakeServerStream) SetHeader(metadata.MD) error  { return nil }
func (stream *fakeServerStream) SendHeader(metadata.MD) error { return nil }
func (stream *fakeServerStream) SetTrailer(metadata.MD)       {}
func (stream *fakeServerStream) Context() context.Context     { return stream.streamContext }
func (stream *fakeServerStream) SendMsg(any) error            { return nil }
func (stream *fakeServerStream) RecvMsg(any) error            { return nil }

func TestStreamAuthInterceptor_RejectsUnauthorizedStream(t *testing.T) {
	streamInterceptor := custodian.StreamAuthInterceptor([]uint32{1000}, nil, nil)

	// Stream with no peer credentials in context must be rejected
	streamWithoutCreds := &fakeServerStream{streamContext: t.Context()}
	handlerCalled := false
	err := streamInterceptor(nil, streamWithoutCreds, &grpc.StreamServerInfo{FullMethod: "/test.Service/Stream"}, func(server any, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	})

	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for stream without peer credentials, got: %v", err)
	}
	if handlerCalled {
		t.Fatal("stream handler should not have been called for unauthorized stream")
	}
}

func TestSocket_AuditLogPeerCredentials(t *testing.T) {
	keysDirectory := t.TempDir()
	generateECDSAKeyAndCertificate(t, keysDirectory, "p256")

	currentUID := uint32(os.Getuid())
	currentPID := int32(os.Getpid())

	var auditBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&auditBuf, nil))
	client, _ := startSocketDaemon(t, keysDirectory, []uint32{currentUID}, nil, logger)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	digest := sha256.Sum256([]byte("peer creds audit test"))
	_, err := client.Sign(ctx, &keycustodianv1alpha1.SignRequest{
		Key:           "p256",
		HashAlgorithm: keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Digest:        digest[:],
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(auditBuf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 audit line, got %d:\n%s", len(lines), auditBuf.String())
	}

	var entry auditEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("failed to unmarshal audit entry: %v", err)
	}

	if entry.CallerUID == nil {
		t.Fatalf("expected CallerUID %d, got nil", currentUID)
	} else if *entry.CallerUID != currentUID {
		t.Fatalf("expected CallerUID %d, got %d", currentUID, *entry.CallerUID)
	}
	if entry.CallerPID == nil {
		t.Fatalf("expected CallerPID %d, got nil", currentPID)
	} else if *entry.CallerPID != currentPID {
		t.Fatalf("expected CallerPID %d, got %d", currentPID, *entry.CallerPID)
	}
	if entry.Key != "p256" {
		t.Fatalf("expected Key p256, got %q", entry.Key)
	}
	if entry.HashAlgorithm != "HASH_ALGORITHM_SHA256" {
		t.Fatalf("expected HashAlgorithm HASH_ALGORITHM_SHA256, got %q", entry.HashAlgorithm)
	}
	if entry.Outcome != custodian.AuditOutcomeSuccess {
		t.Fatalf("expected Outcome %q, got %q", custodian.AuditOutcomeSuccess, entry.Outcome)
	}
}

func TestPeerCredentialCheck_AuditLogDenied(t *testing.T) {
	keysDirectory := t.TempDir()
	generateECDSAKeyAndCertificate(t, keysDirectory, "p256")

	currentUID := uint32(os.Getuid())
	currentPID := int32(os.Getpid())
	disallowedUID := currentUID + 1

	var auditBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&auditBuf, nil))
	client, _ := startSocketDaemon(t, keysDirectory, []uint32{disallowedUID}, nil, logger)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	digest := sha256.Sum256([]byte("denied caller audit test"))
	_, err := client.Sign(ctx, &keycustodianv1alpha1.SignRequest{
		Key:           "p256",
		HashAlgorithm: keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Digest:        digest[:],
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(auditBuf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 audit line, got %d:\n%s", len(lines), auditBuf.String())
	}

	var entry auditEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("failed to unmarshal audit entry: %v", err)
	}

	if entry.Outcome != custodian.AuditOutcomeDenied {
		t.Fatalf("expected outcome %q, got %q", custodian.AuditOutcomeDenied, entry.Outcome)
	}
	if entry.Method != "/keycustodian.v1alpha1.KeyCustodianService/Sign" {
		t.Fatalf("expected method /keycustodian.v1alpha1.KeyCustodianService/Sign, got %q", entry.Method)
	}
	if entry.CallerUID == nil {
		t.Fatalf("expected CallerUID %d, got nil", currentUID)
	} else if *entry.CallerUID != currentUID {
		t.Fatalf("expected CallerUID %d, got %d", currentUID, *entry.CallerUID)
	}
	if entry.CallerPID == nil {
		t.Fatalf("expected CallerPID %d, got nil", currentPID)
	} else if *entry.CallerPID != currentPID {
		t.Fatalf("expected CallerPID %d, got %d", currentPID, *entry.CallerPID)
	}
}

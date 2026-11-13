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

package custodian_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
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
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type auditEntry struct {
	Time          time.Time `json:"time"`
	Level         string    `json:"level"`
	Msg           string    `json:"msg"`
	Key           string    `json:"key,omitempty"`
	CallerUID     *uint32   `json:"caller_uid,omitempty"`
	CallerPID     *int32    `json:"caller_pid,omitempty"`
	HashAlgorithm string    `json:"hash_algorithm,omitempty"`
	Method        string    `json:"method,omitempty"`
	Outcome       string    `json:"outcome"`
}

func generateECDSAKeyAndCertificate(t *testing.T, directory, name string) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal EC private key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})

	if err := os.WriteFile(filepath.Join(directory, name+".key"), keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, name+".crt"), certificatePEM, 0644); err != nil {
		t.Fatalf("failed to write certificate file: %v", err)
	}
	return privateKey
}

func generateRSAKeyAndCertificate(t *testing.T, directory, name string) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	keyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})

	if err := os.WriteFile(filepath.Join(directory, name+".key"), keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, name+".crt"), certificatePEM, 0644); err != nil {
		t.Fatalf("failed to write certificate file: %v", err)
	}
	return privateKey
}

func startInProcessServer(t *testing.T, keysDirectory string, options ...custodian.ServerOption) keycustodianv1alpha1.KeyCustodianServiceClient {
	t.Helper()
	custodianServer, err := custodian.NewServer(keysDirectory, options...)
	if err != nil {
		t.Fatalf("failed to create custodian server: %v", err)
	}

	bufferListener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	keycustodianv1alpha1.RegisterKeyCustodianServiceServer(grpcServer, custodianServer)

	go func() {
		_ = grpcServer.Serve(bufferListener)
	}()

	t.Cleanup(func() {
		grpcServer.Stop()
		_ = bufferListener.Close()
	})

	clientConnection, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return bufferListener.Dial()
		}),
	)
	if err != nil {
		t.Fatalf("failed to connect to buffer listener: %v", err)
	}
	t.Cleanup(func() {
		_ = clientConnection.Close()
	})

	return keycustodianv1alpha1.NewKeyCustodianServiceClient(clientConnection)
}

func TestServer_ListKeysAndGetCertificateChain(t *testing.T) {
	keysDirectory := t.TempDir()
	generateECDSAKeyAndCertificate(t, keysDirectory, "p256")
	generateRSAKeyAndCertificate(t, keysDirectory, "rsa")

	client := startInProcessServer(t, keysDirectory)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	listResponse, err := client.ListKeys(ctx, &keycustodianv1alpha1.ListKeysRequest{})
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(listResponse.Keys) != 2 || listResponse.Keys[0] != "p256" || listResponse.Keys[1] != "rsa" {
		t.Fatalf("unexpected keys listed: %v", listResponse.Keys)
	}

	certificateResponse, err := client.GetCertificateChain(ctx, &keycustodianv1alpha1.GetCertificateChainRequest{Key: "p256"})
	if err != nil {
		t.Fatalf("GetCertificateChain failed: %v", err)
	}
	block, _ := pem.Decode(certificateResponse.CertificateChain)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("failed to decode certificate PEM")
	}

	_, err = client.GetCertificateChain(ctx, &keycustodianv1alpha1.GetCertificateChainRequest{Key: "non-existent"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound for unknown key, got: %v", err)
	}
}

func TestServer_ECDSAP256Signature(t *testing.T) {
	keysDirectory := t.TempDir()
	ecKey := generateECDSAKeyAndCertificate(t, keysDirectory, "p256")

	client := startInProcessServer(t, keysDirectory)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	message := []byte("hello keycustodian ecdsa")
	digest := sha256.Sum256(message)

	signResponse, err := client.Sign(ctx, &keycustodianv1alpha1.SignRequest{
		Key:           "p256",
		HashAlgorithm: keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Digest:        digest[:],
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !ecdsa.VerifyASN1(&ecKey.PublicKey, digest[:], signResponse.Signature) {
		t.Fatalf("ECDSA P-256 signature verification failed")
	}
}

func TestServer_RSAPSSSignature(t *testing.T) {
	keysDirectory := t.TempDir()
	rsaKey := generateRSAKeyAndCertificate(t, keysDirectory, "rsa")

	client := startInProcessServer(t, keysDirectory)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	message := []byte("hello keycustodian rsa pss")
	digest := sha256.Sum256(message)
	saltLength := int32(rsa.PSSSaltLengthEqualsHash)

	signResponse, err := client.Sign(ctx, &keycustodianv1alpha1.SignRequest{
		Key:              "rsa",
		HashAlgorithm:    keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Digest:           digest[:],
		RsaPssSaltLength: &saltLength,
	})
	if err != nil {
		t.Fatalf("Sign RSA-PSS failed: %v", err)
	}

	err = rsa.VerifyPSS(&rsaKey.PublicKey, crypto.SHA256, digest[:], signResponse.Signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	if err != nil {
		t.Fatalf("RSA-PSS signature verification failed: %v", err)
	}
}

func TestServer_WrongDigestLength(t *testing.T) {
	keysDirectory := t.TempDir()
	generateECDSAKeyAndCertificate(t, keysDirectory, "p256")

	client := startInProcessServer(t, keysDirectory)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	testCases := []struct {
		name          string
		hashAlgorithm keycustodianv1alpha1.HashAlgorithm
		digestLength  int
	}{
		{"sha256 short", keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256, 31},
		{"sha256 long", keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256, 33},
		{"sha384 wrong", keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA384, 32},
		{"sha512 wrong", keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA512, 48},
		{"unspecified", keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, 32},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			digest := make([]byte, testCase.digestLength)
			_, err := client.Sign(ctx, &keycustodianv1alpha1.SignRequest{
				Key:           "p256",
				HashAlgorithm: testCase.hashAlgorithm,
				Digest:        digest,
			})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("expected InvalidArgument for digest len %d with algorithm %v, got: %v", testCase.digestLength, testCase.hashAlgorithm, err)
			}
		})
	}
}

func TestServer_UnknownKey(t *testing.T) {
	keysDirectory := t.TempDir()
	generateECDSAKeyAndCertificate(t, keysDirectory, "p256")

	client := startInProcessServer(t, keysDirectory)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	digest := sha256.Sum256([]byte("test"))
	_, err := client.Sign(ctx, &keycustodianv1alpha1.SignRequest{
		Key:           "does-not-exist",
		HashAlgorithm: keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Digest:        digest[:],
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound for unknown key, got: %v", err)
	}
}

func TestServer_LoadPEMDirectoryValidation(t *testing.T) {
	t.Run("CertificateWithoutPrivateKey", func(t *testing.T) {
		directory := t.TempDir()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(10),
			Subject:      pkix.Name{CommonName: "orphan"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey failed: %v", err)
		}
		certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatalf("CreateCertificate failed: %v", err)
		}
		certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
		if err := os.WriteFile(filepath.Join(directory, "orphan.crt"), certificatePEM, 0644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		_, err = custodian.NewServer(directory)
		if err == nil {
			t.Fatal("expected NewServer to fail for certificate without private key, but succeeded")
		}
		if !strings.Contains(err.Error(), "no corresponding private key") {
			t.Fatalf("expected error to mention 'no corresponding private key', got: %v", err)
		}
	})

	t.Run("UnknownPEMBlockType", func(t *testing.T) {
		directory := t.TempDir()
		unknownPEM := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("encrypted")})
		if err := os.WriteFile(filepath.Join(directory, "encrypted.key"), unknownPEM, 0600); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		_, err := custodian.NewServer(directory)
		if err == nil {
			t.Fatal("expected NewServer to fail for unknown PEM block type, but succeeded")
		}
		if !strings.Contains(err.Error(), "unsupported PEM block type") {
			t.Fatalf("expected error to mention 'unsupported PEM block type', got: %v", err)
		}
	})

	t.Run("DuplicatePrivateKey", func(t *testing.T) {
		directory := t.TempDir()
		generateECDSAKeyAndCertificate(t, directory, "dupe")

		secondKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		keyDER, err := x509.MarshalECPrivateKey(secondKey)
		if err != nil {
			t.Fatalf("MarshalECPrivateKey failed: %v", err)
		}
		secondKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		if err := os.WriteFile(filepath.Join(directory, "dupe.key.pem"), secondKeyPEM, 0600); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		_, err = custodian.NewServer(directory)
		if err == nil {
			t.Fatal("expected NewServer to fail for duplicate private key, but succeeded")
		}
		if !strings.Contains(err.Error(), "duplicate private key") {
			t.Fatalf("expected error to mention 'duplicate private key', got: %v", err)
		}
	})

	t.Run("FileWithNoPEMBlocks", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.WriteFile(filepath.Join(directory, "empty.txt"), []byte("not a pem file"), 0644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		_, err := custodian.NewServer(directory)
		if err == nil {
			t.Fatal("expected NewServer to fail for file with no PEM blocks, but succeeded")
		}
		if !strings.Contains(err.Error(), "contains no PEM blocks") {
			t.Fatalf("expected error to mention 'contains no PEM blocks', got: %v", err)
		}
	})

	t.Run("SkipDotPrefixedEntries", func(t *testing.T) {
		directory := t.TempDir()
		generateECDSAKeyAndCertificate(t, directory, "valid")

		// Create a dot-prefixed file and a ..data directory/symlink like in a Kubernetes Secret volume
		secretDataDirectory := filepath.Join(directory, "..2026_11_10_secret_data")
		if err := os.Mkdir(secretDataDirectory, 0755); err != nil {
			t.Fatalf("Mkdir failed: %v", err)
		}
		if err := os.Symlink(secretDataDirectory, filepath.Join(directory, "..data")); err != nil {
			t.Fatalf("Symlink failed: %v", err)
		}
		if err := os.WriteFile(filepath.Join(directory, ".hidden"), []byte("ignore me"), 0644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		server, err := custodian.NewServer(directory)
		if err != nil {
			t.Fatalf("expected NewServer to succeed ignoring dot-prefixed entries, got: %v", err)
		}
		response, err := server.ListKeys(t.Context(), &keycustodianv1alpha1.ListKeysRequest{})
		if err != nil {
			t.Fatalf("ListKeys failed: %v", err)
		}
		if len(response.Keys) != 1 || response.Keys[0] != "valid" {
			t.Fatalf("unexpected keys: %v", response.Keys)
		}
	})
}

func TestServer_AuditLogOutcomes(t *testing.T) {
	keysDirectory := t.TempDir()
	ecKey := generateECDSAKeyAndCertificate(t, keysDirectory, "p256")
	ecKeyDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey failed: %v", err)
	}

	var auditBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&auditBuf, nil))
	client := startInProcessServer(t, keysDirectory,
		custodian.WithAuditLogger(logger),
	)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	testDigest := sha256.Sum256([]byte("sensitive-super-secret-digest-bytes-value"))

	// Outcome 1: success
	_, err = client.Sign(ctx, &keycustodianv1alpha1.SignRequest{
		Key:           "p256",
		HashAlgorithm: keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Digest:        testDigest[:],
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Outcome 2: rejected (invalid digest length)
	_, _ = client.Sign(ctx, &keycustodianv1alpha1.SignRequest{
		Key:           "p256",
		HashAlgorithm: keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Digest:        testDigest[:10],
	})

	auditOutput := auditBuf.String()
	auditLines := strings.Split(strings.TrimSpace(auditOutput), "\n")
	if len(auditLines) != 2 {
		t.Fatalf("expected 2 audit lines, got %d:\n%s", len(auditLines), auditOutput)
	}

	// Assert raw digest bytes do NOT appear in the audit log
	if strings.Contains(auditOutput, string(testDigest[:])) {
		t.Fatalf("audit log leaked raw digest bytes")
	}

	// Assert hex-encoded digest does NOT appear in the audit log
	hexDigest := hex.EncodeToString(testDigest[:])
	if strings.Contains(auditOutput, hexDigest) {
		t.Fatalf("audit log leaked hex-encoded digest: %s", hexDigest)
	}

	// Assert base64-encoded digest does NOT appear in the audit log
	b64Digest := base64.StdEncoding.EncodeToString(testDigest[:])
	if strings.Contains(auditOutput, b64Digest) {
		t.Fatalf("audit log leaked base64-encoded digest: %s", b64Digest)
	}

	// Assert private key DER or PEM material does NOT appear in the audit log
	if strings.Contains(auditOutput, string(ecKeyDER)) {
		t.Fatalf("audit log leaked raw private key DER bytes")
	}
	hexKeyDER := hex.EncodeToString(ecKeyDER)
	if strings.Contains(auditOutput, hexKeyDER) {
		t.Fatalf("audit log leaked hex-encoded private key DER bytes")
	}
	if strings.Contains(auditOutput, "PRIVATE KEY") {
		t.Fatalf("audit log contains PRIVATE KEY string")
	}

	// Verify required audit fields and outcomes
	expectedOutcomes := []string{
		custodian.AuditOutcomeSuccess,
		custodian.AuditOutcomeRejected,
	}
	for i, line := range auditLines {
		var entry auditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if entry.Outcome != expectedOutcomes[i] {
			t.Fatalf("line %d outcome = %q, expected %q", i, entry.Outcome, expectedOutcomes[i])
		}
		if entry.Key != "p256" {
			t.Fatalf("line %d key = %q, expected p256", i, entry.Key)
		}
		if entry.HashAlgorithm != "HASH_ALGORITHM_SHA256" {
			t.Fatalf("line %d hash_algorithm = %q, expected HASH_ALGORITHM_SHA256", i, entry.HashAlgorithm)
		}
		if entry.Time.IsZero() {
			t.Fatalf("line %d time is zero", i)
		}
	}
}

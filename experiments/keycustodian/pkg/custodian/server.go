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

package custodian

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	keycustodianv1alpha1 "github.com/gke-labs/gateway-api-reference-implementation/experiments/keycustodian/api/v1alpha1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Audit log outcomes.
const (
	AuditOutcomeSuccess  = "success"
	AuditOutcomeRejected = "rejected"
	AuditOutcomeError    = "error"
	AuditOutcomeDenied   = "denied"
)

type keyEntry struct {
	signer           crypto.Signer
	certificateChain []byte
}

// Server implements keycustodianv1alpha1.KeyCustodianServiceServer.
type Server struct {
	keycustodianv1alpha1.UnimplementedKeyCustodianServiceServer
	keys        map[string]*keyEntry
	auditLogger *slog.Logger
}

// ServerOption configures a Server instance.
type ServerOption func(*Server)

// WithAuditLogger configures the structured audit logger.
func WithAuditLogger(logger *slog.Logger) ServerOption {
	return func(server *Server) {
		server.auditLogger = logger
	}
}

// NewServer creates a new custodian server, loading keys and certificate chains from directory.
func NewServer(directory string, options ...ServerOption) (*Server, error) {
	keys := make(map[string]*keyEntry)
	if directory != "" {
		loadedKeys, err := loadPEMDirectory(directory)
		if err != nil {
			return nil, fmt.Errorf("failed to load keys from %s: %w", directory, err)
		}
		keys = loadedKeys
	}
	server := &Server{keys: keys}
	for _, option := range options {
		option(server)
	}
	return server, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	var pkcs8Err, ecErr, pkcs1Err error
	if parsedKey, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := parsedKey.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, fmt.Errorf("pkcs8 key type %T is not a crypto.Signer", parsedKey)
	} else {
		pkcs8Err = err
	}
	if ecKey, err := x509.ParseECPrivateKey(der); err == nil {
		return ecKey, nil
	} else {
		ecErr = err
	}
	if rsaKey, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return rsaKey, nil
	} else {
		pkcs1Err = err
	}
	return nil, fmt.Errorf("unrecognized private key format: %w", errors.Join(pkcs8Err, ecErr, pkcs1Err))
}

func loadPEMDirectory(directory string) (map[string]*keyEntry, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]*keyEntry)
	for _, dirEntry := range entries {
		if dirEntry.IsDir() || strings.HasPrefix(dirEntry.Name(), ".") {
			continue
		}
		filePath := filepath.Join(directory, dirEntry.Name())
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		fileName := dirEntry.Name()
		extension := filepath.Ext(fileName)
		keyName := strings.TrimSuffix(fileName, extension)
		if secondExtension := filepath.Ext(keyName); secondExtension == ".key" || secondExtension == ".crt" || secondExtension == ".cert" {
			keyName = strings.TrimSuffix(keyName, secondExtension)
		}

		entry := keys[keyName]
		if entry == nil {
			entry = &keyEntry{}
			keys[keyName] = entry
		}

		remainingData := fileData
		var pemBlockCount int
		for {
			var block *pem.Block
			block, remainingData = pem.Decode(remainingData)
			if block == nil {
				break
			}
			pemBlockCount++
			switch block.Type {
			case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
				if entry.signer != nil {
					return nil, fmt.Errorf("duplicate private key for %q in %s", keyName, dirEntry.Name())
				}
				signer, err := parsePrivateKey(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("failed to parse private key in %s: %w", dirEntry.Name(), err)
				}
				entry.signer = signer
			case "CERTIFICATE":
				entry.certificateChain = append(entry.certificateChain, pem.EncodeToMemory(block)...)
			default:
				return nil, fmt.Errorf("unsupported PEM block type %q in %s", block.Type, dirEntry.Name())
			}
		}

		if pemBlockCount == 0 {
			return nil, fmt.Errorf("file %s contains no PEM blocks", dirEntry.Name())
		}
	}

	for keyName, entry := range keys {
		if entry.signer == nil {
			return nil, fmt.Errorf("certificate for key %q has no corresponding private key", keyName)
		}
	}

	return keys, nil
}

// ListKeys returns the names of all keys held by the custodian.
func (server *Server) ListKeys(ctx context.Context, req *keycustodianv1alpha1.ListKeysRequest) (*keycustodianv1alpha1.ListKeysResponse, error) {
	names := make([]string, 0, len(server.keys))
	for name := range server.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	return &keycustodianv1alpha1.ListKeysResponse{Keys: names}, nil
}

// GetCertificateChain returns the PEM-encoded certificate chain for the given key.
func (server *Server) GetCertificateChain(ctx context.Context, req *keycustodianv1alpha1.GetCertificateChainRequest) (*keycustodianv1alpha1.GetCertificateChainResponse, error) {
	entry, ok := server.keys[req.Key]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.Key)
	}
	if len(entry.certificateChain) == 0 {
		return nil, status.Errorf(codes.NotFound, "certificate chain for key %q not found", req.Key)
	}
	return &keycustodianv1alpha1.GetCertificateChainResponse{
		CertificateChain: entry.certificateChain,
	}, nil
}

// Sign performs a digital signature using the specified key and hash algorithm.
func (server *Server) Sign(ctx context.Context, req *keycustodianv1alpha1.SignRequest) (*keycustodianv1alpha1.SignResponse, error) {
	keyName := req.Key
	hashAlgorithm := req.HashAlgorithm.String()
	outcome := AuditOutcomeRejected

	credentials, err := CredFromContext(ctx)
	if err != nil {
		credentials = nil
	}
	defer func() {
		auditLog(ctx, server.auditLogger, credentials, keyName, hashAlgorithm, "", outcome)
	}()

	var expectedLength int
	var cryptoHash crypto.Hash
	switch req.HashAlgorithm {
	case keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256:
		expectedLength = 32
		cryptoHash = crypto.SHA256
	case keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA384:
		expectedLength = 48
		cryptoHash = crypto.SHA384
	case keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA512:
		expectedLength = 64
		cryptoHash = crypto.SHA512
	default:
		return nil, status.Errorf(codes.InvalidArgument, "invalid or unsupported hash algorithm: %v", req.HashAlgorithm)
	}

	if len(req.Digest) != expectedLength {
		return nil, status.Errorf(codes.InvalidArgument, "digest length %d does not match hash algorithm (expected %d)", len(req.Digest), expectedLength)
	}

	entry, ok := server.keys[req.Key]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "key %q not found", req.Key)
	}

	var signerOptions crypto.SignerOpts = cryptoHash
	if req.RsaPssSaltLength != nil {
		signerOptions = &rsa.PSSOptions{
			SaltLength: int(*req.RsaPssSaltLength),
			Hash:       cryptoHash,
		}
	}

	signature, err := entry.signer.Sign(rand.Reader, req.Digest, signerOptions)
	if err != nil {
		outcome = AuditOutcomeError
		return nil, status.Errorf(codes.Internal, "sign failed: %v", err)
	}
	outcome = AuditOutcomeSuccess
	return &keycustodianv1alpha1.SignResponse{Signature: signature}, nil
}

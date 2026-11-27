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

package jwt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	// DefaultAudience is the default audience required in ServiceAccount tokens.
	DefaultAudience = "snigateway"

	// CertServerAudience is the required audience for ServiceAccount tokens presented to certserver.
	CertServerAudience = "certserver"

	// TimeSkew is the allowed clock skew when evaluating exp and nbf claims.
	TimeSkew = 60 * time.Second

	// MaxTokenAge is the maximum allowed age of a token based on its iat claim.
	MaxTokenAge = 24 * time.Hour
)

// TokenClaims represents verified claims extracted from a ServiceAccount token.
type TokenClaims struct {
	Issuer    string
	Subject   string
	Audience  []string
	Expiry    time.Time
	NotBefore time.Time
	IssuedAt  time.Time
}

// TokenVerifier defines the interface for verifying ServiceAccount tokens.
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (*TokenClaims, error)
}

// Verifier implements TokenVerifier using a KeyProvider.
type Verifier struct {
	keyProvider KeyProvider
	audience    string
	timeNow     func() time.Time
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithAudience sets the expected audience (default "snigateway").
func WithAudience(aud string) VerifierOption {
	return func(v *Verifier) {
		if aud != "" {
			v.audience = aud
		}
	}
}

// WithTimeNow overrides time.Now for deterministic testing.
func WithTimeNow(fn func() time.Time) VerifierOption {
	return func(v *Verifier) {
		v.timeNow = fn
	}
}

// NewVerifier creates a new Verifier with the given KeyProvider.
func NewVerifier(kp KeyProvider, opts ...VerifierOption) *Verifier {
	v := &Verifier{
		keyProvider: kp,
		audience:    DefaultAudience,
		timeNow:     time.Now,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var multi []string
		if err := json.Unmarshal(data, &multi); err != nil {
			return fmt.Errorf("decoding aud claim as list of strings: %w", err)
		}
		*s = multi
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err != nil {
		return fmt.Errorf("decoding aud claim as string: %w", err)
	}
	*s = []string{single}
	return nil
}

type jwtPayload struct {
	Iss string        `json:"iss"`
	Sub string        `json:"sub"`
	Aud stringOrSlice `json:"aud"`
	Exp *int64        `json:"exp"`
	Nbf *int64        `json:"nbf"`
	Iat *int64        `json:"iat"`
}

func base64DecodeURL(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}

// Verify validates the token's structure, algorithm, signature, issuer, audience, and time validity.
// Note: Errors returned from Verify NEVER include the token string or sensitive credentials.
func (v *Verifier) Verify(ctx context.Context, token string) (*TokenClaims, error) {
	if token == "" {
		return nil, errors.New("token is empty")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format: expected 3 dot-separated parts")
	}

	// 1. Decode header
	headerBytes, err := base64DecodeURL(parts[0])
	if err != nil {
		return nil, errors.New("failed to decode token header")
	}

	var hdr jwtHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, errors.New("failed to parse token header JSON")
	}

	// 2. Enforce algorithm allowlist (RS256, ES256). Reject 'none' and HMAC algorithms.
	switch hdr.Alg {
	case "RS256", "ES256":
		// Allowed algorithms
	case "none", "NONE":
		return nil, errors.New("unsupported algorithm: 'none' is rejected")
	case "HS256", "HS384", "HS512":
		return nil, errors.New("unsupported algorithm: HMAC algorithms are rejected")
	default:
		return nil, fmt.Errorf("unsupported algorithm %q: only RS256 and ES256 are permitted", hdr.Alg)
	}

	// 3. Decode payload
	payloadBytes, err := base64DecodeURL(parts[1])
	if err != nil {
		return nil, errors.New("failed to decode token payload")
	}

	var payload jwtPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, errors.New("failed to parse token payload JSON")
	}

	if payload.Iss == "" {
		return nil, errors.New("token missing required 'iss' claim")
	}
	if payload.Sub == "" {
		return nil, errors.New("token missing required 'sub' claim")
	}

	// 4. Validate audience
	audFound := false
	for _, a := range payload.Aud {
		if a == v.audience {
			audFound = true
			break
		}
	}
	if !audFound {
		return nil, fmt.Errorf("token audience mismatch: required %q", v.audience)
	}

	// 5. Validate time claims (exp, nbf, iat)
	now := v.timeNow()

	// exp is required
	if payload.Exp == nil {
		return nil, errors.New("token missing required 'exp' claim")
	}
	expTime := time.Unix(*payload.Exp, 0)
	if now.After(expTime.Add(TimeSkew)) {
		return nil, errors.New("token is expired")
	}

	var nbfTime time.Time
	if payload.Nbf != nil {
		nbfTime = time.Unix(*payload.Nbf, 0)
		if now.Before(nbfTime.Add(-TimeSkew)) {
			return nil, errors.New("token not valid yet (nbf in future)")
		}
	}

	var iatTime time.Time
	if payload.Iat != nil {
		iatTime = time.Unix(*payload.Iat, 0)
		if now.Sub(iatTime) > MaxTokenAge+TimeSkew {
			return nil, errors.New("token iat is older than 24 hours")
		}
	}

	// 6. Decode signature
	sigBytes, err := base64DecodeURL(parts[2])
	if err != nil {
		return nil, errors.New("failed to decode token signature")
	}

	// 7. Resolve public key for issuer and kid
	if v.keyProvider == nil {
		return nil, errors.New("no key provider configured")
	}

	pubKey, err := v.keyProvider.GetKey(ctx, payload.Iss, hdr.Kid)
	if err != nil {
		return nil, fmt.Errorf("resolving key for issuer: %w", err)
	}

	// 8. Verify signature
	signedData := []byte(parts[0] + "." + parts[1])
	hashed := sha256.Sum256(signedData)

	switch hdr.Alg {
	case "RS256":
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("key type mismatch: expected RSA public key for RS256")
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed[:], sigBytes); err != nil {
			return nil, errors.New("invalid RS256 token signature")
		}

	case "ES256":
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("key type mismatch: expected ECDSA public key for ES256")
		}
		if len(sigBytes) != 64 {
			return nil, fmt.Errorf("invalid ES256 signature length: expected 64 bytes, got %d", len(sigBytes))
		}
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		if !ecdsa.Verify(ecPub, hashed[:], r, s) {
			return nil, errors.New("invalid ES256 token signature")
		}
	}

	return &TokenClaims{
		Issuer:    payload.Iss,
		Subject:   payload.Sub,
		Audience:  payload.Aud,
		Expiry:    expTime,
		NotBefore: nbfTime,
		IssuedAt:  iatTime,
	}, nil
}

// ParseTokenExpiry extracts the exp claim from a raw JWT without verifying its signature.
// This is used by clients to schedule timely token re-registration before expiry.
func ParseTokenExpiry(token string) (time.Time, error) {
	if token == "" {
		return time.Time{}, errors.New("token is empty")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, errors.New("invalid token format: expected 3 parts")
	}
	payloadBytes, err := base64DecodeURL(parts[1])
	if err != nil {
		return time.Time{}, errors.New("failed to decode token payload")
	}
	var payload jwtPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return time.Time{}, errors.New("failed to parse token payload JSON")
	}
	if payload.Exp == nil {
		return time.Time{}, errors.New("token missing exp claim")
	}
	return time.Unix(*payload.Exp, 0), nil
}

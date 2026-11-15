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

const (
	// DefaultInternalHostname is the default SNI hostname used for frontend mTLS API.
	DefaultInternalHostname = "snigateway.internal"

	// UpgradeProtocol is the protocol value used in HTTP Upgrade for reverse tunnels.
	UpgradeProtocol = "snigateway-tunnel"

	// HeaderSessionID is the HTTP header used to identify the backend session.
	HeaderSessionID = "X-Session-ID"
)

// SessionResponse is returned upon establishing a backend session.
type SessionResponse struct {
	SessionID string `json:"sessionId"`
	Status    string `json:"status"`
}

// RegistrationRequest contains hostnames to be served by the session.
type RegistrationRequest struct {
	Type      string   `json:"type,omitempty"`
	Hostnames []string `json:"hostnames"`
	Token     string   `json:"token,omitempty"`
}

// RegistrationResponse is returned upon successful registration.
type RegistrationResponse struct {
	Status    string   `json:"status"`
	Hostnames []string `json:"hostnames"`
}

// WireGuardRequest is sent to PUT /v1/sessions/<id>/wireguard to configure WireGuard for a session.
type WireGuardRequest struct {
	Type      string `json:"type,omitempty"`
	PublicKey string `json:"publicKey"`
	Token     string `json:"token,omitempty"`
}

// WireGuardResponse contains frontend WireGuard configuration for the session.
type WireGuardResponse struct {
	PublicKey   string `json:"publicKey"`
	Port        int    `json:"port"`
	ListenPort  int    `json:"listenPort,omitempty"`
	Address     string `json:"address,omitempty"`
	PeerAddress string `json:"peerAddress,omitempty"`
	Prefix      string `json:"prefix"`
}

// WireGuardExchangeRequest is an alias for WireGuardRequest.
type WireGuardExchangeRequest = WireGuardRequest

// WireGuardExchangeResponse is an alias for WireGuardResponse.
type WireGuardExchangeResponse = WireGuardResponse


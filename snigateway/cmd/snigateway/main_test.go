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

package main

import (
	"flag"
	"testing"
)

func TestFlagsGolden(t *testing.T) {
	type flagInfo struct {
		Name     string
		DefValue string
		Usage    string
	}
	golden := []flagInfo{
		{Name: "acme-challenge-ca-bundle-path", DefValue: "", Usage: "Path to the CA bundle PEM file to verify the upstream certificate server."},
		{Name: "acme-challenge-token-path", DefValue: "", Usage: "Path to the projected service-account token file for data-plane identity."},
		{Name: "acme-challenge-upstream-url", DefValue: "", Usage: "URL of the upstream certificate server to forward ACME HTTP-01 challenge requests to."},
		{Name: "ca-cert", DefValue: "", Usage: "Path to the CA certificate PEM file used to verify snigateway-frontend."},
		{Name: "client-cert", DefValue: "", Usage: "Path to the client certificate PEM file for mTLS authentication."},
		{Name: "client-key", DefValue: "", Usage: "Path to the client private key PEM file for mTLS authentication."},
		{Name: "controller-name", DefValue: "github.com/gke-labs/gateway-api-reference-implementation/snigateway", Usage: "The GatewayClass controller name managed by this instance."},
		{Name: "debug-error-responses", DefValue: "false", Usage: "Include detailed error messages in unmatched responses."},
		{Name: "frontend", DefValue: "127.0.0.1:443", Usage: "Address of the snigateway-frontend server (<ip-or-host>:<port>)."},
		{Name: "gateway-address", DefValue: "", Usage: "Address to report in Gateway status (repeatable, IP or hostname). Defaults to host part of --frontend."},
		{Name: "health-probe-bind-address", DefValue: ":8081", Usage: "The address the probe endpoint binds to."},
		{Name: "internal-hostname", DefValue: "snigateway.internal", Usage: "TLS ServerName for the snigateway-frontend mTLS management API."},
		{Name: "leader-elect", DefValue: "false", Usage: "Enable leader election for controller manager."},
		{Name: "leader-election-id", DefValue: "snigateway-controller", Usage: "The ID used for leader election."},
		{Name: "metrics-bind-address", DefValue: ":8080", Usage: "The address the metric endpoint binds to."},
		{Name: "proxy-bind-address", DefValue: "", Usage: "Optional HTTP proxy bind address. Disabled by default."},
		{Name: "token-file", DefValue: "", Usage: "Path to ServiceAccount token file for authentication."},
		{Name: "tunnel-pool-size", DefValue: "4", Usage: "Number of idle pre-dialed reverse tunnel connections to maintain with the frontend when using TCP pool or H2 transport."},
		{Name: "tunnel-transport", DefValue: "tcp", Usage: "Tunnel transport to use (tcp, h2)."},
	}

	cfg := DefaultConfig()
	opts := DefaultGARIOptions()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	BindFlags(fs, &opts, &cfg)

	var got []flagInfo
	fs.VisitAll(func(f *flag.Flag) {
		got = append(got, flagInfo{Name: f.Name, DefValue: f.DefValue, Usage: f.Usage})
	})

	if len(got) != len(golden) {
		t.Fatalf("got %d flags, want %d", len(got), len(golden))
	}
	for i := range golden {
		if got[i] != golden[i] {
			t.Errorf("flag %d mismatch:\ngot:  %+v\nwant: %+v", i, got[i], golden[i])
		}
	}
}

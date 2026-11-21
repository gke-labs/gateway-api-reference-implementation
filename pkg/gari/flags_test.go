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

package gari

import (
	"flag"
	"reflect"
	"strings"
	"testing"
)

func TestCommaSeparatedSlice(t *testing.T) {
	var s []string
	val := CommaSeparatedSlice(&s)

	if got := val.String(); got != "" {
		t.Errorf("empty slice String() = %q, want empty string", got)
	}

	if err := val.Set("  10.0.0.0/8 ,  192.168.0.0/16 "); err != nil {
		t.Fatalf("unexpected error from Set: %v", err)
	}
	want := []string{"10.0.0.0/8", "192.168.0.0/16"}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("got %v, want %v", s, want)
	}
	if got := val.String(); got != "10.0.0.0/8,192.168.0.0/16" {
		t.Errorf("val.String() = %q, want %q", got, "10.0.0.0/8,192.168.0.0/16")
	}

	// Setting empty or whitespace-only should not append empty strings
	if err := val.Set("  , , "); err != nil {
		t.Fatalf("unexpected error from Set: %v", err)
	}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("got %v, want %v", s, want)
	}

	// Repeated flag occurrence
	if err := val.Set("172.16.0.0/12"); err != nil {
		t.Fatalf("unexpected error from Set: %v", err)
	}
	want = []string{"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("got %v, want %v", s, want)
	}

	// Test with flag.FlagSet
	var fsSlice []string
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Var(CommaSeparatedSlice(&fsSlice), "cidrs", "allowed cidrs")
	if err := fs.Parse([]string{"--cidrs=1.1.1.1/32, 2.2.2.2/32", "--cidrs", "3.3.3.3/32"}); err != nil {
		t.Fatalf("fs.Parse failed: %v", err)
	}
	wantFS := []string{"1.1.1.1/32", "2.2.2.2/32", "3.3.3.3/32"}
	if !reflect.DeepEqual(fsSlice, wantFS) {
		t.Errorf("got %v, want %v", fsSlice, wantFS)
	}
}

func TestStringSlice(t *testing.T) {
	var s []string
	val := StringSlice(&s)

	if got := val.String(); got != "" {
		t.Errorf("empty slice String() = %q, want empty string", got)
	}

	if err := val.Set("addr1"); err != nil {
		t.Fatalf("unexpected error from Set: %v", err)
	}
	if err := val.Set("addr2"); err != nil {
		t.Fatalf("unexpected error from Set: %v", err)
	}
	want := []string{"addr1", "addr2"}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("got %v, want %v", s, want)
	}
	if got := val.String(); got != "addr1,addr2" {
		t.Errorf("val.String() = %q, want %q", got, "addr1,addr2")
	}
}

func TestOptionsComplete_InternalAPIFlags(t *testing.T) {
	// Missing token file
	options := DefaultOptions()
	options.DataplaneMode = true
	options.DataplaneGatewayNamespace = "ns"
	options.DataplaneGatewayName = "gw"
	options.InternalAPIAddress = "127.0.0.1:8443"
	options.InternalAPICAFile = "/path/to/ca.crt"
	if err := options.complete(); err == nil || !strings.Contains(err.Error(), "--internal-api-token-file") {
		t.Errorf("expected error naming --internal-api-token-file, got %v", err)
	}

	// Missing CA file
	options = DefaultOptions()
	options.DataplaneMode = true
	options.DataplaneGatewayNamespace = "ns"
	options.DataplaneGatewayName = "gw"
	options.InternalAPIAddress = "127.0.0.1:8443"
	options.InternalAPITokenFile = "/path/to/token"
	if err := options.complete(); err == nil || !strings.Contains(err.Error(), "--internal-api-ca-file") {
		t.Errorf("expected error naming --internal-api-ca-file, got %v", err)
	}

	// Missing address
	options = DefaultOptions()
	options.DataplaneMode = true
	options.DataplaneGatewayNamespace = "ns"
	options.DataplaneGatewayName = "gw"
	options.InternalAPICAFile = "/path/to/ca.crt"
	options.InternalAPITokenFile = "/path/to/token"
	if err := options.complete(); err == nil || !strings.Contains(err.Error(), "--internal-api-address") {
		t.Errorf("expected error naming --internal-api-address, got %v", err)
	}

	// Missing all internal API flags in dataplane mode
	options = DefaultOptions()
	options.DataplaneMode = true
	options.DataplaneGatewayNamespace = "ns"
	options.DataplaneGatewayName = "gw"
	if err := options.complete(); err == nil || !strings.Contains(err.Error(), "--internal-api-address") {
		t.Errorf("expected error naming --internal-api-address, got %v", err)
	}

	// Not in dataplane mode
	options = DefaultOptions()
	options.DataplaneMode = false
	options.InternalAPIAddress = "127.0.0.1:8443"
	options.InternalAPICAFile = "/path/to/ca.crt"
	options.InternalAPITokenFile = "/path/to/token"
	if err := options.complete(); err == nil || !strings.Contains(err.Error(), "require --dataplane-mode") {
		t.Errorf("expected require --dataplane-mode error, got %v", err)
	}

	// Missing gateway namespace / name
	options = DefaultOptions()
	options.DataplaneMode = true
	options.InternalAPIAddress = "127.0.0.1:8443"
	options.InternalAPICAFile = "/path/to/ca.crt"
	options.InternalAPITokenFile = "/path/to/token"
	if err := options.complete(); err == nil || !strings.Contains(err.Error(), "required in --dataplane-mode") {
		t.Errorf("expected required in --dataplane-mode error, got %v", err)
	}

	// Valid combination
	options = DefaultOptions()
	options.DataplaneMode = true
	options.DataplaneGatewayNamespace = "ns"
	options.DataplaneGatewayName = "gw"
	options.InternalAPIAddress = "127.0.0.1:8443"
	options.InternalAPICAFile = "/path/to/ca.crt"
	options.InternalAPITokenFile = "/path/to/token"
	if err := options.complete(); err != nil {
		t.Fatalf("unexpected error for valid options: %v", err)
	}
}

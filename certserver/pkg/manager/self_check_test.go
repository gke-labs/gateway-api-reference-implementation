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

package manager

import (
	"net"
	"testing"
)

func TestSelfCheck_ForbiddenDestinationsRefused(t *testing.T) {
	forbiddenIPs := []string{
		"127.0.0.1",
		"127.0.0.2",
		"::1",
		"169.254.169.254",
		"169.254.1.1",
		"fd00:ec2::254",
		"0.0.0.0",
		"::",
		"224.0.0.1",
		"ff02::1",
	}

	for _, ipString := range forbiddenIPs {
		ip := net.ParseIP(ipString)
		if ip == nil {
			t.Fatalf("failed to parse IP %q", ipString)
		}
		if !isForbiddenSelfCheckIP(ip) {
			t.Errorf("expected IP %s to be forbidden, but was permitted", ipString)
		}
	}

	allowedIPs := []string{
		"93.184.216.34",
		"2606:2800:220:1:248:1893:25c8:1946",
		// RFC 1918 and private ranges are allowed for in-cluster/test environments
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
	}
	for _, ipString := range allowedIPs {
		ip := net.ParseIP(ipString)
		if ip == nil {
			t.Fatalf("failed to parse IP %q", ipString)
		}
		if isForbiddenSelfCheckIP(ip) {
			t.Errorf("expected IP %s to be permitted, but was forbidden", ipString)
		}
	}
}

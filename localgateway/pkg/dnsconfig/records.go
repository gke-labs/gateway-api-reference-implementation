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

package dnsconfig

import (
	"net"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/validation"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

// BuildRecords computes the deterministic list of DNS records from the controller State.
// It reads desired Gateway status computed by the state, includes only HTTP listeners
// that are accepted and programmed, skips loopback and unspecified addresses,
// and resolves conflicts deterministically by oldest creation time, then namespace and name.
func BuildRecords(controllerState *state.State) []Record {
	if controllerState == nil {
		return nil
	}

	gatewayStates := controllerState.GetGateways()
	var matchingGateways []*gatewayv1.Gateway
	for _, gatewayState := range gatewayStates {
		if gatewayState == nil || gatewayState.Gateway == nil || gatewayState.Gateway.DeletionTimestamp != nil {
			continue
		}
		matchingGateways = append(matchingGateways, gatewayState.Gateway)
	}

	// Beyond the Gateway API specification: the specification does not define which Gateway owns a contested DNS name, so the controller gives it to the oldest Gateway by creation time, breaking ties by namespace and name.
	sort.Slice(matchingGateways, func(i, j int) bool {
		timeI := matchingGateways[i].CreationTimestamp
		timeJ := matchingGateways[j].CreationTimestamp
		if !timeI.Equal(&timeJ) {
			return timeI.Before(&timeJ)
		}
		if matchingGateways[i].Namespace != matchingGateways[j].Namespace {
			return matchingGateways[i].Namespace < matchingGateways[j].Namespace
		}
		return matchingGateways[i].Name < matchingGateways[j].Name
	})

	claimedHostnames := make(map[string]bool)
	var records []Record

	for _, gateway := range matchingGateways {
		gatewayKey := types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}
		status, ok := controllerState.GetDesiredGatewayStatus(gatewayKey)
		if !ok || !isGatewayProgrammed(status) {
			continue
		}

		var addressStrings []string
		for _, address := range status.Addresses {
			ip := net.ParseIP(address.Value)
			if ip == nil {
				continue
			}
			// Skip loopback (127.0.0.0/8, ::1) and unspecified (0.0.0.0, ::) addresses
			// because mDNS records advertise addresses reachable by other clients on the local network (RFC 6762).
			if ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			addressStrings = append(addressStrings, ip.String())
		}
		if len(addressStrings) == 0 {
			continue
		}

		for _, listener := range gateway.Spec.Listeners {
			if listener.Protocol != gatewayv1.HTTPProtocolType || listener.Hostname == nil {
				continue
			}
			rawHostname := string(*listener.Hostname)
			if err := validation.ValidateSingleLabelLocalHostname(rawHostname); err != nil {
				continue
			}
			if !isListenerAcceptedAndProgrammed(status, listener.Name) {
				continue
			}

			canonicalHostname := strings.ToLower(rawHostname)
			if claimedHostnames[canonicalHostname] {
				// Already claimed by an older Gateway (or earlier listener).
				continue
			}
			claimedHostnames[canonicalHostname] = true

			records = append(records, Record{
				Name:      canonicalHostname,
				Addresses: append([]string(nil), addressStrings...),
			})
		}
	}

	return records
}

// isGatewayProgrammed returns true if the status has a Programmed condition with status True.
func isGatewayProgrammed(status gatewayv1.GatewayStatus) bool {
	for _, condition := range status.Conditions {
		if condition.Type == string(gatewayv1.GatewayConditionProgrammed) && condition.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

// isListenerAcceptedAndProgrammed returns true if the specified listener has both Accepted
// and Programmed conditions with status True.
func isListenerAcceptedAndProgrammed(status gatewayv1.GatewayStatus, listenerName gatewayv1.SectionName) bool {
	for _, listenerStatus := range status.Listeners {
		if listenerStatus.Name != listenerName {
			continue
		}
		var accepted, programmed bool
		for _, condition := range listenerStatus.Conditions {
			if condition.Type == string(gatewayv1.ListenerConditionAccepted) && condition.Status == metav1.ConditionTrue {
				accepted = true
			}
			if condition.Type == string(gatewayv1.ListenerConditionProgrammed) && condition.Status == metav1.ConditionTrue {
				programmed = true
			}
		}
		return accepted && programmed
	}
	return false
}

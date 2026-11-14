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

package registry

import (
	"errors"
	"fmt"
	"strings"
)

// CallerIdentity identifies a verified caller by cluster ID, Kubernetes namespace, and ServiceAccount.
type CallerIdentity struct {
	ClusterID      string `json:"cluster_id"`
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"service_account"`
}

// String returns a human-readable representation of CallerIdentity.
func (id CallerIdentity) String() string {
	return fmt.Sprintf("%s/%s/%s", id.ClusterID, id.Namespace, id.ServiceAccount)
}

// FullSubject returns the standard Kubernetes ServiceAccount subject representation:
// "system:serviceaccount:<namespace>:<serviceaccount>".
func (id CallerIdentity) FullSubject() string {
	return fmt.Sprintf("system:serviceaccount:%s:%s", id.Namespace, id.ServiceAccount)
}

// ParseSubject extracts the Kubernetes namespace and ServiceAccount name from a JWT subject claim.
func ParseSubject(sub string) (string, string, error) {
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return "", "", errors.New("subject claim is empty")
	}

	const prefix = "system:serviceaccount:"
	if strings.HasPrefix(sub, prefix) {
		rest := strings.TrimPrefix(sub, prefix)
		ns, sa, ok := strings.Cut(rest, ":")
		if !ok || ns == "" || sa == "" {
			return "", "", fmt.Errorf("malformed service account subject %q", sub)
		}
		return ns, sa, nil
	}

	if strings.Contains(sub, "/") {
		ns, sa, ok := strings.Cut(sub, "/")
		if ok && ns != "" && sa != "" {
			return ns, sa, nil
		}
	}

	if strings.Contains(sub, ":") {
		ns, sa, ok := strings.Cut(sub, ":")
		if ok && ns != "" && sa != "" {
			return ns, sa, nil
		}
	}

	return "", "", fmt.Errorf("subject %q is not a valid Kubernetes service account subject", sub)
}

// IsAuthorizedController reports whether the given caller identity matches the cluster's configured
// GARI controller identity.
func IsAuthorizedController(cluster *ClusterConfig, id CallerIdentity) bool {
	if cluster == nil {
		return false
	}

	// 1. If explicit ControllerNamespace is set, verify namespace match
	if cluster.ControllerNamespace != "" && cluster.ControllerNamespace != id.Namespace {
		return false
	}

	ctrlSA := strings.TrimSpace(cluster.ControllerServiceAccount)
	if ctrlSA == "" {
		// If neither ControllerServiceAccount nor ControllerNamespace is configured, refuse by default
		return false
	}

	// 2. Exact match against full subject
	if ctrlSA == id.FullSubject() {
		return true
	}

	// 3. Match against "namespace/serviceaccount" or "namespace:serviceaccount"
	if ctrlSA == fmt.Sprintf("%s/%s", id.Namespace, id.ServiceAccount) ||
		ctrlSA == fmt.Sprintf("%s:%s", id.Namespace, id.ServiceAccount) {
		return true
	}

	// 4. Match against just service account name if ControllerNamespace matches or wasn't specified
	if ctrlSA == id.ServiceAccount {
		if cluster.ControllerNamespace == "" || cluster.ControllerNamespace == id.Namespace {
			return true
		}
	}

	return false
}

// MatchesDataPlaneServiceAccount checks whether id matches the expected data plane service account.
// It requires fully qualified identities ("system:serviceaccount:<ns>:<sa>" or "<ns>/<sa>").
func MatchesDataPlaneServiceAccount(configuredSA string, id CallerIdentity) bool {
	configuredSA = strings.TrimSpace(configuredSA)
	if configuredSA == "" {
		return false
	}

	if id.Namespace == "" || id.ServiceAccount == "" {
		return false
	}

	expectedNS, expectedSA, err := ParseSubject(configuredSA)
	if err != nil {
		return false
	}

	return id.Namespace == expectedNS && id.ServiceAccount == expectedSA
}

// IsAuthorizedForwarder checks whether the forwarding identity is authorized to answer challenges for
// the requesting Gateway. It returns true if:
// 1. The forwarding identity is the data-plane service account recorded for the requesting Gateway in the same cluster; OR
// 2. The forwarding identity is a data-plane service account recorded for a Gateway in the same shared-front-end group.
func IsAuthorizedForwarder(reg *Registry, bindingStore BindingStore, reqClusterID, reqGateway, reqDataPlaneSA string, forwarderID CallerIdentity) bool {
	// 1. Check if forwarding identity is the data plane SA for the requesting Gateway in the same cluster
	if forwarderID.ClusterID == reqClusterID && MatchesDataPlaneServiceAccount(reqDataPlaneSA, forwarderID) {
		return true
	}

	// 2. Check shared-front-end group
	if reg == nil || bindingStore == nil {
		return false
	}

	reqCluster, ok := reg.GetCluster(reqClusterID)
	if !ok || reqCluster == nil {
		return false
	}

	reqGroup := getGatewaySharedFrontEndGroup(reqCluster, reqGateway)
	if reqGroup == "" {
		return false
	}

	// Forwarder must also belong to a cluster configured in the registry
	if _, ok := reg.GetCluster(forwarderID.ClusterID); !ok {
		return false
	}

	// Inspect all recorded bindings to see if forwarder matches a Gateway in the same shared-front-end group
	for _, b := range bindingStore.ListBindings() {
		bCluster, ok := reg.GetCluster(b.ClusterID)
		if !ok || bCluster == nil {
			continue
		}
		bGroup := getGatewaySharedFrontEndGroup(bCluster, b.Gateway)
		if bGroup == reqGroup && b.ClusterID == forwarderID.ClusterID {
			if MatchesDataPlaneServiceAccount(b.DataPlaneServiceAccount, forwarderID) {
				return true
			}
		}
	}

	return false
}

func getGatewaySharedFrontEndGroup(cluster *ClusterConfig, gateway string) string {
	if cluster == nil {
		return ""
	}
	if cluster.GatewaySharedFrontEndGroups != nil && strings.Contains(gateway, "/") {
		if g, ok := cluster.GatewaySharedFrontEndGroups[gateway]; ok && g != "" {
			return g
		}
	}
	return cluster.SharedFrontEndGroup
}

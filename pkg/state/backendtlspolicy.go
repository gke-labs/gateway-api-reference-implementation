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

package state

import (
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ServicePortKey identifies a named port on a Service, or the whole Service when Port is empty.
type ServicePortKey struct {
	// Service is the namespaced name of the target Service.
	Service types.NamespacedName

	// Port is the port name (sectionName) on the Service, or empty to select the whole Service.
	Port string
}

// TargetRefResult represents the resolution result of a single BackendTLSPolicy targetRef that names a core Service.
type TargetRefResult struct {
	// TargetRef is the local policy target reference.
	TargetRef gatewayv1.LocalPolicyTargetReferenceWithSectionName

	// ServiceExists reports whether the targeted Service exists.
	// The status change for a port name that is not found reads this.
	ServiceExists bool

	// PortExists reports whether the named port exists on the Service.
	// The status change for a port name that is not found reads this.
	PortExists bool
}

// MissingPort reports whether this targetRef specifies a named port (sectionName)
// on a Service that exists, but that named port does not exist on the Service.
// The status change for a port name that is not found reads this.
func (targetResult TargetRefResult) MissingPort() bool {
	return targetResult.TargetRef.SectionName != nil && *targetResult.TargetRef.SectionName != "" && targetResult.ServiceExists && !targetResult.PortExists
}

// BackendTLSPolicyResolution contains the resolved targets, winning policies, and conflict state for a set of BackendTLSPolicies.
type BackendTLSPolicyResolution struct {
	// policies maps a Service and port name (or empty port for the whole Service) to the winning policy.
	policies map[ServicePortKey]*gatewayv1.BackendTLSPolicy

	// conflicts maps each losing conflicted policy to the winning policy's "namespace/name".
	conflicts map[types.NamespacedName]string

	// targetResults maps each policy's namespaced name to the resolution results of its core Service targetRefs.
	targetResults map[types.NamespacedName][]TargetRefResult
}

// PolicyForService returns the winning BackendTLSPolicy for the given Service and port name.
// If portName is non-empty and a policy targets that specific port, that policy is returned.
// Otherwise, any policy targeting the whole Service is returned.
func (resolution *BackendTLSPolicyResolution) PolicyForService(serviceKey types.NamespacedName, portName string) *gatewayv1.BackendTLSPolicy {
	if resolution == nil {
		return nil
	}
	if portName != "" {
		if policy, ok := resolution.policies[ServicePortKey{Service: serviceKey, Port: portName}]; ok {
			return policy
		}
	}
	return resolution.policies[ServicePortKey{Service: serviceKey, Port: ""}]
}

// Conflict reports whether the policy is conflicted with an older policy, and if so, returns the conflicting policy.
func (resolution *BackendTLSPolicyResolution) Conflict(policyKey types.NamespacedName) (string, bool) {
	if resolution == nil {
		return "", false
	}
	conflictingPolicy, ok := resolution.conflicts[policyKey]
	return conflictingPolicy, ok
}

// TargetsService reports whether the given policy has a targetRef targeting the given Service.
func (resolution *BackendTLSPolicyResolution) TargetsService(policyKey, serviceKey types.NamespacedName) bool {
	if resolution == nil || policyKey.Namespace != serviceKey.Namespace {
		return false
	}
	for _, targetResult := range resolution.targetResults[policyKey] {
		if string(targetResult.TargetRef.Name) == serviceKey.Name {
			return true
		}
	}
	return false
}

// TargetResultsForPolicy returns the TargetRefResults for the given policy.
func (resolution *BackendTLSPolicyResolution) TargetResultsForPolicy(policyKey types.NamespacedName) []TargetRefResult {
	if resolution == nil {
		return nil
	}
	return resolution.targetResults[policyKey]
}

// sortBackendTLSPolicies deterministically sorts BackendTLSPolicies by creation timestamp, then by namespaced name.
func sortBackendTLSPolicies(backendTLSPolicies []*gatewayv1.BackendTLSPolicy) []*gatewayv1.BackendTLSPolicy {
	if len(backendTLSPolicies) == 0 {
		return nil
	}
	var nonNilPolicies []*gatewayv1.BackendTLSPolicy
	for _, policy := range backendTLSPolicies {
		if policy != nil {
			nonNilPolicies = append(nonNilPolicies, policy)
		}
	}
	sort.SliceStable(nonNilPolicies, func(i, j int) bool {
		if nonNilPolicies[i].CreationTimestamp.Time.Before(nonNilPolicies[j].CreationTimestamp.Time) {
			return true
		}
		if nonNilPolicies[i].CreationTimestamp.Time.After(nonNilPolicies[j].CreationTimestamp.Time) {
			return false
		}
		if nonNilPolicies[i].Namespace != nonNilPolicies[j].Namespace {
			return nonNilPolicies[i].Namespace < nonNilPolicies[j].Namespace
		}
		return nonNilPolicies[i].Name < nonNilPolicies[j].Name
	})
	return nonNilPolicies
}

// ResolveBackendTLSPolicyTargets resolves BackendTLSPolicy targets against Kubernetes Services
// and determines winning policies and conflicts according to Gateway API Direct Policy Attachment
// precedence rules (see the targetRefs comment of apis/v1/backendtlspolicy_types.go):
//
//  1. A policy targeting a specific section (Service port by name via sectionName) takes precedence
//     over a policy targeting the entire Service for that port.
//  2. When more than one BackendTLSPolicy selects the same target and sectionName, implementations
//     MUST determine precedence using the following criteria, continuing on ties:
//     - The older policy by creation timestamp takes precedence.
//     - The policy appearing first in alphabetical order by {namespace}/{name}.
//  3. For any BackendTLSPolicy that does not take precedence, the implementation MUST ensure
//     the Accepted Condition is set to status: False, with Reason: Conflicted.
func ResolveBackendTLSPolicyTargets(
	backendTLSPolicies []*gatewayv1.BackendTLSPolicy,
	services map[types.NamespacedName]*corev1.Service,
) *BackendTLSPolicyResolution {
	resolution := &BackendTLSPolicyResolution{
		policies:      make(map[ServicePortKey]*gatewayv1.BackendTLSPolicy),
		conflicts:     make(map[types.NamespacedName]string),
		targetResults: make(map[types.NamespacedName][]TargetRefResult),
	}

	sortedPolicies := sortBackendTLSPolicies(backendTLSPolicies)

	for _, policy := range sortedPolicies {
		policyKey := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}

		for _, targetRef := range policy.Spec.TargetRefs {
			if string(targetRef.Group) != "" || string(targetRef.Kind) != "Service" {
				continue
			}

			serviceKey := types.NamespacedName{Namespace: policy.Namespace, Name: string(targetRef.Name)}
			var service *corev1.Service
			if services != nil {
				service = services[serviceKey]
			}
			serviceExists := service != nil

			portName := string(ValueOf(targetRef.SectionName))
			portExists := false
			if portName != "" && serviceExists {
				for _, servicePort := range service.Spec.Ports {
					if servicePort.Name == portName {
						portExists = true
						break
					}
				}
			}

			targetResult := TargetRefResult{
				TargetRef:     targetRef,
				ServiceExists: serviceExists,
				PortExists:    portExists,
			}
			resolution.targetResults[policyKey] = append(resolution.targetResults[policyKey], targetResult)

			portKey := ServicePortKey{Service: serviceKey, Port: portName}
			if winner, exists := resolution.policies[portKey]; exists {
				if winner.Namespace != policy.Namespace || winner.Name != policy.Name {
					if _, alreadyConflicted := resolution.conflicts[policyKey]; !alreadyConflicted {
						resolution.conflicts[policyKey] = fmt.Sprintf("%s/%s", winner.Namespace, winner.Name)
					}
				}
			} else {
				resolution.policies[portKey] = policy
			}
		}
	}

	return resolution
}

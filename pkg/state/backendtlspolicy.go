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

// ServicePortKey identifies a named port on a Service.
type ServicePortKey struct {
	Service types.NamespacedName
	Port    string
}

// TargetRefResult represents the resolution result of a single BackendTLSPolicy targetRef that names a core Service.
type TargetRefResult struct {
	TargetRef     gatewayv1.LocalPolicyTargetReferenceWithSectionName
	ServiceExists bool
	PortExists    bool
}

// MissingPort reports whether this targetRef specifies a named port (sectionName)
// on a Service that exists, but that named port does not exist on the Service.
func (tr TargetRefResult) MissingPort() bool {
	return tr.TargetRef.SectionName != nil && *tr.TargetRef.SectionName != "" && tr.ServiceExists && !tr.PortExists
}

// BackendTLSPolicyResolution contains the resolved targets, winning policies, and conflict state for a set of BackendTLSPolicies.
type BackendTLSPolicyResolution struct {
	// ServicePolicy maps a Service to the winning policy targeting the whole Service.
	ServicePolicy map[types.NamespacedName]*gatewayv1.BackendTLSPolicy

	// PortPolicy maps a Service and port name to the winning policy targeting that specific port.
	PortPolicy map[ServicePortKey]*gatewayv1.BackendTLSPolicy

	// Conflicts maps each losing conflicted policy to the winning policy's "namespace/name".
	Conflicts map[types.NamespacedName]string

	// TargetResults maps each policy's namespaced name to the resolution results of its core Service targetRefs.
	TargetResults map[types.NamespacedName][]TargetRefResult
}

// PolicyForService returns the winning BackendTLSPolicy for the given Service and port name.
// If portName is non-empty and a policy targets that specific port, that policy is returned.
// Otherwise, any policy targeting the whole Service is returned.
func (r *BackendTLSPolicyResolution) PolicyForService(svcKey types.NamespacedName, portName string) *gatewayv1.BackendTLSPolicy {
	if r == nil {
		return nil
	}
	if portName != "" {
		if p, ok := r.PortPolicy[ServicePortKey{Service: svcKey, Port: portName}]; ok {
			return p
		}
	}
	return r.ServicePolicy[svcKey]
}

// Conflict reports whether the policy is conflicted with an older policy, and if so, returns the conflicting policy.
func (r *BackendTLSPolicyResolution) Conflict(policyKey types.NamespacedName) (string, bool) {
	if r == nil {
		return "", false
	}
	conflictingPolicy, ok := r.Conflicts[policyKey]
	return conflictingPolicy, ok
}

// TargetsService reports whether the given policy has a targetRef targeting the given Service.
func (r *BackendTLSPolicyResolution) TargetsService(policyKey, svcKey types.NamespacedName) bool {
	if r == nil || policyKey.Namespace != svcKey.Namespace {
		return false
	}
	for _, tr := range r.TargetResults[policyKey] {
		if string(tr.TargetRef.Name) == svcKey.Name {
			return true
		}
	}
	return false
}

// TargetResultsForPolicy returns the TargetRefResults for the given policy.
func (r *BackendTLSPolicyResolution) TargetResultsForPolicy(policyKey types.NamespacedName) []TargetRefResult {
	if r == nil {
		return nil
	}
	return r.TargetResults[policyKey]
}

// sortBackendTLSPolicies deterministically sorts BackendTLSPolicies by creation timestamp, then by namespaced name.
func sortBackendTLSPolicies(backendTLSPolicies []*gatewayv1.BackendTLSPolicy) []*gatewayv1.BackendTLSPolicy {
	if len(backendTLSPolicies) == 0 {
		return nil
	}
	var nonNil []*gatewayv1.BackendTLSPolicy
	for _, p := range backendTLSPolicies {
		if p != nil {
			nonNil = append(nonNil, p)
		}
	}
	sort.SliceStable(nonNil, func(i, j int) bool {
		if nonNil[i].CreationTimestamp.Time.Before(nonNil[j].CreationTimestamp.Time) {
			return true
		}
		if nonNil[i].CreationTimestamp.Time.After(nonNil[j].CreationTimestamp.Time) {
			return false
		}
		if nonNil[i].Namespace != nonNil[j].Namespace {
			return nonNil[i].Namespace < nonNil[j].Namespace
		}
		return nonNil[i].Name < nonNil[j].Name
	})
	return nonNil
}

// ResolveBackendTLSPolicyTargets resolves BackendTLSPolicy targets against Kubernetes Services
// and determines winning policies and conflicts according to Gateway API Direct Policy Attachment
// precedence rules (see https://gateway-api.sigs.k8s.io/geps/gep-713/ and
// https://gateway-api.sigs.k8s.io/concepts/policy-attachment/#direct-policy-attachment):
//
//  1. A policy targeting a specific section (Service port by name via sectionName) takes precedence
//     over a policy targeting the entire Service for that port.
//  2. When multiple policies target the same target (the same Service and port name, or the same whole Service),
//     the policy with the oldest CreationTimestamp takes precedence. If creation timestamps are equal,
//     the policy that is alphabetically first by "{namespace}/{name}" takes precedence.
//  3. Any policy that targets the same resource/section as a higher-precedence policy is considered
//     conflicted and its Accepted condition is set to False with Reason "Conflicted".
func ResolveBackendTLSPolicyTargets(
	policies []*gatewayv1.BackendTLSPolicy,
	services map[types.NamespacedName]*corev1.Service,
) *BackendTLSPolicyResolution {
	res := &BackendTLSPolicyResolution{
		ServicePolicy: make(map[types.NamespacedName]*gatewayv1.BackendTLSPolicy),
		PortPolicy:    make(map[ServicePortKey]*gatewayv1.BackendTLSPolicy),
		Conflicts:     make(map[types.NamespacedName]string),
		TargetResults: make(map[types.NamespacedName][]TargetRefResult),
	}

	sorted := sortBackendTLSPolicies(policies)

	for _, policy := range sorted {
		policyKey := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}

		for _, targetRef := range policy.Spec.TargetRefs {
			if string(targetRef.Group) != "" || string(targetRef.Kind) != "Service" {
				continue
			}

			svcKey := types.NamespacedName{Namespace: policy.Namespace, Name: string(targetRef.Name)}
			var svc *corev1.Service
			if services != nil {
				svc = services[svcKey]
			}
			svcExists := svc != nil

			portName := string(ValueOf(targetRef.SectionName))
			portExists := false
			if portName != "" && svcExists {
				for _, p := range svc.Spec.Ports {
					if p.Name == portName {
						portExists = true
						break
					}
				}
			}

			res.TargetResults[policyKey] = append(res.TargetResults[policyKey], TargetRefResult{
				TargetRef:     targetRef,
				ServiceExists: svcExists,
				PortExists:    portExists,
			})

			if portName != "" {
				portKey := ServicePortKey{Service: svcKey, Port: portName}
				if winner, exists := res.PortPolicy[portKey]; exists {
					if winner.Namespace != policy.Namespace || winner.Name != policy.Name {
						if _, alreadyConflicted := res.Conflicts[policyKey]; !alreadyConflicted {
							res.Conflicts[policyKey] = fmt.Sprintf("%s/%s", winner.Namespace, winner.Name)
						}
					}
				} else {
					res.PortPolicy[portKey] = policy
				}
			} else {
				if winner, exists := res.ServicePolicy[svcKey]; exists {
					if winner.Namespace != policy.Namespace || winner.Name != policy.Name {
						if _, alreadyConflicted := res.Conflicts[policyKey]; !alreadyConflicted {
							res.Conflicts[policyKey] = fmt.Sprintf("%s/%s", winner.Namespace, winner.Name)
						}
					}
				} else {
					res.ServicePolicy[svcKey] = policy
				}
			}
		}
	}

	return res
}

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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestResolveBackendTLSPolicyTargets(t *testing.T) {
	t0 := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	t1 := metav1.NewTime(time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC))

	svcKey := types.NamespacedName{Namespace: "default", Name: "my-service"}
	svcWithPorts := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-service"},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80},
				{Name: "https", Port: 443},
			},
		},
	}

	httpsSection := gatewayv1.SectionName("https")
	missingSection := gatewayv1.SectionName("missing-port")

	tests := []struct {
		name     string
		policies []*gatewayv1.BackendTLSPolicy
		services map[types.NamespacedName]*corev1.Service
		check    func(t *testing.T, res *BackendTLSPolicyResolution)
	}{
		{
			name: "a named port",
			policies: []*gatewayv1.BackendTLSPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p-named-port", CreationTimestamp: t0},
					Spec: gatewayv1.BackendTLSPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: "",
									Kind:  "Service",
									Name:  "my-service",
								},
								SectionName: &httpsSection,
							},
						},
					},
				},
			},
			services: map[types.NamespacedName]*corev1.Service{svcKey: svcWithPorts},
			check: func(t *testing.T, res *BackendTLSPolicyResolution) {
				policyKey := types.NamespacedName{Namespace: "default", Name: "p-named-port"}
				targets := res.TargetResults[policyKey]
				if len(targets) != 1 {
					t.Fatalf("expected 1 target result, got %d", len(targets))
				}
				if !targets[0].ServiceExists {
					t.Errorf("expected ServiceExists=true")
				}
				if !targets[0].PortExists {
					t.Errorf("expected PortExists=true")
				}
				if targets[0].MissingPort() {
					t.Errorf("expected MissingPort=false")
				}

				if p := res.PolicyForService(svcKey, "https"); p == nil || p.Name != "p-named-port" {
					t.Errorf("expected PolicyForService(https) to be p-named-port, got %v", p)
				}
				if p := res.PolicyForService(svcKey, "http"); p != nil {
					t.Errorf("expected PolicyForService(http) to be nil, got %v", p)
				}
				if p := res.PolicyForService(svcKey, ""); p != nil {
					t.Errorf("expected PolicyForService('') to be nil, got %v", p)
				}

				if _, conflicted := res.Conflict(policyKey); conflicted {
					t.Errorf("expected policy not to be conflicted")
				}
			},
		},
		{
			name: "a whole Service",
			policies: []*gatewayv1.BackendTLSPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p-whole-svc", CreationTimestamp: t0},
					Spec: gatewayv1.BackendTLSPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: "",
									Kind:  "Service",
									Name:  "my-service",
								},
								SectionName: nil,
							},
						},
					},
				},
			},
			services: map[types.NamespacedName]*corev1.Service{svcKey: svcWithPorts},
			check: func(t *testing.T, res *BackendTLSPolicyResolution) {
				policyKey := types.NamespacedName{Namespace: "default", Name: "p-whole-svc"}
				targets := res.TargetResults[policyKey]
				if len(targets) != 1 {
					t.Fatalf("expected 1 target result, got %d", len(targets))
				}
				if !targets[0].ServiceExists {
					t.Errorf("expected ServiceExists=true")
				}
				if targets[0].PortExists {
					t.Errorf("expected PortExists=false for whole service target")
				}
				if targets[0].MissingPort() {
					t.Errorf("expected MissingPort=false")
				}

				if p := res.PolicyForService(svcKey, "https"); p == nil || p.Name != "p-whole-svc" {
					t.Errorf("expected PolicyForService(https) to be p-whole-svc, got %v", p)
				}
				if p := res.PolicyForService(svcKey, "http"); p == nil || p.Name != "p-whole-svc" {
					t.Errorf("expected PolicyForService(http) to be p-whole-svc, got %v", p)
				}
				if p := res.PolicyForService(svcKey, ""); p == nil || p.Name != "p-whole-svc" {
					t.Errorf("expected PolicyForService('') to be p-whole-svc, got %v", p)
				}

				if _, conflicted := res.Conflict(policyKey); conflicted {
					t.Errorf("expected policy not to be conflicted")
				}
			},
		},
		{
			name: "both on one Service (the named port wins for that port)",
			policies: []*gatewayv1.BackendTLSPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p-whole-svc", CreationTimestamp: t0},
					Spec: gatewayv1.BackendTLSPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: "",
									Kind:  "Service",
									Name:  "my-service",
								},
								SectionName: nil,
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p-named-port", CreationTimestamp: t1},
					Spec: gatewayv1.BackendTLSPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: "",
									Kind:  "Service",
									Name:  "my-service",
								},
								SectionName: &httpsSection,
							},
						},
					},
				},
			},
			services: map[types.NamespacedName]*corev1.Service{svcKey: svcWithPorts},
			check: func(t *testing.T, res *BackendTLSPolicyResolution) {
				// The named port policy wins for the named port "https"
				if p := res.PolicyForService(svcKey, "https"); p == nil || p.Name != "p-named-port" {
					t.Errorf("expected PolicyForService(https) to be p-named-port, got %v", p)
				}
				// The whole Service policy applies to other ports like "http" and unspecified ports
				if p := res.PolicyForService(svcKey, "http"); p == nil || p.Name != "p-whole-svc" {
					t.Errorf("expected PolicyForService(http) to be p-whole-svc, got %v", p)
				}
				if p := res.PolicyForService(svcKey, ""); p == nil || p.Name != "p-whole-svc" {
					t.Errorf("expected PolicyForService('') to be p-whole-svc, got %v", p)
				}

				// Neither policy conflicts because one targets a section and one targets the whole service
				if _, conflicted := res.Conflict(types.NamespacedName{Namespace: "default", Name: "p-whole-svc"}); conflicted {
					t.Errorf("expected p-whole-svc not to be conflicted")
				}
				if _, conflicted := res.Conflict(types.NamespacedName{Namespace: "default", Name: "p-named-port"}); conflicted {
					t.Errorf("expected p-named-port not to be conflicted")
				}
			},
		},
		{
			name: "two policies on the same target (the older wins, then by name)",
			policies: []*gatewayv1.BackendTLSPolicy{
				// Older wins by creation timestamp
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p-older", CreationTimestamp: t0},
					Spec: gatewayv1.BackendTLSPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: "",
									Kind:  "Service",
									Name:  "my-service",
								},
								SectionName: &httpsSection,
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p-newer", CreationTimestamp: t1},
					Spec: gatewayv1.BackendTLSPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: "",
									Kind:  "Service",
									Name:  "my-service",
								},
								SectionName: &httpsSection,
							},
						},
					},
				},
			},
			services: map[types.NamespacedName]*corev1.Service{svcKey: svcWithPorts},
			check: func(t *testing.T, res *BackendTLSPolicyResolution) {
				// Older policy wins
				if p := res.PolicyForService(svcKey, "https"); p == nil || p.Name != "p-older" {
					t.Errorf("expected PolicyForService(https) to be p-older, got %v", p)
				}

				olderKey := types.NamespacedName{Namespace: "default", Name: "p-older"}
				if _, conflicted := res.Conflict(olderKey); conflicted {
					t.Errorf("expected p-older not to be conflicted")
				}

				newerKey := types.NamespacedName{Namespace: "default", Name: "p-newer"}
				conflicting, conflicted := res.Conflict(newerKey)
				if !conflicted {
					t.Errorf("expected p-newer to be conflicted")
				}
				if conflicting != "default/p-older" {
					t.Errorf("expected conflicting policy 'default/p-older', got %q", conflicting)
				}
			},
		},
		{
			name: "two policies on the same target (tie-break by name)",
			policies: []*gatewayv1.BackendTLSPolicy{
				// Same creation timestamp: alphabetical name wins ("p-a" < "p-b")
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p-b", CreationTimestamp: t0},
					Spec: gatewayv1.BackendTLSPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: "",
									Kind:  "Service",
									Name:  "my-service",
								},
								SectionName: nil,
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p-a", CreationTimestamp: t0},
					Spec: gatewayv1.BackendTLSPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: "",
									Kind:  "Service",
									Name:  "my-service",
								},
								SectionName: nil,
							},
						},
					},
				},
			},
			services: map[types.NamespacedName]*corev1.Service{svcKey: svcWithPorts},
			check: func(t *testing.T, res *BackendTLSPolicyResolution) {
				// p-a wins alphabetically
				if p := res.PolicyForService(svcKey, ""); p == nil || p.Name != "p-a" {
					t.Errorf("expected PolicyForService to be p-a, got %v", p)
				}

				aKey := types.NamespacedName{Namespace: "default", Name: "p-a"}
				if _, conflicted := res.Conflict(aKey); conflicted {
					t.Errorf("expected p-a not to be conflicted")
				}

				bKey := types.NamespacedName{Namespace: "default", Name: "p-b"}
				conflicting, conflicted := res.Conflict(bKey)
				if !conflicted {
					t.Errorf("expected p-b to be conflicted")
				}
				if conflicting != "default/p-a" {
					t.Errorf("expected conflicting policy 'default/p-a', got %q", conflicting)
				}
			},
		},
		{
			name: "a missing Service",
			policies: []*gatewayv1.BackendTLSPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p-missing-svc", CreationTimestamp: t0},
					Spec: gatewayv1.BackendTLSPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: "",
									Kind:  "Service",
									Name:  "nonexistent-service",
								},
								SectionName: &httpsSection,
							},
						},
					},
				},
			},
			services: map[types.NamespacedName]*corev1.Service{svcKey: svcWithPorts},
			check: func(t *testing.T, res *BackendTLSPolicyResolution) {
				policyKey := types.NamespacedName{Namespace: "default", Name: "p-missing-svc"}
				targets := res.TargetResults[policyKey]
				if len(targets) != 1 {
					t.Fatalf("expected 1 target result, got %d", len(targets))
				}
				if targets[0].ServiceExists {
					t.Errorf("expected ServiceExists=false")
				}
				if targets[0].PortExists {
					t.Errorf("expected PortExists=false")
				}
				if targets[0].MissingPort() {
					t.Errorf("expected MissingPort=false when Service does not exist")
				}

				missingSvcKey := types.NamespacedName{Namespace: "default", Name: "nonexistent-service"}
				if !res.TargetsService(policyKey, missingSvcKey) {
					t.Errorf("expected TargetsService to be true")
				}
			},
		},
		{
			name: "a missing port name",
			policies: []*gatewayv1.BackendTLSPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p-missing-port", CreationTimestamp: t0},
					Spec: gatewayv1.BackendTLSPolicySpec{
						TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
									Group: "",
									Kind:  "Service",
									Name:  "my-service",
								},
								SectionName: &missingSection,
							},
						},
					},
				},
			},
			services: map[types.NamespacedName]*corev1.Service{svcKey: svcWithPorts},
			check: func(t *testing.T, res *BackendTLSPolicyResolution) {
				policyKey := types.NamespacedName{Namespace: "default", Name: "p-missing-port"}
				targets := res.TargetResults[policyKey]
				if len(targets) != 1 {
					t.Fatalf("expected 1 target result, got %d", len(targets))
				}
				if !targets[0].ServiceExists {
					t.Errorf("expected ServiceExists=true")
				}
				if targets[0].PortExists {
					t.Errorf("expected PortExists=false for nonexistent port")
				}
				if !targets[0].MissingPort() {
					t.Errorf("expected MissingPort=true when Service exists but port is missing")
				}

				if p := res.PolicyForService(svcKey, "http"); p != nil {
					t.Errorf("expected PolicyForService(http) to be nil, got %v", p)
				}
				if p := res.PolicyForService(svcKey, "https"); p != nil {
					t.Errorf("expected PolicyForService(https) to be nil, got %v", p)
				}
				if p := res.PolicyForService(svcKey, ""); p != nil {
					t.Errorf("expected PolicyForService('') to be nil, got %v", p)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := ResolveBackendTLSPolicyTargets(tt.policies, tt.services)
			tt.check(t, res)
		})
	}
}

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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// InternalL4Backend represents a resolved backend target and weight for an L4 route (TCPRoute or UDPRoute).
type InternalL4Backend struct {
	Target string
	Weight int32
}

// InternalTCPBackend is an alias for InternalL4Backend.
type InternalTCPBackend = InternalL4Backend

// InternalUDPBackend is an alias for InternalL4Backend.
type InternalUDPBackend = InternalL4Backend

// resolveL4BackendRefs compiles a slice of gatewayv1.BackendRef into InternalL4Backend targets
// using resolveBackendTarget, recording the first resolution failure in resolvedRefsCondition.
func resolveL4BackendRefs(
	backendRefs []gatewayv1.BackendRef,
	routeNamespace string,
	routeGeneration int64,
	routeKind string,
	services map[types.NamespacedName]*corev1.Service,
	refValidator ReferenceGrantValidator,
	resolvedRefsCondition *metav1.Condition,
) []InternalL4Backend {
	var backends []InternalL4Backend
	for _, backendRef := range backendRefs {
		backend, resolutionErr := resolveBackendTarget(
			backendRef.BackendObjectReference,
			routeKind,
			routeNamespace,
			routeGeneration,
			services,
			nil,
			nil,
			refValidator,
		)
		if resolutionErr != nil {
			if resolvedRefsCondition != nil && resolvedRefsCondition.Status == metav1.ConditionTrue {
				*resolvedRefsCondition = resolutionErr.Condition
			}
			continue
		}

		backends = append(backends, InternalL4Backend{
			Target: fmt.Sprintf("%s:%d", backend.Host, backend.Port),
			Weight: resolveBackendWeight(backendRef.Weight),
		})
	}
	return backends
}

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
// using resolveBackendTarget, returning any resolution failures.
func resolveL4BackendRefs(
	backendRefs []gatewayv1.BackendRef,
	routeNamespace string,
	routeKind string,
	services map[types.NamespacedName]*corev1.Service,
	refValidator ReferenceGrantValidator,
) ([]InternalL4Backend, []*ConditionError) {
	var backends []InternalL4Backend
	var refErrors []*ConditionError
	for _, backendRef := range backendRefs {
		backend, resolutionErr := resolveBackendTarget(
			backendRef.BackendObjectReference,
			routeKind,
			routeNamespace,
			services,
			nil,
			nil,
			refValidator,
		)
		if resolutionErr != nil {
			refErrors = append(refErrors, resolutionErr)
			continue
		}

		backends = append(backends, InternalL4Backend{
			Target: fmt.Sprintf("%s:%d", backend.Host, backend.Port),
			Weight: resolveBackendWeight(backendRef.Weight),
		})
	}
	return backends, refErrors
}

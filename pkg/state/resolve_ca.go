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
	"crypto/x509"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ResolveCACertificateRefs resolves the CA certificate references into a CertPool or returns an error reason.
// Returns (CertPool, resolvedRefsReason, resolvedRefsMessage, allInvalid)
func ResolveCACertificateRefs(validation *gatewayv1.FrontendTLSValidation, configMaps map[types.NamespacedName]*corev1.ConfigMap, gatewayNamespace string) (*x509.CertPool, gatewayv1.ListenerConditionReason, string, bool) {
	if validation == nil {
		return nil, "", "", false
	}

	clientCAs := x509.NewCertPool()
	validCount := 0

	var firstResolvedErrorReason gatewayv1.ListenerConditionReason
	var firstResolvedErrorMessage string

	setError := func(reason gatewayv1.ListenerConditionReason, message string) {
		if firstResolvedErrorReason == "" {
			firstResolvedErrorReason = reason
			firstResolvedErrorMessage = message
		}
	}

	for _, caRef := range validation.CACertificateRefs {
		if string(caRef.Group) == "" && string(caRef.Kind) == "ConfigMap" {
			ns := gatewayNamespace
			if caRef.Namespace != nil {
				ns = string(*caRef.Namespace)
			}
			if ns != gatewayNamespace {
				setError(gatewayv1.ListenerReasonRefNotPermitted, "Cross-namespace references are not permitted without ReferenceGrant")
				continue
			}

			cmName := types.NamespacedName{Namespace: ns, Name: string(caRef.Name)}
			if cm, ok := configMaps[cmName]; ok {
				if data, ok := cm.Data["ca.crt"]; ok {
					clientCAs.AppendCertsFromPEM([]byte(data))
					validCount++
				} else if data, ok := cm.BinaryData["ca.crt"]; ok {
					clientCAs.AppendCertsFromPEM(data)
					validCount++
				} else {
					setError(gatewayv1.ListenerReasonInvalidCACertificateRef, "Missing ca.crt in ConfigMap")
				}
			} else {
				setError(gatewayv1.ListenerReasonInvalidCACertificateRef, "ConfigMap not found")
			}
		} else {
			setError(gatewayv1.ListenerReasonInvalidCACertificateKind, "Unsupported CACertificateRef Group/Kind")
		}
	}

	allInvalid := false
	if validCount == 0 && len(validation.CACertificateRefs) > 0 {
		allInvalid = true
		if firstResolvedErrorReason == "" {
			setError(gatewayv1.ListenerReasonInvalidCACertificateRef, "No valid CACertificateRefs found")
		}
	}

	return clientCAs, firstResolvedErrorReason, firstResolvedErrorMessage, allInvalid
}

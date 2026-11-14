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
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	gatewayconsts "sigs.k8s.io/gateway-api/pkg/consts"
)

const (
	// RouteReasonAnotherRouteHoldsHostname is used when a TLSRoute cannot bind because another route holds the hostname.
	RouteReasonAnotherRouteHoldsHostname gatewayv1.RouteConditionReason = "AnotherRouteHoldsHostname"
)

var (
	sourceErrorLogMu   sync.Mutex
	lastSourceErrorLog = make(map[string]time.Time)
)

const sourceErrorLogInterval = 10 * time.Second

func logSourceError(sourceName string, gw *gatewayv1.Gateway, listener gatewayv1.SectionName, err error) {
	gwKey := ""
	if gw != nil {
		gwKey = fmt.Sprintf("%s/%s", gw.Namespace, gw.Name)
	}
	key := fmt.Sprintf("%s:%s:%s", sourceName, gwKey, listener)

	sourceErrorLogMu.Lock()
	now := time.Now()
	// Prune entries older than the log interval to prevent unbounded map growth over time
	for k, last := range lastSourceErrorLog {
		if now.Sub(last) > sourceErrorLogInterval {
			delete(lastSourceErrorLog, k)
		}
	}

	lastLog, seen := lastSourceErrorLog[key]
	shouldLog := !seen || now.Sub(lastLog) >= sourceErrorLogInterval
	if shouldLog {
		lastSourceErrorLog[key] = now
	}
	sourceErrorLogMu.Unlock()

	if shouldLog {
		klog.Errorf("certificate source %q returned error for listener %s on gateway %s: %v", sourceName, listener, gwKey, err)
	}
}

// CertificateSourceOptionKey is the tls.options key used to select a certificate source for a listener.
const CertificateSourceOptionKey = "gateway.gke-labs.io/certificate-source"

// CertificateResult contains the resolved certificates and condition details for a listener.
type CertificateResult struct {
	Certificates []*tls.Certificate

	// FailedReason is set when certificate resolution failed (e.g. InvalidCertificateRef, RefNotPermitted).
	// If empty and not Pending, resolution succeeded.
	FailedReason gatewayv1.ListenerConditionReason
	// FailedMessage is the message for ResolvedRefs and Programmed when resolution failed.
	FailedMessage string
	// ProgrammedMessage overrides the Programmed condition message when resolution failed.
	ProgrammedMessage string

	// Pending is true when the certificate is not yet available (e.g. external fetch in progress).
	// When Pending is true, ResolvedRefs and Programmed report ListenerReasonPending.
	Pending bool
}

// CertificateSource supplies TLS certificates for a Gateway's listeners.
//
// Contract:
//   - Implementations must be non-blocking: return what is currently known in local cache.
//   - Implementations must NOT modify gw or listener: they are shared State objects.
//   - When an external source's background worker updates its cache, it invokes the trigger
//     callback provided via SetRecomputeTrigger to request a State recompute.
type CertificateSource interface {
	// ResolveCertificates returns the certificates for the listener and the
	// listener conditions to report. It must not block: return what is known now.
	// It must not modify gw or listener.
	ResolveCertificates(gw *gatewayv1.Gateway, listener *gatewayv1.Listener) (CertificateResult, error)
}

// TriggerableCertificateSource is an optional interface that a CertificateSource can implement
// to receive a trigger callback when registered with GARI. Calling the trigger requests a State recompute.
type TriggerableCertificateSource interface {
	CertificateSource
	SetRecomputeTrigger(trigger func())
}

// SecretsCertificateSource resolves certificates from Secret references specified in listener.TLS.CertificateRefs.
type SecretsCertificateSource struct {
	Secrets      map[types.NamespacedName]*corev1.Secret
	RefValidator ReferenceGrantValidator
	Owner        ListenerOwner
}

// ResolveCertificates resolves and validates all certificates referenced in listener.TLS.CertificateRefs.
func (s *SecretsCertificateSource) ResolveCertificates(gw *gatewayv1.Gateway, listener *gatewayv1.Listener) (CertificateResult, error) {
	if listener == nil || listener.TLS == nil || len(listener.TLS.CertificateRefs) == 0 {
		return CertificateResult{
			FailedReason:      gatewayv1.ListenerReasonInvalidCertificateRef,
			FailedMessage:     "No certificate refs specified",
			ProgrammedMessage: "Invalid TLS configuration: no certificate refs specified",
		}, nil
	}

	ownerKind := s.Owner.Kind
	if ownerKind == "" {
		ownerKind = "Gateway"
	}
	ownerNamespace := s.Owner.Namespace
	if ownerNamespace == "" && gw != nil {
		ownerNamespace = gw.Namespace
	}

	var certs []*tls.Certificate
	for _, ref := range listener.TLS.CertificateRefs {
		group := ValueOf(ref.Group)
		kind := ValueOf(ref.Kind)
		if group != "" || (kind != "" && kind != "Secret") {
			return CertificateResult{
				FailedReason:      gatewayv1.ListenerReasonInvalidCertificateRef,
				FailedMessage:     fmt.Sprintf("Unsupported certificate ref group %q kind %q", group, kind),
				ProgrammedMessage: fmt.Sprintf("Invalid certificate ref group %q kind %q", group, kind),
			}, nil
		}

		if kind == "" {
			kind = "Secret"
		}

		secretNs := ownerNamespace
		if ref.Namespace != nil && string(*ref.Namespace) != "" {
			secretNs = string(*ref.Namespace)
		}
		secretKey := types.NamespacedName{
			Namespace: secretNs,
			Name:      string(ref.Name),
		}

		if secretNs != ownerNamespace {
			from := Reference{
				GroupKind: schema.GroupKind{Group: gatewayv1.GroupName, Kind: string(ownerKind)},
				Namespace: ownerNamespace,
			}
			to := Reference{
				GroupKind: schema.GroupKind{Group: string(group), Kind: string(kind)},
				Namespace: secretKey.Namespace,
				Name:      secretKey.Name,
			}
			if s.RefValidator == nil || !s.RefValidator.IsReferencePermitted(from, to) {
				return CertificateResult{
					FailedReason:      gatewayv1.ListenerReasonRefNotPermitted,
					FailedMessage:     fmt.Sprintf("Cross-namespace reference to %s/%s is not permitted by any ReferenceGrant", secretKey.Namespace, secretKey.Name),
					ProgrammedMessage: fmt.Sprintf("Cross-namespace reference to %s/%s is not permitted by any ReferenceGrant", secretKey.Namespace, secretKey.Name),
				}, nil
			}
		}

		var secret *corev1.Secret
		if s.Secrets != nil {
			secret = s.Secrets[secretKey]
		}
		if secret == nil {
			return CertificateResult{
				FailedReason:      gatewayv1.ListenerReasonInvalidCertificateRef,
				FailedMessage:     fmt.Sprintf("Secret %s/%s not found", secretKey.Namespace, secretKey.Name),
				ProgrammedMessage: fmt.Sprintf("Secret %s/%s not found", secretKey.Namespace, secretKey.Name),
			}, nil
		}

		certBytes := secret.Data[corev1.TLSCertKey]
		keyBytes := secret.Data[corev1.TLSPrivateKeyKey]
		if len(certBytes) == 0 || len(keyBytes) == 0 {
			return CertificateResult{
				FailedReason:      gatewayv1.ListenerReasonInvalidCertificateRef,
				FailedMessage:     fmt.Sprintf("Secret %s/%s is missing tls.crt or tls.key", secretKey.Namespace, secretKey.Name),
				ProgrammedMessage: fmt.Sprintf("Secret %s/%s is missing tls.crt or tls.key", secretKey.Namespace, secretKey.Name),
			}, nil
		}

		tlsCert, err := tls.X509KeyPair(certBytes, keyBytes)
		if err != nil {
			return CertificateResult{
				FailedReason:      gatewayv1.ListenerReasonInvalidCertificateRef,
				FailedMessage:     fmt.Sprintf("Secret %s/%s contains invalid certificate or key: %v", secretKey.Namespace, secretKey.Name, err),
				ProgrammedMessage: fmt.Sprintf("Secret %s/%s contains invalid certificate or key: %v", secretKey.Namespace, secretKey.Name, err),
			}, nil
		}

		certs = append(certs, &tlsCert)
	}

	return CertificateResult{
		Certificates: certs,
	}, nil
}

// ValidateCertificate verifies that cert has a non-empty certificate chain,
// that the leaf certificate parses as X.509, and that the private key matches
// the leaf certificate's public key.
func ValidateCertificate(cert *tls.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("certificate chain is empty")
	}
	if cert.PrivateKey == nil {
		return fmt.Errorf("certificate private key is missing")
	}
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("failed to parse leaf certificate: %w", err)
		}
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("certificate private key does not implement crypto.Signer")
	}
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(leaf.PublicKey) {
		return fmt.Errorf("certificate private key does not match public key")
	}
	return nil
}

// CopyTLSCertificate returns a deep copy of a tls.Certificate.
func CopyTLSCertificate(cert *tls.Certificate) *tls.Certificate {
	if cert == nil {
		return nil
	}
	cp := *cert
	if len(cert.Certificate) > 0 {
		cp.Certificate = make([][]byte, len(cert.Certificate))
		for i, c := range cert.Certificate {
			cp.Certificate[i] = bytes.Clone(c)
		}
	}
	if len(cert.OCSPStaple) > 0 {
		cp.OCSPStaple = bytes.Clone(cert.OCSPStaple)
	}
	if len(cert.SignedCertificateTimestamps) > 0 {
		cp.SignedCertificateTimestamps = make([][]byte, len(cert.SignedCertificateTimestamps))
		for i, sct := range cert.SignedCertificateTimestamps {
			cp.SignedCertificateTimestamps[i] = bytes.Clone(sct)
		}
	}
	if len(cert.SupportedSignatureAlgorithms) > 0 {
		cp.SupportedSignatureAlgorithms = make([]tls.SignatureScheme, len(cert.SupportedSignatureAlgorithms))
		copy(cp.SupportedSignatureAlgorithms, cert.SupportedSignatureAlgorithms)
	}
	return &cp
}

// ListenerOwner identifies the resource (Gateway or ListenerSet) that defines a listener.
type ListenerOwner struct {
	Kind      gatewayv1.Kind
	Namespace string
	Name      string
}

// ListenerSpec represents the common configuration specification of a listener across Gateway and ListenerSet.
type ListenerSpec struct {
	Name          gatewayv1.SectionName
	Port          gatewayv1.PortNumber
	Protocol      gatewayv1.ProtocolType
	Hostname      *gatewayv1.Hostname
	TLS           *gatewayv1.ListenerTLSConfig
	AllowedRoutes *gatewayv1.AllowedRoutes
}

// ListenerToSpec converts a Gateway Listener to ListenerSpec.
func ListenerToSpec(l gatewayv1.Listener) ListenerSpec {
	return ListenerSpec{
		Name:          l.Name,
		Port:          l.Port,
		Protocol:      l.Protocol,
		Hostname:      l.Hostname,
		TLS:           l.TLS,
		AllowedRoutes: l.AllowedRoutes,
	}
}

// ListenerEntryToSpec converts a ListenerSet ListenerEntry to ListenerSpec.
func ListenerEntryToSpec(l gatewayv1.ListenerEntry) ListenerSpec {
	return ListenerSpec{
		Name:          l.Name,
		Port:          l.Port,
		Protocol:      l.Protocol,
		Hostname:      l.Hostname,
		TLS:           l.TLS,
		AllowedRoutes: l.AllowedRoutes,
	}
}

// EffectiveListener represents a single compiled listener on a Gateway,
// originating either directly from the Gateway spec or attached via an allowed ListenerSet.
type EffectiveListener struct {
	// Owner identifies the resource (Gateway or ListenerSet) that defines this listener.
	Owner ListenerOwner
	// ParentGateway is the namespaced name of the Gateway that hosts this listener.
	ParentGateway types.NamespacedName

	// Name is the listener's name within its defining resource.
	Name gatewayv1.SectionName
	// Port is the network port on which this listener receives traffic.
	Port gatewayv1.PortNumber
	// Protocol is the network protocol expected on this port (e.g. HTTP, HTTPS, TLS, TCP, UDP).
	Protocol gatewayv1.ProtocolType
	// Hostname is the optional virtual host name or wildcard pattern configured on the listener.
	Hostname *gatewayv1.Hostname
	// TLS contains the listener's TLS settings, such as mode and certificate references.
	TLS *gatewayv1.ListenerTLSConfig
	// AllowedRoutes defines constraints on routes permitted to attach to this listener.
	AllowedRoutes *gatewayv1.AllowedRoutes
	// SupportedKinds lists the route GroupKinds permitted by this listener's protocol and spec.
	SupportedKinds []gatewayv1.RouteGroupKind

	// Conditions tracks validation and programmed conditions reported in listener status.
	Conditions []metav1.Condition
	// AttachedRoutes is the count of routes bound to this listener, updated during compilation.
	AttachedRoutes int32

	// Routes holds compiled HTTP and gRPC routes attached to this listener.
	Routes []InternalRoute
	// TLSBackends maps SNI hostnames to backend destinations attached by TLSRoutes.
	TLSBackends map[string][]InternalTLSBackend
	// TLSHostnameOwners maps each hostname to the TLSRoute that won precedence on this listener.
	TLSHostnameOwners map[string]types.NamespacedName
	// BoundTCPRoute is the namespaced name of the single TCPRoute attached to this listener, if any.
	BoundTCPRoute *types.NamespacedName
	// TCPBackends holds backend destinations attached by the bound TCPRoute.
	TCPBackends []InternalTCPBackend
	// BoundUDPRoute is the namespaced name of the single UDPRoute attached to this listener, if any.
	BoundUDPRoute *types.NamespacedName
	// UDPBackends holds backend destinations attached by the bound UDPRoute.
	UDPBackends []InternalUDPBackend
	// ClientValidation specifies client certificate validation rules for mutual TLS, if configured.
	ClientValidation *InternalClientValidation

	// Generation is the observed generation of the defining resource at compile time.
	Generation int64

	// ResolvedCertificates holds TLS certificates resolved from Secret references or certificate sources.
	ResolvedCertificates []*tls.Certificate
	// ResolvedCertificate holds the primary resolved certificate for this listener.
	ResolvedCertificate *tls.Certificate
}

// IsAccepted returns true if the listener has an Accepted condition with status True.
func (el *EffectiveListener) IsAccepted() bool {
	for _, c := range el.Conditions {
		if c.Type == string(gatewayv1.ListenerConditionAccepted) && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

// IsProgrammed returns true if the listener has a Programmed condition with status True.
func (el *EffectiveListener) IsProgrammed() bool {
	for _, c := range el.Conditions {
		if c.Type == string(gatewayv1.ListenerConditionProgrammed) && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

// IsConflicted returns true if the listener has a Conflicted condition with status True.
func (el *EffectiveListener) IsConflicted() bool {
	for _, c := range el.Conditions {
		if c.Type == string(gatewayv1.ListenerConditionConflicted) && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

// QualifiedName returns the listener name, qualified with owner namespace and name for ListenerSets.
func (el *EffectiveListener) QualifiedName() string {
	if el.Owner.Kind == "Gateway" {
		return string(el.Name)
	}
	return fmt.Sprintf("%s/%s/%s", el.Owner.Namespace, el.Owner.Name, el.Name)
}

// ToInternalListener converts the effective listener to an InternalListener for proxy routing.
func (el *EffectiveListener) ToInternalListener() InternalListener {
	var tlsMode *gatewayv1.TLSModeType
	if el.TLS != nil {
		if el.TLS.Mode != nil {
			tlsMode = el.TLS.Mode
		} else if el.Protocol == gatewayv1.TLSProtocolType {
			m := gatewayv1.TLSModeTerminate
			tlsMode = &m
		}
	}
	var tlsBackends map[string][]InternalTLSBackend
	for k, v := range el.TLSBackends {
		if len(v) > 0 {
			if tlsBackends == nil {
				tlsBackends = make(map[string][]InternalTLSBackend)
			}
			copied := make([]InternalTLSBackend, len(v))
			copy(copied, v)
			tlsBackends[k] = copied
		}
	}
	var tcpBackends []InternalTCPBackend
	if len(el.TCPBackends) > 0 {
		tcpBackends = make([]InternalTCPBackend, len(el.TCPBackends))
		copy(tcpBackends, el.TCPBackends)
	}
	var udpBackends []InternalUDPBackend
	if len(el.UDPBackends) > 0 {
		udpBackends = make([]InternalUDPBackend, len(el.UDPBackends))
		copy(udpBackends, el.UDPBackends)
	}
	var clientValidation *InternalClientValidation
	if el.ClientValidation != nil {
		clientValidation = el.ClientValidation.DeepCopy()
	}
	return InternalListener{
		Name:             el.QualifiedName(),
		Protocol:         el.Protocol,
		Port:             el.Port,
		Hostname:         string(ValueOf(el.Hostname)),
		GatewayName:      el.ParentGateway,
		Routes:           el.Routes,
		TLSMode:          tlsMode,
		TLSBackends:      tlsBackends,
		TCPBackends:      tcpBackends,
		UDPBackends:      udpBackends,
		ClientValidation: clientValidation,
	}
}

// HostnamesOverlap returns true if two listener hostnames overlap (e.g. *.example.com and foo.example.com).
// Duplicate exact hostnames return false because they represent conflicts handled by Conflicted status.
func HostnamesOverlap(h1, h2 string) bool {
	h1 = strings.ToLower(h1)
	h2 = strings.ToLower(h2)

	if h1 == h2 {
		return false
	}

	_, ok := Intersect(h1, h2)
	return ok
}

func getEffectiveListenerCertRefs(el *EffectiveListener) []gatewayv1.SecretObjectReference {
	if el == nil || el.TLS == nil {
		return nil
	}
	return el.TLS.CertificateRefs
}

func listenerCertificatesDiffer(el1, el2 *EffectiveListener, secrets map[types.NamespacedName]*corev1.Secret) bool {
	refs1 := getEffectiveListenerCertRefs(el1)
	refs2 := getEffectiveListenerCertRefs(el2)

	if len(refs1) == 0 && len(refs2) == 0 {
		return false
	}
	if len(refs1) != len(refs2) {
		return true
	}

	allSecretsAvailable := true
	var certs1, certs2 [][]byte
	for _, ref := range refs1 {
		secNs := el1.Owner.Namespace
		if ref.Namespace != nil && string(*ref.Namespace) != "" {
			secNs = string(*ref.Namespace)
		}
		secKey := types.NamespacedName{Namespace: secNs, Name: string(ref.Name)}
		sec := secrets[secKey]
		if sec == nil || len(sec.Data[corev1.TLSCertKey]) == 0 {
			allSecretsAvailable = false
			break
		}
		certs1 = append(certs1, sec.Data[corev1.TLSCertKey])
	}
	for _, ref := range refs2 {
		secNs := el2.Owner.Namespace
		if ref.Namespace != nil && string(*ref.Namespace) != "" {
			secNs = string(*ref.Namespace)
		}
		secKey := types.NamespacedName{Namespace: secNs, Name: string(ref.Name)}
		sec := secrets[secKey]
		if sec == nil || len(sec.Data[corev1.TLSCertKey]) == 0 {
			allSecretsAvailable = false
			break
		}
		certs2 = append(certs2, sec.Data[corev1.TLSCertKey])
	}

	if allSecretsAvailable && len(certs1) == len(refs1) && len(certs2) == len(refs2) {
		for i := range certs1 {
			if !bytes.Equal(certs1[i], certs2[i]) {
				return true
			}
		}
		return false
	}

	// Fallback to comparing normalized secret reference namespace and name
	for i := range refs1 {
		ns1 := el1.Owner.Namespace
		if refs1[i].Namespace != nil && string(*refs1[i].Namespace) != "" {
			ns1 = string(*refs1[i].Namespace)
		}
		ns2 := el2.Owner.Namespace
		if refs2[i].Namespace != nil && string(*refs2[i].Namespace) != "" {
			ns2 = string(*refs2[i].Namespace)
		}
		if ns1 != ns2 || string(refs1[i].Name) != string(refs2[i].Name) {
			return true
		}
	}
	return false
}

func computeOverlappingTLSConfig(gateways []*CompiledGateway, allInOneMode bool, secrets map[types.NamespacedName]*corev1.Secret) {
	if allInOneMode {
		var allListeners []*EffectiveListener
		for _, cg := range gateways {
			if cg == nil {
				continue
			}
			for _, el := range cg.EffectiveListeners {
				if (el.Protocol == gatewayv1.HTTPSProtocolType || el.Protocol == gatewayv1.TLSProtocolType) && !el.IsConflicted() {
					allListeners = append(allListeners, el)
				}
			}
		}
		computeOverlappingTLSConfigForListeners(allListeners, secrets)
	} else {
		for _, cg := range gateways {
			if cg == nil {
				continue
			}
			var gwListeners []*EffectiveListener
			for _, el := range cg.EffectiveListeners {
				if (el.Protocol == gatewayv1.HTTPSProtocolType || el.Protocol == gatewayv1.TLSProtocolType) && !el.IsConflicted() {
					gwListeners = append(gwListeners, el)
				}
			}
			computeOverlappingTLSConfigForListeners(gwListeners, secrets)
		}
	}
}

func computeOverlappingTLSConfigForListeners(listeners []*EffectiveListener, secrets map[types.NamespacedName]*corev1.Secret) {
	byPort := make(map[gatewayv1.PortNumber][]*EffectiveListener)
	for _, el := range listeners {
		byPort[el.Port] = append(byPort[el.Port], el)
	}

	for port, portListeners := range byPort {
		n := len(portListeners)
		if n < 2 {
			continue
		}
		overlapping := make([]bool, n)
		certsDiffer := make([]bool, n)

		for i := 0; i < n; i++ {
			h1 := string(ValueOf(portListeners[i].Hostname))
			for j := i + 1; j < n; j++ {
				h2 := string(ValueOf(portListeners[j].Hostname))
				if HostnamesOverlap(h1, h2) {
					overlapping[i] = true
					overlapping[j] = true
					if listenerCertificatesDiffer(portListeners[i], portListeners[j], secrets) {
						certsDiffer[i] = true
						certsDiffer[j] = true
					}
				}
			}
		}

		for i := 0; i < n; i++ {
			if overlapping[i] {
				reason := gatewayv1.ListenerReasonOverlappingHostnames
				msg := fmt.Sprintf("Overlapping TLS configuration: listener shares port %d and overlapping hostname with another listener", port)
				if certsDiffer[i] {
					reason = gatewayv1.ListenerReasonOverlappingCertificates
					msg = fmt.Sprintf("Overlapping TLS configuration: listener shares port %d and overlapping hostname with another listener using differing certificates", port)
				}
				SetCondition(&portListeners[i].Conditions, NewCondition(
					string(gatewayv1.ListenerConditionOverlappingTLSConfig),
					metav1.ConditionTrue,
					string(reason),
					msg,
					portListeners[i].Generation,
				))
			}
		}
	}
}

// CompiledGateway contains the compiled state for a single Gateway.
type CompiledGateway struct {
	Gateway               *gatewayv1.Gateway
	EffectiveListeners    []*EffectiveListener
	AttachedListenerSets  int32
	Conditions            []metav1.Condition
	BackendClientCert     *tls.Certificate
	ResolvedRefsCondition metav1.Condition
	Parameters            *Parameters
	ParametersRefError    error
}

// CompiledRoute contains the compiled state for an HTTPRoute.
type CompiledRoute struct {
	HTTPRoute        *gatewayv1.HTTPRoute
	RouteState       *HTTPRouteState
	ParentConditions []metav1.Condition
}

// CompiledTLSRoute contains the compiled state for a TLSRoute.
type CompiledTLSRoute struct {
	TLSRoute         *gatewayv1.TLSRoute
	RouteState       *TLSRouteState
	ParentConditions []metav1.Condition
	BoundListeners   []*EffectiveListener
}

// CompiledGRPCRoute contains the compiled state for a GRPCRoute.
type CompiledGRPCRoute struct {
	GRPCRoute        *gatewayv1.GRPCRoute
	RouteState       *GRPCRouteState
	ParentConditions []metav1.Condition
}

// CompiledTCPRoute contains the compiled state for a TCPRoute.
type CompiledTCPRoute struct {
	TCPRoute         *gatewayv1.TCPRoute
	RouteState       *TCPRouteState
	ParentConditions []metav1.Condition
}

// CompiledUDPRoute contains the compiled state for a UDPRoute.
type CompiledUDPRoute struct {
	UDPRoute         *gatewayv1.UDPRoute
	RouteState       *UDPRouteState
	ParentConditions []metav1.Condition
}

// CompiledModel is the complete compiled model of Gateways, ListenerSets, HTTPRoutes, TLSRoutes, GRPCRoutes, TCPRoutes, and UDPRoutes.
type CompiledModel struct {
	Gateways     map[types.NamespacedName]*CompiledGateway
	HTTPRoutes   map[types.NamespacedName]*CompiledRoute
	TLSRoutes    map[types.NamespacedName]*CompiledTLSRoute
	GRPCRoutes   map[types.NamespacedName]*CompiledGRPCRoute
	TCPRoutes    map[types.NamespacedName]*CompiledTCPRoute
	UDPRoutes    map[types.NamespacedName]*CompiledUDPRoute
	ListenerSets map[types.NamespacedName]*gatewayv1.ListenerSet
}

// GatewaysList returns all compiled gateways as a slice.
func (cm *CompiledModel) GatewaysList() []*CompiledGateway {
	if cm == nil {
		return nil
	}
	res := make([]*CompiledGateway, 0, len(cm.Gateways))
	for _, cg := range cm.Gateways {
		res = append(res, cg)
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].Gateway.Namespace != res[j].Gateway.Namespace {
			return res[i].Gateway.Namespace < res[j].Gateway.Namespace
		}
		return res[i].Gateway.Name < res[j].Gateway.Name
	})
	return res
}

// ResolvedGateways returns deep copies of all Gateways in the model.
func (cm *CompiledModel) ResolvedGateways() []*gatewayv1.Gateway {
	if cm == nil {
		return nil
	}
	var res []*gatewayv1.Gateway
	for _, cg := range cm.GatewaysList() {
		if cg.Gateway != nil {
			res = append(res, cg.Gateway.DeepCopy())
		}
	}
	return res
}

// GatewayReadiness represents the data-plane readiness state of a Gateway.
type GatewayReadiness struct {
	Ready   bool
	Reason  string
	Message string
}

// ModelInputs contains all inputs required to build a CompiledModel and ComputeOutputs.
type ModelInputs struct {
	// Revision is the monotonically increasing snapshot revision number for state computation.
	Revision uint64

	// Gateways is the list of Gateway resources to compile.
	Gateways []*gatewayv1.Gateway
	// GatewayClasses is the list of GatewayClass resources known to the controller.
	GatewayClasses []*gatewayv1.GatewayClass
	// GatewayAddresses provides infrastructure-assigned status addresses keyed by Gateway.
	GatewayAddresses map[types.NamespacedName][]gatewayv1.GatewayStatusAddress
	// GatewayReadiness provides data-plane readiness state keyed by Gateway.
	GatewayReadiness map[types.NamespacedName]GatewayReadiness
	// ProvisioningErrors maps Gateway names to error messages from infrastructure provisioning.
	ProvisioningErrors map[types.NamespacedName]string
	// SupportedAddressTypes lists address types supported by the controller implementation.
	SupportedAddressTypes []gatewayv1.AddressType

	// ListenerSets is the list of ListenerSet resources that attach listeners to Gateways.
	ListenerSets []*gatewayv1.ListenerSet
	// HTTPRoutes is the list of HTTPRoute resources to bind to listeners.
	HTTPRoutes []*gatewayv1.HTTPRoute
	// TLSRoutes is the list of TLSRoute resources to bind to listeners.
	TLSRoutes []*gatewayv1.TLSRoute
	// GRPCRoutes is the list of GRPCRoute resources to bind to listeners.
	GRPCRoutes []*gatewayv1.GRPCRoute
	// TCPRoutes is the list of TCPRoute resources to bind to listeners.
	TCPRoutes []*gatewayv1.TCPRoute
	// UDPRoutes is the list of UDPRoute resources to bind to listeners.
	UDPRoutes []*gatewayv1.UDPRoute

	// Services provides backend Kubernetes Services keyed by namespaced name.
	Services map[types.NamespacedName]*corev1.Service
	// BackendTLSPolicies configures TLS settings for connections to backend services.
	BackendTLSPolicies []*gatewayv1.BackendTLSPolicy
	// ConfigMaps provides ConfigMap resources, such as CA bundles or parameters, by namespaced name.
	ConfigMaps map[types.NamespacedName]*corev1.ConfigMap
	// Secrets provides Secret resources, such as TLS certificates or client CAs, by namespaced name.
	Secrets map[types.NamespacedName]*corev1.Secret
	// Namespaces provides Namespace resources keyed by name for cross-namespace checks.
	Namespaces map[string]*corev1.Namespace
	// ReferenceGrants provides ReferenceGrant resources authorizing cross-namespace references.
	ReferenceGrants map[types.NamespacedName]*gatewayv1beta1.ReferenceGrant

	// RefValidator checks whether cross-namespace references are permitted by ReferenceGrants.
	RefValidator ReferenceGrantValidator
	// ControllerName is the controller name used to match GatewayClasses and condition reporters.
	ControllerName string
	// AllInOneMode indicates whether Gateways share a single data-plane proxy instance.
	AllInOneMode bool
	// GatewayCRDBundleVersion is the detected Gateway API CRD release bundle version string.
	GatewayCRDBundleVersion *string
	// DisabledRouteKinds specifies route kinds that are administratively disabled.
	DisabledRouteKinds map[gatewayv1.Kind]bool

	// CertificateSources maps source names to pluggable external TLS certificate providers.
	CertificateSources map[string]CertificateSource

	// ListenerValidator is an optional callback to validate listener specifications against custom policies.
	ListenerValidator ListenerValidator
}

// ListenerValidator is an optional function to validate listener specifications.
// If it returns conditions, they are applied to the listener and can reject it (e.g. Accepted=False).
type ListenerValidator func(spec ListenerSpec, owner ListenerOwner, gw *gatewayv1.Gateway) []metav1.Condition

// Outputs represents all computed outputs produced by ComputeOutputs.
type Outputs struct {
	// Revision is the snapshot revision number corresponding to the inputs used for computation.
	Revision uint64

	// GatewayStatuses holds the computed status to apply to each Gateway.
	GatewayStatuses map[types.NamespacedName]gatewayv1.GatewayStatus
	// GatewayParameters holds resolved configuration parameters for each Gateway.
	GatewayParameters map[types.NamespacedName]*Parameters
	// GatewayParametersErrors holds parameter resolution errors keyed by Gateway.
	GatewayParametersErrors map[types.NamespacedName]error
	// HTTPRouteStatuses holds the computed status to apply to each HTTPRoute.
	HTTPRouteStatuses map[types.NamespacedName]gatewayv1.HTTPRouteStatus
	// TLSRouteStatuses holds the computed status to apply to each TLSRoute.
	TLSRouteStatuses map[types.NamespacedName]gatewayv1.TLSRouteStatus
	// GRPCRouteStatuses holds the computed status to apply to each GRPCRoute.
	GRPCRouteStatuses map[types.NamespacedName]gatewayv1.GRPCRouteStatus
	// TCPRouteStatuses holds the computed status to apply to each TCPRoute.
	TCPRouteStatuses map[types.NamespacedName]gatewayv1.TCPRouteStatus
	// UDPRouteStatuses holds the computed status to apply to each UDPRoute.
	UDPRouteStatuses map[types.NamespacedName]gatewayv1.UDPRouteStatus
	// ListenerSetStatuses holds the computed status to apply to each ListenerSet.
	ListenerSetStatuses map[types.NamespacedName]gatewayv1.ListenerSetStatus
	// BackendTLSPolicyStatuses holds the computed status to apply to each BackendTLSPolicy.
	BackendTLSPolicyStatuses map[types.NamespacedName]gatewayv1.PolicyStatus
	// GatewayClassStatuses holds the computed status to apply to each GatewayClass.
	GatewayClassStatuses map[types.NamespacedName]gatewayv1.GatewayClassStatus

	// ProxyListeners holds internal listeners configured for the data-plane proxy engine.
	ProxyListeners []InternalListener
	// ProxyRoutes holds internal HTTP routes configured for the data-plane proxy engine.
	ProxyRoutes []InternalRoute
	// CertificatesMap indexes TLS certificates by hostname for SNI matching in the proxy.
	CertificatesMap map[string]*tls.Certificate
	// DefaultCert is the fallback TLS certificate used when no hostname matches.
	DefaultCert *tls.Certificate

	// ResolvedGateways holds deep copies of Gateways reflecting status updates.
	ResolvedGateways []*gatewayv1.Gateway
	// CompiledGateways maps Gateway names to their intermediate compiled representations.
	CompiledGateways map[types.NamespacedName]*CompiledGateway
	// DataplaneConfigs maps Gateway names to their serialized data-plane configurations.
	DataplaneConfigs map[types.NamespacedName]*DataplaneConfig
}

func isSupportedProtocol(protocol gatewayv1.ProtocolType) bool {
	switch protocol {
	case gatewayv1.HTTPProtocolType,
		gatewayv1.HTTPSProtocolType,
		gatewayv1.TLSProtocolType,
		gatewayv1.TCPProtocolType,
		gatewayv1.UDPProtocolType:
		return true
	default:
		return false
	}
}

func isValidRouteKindForProtocol(protocol gatewayv1.ProtocolType, group *gatewayv1.Group, kind gatewayv1.Kind) bool {
	grp := ValueOf(group)
	if grp != "" && grp != gatewayv1.GroupName {
		return false
	}
	switch protocol {
	case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
		return kind == "HTTPRoute" || kind == "GRPCRoute"
	case gatewayv1.TLSProtocolType:
		return kind == "TLSRoute"
	case gatewayv1.TCPProtocolType:
		return kind == "TCPRoute"
	case gatewayv1.UDPProtocolType:
		return kind == "UDPRoute"
	default:
		return false
	}
}

func defaultSupportedKindsForProtocol(protocol gatewayv1.ProtocolType) []gatewayv1.RouteGroupKind {
	switch protocol {
	case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
		return []gatewayv1.RouteGroupKind{{
			Group: Ptr(gatewayv1.Group(gatewayv1.GroupName)),
			Kind:  gatewayv1.Kind("HTTPRoute"),
		}}
	case gatewayv1.TLSProtocolType:
		return []gatewayv1.RouteGroupKind{{
			Group: Ptr(gatewayv1.Group(gatewayv1.GroupName)),
			Kind:  gatewayv1.Kind("TLSRoute"),
		}}
	case gatewayv1.TCPProtocolType:
		return []gatewayv1.RouteGroupKind{{
			Group: Ptr(gatewayv1.Group(gatewayv1.GroupName)),
			Kind:  gatewayv1.Kind("TCPRoute"),
		}}
	case gatewayv1.UDPProtocolType:
		return []gatewayv1.RouteGroupKind{{
			Group: Ptr(gatewayv1.Group(gatewayv1.GroupName)),
			Kind:  gatewayv1.Kind("UDPRoute"),
		}}
	default:
		return []gatewayv1.RouteGroupKind{}
	}
}

// EffectiveFrontendValidation returns the effective frontend TLS validation configuration for a listener on a Gateway.
// Frontend client certificate validation applies to HTTPS listeners only.
// If a perPort configuration matches the listener port, it overrides the default configuration.
func EffectiveFrontendValidation(gwTLS *gatewayv1.GatewayTLSConfig, port gatewayv1.PortNumber, protocol gatewayv1.ProtocolType) *gatewayv1.FrontendTLSValidation {
	if protocol != gatewayv1.HTTPSProtocolType || gwTLS == nil || gwTLS.Frontend == nil {
		return nil
	}

	for _, pp := range gwTLS.Frontend.PerPort {
		if pp.Port == port {
			return pp.TLS.Validation
		}
	}

	return gwTLS.Frontend.Default.Validation
}

// ListenerValidationResult holds the computed validation outputs for a listener.
type ListenerValidationResult struct {
	// SupportedKinds is the set of route kinds this listener accepts.
	SupportedKinds []gatewayv1.RouteGroupKind
	// Conditions holds status conditions computed for this listener.
	Conditions []metav1.Condition
	// ClientValidation holds TLS client certificate validation settings, if configured.
	ClientValidation *InternalClientValidation
	// Certificates holds the resolved TLS certificates for this listener.
	Certificates []*tls.Certificate
}

// ValidateListener validates a listener specification, computing its supported kinds, conditions, and client validation.
func ValidateListener(
	listener ListenerSpec,
	owner ListenerOwner,
	gw *gatewayv1.Gateway,
	generation int64,
	secrets map[types.NamespacedName]*corev1.Secret,
	configMaps map[types.NamespacedName]*corev1.ConfigMap,
	frontendValidation *gatewayv1.FrontendTLSValidation,
	refValidator ReferenceGrantValidator,
	certSources map[string]CertificateSource,
	disabledRouteKinds ...map[gatewayv1.Kind]bool,
) ListenerValidationResult {
	var supportedKinds []gatewayv1.RouteGroupKind
	var conditions []metav1.Condition
	var clientValidation *InternalClientValidation
	var resolvedCerts []*tls.Certificate

	gwNamespace := ""
	if gw != nil {
		gwNamespace = gw.Namespace
	}
	if gwNamespace == "" {
		gwNamespace = owner.Namespace
	}

	var disabledKinds map[gatewayv1.Kind]bool
	if len(disabledRouteKinds) > 0 {
		disabledKinds = disabledRouteKinds[0]
	}
	isKindDisabled := func(kind gatewayv1.Kind) bool {
		return disabledKinds != nil && disabledKinds[kind]
	}

	isSupported := isSupportedProtocol(listener.Protocol)

	if !isSupported {
		supportedKinds = []gatewayv1.RouteGroupKind{}
		conditions = []metav1.Condition{
			NewCondition(
				string(gatewayv1.ListenerConditionProgrammed),
				metav1.ConditionFalse,
				string(gatewayv1.ListenerReasonInvalid),
				fmt.Sprintf("Protocol %q is not supported", listener.Protocol),
				generation,
			),
			NewCondition(
				string(gatewayv1.ListenerConditionAccepted),
				metav1.ConditionFalse,
				string(gatewayv1.ListenerReasonUnsupportedProtocol),
				fmt.Sprintf("Protocol %q is not supported", listener.Protocol),
				generation,
			),
		}
		return ListenerValidationResult{
			SupportedKinds: supportedKinds,
			Conditions:     conditions,
		}
	}

	hasInvalidRouteKind := false
	if listener.AllowedRoutes != nil && len(listener.AllowedRoutes.Kinds) > 0 {
		supportedKinds = []gatewayv1.RouteGroupKind{}
		hasValidEnabledKind := false
		hasValidDisabledKind := false
		for _, k := range listener.AllowedRoutes.Kinds {
			if isValidRouteKindForProtocol(listener.Protocol, k.Group, k.Kind) {
				if isKindDisabled(k.Kind) {
					hasValidDisabledKind = true
					continue
				}
				hasValidEnabledKind = true
				alreadyPresent := false
				for _, sk := range supportedKinds {
					if sk.Kind == k.Kind && ValueOf(sk.Group) == gatewayv1.GroupName {
						alreadyPresent = true
						break
					}
				}
				if !alreadyPresent {
					supportedKinds = append(supportedKinds, gatewayv1.RouteGroupKind{
						Group: Ptr(gatewayv1.Group(gatewayv1.GroupName)),
						Kind:  k.Kind,
					})
				}
			} else {
				hasInvalidRouteKind = true
			}
		}
		if hasValidDisabledKind && !hasValidEnabledKind && !hasInvalidRouteKind {
			hasInvalidRouteKind = true
		}
	} else {
		defaultKinds := defaultSupportedKindsForProtocol(listener.Protocol)
		supportedKinds = []gatewayv1.RouteGroupKind{}
		hasDefaultKind := len(defaultKinds) > 0
		hasDefaultEnabledKind := false
		for _, k := range defaultKinds {
			if isKindDisabled(k.Kind) {
				continue
			}
			hasDefaultEnabledKind = true
			supportedKinds = append(supportedKinds, k)
		}
		if hasDefaultKind && !hasDefaultEnabledKind {
			hasInvalidRouteKind = true
		}
	}

	var tlsInvalidReason string
	var tlsInvalidMessage string
	var tlsProgrammedMessage string
	var tlsPendingMessage string

	needsTLSSecretValidation := isSupported && (listener.Protocol == gatewayv1.HTTPSProtocolType || (listener.Protocol == gatewayv1.TLSProtocolType && listener.TLS != nil && (listener.TLS.Mode == nil || *listener.TLS.Mode == gatewayv1.TLSModeTerminate))) && listener.TLS != nil
	hasSourceOption := false
	var sourceName string
	if needsTLSSecretValidation && listener.TLS.Options != nil {
		if optVal, ok := listener.TLS.Options[gatewayv1.AnnotationKey(CertificateSourceOptionKey)]; ok && string(optVal) != "" {
			hasSourceOption = true
			sourceName = string(optVal)
		}
	}

	if needsTLSSecretValidation {
		gListener := &gatewayv1.Listener{
			Name:          listener.Name,
			Port:          listener.Port,
			Protocol:      listener.Protocol,
			Hostname:      listener.Hostname,
			TLS:           listener.TLS,
			AllowedRoutes: listener.AllowedRoutes,
		}

		var source CertificateSource
		var selectedSourceName string
		var isSecretSource bool

		if len(listener.TLS.CertificateRefs) > 0 {
			// A listener with certificateRefs resolves via SecretsCertificateSource.
			source = &SecretsCertificateSource{
				Secrets:      secrets,
				RefValidator: refValidator,
				Owner:        owner,
			}
			isSecretSource = true
			selectedSourceName = "secrets"
		} else if hasSourceOption {
			if listener.Hostname == nil || *listener.Hostname == "" || strings.Contains(string(*listener.Hostname), "*") {
				tlsInvalidReason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
				tlsInvalidMessage = "Certificate source requires an exact, non-wildcard hostname"
				tlsProgrammedMessage = "Certificate source requires an exact, non-wildcard hostname"
			} else {
				source = certSources[sourceName]
				if source == nil {
					tlsInvalidReason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
					tlsInvalidMessage = fmt.Sprintf("Unknown certificate source %q", sourceName)
					tlsProgrammedMessage = fmt.Sprintf("Unknown certificate source %q", sourceName)
				} else {
					selectedSourceName = sourceName
				}
			}
		} else {
			tlsInvalidReason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
			tlsInvalidMessage = "No certificate refs specified"
			tlsProgrammedMessage = "Invalid TLS configuration: no certificate refs specified"
		}

		if source != nil && tlsInvalidReason == "" {
			res, err := source.ResolveCertificates(gw, gListener)
			if err != nil {
				logSourceError(selectedSourceName, gw, listener.Name, err)
				tlsInvalidReason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
				msg := fmt.Sprintf("Certificate source %q returned an error", selectedSourceName)
				if isSecretSource {
					msg = err.Error()
				}
				tlsInvalidMessage = msg
				tlsProgrammedMessage = msg
			} else if res.Pending {
				tlsPendingMessage = "Certificate pending from source"
			} else if res.FailedReason != "" {
				tlsInvalidReason = string(res.FailedReason)
				tlsInvalidMessage = res.FailedMessage
				tlsProgrammedMessage = res.ProgrammedMessage
			} else if len(res.Certificates) == 0 {
				tlsInvalidReason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
				tlsInvalidMessage = "No certificate resolved"
				tlsProgrammedMessage = "No certificate resolved"
			} else {
				var validCerts []*tls.Certificate
				var valErr error
				for _, c := range res.Certificates {
					cp := CopyTLSCertificate(c)
					if err := ValidateCertificate(cp); err != nil {
						valErr = err
						break
					}
					validCerts = append(validCerts, cp)
				}
				if valErr != nil {
					tlsInvalidReason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
					msg := fmt.Sprintf("Certificate source %q returned an invalid certificate", selectedSourceName)
					if isSecretSource {
						msg = valErr.Error()
					}
					tlsInvalidMessage = msg
					tlsProgrammedMessage = msg
				} else {
					resolvedCerts = validCerts
				}
			}
		}
	}

	var caInvalidReason string
	var caInvalidMessage string
	var caPEMs [][]byte

	if listener.Protocol == gatewayv1.HTTPSProtocolType && frontendValidation != nil {
		if len(frontendValidation.CACertificateRefs) == 0 {
			caInvalidReason = string(gatewayv1.ListenerReasonInvalidCACertificateRef)
			caInvalidMessage = "No CA certificate refs specified"
		} else {
			for _, caRef := range frontendValidation.CACertificateRefs {
				group := string(caRef.Group)
				kind := string(caRef.Kind)
				if group != "" || kind != "ConfigMap" {
					caInvalidReason = string(gatewayv1.ListenerReasonInvalidCACertificateKind)
					caInvalidMessage = fmt.Sprintf("Unsupported CA certificate ref group %q kind %q", group, kind)
					break
				}

				targetNs := gwNamespace
				if caRef.Namespace != nil && string(*caRef.Namespace) != "" {
					targetNs = string(*caRef.Namespace)
				}

				if targetNs != gwNamespace {
					from := Reference{
						GroupKind: schema.GroupKind{Group: gatewayv1.GroupName, Kind: "Gateway"},
						Namespace: gwNamespace,
					}
					to := Reference{
						GroupKind: schema.GroupKind{Group: "", Kind: "ConfigMap"},
						Namespace: targetNs,
						Name:      string(caRef.Name),
					}
					if refValidator == nil || !refValidator.IsReferencePermitted(from, to) {
						caInvalidReason = string(gatewayv1.ListenerReasonRefNotPermitted)
						caInvalidMessage = fmt.Sprintf("Cross-namespace reference to ConfigMap %s/%s is not permitted by any ReferenceGrant", targetNs, caRef.Name)
						break
					}
				}

				cmKey := types.NamespacedName{
					Namespace: targetNs,
					Name:      string(caRef.Name),
				}
				var cm *corev1.ConfigMap
				if configMaps != nil {
					cm = configMaps[cmKey]
				}
				if cm == nil {
					caInvalidReason = string(gatewayv1.ListenerReasonInvalidCACertificateRef)
					caInvalidMessage = fmt.Sprintf("ConfigMap %s/%s not found", targetNs, caRef.Name)
					break
				}

				data, err := ExtractCACertFromConfigMap(cm)
				if err != nil {
					caInvalidReason = string(gatewayv1.ListenerReasonInvalidCACertificateRef)
					caInvalidMessage = fmt.Sprintf("ConfigMap %s/%s is invalid: %v", targetNs, caRef.Name, err)
					break
				}
				caPEMs = append(caPEMs, data)
			}
		}
	}

	listenerProgrammedStatus := metav1.ConditionTrue
	listenerProgrammedReason := gatewayv1.ListenerReasonProgrammed
	listenerProgrammedMessage := "Listener programmed"

	listenerAcceptedStatus := metav1.ConditionTrue
	listenerAcceptedReason := gatewayv1.ListenerReasonAccepted
	listenerAcceptedMessage := "Listener accepted"

	resolvedRefsStatus := metav1.ConditionTrue
	resolvedRefsReason := gatewayv1.ListenerReasonResolvedRefs
	resolvedRefsMessage := "All references resolved"
	if listener.TLS != nil && len(listener.TLS.CertificateRefs) > 0 && hasSourceOption {
		resolvedRefsMessage = fmt.Sprintf("All references resolved; %s option was ignored", CertificateSourceOptionKey)
	}

	if hasInvalidRouteKind {
		resolvedRefsStatus = metav1.ConditionFalse
		resolvedRefsReason = gatewayv1.ListenerReasonInvalidRouteKinds
		resolvedRefsMessage = "One or more route kinds are not supported"

		listenerProgrammedStatus = metav1.ConditionFalse
		listenerProgrammedReason = gatewayv1.ListenerReasonInvalid
		listenerProgrammedMessage = "One or more route kinds are not supported"
	} else if tlsPendingMessage != "" {
		resolvedRefsStatus = metav1.ConditionFalse
		resolvedRefsReason = gatewayv1.ListenerReasonPending
		resolvedRefsMessage = tlsPendingMessage

		listenerProgrammedStatus = metav1.ConditionFalse
		listenerProgrammedReason = gatewayv1.ListenerReasonPending
		listenerProgrammedMessage = tlsPendingMessage
	} else if tlsInvalidReason != "" {
		resolvedRefsStatus = metav1.ConditionFalse
		resolvedRefsReason = gatewayv1.ListenerConditionReason(tlsInvalidReason)
		resolvedRefsMessage = tlsInvalidMessage

		listenerProgrammedStatus = metav1.ConditionFalse
		listenerProgrammedReason = gatewayv1.ListenerReasonInvalid
		listenerProgrammedMessage = tlsProgrammedMessage
	} else if caInvalidReason != "" {
		resolvedRefsStatus = metav1.ConditionFalse
		resolvedRefsReason = gatewayv1.ListenerConditionReason(caInvalidReason)
		resolvedRefsMessage = caInvalidMessage

		listenerAcceptedStatus = metav1.ConditionFalse
		listenerAcceptedReason = gatewayv1.ListenerReasonNoValidCACertificate
		listenerAcceptedMessage = "No valid CA certificate for client certificate validation"

		listenerProgrammedStatus = metav1.ConditionFalse
		listenerProgrammedReason = gatewayv1.ListenerReasonNoValidCACertificate
		listenerProgrammedMessage = "No valid CA certificate for client certificate validation"
	} else if len(caPEMs) > 0 {
		mode := frontendValidation.Mode
		if mode == "" {
			mode = gatewayv1.AllowValidOnly
		}
		clientValidation = &InternalClientValidation{
			CACertPEMs: caPEMs,
			Mode:       mode,
		}
	}

	conditions = []metav1.Condition{
		NewCondition(
			string(gatewayv1.ListenerConditionProgrammed),
			listenerProgrammedStatus,
			string(listenerProgrammedReason),
			listenerProgrammedMessage,
			generation,
		),
		NewCondition(
			string(gatewayv1.ListenerConditionAccepted),
			listenerAcceptedStatus,
			string(listenerAcceptedReason),
			listenerAcceptedMessage,
			generation,
		),
		NewCondition(
			string(gatewayv1.ListenerConditionResolvedRefs),
			resolvedRefsStatus,
			string(resolvedRefsReason),
			resolvedRefsMessage,
			generation,
		),
	}

	return ListenerValidationResult{
		SupportedKinds:   supportedKinds,
		Conditions:       conditions,
		ClientValidation: clientValidation,
		Certificates:     resolvedCerts,
	}
}

// BuildEffectiveListener constructs an EffectiveListener from a listener specification.
func BuildEffectiveListener(
	listener ListenerSpec,
	owner ListenerOwner,
	gw *gatewayv1.Gateway,
	generation int64,
	secrets map[types.NamespacedName]*corev1.Secret,
	configMaps map[types.NamespacedName]*corev1.ConfigMap,
	frontendValidation *gatewayv1.FrontendTLSValidation,
	refValidator ReferenceGrantValidator,
	certSources map[string]CertificateSource,
	disabledRouteKinds ...map[gatewayv1.Kind]bool,
) *EffectiveListener {
	validationResult := ValidateListener(
		listener,
		owner,
		gw,
		generation,
		secrets,
		configMaps,
		frontendValidation,
		refValidator,
		certSources,
		disabledRouteKinds...,
	)
	var parentGateway types.NamespacedName
	if gw != nil {
		parentGateway = types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
	} else {
		parentGateway = types.NamespacedName{Namespace: owner.Namespace, Name: owner.Name}
	}
	return &EffectiveListener{
		Owner:                owner,
		ParentGateway:        parentGateway,
		Name:                 listener.Name,
		Port:                 listener.Port,
		Protocol:             listener.Protocol,
		Hostname:             listener.Hostname,
		TLS:                  listener.TLS,
		AllowedRoutes:        listener.AllowedRoutes,
		SupportedKinds:       validationResult.SupportedKinds,
		Conditions:           validationResult.Conditions,
		AttachedRoutes:       0,
		Routes:               nil,
		ClientValidation:     validationResult.ClientValidation,
		ResolvedCertificates: validationResult.Certificates,
		Generation:           generation,
	}
}

// IsAddressTypeSupported returns true if the specified address type is in the supported list.
func IsAddressTypeSupported(addrType gatewayv1.AddressType, supported []gatewayv1.AddressType) bool {
	return slices.Contains(supported, addrType)
}

// HasUnsupportedAddress returns true and the first unsupported address type if any address
// in the provided slice is not supported by the provider.
// If addr.Type is nil or empty, it defaults to gatewayv1.IPAddressType.
func HasUnsupportedAddress(addresses []gatewayv1.GatewaySpecAddress, supported []gatewayv1.AddressType) (bool, gatewayv1.AddressType) {
	for _, addr := range addresses {
		addrType := gatewayv1.IPAddressType
		if addr.Type != nil && *addr.Type != "" {
			addrType = *addr.Type
		}
		if !IsAddressTypeSupported(addrType, supported) {
			return true, addrType
		}
	}
	return false, ""
}

// computeDesiredAddresses computes the addresses to report in status.addresses.
// If specific addresses (with values) are requested in spec.addresses, only bound requested
// addresses matching the requested type are reported.
// If {type: IPAddress} with no value is requested, or if no addresses are requested, all provided
// addresses matching the requested type(s) (or all provided addresses if none requested) are reported.
func computeDesiredAddresses(specAddresses []gatewayv1.GatewaySpecAddress, providedAddresses []gatewayv1.GatewayStatusAddress) []gatewayv1.GatewayStatusAddress {
	if len(specAddresses) == 0 {
		return providedAddresses
	}

	var requestedWithValues []gatewayv1.GatewaySpecAddress
	hasEmptyValue := false
	for _, sa := range specAddresses {
		if sa.Value != "" {
			requestedWithValues = append(requestedWithValues, sa)
		} else {
			hasEmptyValue = true
		}
	}

	if len(requestedWithValues) == 0 {
		return providedAddresses
	}

	var result []gatewayv1.GatewayStatusAddress
	for _, req := range requestedWithValues {
		reqType := gatewayv1.IPAddressType
		if req.Type != nil && *req.Type != "" {
			reqType = *req.Type
		}
		for _, prov := range providedAddresses {
			provType := gatewayv1.IPAddressType
			if prov.Type != nil && *prov.Type != "" {
				provType = *prov.Type
			}
			if prov.Value == req.Value && provType == reqType {
				t := req.Type
				if t == nil {
					t = Ptr(gatewayv1.IPAddressType)
				}
				result = append(result, gatewayv1.GatewayStatusAddress{
					Type:  t,
					Value: req.Value,
				})
				break
			}
		}
	}

	if hasEmptyValue {
		for _, prov := range providedAddresses {
			alreadyPresent := false
			for _, r := range result {
				if r.Value == prov.Value {
					alreadyPresent = true
					break
				}
			}
			if !alreadyPresent {
				result = append(result, prov)
			}
		}
	}

	return result
}

// resolveGatewayBackendClientCert validates and extracts the client certificate
// referenced by a Gateway's backend TLS configuration, returning the parsed certificate
// (if valid) and the ResolvedRefs condition for the Gateway.
func resolveGatewayBackendClientCert(
	gw *gatewayv1.Gateway,
	secrets map[types.NamespacedName]*corev1.Secret,
	refValidator ReferenceGrantValidator,
) (*tls.Certificate, metav1.Condition) {
	if gw == nil || gw.Spec.TLS == nil || gw.Spec.TLS.Backend == nil || gw.Spec.TLS.Backend.ClientCertificateRef == nil {
		gen := int64(0)
		if gw != nil {
			gen = gw.Generation
		}
		return nil, NewCondition(
			string(gatewayv1.GatewayConditionResolvedRefs),
			metav1.ConditionTrue,
			string(gatewayv1.GatewayReasonResolvedRefs),
			"Resolved references",
			gen,
		)
	}

	ref := gw.Spec.TLS.Backend.ClientCertificateRef
	group := ValueOf(ref.Group)
	kind := ValueOf(ref.Kind)
	if kind == "" {
		kind = "Secret"
	}

	if group != "" || kind != "Secret" {
		return nil, NewCondition(
			string(gatewayv1.GatewayConditionResolvedRefs),
			metav1.ConditionFalse,
			string(gatewayv1.GatewayReasonInvalidClientCertificateRef),
			fmt.Sprintf("Unsupported client certificate ref group %q kind %q", group, kind),
			gw.Generation,
		)
	}

	secretNs := gw.Namespace
	if ref.Namespace != nil && string(*ref.Namespace) != "" {
		secretNs = string(*ref.Namespace)
	}
	secretKey := types.NamespacedName{
		Namespace: secretNs,
		Name:      string(ref.Name),
	}

	if secretKey.Namespace != gw.Namespace {
		from := Reference{
			GroupKind: schema.GroupKind{Group: gatewayv1.GroupName, Kind: "Gateway"},
			Namespace: gw.Namespace,
		}
		to := Reference{
			GroupKind: schema.GroupKind{Group: string(group), Kind: string(kind)},
			Namespace: secretKey.Namespace,
			Name:      secretKey.Name,
		}
		if refValidator == nil || !refValidator.IsReferencePermitted(from, to) {
			return nil, NewCondition(
				string(gatewayv1.GatewayConditionResolvedRefs),
				metav1.ConditionFalse,
				string(gatewayv1.GatewayReasonRefNotPermitted),
				fmt.Sprintf("Cross-namespace reference to %s/%s is not permitted by any ReferenceGrant", secretKey.Namespace, secretKey.Name),
				gw.Generation,
			)
		}
	}

	var secret *corev1.Secret
	if secrets != nil {
		secret = secrets[secretKey]
	}
	if secret == nil {
		return nil, NewCondition(
			string(gatewayv1.GatewayConditionResolvedRefs),
			metav1.ConditionFalse,
			string(gatewayv1.GatewayReasonInvalidClientCertificateRef),
			fmt.Sprintf("Secret %s/%s not found", secretKey.Namespace, secretKey.Name),
			gw.Generation,
		)
	}

	certBytes := secret.Data[corev1.TLSCertKey]
	keyBytes := secret.Data[corev1.TLSPrivateKeyKey]
	if len(certBytes) == 0 || len(keyBytes) == 0 {
		return nil, NewCondition(
			string(gatewayv1.GatewayConditionResolvedRefs),
			metav1.ConditionFalse,
			string(gatewayv1.GatewayReasonInvalidClientCertificateRef),
			fmt.Sprintf("Secret %s/%s is missing tls.crt or tls.key", secretKey.Namespace, secretKey.Name),
			gw.Generation,
		)
	}

	tlsCert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, NewCondition(
			string(gatewayv1.GatewayConditionResolvedRefs),
			metav1.ConditionFalse,
			string(gatewayv1.GatewayReasonInvalidClientCertificateRef),
			fmt.Sprintf("Secret %s/%s contains invalid certificate or key: %v", secretKey.Namespace, secretKey.Name, err),
			gw.Generation,
		)
	}

	return &tlsCert, NewCondition(
		string(gatewayv1.GatewayConditionResolvedRefs),
		metav1.ConditionTrue,
		string(gatewayv1.GatewayReasonResolvedRefs),
		"Resolved references",
		gw.Generation,
	)
}

// ComputeGatewayConditions computes the top-level conditions for a Gateway.
func ComputeGatewayConditions(
	gw *gatewayv1.Gateway,
	effectiveListeners []*EffectiveListener,
	hasAddress bool,
	readiness GatewayReadiness,
	provErr string,
	supportedAddressTypes []gatewayv1.AddressType,
	resolvedRefsCond metav1.Condition,
	paramsErr error,
) []metav1.Condition {
	totalListeners := len(gw.Spec.Listeners)
	acceptedListenersCount := 0

	for _, el := range effectiveListeners {
		if el.Owner.Kind == "Gateway" {
			if el.IsAccepted() {
				acceptedListenersCount++
			}
		}
	}

	gwAcceptedStatus := metav1.ConditionTrue
	gwAcceptedReason := gatewayv1.GatewayReasonAccepted
	gwAcceptedMessage := "Gateway accepted by reference implementation"

	if paramsErr != nil {
		gwAcceptedStatus = metav1.ConditionFalse
		gwAcceptedReason = gatewayv1.GatewayReasonInvalidParameters
		gwAcceptedMessage = paramsErr.Error()
	}
	if gwAcceptedStatus == metav1.ConditionTrue {
		if unsupp, unsuppType := HasUnsupportedAddress(gw.Spec.Addresses, supportedAddressTypes); unsupp {
			gwAcceptedStatus = metav1.ConditionFalse
			gwAcceptedReason = gatewayv1.GatewayReasonUnsupportedAddress
			gwAcceptedMessage = fmt.Sprintf("Address type %q is not supported", unsuppType)
		} else if totalListeners == 0 {
			gwAcceptedStatus = metav1.ConditionFalse
			gwAcceptedReason = gatewayv1.GatewayReasonListenersNotValid
			gwAcceptedMessage = "No listeners configured on Gateway"
		} else if acceptedListenersCount == 0 {
			gwAcceptedStatus = metav1.ConditionFalse
			gwAcceptedReason = gatewayv1.GatewayReasonListenersNotValid
			gwAcceptedMessage = "No listeners are accepted"
		} else if acceptedListenersCount < totalListeners {
			gwAcceptedStatus = metav1.ConditionTrue
			gwAcceptedReason = gatewayv1.GatewayReasonListenersNotValid
			gwAcceptedMessage = "One or more listeners have invalid configuration"
		}
	}

	gwProgrammedStatus := metav1.ConditionTrue
	gwProgrammedReason := gatewayv1.GatewayReasonProgrammed
	gwProgrammedMessage := "Gateway programmed by reference implementation"

	if gwAcceptedStatus == metav1.ConditionFalse {
		gwProgrammedStatus = metav1.ConditionFalse
		gwProgrammedReason = gatewayv1.GatewayReasonInvalid
		gwProgrammedMessage = "Gateway is not accepted"
	} else if provErr != "" {
		gwProgrammedStatus = metav1.ConditionFalse
		gwProgrammedReason = gatewayv1.GatewayReasonPending
		gwProgrammedMessage = provErr
	} else if !readiness.Ready && readiness.Reason == string(gatewayv1.GatewayReasonAddressNotUsable) {
		gwProgrammedStatus = metav1.ConditionFalse
		gwProgrammedReason = gatewayv1.GatewayReasonAddressNotUsable
		gwProgrammedMessage = "Requested address cannot be used"
		if readiness.Message != "" {
			gwProgrammedMessage = readiness.Message
		}
	} else if !hasAddress {
		gwProgrammedStatus = metav1.ConditionFalse
		gwProgrammedReason = gatewayv1.GatewayReasonAddressNotAssigned
		gwProgrammedMessage = "Waiting for address to be assigned to the Gateway"
		if readiness.Reason == string(gatewayv1.GatewayReasonAddressNotAssigned) && readiness.Message != "" {
			gwProgrammedMessage = readiness.Message
		}
	} else if !readiness.Ready {
		gwProgrammedStatus = metav1.ConditionFalse
		gwProgrammedReason = gatewayv1.GatewayReasonPending
		gwProgrammedMessage = "Waiting for data-plane deployment to become available"
		if readiness.Reason != "" {
			gwProgrammedReason = gatewayv1.GatewayConditionReason(readiness.Reason)
		}
		if readiness.Message != "" {
			gwProgrammedMessage = readiness.Message
		}
	}

	if resolvedRefsCond.Type == "" {
		gen := int64(0)
		if gw != nil {
			gen = gw.Generation
		}
		resolvedRefsCond = NewCondition(
			string(gatewayv1.GatewayConditionResolvedRefs),
			metav1.ConditionTrue,
			string(gatewayv1.GatewayReasonResolvedRefs),
			"Resolved references",
			gen,
		)
	}

	conds := []metav1.Condition{
		NewCondition(
			string(gatewayv1.GatewayConditionProgrammed),
			gwProgrammedStatus,
			string(gwProgrammedReason),
			gwProgrammedMessage,
			gw.Generation,
		),
		NewCondition(
			string(gatewayv1.GatewayConditionAccepted),
			gwAcceptedStatus,
			string(gwAcceptedReason),
			gwAcceptedMessage,
			gw.Generation,
		),
		resolvedRefsCond,
	}

	if hasInsecureFallbackListener(gw, effectiveListeners) {
		conds = append(conds, NewCondition(
			string(gatewayv1.GatewayConditionInsecureFrontendValidationMode),
			metav1.ConditionTrue,
			string(gatewayv1.GatewayReasonConfigurationChanged),
			"Frontend validation mode is set to AllowInsecureFallback",
			gw.Generation,
		))
	}

	return conds
}

func hasInsecureFallbackListener(gw *gatewayv1.Gateway, effectiveListeners []*EffectiveListener) bool {
	for _, el := range effectiveListeners {
		if el.ClientValidation != nil && el.ClientValidation.Mode == gatewayv1.AllowInsecureFallback {
			return true
		}
		if gw != nil && el.Protocol == gatewayv1.HTTPSProtocolType {
			if effVal := EffectiveFrontendValidation(gw.Spec.TLS, el.Port, el.Protocol); effVal != nil && effVal.Mode == gatewayv1.AllowInsecureFallback {
				return true
			}
		}
	}
	return false
}

// areProtocolsCompatible returns true if two listeners on the same port can co-exist.
// HTTP listeners can share a port with other HTTP listeners (differentiated by hostname).
// HTTPS listeners can share a port with other HTTPS listeners (differentiated by SNI/hostname).
// HTTPS and TLS listeners can also share a port (both routed by SNI).
func areProtocolsCompatible(p1, p2 gatewayv1.ProtocolType) bool {
	if p1 == p2 {
		if p1 == gatewayv1.HTTPProtocolType || p1 == gatewayv1.HTTPSProtocolType || p1 == gatewayv1.TLSProtocolType {
			return true
		}
		return false
	}
	if (p1 == gatewayv1.HTTPSProtocolType && p2 == gatewayv1.TLSProtocolType) ||
		(p1 == gatewayv1.TLSProtocolType && p2 == gatewayv1.HTTPSProtocolType) {
		return true
	}
	return false
}

// IsReservedDataPlanePort returns true if the port is reserved inside the data-plane pod:
// DataPlaneHTTPPort (HTTP proxy), DataPlaneHTTPSPort (HTTPS/TLS/HTTP3 proxy), DataPlaneHealthProbePort (metrics and health probes).
func IsReservedDataPlanePort(port gatewayv1.PortNumber) bool {
	return port == DataPlaneHTTPPort || port == DataPlaneHTTPSPort || port == DataPlaneHealthProbePort
}

func markListenerConflicted(el *EffectiveListener, reason gatewayv1.ListenerConditionReason, message string) {
	SetCondition(&el.Conditions, NewCondition(
		string(gatewayv1.ListenerConditionAccepted),
		metav1.ConditionFalse,
		string(reason),
		message,
		el.Generation,
	))
	SetCondition(&el.Conditions, NewCondition(
		string(gatewayv1.ListenerConditionProgrammed),
		metav1.ConditionFalse,
		string(reason),
		message,
		el.Generation,
	))
	SetCondition(&el.Conditions, NewCondition(
		string(gatewayv1.ListenerConditionConflicted),
		metav1.ConditionTrue,
		string(reason),
		message,
		el.Generation,
	))
}

type portHostnameKey struct {
	port     gatewayv1.PortNumber
	hostname string
}

// tlsHostnameClaim records a TLSRoute's claim on an effective listener hostname.
type tlsHostnameClaim struct {
	routeKey          types.NamespacedName
	originalHostname  string
	creationTimestamp metav1.Time
}

// hostnameSpecificity returns whether a hostname pattern is exact and its match length.
func hostnameSpecificity(h string) (isExact bool, length int) {
	if h == "" || h == "*" {
		return false, 0
	}
	if strings.HasPrefix(h, "*.") {
		return false, len(h)
	}
	return true, len(h)
}

// isBetterClaim reports whether the candidate claim has higher precedence than the current best claim.
func isBetterClaim(candidate, best tlsHostnameClaim) bool {
	candidateIsExact, candidateLen := hostnameSpecificity(candidate.originalHostname)
	bestIsExact, bestLen := hostnameSpecificity(best.originalHostname)

	// The Gateway API specification requires precedence by hostname specificity,
	// using the route's original hostnames (TLSRoute.spec.hostnames).
	// 1. Exact before wildcard
	if candidateIsExact != bestIsExact {
		return candidateIsExact
	}

	// 2. Longer wildcard (or exact) before shorter
	if candidateLen != bestLen {
		return candidateLen > bestLen
	}

	// Beyond the Gateway API specification: the specification does not define
	// a tie-break when two TLSRoutes claim identical hostnames on one listener,
	// leaving the case open for TLSRoute. This controller chooses the older route
	// by creation timestamp, then breaks ties alphabetically by namespace and name,
	// following the HTTPRoute rule. See tracking issue #1211.
	// 3. Oldest route by CreationTimestamp
	if !candidate.creationTimestamp.Equal(&best.creationTimestamp) {
		return candidate.creationTimestamp.Before(&best.creationTimestamp)
	}

	// 4. Alphabetically by namespace, then name
	if candidate.routeKey.Namespace != best.routeKey.Namespace {
		return candidate.routeKey.Namespace < best.routeKey.Namespace
	}
	return candidate.routeKey.Name < best.routeKey.Name
}

// isTLSRouteCompatible reports whether an effective listener supports TLSRoute binding.
func isTLSRouteCompatible(el *EffectiveListener) bool {
	if el.Protocol != gatewayv1.TLSProtocolType || el.TLS == nil {
		return false
	}
	if el.TLS.Mode == nil {
		return true
	}
	return *el.TLS.Mode == gatewayv1.TLSModePassthrough || *el.TLS.Mode == gatewayv1.TLSModeTerminate
}

// resolveTLSRouteHostnameClaims resolves hostname ownership across all candidate TLSRoutes.
//
// Invariant: each effective hostname on a listener has exactly one owning TLSRoute.
// Precedence order:
//  1. More specific route hostname first (exact match, then the longer wildcard).
//     The Gateway API specification requires precedence by hostname specificity,
//     using the route's original hostnames (TLSRoute.spec.hostnames).
//  2. Oldest route by CreationTimestamp.
//  3. Alphabetically by namespace, then name.
//     Beyond the Gateway API specification: the specification does not define
//     a tie-break when two TLSRoutes claim identical hostnames on one listener,
//     leaving the case open for TLSRoute. This controller chooses the older route
//     by creation timestamp, then breaks ties alphabetically by namespace and name,
//     following the HTTPRoute rule. See tracking issue #1211.
//
// This runs before binding because one route can win one hostname and lose another on the same listener.
func resolveTLSRouteHostnameClaims(
	routes []*gatewayv1.TLSRoute,
	cm *CompiledModel,
	namespaces map[string]*corev1.Namespace,
) {
	bestClaims := make(map[*EffectiveListener]map[string]tlsHostnameClaim)

	for _, route := range routes {
		if route == nil {
			continue
		}
		routeKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		var hostnames []string
		for _, h := range route.Spec.Hostnames {
			hostnames = append(hostnames, string(h))
		}

		for _, parentRef := range route.Spec.ParentRefs {
			allowedListeners, _, _ := matchAllowedListeners(
				parentRef,
				route.Namespace,
				route.Generation,
				cm,
				namespaces,
				isTLSRouteCompatible,
				IsTLSRoute,
			)

			for _, el := range allowedListeners {
				routeHostnames := IntersectRouteHostnames(hostnames, string(ValueOf(el.Hostname)))
				for _, rh := range routeHostnames {
					effectiveHostname := rh.Hostname
					// The Gateway API specification requires evaluating precedence using the
					// route's original hostnames (TLSRoute.spec.hostnames).
					claim := tlsHostnameClaim{
						routeKey:          routeKey,
						originalHostname:  rh.OriginalHostname,
						creationTimestamp: route.CreationTimestamp,
					}

					elClaims := bestClaims[el]
					if elClaims == nil {
						elClaims = make(map[string]tlsHostnameClaim)
						bestClaims[el] = elClaims
					}

					if existing, exists := elClaims[effectiveHostname]; !exists || isBetterClaim(claim, existing) {
						elClaims[effectiveHostname] = claim
						if el.TLSHostnameOwners == nil {
							el.TLSHostnameOwners = make(map[string]types.NamespacedName)
						}
						el.TLSHostnameOwners[effectiveHostname] = routeKey
					}
				}
			}
		}
	}
}

// CompileModel compiles the effective listeners, route bindings, and statuses across all Gateways and ListenerSets.
func CompileModel(inputs ModelInputs) *CompiledModel {
	refValidator := inputs.RefValidator
	if refValidator == nil && len(inputs.ReferenceGrants) > 0 {
		refValidator = mapReferenceValidator{referenceGrants: inputs.ReferenceGrants}
	}

	cm := &CompiledModel{
		Gateways:     make(map[types.NamespacedName]*CompiledGateway),
		HTTPRoutes:   make(map[types.NamespacedName]*CompiledRoute),
		TLSRoutes:    make(map[types.NamespacedName]*CompiledTLSRoute),
		GRPCRoutes:   make(map[types.NamespacedName]*CompiledGRPCRoute),
		TCPRoutes:    make(map[types.NamespacedName]*CompiledTCPRoute),
		UDPRoutes:    make(map[types.NamespacedName]*CompiledUDPRoute),
		ListenerSets: make(map[types.NamespacedName]*gatewayv1.ListenerSet),
	}

	for _, ls := range inputs.ListenerSets {
		if ls != nil {
			cm.ListenerSets[types.NamespacedName{Namespace: ls.Namespace, Name: ls.Name}] = ls
		}
	}

	managedGatewayClasses := make(map[string]bool)
	if inputs.ControllerName != "" {
		for _, gc := range inputs.GatewayClasses {
			if gc != nil && string(gc.Spec.ControllerName) == inputs.ControllerName {
				managedGatewayClasses[gc.Name] = true
			}
		}
	}

	// 1. Compile each Gateway and its effective listeners in precedence order
	sortedGateways := make([]*gatewayv1.Gateway, len(inputs.Gateways))
	copy(sortedGateways, inputs.Gateways)
	sort.Slice(sortedGateways, func(i, j int) bool {
		if !sortedGateways[i].CreationTimestamp.Equal(&sortedGateways[j].CreationTimestamp) {
			return sortedGateways[i].CreationTimestamp.Before(&sortedGateways[j].CreationTimestamp)
		}
		if sortedGateways[i].Namespace != sortedGateways[j].Namespace {
			return sortedGateways[i].Namespace < sortedGateways[j].Namespace
		}
		return sortedGateways[i].Name < sortedGateways[j].Name
	})

	boundTCPPorts := make(map[gatewayv1.PortNumber]string)
	boundUDPPorts := make(map[gatewayv1.PortNumber]string)
	boundHostnames := make(map[portHostnameKey]string)

	for _, gw := range sortedGateways {
		if gw == nil {
			continue
		}
		if inputs.ControllerName != "" && !managedGatewayClasses[string(gw.Spec.GatewayClassName)] {
			continue
		}
		gwKey := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
		cg := &CompiledGateway{
			Gateway: gw,
		}

		// Gateway's own listeners (highest precedence)
		for _, l := range gw.Spec.Listeners {
			frontendVal := EffectiveFrontendValidation(gw.Spec.TLS, l.Port, l.Protocol)
			el := BuildEffectiveListener(
				ListenerToSpec(l),
				ListenerOwner{Kind: "Gateway", Namespace: gw.Namespace, Name: gw.Name},
				gw,
				gw.Generation,
				inputs.Secrets,
				inputs.ConfigMaps,
				frontendVal,
				refValidator,
				inputs.CertificateSources,
				inputs.DisabledRouteKinds,
			)
			if inputs.ListenerValidator != nil {
				for _, cond := range inputs.ListenerValidator(ListenerToSpec(l), ListenerOwner{Kind: "Gateway", Namespace: gw.Namespace, Name: gw.Name}, gw) {
					SetCondition(&el.Conditions, cond)
				}
			}
			cg.EffectiveListeners = append(cg.EffectiveListeners, el)
		}

		// Allowed ListenerSets in precedence order:
		// 1. Creation time (oldest first)
		// 2. Alphabetically by "{namespace}/{name}"
		var allowedListenerSets []*gatewayv1.ListenerSet
		for _, ls := range inputs.ListenerSets {
			if ls == nil {
				continue
			}
			if IsListenerSetParent(ls, gw) && IsListenerSetAllowed(ls, gw, inputs.Namespaces) {
				allowedListenerSets = append(allowedListenerSets, ls)
			}
		}

		sort.Slice(allowedListenerSets, func(i, j int) bool {
			if !allowedListenerSets[i].CreationTimestamp.Equal(&allowedListenerSets[j].CreationTimestamp) {
				return allowedListenerSets[i].CreationTimestamp.Before(&allowedListenerSets[j].CreationTimestamp)
			}
			if allowedListenerSets[i].Namespace != allowedListenerSets[j].Namespace {
				return allowedListenerSets[i].Namespace < allowedListenerSets[j].Namespace
			}
			return allowedListenerSets[i].Name < allowedListenerSets[j].Name
		})

		for _, ls := range allowedListenerSets {
			for _, l := range ls.Spec.Listeners {
				frontendVal := EffectiveFrontendValidation(gw.Spec.TLS, l.Port, l.Protocol)
				el := BuildEffectiveListener(
					ListenerEntryToSpec(l),
					ListenerOwner{Kind: "ListenerSet", Namespace: ls.Namespace, Name: ls.Name},
					gw,
					ls.Generation,
					inputs.Secrets,
					inputs.ConfigMaps,
					frontendVal,
					refValidator,
					inputs.CertificateSources,
					inputs.DisabledRouteKinds,
				)
				if inputs.ListenerValidator != nil {
					for _, cond := range inputs.ListenerValidator(ListenerEntryToSpec(l), ListenerOwner{Kind: "ListenerSet", Namespace: ls.Namespace, Name: ls.Name}, gw) {
						SetCondition(&el.Conditions, cond)
					}
				}
				cg.EffectiveListeners = append(cg.EffectiveListeners, el)
			}
		}

		// Conflict detection pass over all effective listeners on this Gateway in precedence order
		for i := 0; i < len(cg.EffectiveListeners); i++ {
			elCur := cg.EffectiveListeners[i]
			if elCur.IsConflicted() {
				continue
			}

			// Raw TCP or UDP listener requesting a reserved data-plane port (8080, 8443, 8999)
			if (elCur.Protocol == gatewayv1.TCPProtocolType || elCur.Protocol == gatewayv1.UDPProtocolType) && IsReservedDataPlanePort(elCur.Port) {
				msg := fmt.Sprintf("%s listener port %d conflicts with reserved port %d", elCur.Protocol, elCur.Port, elCur.Port)
				markListenerConflicted(elCur, gatewayv1.ListenerReasonPortUnavailable, msg)
				continue
			}

			for j := 0; j < i; j++ {
				elPrev := cg.EffectiveListeners[j]
				if elPrev.IsConflicted() {
					continue
				}
				if elPrev.Port != elCur.Port {
					continue
				}

				// Check protocol compatibility
				if !areProtocolsCompatible(elPrev.Protocol, elCur.Protocol) {
					var msg string
					if elPrev.Protocol == elCur.Protocol {
						msg = fmt.Sprintf("Multiple %q listeners cannot share port %d without hostname/SNI routing (conflicts with %q)", elCur.Protocol, elCur.Port, elPrev.QualifiedName())
					} else {
						msg = fmt.Sprintf("Protocol %q conflicts with higher-precedence listener %q protocol %q on port %d", elCur.Protocol, elPrev.QualifiedName(), elPrev.Protocol, elCur.Port)
					}
					markListenerConflicted(elCur, gatewayv1.ListenerReasonProtocolConflict, msg)
					break
				}

				// Check hostname conflict for compatible protocols
				hPrev := strings.ToLower(string(ValueOf(elPrev.Hostname)))
				hCur := strings.ToLower(string(ValueOf(elCur.Hostname)))
				if hPrev == hCur {
					msg := fmt.Sprintf("Hostname %q conflicts with higher-precedence listener %q on port %d", hCur, elPrev.QualifiedName(), elCur.Port)
					markListenerConflicted(elCur, gatewayv1.ListenerReasonHostnameConflict, msg)
					break
				}
			}
		}

		// In all-in-one mode, two Gateways with the same TCP/UDP port cannot both bind; first wins and second reports Programmed=False.
		// Similarly, HTTP/HTTPS/TLS listeners sharing the same (port, hostname) conflict across Gateways; first wins and second reports Programmed=False.
		if inputs.AllInOneMode {
			for _, el := range cg.EffectiveListeners {
				if el.Protocol == gatewayv1.TCPProtocolType && el.IsAccepted() && !el.IsConflicted() {
					if firstGW, exists := boundTCPPorts[el.Port]; exists {
						SetCondition(&el.Conditions, NewCondition(
							string(gatewayv1.ListenerConditionProgrammed),
							metav1.ConditionFalse,
							string(gatewayv1.ListenerReasonPortUnavailable),
							fmt.Sprintf("Port %d is already bound by Gateway %s in all-in-one mode", el.Port, firstGW),
							el.Generation,
						))
					} else {
						boundTCPPorts[el.Port] = gwKey.String()
					}
				}
				if el.Protocol == gatewayv1.UDPProtocolType && el.IsAccepted() && !el.IsConflicted() {
					if firstGW, exists := boundUDPPorts[el.Port]; exists {
						SetCondition(&el.Conditions, NewCondition(
							string(gatewayv1.ListenerConditionProgrammed),
							metav1.ConditionFalse,
							string(gatewayv1.ListenerReasonPortUnavailable),
							fmt.Sprintf("Port %d is already bound by Gateway %s in all-in-one mode", el.Port, firstGW),
							el.Generation,
						))
					} else {
						boundUDPPorts[el.Port] = gwKey.String()
					}
				}
				if (el.Protocol == gatewayv1.HTTPProtocolType || el.Protocol == gatewayv1.HTTPSProtocolType || el.Protocol == gatewayv1.TLSProtocolType) && el.IsAccepted() && !el.IsConflicted() {
					h := strings.ToLower(string(ValueOf(el.Hostname)))
					key := portHostnameKey{port: el.Port, hostname: h}
					if firstGW, exists := boundHostnames[key]; exists {
						reason := gatewayv1.ListenerReasonHostnameConflict
						msg := fmt.Sprintf("Hostname %q is already bound by Gateway %s on port %d in all-in-one mode", h, firstGW, el.Port)
						if h == "" {
							reason = gatewayv1.ListenerReasonPortUnavailable
							msg = fmt.Sprintf("Port %d is already bound by Gateway %s in all-in-one mode", el.Port, firstGW)
						}
						SetCondition(&el.Conditions, NewCondition(
							string(gatewayv1.ListenerConditionProgrammed),
							metav1.ConditionFalse,
							string(reason),
							msg,
							el.Generation,
						))
					} else {
						boundHostnames[key] = gwKey.String()
					}
				}
			}
		}

		// Count only accepted ListenerSets (where at least one listener is valid/programmed and unconflicted)
		acceptedLSCount := int32(0)
		for _, ls := range allowedListenerSets {
			validCount := 0
			for _, el := range cg.EffectiveListeners {
				if el.Owner.Kind == "ListenerSet" && el.Owner.Namespace == ls.Namespace && el.Owner.Name == ls.Name {
					if el.IsAccepted() && el.IsProgrammed() && !el.IsConflicted() {
						validCount++
					}
				}
			}
			if validCount > 0 {
				acceptedLSCount++
			}
		}
		cg.AttachedListenerSets = acceptedLSCount

		hasAddress := false
		if inputs.GatewayAddresses != nil {
			hasAddress = len(inputs.GatewayAddresses[gwKey]) > 0
		}
		var provErr string
		if inputs.ProvisioningErrors != nil {
			provErr = inputs.ProvisioningErrors[gwKey]
		}
		var gcParams *Parameters
		var paramsErr error
		for _, gc := range inputs.GatewayClasses {
			if gc != nil && gc.Name == string(gw.Spec.GatewayClassName) {
				if gc.Spec.ParametersRef != nil {
					p, err := ValidateGatewayClassParametersRef(gc.Spec.ParametersRef, inputs.ConfigMaps)
					if err != nil {
						paramsErr = fmt.Errorf("invalid GatewayClass parametersRef: %w", err)
					} else {
						gcParams = p
					}
				}
				break
			}
		}
		var gwParams *Parameters
		if paramsErr == nil && gw.Spec.Infrastructure != nil && gw.Spec.Infrastructure.ParametersRef != nil {
			p, err := ValidateGatewayParametersRef(gw.Spec.Infrastructure.ParametersRef, gw.Namespace, inputs.ConfigMaps)
			if err != nil {
				paramsErr = fmt.Errorf("invalid infrastructure parametersRef: %w", err)
			} else {
				gwParams = p
			}
		}
		if paramsErr == nil {
			mergedParams := MergeParameters(gcParams, gwParams)
			if inputs.AllInOneMode && (len(mergedParams.AllowedSourceCIDRs) > 0 || mergedParams.ProxyProtocol != "" || len(mergedParams.ProxyProtocolTrustedCIDRs) > 0) {
				paramsErr = fmt.Errorf("per-Gateway listener parameters (allowedSourceCIDRs, proxyProtocol) are not supported in all-in-one mode")
				cg.Parameters = nil
			} else {
				cg.Parameters = mergedParams
			}
		} else {
			cg.Parameters = nil
		}
		cg.ParametersRefError = paramsErr

		clientCert, resolvedRefsCond := resolveGatewayBackendClientCert(gw, inputs.Secrets, refValidator)
		cg.BackendClientCert = clientCert
		cg.ResolvedRefsCondition = resolvedRefsCond
		cg.Conditions = ComputeGatewayConditions(gw, cg.EffectiveListeners, hasAddress, GatewayReadiness{Ready: true}, provErr, inputs.SupportedAddressTypes, resolvedRefsCond, cg.ParametersRefError)
		cm.Gateways[gwKey] = cg
	}

	var allCGs []*CompiledGateway
	for _, cg := range cm.Gateways {
		allCGs = append(allCGs, cg)
	}
	computeOverlappingTLSConfig(allCGs, inputs.AllInOneMode, inputs.Secrets)

	// 2. Compile HTTPRoutes and perform route binding
	for _, route := range inputs.HTTPRoutes {
		if route == nil {
			continue
		}
		routeKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		rs := &HTTPRouteState{HTTPRoute: route}
		rs.Compile(inputs.Services, inputs.BackendTLSPolicies, inputs.ConfigMaps, refValidator)

		parentConditions := make([]metav1.Condition, len(route.Spec.ParentRefs))
		boundListenersForRoute := make(map[*EffectiveListener]bool)

		for pIdx, parentRef := range route.Spec.ParentRefs {
			parentConditions[pIdx] = bindRouteParentRef(
				route,
				rs,
				parentRef,
				cm,
				inputs.Namespaces,
				boundListenersForRoute,
			)
		}

		cm.HTTPRoutes[routeKey] = &CompiledRoute{
			HTTPRoute:        route,
			RouteState:       rs,
			ParentConditions: parentConditions,
		}
	}

	// 3. Compile TLSRoutes and perform route binding
	resolveTLSRouteHostnameClaims(inputs.TLSRoutes, cm, inputs.Namespaces)

	for _, route := range inputs.TLSRoutes {
		if route == nil {
			continue
		}
		routeKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		rs := &TLSRouteState{TLSRoute: route}
		rs.Compile(inputs.Services, inputs.BackendTLSPolicies, inputs.ConfigMaps, refValidator)

		parentConditions := make([]metav1.Condition, len(route.Spec.ParentRefs))
		boundListenersForRoute := make(map[*EffectiveListener]bool)

		for pIdx, parentRef := range route.Spec.ParentRefs {
			parentConditions[pIdx] = bindTLSRouteParentRef(
				route,
				rs,
				parentRef,
				cm,
				inputs.Namespaces,
				boundListenersForRoute,
			)
		}

		var boundListeners []*EffectiveListener
		for listener := range boundListenersForRoute {
			boundListeners = append(boundListeners, listener)
		}

		cm.TLSRoutes[routeKey] = &CompiledTLSRoute{
			TLSRoute:         route,
			RouteState:       rs,
			ParentConditions: parentConditions,
			BoundListeners:   boundListeners,
		}
	}

	// 4. Compile GRPCRoutes and perform route binding
	for _, route := range inputs.GRPCRoutes {
		if route == nil {
			continue
		}
		routeKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		rs := &GRPCRouteState{GRPCRoute: route}
		rs.Compile(inputs.Services, inputs.BackendTLSPolicies, inputs.ConfigMaps, refValidator)

		parentConditions := make([]metav1.Condition, len(route.Spec.ParentRefs))
		boundListenersForRoute := make(map[*EffectiveListener]bool)

		for pIdx, parentRef := range route.Spec.ParentRefs {
			parentConditions[pIdx] = bindGRPCRouteParentRef(
				route,
				rs,
				parentRef,
				cm,
				inputs.Namespaces,
				boundListenersForRoute,
			)
		}

		cm.GRPCRoutes[routeKey] = &CompiledGRPCRoute{
			GRPCRoute:        route,
			RouteState:       rs,
			ParentConditions: parentConditions,
		}
	}

	// 5. Compile TCPRoutes and perform route binding
	for _, route := range inputs.TCPRoutes {
		if route == nil {
			continue
		}
		routeKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		rs := &TCPRouteState{TCPRoute: route}
		rs.Compile(inputs.Services, refValidator)

		parentConditions := make([]metav1.Condition, len(route.Spec.ParentRefs))
		boundListenersForRoute := make(map[*EffectiveListener]bool)

		for pIdx, parentRef := range route.Spec.ParentRefs {
			parentConditions[pIdx] = bindTCPRouteParentRef(
				route,
				rs,
				parentRef,
				cm,
				inputs.Namespaces,
				boundListenersForRoute,
			)
		}

		cm.TCPRoutes[routeKey] = &CompiledTCPRoute{
			TCPRoute:         route,
			RouteState:       rs,
			ParentConditions: parentConditions,
		}
	}

	// 6. Compile UDPRoutes and perform route binding
	for _, route := range inputs.UDPRoutes {
		if route == nil {
			continue
		}
		routeKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		rs := &UDPRouteState{UDPRoute: route}
		rs.Compile(inputs.Services, refValidator)

		parentConditions := make([]metav1.Condition, len(route.Spec.ParentRefs))
		boundListenersForRoute := make(map[*EffectiveListener]bool)

		for pIdx, parentRef := range route.Spec.ParentRefs {
			parentConditions[pIdx] = bindUDPRouteParentRef(
				route,
				rs,
				parentRef,
				cm,
				inputs.Namespaces,
				boundListenersForRoute,
			)
		}

		cm.UDPRoutes[routeKey] = &CompiledUDPRoute{
			UDPRoute:         route,
			RouteState:       rs,
			ParentConditions: parentConditions,
		}
	}

	return cm
}

type routeBindingConfig struct {
	namespace             string
	generation            int64
	hostnames             []string
	validationCond        *metav1.Condition
	isProtocolCompatible  func(el *EffectiveListener) bool
	isKindAllowed         func(group *gatewayv1.Group, kind gatewayv1.Kind) bool
	checkHostnameConflict func(el *EffectiveListener, routeHostnames []RouteHostname) ([]RouteHostname, *metav1.Condition)
	onBind                func(el *EffectiveListener, routeHostnames []RouteHostname)
}

// matchAllowedListeners returns the listeners matching the parentRef that permit route attachment.
func matchAllowedListeners(
	parentRef gatewayv1.ParentReference,
	routeNs string,
	generation int64,
	cm *CompiledModel,
	namespaces map[string]*corev1.Namespace,
	isProtocolCompatible func(el *EffectiveListener) bool,
	isKindAllowed func(group *gatewayv1.Group, kind gatewayv1.Kind) bool,
) ([]*EffectiveListener, bool, *metav1.Condition) {
	group := ValueOf(parentRef.Group)
	if group != "" && group != gatewayv1.GroupName {
		cond := NewCondition(
			string(gatewayv1.RouteConditionAccepted),
			metav1.ConditionFalse,
			string(gatewayv1.RouteReasonNoMatchingParent),
			fmt.Sprintf("Unsupported parent group: %s", group),
			generation,
		)
		return nil, false, &cond
	}

	kind := ValueOf(parentRef.Kind)
	if kind == "" {
		kind = "Gateway"
	}
	if kind != "Gateway" && kind != "ListenerSet" {
		cond := NewCondition(
			string(gatewayv1.RouteConditionAccepted),
			metav1.ConditionFalse,
			string(gatewayv1.RouteReasonNoMatchingParent),
			fmt.Sprintf("Unsupported parent kind: %s", kind),
			generation,
		)
		return nil, false, &cond
	}

	targetNamespace := routeNs
	if parentNamespace := ValueOf(parentRef.Namespace); parentNamespace != "" {
		targetNamespace = string(parentNamespace)
	}
	targetName := string(parentRef.Name)

	var candidateListeners []*EffectiveListener

	if kind == "Gateway" {
		cg := cm.Gateways[types.NamespacedName{Namespace: targetNamespace, Name: targetName}]
		if cg == nil {
			cond := NewCondition(
				string(gatewayv1.RouteConditionAccepted),
				metav1.ConditionFalse,
				string(gatewayv1.RouteReasonNoMatchingParent),
				"Gateway not found",
				generation,
			)
			return nil, false, &cond
		}
		for _, el := range cg.EffectiveListeners {
			if el.Owner.Kind == "Gateway" && el.IsAccepted() {
				candidateListeners = append(candidateListeners, el)
			}
		}
	} else if kind == "ListenerSet" {
		targetLS := cm.ListenerSets[types.NamespacedName{Namespace: targetNamespace, Name: targetName}]
		if targetLS == nil {
			cond := NewCondition(
				string(gatewayv1.RouteConditionAccepted),
				metav1.ConditionFalse,
				string(gatewayv1.RouteReasonNoMatchingParent),
				"ListenerSet not found",
				generation,
			)
			return nil, false, &cond
		}

		gwNs := targetLS.Namespace
		if ns := ValueOf(targetLS.Spec.ParentRef.Namespace); ns != "" {
			gwNs = string(ns)
		}
		cg := cm.Gateways[types.NamespacedName{Namespace: gwNs, Name: string(targetLS.Spec.ParentRef.Name)}]
		if cg == nil || !IsListenerSetAllowed(targetLS, cg.Gateway, namespaces) {
			cond := NewCondition(
				string(gatewayv1.RouteConditionAccepted),
				metav1.ConditionFalse,
				string(gatewayv1.RouteReasonNoMatchingParent),
				"Parent ListenerSet is not accepted by Gateway",
				generation,
			)
			return nil, false, &cond
		}

		for _, el := range cg.EffectiveListeners {
			if el.Owner.Kind == "ListenerSet" && el.Owner.Namespace == targetLS.Namespace && el.Owner.Name == targetLS.Name && el.IsAccepted() {
				candidateListeners = append(candidateListeners, el)
			}
		}
	}

	hasMatchingListener := false
	var allowedListeners []*EffectiveListener

	for _, el := range candidateListeners {
		if sectionName := ValueOf(parentRef.SectionName); sectionName != "" && sectionName != el.Name {
			continue
		}
		if port := ValueOf(parentRef.Port); port != 0 && port != el.Port {
			continue
		}
		hasMatchingListener = true

		// Check protocol compatibility
		if !isProtocolCompatible(el) {
			continue
		}

		// Check AllowedRoutes kinds
		if el.AllowedRoutes != nil && len(el.AllowedRoutes.Kinds) > 0 {
			kindAllowed := false
			for _, k := range el.AllowedRoutes.Kinds {
				if isKindAllowed(k.Group, k.Kind) {
					kindAllowed = true
					break
				}
			}
			if !kindAllowed {
				continue
			}
		}

		// Check AllowedRoutes namespaces
		if el.AllowedRoutes != nil && el.AllowedRoutes.Namespaces != nil && el.AllowedRoutes.Namespaces.From != nil {
			switch *el.AllowedRoutes.Namespaces.From {
			case gatewayv1.NamespacesFromSame:
				if routeNs != el.Owner.Namespace {
					continue
				}
			case gatewayv1.NamespacesFromAll:
				// Allowed
			case gatewayv1.NamespacesFromSelector:
				if el.AllowedRoutes.Namespaces.Selector != nil {
					sel, err := metav1.LabelSelectorAsSelector(el.AllowedRoutes.Namespaces.Selector)
					if err != nil {
						continue
					}
					var nsObj *corev1.Namespace
					if namespaces != nil {
						nsObj = namespaces[routeNs]
					}
					if nsObj != nil {
						if !sel.Matches(labels.Set(nsObj.Labels)) {
							continue
						}
					} else if routeNs != el.Owner.Namespace && namespaces != nil {
						continue
					}
				}
			}
		} else {
			// Default is Same namespace
			if routeNs != el.Owner.Namespace {
				continue
			}
		}

		allowedListeners = append(allowedListeners, el)
	}

	return allowedListeners, hasMatchingListener, nil
}

func bindParentRef(
	cfg routeBindingConfig,
	parentRef gatewayv1.ParentReference,
	cm *CompiledModel,
	namespaces map[string]*corev1.Namespace,
	boundListenersForRoute map[*EffectiveListener]bool,
) metav1.Condition {
	if cfg.validationCond != nil && cfg.validationCond.Status == metav1.ConditionFalse {
		return *cfg.validationCond
	}

	allowedListeners, hasMatchingListener, errorCondition := matchAllowedListeners(
		parentRef,
		cfg.namespace,
		cfg.generation,
		cm,
		namespaces,
		cfg.isProtocolCompatible,
		cfg.isKindAllowed,
	)
	if errorCondition != nil {
		return *errorCondition
	}

	hasAllowedListener := len(allowedListeners) > 0
	hasMatchingHostname := false
	var conflictCond *metav1.Condition

	for _, el := range allowedListeners {
		routeHostnames := IntersectRouteHostnames(cfg.hostnames, string(ValueOf(el.Hostname)))
		if len(routeHostnames) == 0 && len(cfg.hostnames) > 0 {
			continue
		}

		if cfg.checkHostnameConflict != nil {
			var cond *metav1.Condition
			routeHostnames, cond = cfg.checkHostnameConflict(el, routeHostnames)
			if cond != nil && conflictCond == nil {
				conflictCond = cond
			}
		}
		if len(routeHostnames) > 0 {
			hasMatchingHostname = true

			if !boundListenersForRoute[el] {
				boundListenersForRoute[el] = true
				el.AttachedRoutes++
				if cfg.onBind != nil {
					cfg.onBind(el, routeHostnames)
				}
			}
		}
	}

	if hasMatchingHostname {
		return NewCondition(
			string(gatewayv1.RouteConditionAccepted),
			metav1.ConditionTrue,
			string(gatewayv1.RouteReasonAccepted),
			"Route accepted by reference implementation",
			cfg.generation,
		)
	}
	if conflictCond != nil {
		return *conflictCond
	}
	if hasAllowedListener {
		return NewCondition(
			string(gatewayv1.RouteConditionAccepted),
			metav1.ConditionFalse,
			string(gatewayv1.RouteReasonNoMatchingListenerHostname),
			"No matching listener hostname",
			cfg.generation,
		)
	}
	if hasMatchingListener {
		return NewCondition(
			string(gatewayv1.RouteConditionAccepted),
			metav1.ConditionFalse,
			string(gatewayv1.RouteReasonNotAllowedByListeners),
			"Not allowed by listener permissions or protocol",
			cfg.generation,
		)
	}
	return NewCondition(
		string(gatewayv1.RouteConditionAccepted),
		metav1.ConditionFalse,
		string(gatewayv1.RouteReasonNoMatchingParent),
		"No matching listener for parentRef",
		cfg.generation,
	)
}

func bindRouteParentRef(
	route *gatewayv1.HTTPRoute,
	rs *HTTPRouteState,
	parentRef gatewayv1.ParentReference,
	cm *CompiledModel,
	namespaces map[string]*corev1.Namespace,
	boundListenersForRoute map[*EffectiveListener]bool,
) metav1.Condition {
	var valCond *metav1.Condition
	if rs.Internal != nil {
		valCond = &rs.Internal.ValidationCondition
	}
	return bindParentRef(
		routeBindingConfig{
			namespace:      route.Namespace,
			generation:     route.Generation,
			hostnames:      rs.GetHostnames(),
			validationCond: valCond,
			isProtocolCompatible: func(el *EffectiveListener) bool {
				return el.Protocol == gatewayv1.HTTPProtocolType || el.Protocol == gatewayv1.HTTPSProtocolType
			},
			isKindAllowed: IsHTTPRoute,
			onBind: func(el *EffectiveListener, routeHostnames []RouteHostname) {
				ir := InternalRoute{
					Hostnames: routeHostnames,
					Rules:     rs.Internal.Rules,
				}
				el.Routes = append(el.Routes, ir)
			},
		},
		parentRef,
		cm,
		namespaces,
		boundListenersForRoute,
	)
}

func bindTLSRouteParentRef(
	route *gatewayv1.TLSRoute,
	rs *TLSRouteState,
	parentRef gatewayv1.ParentReference,
	cm *CompiledModel,
	namespaces map[string]*corev1.Namespace,
	boundListenersForRoute map[*EffectiveListener]bool,
) metav1.Condition {
	var valCond *metav1.Condition
	if rs.Internal != nil {
		valCond = &rs.Internal.ValidationCondition
	}
	routeKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
	return bindParentRef(
		routeBindingConfig{
			namespace:            route.Namespace,
			generation:           route.Generation,
			hostnames:            rs.GetHostnames(),
			validationCond:       valCond,
			isProtocolCompatible: isTLSRouteCompatible,
			isKindAllowed:        IsTLSRoute,
			checkHostnameConflict: func(el *EffectiveListener, routeHostnames []RouteHostname) ([]RouteHostname, *metav1.Condition) {
				var available []RouteHostname
				for _, rh := range routeHostnames {
					effectiveHostname := rh.Hostname
					if el.TLSHostnameOwners != nil && el.TLSHostnameOwners[effectiveHostname] != routeKey {
						continue
					}
					available = append(available, rh)
				}
				if len(available) == 0 && len(routeHostnames) > 0 {
					// Beyond the Gateway API specification: the specification does not define
					// what condition a TLSRoute reports when another route holds all matching hostnames
					// on a parent listener, leaving the condition unspecified for a route that holds
					// no hostname on a parent. This controller reports Accepted=False with the reason
					// AnotherRouteHoldsHostname so that operators can diagnose why the route did not bind.
					// See tracking issue #1211.
					cond := NewCondition(
						string(gatewayv1.RouteConditionAccepted),
						metav1.ConditionFalse,
						string(RouteReasonAnotherRouteHoldsHostname),
						"Another route holds the hostname",
						route.Generation,
					)
					return nil, &cond
				}
				return available, nil
			},
			onBind: func(el *EffectiveListener, routeHostnames []RouteHostname) {
				if el.TLSBackends == nil {
					el.TLSBackends = make(map[string][]InternalTLSBackend)
				}
				for _, rh := range routeHostnames {
					effectiveHostname := rh.Hostname
					if rs.Internal != nil {
						for _, rule := range rs.Internal.Rules {
							if len(rule.Backends) > 0 {
								el.TLSBackends[effectiveHostname] = append(el.TLSBackends[effectiveHostname], rule.Backends...)
							}
						}
					}
				}
			},
		},
		parentRef,
		cm,
		namespaces,
		boundListenersForRoute,
	)
}

func bindGRPCRouteParentRef(
	route *gatewayv1.GRPCRoute,
	rs *GRPCRouteState,
	parentRef gatewayv1.ParentReference,
	cm *CompiledModel,
	namespaces map[string]*corev1.Namespace,
	boundListenersForRoute map[*EffectiveListener]bool,
) metav1.Condition {
	var valCond *metav1.Condition
	if rs.Internal != nil {
		valCond = &rs.Internal.ValidationCondition
	}
	return bindParentRef(
		routeBindingConfig{
			namespace:      route.Namespace,
			generation:     route.Generation,
			hostnames:      rs.GetHostnames(),
			validationCond: valCond,
			isProtocolCompatible: func(el *EffectiveListener) bool {
				return el.Protocol == gatewayv1.HTTPProtocolType || el.Protocol == gatewayv1.HTTPSProtocolType
			},
			isKindAllowed: IsGRPCRoute,
			onBind: func(el *EffectiveListener, routeHostnames []RouteHostname) {
				ir := InternalRoute{
					Hostnames: routeHostnames,
					Rules:     rs.Internal.Rules,
				}
				el.Routes = append(el.Routes, ir)
			},
		},
		parentRef,
		cm,
		namespaces,
		boundListenersForRoute,
	)
}

func bindTCPRouteParentRef(
	route *gatewayv1.TCPRoute,
	rs *TCPRouteState,
	parentRef gatewayv1.ParentReference,
	cm *CompiledModel,
	namespaces map[string]*corev1.Namespace,
	boundListenersForRoute map[*EffectiveListener]bool,
) metav1.Condition {
	var valCond *metav1.Condition
	if rs.Internal != nil {
		valCond = &rs.Internal.ValidationCondition
	}
	return bindParentRef(
		routeBindingConfig{
			namespace:      route.Namespace,
			generation:     route.Generation,
			hostnames:      nil,
			validationCond: valCond,
			isProtocolCompatible: func(el *EffectiveListener) bool {
				return el.Protocol == gatewayv1.TCPProtocolType
			},
			isKindAllowed: IsTCPRoute,
			onBind: func(el *EffectiveListener, _ []RouteHostname) {
				if rs.Internal != nil {
					routeKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
					if el.BoundTCPRoute == nil || *el.BoundTCPRoute == routeKey {
						el.BoundTCPRoute = &routeKey
						for _, rule := range rs.Internal.Rules {
							if len(rule.Backends) > 0 {
								el.TCPBackends = append(el.TCPBackends, rule.Backends...)
							}
						}
					}
				}
			},
		},
		parentRef,
		cm,
		namespaces,
		boundListenersForRoute,
	)
}

func bindUDPRouteParentRef(
	route *gatewayv1.UDPRoute,
	rs *UDPRouteState,
	parentRef gatewayv1.ParentReference,
	cm *CompiledModel,
	namespaces map[string]*corev1.Namespace,
	boundListenersForRoute map[*EffectiveListener]bool,
) metav1.Condition {
	var valCond *metav1.Condition
	if rs.Internal != nil {
		valCond = &rs.Internal.ValidationCondition
	}
	return bindParentRef(
		routeBindingConfig{
			namespace:      route.Namespace,
			generation:     route.Generation,
			hostnames:      nil,
			validationCond: valCond,
			isProtocolCompatible: func(el *EffectiveListener) bool {
				return el.Protocol == gatewayv1.UDPProtocolType
			},
			isKindAllowed: IsUDPRoute,
			onBind: func(el *EffectiveListener, _ []RouteHostname) {
				if rs.Internal != nil {
					routeKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
					if el.BoundUDPRoute == nil || *el.BoundUDPRoute == routeKey {
						el.BoundUDPRoute = &routeKey
						for _, rule := range rs.Internal.Rules {
							if len(rule.Backends) > 0 {
								el.UDPBackends = append(el.UDPBackends, rule.Backends...)
							}
						}
					}
				}
			},
		},
		parentRef,
		cm,
		namespaces,
		boundListenersForRoute,
	)
}

// ExtractCertificates extracts TLS certificates once per effective listener across all compiled gateways.
func ExtractCertificates(gateways []*CompiledGateway) (map[string]*tls.Certificate, *tls.Certificate) {
	certsMap := make(map[string]*tls.Certificate)
	listenerHosts := make(map[string]*EffectiveListener)
	var defaultCert *tls.Certificate

	type listenerCert struct {
		el           *EffectiveListener
		listenerHost string
		cert         *tls.Certificate
	}
	var validCerts []listenerCert

	for _, cg := range gateways {
		if cg == nil {
			continue
		}
		for _, el := range cg.EffectiveListeners {
			if !el.IsAccepted() || !el.IsProgrammed() {
				continue
			}
			if (el.Protocol != gatewayv1.HTTPSProtocolType && el.Protocol != gatewayv1.TLSProtocolType) || el.TLS == nil {
				continue
			}
			if el.Protocol == gatewayv1.TLSProtocolType && (el.TLS.Mode != nil && *el.TLS.Mode == gatewayv1.TLSModePassthrough) {
				continue
			}

			var listenerHost string
			if el.Hostname != nil && string(*el.Hostname) != "" {
				listenerHost = strings.ToLower(string(*el.Hostname))
			}

			for _, cert := range el.ResolvedCertificates {
				if cert == nil || len(cert.Certificate) == 0 {
					continue
				}
				certCopy := new(tls.Certificate)
				*certCopy = *cert
				leaf := certCopy.Leaf
				if leaf == nil {
					var err error
					leaf, err = x509.ParseCertificate(certCopy.Certificate[0])
					if err != nil {
						continue
					}
					certCopy.Leaf = leaf
				}

				if el.Owner.Kind == "Gateway" && (listenerHost == "" || defaultCert == nil) {
					defaultCert = certCopy
				}

				validCerts = append(validCerts, listenerCert{
					el:           el,
					listenerHost: listenerHost,
					cert:         certCopy,
				})
			}
		}
	}

	// Pass 1: key every listener by its own hostname.
	for _, lc := range validCerts {
		if lc.listenerHost == "" {
			continue
		}
		if prevListener, exists := listenerHosts[lc.listenerHost]; exists {
			if prevListener != lc.el {
				klog.V(2).Infof("listener %s certificate for hostname %q would overwrite existing certificate from listener %s, skipping", lc.el.Name, lc.listenerHost, prevListener.Name)
			}
			continue
		}
		listenerHosts[lc.listenerHost] = lc.el
		certsMap[lc.listenerHost] = lc.cert
	}

	// Pass 2: add SAN-derived keys only where no listener hostname already owns the name.
	for _, lc := range validCerts {
		leaf := lc.cert.Leaf
		if leaf == nil {
			continue
		}
		var sans []string
		if leaf.Subject.CommonName != "" {
			sans = append(sans, leaf.Subject.CommonName)
		}
		sans = append(sans, leaf.DNSNames...)
		for _, san := range sans {
			cleanSAN := strings.ToLower(san)
			if !sanFallsWithinListener(cleanSAN, lc.listenerHost) {
				continue
			}
			if _, exists := listenerHosts[cleanSAN]; exists {
				continue
			}
			if _, exists := certsMap[cleanSAN]; exists {
				continue
			}
			certsMap[cleanSAN] = lc.cert
		}
	}

	return certsMap, defaultCert
}

func sanFallsWithinListener(san, listenerHost string) bool {
	if listenerHost == "" || listenerHost == "*" {
		return true
	}
	if san == listenerHost {
		return true
	}
	if strings.HasPrefix(listenerHost, "*.") && MatchesWildcard(listenerHost, san) {
		return true
	}
	return false
}

// BuildProxyConfig constructs the proxy listeners and routes from compiled gateways.
func BuildProxyConfig(gateways []*CompiledGateway) ([]InternalListener, []InternalRoute) {
	var proxyListeners []InternalListener
	var proxyRoutes []InternalRoute

	for _, cg := range gateways {
		if cg == nil {
			continue
		}
		acmeEnabled := cg.Parameters != nil && cg.Parameters.ACMEChallenge == "enabled"
		for _, el := range cg.EffectiveListeners {
			if !el.IsAccepted() || !el.IsProgrammed() {
				continue
			}
			if el.Protocol == gatewayv1.TCPProtocolType && !el.IsProgrammed() {
				continue
			}
			if el.Protocol == gatewayv1.UDPProtocolType && !el.IsProgrammed() {
				continue
			}
			iListener := el.ToInternalListener()
			iListener.ACMEChallenge = acmeEnabled
			proxyListeners = append(proxyListeners, iListener)
			proxyRoutes = append(proxyRoutes, el.Routes...)
		}
	}

	return proxyListeners, proxyRoutes
}

// ComputeOutputs computes all desired statuses, proxy configuration, certificates, and resolved gateways.
func ComputeOutputs(inputs ModelInputs) *Outputs {
	if inputs.RefValidator == nil && len(inputs.ReferenceGrants) > 0 {
		inputs.RefValidator = mapReferenceValidator{referenceGrants: inputs.ReferenceGrants}
	}

	compiled := CompileModel(inputs)

	outputs := &Outputs{
		Revision:                 inputs.Revision,
		GatewayStatuses:          make(map[types.NamespacedName]gatewayv1.GatewayStatus),
		HTTPRouteStatuses:        make(map[types.NamespacedName]gatewayv1.HTTPRouteStatus),
		TLSRouteStatuses:         make(map[types.NamespacedName]gatewayv1.TLSRouteStatus),
		GRPCRouteStatuses:        make(map[types.NamespacedName]gatewayv1.GRPCRouteStatus),
		TCPRouteStatuses:         make(map[types.NamespacedName]gatewayv1.TCPRouteStatus),
		UDPRouteStatuses:         make(map[types.NamespacedName]gatewayv1.UDPRouteStatus),
		ListenerSetStatuses:      make(map[types.NamespacedName]gatewayv1.ListenerSetStatus),
		BackendTLSPolicyStatuses: make(map[types.NamespacedName]gatewayv1.PolicyStatus),
		GatewayClassStatuses:     make(map[types.NamespacedName]gatewayv1.GatewayClassStatus),
		GatewayParameters:        make(map[types.NamespacedName]*Parameters),
		GatewayParametersErrors:  make(map[types.NamespacedName]error),
	}

	// 1. Gateway Statuses
	for _, gw := range inputs.Gateways {
		if gw == nil {
			continue
		}
		gwKey := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
		cg := compiled.Gateways[gwKey]
		if cg != nil {
			outputs.GatewayParameters[gwKey] = cg.Parameters
			outputs.GatewayParametersErrors[gwKey] = cg.ParametersRefError
			var addrs []gatewayv1.GatewayStatusAddress
			if inputs.GatewayAddresses != nil {
				addrs = inputs.GatewayAddresses[gwKey]
			}
			readiness := GatewayReadiness{Ready: true}
			if inputs.GatewayReadiness != nil {
				if r, ok := inputs.GatewayReadiness[gwKey]; ok {
					readiness = r
				}
			}
			var provErr string
			if inputs.ProvisioningErrors != nil {
				provErr = inputs.ProvisioningErrors[gwKey]
			}
			outputs.GatewayStatuses[gwKey] = ComputeDesiredGatewayStatus(gw, cg, addrs, readiness, provErr, inputs.SupportedAddressTypes)
		}
	}

	// 2. ListenerSet Statuses
	for _, ls := range inputs.ListenerSets {
		if ls == nil {
			continue
		}
		lsKey := types.NamespacedName{Namespace: ls.Namespace, Name: ls.Name}
		var parentGW *gatewayv1.Gateway
		for _, g := range inputs.Gateways {
			if g != nil && IsListenerSetParent(ls, g) {
				parentGW = g
				break
			}
		}
		var compiledGw *CompiledGateway
		if parentGW != nil {
			parentKey := types.NamespacedName{Namespace: parentGW.Namespace, Name: parentGW.Name}
			compiledGw = compiled.Gateways[parentKey]
		}
		if parentGW != nil && (inputs.ControllerName == "" || compiledGw != nil) {
			outputs.ListenerSetStatuses[lsKey] = ComputeDesiredListenerSetStatus(ls, parentGW, inputs.Namespaces, compiledGw)
		}
	}

	// 3. HTTPRoute Statuses
	for _, route := range inputs.HTTPRoutes {
		if route == nil {
			continue
		}
		routeKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		compiledRoute := compiled.HTTPRoutes[routeKey]
		outputs.HTTPRouteStatuses[routeKey] = ComputeDesiredHTTPRouteStatus(route, compiledRoute, inputs.ControllerName)
	}

	// 4. TLSRoute Statuses
	for _, route := range inputs.TLSRoutes {
		if route == nil {
			continue
		}
		routeKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		compiledRoute := compiled.TLSRoutes[routeKey]
		outputs.TLSRouteStatuses[routeKey] = ComputeDesiredTLSRouteStatus(route, compiledRoute, inputs.ControllerName)
	}

	// 5. GRPCRoute Statuses
	for _, route := range inputs.GRPCRoutes {
		if route == nil {
			continue
		}
		routeKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		compiledRoute := compiled.GRPCRoutes[routeKey]
		outputs.GRPCRouteStatuses[routeKey] = ComputeDesiredGRPCRouteStatus(route, compiledRoute, inputs.ControllerName)
	}

	// 6. TCPRoute Statuses
	for _, route := range inputs.TCPRoutes {
		if route == nil {
			continue
		}
		routeKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		compiledRoute := compiled.TCPRoutes[routeKey]
		outputs.TCPRouteStatuses[routeKey] = ComputeDesiredTCPRouteStatus(route, compiledRoute, inputs.ControllerName)
	}

	// 7. UDPRoute Statuses
	for _, route := range inputs.UDPRoutes {
		if route == nil {
			continue
		}
		routeKey := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		compiledRoute := compiled.UDPRoutes[routeKey]
		outputs.UDPRouteStatuses[routeKey] = ComputeDesiredUDPRouteStatus(route, compiledRoute, inputs.ControllerName)
	}

	// 8. BackendTLSPolicy Statuses
	for _, policy := range inputs.BackendTLSPolicies {
		if policy == nil {
			continue
		}
		policyKey := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}
		outputs.BackendTLSPolicyStatuses[policyKey] = ComputeDesiredBackendTLSPolicyStatus(
			policy,
			compiled,
			inputs.ConfigMaps,
			inputs.BackendTLSPolicies,
			inputs.ControllerName,
		)
	}

	// 5. GatewayClass Statuses
	for _, gc := range inputs.GatewayClasses {
		if gc == nil {
			continue
		}
		if inputs.ControllerName == "" || string(gc.Spec.ControllerName) == inputs.ControllerName {
			gcKey := types.NamespacedName{Name: gc.Name}
			outputs.GatewayClassStatuses[gcKey] = ComputeDesiredGatewayClassStatus(gc, inputs.ControllerName, inputs.GatewayCRDBundleVersion, inputs.ConfigMaps)
		}
	}

	// 6. Proxy Config & Certs
	proxyListeners, proxyRoutes := BuildProxyConfig(compiled.GatewaysList())
	certsMap, defaultCert := ExtractCertificates(compiled.GatewaysList())

	outputs.ProxyListeners = proxyListeners
	outputs.ProxyRoutes = proxyRoutes
	outputs.CertificatesMap = certsMap
	outputs.DefaultCert = defaultCert
	outputs.ResolvedGateways = compiled.ResolvedGateways()
	outputs.CompiledGateways = compiled.Gateways

	outputs.DataplaneConfigs = make(map[types.NamespacedName]*DataplaneConfig)
	for gwKey, cg := range compiled.Gateways {
		dpConfig, err := BuildGatewayDataplaneConfig(cg)
		if err == nil && dpConfig != nil {
			outputs.DataplaneConfigs[gwKey] = dpConfig
		}
	}

	return outputs
}

// ComputeDesiredGatewayStatus computes the desired GatewayStatus from the compiled model and address provider.
func ComputeDesiredGatewayStatus(
	gw *gatewayv1.Gateway,
	compiledGw *CompiledGateway,
	providedAddresses []gatewayv1.GatewayStatusAddress,
	readiness GatewayReadiness,
	provErr string,
	supportedAddressTypes []gatewayv1.AddressType,
) gatewayv1.GatewayStatus {
	desiredAddresses := computeDesiredAddresses(gw.Spec.Addresses, providedAddresses)
	hasAddress := len(desiredAddresses) > 0
	var effectiveListeners []*EffectiveListener
	attachedLSCount := int32(0)
	var resolvedRefsCond metav1.Condition
	var paramsErr error
	if compiledGw != nil {
		effectiveListeners = compiledGw.EffectiveListeners
		attachedLSCount = compiledGw.AttachedListenerSets
		resolvedRefsCond = compiledGw.ResolvedRefsCondition
		paramsErr = compiledGw.ParametersRefError
	} else if gw.Spec.Infrastructure != nil && gw.Spec.Infrastructure.ParametersRef != nil {
		_, paramsErr = ValidateGatewayParametersRef(gw.Spec.Infrastructure.ParametersRef, gw.Namespace, nil)
	}

	desiredConditions := ComputeGatewayConditions(gw, effectiveListeners, hasAddress, readiness, provErr, supportedAddressTypes, resolvedRefsCond, paramsErr)

	var desiredListenerStatuses []gatewayv1.ListenerStatus
	for _, l := range gw.Spec.Listeners {
		var matchedEl *EffectiveListener
		for _, el := range effectiveListeners {
			if el.Owner.Kind == "Gateway" && el.Name == l.Name {
				matchedEl = el
				break
			}
		}

		supportedKinds := defaultSupportedKindsForProtocol(l.Protocol)
		attachedRoutes := int32(0)
		var conds []metav1.Condition
		if matchedEl != nil {
			supportedKinds = matchedEl.SupportedKinds
			attachedRoutes = matchedEl.AttachedRoutes
			conds = make([]metav1.Condition, len(matchedEl.Conditions))
			copy(conds, matchedEl.Conditions)
		}

		desiredListenerStatuses = append(desiredListenerStatuses, gatewayv1.ListenerStatus{
			Name:           l.Name,
			SupportedKinds: supportedKinds,
			AttachedRoutes: attachedRoutes,
			Conditions:     conds,
		})
	}

	gwAccepted := false
	for _, cond := range desiredConditions {
		if cond.Type == string(gatewayv1.GatewayConditionAccepted) && cond.Status == metav1.ConditionTrue {
			gwAccepted = true
			break
		}
	}

	if !gwAccepted {
		desiredAddresses = nil
	}

	return gatewayv1.GatewayStatus{
		Conditions:           desiredConditions,
		Listeners:            desiredListenerStatuses,
		Addresses:            desiredAddresses,
		AttachedListenerSets: &attachedLSCount,
	}
}

// ComputeDesiredListenerSetStatus computes the desired ListenerSetStatus from the compiled model.
func ComputeDesiredListenerSetStatus(
	ls *gatewayv1.ListenerSet,
	parentGW *gatewayv1.Gateway,
	namespaces map[string]*corev1.Namespace,
	compiledGw *CompiledGateway,
) gatewayv1.ListenerSetStatus {
	var effectiveListeners []*EffectiveListener
	if compiledGw != nil {
		effectiveListeners = compiledGw.EffectiveListeners
	}

	acceptedCond, programmedCond := ComputeListenerSetConditions(ls, parentGW, namespaces, effectiveListeners)
	desiredConditions := []metav1.Condition{programmedCond, acceptedCond}

	var desiredListeners []gatewayv1.ListenerEntryStatus
	if parentGW != nil && IsListenerSetAllowed(ls, parentGW, namespaces) {
		for _, l := range ls.Spec.Listeners {
			var matchedEl *EffectiveListener
			if compiledGw != nil {
				for _, el := range compiledGw.EffectiveListeners {
					if el.Owner.Kind == "ListenerSet" && el.Owner.Namespace == ls.Namespace && el.Owner.Name == ls.Name && el.Name == l.Name {
						matchedEl = el
						break
					}
				}
			}

			if matchedEl == nil {
				continue
			}

			supportedKinds := matchedEl.SupportedKinds
			attachedRoutes := matchedEl.AttachedRoutes
			conds := make([]metav1.Condition, len(matchedEl.Conditions))
			copy(conds, matchedEl.Conditions)

			desiredListeners = append(desiredListeners, gatewayv1.ListenerEntryStatus{
				Name:           l.Name,
				SupportedKinds: supportedKinds,
				AttachedRoutes: attachedRoutes,
				Conditions:     conds,
			})
		}
	}

	return gatewayv1.ListenerSetStatus{
		Conditions: desiredConditions,
		Listeners:  desiredListeners,
	}
}

// isRoutePartiallyInvalid returns true when a route contains at least one valid and at least one invalid rule.
func isRoutePartiallyInvalid(rules []InternalRule) bool {
	var valid, invalid int
	for _, r := range rules {
		if r.Error != nil {
			invalid++
		} else {
			valid++
		}
	}
	return valid > 0 && invalid > 0
}

// routePartiallyInvalidMessage returns a spec-compliant condition message starting with "Dropped Rule".
func routePartiallyInvalidMessage(rules []InternalRule) string {
	var dropped []string
	for i, r := range rules {
		if r.Error != nil {
			if r.Name != nil && *r.Name != "" {
				dropped = append(dropped, fmt.Sprintf("rule %d (%s)", i, *r.Name))
			} else {
				dropped = append(dropped, fmt.Sprintf("rule %d", i))
			}
		}
	}
	return fmt.Sprintf("Dropped Rule(s): %s", strings.Join(dropped, ", "))
}

// routePartiallyInvalidCondition returns a PartiallyInvalid condition if the rules are partially invalid, or nil otherwise.
func routePartiallyInvalidCondition(rules []InternalRule, generation int64) *metav1.Condition {
	if !isRoutePartiallyInvalid(rules) {
		return nil
	}
	cond := NewCondition(
		string(gatewayv1.RouteConditionPartiallyInvalid),
		metav1.ConditionTrue,
		string(gatewayv1.RouteReasonUnsupportedValue),
		routePartiallyInvalidMessage(rules),
		generation,
	)
	return &cond
}

// computeDesiredRouteParentStatuses computes desired RouteParentStatus entries for route parents.
func computeDesiredRouteParentStatuses(
	parentRefs []gatewayv1.ParentReference,
	parentConditions []metav1.Condition,
	resolvedRefsCond metav1.Condition,
	controllerName string,
	generation int64,
	partiallyInvalidCond *metav1.Condition,
) []gatewayv1.RouteParentStatus {
	var desiredParents []gatewayv1.RouteParentStatus
	for i, parentRef := range parentRefs {
		cond := NewCondition(string(gatewayv1.RouteConditionAccepted), metav1.ConditionFalse, string(gatewayv1.RouteReasonNoMatchingParent), "Parent not found", generation)
		if i < len(parentConditions) {
			cond = parentConditions[i]
		}
		conditions := []metav1.Condition{
			cond,
			resolvedRefsCond,
		}
		if cond.Status == metav1.ConditionTrue && partiallyInvalidCond != nil {
			conditions = append(conditions, *partiallyInvalidCond)
		}
		desiredParents = append(desiredParents, gatewayv1.RouteParentStatus{
			ParentRef:      parentRef,
			ControllerName: gatewayv1.GatewayController(controllerName),
			Conditions:     conditions,
		})
	}
	return desiredParents
}

// ComputeDesiredHTTPRouteStatus computes the desired HTTPRouteStatus from the compiled model.
func ComputeDesiredHTTPRouteStatus(route *gatewayv1.HTTPRoute, compiledRoute *CompiledRoute, controllerName string) gatewayv1.HTTPRouteStatus {
	if route == nil || compiledRoute == nil || len(route.Spec.ParentRefs) == 0 {
		return gatewayv1.HTTPRouteStatus{}
	}
	var partiallyInvalid *metav1.Condition
	if compiledRoute.RouteState != nil && compiledRoute.RouteState.Internal != nil {
		partiallyInvalid = routePartiallyInvalidCondition(compiledRoute.RouteState.Internal.Rules, route.Generation)
	}
	return gatewayv1.HTTPRouteStatus{
		Parents: computeDesiredRouteParentStatuses(
			route.Spec.ParentRefs, compiledRoute.ParentConditions,
			compiledRoute.RouteState.Internal.ResolvedRefsCondition,
			controllerName, route.Generation, partiallyInvalid,
		),
	}
}

// ComputeDesiredTLSRouteStatus computes the desired TLSRouteStatus from the compiled model.
func ComputeDesiredTLSRouteStatus(route *gatewayv1.TLSRoute, compiledRoute *CompiledTLSRoute, controllerName string) gatewayv1.TLSRouteStatus {
	if route == nil || compiledRoute == nil || len(route.Spec.ParentRefs) == 0 {
		return gatewayv1.TLSRouteStatus{}
	}
	return gatewayv1.TLSRouteStatus{
		RouteStatus: gatewayv1.RouteStatus{
			Parents: computeDesiredRouteParentStatuses(
				route.Spec.ParentRefs, compiledRoute.ParentConditions,
				compiledRoute.RouteState.Internal.ResolvedRefsCondition,
				controllerName, route.Generation, nil,
			),
		},
	}
}

// ComputeDesiredGRPCRouteStatus computes the desired GRPCRouteStatus from the compiled model.
func ComputeDesiredGRPCRouteStatus(route *gatewayv1.GRPCRoute, compiledRoute *CompiledGRPCRoute, controllerName string) gatewayv1.GRPCRouteStatus {
	if route == nil || compiledRoute == nil || len(route.Spec.ParentRefs) == 0 {
		return gatewayv1.GRPCRouteStatus{}
	}
	var partiallyInvalid *metav1.Condition
	if compiledRoute.RouteState != nil && compiledRoute.RouteState.Internal != nil {
		partiallyInvalid = routePartiallyInvalidCondition(compiledRoute.RouteState.Internal.Rules, route.Generation)
	}
	return gatewayv1.GRPCRouteStatus{
		RouteStatus: gatewayv1.RouteStatus{
			Parents: computeDesiredRouteParentStatuses(
				route.Spec.ParentRefs, compiledRoute.ParentConditions,
				compiledRoute.RouteState.Internal.ResolvedRefsCondition,
				controllerName, route.Generation, partiallyInvalid,
			),
		},
	}
}

// ComputeDesiredTCPRouteStatus computes the desired TCPRouteStatus from the compiled model.
func ComputeDesiredTCPRouteStatus(route *gatewayv1.TCPRoute, compiledRoute *CompiledTCPRoute, controllerName string) gatewayv1.TCPRouteStatus {
	if route == nil || compiledRoute == nil || len(route.Spec.ParentRefs) == 0 {
		return gatewayv1.TCPRouteStatus{}
	}
	return gatewayv1.TCPRouteStatus{
		RouteStatus: gatewayv1.RouteStatus{
			Parents: computeDesiredRouteParentStatuses(
				route.Spec.ParentRefs, compiledRoute.ParentConditions,
				compiledRoute.RouteState.Internal.ResolvedRefsCondition,
				controllerName, route.Generation, nil,
			),
		},
	}
}

// ComputeDesiredUDPRouteStatus computes the desired UDPRouteStatus from the compiled model.
func ComputeDesiredUDPRouteStatus(route *gatewayv1.UDPRoute, compiledRoute *CompiledUDPRoute, controllerName string) gatewayv1.UDPRouteStatus {
	if route == nil || compiledRoute == nil || len(route.Spec.ParentRefs) == 0 {
		return gatewayv1.UDPRouteStatus{}
	}
	return gatewayv1.UDPRouteStatus{
		RouteStatus: gatewayv1.RouteStatus{
			Parents: computeDesiredRouteParentStatuses(
				route.Spec.ParentRefs, compiledRoute.ParentConditions,
				compiledRoute.RouteState.Internal.ResolvedRefsCondition,
				controllerName, route.Generation, nil,
			),
		},
	}
}

type backendTLSPolicyRouteTarget struct {
	namespace        string
	parentRefs       []gatewayv1.ParentReference
	parentConditions []metav1.Condition
	backendRefs      []gatewayv1.BackendObjectReference
	isTLSRoute       bool
	boundListeners   []*EffectiveListener
}

func collectBackendTLSPolicyRouteTargets(compiled *CompiledModel) []backendTLSPolicyRouteTarget {
	if compiled == nil {
		return nil
	}
	var targets []backendTLSPolicyRouteTarget

	for _, cr := range compiled.HTTPRoutes {
		if cr == nil || cr.HTTPRoute == nil {
			continue
		}
		var backendRefs []gatewayv1.BackendObjectReference
		for _, rule := range cr.HTTPRoute.Spec.Rules {
			for _, b := range rule.BackendRefs {
				backendRefs = append(backendRefs, b.BackendObjectReference)
			}
		}
		targets = append(targets, backendTLSPolicyRouteTarget{
			namespace:        cr.HTTPRoute.Namespace,
			parentRefs:       cr.HTTPRoute.Spec.ParentRefs,
			parentConditions: cr.ParentConditions,
			backendRefs:      backendRefs,
		})
	}

	for _, cr := range compiled.GRPCRoutes {
		if cr == nil || cr.GRPCRoute == nil {
			continue
		}
		var backendRefs []gatewayv1.BackendObjectReference
		for _, rule := range cr.GRPCRoute.Spec.Rules {
			for _, b := range rule.BackendRefs {
				backendRefs = append(backendRefs, b.BackendObjectReference)
			}
		}
		targets = append(targets, backendTLSPolicyRouteTarget{
			namespace:        cr.GRPCRoute.Namespace,
			parentRefs:       cr.GRPCRoute.Spec.ParentRefs,
			parentConditions: cr.ParentConditions,
			backendRefs:      backendRefs,
		})
	}

	for _, cr := range compiled.TLSRoutes {
		if cr == nil || cr.TLSRoute == nil {
			continue
		}
		var backendRefs []gatewayv1.BackendObjectReference
		for _, rule := range cr.TLSRoute.Spec.Rules {
			for _, b := range rule.BackendRefs {
				backendRefs = append(backendRefs, b.BackendObjectReference)
			}
		}
		targets = append(targets, backendTLSPolicyRouteTarget{
			namespace:        cr.TLSRoute.Namespace,
			parentRefs:       cr.TLSRoute.Spec.ParentRefs,
			parentConditions: cr.ParentConditions,
			backendRefs:      backendRefs,
			isTLSRoute:       true,
			boundListeners:   cr.BoundListeners,
		})
	}

	return targets
}

func hasBoundTLSTerminateListener(boundListeners []*EffectiveListener, cg *CompiledGateway) bool {
	if cg == nil || len(boundListeners) == 0 {
		return false
	}
	for _, listener := range cg.EffectiveListeners {
		if listener.Protocol == gatewayv1.TLSProtocolType && listener.TLS != nil && (listener.TLS.Mode == nil || *listener.TLS.Mode == gatewayv1.TLSModeTerminate) {
			for _, boundListener := range boundListeners {
				if boundListener == listener {
					return true
				}
			}
		}
	}
	return false
}

// ComputeDesiredBackendTLSPolicyStatus computes the desired BackendTLSPolicy PolicyStatus.
func ComputeDesiredBackendTLSPolicyStatus(
	policy *gatewayv1.BackendTLSPolicy,
	compiled *CompiledModel,
	configMaps map[types.NamespacedName]*corev1.ConfigMap,
	allPolicies []*gatewayv1.BackendTLSPolicy,
	controllerName string,
) gatewayv1.PolicyStatus {
	isConflicted := false
	var conflictingPolicy string
	for _, targetRef := range policy.Spec.TargetRefs {
		if string(targetRef.Group) != "" {
			continue
		}
		if string(targetRef.Kind) != "Service" {
			continue
		}

		targetSvcNamespace := policy.Namespace
		targetSvcName := string(targetRef.Name)
		targetSection := ValueOf(targetRef.SectionName)

		for _, p := range allPolicies {
			if p == nil || (p.Namespace == policy.Namespace && p.Name == policy.Name) {
				continue
			}

			for _, t := range p.Spec.TargetRefs {
				if string(t.Group) == "" && string(t.Kind) == "Service" {
					if p.Namespace == targetSvcNamespace && string(t.Name) == targetSvcName && ValueOf(t.SectionName) == targetSection {
						if p.CreationTimestamp.Time.Before(policy.CreationTimestamp.Time) {
							isConflicted = true
							conflictingPolicy = fmt.Sprintf("%s/%s", p.Namespace, p.Name)
							break
						}
						if p.CreationTimestamp.Time.Equal(policy.CreationTimestamp.Time) {
							if p.Namespace < policy.Namespace || (p.Namespace == policy.Namespace && p.Name < policy.Name) {
								isConflicted = true
								conflictingPolicy = fmt.Sprintf("%s/%s", p.Namespace, p.Name)
								break
							}
						}
					}
				}
			}
			if isConflicted {
				break
			}
		}
		if isConflicted {
			break
		}
	}

	var unresolvedRefs []string
	hasInvalidKind := false
	hasInvalidCACertRef := false

	if policy.Spec.Validation.WellKnownCACertificates != nil {
		if *policy.Spec.Validation.WellKnownCACertificates != gatewayv1.WellKnownCACertificatesSystem {
			hasInvalidKind = true
			unresolvedRefs = append(unresolvedRefs, string(*policy.Spec.Validation.WellKnownCACertificates))
		}
	} else {
		for _, caRef := range policy.Spec.Validation.CACertificateRefs {
			if string(caRef.Group) != "" || string(caRef.Kind) != "ConfigMap" {
				unresolvedRefs = append(unresolvedRefs, string(caRef.Name))
				hasInvalidKind = true
			} else {
				cmKey := types.NamespacedName{Namespace: policy.Namespace, Name: string(caRef.Name)}
				cm, ok := configMaps[cmKey]
				if !ok || cm == nil {
					unresolvedRefs = append(unresolvedRefs, string(caRef.Name))
					hasInvalidCACertRef = true
				} else {
					if _, err := ExtractCACertFromConfigMap(cm); err != nil {
						unresolvedRefs = append(unresolvedRefs, string(caRef.Name))
						hasInvalidCACertRef = true
					}
				}
			}
		}
	}

	acceptedStatus := metav1.ConditionTrue
	acceptedReason := string(gatewayv1.PolicyReasonAccepted)
	acceptedMessage := "Policy accepted"

	resolvedRefsStatus := metav1.ConditionTrue
	resolvedRefsReason := string(gatewayv1.BackendTLSPolicyReasonResolvedRefs)
	resolvedRefsMessage := "All references resolved"

	if hasInvalidKind || hasInvalidCACertRef {
		acceptedStatus = metav1.ConditionFalse
		acceptedReason = string(gatewayv1.BackendTLSPolicyReasonNoValidCACertificate)
		acceptedMessage = fmt.Sprintf("Unresolved or invalid CA certificate references: %v", unresolvedRefs)

		resolvedRefsStatus = metav1.ConditionFalse
		if hasInvalidKind {
			resolvedRefsReason = string(gatewayv1.BackendTLSPolicyReasonInvalidKind)
			resolvedRefsMessage = fmt.Sprintf("Unsupported or unknown CA certificate reference kind: %v", unresolvedRefs)
		} else {
			resolvedRefsReason = string(gatewayv1.BackendTLSPolicyReasonInvalidCACertificateRef)
			resolvedRefsMessage = fmt.Sprintf("Unresolved or invalid CA certificate references: %v", unresolvedRefs)
		}
	}

	if isConflicted {
		acceptedStatus = metav1.ConditionFalse
		acceptedReason = string(gatewayv1.PolicyReasonConflicted)
		acceptedMessage = fmt.Sprintf("Conflicted with older policy: %s", conflictingPolicy)
	}

	var ancestors []gatewayv1.PolicyAncestorStatus

	if compiled != nil {
		routes := collectBackendTLSPolicyRouteTargets(compiled)
		for _, cg := range compiled.Gateways {
			if cg == nil || cg.Gateway == nil {
				continue
			}
			gw := cg.Gateway

			usesPolicy := false
			for _, route := range routes {
				routeMatchesGw := false
				for i, pref := range route.parentRefs {
					if string(pref.Name) == gw.Name && (ValueOf(pref.Namespace) == "" || string(ValueOf(pref.Namespace)) == gw.Namespace) {
						if i < len(route.parentConditions) && route.parentConditions[i].Status == metav1.ConditionTrue {
							if route.isTLSRoute && !hasBoundTLSTerminateListener(route.boundListeners, cg) {
								continue
							}
							routeMatchesGw = true
							break
						}
					}
				}

				if routeMatchesGw {
					for _, backendRef := range route.backendRefs {
						if string(ValueOf(backendRef.Kind)) == "Service" || ValueOf(backendRef.Kind) == "" {
							svcNs := route.namespace
							if backendRef.Namespace != nil && string(*backendRef.Namespace) != "" {
								svcNs = string(*backendRef.Namespace)
							}
							for _, targetRef := range policy.Spec.TargetRefs {
								if string(targetRef.Group) == "" && string(targetRef.Kind) == "Service" &&
									svcNs == policy.Namespace && string(backendRef.Name) == string(targetRef.Name) {
									usesPolicy = true
									break
								}
							}
						}
						if usesPolicy {
							break
						}
					}
				}
				if usesPolicy {
					break
				}
			}

			if usesPolicy {
				ancestors = append(ancestors, gatewayv1.PolicyAncestorStatus{
					AncestorRef: gatewayv1.ParentReference{
						Group:     Ptr(gatewayv1.Group(gatewayv1.GroupName)),
						Kind:      Ptr(gatewayv1.Kind("Gateway")),
						Namespace: Ptr(gatewayv1.Namespace(gw.Namespace)),
						Name:      gatewayv1.ObjectName(gw.Name),
					},
					ControllerName: gatewayv1.GatewayController(controllerName),
					Conditions: []metav1.Condition{
						{
							Type:               string(gatewayv1.PolicyConditionAccepted),
							Status:             acceptedStatus,
							ObservedGeneration: policy.Generation,
							Reason:             acceptedReason,
							Message:            acceptedMessage,
						},
						{
							Type:               string(gatewayv1.BackendTLSPolicyConditionResolvedRefs),
							Status:             resolvedRefsStatus,
							ObservedGeneration: policy.Generation,
							Reason:             resolvedRefsReason,
							Message:            resolvedRefsMessage,
						},
					},
				})
			}
		}
	}

	sort.Slice(ancestors, func(i, j int) bool {
		return CompareParentReference(ancestors[i].AncestorRef, ancestors[j].AncestorRef, policy.Namespace) < 0
	})

	return gatewayv1.PolicyStatus{Ancestors: ancestors}
}

// isSupportedBundleVersion returns true if bundleVersion has the same major version as the
// compiled-in Gateway API bundle version, has minor version N or N-1 (where N is the compiled
// minor version), is valid semver, and is not a pre-release.
func isSupportedBundleVersion(bundleVersion string) bool {
	compiledV, err := version.ParseSemantic(gatewayconsts.BundleVersion)
	if err != nil {
		return bundleVersion == gatewayconsts.BundleVersion
	}
	bundleV, err := version.ParseSemantic(bundleVersion)
	if err != nil {
		return false
	}
	if bundleV.PreRelease() != "" {
		return false
	}
	if bundleV.Major() != compiledV.Major() {
		return false
	}
	return bundleV.Minor() == compiledV.Minor() || (compiledV.Minor() > 0 && bundleV.Minor() == compiledV.Minor()-1)
}

// unsupportedBundleVersionMessage returns the condition message for an unsupported bundle version,
// deriving the supported minor range from compiledVersion.
// If compiledVersion cannot be parsed, it falls back to naming compiledVersion directly.
func unsupportedBundleVersionMessage(bundleVersion, compiledVersion string) string {
	compiledV, err := version.ParseSemantic(compiledVersion)
	if err != nil {
		return fmt.Sprintf("Gateway API CRD bundle-version %q is not supported (controller supports %s)", bundleVersion, compiledVersion)
	}
	if compiledV.Minor() == 0 {
		return fmt.Sprintf("Gateway API CRD bundle-version %q is not supported (controller supports v%d.%d.x, built against %s)", bundleVersion, compiledV.Major(), compiledV.Minor(), compiledVersion)
	}
	return fmt.Sprintf("Gateway API CRD bundle-version %q is not supported (controller supports v%d.%d.x and v%d.%d.x, built against %s)", bundleVersion, compiledV.Major(), compiledV.Minor()-1, compiledV.Major(), compiledV.Minor(), compiledVersion)
}

// ComputeSupportedVersionCondition computes the SupportedVersion condition for a GatewayClass given a bundle version.
func ComputeSupportedVersionCondition(bundleVersion string, generation int64) metav1.Condition {
	if isSupportedBundleVersion(bundleVersion) {
		return NewCondition(
			string(gatewayv1.GatewayClassConditionStatusSupportedVersion),
			metav1.ConditionTrue,
			string(gatewayv1.GatewayClassReasonSupportedVersion),
			fmt.Sprintf("Gateway API CRD bundle-version %q is supported", bundleVersion),
			generation,
		)
	}
	return NewCondition(
		string(gatewayv1.GatewayClassConditionStatusSupportedVersion),
		metav1.ConditionFalse,
		string(gatewayv1.GatewayClassReasonUnsupportedVersion),
		unsupportedBundleVersionMessage(bundleVersion, gatewayconsts.BundleVersion),
		generation,
	)
}

// ComputeDesiredGatewayClassStatus computes the desired GatewayClass status.
func ComputeDesiredGatewayClassStatus(gc *gatewayv1.GatewayClass, controllerName string, crdBundleVersion *string, configMaps ...map[types.NamespacedName]*corev1.ConfigMap) gatewayv1.GatewayClassStatus {
	acceptedStatus := metav1.ConditionTrue
	acceptedReason := string(gatewayv1.GatewayClassReasonAccepted)
	acceptedMessage := "GatewayClass accepted by reference implementation"

	if gc.Spec.ParametersRef != nil {
		var cms map[types.NamespacedName]*corev1.ConfigMap
		if len(configMaps) > 0 {
			cms = configMaps[0]
		}
		_, err := ValidateGatewayClassParametersRef(gc.Spec.ParametersRef, cms)
		if err != nil {
			acceptedStatus = metav1.ConditionFalse
			acceptedReason = string(gatewayv1.GatewayClassReasonInvalidParameters)
			acceptedMessage = fmt.Sprintf("Invalid parametersRef: %v", err)
		}
	}

	conds := []metav1.Condition{
		{
			Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
			Status:             acceptedStatus,
			ObservedGeneration: gc.Generation,
			Reason:             acceptedReason,
			Message:            acceptedMessage,
		},
	}

	if crdBundleVersion != nil && *crdBundleVersion != "" {
		conds = append(conds, ComputeSupportedVersionCondition(*crdBundleVersion, gc.Generation))
	}

	var supportedFeatures []gatewayv1.SupportedFeature
	if acceptedStatus == metav1.ConditionTrue {
		supportedFeatures = GatewayClassSupportedFeatures()
	}

	return gatewayv1.GatewayClassStatus{
		Conditions:        conds,
		SupportedFeatures: supportedFeatures,
	}
}

// MergeGatewayStatus merges desired GatewayStatus into current, preserving LastTransitionTime and foreign conditions.
func MergeGatewayStatus(current *gatewayv1.GatewayStatus, desired gatewayv1.GatewayStatus) bool {
	updated := false
	if MergeConditions(&current.Conditions, desired.Conditions, GatewayOwnedConditionTypes) {
		updated = true
	}
	if !reflectAddressesEqual(current.Addresses, desired.Addresses) {
		current.Addresses = desired.Addresses
		updated = true
	}
	if (current.AttachedListenerSets == nil && desired.AttachedListenerSets != nil) ||
		(current.AttachedListenerSets != nil && desired.AttachedListenerSets == nil) ||
		(current.AttachedListenerSets != nil && desired.AttachedListenerSets != nil && *current.AttachedListenerSets != *desired.AttachedListenerSets) {
		current.AttachedListenerSets = desired.AttachedListenerSets
		updated = true
	}

	var newListeners []gatewayv1.ListenerStatus
	for _, dl := range desired.Listeners {
		var entryConditions []metav1.Condition
		for _, ol := range current.Listeners {
			if ol.Name == dl.Name {
				entryConditions = slices.Clone(ol.Conditions)
				break
			}
		}
		MergeConditions(&entryConditions, dl.Conditions, ListenerOwnedConditionTypes)

		entry := gatewayv1.ListenerStatus{
			Name:           dl.Name,
			SupportedKinds: dl.SupportedKinds,
			AttachedRoutes: dl.AttachedRoutes,
			Conditions:     entryConditions,
		}
		newListeners = append(newListeners, entry)
	}
	if !reflectListenerStatusesEqual(current.Listeners, newListeners) {
		current.Listeners = newListeners
		updated = true
	}
	return updated
}

// MergeListenerSetStatus merges desired ListenerSetStatus into current, preserving LastTransitionTime.
func MergeListenerSetStatus(current *gatewayv1.ListenerSetStatus, desired gatewayv1.ListenerSetStatus) bool {
	updated := false
	if SetConditions(&current.Conditions, desired.Conditions) {
		updated = true
	}
	var newListeners []gatewayv1.ListenerEntryStatus
	for _, dl := range desired.Listeners {
		entry := gatewayv1.ListenerEntryStatus{
			Name:           dl.Name,
			SupportedKinds: dl.SupportedKinds,
			AttachedRoutes: dl.AttachedRoutes,
			Conditions:     make([]metav1.Condition, len(dl.Conditions)),
		}
		copy(entry.Conditions, dl.Conditions)

		var matchedOld *gatewayv1.ListenerEntryStatus
		for _, ol := range current.Listeners {
			if ol.Name == dl.Name {
				matchedOld = &ol
				break
			}
		}
		if matchedOld != nil {
			for k, dc := range entry.Conditions {
				for _, oc := range matchedOld.Conditions {
					if oc.Type == dc.Type {
						if oc.Status == dc.Status {
							entry.Conditions[k].LastTransitionTime = oc.LastTransitionTime
						}
						break
					}
				}
			}
		}
		for k := range entry.Conditions {
			if entry.Conditions[k].LastTransitionTime.IsZero() {
				entry.Conditions[k].LastTransitionTime = metav1.Now()
			}
		}
		newListeners = append(newListeners, entry)
	}
	if !reflectListenerEntryStatusesEqual(current.Listeners, newListeners) {
		current.Listeners = newListeners
		updated = true
	}
	return updated
}

// mergeRouteParentStatuses merges desired RouteParentStatus slice into current, preserving LastTransitionTime and other controllers' parents.
// It returns true if semantic changes occurred that require updating status in the API server.
func mergeRouteParentStatuses(current *[]gatewayv1.RouteParentStatus, desired []gatewayv1.RouteParentStatus, routeNamespace string, controllerName gatewayv1.GatewayController) bool {
	newParents, updated := UpdateRouteParentStatuses(*current, desired, routeNamespace, controllerName)
	*current = newParents
	return updated
}

// MergeHTTPRouteStatus merges desired HTTPRouteStatus into current, preserving LastTransitionTime and other controllers' parents.
// It returns true if semantic changes occurred that require updating status in the API server.
func MergeHTTPRouteStatus(current *gatewayv1.HTTPRouteStatus, desired gatewayv1.HTTPRouteStatus, routeNamespace string, controllerName gatewayv1.GatewayController) bool {
	return mergeRouteParentStatuses(&current.Parents, desired.Parents, routeNamespace, controllerName)
}

// MergeTLSRouteStatus merges desired TLSRouteStatus into current, preserving LastTransitionTime and other controllers' parents.
// It returns true if semantic changes occurred that require updating status in the API server.
func MergeTLSRouteStatus(current *gatewayv1.TLSRouteStatus, desired gatewayv1.TLSRouteStatus, routeNamespace string, controllerName gatewayv1.GatewayController) bool {
	return mergeRouteParentStatuses(&current.Parents, desired.Parents, routeNamespace, controllerName)
}

// MergeGRPCRouteStatus merges desired GRPCRouteStatus into current, preserving LastTransitionTime and other controllers' parents.
// It returns true if semantic changes occurred that require updating status in the API server.
func MergeGRPCRouteStatus(current *gatewayv1.GRPCRouteStatus, desired gatewayv1.GRPCRouteStatus, routeNamespace string, controllerName gatewayv1.GatewayController) bool {
	return mergeRouteParentStatuses(&current.Parents, desired.Parents, routeNamespace, controllerName)
}

// MergeTCPRouteStatus merges desired TCPRouteStatus into current, preserving LastTransitionTime and other controllers' parents.
// It returns true if semantic changes occurred that require updating status in the API server.
func MergeTCPRouteStatus(current *gatewayv1.TCPRouteStatus, desired gatewayv1.TCPRouteStatus, routeNamespace string, controllerName gatewayv1.GatewayController) bool {
	return mergeRouteParentStatuses(&current.Parents, desired.Parents, routeNamespace, controllerName)
}

// MergeUDPRouteStatus merges desired UDPRouteStatus into current, preserving LastTransitionTime and other controllers' parents.
// It returns true if semantic changes occurred that require updating status in the API server.
func MergeUDPRouteStatus(current *gatewayv1.UDPRouteStatus, desired gatewayv1.UDPRouteStatus, routeNamespace string, controllerName gatewayv1.GatewayController) bool {
	return mergeRouteParentStatuses(&current.Parents, desired.Parents, routeNamespace, controllerName)
}

// MergeBackendTLSPolicyStatus merges desired PolicyStatus into current, preserving LastTransitionTime and other controllers' ancestors.
func MergeBackendTLSPolicyStatus(current *gatewayv1.PolicyStatus, desired gatewayv1.PolicyStatus, controllerName gatewayv1.GatewayController) bool {
	newAncestors, updated := UpdatePolicyAncestors(current.Ancestors, desired.Ancestors, controllerName)
	if updated {
		current.Ancestors = newAncestors
	}
	return updated
}

// MergeGatewayClassStatus merges desired GatewayClassStatus into current, preserving LastTransitionTime.
func MergeGatewayClassStatus(current *gatewayv1.GatewayClassStatus, desired gatewayv1.GatewayClassStatus) bool {
	updated := SetConditions(&current.Conditions, desired.Conditions)
	if !slices.Equal(current.SupportedFeatures, desired.SupportedFeatures) {
		current.SupportedFeatures = slices.Clone(desired.SupportedFeatures)
		updated = true
	}
	return updated
}

// GatewayStatusesEqual compares two GatewayStatus objects (ignoring LastTransitionTime).
func GatewayStatusesEqual(a, b gatewayv1.GatewayStatus) bool {
	if !ConditionsEqual(a.Conditions, b.Conditions) {
		return false
	}
	if !reflectAddressesEqual(a.Addresses, b.Addresses) {
		return false
	}
	if (a.AttachedListenerSets == nil) != (b.AttachedListenerSets == nil) {
		return false
	}
	if a.AttachedListenerSets != nil && b.AttachedListenerSets != nil && *a.AttachedListenerSets != *b.AttachedListenerSets {
		return false
	}
	return reflectListenerStatusesEqual(a.Listeners, b.Listeners)
}

// routeParentStatusesEqual compares two slices of RouteParentStatus (ignoring LastTransitionTime).
func routeParentStatusesEqual(a, b []gatewayv1.RouteParentStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !reflectParentReferenceEqual(a[i].ParentRef, b[i].ParentRef) ||
			a[i].ControllerName != b[i].ControllerName ||
			!ConditionsEqual(a[i].Conditions, b[i].Conditions) {
			return false
		}
	}
	return true
}

// HTTPRouteStatusesEqual compares two HTTPRouteStatus objects (ignoring LastTransitionTime).
func HTTPRouteStatusesEqual(a, b gatewayv1.HTTPRouteStatus) bool {
	return routeParentStatusesEqual(a.Parents, b.Parents)
}

// TLSRouteStatusesEqual compares two TLSRouteStatus objects (ignoring LastTransitionTime).
func TLSRouteStatusesEqual(a, b gatewayv1.TLSRouteStatus) bool {
	return routeParentStatusesEqual(a.Parents, b.Parents)
}

// GRPCRouteStatusesEqual compares two GRPCRouteStatus objects (ignoring LastTransitionTime).
func GRPCRouteStatusesEqual(a, b gatewayv1.GRPCRouteStatus) bool {
	return routeParentStatusesEqual(a.Parents, b.Parents)
}

// TCPRouteStatusesEqual compares two TCPRouteStatus objects (ignoring LastTransitionTime).
func TCPRouteStatusesEqual(a, b gatewayv1.TCPRouteStatus) bool {
	return routeParentStatusesEqual(a.Parents, b.Parents)
}

// UDPRouteStatusesEqual compares two UDPRouteStatus objects (ignoring LastTransitionTime).
func UDPRouteStatusesEqual(a, b gatewayv1.UDPRouteStatus) bool {
	return routeParentStatusesEqual(a.Parents, b.Parents)
}

// ListenerSetStatusesEqual compares two ListenerSetStatus objects (ignoring LastTransitionTime).
func ListenerSetStatusesEqual(a, b gatewayv1.ListenerSetStatus) bool {
	if !ConditionsEqual(a.Conditions, b.Conditions) {
		return false
	}
	return reflectListenerEntryStatusesEqual(a.Listeners, b.Listeners)
}

// PolicyStatusesEqual compares two PolicyStatus objects (ignoring LastTransitionTime).
func PolicyStatusesEqual(a, b gatewayv1.PolicyStatus) bool {
	if len(a.Ancestors) != len(b.Ancestors) {
		return false
	}
	for i := range a.Ancestors {
		if !reflectParentReferenceEqual(a.Ancestors[i].AncestorRef, b.Ancestors[i].AncestorRef) ||
			a.Ancestors[i].ControllerName != b.Ancestors[i].ControllerName ||
			!ConditionsEqual(a.Ancestors[i].Conditions, b.Ancestors[i].Conditions) {
			return false
		}
	}
	return true
}

// GatewayClassStatusesEqual compares two GatewayClassStatus objects (ignoring LastTransitionTime).
func GatewayClassStatusesEqual(a, b gatewayv1.GatewayClassStatus) bool {
	if !ConditionsEqual(a.Conditions, b.Conditions) {
		return false
	}
	return slices.Equal(a.SupportedFeatures, b.SupportedFeatures)
}

func reflectAddressesEqual(a, b []gatewayv1.GatewayStatusAddress) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Value != b[i].Value || ValueOf(a[i].Type) != ValueOf(b[i].Type) {
			return false
		}
	}
	return true
}

func reflectListenerStatusesEqual(a, b []gatewayv1.ListenerStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].AttachedRoutes != b[i].AttachedRoutes {
			return false
		}
		if len(a[i].SupportedKinds) != len(b[i].SupportedKinds) {
			return false
		}
		for j := range a[i].SupportedKinds {
			if a[i].SupportedKinds[j].Kind != b[i].SupportedKinds[j].Kind || ValueOf(a[i].SupportedKinds[j].Group) != ValueOf(b[i].SupportedKinds[j].Group) {
				return false
			}
		}
		if !ConditionsEqual(a[i].Conditions, b[i].Conditions) {
			return false
		}
	}
	return true
}

func reflectListenerEntryStatusesEqual(a, b []gatewayv1.ListenerEntryStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].AttachedRoutes != b[i].AttachedRoutes {
			return false
		}
		if len(a[i].SupportedKinds) != len(b[i].SupportedKinds) {
			return false
		}
		for j := range a[i].SupportedKinds {
			if a[i].SupportedKinds[j].Kind != b[i].SupportedKinds[j].Kind || ValueOf(a[i].SupportedKinds[j].Group) != ValueOf(b[i].SupportedKinds[j].Group) {
				return false
			}
		}
		if !ConditionsEqual(a[i].Conditions, b[i].Conditions) {
			return false
		}
	}
	return true
}

// CompileModel on State compiles the state snapshot into a CompiledModel.
func (s *State) CompileModel(controllerName string) *CompiledModel {
	gatewaysMap := s.GetGateways()
	var gateways []*gatewayv1.Gateway
	for _, gwState := range gatewaysMap {
		if gwState != nil && gwState.Gateway != nil {
			gateways = append(gateways, gwState.Gateway)
		}
	}
	sort.Slice(gateways, func(i, j int) bool {
		if gateways[i].Namespace != gateways[j].Namespace {
			return gateways[i].Namespace < gateways[j].Namespace
		}
		return gateways[i].Name < gateways[j].Name
	})

	listenerSetsList := s.GetListenerSets()
	var listenerSets []*gatewayv1.ListenerSet
	for _, lsState := range listenerSetsList {
		if lsState != nil && lsState.ListenerSet != nil {
			listenerSets = append(listenerSets, lsState.ListenerSet)
		}
	}

	routesList := s.GetHTTPRoutes()
	var routes []*gatewayv1.HTTPRoute
	for _, rState := range routesList {
		if rState != nil && rState.HTTPRoute != nil {
			routes = append(routes, rState.HTTPRoute)
		}
	}

	var backendTLSPolicies []*gatewayv1.BackendTLSPolicy
	for _, b := range s.GetBackendTLSPolicies() {
		if b != nil {
			backendTLSPolicies = append(backendTLSPolicies, b)
		}
	}

	var gatewayClasses []*gatewayv1.GatewayClass
	for _, gc := range s.GetGatewayClasses() {
		if gc != nil {
			gatewayClasses = append(gatewayClasses, gc)
		}
	}

	return CompileModel(ModelInputs{
		Revision:           s.Revision(),
		Gateways:           gateways,
		GatewayClasses:     gatewayClasses,
		GatewayAddresses:   s.GetGatewayAddresses(),
		ListenerSets:       listenerSets,
		HTTPRoutes:         routes,
		Services:           s.GetServices(),
		BackendTLSPolicies: backendTLSPolicies,
		ConfigMaps:         s.GetConfigMaps(),
		Secrets:            s.GetSecrets(),
		Namespaces:         s.GetNamespaces(),
		ReferenceGrants:    nil,
		RefValidator:       s,
		ControllerName:     controllerName,
	})
}

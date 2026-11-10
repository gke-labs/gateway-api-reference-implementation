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

package gari

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxyproto"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

var setupLog = ctrl.Log.WithName("gari")

// AddressProvider returns the addresses to report in Gateway.status.addresses.
// An empty result means the address is not assigned yet.
type AddressProvider = controller.AddressProvider

// AddressWatcher is an optional interface an AddressProvider can implement
// to register custom watches with the Gateway controller.
type AddressWatcher = controller.AddressWatcher

// AddressReadinessProvider is an optional interface an AddressProvider can implement
// to report addresses and detailed readiness state in a single call.
type AddressReadinessProvider = controller.AddressReadinessProvider

// AddressTypeProvider is an optional interface an AddressProvider can implement
// to declare which address types it supports for requested addresses (spec.addresses).
type AddressTypeProvider = controller.AddressTypeProvider

// GatewayStatusHook is an optional hook called by GARI's Gateway reconciler after computing
// the desired status and before writing it to the API server.
type GatewayStatusHook = controller.GatewayStatusHook

// CertificateSourceOptionKey is the tls.options key used to select a certificate source for a listener.
const CertificateSourceOptionKey = controller.CertificateSourceOptionKey

// CertificateResult contains the resolved certificates and condition details for a listener.
type CertificateResult = controller.CertificateResult

// CertificateSource supplies TLS certificates for a Gateway's listeners.
// Implementations must be non-blocking and must not modify gw or listener (they are shared State objects).
type CertificateSource = controller.CertificateSource

// TriggerableCertificateSource is an optional interface that a CertificateSource can implement
// to receive a trigger callback when registered with GARI.
type TriggerableCertificateSource = controller.TriggerableCertificateSource

// SecretsCertificateSource resolves certificates from Secret references specified in listener.TLS.CertificateRefs.
type SecretsCertificateSource = controller.SecretsCertificateSource

// GatewayReadiness represents the data-plane readiness state of a Gateway.
type GatewayReadiness = state.GatewayReadiness

// DefaultScheme creates a new runtime.Scheme initialized with client-go and Gateway API schemes.
func DefaultScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.AddToScheme(scheme))
	utilruntime.Must(gatewayv1beta1.AddToScheme(scheme))
	utilruntime.Must(gatewayv1alpha2.AddToScheme(scheme))
	return scheme
}

// Options contains configuration for running GARI.
type Options struct {
	// RestConfig is the Kubernetes client REST configuration.
	// If nil and Manager is nil, ctrl.GetConfig() will be called.
	RestConfig *rest.Config

	// Scheme is the runtime.Scheme. If nil, DefaultScheme() is used.
	Scheme *runtime.Scheme

	// ControllerName is the GatewayClass controller name managed by this instance.
	// Defaults to controller.DefaultControllerName.
	ControllerName string

	// MetricsAddr is the address the metrics endpoint binds to.
	// Defaults to ":8999". Set to "0" or empty to disable metrics.
	MetricsAddr string

	// HealthProbeBindAddress is the address the health probe endpoint binds to.
	// Defaults to ":8999". If configured to the same port as MetricsAddr, health checks
	// and metrics share a single listener. Set to a separate host:port to serve health probes
	// from a separate server, or "0" to disable.
	HealthProbeBindAddress string

	// ProxyAddr is the address the HTTP proxy server binds to.
	// Defaults to ":8080". Ignored if HTTPListener is provided.
	ProxyAddr string

	// ProxyHTTPSAddr is the address the HTTPS proxy server binds to.
	// Defaults to ":8443". Ignored if HTTPSListener is provided.
	ProxyHTTPSAddr string

	// ProxyHTTP3Addr is the UDP address the HTTP/3 proxy server binds to.
	// Defaults to "" (disabled). Ignored if HTTP3PacketConn is provided.
	ProxyHTTP3Addr string

	// ProxyHTTP3AdvertisedPort is the port advertised in Alt-Svc headers on HTTPS responses.
	// If 0, the port is inferred from the HTTP/3 listener address.
	ProxyHTTP3AdvertisedPort int

	// HTTP3PacketConn is an optional custom net.PacketConn for the HTTP/3 proxy server.
	// If set, ProxyHTTP3Addr is ignored.
	HTTP3PacketConn net.PacketConn

	// HTTP3QUICConfig is an optional custom QUIC configuration for the HTTP/3 proxy server.
	HTTP3QUICConfig *quic.Config

	// EnableH2C enables HTTP/2 Cleartext (H2C) support on the HTTP proxy server.
	EnableH2C bool

	// ForwardedForMode specifies how the X-Forwarded-For header is handled: "append" or "replace".
	// Defaults to "append".
	ForwardedForMode proxy.ForwardedForMode

	// LeaderElection enables leader election for the controller manager.
	LeaderElection bool

	// LeaderElectionID is the ID used for leader election.
	// Defaults to "gateway-api-reference-implementation".
	LeaderElectionID string

	// HTTPListener is an optional custom net.Listener for the HTTP proxy server.
	// If set, ProxyAddr is ignored.
	HTTPListener net.Listener

	// HTTPSListener is an optional custom net.Listener for the HTTPS proxy server.
	// If set, ProxyHTTPSAddr is ignored.
	HTTPSListener net.Listener

	// DefaultCertificate is an optional default fallback TLS certificate for the HTTPS proxy.
	// If nil, a self-signed certificate will be automatically generated.
	DefaultCertificate *tls.Certificate

	// OnGatewaysUpdate is an optional hook invoked whenever configuration is pushed
	// to the proxy with the currently resolved Gateways.
	OnGatewaysUpdate func(gateways []*gatewayv1.Gateway)

	// AddressProvider is an optional hook that returns addresses to report in Gateway.status.addresses.
	// If nil or returns no addresses, Gateways report Programmed=False with reason AddressNotAssigned.
	AddressProvider AddressProvider

	// GatewayFilter is an optional filter func restricting which Gateways this instance serves.
	// If set, only Gateways for which GatewayFilter returns true are reconciled and served.
	GatewayFilter func(gw *gatewayv1.Gateway) bool

	// DisableStatusUpdates disables writing status back to the Kubernetes API.
	// Useful for data-plane instances where the control-plane controller owns status reporting.
	DisableStatusUpdates bool

	// CertificateSources is an optional map of named CertificateSource implementations
	// for Gateway TLS listeners configured with tls.options[gateway.gke-labs.io/certificate-source].
	CertificateSources map[string]CertificateSource

	// ListenerValidator is an optional hook to validate listener specifications.
	// If it returns conditions, they are applied to the listener.
	ListenerValidator state.ListenerValidator

	// Manager is an optional controller-runtime manager. If provided, New will
	// register reconcilers with it instead of creating a new manager.
	Manager ctrl.Manager

	// DataplaneMode runs in data-plane mode serving a single Gateway.
	// In this mode, the instance watches only its per-Gateway configuration Secret
	// and applies updates directly to the proxy, without running state computation.
	DataplaneMode bool

	// DataplaneGatewayNamespace is the namespace of the Gateway in DataplaneMode.
	DataplaneGatewayNamespace string

	// DataplaneGatewayName is the name of the Gateway in DataplaneMode.
	DataplaneGatewayName string

	// UDPIdleTimeout is the idle timeout for UDP sessions.
	// Defaults to 60s.
	UDPIdleTimeout time.Duration

	// UDPMaxSessions is the maximum number of concurrent UDP sessions per listener.
	// Defaults to 10000.
	UDPMaxSessions int

	// ReadHeaderTimeout is the amount of time allowed to read request headers on HTTP and HTTPS servers.
	// Defaults to 10s.
	ReadHeaderTimeout time.Duration

	// ReadTimeout is the maximum duration for reading the entire request, including the body.
	// Defaults to 0 (disabled).
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out writes of the response.
	// Defaults to 0 (disabled).
	WriteTimeout time.Duration

	// IdleTimeout is the maximum amount of time to wait for the next request when keep-alives are enabled.
	// Defaults to 60s.
	IdleTimeout time.Duration

	// TCPIdleTimeout is the idle timeout for spliced TCP and TLS passthrough connections.
	// Defaults to 0 (disabled).
	TCPIdleTimeout time.Duration

	// TCPMaxConnections is the maximum number of concurrent TCP connections per listener.
	// Defaults to 10000.
	TCPMaxConnections int

	// AllowedSourceCIDRs is an optional list of CIDRs permitted to connect to HTTP and HTTPS listeners.
	// Connections from outside these CIDRs are closed immediately before TLS.
	AllowedSourceCIDRs []string

	// ProxyProtocol enables PROXY protocol parsing on HTTP and HTTPS listeners when set to "enabled".
	ProxyProtocol string

	// ProxyProtocolTrustedCIDRs is an optional list of CIDRs from which PROXY headers are parsed.
	// If a connection's source IP is not in this list, PROXY headers are not honoured.
	ProxyProtocolTrustedCIDRs []string

	// DrainSentinelPath is the file path checked for connection draining.
	// If the file exists, the readyz probe reports draining (HTTP 503).
	// Disabled if empty (default).
	DrainSentinelPath string

	// DebugErrorResponses enables verbose error messages in unmatched responses.
	DebugErrorResponses bool

	// GatewayStatusHook is an optional hook called by GARI's Gateway reconciler after computing
	// the desired status and before writing it to the API server.
	// The hook receives a deep copy of the desired status and may adjust Programmed
	// (status, reason, and message) and addresses, downgrade Accepted to False,
	// and add its own condition types. The gw parameter must not be modified.
	// GARI retains ownership of Accepted (other than downgrading), listener conditions,
	// and other core status fields.
	GatewayStatusHook GatewayStatusHook

	// ACMEChallengeUpstreamURL is the URL of the upstream certificate server to forward ACME HTTP-01 challenge requests to.
	ACMEChallengeUpstreamURL string

	// ACMEChallengeCABundlePath is the path to the CA bundle PEM file to verify the upstream certificate server.
	ACMEChallengeCABundlePath string

	// ACMEChallengeTokenPath is the path to the projected service-account token file for data-plane identity.
	ACMEChallengeTokenPath string

	// SetupWithManager is an optional callback called after the controller-runtime Manager
	// is created, allowing callers to register additional reconcilers or runnables before
	// the manager starts. If non-nil, it is passed the manager and the GARI Server.
	SetupWithManager func(mgr ctrl.Manager, s *Server) error
}

// ErrDraining indicates that the server is draining connections.
var ErrDraining = errors.New("draining")

// DefaultOptions returns standard default options for GARI.
func DefaultOptions() Options {
	return Options{
		ControllerName:         controller.DefaultControllerName,
		MetricsAddr:            fmt.Sprintf(":%d", state.DataPlaneHealthProbePort),
		HealthProbeBindAddress: fmt.Sprintf(":%d", state.DataPlaneHealthProbePort),
		ProxyAddr:              fmt.Sprintf(":%d", state.DataPlaneHTTPPort),
		ProxyHTTPSAddr:         fmt.Sprintf(":%d", state.DataPlaneHTTPSPort),
		LeaderElectionID:       "gateway-api-reference-implementation",
		UDPIdleTimeout:         proxy.DefaultUDPIdleTimeout,
		UDPMaxSessions:         proxy.DefaultUDPMaxSessions,
		ReadHeaderTimeout:      10 * time.Second,
		IdleTimeout:            60 * time.Second,
		TCPIdleTimeout:         proxy.DefaultTCPIdleTimeout,
		TCPMaxConnections:      proxy.DefaultTCPMaxConnections,
		ForwardedForMode:       proxy.ForwardedForModeAppend,
		DrainSentinelPath:      "",
	}
}

func (o *Options) complete() error {
	if o.ControllerName == "" {
		o.ControllerName = controller.DefaultControllerName
	}
	if o.Scheme == nil {
		o.Scheme = DefaultScheme()
	}
	if o.LeaderElectionID == "" {
		o.LeaderElectionID = "gateway-api-reference-implementation"
	}
	if o.UDPIdleTimeout <= 0 {
		o.UDPIdleTimeout = proxy.DefaultUDPIdleTimeout
	}
	if o.UDPMaxSessions <= 0 {
		o.UDPMaxSessions = proxy.DefaultUDPMaxSessions
	}
	if o.ReadHeaderTimeout == 0 {
		o.ReadHeaderTimeout = 10 * time.Second
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = 60 * time.Second
	}
	if o.TCPMaxConnections == 0 {
		o.TCPMaxConnections = proxy.DefaultTCPMaxConnections
	}
	if o.ForwardedForMode == "" {
		o.ForwardedForMode = proxy.ForwardedForModeAppend
	} else if o.ForwardedForMode != proxy.ForwardedForModeAppend && o.ForwardedForMode != proxy.ForwardedForModeReplace {
		return fmt.Errorf("invalid forwarded-for-mode: %q (must be %q or %q)", o.ForwardedForMode, proxy.ForwardedForModeAppend, proxy.ForwardedForModeReplace)
	}
	if o.DataplaneMode {
		o.LeaderElection = false
		o.DisableStatusUpdates = true
		o.AddressProvider = nil
	}
	return nil
}

// Server encapsulates GARI components: state, proxy, manager, and proxy servers.
type Server struct {
	opts Options

	manager ctrl.Manager
	state   *state.State
	proxy   *proxy.Proxy

	proxySynced atomic.Bool

	// filterMu guards listenerOpts, httpFilter, and httpsFilter.
	filterMu     sync.Mutex
	listenerOpts *proxyproto.ListenerOptions
	httpFilter   *proxyproto.Listener
	httpsFilter  *proxyproto.Listener

	// appliedMu guards appliedRevisions.
	appliedMu        sync.RWMutex
	appliedRevisions map[string]string
}

func (s *Server) listenerOptionsLocked() proxyproto.ListenerOptions {
	if s.listenerOpts != nil {
		return *s.listenerOpts
	}
	return proxyproto.ListenerOptions{
		AllowedSourceCIDRs:        s.opts.AllowedSourceCIDRs,
		ProxyProtocolTrustedCIDRs: s.opts.ProxyProtocolTrustedCIDRs,
		ProxyProtocol:             s.opts.ProxyProtocol,
	}
}

func (s *Server) updateListenerFilters(opts proxyproto.ListenerOptions) error {
	if _, err := proxyproto.ParseCIDRs(opts.AllowedSourceCIDRs); err != nil {
		return fmt.Errorf("parsing allowedSourceCIDRs: %w", err)
	}
	if _, err := proxyproto.ParseCIDRs(opts.ProxyProtocolTrustedCIDRs); err != nil {
		return fmt.Errorf("parsing proxyProtocolTrustedCIDRs: %w", err)
	}

	s.filterMu.Lock()
	defer s.filterMu.Unlock()

	cloned := opts
	if opts.AllowedSourceCIDRs != nil {
		cloned.AllowedSourceCIDRs = slices.Clone(opts.AllowedSourceCIDRs)
	}
	if opts.ProxyProtocolTrustedCIDRs != nil {
		cloned.ProxyProtocolTrustedCIDRs = slices.Clone(opts.ProxyProtocolTrustedCIDRs)
	}
	s.listenerOpts = &cloned

	if s.httpFilter != nil {
		if err := s.httpFilter.UpdateOptions(cloned); err != nil {
			setupLog.Error(err, "failed to update HTTP listener options")
		}
	}
	if s.httpsFilter != nil {
		if err := s.httpsFilter.UpdateOptions(cloned); err != nil {
			setupLog.Error(err, "failed to update HTTPS listener options")
		}
	}
	return nil
}

func (s *Server) initHTTPFilter(lis net.Listener) (*proxyproto.Listener, error) {
	s.filterMu.Lock()
	defer s.filterMu.Unlock()

	filterLis, err := proxyproto.NewListener(lis, s.listenerOptionsLocked())
	if err != nil {
		return nil, err
	}
	s.httpFilter = filterLis
	return filterLis, nil
}

func (s *Server) initHTTPSFilter(lis net.Listener) (*proxyproto.Listener, error) {
	s.filterMu.Lock()
	defer s.filterMu.Unlock()

	filterLis, err := proxyproto.NewListener(lis, s.listenerOptionsLocked())
	if err != nil {
		return nil, err
	}
	s.httpsFilter = filterLis
	return filterLis, nil
}

// State returns the internal state store.
func (s *Server) State() *state.State {
	return s.state
}

// Proxy returns the internal HTTP proxy.
func (s *Server) Proxy() *proxy.Proxy {
	return s.proxy
}

// Manager returns the controller-runtime Manager, if one was configured or created.
func (s *Server) Manager() ctrl.Manager {
	return s.manager
}

// Options returns the server configuration options.
func (s *Server) Options() Options {
	return s.opts
}

// EnqueueGateway requests a reconcile of the given Gateway in the GARI Gateway controller.
func (s *Server) EnqueueGateway(req types.NamespacedName) {
	if s.state != nil {
		s.state.EnqueueGateway(req)
	}
}

// New creates and initializes a new GARI Server.
// If opts.Manager is nil, a controller-runtime Manager is created using opts.RestConfig and registered with GARI reconcilers.
func New(opts Options) (*Server, error) {
	if err := opts.complete(); err != nil {
		return nil, err
	}

	st := state.NewState()
	p := proxy.NewProxy()
	if opts.UDPIdleTimeout > 0 {
		p.SetUDPIdleTimeout(opts.UDPIdleTimeout)
	}
	if opts.UDPMaxSessions > 0 {
		p.SetUDPMaxSessions(opts.UDPMaxSessions)
	}
	if opts.TCPIdleTimeout > 0 {
		p.SetTCPIdleTimeout(opts.TCPIdleTimeout)
	}
	if opts.TCPMaxConnections > 0 {
		p.SetTCPMaxConnections(opts.TCPMaxConnections)
	}
	if opts.ForwardedForMode != "" {
		p.SetForwardedForMode(opts.ForwardedForMode)
	}
	if opts.DebugErrorResponses {
		p.SetDebugErrorResponses(true)
	}
	if opts.ACMEChallengeUpstreamURL != "" {
		p.UpdateACMEChallenge(&proxy.ACMEChallengeConfig{
			UpstreamURL:  opts.ACMEChallengeUpstreamURL,
			CABundlePath: opts.ACMEChallengeCABundlePath,
			TokenPath:    opts.ACMEChallengeTokenPath,
		})
	}

	s := &Server{
		opts:  opts,
		state: st,
		proxy: p,
	}

	mgr := opts.Manager
	if mgr == nil {
		cfg := opts.RestConfig
		if cfg == nil {
			var err error
			cfg, err = ctrl.GetConfig()
			if err != nil {
				return nil, fmt.Errorf("unable to get kubeconfig: %w", err)
			}
		}

		readyzHandler, healthzHandler := s.healthzHandlers()
		appliedHandler := s.appliedHandler()
		metricsOpts := metricsserver.Options{
			BindAddress: opts.MetricsAddr,
		}
		healthProbeBindAddress := opts.HealthProbeBindAddress
		extraHandlers := map[string]http.Handler{
			"/healthz":        http.StripPrefix("/healthz", healthzHandler),
			"/healthz/":       http.StripPrefix("/healthz", healthzHandler),
			"/readyz":         http.StripPrefix("/readyz", readyzHandler),
			"/readyz/":        http.StripPrefix("/readyz", readyzHandler),
			"/_gari/readyz":   http.StripPrefix("/_gari/readyz", readyzHandler),
			"/_gari/readyz/":  http.StripPrefix("/_gari/readyz", readyzHandler),
			"/_gari/applied":  appliedHandler,
			"/_gari/applied/": appliedHandler,
		}
		if samePortOrAddr(opts.MetricsAddr, opts.HealthProbeBindAddress) && opts.MetricsAddr != "" && opts.MetricsAddr != "0" && opts.HealthProbeBindAddress != "" && opts.HealthProbeBindAddress != "0" {
			metricsOpts.ExtraHandlers = extraHandlers
			healthProbeBindAddress = ""
		} else if (opts.MetricsAddr == "" || opts.MetricsAddr == "0") && opts.HealthProbeBindAddress != "" && opts.HealthProbeBindAddress != "0" {
			metricsOpts.BindAddress = opts.HealthProbeBindAddress
			metricsOpts.ExtraHandlers = extraHandlers
			healthProbeBindAddress = ""
		}

		var err error
		if opts.DataplaneMode {
			secretName := singlepod.ResourceNameForGateway(opts.DataplaneGatewayName)
			mgr, err = ctrl.NewManager(cfg, ctrl.Options{
				Scheme:                 opts.Scheme,
				Metrics:                metricsOpts,
				HealthProbeBindAddress: healthProbeBindAddress,
				LeaderElection:         false,
				Cache: cache.Options{
					ByObject: map[client.Object]cache.ByObject{
						&corev1.Secret{}: {
							Namespaces: map[string]cache.Config{
								opts.DataplaneGatewayNamespace: {
									FieldSelector: fields.OneTermEqualSelector("metadata.name", secretName),
								},
							},
						},
					},
				},
			})
		} else {
			mgr, err = ctrl.NewManager(cfg, ctrl.Options{
				Scheme:  opts.Scheme,
				Metrics: metricsOpts,
				WebhookServer: webhook.NewServer(webhook.Options{
					Port: 9443,
				}),
				HealthProbeBindAddress: healthProbeBindAddress,
				LeaderElection:         opts.LeaderElection,
				LeaderElectionID:       opts.LeaderElectionID,
			})
		}
		if err != nil {
			return nil, fmt.Errorf("unable to start manager: %w", err)
		}
	}

	s.manager = mgr

	if err := s.SetupWithManager(mgr); err != nil {
		return nil, err
	}

	if s.opts.SetupWithManager != nil {
		if err := s.opts.SetupWithManager(mgr, s); err != nil {
			return nil, fmt.Errorf("custom SetupWithManager failed: %w", err)
		}
	}

	return s, nil
}

// NewWithManager initializes a GARI Server using an existing controller-runtime Manager.
func NewWithManager(mgr ctrl.Manager, opts Options) (*Server, error) {
	opts.Manager = mgr
	return New(opts)
}

func samePortOrAddr(addr1, addr2 string) bool {
	if addr1 == addr2 && addr1 != "0" && addr1 != ":0" && addr1 != "" {
		_, port, err := net.SplitHostPort(addr1)
		if err == nil && port == "0" {
			return false
		}
		return true
	}
	_, port1, err1 := net.SplitHostPort(addr1)
	_, port2, err2 := net.SplitHostPort(addr2)
	if err1 == nil && err2 == nil && port1 == port2 && port1 != "" && port1 != "0" {
		return true
	}
	return false
}

func (s *Server) readyzChecker() healthz.Checker {
	return func(req *http.Request) error {
		if s.opts.DrainSentinelPath != "" {
			if _, err := os.Stat(s.opts.DrainSentinelPath); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("checking drain sentinel: %w", err)
				}
			} else {
				return ErrDraining
			}
		}
		if !s.proxySynced.Load() {
			return errors.New("proxy configuration not yet applied")
		}
		return nil
	}
}

func (s *Server) healthzHandlers() (readyz http.Handler, healthzHandler http.Handler) {
	rHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if err := s.readyzChecker()(req); err != nil {
			if errors.Is(err, ErrDraining) {
				http.Error(w, ErrDraining.Error(), http.StatusServiceUnavailable)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			klog.V(4).Infof("failed to write readyz response: %v", err)
		}
	})
	hHandler := &healthz.Handler{Checks: map[string]healthz.Checker{"ping": healthz.Ping}}
	return rHandler, hHandler
}

func (s *Server) appliedRevisionsCopy() map[string]string {
	if s == nil {
		return make(map[string]string)
	}
	s.appliedMu.RLock()
	defer s.appliedMu.RUnlock()
	revisions := make(map[string]string, len(s.appliedRevisions))
	for k, v := range s.appliedRevisions {
		revisions[k] = v
	}
	return revisions
}

func (s *Server) recordAppliedRevision(gatewayKey, revision string) {
	if s == nil {
		return
	}
	s.appliedMu.Lock()
	defer s.appliedMu.Unlock()
	if s.appliedRevisions == nil {
		s.appliedRevisions = make(map[string]string)
	}
	s.appliedRevisions[gatewayKey] = revision
}

func (s *Server) appliedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		revisions := s.appliedRevisionsCopy()
		if err := json.NewEncoder(w).Encode(revisions); err != nil {
			// Disconnects while writing the response are safe to ignore; the probe will retry.
			klog.Warningf("failed to write applied revisions response: %v", err)
		}
	})
}

// SetupWithManager registers all GARI reconcilers with the given Manager.
func (s *Server) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.AddReadyzCheck("readyz", s.readyzChecker()); err != nil {
		return fmt.Errorf("failed to register readyz check: %w", err)
	}
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("failed to register healthz check: %w", err)
	}

	if s.opts.DataplaneMode {
		secretName := singlepod.ResourceNameForGateway(s.opts.DataplaneGatewayName)
		reconciler := &dataplaneSecretReconciler{
			Client:           mgr.GetClient(),
			proxy:            s.proxy,
			proxySynced:      &s.proxySynced,
			gatewayNamespace: s.opts.DataplaneGatewayNamespace,
			secretName:       secretName,
			onConfigUpdate:   s.updateListenerFilters,
			onConfigApplied:  s.recordAppliedRevision,
		}
		if err := ctrl.NewControllerManagedBy(mgr).
			For(&corev1.Secret{}).
			Complete(reconciler); err != nil {
			return fmt.Errorf("failed to create dataplane secret controller: %w", err)
		}
		return nil
	}

	userHook := s.opts.OnGatewaysUpdate
	wrappedHook := func(gateways []*gatewayv1.Gateway) {
		s.proxySynced.Store(true)
		newRevisions := make(map[string]string, len(gateways))
		for _, gw := range gateways {
			if gw == nil {
				continue
			}
			gwKey := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
			if s.state != nil {
				if dpCfg := s.state.GetDataplaneConfig(gwKey); dpCfg != nil && dpCfg.Revision != "" {
					newRevisions[gwKey.String()] = dpCfg.Revision
				}
			}
		}
		s.appliedMu.Lock()
		s.appliedRevisions = newRevisions
		s.appliedMu.Unlock()
		if userHook != nil {
			userHook(gateways)
		}
	}

	return controller.RegisterReconcilers(mgr, s.state, s.proxy, controller.ReconcilerOptions{
		ControllerName:       s.opts.ControllerName,
		OnGatewaysUpdate:     wrappedHook,
		AddressProvider:      s.opts.AddressProvider,
		GatewayFilter:        s.opts.GatewayFilter,
		DisableStatusUpdates: s.opts.DisableStatusUpdates,
		GatewayStatusHook:    s.opts.GatewayStatusHook,
		ListenerValidator:    s.opts.ListenerValidator,

		CertificateSources: s.opts.CertificateSources,
	})
}

type dataplaneSecretReconciler struct {
	client.Client
	proxy            *proxy.Proxy
	proxySynced      *atomic.Bool
	gatewayNamespace string
	secretName       string
	onConfigUpdate   func(opts proxyproto.ListenerOptions) error
	onConfigApplied  func(gwKey string, revision string)
}

func (r *dataplaneSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Namespace != r.gatewayNamespace || req.Name != r.secretName {
		return ctrl.Result{}, nil
	}

	var sec corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	data, ok := sec.Data[singlepod.DataplaneSecretDataKey]
	if !ok || len(data) == 0 {
		return ctrl.Result{}, nil
	}

	if err := state.ApplyDataplaneConfig(r.proxy, data); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to apply dataplane config: %w", err)
	}
	r.proxySynced.Store(true)

	dpCfg, err := state.UnmarshalDataplaneConfig(data)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to unmarshal dataplane config: %w", err)
	}

	if r.onConfigUpdate != nil {
		opts := proxyproto.ListenerOptions{
			AllowedSourceCIDRs:        dpCfg.AllowedSourceCIDRs,
			ProxyProtocol:             dpCfg.ProxyProtocol,
			ProxyProtocolTrustedCIDRs: dpCfg.ProxyProtocolTrustedCIDRs,
		}
		if err := r.onConfigUpdate(opts); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update listener filters: %w", err)
		}
	}

	if r.onConfigApplied != nil && dpCfg.Revision != "" {
		r.onConfigApplied(dpCfg.GatewayName.String(), dpCfg.Revision)
	}

	return ctrl.Result{}, nil
}

func (s *Server) initDefaultCertificate() error {
	if s.opts.DefaultCertificate != nil {
		s.proxy.SetDefaultCertificate(s.opts.DefaultCertificate)
		return nil
	}
	cert, err := GenerateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("failed to generate self-signed cert: %w", err)
	}
	s.proxy.SetDefaultCertificate(&cert)
	return nil
}

func (s *Server) newTLSConfig() *tls.Config {
	return s.proxy.TLSConfig()
}

func parsePort(addr string) (int, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(portStr)
}

// StartProxyServers starts the HTTP and HTTPS proxy servers and blocks until ctx is canceled.
func (s *Server) newHTTPServer(handler http.Handler, tlsConfig *tls.Config) *http.Server {
	readHeaderTimeout := s.opts.ReadHeaderTimeout
	if readHeaderTimeout <= 0 {
		if readHeaderTimeout < 0 {
			readHeaderTimeout = 0
		} else {
			readHeaderTimeout = 10 * time.Second
		}
	}
	idleTimeout := s.opts.IdleTimeout
	if idleTimeout <= 0 {
		if idleTimeout < 0 {
			idleTimeout = 0
		} else {
			idleTimeout = 60 * time.Second
		}
	}
	readTimeout := s.opts.ReadTimeout
	if readTimeout < 0 {
		readTimeout = 0
	}
	writeTimeout := s.opts.WriteTimeout
	if writeTimeout < 0 {
		writeTimeout = 0
	}
	return &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
	}
}

func (s *Server) StartProxyServers(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	go func() {
		<-ctx.Done()
		if err := s.proxy.Close(); err != nil {
			klog.Warningf("failed to close proxy: %v", err)
		}
	}()

	hasHTTPS := s.opts.HTTPSListener != nil || s.opts.ProxyHTTPSAddr != ""
	hasHTTP3 := s.opts.HTTP3PacketConn != nil || s.opts.ProxyHTTP3Addr != ""
	if hasHTTPS || hasHTTP3 {
		if err := s.initDefaultCertificate(); err != nil {
			return err
		}
	}

	// HTTP Proxy Server
	if s.opts.HTTPListener != nil || s.opts.ProxyAddr != "" {
		g.Go(func() error {
			var lis net.Listener
			if s.opts.HTTPListener != nil {
				lis = s.opts.HTTPListener
			} else {
				var err error
				lis, err = net.Listen("tcp", s.opts.ProxyAddr)
				if err != nil {
					return fmt.Errorf("failed to listen on HTTP proxy address %q: %w", s.opts.ProxyAddr, err)
				}
			}

			filterLis, err := s.initHTTPFilter(lis)
			if err != nil {
				if closeErr := lis.Close(); closeErr != nil {
					klog.V(4).Infof("closing HTTP listener: %v", closeErr)
				}
				return fmt.Errorf("failed to create HTTP listener filter: %w", err)
			}

			setupLog.Info("starting proxy server", "addr", filterLis.Addr().String())
			var handler http.Handler = s.proxy
			if s.opts.EnableH2C {
				h2s := &http2.Server{}
				handler = h2c.NewHandler(s.proxy, h2s)
			}
			srv := s.newHTTPServer(handler, nil)
			go func() {
				<-ctx.Done()
				setupLog.Info("shutting down proxy server")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := srv.Shutdown(shutdownCtx); err != nil {
					klog.Warningf("failed to shut down proxy server: %v", err)
				}
			}()
			if err := srv.Serve(filterLis); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("proxy server failed: %w", err)
			}
			return nil
		})
	}

	var h3Conn net.PacketConn
	var advertisedH3Port int

	if hasHTTP3 {
		if s.opts.HTTP3PacketConn != nil {
			h3Conn = s.opts.HTTP3PacketConn
		} else {
			var err error
			h3Conn, err = net.ListenPacket("udp", s.opts.ProxyHTTP3Addr)
			if err != nil {
				return fmt.Errorf("failed to listen on HTTP/3 proxy address %q: %w", s.opts.ProxyHTTP3Addr, err)
			}
		}

		advertisedH3Port = s.opts.ProxyHTTP3AdvertisedPort
		if advertisedH3Port == 0 && h3Conn != nil {
			if udpAddr, ok := h3Conn.LocalAddr().(*net.UDPAddr); ok {
				advertisedH3Port = udpAddr.Port
			} else {
				p, err := parsePort(h3Conn.LocalAddr().String())
				if err != nil {
					return fmt.Errorf("failed to parse port from HTTP/3 connection address %q: %w", h3Conn.LocalAddr().String(), err)
				}
				if p > 0 {
					advertisedH3Port = p
				}
			}
		}
	}

	// HTTPS Proxy Server
	if hasHTTPS {
		g.Go(func() error {
			var lis net.Listener
			if s.opts.HTTPSListener != nil {
				lis = s.opts.HTTPSListener
			} else {
				var err error
				lis, err = net.Listen("tcp", s.opts.ProxyHTTPSAddr)
				if err != nil {
					return fmt.Errorf("failed to listen on HTTPS proxy address %q: %w", s.opts.ProxyHTTPSAddr, err)
				}
			}

			filterLis, err := s.initHTTPSFilter(lis)
			if err != nil {
				if closeErr := lis.Close(); closeErr != nil {
					klog.V(4).Infof("closing HTTPS listener: %v", closeErr)
				}
				return fmt.Errorf("failed to create HTTPS listener filter: %w", err)
			}

			setupLog.Info("starting proxy HTTPS server", "addr", filterLis.Addr().String())

			var handler http.Handler = s.proxy
			if hasHTTP3 && advertisedH3Port > 0 {
				altSvcVal := fmt.Sprintf(`h3=":%d"; ma=86400`, advertisedH3Port)
				handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Alt-Svc", altSvcVal)
					s.proxy.ServeHTTP(w, r)
				})
			}

			tlsConfig := s.newTLSConfig()
			srv := s.newHTTPServer(handler, tlsConfig)
			if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
				return fmt.Errorf("failed to configure HTTP/2 on HTTPS proxy: %w", err)
			}
			sniLis := s.proxy.NewSNIListener(filterLis)
			tlsLis := tls.NewListener(sniLis, tlsConfig)
			go func() {
				<-ctx.Done()
				setupLog.Info("shutting down proxy HTTPS server")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := srv.Shutdown(shutdownCtx); err != nil {
					klog.Warningf("failed to shut down proxy HTTPS server: %v", err)
				}
				if err := sniLis.Close(); err != nil {
					klog.Warningf("failed to close HTTPS SNI listener: %v", err)
				}
			}()
			if err := srv.Serve(tlsLis); err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("proxy HTTPS server failed: %w", err)
			}
			return nil
		})
	}

	// HTTP/3 Proxy Server
	if hasHTTP3 && h3Conn != nil {
		g.Go(func() error {
			setupLog.Info("starting proxy HTTP/3 server", "addr", h3Conn.LocalAddr().String())

			tlsConfig := s.newTLSConfig()
			quicConfig := s.opts.HTTP3QUICConfig
			if quicConfig == nil {
				quicConfig = &quic.Config{}
			} else {
				quicConfig = quicConfig.Clone()
			}
			if quicConfig.MaxIdleTimeout == 0 {
				idleTimeout := s.opts.IdleTimeout
				if idleTimeout <= 0 {
					if idleTimeout < 0 {
						idleTimeout = 0
					} else {
						idleTimeout = 60 * time.Second
					}
				}
				quicConfig.MaxIdleTimeout = idleTimeout
			}

			h3Server := &http3.Server{
				Handler:    s.proxy,
				TLSConfig:  tlsConfig,
				Port:       advertisedH3Port,
				QUICConfig: quicConfig,
			}

			go func() {
				<-ctx.Done()
				setupLog.Info("shutting down proxy HTTP/3 server")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := h3Server.Shutdown(shutdownCtx); err != nil {
					klog.Warningf("failed to shut down proxy HTTP/3 server: %v", err)
				}
				if err := h3Conn.Close(); err != nil {
					klog.Warningf("failed to close HTTP/3 packet connection: %v", err)
				}
			}()

			if err := h3Server.Serve(h3Conn); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, quic.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("proxy HTTP/3 server failed: %w", err)
			}
			return nil
		})
	}

	return g.Wait()
}

// Start starts both the proxy servers and the controller manager, running until ctx is canceled.
func (s *Server) Start(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return s.StartProxyServers(ctx)
	})

	if s.manager != nil {
		g.Go(func() error {
			setupLog.Info("starting manager")
			if err := s.manager.Start(ctx); err != nil {
				return fmt.Errorf("problem running manager: %w", err)
			}
			return nil
		})
	}

	return g.Wait()
}

// Run creates a new Server with opts and runs it until ctx is canceled.
func Run(ctx context.Context, opts Options) error {
	s, err := New(opts)
	if err != nil {
		return err
	}
	return s.Start(ctx)
}

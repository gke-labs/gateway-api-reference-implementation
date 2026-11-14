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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/dnsconfig"
	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/mdns"
	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/validation"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

type parsedAnswer struct {
	name  string
	qtype dnsmessage.Type
	ttl   uint32
	ip    net.IP
}

func parseAnswers(raw []byte) []parsedAnswer {
	var parser dnsmessage.Parser
	if _, err := parser.Start(raw); err != nil {
		return nil
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil
	}
	var answers []parsedAnswer
	for {
		answer, err := parser.Answer()
		if err == dnsmessage.ErrSectionDone || err != nil {
			break
		}
		var ip net.IP
		if aRecord, ok := answer.Body.(*dnsmessage.AResource); ok {
			ip = net.IPv4(aRecord.A[0], aRecord.A[1], aRecord.A[2], aRecord.A[3])
		} else if aaaaRecord, ok := answer.Body.(*dnsmessage.AAAAResource); ok {
			ip = net.IP(aaaaRecord.AAAA[:])
		}
		answers = append(answers, parsedAnswer{
			name:  answer.Header.Name.String(),
			qtype: answer.Header.Type,
			ttl:   answer.Header.TTL,
			ip:    ip,
		})
	}
	return answers
}

func isNormalClose(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
		return true
	}
	return false
}

type testFixture struct {
	controllerState  *state.State
	fakeClient       client.Client
	dnsPublisher     *dnsconfig.Publisher
	reconciler       *Reconciler
	prober           *mdns.Prober
	responder        *mdns.Responder
	capturedPackets  [][]byte
	packetLock       sync.Mutex
	reconcileRequest ctrl.Request
}

func newTestFixture(t *testing.T, ctx context.Context) *testFixture {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme failed: %v", err)
	}
	if err := gatewayv1.Install(scheme); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	controllerState := state.NewState()
	controllerState.SetControllerName("github.com/gke-labs/gateway-api-reference-implementation/localgateway")
	controllerState.SetListenerValidator(validation.ValidateListener)
	controllerState.SetProxy(proxy.NewProxy())
	controllerState.SetSynced(true)
	controllerState.UpsertGatewayClass(&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "localgateway"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "github.com/gke-labs/gateway-api-reference-implementation/localgateway",
		},
	})

	dnsPublisher := dnsconfig.NewPublisher(
		fakeClient,
		dnsconfig.DefaultConfigSecretNamespace,
		dnsconfig.DefaultConfigSecretName,
		controllerState,
	)

	publisherStartErrChan := make(chan error, 1)
	go func() {
		publisherStartErrChan <- dnsPublisher.Start(ctx)
	}()

	t.Cleanup(func() {
		if err := <-publisherStartErrChan; err != nil {
			t.Errorf("dnsPublisher.Start returned unexpected error: %v", err)
		}
	})

	fixture := &testFixture{
		controllerState: controllerState,
		fakeClient:      fakeClient,
		dnsPublisher:    dnsPublisher,
		reconcileRequest: ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: dnsconfig.DefaultConfigSecretNamespace,
				Name:      dnsconfig.DefaultConfigSecretName,
			},
		},
	}

	responder, err := mdns.NewResponder(mdns.ResponderOptions{
		Ephemeral:   true,
		DisableIPv6: true,
		MulticastTap: func(raw []byte) {
			fixture.packetLock.Lock()
			defer fixture.packetLock.Unlock()
			fixture.capturedPackets = append(fixture.capturedPackets, slices.Clone(raw))
		},
	})
	if err != nil {
		t.Fatalf("failed to create responder: %v", err)
	}

	prober, err := mdns.NewProber(mdns.ProberOptions{
		Responder:             responder,
		TTL:                   120,
		ProbeInterval:         20 * time.Millisecond,
		ProbeCount:            2,
		ConflictRetryInterval: 100 * time.Millisecond,
		AnnounceInterval:      20 * time.Millisecond,
		OnStateChange:         logOnStateChange,
	})
	if err != nil {
		if closeErr := responder.Close(); closeErr != nil && !isNormalClose(closeErr) {
			t.Errorf("responder.Close failed: %v", closeErr)
		}
		t.Fatalf("failed to create prober: %v", err)
	}

	t.Cleanup(func() {
		if err := prober.Shutdown(); err != nil && !isNormalClose(err) {
			t.Errorf("prober.Shutdown failed: %v", err)
		}
		if err := responder.Close(); err != nil && !isNormalClose(err) {
			t.Errorf("responder.Close failed: %v", err)
		}
	})

	fixture.responder = responder
	fixture.prober = prober
	fixture.reconciler = NewReconciler(
		fakeClient,
		dnsconfig.DefaultConfigSecretNamespace,
		dnsconfig.DefaultConfigSecretName,
		prober,
		responder,
	)

	return fixture
}

func (f *testFixture) getCapturedAnswers() []parsedAnswer {
	f.packetLock.Lock()
	defer f.packetLock.Unlock()

	var answers []parsedAnswer
	for _, raw := range f.capturedPackets {
		answers = append(answers, parseAnswers(raw)...)
	}
	return answers
}

func (f *testFixture) drainCapturedAnswers() []parsedAnswer {
	f.packetLock.Lock()
	defer f.packetLock.Unlock()

	var answers []parsedAnswer
	for _, raw := range f.capturedPackets {
		answers = append(answers, parseAnswers(raw)...)
	}
	f.capturedPackets = nil
	return answers
}

func (f *testFixture) applyGateway(t *testing.T, ctx context.Context, name, hostname, address string) []parsedAnswer {
	t.Helper()

	f.packetLock.Lock()
	f.capturedPackets = nil
	f.packetLock.Unlock()

	hostnameValue := gatewayv1.Hostname(hostname)
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              name,
			CreationTimestamp: metav1.Now(),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "localgateway",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Hostname: &hostnameValue,
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	gatewayKey := types.NamespacedName{Namespace: "default", Name: name}
	f.controllerState.UpsertGateway(gateway)
	f.controllerState.SetGatewayAddresses(gatewayKey, []gatewayv1.GatewayStatusAddress{{Value: address}})
	f.controllerState.SetGatewayReadiness(gatewayKey, state.GatewayReadiness{Ready: true})
	f.controllerState.Recompute()

	waitForConfigInClient(t, ctx, f.fakeClient, func(config *dnsconfig.Config) bool {
		if config == nil {
			return false
		}
		for _, record := range config.Records {
			if record.Name == hostname && slices.Contains(record.Addresses, address) {
				return true
			}
		}
		return false
	})

	if _, err := f.reconciler.Reconcile(ctx, f.reconcileRequest); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Wait directly for the announcement answer to be captured, eliminating any race
	// where StatePublished is set before SendAnnouncement completes.
	expectedFQDN := strings.ToLower(mdns.ToFQDN(hostname))
	deadline := time.After(2 * time.Second)
	for {
		answers := f.getCapturedAnswers()
		for _, answer := range answers {
			if strings.EqualFold(answer.name, expectedFQDN) && answer.ip != nil && answer.ip.String() == address && answer.ttl > 0 {
				return f.drainCapturedAnswers()
			}
		}

		select {
		case <-deadline:
			t.Fatalf("timeout waiting for announcement for %s with %s, captured answers: %+v", hostname, address, f.getCapturedAnswers())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (f *testFixture) removeGateway(t *testing.T, ctx context.Context, name, hostname string) []parsedAnswer {
	t.Helper()

	f.packetLock.Lock()
	f.capturedPackets = nil
	f.packetLock.Unlock()

	gatewayKey := types.NamespacedName{Namespace: "default", Name: name}
	f.controllerState.DeleteGateway(gatewayKey)
	f.controllerState.Recompute()

	waitForConfigInClient(t, ctx, f.fakeClient, func(config *dnsconfig.Config) bool {
		if config == nil {
			return true
		}
		for _, record := range config.Records {
			if record.Name == hostname {
				return false
			}
		}
		return true
	})

	if _, err := f.reconciler.Reconcile(ctx, f.reconcileRequest); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Wait directly for the goodbye answer (TTL=0) to be captured.
	expectedFQDN := strings.ToLower(mdns.ToFQDN(hostname))
	deadline := time.After(2 * time.Second)
	for {
		answers := f.getCapturedAnswers()
		for _, answer := range answers {
			if strings.EqualFold(answer.name, expectedFQDN) && answer.ttl == 0 {
				return f.drainCapturedAnswers()
			}
		}

		select {
		case <-deadline:
			t.Fatalf("timeout waiting for goodbye packet for %s, captured answers: %+v", hostname, f.getCapturedAnswers())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func waitForConfigInClient(t *testing.T, ctx context.Context, kubernetesClient client.Client, condition func(config *dnsconfig.Config) bool) *dnsconfig.Config {
	t.Helper()

	deadline := time.After(2 * time.Second)
	for {
		var secret corev1.Secret
		err := kubernetesClient.Get(ctx, types.NamespacedName{
			Namespace: dnsconfig.DefaultConfigSecretNamespace,
			Name:      dnsconfig.DefaultConfigSecretName,
		}, &secret)
		if err == nil {
			payload, ok := secret.Data[singlepod.DataplaneSecretDataKey]
			if ok && len(payload) > 0 {
				var config dnsconfig.Config
				if err := json.Unmarshal(payload, &config); err == nil {
					if condition(&config) {
						return &config
					}
				}
			}
		} else if apierrors.IsNotFound(err) {
			if condition(nil) {
				return nil
			}
		}

		select {
		case <-deadline:
			t.Fatalf("timeout waiting for expected DNS config in Secret")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestReconciler_Lifecycle verifies acceptance criteria:
// A record in the config is announced, a changed address replaces the old one,
// and a removed record gets a goodbye.
func TestReconciler_Lifecycle(t *testing.T) {
	ctx := t.Context()
	fixture := newTestFixture(t, ctx)

	// 1. Initial gateway: app.local -> 192.168.1.100
	answers := fixture.applyGateway(t, ctx, "gw-app", "app.local", "192.168.1.100")

	foundAnnouncement := false
	for _, answer := range answers {
		if answer.name == "app.local." && answer.ttl == 120 && answer.ip.String() == "192.168.1.100" {
			foundAnnouncement = true
			break
		}
	}
	if !foundAnnouncement {
		t.Fatalf("expected announcement for app.local. with 192.168.1.100, got: %+v", answers)
	}

	record, ok := fixture.responder.GetRecord("app.local.")
	if !ok || len(record.A) != 1 || record.A[0].String() != "192.168.1.100" {
		t.Fatalf("expected responder to have app.local. with 192.168.1.100, got: %+v", record)
	}

	// 2. Changed address replaces the old one: app.local -> 192.168.1.200
	answers = fixture.applyGateway(t, ctx, "gw-app", "app.local", "192.168.1.200")

	foundReplacement := false
	for _, answer := range answers {
		if answer.name == "app.local." && answer.ttl == 120 && answer.ip.String() == "192.168.1.200" {
			foundReplacement = true
			break
		}
	}
	if !foundReplacement {
		t.Fatalf("expected announcement for app.local. with 192.168.1.200, got: %+v", answers)
	}

	record, ok = fixture.responder.GetRecord("app.local.")
	if !ok || len(record.A) != 1 || record.A[0].String() != "192.168.1.200" {
		t.Fatalf("expected responder address to be replaced with 192.168.1.200, got: %+v", record)
	}

	// 3. Removed record gets a goodbye (TTL=0) and is removed from responder
	answers = fixture.removeGateway(t, ctx, "gw-app", "app.local")

	foundGoodbye := false
	for _, answer := range answers {
		if answer.name == "app.local." && answer.ttl == 0 {
			foundGoodbye = true
			break
		}
	}
	if !foundGoodbye {
		t.Fatalf("expected goodbye packet (TTL=0) for app.local., got: %+v", answers)
	}

	if _, ok := fixture.responder.GetRecord("app.local."); ok {
		t.Fatalf("expected app.local. to be removed from responder")
	}
}

// TestReconciler_CancelContextSendsGoodbyes verifies acceptance criteria:
// Cancelling the context sends goodbyes for the published names.
func TestReconciler_CancelContextSendsGoodbyes(t *testing.T) {
	ctx := t.Context()
	fixture := newTestFixture(t, ctx)

	fixture.applyGateway(t, ctx, "gw-1", "app.local", "10.0.0.1")
	fixture.applyGateway(t, ctx, "gw-2", "site.local", "10.0.0.2")

	fixture.drainCapturedAnswers()

	cancelCtx, cancel := context.WithCancel(ctx)
	errChan := make(chan error, 1)
	go func() {
		errChan <- fixture.reconciler.Start(cancelCtx)
	}()

	cancel()

	select {
	case err := <-errChan:
		if err != nil && !isNormalClose(err) {
			t.Fatalf("reconciler.Start returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for reconciler.Start to exit on cancellation")
	}

	// Wait for goodbyes to be captured
	deadline := time.After(2 * time.Second)
	goodbyes := make(map[string]bool)
	for {
		answers := fixture.getCapturedAnswers()
		for _, answer := range answers {
			if answer.ttl == 0 {
				goodbyes[answer.name] = true
			}
		}
		if goodbyes["app.local."] && goodbyes["site.local."] {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timeout waiting for goodbyes on shutdown, captured answers: %+v", answers)
		case <-time.After(10 * time.Millisecond):
		}
	}

	if !goodbyes["app.local."] {
		t.Errorf("expected goodbye packet for app.local. on shutdown")
	}
	if !goodbyes["site.local."] {
		t.Errorf("expected goodbye packet for site.local. on shutdown")
	}

	if _, ok := fixture.prober.GetHostnameState("app.local."); !ok {
		t.Errorf("prober should keep names in place for inspection on shutdown")
	}
}

// TestReconciler_MalformedPayloadKeepsLastGoodRecords verifies that an unmarshaling error
// leaves previous records published in memory and causes Reconcile to return an error.
func TestReconciler_MalformedPayloadKeepsLastGoodRecords(t *testing.T) {
	ctx := t.Context()
	fixture := newTestFixture(t, ctx)

	fixture.applyGateway(t, ctx, "gw-1", "app.local", "10.0.0.1")

	var secret corev1.Secret
	if err := fixture.fakeClient.Get(ctx, types.NamespacedName{
		Namespace: dnsconfig.DefaultConfigSecretNamespace,
		Name:      dnsconfig.DefaultConfigSecretName,
	}, &secret); err != nil {
		t.Fatalf("failed to get Secret: %v", err)
	}
	secret.Data[singlepod.DataplaneSecretDataKey] = []byte("not-valid-json")
	if err := fixture.fakeClient.Update(ctx, &secret); err != nil {
		t.Fatalf("failed to update Secret: %v", err)
	}

	fixture.drainCapturedAnswers()

	_, err := fixture.reconciler.Reconcile(ctx, fixture.reconcileRequest)
	if err == nil {
		t.Fatalf("expected error from Reconcile when secret has invalid JSON, got nil")
	}

	record, ok := fixture.responder.GetRecord("app.local.")
	if !ok || len(record.A) != 1 || record.A[0].String() != "10.0.0.1" {
		t.Fatalf("expected app.local. to stay published after malformed payload, got: %+v", record)
	}

	answers := fixture.drainCapturedAnswers()
	for _, answer := range answers {
		if answer.ttl == 0 {
			t.Errorf("expected no goodbyes to be sent on malformed payload, got: %+v", answer)
		}
	}
}

// TestReconciler_InvalidConfigRecordsSkipped verifies that records with invalid hostnames
// or unparsable IP addresses are reported and skipped without interrupting valid records.
func TestReconciler_InvalidConfigRecordsSkipped(t *testing.T) {
	ctx := t.Context()
	fixture := newTestFixture(t, ctx)

	fixture.applyGateway(t, ctx, "gw-valid", "valid.local", "10.0.0.1")

	invalidConfig := &dnsconfig.Config{
		Records: []dnsconfig.Record{
			{Name: "invalid..local", Addresses: []string{"10.0.0.2"}},
			{Name: "badip.local", Addresses: []string{"999.999.999.999"}},
			{Name: "valid.local", Addresses: []string{"10.0.0.1"}},
		},
	}
	payload, err := json.Marshal(invalidConfig)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	var secret corev1.Secret
	if err := fixture.fakeClient.Get(ctx, types.NamespacedName{
		Namespace: dnsconfig.DefaultConfigSecretNamespace,
		Name:      dnsconfig.DefaultConfigSecretName,
	}, &secret); err != nil {
		t.Fatalf("failed to get Secret: %v", err)
	}
	secret.Data[singlepod.DataplaneSecretDataKey] = payload
	if err := fixture.fakeClient.Update(ctx, &secret); err != nil {
		t.Fatalf("failed to update Secret: %v", err)
	}

	if _, err := fixture.reconciler.Reconcile(ctx, fixture.reconcileRequest); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Wait for valid.local to be captured
	expectedFQDN := "valid.local."
	deadline := time.After(2 * time.Second)
	for {
		answers := fixture.getCapturedAnswers()
		found := false
		for _, answer := range answers {
			if strings.EqualFold(answer.name, expectedFQDN) && answer.ttl > 0 {
				found = true
				break
			}
		}
		if found {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timeout waiting for valid.local. announcement")
		case <-time.After(10 * time.Millisecond):
		}
	}

	if _, ok := fixture.responder.GetRecord("valid.local."); !ok {
		t.Errorf("expected valid.local. to be published")
	}
	if _, ok := fixture.prober.GetHostnameState("invalid..local."); ok {
		t.Errorf("expected invalid..local. to not exist in prober")
	}
	if _, ok := fixture.prober.GetHostnameState("badip.local."); ok {
		t.Errorf("expected badip.local. to not exist in prober")
	}
}

// TestReconciler_ConflictStateChange verifies that a LAN conflict triggers OnStateChange
// with StateConflict, invokes logOnStateChange, and removes the conflicting record.
func TestReconciler_ConflictStateChange(t *testing.T) {
	ctx := t.Context()
	conflictCh := make(chan string, 1)

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme failed: %v", err)
	}

	rawConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral socket: %v", err)
	}
	defer rawConn.Close()
	ephemeralPort := rawConn.LocalAddr().(*net.UDPAddr).Port

	responder, err := mdns.NewResponder(mdns.ResponderOptions{
		Port:        ephemeralPort,
		IPv4Conn:    rawConn,
		DisableIPv6: true,
	})
	if err != nil {
		t.Fatalf("NewResponder failed: %v", err)
	}
	defer responder.Close()

	prober, err := mdns.NewProber(mdns.ProberOptions{
		Responder:             responder,
		TTL:                   120,
		ProbeInterval:         20 * time.Millisecond,
		ProbeCount:            2,
		ConflictRetryInterval: 1 * time.Second,
		AnnounceInterval:      20 * time.Millisecond,
		OnStateChange: func(fqdn string, state mdns.HostnameState) {
			logOnStateChange(fqdn, state)
			if state == mdns.StateConflict {
				select {
				case conflictCh <- fqdn:
				default:
				}
			}
		},
	})
	if err != nil {
		t.Fatalf("NewProber failed: %v", err)
	}
	defer func() {
		if err := prober.Shutdown(); err != nil && !isNormalClose(err) {
			t.Errorf("prober.Shutdown failed: %v", err)
		}
	}()

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := NewReconciler(fakeClient, "default", "localgateway-dns", prober, responder)

	reconciler.applyConfig(ctx, &dnsconfig.Config{
		Records: []dnsconfig.Record{
			{Name: "conflict.local", Addresses: []string{"127.0.0.1"}},
		},
	})

	// Wait for record to reach published state
	deadline := time.After(2 * time.Second)
	for {
		snap, ok := prober.GetHostnameState("conflict.local.")
		if ok && snap.State == mdns.StatePublished {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timeout waiting for conflict.local. to publish")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Inject conflicting response from another host on the LAN
	bConflict := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		Response:      true,
		Authoritative: true,
	})
	bConflict.EnableCompression()
	if err := bConflict.StartAnswers(); err != nil {
		t.Fatalf("starting answers: %v", err)
	}
	if err := bConflict.AResource(
		dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("conflict.local."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | mdns.CacheFlushBit),
			TTL:   120,
		},
		dnsmessage.AResource{A: [4]byte{10, 0, 0, 99}},
	); err != nil {
		t.Fatalf("adding AResource: %v", err)
	}
	respData, err := bConflict.Finish()
	if err != nil {
		t.Fatalf("building conflict packet: %v", err)
	}

	sender, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("creating sender: %v", err)
	}
	defer sender.Close()

	if _, err := sender.WriteTo(respData, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: ephemeralPort}); err != nil {
		t.Fatalf("sending conflict packet: %v", err)
	}

	select {
	case fqdn := <-conflictCh:
		if !strings.EqualFold(fqdn, "conflict.local.") {
			t.Errorf("expected conflict for conflict.local., got %s", fqdn)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for conflict callback")
	}

	// Verify record is withdrawn from responder
	if _, ok := responder.GetRecord("conflict.local."); ok {
		t.Errorf("conflict.local. should be removed from responder after conflict")
	}
}

// TestParseOptions verifies CLI argument parsing and default values.
func TestParseOptions(t *testing.T) {
	// Defaults
	options, err := ParseOptions([]string{})
	if err != nil {
		t.Fatalf("ParseOptions failed: %v", err)
	}
	if options.Namespace != "default" {
		t.Errorf("expected default namespace 'default', got %q", options.Namespace)
	}
	if options.SecretName != "localgateway-dns" {
		t.Errorf("expected default secret name 'localgateway-dns', got %q", options.SecretName)
	}
	if options.MDNSPort != 5353 {
		t.Errorf("expected default mDNS port 5353, got %d", options.MDNSPort)
	}

	// Explicit flags
	options, err = ParseOptions([]string{
		"--secret-namespace=custom-namespace",
		"--secret-name=custom-secret",
		"--interface=eth0",
		"--mdns-port=5354",
	})
	if err != nil {
		t.Fatalf("ParseOptions failed: %v", err)
	}
	if options.Namespace != "custom-namespace" || options.SecretName != "custom-secret" || options.Interface != "eth0" || options.MDNSPort != 5354 {
		t.Errorf("explicit options mismatch: %+v", options)
	}
}

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

package controller

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func TestGatewayClassReconciler_CustomControllerName(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	gcManaged := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "managed-gc",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "custom.domain/controller",
		},
	}
	gcIgnored := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ignored-gc",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "other.domain/controller",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gcManaged, gcIgnored).
		WithStatusSubresource(gcManaged, gcIgnored).
		Build()

	r := &GatewayClassReconciler{
		Client:         client,
		Scheme:         scheme,
		ControllerName: "custom.domain/controller",
	}

	ctx := t.Context()

	// 1. Reconcile ignored class -> should not update status
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "ignored-gc"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resIgnored gatewayv1.GatewayClass
	_ = client.Get(ctx, types.NamespacedName{Name: "ignored-gc"}, &resIgnored)
	if len(resIgnored.Status.Conditions) != 0 {
		t.Errorf("expected no conditions on ignored GatewayClass, got %d", len(resIgnored.Status.Conditions))
	}

	// 2. Reconcile managed class -> should update status to Accepted
	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "managed-gc"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resManaged gatewayv1.GatewayClass
	_ = client.Get(ctx, types.NamespacedName{Name: "managed-gc"}, &resManaged)
	if len(resManaged.Status.Conditions) == 0 {
		t.Fatalf("expected conditions on managed GatewayClass, got 0")
	}
	if resManaged.Status.Conditions[0].Type != string(gatewayv1.GatewayClassConditionStatusAccepted) ||
		resManaged.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Errorf("expected Accepted=True condition, got %+v", resManaged.Status.Conditions[0])
	}
}

func TestHTTPRouteReconciler_CustomControllerName(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	st := state.NewState()
	p := proxy.NewProxy()

	customController := "custom.domain/controller"

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: "some-gw",
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route).
		WithStatusSubresource(route).
		Build()

	r := &HTTPRouteReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		Proxy:          p,
		ControllerName: customController,
	}

	ctx := t.Context()
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-route"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var updatedRoute gatewayv1.HTTPRoute
	_ = client.Get(ctx, types.NamespacedName{Namespace: "default", Name: "test-route"}, &updatedRoute)
	if len(updatedRoute.Status.Parents) != 1 {
		t.Fatalf("expected 1 parent status, got %d", len(updatedRoute.Status.Parents))
	}
	if string(updatedRoute.Status.Parents[0].ControllerName) != customController {
		t.Errorf("expected ControllerName %q, got %q", customController, updatedRoute.Status.Parents[0].ControllerName)
	}
}

func TestServiceAndSecretAndConfigMapReconcilers(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	st := state.NewState()
	p := proxy.NewProxy()

	hookCalled := false
	onUpdate := func(gws []*gatewayv1.Gateway) {
		hookCalled = true
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-svc",
			Namespace: "default",
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "default",
		},
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-cm",
			Namespace: "default",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(svc, secret, cm).
		Build()

	svcReconciler := &ServiceReconciler{
		Client:           client,
		Scheme:           scheme,
		State:            st,
		Proxy:            p,
		ControllerName:   "test-controller",
		OnGatewaysUpdate: onUpdate,
	}
	secretReconciler := &SecretReconciler{
		Client:           client,
		Scheme:           scheme,
		State:            st,
		Proxy:            p,
		ControllerName:   "test-controller",
		OnGatewaysUpdate: onUpdate,
	}
	cmReconciler := &ConfigMapReconciler{
		Client:           client,
		Scheme:           scheme,
		State:            st,
		Proxy:            p,
		ControllerName:   "test-controller",
		OnGatewaysUpdate: onUpdate,
	}

	ctx := t.Context()

	hookCalled = false
	_, err := svcReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "my-svc"}})
	if err != nil || !hookCalled {
		t.Fatalf("ServiceReconciler failed or hook not called: err=%v, hookCalled=%v", err, hookCalled)
	}

	hookCalled = false
	_, err = secretReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "my-secret"}})
	if err != nil || !hookCalled {
		t.Fatalf("SecretReconciler failed or hook not called: err=%v, hookCalled=%v", err, hookCalled)
	}

	hookCalled = false
	_, err = cmReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "my-cm"}})
	if err != nil || !hookCalled {
		t.Fatalf("ConfigMapReconciler failed or hook not called: err=%v, hookCalled=%v", err, hookCalled)
	}
}

func TestReconcilerSetupWithManager_RequiresControllerName(t *testing.T) {
	reconcilers := []struct {
		name     string
		setupErr error
	}{
		{
			name:     "GatewayClassReconciler",
			setupErr: (&GatewayClassReconciler{}).SetupWithManager(nil),
		},
		{
			name:     "GatewayReconciler",
			setupErr: (&GatewayReconciler{}).SetupWithManager(nil),
		},
		{
			name:     "HTTPRouteReconciler",
			setupErr: (&HTTPRouteReconciler{}).SetupWithManager(nil),
		},
		{
			name:     "BackendTLSPolicyReconciler",
			setupErr: (&BackendTLSPolicyReconciler{}).SetupWithManager(nil),
		},
		{
			name:     "ServiceReconciler",
			setupErr: (&ServiceReconciler{}).SetupWithManager(nil),
		},
		{
			name:     "ConfigMapReconciler",
			setupErr: (&ConfigMapReconciler{}).SetupWithManager(nil),
		},
		{
			name:     "SecretReconciler",
			setupErr: (&SecretReconciler{}).SetupWithManager(nil),
		},
		{
			name:     "ReferenceGrantReconciler",
			setupErr: (&ReferenceGrantReconciler{}).SetupWithManager(nil),
		},
	}

	for _, tc := range reconcilers {
		if tc.setupErr == nil {
			t.Errorf("%s: expected error when ControllerName is empty, got nil", tc.name)
		}
	}
}

func generateTestCertPEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM
}

func TestGatewayReconciler_TLSReferenceGrant(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)
	_ = gatewayv1beta1.AddToScheme(scheme)

	st := state.NewState()
	p := proxy.NewProxy()

	certPEM, keyPEM := generateTestCertPEM(t)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-cert",
			Namespace: "secret-ns",
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}
	st.UpsertSecret(secret)

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-gc",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "gw-ns",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-gc",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{
								Namespace: state.Ptr(gatewayv1.Namespace("secret-ns")),
								Name:      "my-cert",
							},
						},
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw, secret).
		WithStatusSubresource(gw).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		Proxy:          p,
		ControllerName: "test-controller",
	}

	ctx := t.Context()

	// 1. Reconcile without ReferenceGrant -> ResolvedRefs should be False / RefNotPermitted
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "gw-ns", Name: "test-gw"}})
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}

	var reconciledGW gatewayv1.Gateway
	if err := client.Get(ctx, types.NamespacedName{Namespace: "gw-ns", Name: "test-gw"}, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}

	if len(reconciledGW.Status.Listeners) != 1 {
		t.Fatalf("expected 1 listener status, got %d", len(reconciledGW.Status.Listeners))
	}
	resolvedRefsCond := findCondition(reconciledGW.Status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
	if resolvedRefsCond == nil {
		t.Fatalf("expected ResolvedRefs condition on listener, got none")
	}
	if resolvedRefsCond.Status != metav1.ConditionFalse || resolvedRefsCond.Reason != string(gatewayv1.ListenerReasonRefNotPermitted) {
		t.Errorf("expected ResolvedRefs=False/RefNotPermitted, got Status=%s, Reason=%s", resolvedRefsCond.Status, resolvedRefsCond.Reason)
	}

	// 2. Add ReferenceGrant permitting Gateway in gw-ns to access Secret in secret-ns
	rg := &gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-gw-secret",
			Namespace: "secret-ns",
		},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{
					Group:     gatewayv1.GroupName,
					Kind:      "Gateway",
					Namespace: "gw-ns",
				},
			},
			To: []gatewayv1beta1.ReferenceGrantTo{
				{
					Group: "",
					Kind:  "Secret",
					Name:  state.Ptr(gatewayv1.ObjectName("my-cert")),
				},
			},
		},
	}
	st.UpsertReferenceGrant(rg)

	// Reconcile again -> ResolvedRefs should be True
	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "gw-ns", Name: "test-gw"}})
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}

	if err := client.Get(ctx, types.NamespacedName{Namespace: "gw-ns", Name: "test-gw"}, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}

	resolvedRefsCond = findCondition(reconciledGW.Status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
	if resolvedRefsCond == nil {
		t.Fatalf("expected ResolvedRefs condition on listener, got none")
	}
	if resolvedRefsCond.Status != metav1.ConditionTrue || resolvedRefsCond.Reason != string(gatewayv1.ListenerReasonResolvedRefs) {
		t.Errorf("expected ResolvedRefs=True/ResolvedRefs, got Status=%s, Reason=%s", resolvedRefsCond.Status, resolvedRefsCond.Reason)
	}
}

func TestGatewayClassReconciler_ParametersRefAndGeneration(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	gcInvalidParams := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "invalid-params-gc",
			Generation: 1,
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
			ParametersRef: &gatewayv1.ParametersReference{
				Group: "example.com",
				Kind:  "Config",
				Name:  "some-config",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gcInvalidParams).
		WithStatusSubresource(gcInvalidParams).
		Build()

	r := &GatewayClassReconciler{
		Client:         client,
		Scheme:         scheme,
		ControllerName: "test-controller",
	}

	ctx := t.Context()

	// Reconcile -> Accepted should be False / InvalidParameters
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "invalid-params-gc"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var res gatewayv1.GatewayClass
	if err := client.Get(ctx, types.NamespacedName{Name: "invalid-params-gc"}, &res); err != nil {
		t.Fatalf("failed to get GatewayClass: %v", err)
	}
	cond := findCondition(res.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusAccepted))
	if cond == nil {
		t.Fatalf("expected Accepted condition on GatewayClass, got none")
	}
	if cond.Status != metav1.ConditionFalse || cond.Reason != string(gatewayv1.GatewayClassReasonInvalidParameters) {
		t.Errorf("expected Accepted=False/InvalidParameters, got Status=%s, Reason=%s", cond.Status, cond.Reason)
	}
	if cond.ObservedGeneration != 1 {
		t.Errorf("expected ObservedGeneration=1, got %d", cond.ObservedGeneration)
	}

	// Update spec to remove ParametersRef and increment generation
	res.Spec.ParametersRef = nil
	res.Generation = 2
	if err := client.Update(ctx, &res); err != nil {
		t.Fatalf("failed to update GatewayClass: %v", err)
	}

	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "invalid-params-gc"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := client.Get(ctx, types.NamespacedName{Name: "invalid-params-gc"}, &res); err != nil {
		t.Fatalf("failed to get GatewayClass: %v", err)
	}
	cond = findCondition(res.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusAccepted))
	if cond == nil {
		t.Fatalf("expected Accepted condition on GatewayClass, got none")
	}
	if cond.Status != metav1.ConditionTrue || cond.Reason != string(gatewayv1.GatewayClassReasonAccepted) {
		t.Errorf("expected Accepted=True/Accepted, got Status=%s, Reason=%s", cond.Status, cond.Reason)
	}
	if cond.ObservedGeneration != 2 {
		t.Errorf("expected ObservedGeneration=2, got %d", cond.ObservedGeneration)
	}
}

func TestGatewayReconciler_InvalidParametersRef(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	st := state.NewState()
	p := proxy.NewProxy()

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-gc"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gw",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-gc",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				ParametersRef: &gatewayv1.LocalParametersReference{
					Group: "invalid.io",
					Kind:  "InvalidParameters",
					Name:  "invalid",
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw).
		WithStatusSubresource(gw).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		Proxy:          p,
		ControllerName: "test-controller",
	}

	ctx := t.Context()
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var res gatewayv1.Gateway
	if err := client.Get(ctx, types.NamespacedName{Namespace: "default", Name: "test-gw"}, &res); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}

	acceptedCond := findCondition(res.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if acceptedCond == nil {
		t.Fatalf("expected Accepted condition on Gateway, got none")
	}
	if acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.GatewayReasonInvalidParameters) {
		t.Errorf("expected Accepted=False/InvalidParameters, got Status=%s, Reason=%s", acceptedCond.Status, acceptedCond.Reason)
	}

	progCond := findCondition(res.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil {
		t.Fatalf("expected Programmed condition on Gateway, got none")
	}
	if progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.GatewayReasonInvalid) {
		t.Errorf("expected Programmed=False/Invalid, got Status=%s, Reason=%s", progCond.Status, progCond.Reason)
	}
}

func TestGatewayReconciler_UnsupportedProtocol(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	st := state.NewState()
	p := proxy.NewProxy()

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-gc"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	// 1. Gateway with only unsupported protocol
	gwOnlyUnsupported := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "gw-unsupported",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-gc",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "invalid",
					Port:     1111,
					Protocol: "INVALID",
				},
			},
		},
	}

	// 2. Gateway with mixed supported and unsupported protocols
	gwMixed := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "gw-mixed",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-gc",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
				{
					Name:     "invalid",
					Port:     1111,
					Protocol: "INVALID",
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gwOnlyUnsupported, gwMixed).
		WithStatusSubresource(gwOnlyUnsupported, gwMixed).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		Proxy:          p,
		ControllerName: "test-controller",
	}

	ctx := t.Context()

	// Reconcile gw-unsupported -> Gateway Accepted=False / ListenersNotValid
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "gw-unsupported"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var res1 gatewayv1.Gateway
	if err := client.Get(ctx, types.NamespacedName{Namespace: "default", Name: "gw-unsupported"}, &res1); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}
	gwCond1 := findCondition(res1.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if gwCond1 == nil || gwCond1.Status != metav1.ConditionFalse || gwCond1.Reason != string(gatewayv1.GatewayReasonListenersNotValid) {
		t.Errorf("expected Gateway Accepted=False/ListenersNotValid, got %+v", gwCond1)
	}
	if len(res1.Status.Listeners) != 1 {
		t.Fatalf("expected 1 listener status, got %d", len(res1.Status.Listeners))
	}
	if len(res1.Status.Listeners[0].SupportedKinds) != 0 {
		t.Errorf("expected empty SupportedKinds, got %+v", res1.Status.Listeners[0].SupportedKinds)
	}
	lCond1 := findCondition(res1.Status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionAccepted))
	if lCond1 == nil || lCond1.Status != metav1.ConditionFalse || lCond1.Reason != string(gatewayv1.ListenerReasonUnsupportedProtocol) {
		t.Errorf("expected Listener Accepted=False/UnsupportedProtocol, got %+v", lCond1)
	}

	// Reconcile gw-mixed -> Gateway Accepted=True / ListenersNotValid
	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "gw-mixed"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var res2 gatewayv1.Gateway
	if err := client.Get(ctx, types.NamespacedName{Namespace: "default", Name: "gw-mixed"}, &res2); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}
	gwCond2 := findCondition(res2.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if gwCond2 == nil || gwCond2.Status != metav1.ConditionTrue || gwCond2.Reason != string(gatewayv1.GatewayReasonListenersNotValid) {
		t.Errorf("expected Gateway Accepted=True/ListenersNotValid, got %+v", gwCond2)
	}
	if len(res2.Status.Listeners) != 2 {
		t.Fatalf("expected 2 listener statuses, got %d", len(res2.Status.Listeners))
	}
	lHttp := res2.Status.Listeners[0]
	lHttpCond := findCondition(lHttp.Conditions, string(gatewayv1.ListenerConditionAccepted))
	if lHttpCond == nil || lHttpCond.Status != metav1.ConditionTrue || lHttpCond.Reason != string(gatewayv1.ListenerReasonAccepted) {
		t.Errorf("expected HTTP Listener Accepted=True/Accepted, got %+v", lHttpCond)
	}
	if len(lHttp.SupportedKinds) != 1 || lHttp.SupportedKinds[0].Kind != "HTTPRoute" {
		t.Errorf("expected SupportedKinds=[HTTPRoute], got %+v", lHttp.SupportedKinds)
	}

	lInvalid := res2.Status.Listeners[1]
	lInvalidCond := findCondition(lInvalid.Conditions, string(gatewayv1.ListenerConditionAccepted))
	if lInvalidCond == nil || lInvalidCond.Status != metav1.ConditionFalse || lInvalidCond.Reason != string(gatewayv1.ListenerReasonUnsupportedProtocol) {
		t.Errorf("expected Invalid Listener Accepted=False/UnsupportedProtocol, got %+v", lInvalidCond)
	}
	if len(lInvalid.SupportedKinds) != 0 {
		t.Errorf("expected empty SupportedKinds on invalid listener, got %+v", lInvalid.SupportedKinds)
	}
}

func TestGatewayReconciler_InvalidRouteKind(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	st := state.NewState()
	p := proxy.NewProxy()

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-gc"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	// 1. Gateway with only invalid route kind
	gwOnlyInvalid := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "gw-only-invalid",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-gc",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{
							{Kind: "InvalidRoute"},
						},
					},
				},
			},
		},
	}

	// 2. Gateway with both valid and invalid route kinds
	gwSupportedAndInvalid := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "gw-supported-and-invalid",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-gc",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{
							{Kind: "InvalidRoute"},
							{Kind: "HTTPRoute"},
						},
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gwOnlyInvalid, gwSupportedAndInvalid).
		WithStatusSubresource(gwOnlyInvalid, gwSupportedAndInvalid).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		Proxy:          p,
		ControllerName: "test-controller",
	}

	ctx := t.Context()

	// Reconcile gw-only-invalid
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "gw-only-invalid"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var res1 gatewayv1.Gateway
	if err := client.Get(ctx, types.NamespacedName{Namespace: "default", Name: "gw-only-invalid"}, &res1); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}
	if len(res1.Status.Listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(res1.Status.Listeners))
	}
	if len(res1.Status.Listeners[0].SupportedKinds) != 0 {
		t.Errorf("expected empty SupportedKinds, got %+v", res1.Status.Listeners[0].SupportedKinds)
	}
	cond1 := findCondition(res1.Status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
	if cond1 == nil || cond1.Status != metav1.ConditionFalse || cond1.Reason != string(gatewayv1.ListenerReasonInvalidRouteKinds) {
		t.Errorf("expected ResolvedRefs=False/InvalidRouteKinds, got %+v", cond1)
	}

	// Reconcile gw-supported-and-invalid
	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "gw-supported-and-invalid"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var res2 gatewayv1.Gateway
	if err := client.Get(ctx, types.NamespacedName{Namespace: "default", Name: "gw-supported-and-invalid"}, &res2); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}
	if len(res2.Status.Listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(res2.Status.Listeners))
	}
	if len(res2.Status.Listeners[0].SupportedKinds) != 1 || res2.Status.Listeners[0].SupportedKinds[0].Kind != "HTTPRoute" {
		t.Errorf("expected SupportedKinds=[HTTPRoute], got %+v", res2.Status.Listeners[0].SupportedKinds)
	}
	cond2 := findCondition(res2.Status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
	if cond2 == nil || cond2.Status != metav1.ConditionFalse || cond2.Reason != string(gatewayv1.ListenerReasonInvalidRouteKinds) {
		t.Errorf("expected ResolvedRefs=False/InvalidRouteKinds, got %+v", cond2)
	}
}

func findCondition(conditions []metav1.Condition, condType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}

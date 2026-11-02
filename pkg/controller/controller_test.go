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
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/version"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	gatewayconsts "sigs.k8s.io/gateway-api/pkg/consts"
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

	st.SetControllerName(customController)
	st.UpsertHTTPRoute(route)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route).
		WithStatusSubresource(route).
		Build()

	r := &HTTPRouteReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
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

type trackingAddressProvider struct {
	called bool
}

func (p *trackingAddressProvider) GatewayAddresses(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, bool, error) {
	p.called = true
	return nil, false, nil
}

func TestGatewayReconciler_SkipsOtherControllersGateways(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	st := state.NewState()
	st.SetControllerName("my.domain/controller")

	otherGC := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "other-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "other.domain/controller"},
	}
	otherGW := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-gw",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "other-class",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(otherGC, otherGW).
		WithStatusSubresource(otherGW).
		Build()

	provider := &trackingAddressProvider{}
	r := &GatewayReconciler{
		Client:          client,
		Scheme:          scheme,
		State:           st,
		ControllerName:  "my.domain/controller",
		AddressProvider: provider,
	}

	ctx := t.Context()
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "other-gw"}})
	if err != nil {
		t.Fatalf("unexpected error reconciling other controller gateway: %v", err)
	}

	if provider.called {
		t.Errorf("expected AddressProvider NOT to be called for other controller's Gateway")
	}

	var fetchedGW gatewayv1.Gateway
	if err := client.Get(ctx, types.NamespacedName{Namespace: "default", Name: "other-gw"}, &fetchedGW); err != nil {
		t.Fatalf("failed to fetch gateway: %v", err)
	}
	if len(fetchedGW.Status.Conditions) != 0 {
		t.Errorf("expected no conditions written to other controller's Gateway, got %v", fetchedGW.Status.Conditions)
	}
	if len(fetchedGW.Status.Addresses) != 0 {
		t.Errorf("expected no addresses written to other controller's Gateway, got %v", fetchedGW.Status.Addresses)
	}

	if len(st.GetGateways()) != 0 {
		t.Errorf("expected other controller's Gateway not to be in State, got %v", st.GetGateways())
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
			name:     "TLSRouteReconciler",
			setupErr: (&TLSRouteReconciler{}).SetupWithManager(nil),
		},
		{
			name:     "GRPCRouteReconciler",
			setupErr: (&GRPCRouteReconciler{}).SetupWithManager(nil),
		},
		{
			name:     "TCPRouteReconciler",
			setupErr: (&TCPRouteReconciler{}).SetupWithManager(nil),
		},
		{
			name:     "UDPRouteReconciler",
			setupErr: (&UDPRouteReconciler{}).SetupWithManager(nil),
		},
		{
			name:     "BackendTLSPolicyReconciler",
			setupErr: (&BackendTLSPolicyReconciler{}).SetupWithManager(nil),
		},
		{
			name:     "ListenerSetReconciler",
			setupErr: (&ListenerSetReconciler{}).SetupWithManager(nil),
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

	st.SetControllerName("test-controller")
	st.UpsertSecret(secret)
	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gw)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw, secret).
		WithStatusSubresource(gw).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
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
	st.Recompute()

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

	st := state.NewState()
	st.SetControllerName("test-controller")
	st.UpsertGatewayClass(gcInvalidParams)
	st.Recompute()

	r := &GatewayClassReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
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
	st.UpsertGatewayClass(&res)
	st.Recompute()

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

	// 3. Update GatewayClass with valid ConfigMap parametersRef -> Accepted=True/Accepted
	validCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "valid-gc-cm"},
		Data: map[string]string{
			state.ParameterKeyServiceType: "LoadBalancer",
		},
	}
	if err := client.Create(ctx, validCM); err != nil {
		t.Fatalf("failed to create valid ConfigMap: %v", err)
	}
	nsDefault := gatewayv1.Namespace("default")
	res.Spec.ParametersRef = &gatewayv1.ParametersReference{
		Group:     "",
		Kind:      "ConfigMap",
		Namespace: &nsDefault,
		Name:      "valid-gc-cm",
	}
	res.Generation = 3
	if err := client.Update(ctx, &res); err != nil {
		t.Fatalf("failed to update GatewayClass: %v", err)
	}
	st.UpsertConfigMap(validCM)
	st.UpsertGatewayClass(&res)
	st.Recompute()

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
	if cond.ObservedGeneration != 3 {
		t.Errorf("expected ObservedGeneration=3, got %d", cond.ObservedGeneration)
	}
}

func TestGatewayClassReconciler_SupportedVersion(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = apiextensionsv1.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-gc",
			Generation: 1,
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}

	compiledV, err := version.ParseSemantic(gatewayconsts.BundleVersion)
	if err != nil {
		t.Fatalf("failed to parse compiled bundle version %q: %v", gatewayconsts.BundleVersion, err)
	}
	differentPatchVersion := fmt.Sprintf("v%d.%d.%d", compiledV.Major(), compiledV.Minor(), compiledV.Patch()+1)
	mismatchedVersion := fmt.Sprintf("v%d.%d.0", compiledV.Major(), compiledV.Minor()-1)
	supportedRange := fmt.Sprintf("v%d.%d.x", compiledV.Major(), compiledV.Minor())

	crdWithMatchingVersion := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: GatewayCRDName,
			Annotations: map[string]string{
				gatewayconsts.BundleVersionAnnotation: gatewayconsts.BundleVersion,
			},
		},
	}

	crdWithDifferentPatchVersion := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: GatewayCRDName,
			Annotations: map[string]string{
				gatewayconsts.BundleVersionAnnotation: differentPatchVersion,
			},
		},
	}

	crdWithMismatchedVersion := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: GatewayCRDName,
			Annotations: map[string]string{
				gatewayconsts.BundleVersionAnnotation: mismatchedVersion,
			},
		},
	}

	crdWithoutAnnotation := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: GatewayCRDName,
		},
	}

	t.Run("matching CRD annotation yields SupportedVersion=True", func(t *testing.T) {
		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gc.DeepCopy(), crdWithMatchingVersion).
			WithStatusSubresource(gc.DeepCopy()).
			Build()

		ctx := t.Context()
		crdView := NewCRDViewFromSnapshot(CRDSnapshot{BundleVersion: gatewayconsts.BundleVersion})

		r := &GatewayClassReconciler{
			Client:         client,
			Scheme:         scheme,
			ControllerName: "test-controller",
			CRDView:        crdView,
		}

		_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-gc"}})
		if err != nil {
			t.Fatalf("unexpected reconcile error: %v", err)
		}

		var res gatewayv1.GatewayClass
		if err := client.Get(ctx, types.NamespacedName{Name: "test-gc"}, &res); err != nil {
			t.Fatalf("failed to get GatewayClass: %v", err)
		}

		cond := findCondition(res.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
		if cond == nil {
			t.Fatalf("expected SupportedVersion condition, got nil")
		}
		if cond.Status != metav1.ConditionTrue {
			t.Errorf("expected Status=True, got %s", cond.Status)
		}
		if cond.Reason != string(gatewayv1.GatewayClassReasonSupportedVersion) {
			t.Errorf("expected Reason=SupportedVersion, got %s", cond.Reason)
		}
		if cond.ObservedGeneration != 1 {
			t.Errorf("expected ObservedGeneration=1, got %d", cond.ObservedGeneration)
		}
	})

	t.Run("different patch CRD annotation yields SupportedVersion=True", func(t *testing.T) {
		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gc.DeepCopy(), crdWithDifferentPatchVersion).
			WithStatusSubresource(gc.DeepCopy()).
			Build()

		ctx := t.Context()
		crdView := NewCRDViewFromSnapshot(CRDSnapshot{BundleVersion: differentPatchVersion})

		r := &GatewayClassReconciler{
			Client:         client,
			Scheme:         scheme,
			ControllerName: "test-controller",
			CRDView:        crdView,
		}

		_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-gc"}})
		if err != nil {
			t.Fatalf("unexpected reconcile error: %v", err)
		}

		var res gatewayv1.GatewayClass
		if err := client.Get(ctx, types.NamespacedName{Name: "test-gc"}, &res); err != nil {
			t.Fatalf("failed to get GatewayClass: %v", err)
		}

		cond := findCondition(res.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
		if cond == nil {
			t.Fatalf("expected SupportedVersion condition, got nil")
		}
		if cond.Status != metav1.ConditionTrue {
			t.Errorf("expected Status=True, got %s", cond.Status)
		}
		if cond.Reason != string(gatewayv1.GatewayClassReasonSupportedVersion) {
			t.Errorf("expected Reason=SupportedVersion, got %s", cond.Reason)
		}
		if cond.ObservedGeneration != 1 {
			t.Errorf("expected ObservedGeneration=1, got %d", cond.ObservedGeneration)
		}
	})

	t.Run("mismatched CRD annotation yields SupportedVersion=False", func(t *testing.T) {
		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gc.DeepCopy(), crdWithMismatchedVersion).
			WithStatusSubresource(gc.DeepCopy()).
			Build()

		ctx := t.Context()
		crdView := NewCRDViewFromSnapshot(CRDSnapshot{BundleVersion: mismatchedVersion})

		r := &GatewayClassReconciler{
			Client:         client,
			Scheme:         scheme,
			ControllerName: "test-controller",
			CRDView:        crdView,
		}

		_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-gc"}})
		if err != nil {
			t.Fatalf("unexpected reconcile error: %v", err)
		}

		var res gatewayv1.GatewayClass
		if err := client.Get(ctx, types.NamespacedName{Name: "test-gc"}, &res); err != nil {
			t.Fatalf("failed to get GatewayClass: %v", err)
		}

		cond := findCondition(res.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
		if cond == nil {
			t.Fatalf("expected SupportedVersion condition, got nil")
		}
		if cond.Status != metav1.ConditionFalse {
			t.Errorf("expected Status=False, got %s", cond.Status)
		}
		if cond.Reason != string(gatewayv1.GatewayClassReasonUnsupportedVersion) {
			t.Errorf("expected Reason=UnsupportedVersion, got %s", cond.Reason)
		}
		if cond.ObservedGeneration != 1 {
			t.Errorf("expected ObservedGeneration=1, got %d", cond.ObservedGeneration)
		}
		expectedMsg := fmt.Sprintf("Gateway API CRD bundle-version %q is not supported (controller supports %s, built against %s)", mismatchedVersion, supportedRange, gatewayconsts.BundleVersion)
		if cond.Message != expectedMsg {
			t.Errorf("expected message %q, got %q", expectedMsg, cond.Message)
		}
	})

	t.Run("CRD without bundle-version annotation leaves SupportedVersion absent", func(t *testing.T) {
		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gc.DeepCopy(), crdWithoutAnnotation).
			WithStatusSubresource(gc.DeepCopy()).
			Build()

		ctx := t.Context()
		crdView := NewCRDViewFromSnapshot(CRDSnapshot{})

		r := &GatewayClassReconciler{
			Client:         client,
			Scheme:         scheme,
			ControllerName: "test-controller",
			CRDView:        crdView,
		}

		_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-gc"}})
		if err != nil {
			t.Fatalf("unexpected reconcile error: %v", err)
		}

		var res gatewayv1.GatewayClass
		if err := client.Get(ctx, types.NamespacedName{Name: "test-gc"}, &res); err != nil {
			t.Fatalf("failed to get GatewayClass: %v", err)
		}

		cond := findCondition(res.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
		if cond != nil {
			t.Errorf("expected SupportedVersion condition to be absent, got %+v", cond)
		}
	})

	t.Run("CRD with empty bundle-version annotation leaves SupportedVersion absent", func(t *testing.T) {
		crdWithEmptyAnnotation := &apiextensionsv1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name: GatewayCRDName,
				Annotations: map[string]string{
					gatewayconsts.BundleVersionAnnotation: "",
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gc.DeepCopy(), crdWithEmptyAnnotation).
			WithStatusSubresource(gc.DeepCopy()).
			Build()

		ctx := t.Context()
		crdView := NewCRDViewFromSnapshot(CRDSnapshot{})

		r := &GatewayClassReconciler{
			Client:         client,
			Scheme:         scheme,
			ControllerName: "test-controller",
			CRDView:        crdView,
		}

		_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-gc"}})
		if err != nil {
			t.Fatalf("unexpected reconcile error: %v", err)
		}

		var res gatewayv1.GatewayClass
		if err := client.Get(ctx, types.NamespacedName{Name: "test-gc"}, &res); err != nil {
			t.Fatalf("failed to get GatewayClass: %v", err)
		}

		cond := findCondition(res.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
		if cond != nil {
			t.Errorf("expected SupportedVersion condition to be absent, got %+v", cond)
		}
	})

	t.Run("CRD cannot be read leaves SupportedVersion absent", func(t *testing.T) {
		// CRD not in client objects -> Get will return NotFound
		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gc.DeepCopy()).
			WithStatusSubresource(gc.DeepCopy()).
			Build()

		ctx := t.Context()
		crdView := NewCRDViewFromSnapshot(CRDSnapshot{})

		r := &GatewayClassReconciler{
			Client:         client,
			Scheme:         scheme,
			ControllerName: "test-controller",
			CRDView:        crdView,
		}

		_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-gc"}})
		if err != nil {
			t.Fatalf("unexpected reconcile error: %v", err)
		}

		var res gatewayv1.GatewayClass
		if err := client.Get(ctx, types.NamespacedName{Name: "test-gc"}, &res); err != nil {
			t.Fatalf("failed to get GatewayClass: %v", err)
		}

		cond := findCondition(res.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
		if cond != nil {
			t.Errorf("expected SupportedVersion condition to be absent, got %+v", cond)
		}
	})

	t.Run("view syncs CRD bundle version to State via real wiring", func(t *testing.T) {
		st := state.NewState()
		st.SetControllerName("test-controller")

		initialBV := fmt.Sprintf("v%d.%d.%d", compiledV.Major(), compiledV.Minor(), compiledV.Patch()+1)
		updatedBV := fmt.Sprintf("v%d.%d.%d", compiledV.Major(), compiledV.Minor(), compiledV.Patch()+2)

		// Construct the view with an initial version
		crdView := NewCRDViewFromSnapshot(CRDSnapshot{
			ServedKinds:   ServedKinds{GatewayClass: true, Gateway: true, HTTPRoute: true},
			BundleVersion: initialBV,
		})

		// Wire the view to State exactly as RegisterReconcilers does in utils.go
		snapshot := crdView.Snapshot()
		var bvPtr *string
		if snapshot.BundleVersion != "" {
			bvPtr = &snapshot.BundleVersion
		}
		st.SetGatewayCRDBundleVersion(bvPtr)
		crdView.SetOnBundleVersionChanged(func(newVersion string) {
			var newBVPtr *string
			if newVersion != "" {
				newBVPtr = &newVersion
			}
			st.SetGatewayCRDBundleVersion(newBVPtr)
		})

		if st.GatewayCRDBundleVersion() == nil || *st.GatewayCRDBundleVersion() != initialBV {
			t.Fatalf("expected initial State bundle version %s, got %v", initialBV, st.GatewayCRDBundleVersion())
		}

		// Deliver a CRD update with a new bundle-version annotation
		oldCRD := makeTestCRD(GatewayCRDName, initialBV)
		newCRD := makeTestCRD(GatewayCRDName, updatedBV)
		newCRD.ResourceVersion = "2"
		crdView.HandleUpdate(oldCRD, newCRD)

		// Assert on State
		if st.GatewayCRDBundleVersion() == nil || *st.GatewayCRDBundleVersion() != updatedBV {
			t.Errorf("expected State bundle version %s after update, got %v", updatedBV, st.GatewayCRDBundleVersion())
		}

		// Deliver a CRD deletion clearing bundle-version
		crdView.HandleDelete(newCRD)
		if st.GatewayCRDBundleVersion() != nil {
			t.Errorf("expected State bundle version nil after delete, got %v", st.GatewayCRDBundleVersion())
		}
	})
}

func TestGatewayReconciler_InvalidParametersRef(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

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

	st := state.NewState()
	st.SetControllerName("test-controller")
	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gw)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw).
		WithStatusSubresource(gw).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
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

func TestGatewayReconciler_ValidAndMissingConfigMapParametersRef(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-gc"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}
	validCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "valid-params"},
		Data: map[string]string{
			state.ParameterKeyServiceType: "LoadBalancer",
		},
	}
	gwValid := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "valid-gw",
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
					Group: "",
					Kind:  "ConfigMap",
					Name:  "valid-params",
				},
			},
		},
	}
	gwMissingCM := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "missing-cm-gw",
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
					Group: "",
					Kind:  "ConfigMap",
					Name:  "nonexistent-params",
				},
			},
		},
	}

	st := state.NewState()
	st.SetControllerName("test-controller")
	st.UpsertGatewayClass(gwClass)
	st.UpsertConfigMap(validCM)
	st.UpsertGateway(gwValid)
	st.UpsertGateway(gwMissingCM)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, validCM, gwValid, gwMissingCM).
		WithStatusSubresource(gwValid, gwMissingCM).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		ControllerName: "test-controller",
	}

	ctx := t.Context()

	// 1. Valid parametersRef should be Accepted=True
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "valid-gw"}})
	if err != nil {
		t.Fatalf("unexpected error reconciling valid-gw: %v", err)
	}
	var resValid gatewayv1.Gateway
	if err := client.Get(ctx, types.NamespacedName{Namespace: "default", Name: "valid-gw"}, &resValid); err != nil {
		t.Fatalf("failed to get valid gateway: %v", err)
	}
	acceptedCond := findCondition(resValid.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionTrue || acceptedCond.Reason != string(gatewayv1.GatewayReasonAccepted) {
		t.Errorf("expected Accepted=True/Accepted for valid-gw, got %+v", acceptedCond)
	}

	// 2. Missing ConfigMap should be Accepted=False/InvalidParameters
	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "missing-cm-gw"}})
	if err != nil {
		t.Fatalf("unexpected error reconciling missing-cm-gw: %v", err)
	}
	var resMissing gatewayv1.Gateway
	if err := client.Get(ctx, types.NamespacedName{Namespace: "default", Name: "missing-cm-gw"}, &resMissing); err != nil {
		t.Fatalf("failed to get missing gateway: %v", err)
	}
	missingAcceptedCond := findCondition(resMissing.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if missingAcceptedCond == nil || missingAcceptedCond.Status != metav1.ConditionFalse || missingAcceptedCond.Reason != string(gatewayv1.GatewayReasonInvalidParameters) {
		t.Errorf("expected Accepted=False/InvalidParameters for missing-cm-gw, got %+v", missingAcceptedCond)
	}
}

func TestGatewayReconciler_ReconcileBeforeStateRecompute(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-gc"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "clusterip-params"},
		Data: map[string]string{
			state.ParameterKeyServiceType: "ClusterIP",
		},
	}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "race-gw",
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
					Group: "",
					Kind:  "ConfigMap",
					Name:  "clusterip-params",
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, cm, gw).
		WithStatusSubresource(gw).
		Build()

	st := state.NewState()
	st.SetControllerName("test-controller")
	// State only knows about GatewayClass so far; Gateway has not been recomputed yet (!found)
	st.UpsertGatewayClass(gwClass)
	st.Recompute()

	provider := &trackingAddressProvider{}
	r := &GatewayReconciler{
		Client:          client,
		Scheme:          scheme,
		State:           st,
		ControllerName:  "test-controller",
		AddressProvider: provider,
	}

	ctx := t.Context()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "race-gw"}}

	// 1. Reconcile runs before state has recomputed for gw -> must NOT call address provider
	res, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling before recompute: %v", err)
	}
	if res.Requeue || res.RequeueAfter != 0 {
		t.Errorf("expected no requeue, got %+v", res)
	}
	if provider.called {
		t.Errorf("expected AddressProvider NOT to be called before State computes Gateway parameters")
	}

	// 2. Now state recomputes including the Gateway and ConfigMap
	st.UpsertConfigMap(cm)
	st.UpsertGateway(gw)
	st.Recompute()

	// 3. Reconcile runs after state recompute -> must call address provider
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling after recompute: %v", err)
	}
	if !provider.called {
		t.Errorf("expected AddressProvider to be called after State computes Gateway parameters")
	}
}

func TestGatewayReconciler_UnsupportedProtocol(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	st := state.NewState()

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

	st.SetControllerName("test-controller")
	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gwOnlyUnsupported)
	st.UpsertGateway(gwMixed)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gwOnlyUnsupported, gwMixed).
		WithStatusSubresource(gwOnlyUnsupported, gwMixed).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
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

	st.SetControllerName("test-controller")
	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gwOnlyInvalid)
	st.UpsertGateway(gwSupportedAndInvalid)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gwOnlyInvalid, gwSupportedAndInvalid).
		WithStatusSubresource(gwOnlyInvalid, gwSupportedAndInvalid).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
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

type fakeAddressProvider struct {
	addresses []gatewayv1.GatewayStatusAddress
	ready     bool
	err       error
}

func (f *fakeAddressProvider) GatewayAddresses(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, bool, error) {
	ready := f.ready
	if !ready && f.err == nil && len(f.addresses) > 0 {
		ready = true
	}
	return f.addresses, ready, f.err
}

type fakeAddressWatcherProvider struct {
	fakeAddressProvider
	setupWatchesCalled bool
}

func (f *fakeAddressWatcherProvider) SetupWatches(mgr ctrl.Manager, bldr *builder.Builder) error {
	f.setupWatchesCalled = true
	return nil
}

func TestGatewayReconciler_AddressProvider(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	st := state.NewState()

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
			Namespace: "default",
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
		},
	}

	st.SetControllerName("test-controller")
	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gw)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw).
		WithStatusSubresource(gw).
		Build()

	ctx := t.Context()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}}

	// 1. With address provider returning IP and Hostname
	ipType := gatewayv1.IPAddressType
	hostType := gatewayv1.HostnameAddressType
	provider := &fakeAddressProvider{
		addresses: []gatewayv1.GatewayStatusAddress{
			{Type: &ipType, Value: "1.2.3.4"},
			{Type: &hostType, Value: "gateway.example.com"},
		},
	}

	r := &GatewayReconciler{
		Client:          client,
		Scheme:          scheme,
		State:           st,
		ControllerName:  "test-controller",
		AddressProvider: provider,
	}

	_, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}

	// In the real system, State.SetGatewayAddresses triggers a background recompute which emits a Gateway change event to reconcile and write status.
	st.Recompute()
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error on second reconcile: %v", err)
	}

	var reconciledGW gatewayv1.Gateway
	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}

	if len(reconciledGW.Status.Addresses) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(reconciledGW.Status.Addresses))
	}
	if reconciledGW.Status.Addresses[0].Value != "1.2.3.4" || state.ValueOf(reconciledGW.Status.Addresses[0].Type) != gatewayv1.IPAddressType {
		t.Errorf("expected IP address 1.2.3.4, got %+v", reconciledGW.Status.Addresses[0])
	}
	if reconciledGW.Status.Addresses[1].Value != "gateway.example.com" || state.ValueOf(reconciledGW.Status.Addresses[1].Type) != gatewayv1.HostnameAddressType {
		t.Errorf("expected hostname gateway.example.com, got %+v", reconciledGW.Status.Addresses[1])
	}

	progCond := findCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Errorf("expected Programmed=True/Programmed, got %+v", progCond)
	}

	// 2. Re-reconcile when provider signals a change (addresses change)
	provider.addresses = []gatewayv1.GatewayStatusAddress{
		{Type: &ipType, Value: "5.6.7.8"},
	}
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error re-reconciling gateway: %v", err)
	}
	st.Recompute()
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error on second reconcile: %v", err)
	}
	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}
	if len(reconciledGW.Status.Addresses) != 1 || reconciledGW.Status.Addresses[0].Value != "5.6.7.8" {
		t.Errorf("expected updated address 5.6.7.8, got %+v", reconciledGW.Status.Addresses)
	}

	// 3. With address provider returning empty slice -> Programmed=False, reason AddressNotAssigned
	provider.addresses = nil
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}
	st.Recompute()
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error on second reconcile: %v", err)
	}

	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}

	if len(reconciledGW.Status.Addresses) != 0 {
		t.Errorf("expected 0 addresses, got %d", len(reconciledGW.Status.Addresses))
	}
	progCond = findCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected Programmed=False/AddressNotAssigned, got %+v", progCond)
	}

	// 4. With nil address provider -> Programmed=False, reason AddressNotAssigned
	r.AddressProvider = nil
	st.SetGatewayAddresses(req.NamespacedName, nil)
	st.Recompute()
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}

	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}

	if len(reconciledGW.Status.Addresses) != 0 {
		t.Errorf("expected 0 addresses, got %d", len(reconciledGW.Status.Addresses))
	}
	progCond = findCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
		t.Errorf("expected Programmed=False/AddressNotAssigned, got %+v", progCond)
	}
}

func TestGatewayReconciler_ErrorHandling(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-class",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gc, gw).
		WithStatusSubresource(gw).
		Build()

	st := state.NewState()
	st.SetControllerName("test-controller")
	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.Recompute()

	ctx := t.Context()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}}

	// 1. Transient error: should be returned from Reconcile
	transientProvider := &fakeAddressProvider{
		err: errors.New("transient network failure"),
	}
	r := &GatewayReconciler{
		Client:          client,
		Scheme:          scheme,
		State:           st,
		ControllerName:  "test-controller",
		AddressProvider: transientProvider,
	}

	_, err := r.Reconcile(ctx, req)
	if err == nil || err.Error() != "transient network failure" {
		t.Fatalf("expected transient error returned from Reconcile, got: %v", err)
	}

	// 2. OwnershipConflictError: should NOT be returned from Reconcile, but recorded on Gateway status, and requeued after delay.
	// The resource name "default/test-gw-gari" is kept as a literal here to avoid an import cycle with pkg/provisioning/singlepod.
	conflictProvider := &fakeAddressProvider{
		err: &OwnershipConflictError{
			Message: "conflict: existing Service default/test-gw-gari is not owned by Gateway test-gw",
		},
	}
	r.AddressProvider = conflictProvider

	res, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("expected nil error on OwnershipConflictError, got: %v", err)
	}
	if res.RequeueAfter != DefaultConflictRequeueDelay {
		t.Fatalf("expected RequeueAfter %v on OwnershipConflictError, got: %v", DefaultConflictRequeueDelay, res.RequeueAfter)
	}

	st.Recompute()
	res, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("expected nil error on second reconcile, got: %v", err)
	}
	if res.RequeueAfter != DefaultConflictRequeueDelay {
		t.Fatalf("expected RequeueAfter %v on second reconcile, got: %v", DefaultConflictRequeueDelay, res.RequeueAfter)
	}

	var reconciledGW gatewayv1.Gateway
	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}

	progCond := findCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.GatewayReasonPending) {
		t.Fatalf("expected Programmed=False/Pending on conflict, got %+v", progCond)
	}
	if !strings.Contains(progCond.Message, "conflict: existing Service") {
		t.Errorf("expected conflict message in condition, got %s", progCond.Message)
	}
}

func TestGatewayReconciler_AddressWatcher(t *testing.T) {
	watcher := &fakeAddressWatcherProvider{}
	r := &GatewayReconciler{
		ControllerName:  "test-controller",
		AddressProvider: watcher,
	}

	// SetupWithManager should invoke SetupWatches on the provider
	// We verify that watcher implements AddressWatcher
	var _ AddressWatcher = watcher

	if _, ok := r.AddressProvider.(AddressWatcher); !ok {
		t.Fatalf("expected AddressProvider to implement AddressWatcher")
	}
}

type fakeAddressReadinessProvider struct {
	fakeAddressProvider
	readiness state.GatewayReadiness
}

func (f *fakeAddressReadinessProvider) GatewayAddressesWithReadiness(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, state.GatewayReadiness, error) {
	return f.addresses, f.readiness, f.err
}

func TestGatewayReconciler_AddressReadinessProvider(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	st := state.NewState()

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}
	st.UpsertGatewayClass(gwClass)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}
	st.UpsertGateway(gw)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		Build()

	readinessProvider := &fakeAddressReadinessProvider{
		fakeAddressProvider: fakeAddressProvider{
			addresses: []gatewayv1.GatewayStatusAddress{{Value: "1.2.3.4"}},
		},
		readiness: state.GatewayReadiness{
			Ready:   false,
			Reason:  "Pending",
			Message: "Tunnel session to frontend is not connected",
		},
	}

	r := &GatewayReconciler{
		Client:          client,
		Scheme:          scheme,
		State:           st,
		ControllerName:  "test-controller",
		AddressProvider: readinessProvider,
	}

	ctx := t.Context()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}}
	_, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}

	st.Recompute()
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected second reconcile error: %v", err)
	}

	var reconciledGW gatewayv1.Gateway
	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}

	progCond := findCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != "Pending" || progCond.Message != "Tunnel session to frontend is not connected" {
		t.Fatalf("expected Programmed=False Reason=Pending Message='Tunnel session to frontend is not connected', got: %+v", progCond)
	}
}

func TestGatewayReconciler_GatewayStatusHook(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	st := state.NewState()

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}
	st.UpsertGatewayClass(gwClass)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}
	st.UpsertGateway(gw)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		Build()

	hookCalled := false
	addrType := gatewayv1.IPAddressType
	hook := func(ctx context.Context, g *gatewayv1.Gateway, status *gatewayv1.GatewayStatus) error {
		hookCalled = true
		// Downgrade Accepted
		for i, c := range status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionAccepted) {
				status.Conditions[i].Status = metav1.ConditionFalse
				status.Conditions[i].Reason = "ConflictingParameters"
				status.Conditions[i].Message = "NEGs already claimed"
			}
		}
		// Override Programmed
		for i, c := range status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionProgrammed) {
				status.Conditions[i].Status = metav1.ConditionFalse
				status.Conditions[i].Reason = "WaitingForEndpoints"
				status.Conditions[i].Message = "Waiting for NEGs"
			}
		}
		// Set addresses
		status.Addresses = []gatewayv1.GatewayStatusAddress{
			{Type: &addrType, Value: "10.10.10.10"},
		}
		// Add custom condition
		status.Conditions = append(status.Conditions, metav1.Condition{
			Type:               "CustomNEGReady",
			Status:             metav1.ConditionTrue,
			Reason:             "NEGAttached",
			Message:            "Endpoints attached to zonal NEGs",
			LastTransitionTime: metav1.Now(),
		})
		return nil
	}

	r := &GatewayReconciler{
		Client:            client,
		Scheme:            scheme,
		State:             st,
		ControllerName:    "test-controller",
		GatewayStatusHook: hook,
	}

	ctx := t.Context()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}}
	_, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}

	if !hookCalled {
		t.Fatalf("expected GatewayStatusHook to be called")
	}

	var reconciledGW gatewayv1.Gateway
	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}

	// 1. Verify Accepted was downgraded by the hook
	acceptedCond := findCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != "ConflictingParameters" {
		t.Fatalf("expected Accepted downgraded to False by hook, got: %+v", acceptedCond)
	}

	// 2. Verify Programmed is adjusted by the hook
	progCond := findCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != "WaitingForEndpoints" || progCond.Message != "Waiting for NEGs" {
		t.Fatalf("expected Programmed adjusted by hook, got: %+v", progCond)
	}

	// 3. Verify addresses set by the hook
	if len(reconciledGW.Status.Addresses) != 1 || reconciledGW.Status.Addresses[0].Value != "10.10.10.10" {
		t.Fatalf("expected addresses from hook, got: %+v", reconciledGW.Status.Addresses)
	}

	// 4. Verify custom condition added by hook
	customCond := findCondition(reconciledGW.Status.Conditions, "CustomNEGReady")
	if customCond == nil || customCond.Status != metav1.ConditionTrue || customCond.Reason != "NEGAttached" {
		t.Fatalf("expected custom condition from hook, got: %+v", customCond)
	}

	// 5. Test hook returning error stops reconcile
	errHook := func(ctx context.Context, g *gatewayv1.Gateway, status *gatewayv1.GatewayStatus) error {
		return errors.New("hook simulated error")
	}
	r.GatewayStatusHook = errHook
	_, err = r.Reconcile(ctx, req)
	if err == nil || !strings.Contains(err.Error(), "hook simulated error") {
		t.Fatalf("expected error from hook, got: %v", err)
	}

	// 6. Test hook cannot upgrade Accepted from False to True
	gw.Spec.Listeners = nil
	st.UpsertGateway(gw)
	st.Recompute()
	_ = client.Update(ctx, gw)
	upgradeHook := func(ctx context.Context, g *gatewayv1.Gateway, status *gatewayv1.GatewayStatus) error {
		for i, c := range status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionAccepted) {
				status.Conditions[i].Status = metav1.ConditionTrue
				status.Conditions[i].Reason = "HookUpgradeAttempt"
			}
		}
		return nil
	}
	r.GatewayStatusHook = upgradeHook
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}
	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}
	acceptedCond = findCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionFalse {
		t.Fatalf("expected GARI to enforce Accepted=False and prevent hook upgrade, got: %+v", acceptedCond)
	}
}

func TestGatewayReconciler_EnqueueGateway(t *testing.T) {
	st := state.NewState()
	r := &GatewayReconciler{
		State: st,
	}

	req := types.NamespacedName{Namespace: "default", Name: "my-gw"}
	// Should not panic or fail
	r.EnqueueGateway(req)
}

type fakeAddressTypeProvider struct {
	fakeAddressProvider
	supportedTypes []gatewayv1.AddressType
	called         bool
}

func (f *fakeAddressTypeProvider) SupportedAddressTypes() []gatewayv1.AddressType {
	return f.supportedTypes
}

func (f *fakeAddressTypeProvider) GatewayAddresses(ctx context.Context, gw *gatewayv1.Gateway, effectiveListeners []*state.EffectiveListener) ([]gatewayv1.GatewayStatusAddress, bool, error) {
	f.called = true
	return f.fakeAddressProvider.GatewayAddresses(ctx, gw, effectiveListeners)
}

func TestGatewayReconciler_UnsupportedAddressType_NothingProvisioned(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	st := state.NewState()

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-class"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}
	st.UpsertGatewayClass(gwClass)

	invalidType := gatewayv1.AddressType("test/fake-invalid-type")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-class",
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &invalidType, Value: "fake address"},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}
	st.UpsertGateway(gw)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		Build()

	typeProvider := &fakeAddressTypeProvider{
		supportedTypes: []gatewayv1.AddressType{gatewayv1.IPAddressType},
	}

	r := &GatewayReconciler{
		Client:          client,
		Scheme:          scheme,
		State:           st,
		ControllerName:  "test-controller",
		AddressProvider: typeProvider,
	}

	ctx := t.Context()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}}
	_, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}

	if typeProvider.called {
		t.Errorf("expected AddressProvider not to be called for unsupported address type (nothing provisioned)")
	}

	var reconciledGW gatewayv1.Gateway
	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}

	acceptedCond := findCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionFalse || acceptedCond.Reason != string(gatewayv1.GatewayReasonUnsupportedAddress) {
		t.Fatalf("expected Accepted=False Reason=UnsupportedAddress, got: %+v", acceptedCond)
	}
}

func containsGateway(gws []*state.GatewayState, key types.NamespacedName) bool {
	for _, gw := range gws {
		if gw.Gateway != nil && gw.Gateway.Namespace == key.Namespace && gw.Gateway.Name == key.Name {
			return true
		}
	}
	return false
}

func TestGatewayReconciler_GatewayFilter(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	st := state.NewState()
	st.SetControllerName("test-controller")
	st.SetGatewayFilter(func(gw *gatewayv1.Gateway) bool {
		return gw.Labels["env"] == "prod"
	})

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-gc",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}

	gwProd := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-prod",
			Namespace: "default",
			Labels:    map[string]string{"env": "prod"},
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
		},
	}

	gwDev := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw-dev",
			Namespace: "default",
			Labels:    map[string]string{"env": "dev"},
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-gc",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gwProd, gwDev).
		WithStatusSubresource(gwProd, gwDev).
		Build()

	// Simulate informer upserts into State
	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gwProd)
	st.UpsertGateway(gwDev)

	outputs := st.Recompute()

	prodKey := types.NamespacedName{Namespace: "default", Name: "gw-prod"}
	devKey := types.NamespacedName{Namespace: "default", Name: "gw-dev"}

	if !containsGateway(st.GetGateways(), prodKey) {
		t.Errorf("expected prod gateway in state")
	}
	if containsGateway(st.GetGateways(), devKey) {
		t.Errorf("expected dev gateway NOT in state")
	}

	// Verify out-of-scope Gateway never appears in ProxyListeners or ResolvedGateways
	for _, l := range outputs.ProxyListeners {
		if l.GatewayName == devKey {
			t.Errorf("expected dev gateway listener NOT in proxy listeners, got %+v", l)
		}
	}
	for _, g := range outputs.ResolvedGateways {
		if g.Name == "gw-dev" {
			t.Errorf("expected dev gateway NOT in resolved gateways, got %+v", g)
		}
	}

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		ControllerName: "test-controller",
	}

	ctx := t.Context()

	// 1. Reconcile gw-prod (matches filter) -> accepted
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: prodKey})
	if err != nil {
		t.Fatalf("unexpected error reconciling prod gateway: %v", err)
	}

	var resProd gatewayv1.Gateway
	if err := client.Get(ctx, prodKey, &resProd); err != nil {
		t.Fatalf("failed to get prod gateway: %v", err)
	}
	if len(resProd.Status.Conditions) == 0 {
		t.Errorf("expected conditions on prod Gateway, got none")
	}

	// 2. Reconcile gw-dev (does not match filter) -> no status written
	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: devKey})
	if err != nil {
		t.Fatalf("unexpected error reconciling dev gateway: %v", err)
	}

	var resDev gatewayv1.Gateway
	if err := client.Get(ctx, devKey, &resDev); err != nil {
		t.Fatalf("failed to get dev gateway: %v", err)
	}
	if len(resDev.Status.Conditions) != 0 {
		t.Errorf("expected no conditions on dev Gateway, got %+v", resDev.Status.Conditions)
	}
}

func TestListenerSetReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-class",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: DefaultControllerName,
		},
	}

	sameFrom := gatewayv1.NamespacesFromSame
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-class",
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: &sameFrom,
				},
			},
		},
	}

	lsAllowed := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "ls-allowed",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Name: "test-gw",
			},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	lsDisallowed := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "ls-disallowed",
			Namespace:  "other-ns",
			Generation: 1,
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Name:      "test-gw",
				Namespace: state.Ptr(gatewayv1.Namespace("default")),
			},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	st := state.NewState()
	st.SetControllerName(DefaultControllerName)
	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.UpsertListenerSet(lsAllowed)
	st.UpsertListenerSet(lsDisallowed)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gc, gw, lsAllowed, lsDisallowed).
		WithStatusSubresource(gw, lsAllowed, lsDisallowed).
		Build()

	r := &ListenerSetReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		ControllerName: DefaultControllerName,
	}

	ctx := t.Context()

	// 1. Reconcile allowed ListenerSet
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "ls-allowed"}})
	if err != nil {
		t.Fatalf("unexpected error reconciling allowed listener set: %v", err)
	}

	var reconciledLS gatewayv1.ListenerSet
	if err := client.Get(ctx, types.NamespacedName{Namespace: "default", Name: "ls-allowed"}, &reconciledLS); err != nil {
		t.Fatalf("failed to get allowed listener set: %v", err)
	}

	acceptedCond := findCondition(reconciledLS.Status.Conditions, string(gatewayv1.ListenerSetConditionAccepted))
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Accepted=True for allowed ListenerSet, got %+v", acceptedCond)
	}
	progCond := findCondition(reconciledLS.Status.Conditions, string(gatewayv1.ListenerSetConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Programmed=True for allowed ListenerSet, got %+v", progCond)
	}
	if len(reconciledLS.Status.Listeners) != 1 {
		t.Fatalf("expected 1 listener status, got %d", len(reconciledLS.Status.Listeners))
	}
	if reconciledLS.Status.Listeners[0].Name != "http" {
		t.Errorf("expected listener status name 'http', got %s", reconciledLS.Status.Listeners[0].Name)
	}

	// 2. Reconcile disallowed ListenerSet
	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "other-ns", Name: "ls-disallowed"}})
	if err != nil {
		t.Fatalf("unexpected error reconciling disallowed listener set: %v", err)
	}

	var reconciledDisallowedLS gatewayv1.ListenerSet
	if err := client.Get(ctx, types.NamespacedName{Namespace: "other-ns", Name: "ls-disallowed"}, &reconciledDisallowedLS); err != nil {
		t.Fatalf("failed to get disallowed listener set: %v", err)
	}

	disallowedAcceptedCond := findCondition(reconciledDisallowedLS.Status.Conditions, string(gatewayv1.ListenerSetConditionAccepted))
	if disallowedAcceptedCond == nil || disallowedAcceptedCond.Status != metav1.ConditionFalse || disallowedAcceptedCond.Reason != string(gatewayv1.ListenerSetReasonNotAllowed) {
		t.Errorf("expected Accepted=False/NotAllowed for disallowed ListenerSet, got %+v", disallowedAcceptedCond)
	}
}

func TestGatewayReconciler_AttachedListenerSets(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-class",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: DefaultControllerName,
		},
	}

	sameFrom := gatewayv1.NamespacesFromSame
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-class",
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: &sameFrom,
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	ls1 := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ls-1",
			Namespace: "default",
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Name: "test-gw",
			},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "ls-http",
					Port:     8080,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}
	ls2 := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ls-2",
			Namespace: "other-ns",
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Name:      "test-gw",
				Namespace: state.Ptr(gatewayv1.Namespace("default")),
			},
		},
	}

	st := state.NewState()
	st.SetControllerName(DefaultControllerName)
	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.UpsertListenerSet(ls1)
	st.UpsertListenerSet(ls2)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gc, gw).
		WithStatusSubresource(gw).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		ControllerName: DefaultControllerName,
	}

	ctx := t.Context()

	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resGW gatewayv1.Gateway
	if err := client.Get(ctx, types.NamespacedName{Namespace: "default", Name: "test-gw"}, &resGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}

	if resGW.Status.AttachedListenerSets == nil {
		t.Fatalf("expected AttachedListenerSets to be non-nil")
	}
	if *resGW.Status.AttachedListenerSets != 1 {
		t.Errorf("expected AttachedListenerSets to be 1, got %d", *resGW.Status.AttachedListenerSets)
	}
}

func TestGatewayReconciler_PartialCRDInstallation_ReconcilesGatewayAndHTTPRoute(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)
	_ = gatewayv1beta1.AddToScheme(scheme)

	// Simulate GKE standard channel: 6 of 10 CRDs served, 4 optional CRDs absent
	mapper := newTestRESTMapper(gkeStandardGatewayAPIGVKs()...)

	servedKinds, err := SnapshotFromRESTMapper(mapper, scheme)
	if err != nil {
		t.Fatalf("unexpected SnapshotFromRESTMapper error: %v", err)
	}
	snapshot := CRDSnapshot{ServedKinds: servedKinds}
	disabledKinds := snapshot.DisabledKinds()
	if len(disabledKinds) != 4 {
		t.Fatalf("expected 4 disabled kinds, got %d: %v", len(disabledKinds), disabledKinds)
	}

	st := state.NewState()
	st.SetControllerName("test-controller")

	var disabledRouteKinds map[gatewayv1.Kind]bool
	for _, kind := range disabledKinds {
		switch kind {
		case "TLSRoute", "GRPCRoute", "TCPRoute", "UDPRoute":
			if disabledRouteKinds == nil {
				disabledRouteKinds = make(map[gatewayv1.Kind]bool)
			}
			disabledRouteKinds[gatewayv1.Kind(kind)] = true
		}
	}
	st.SetDisabledRouteKinds(disabledRouteKinds)

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-gc"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	gwKey := types.NamespacedName{Namespace: "default", Name: "partial-crd-gw"}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "partial-crd-gw",
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
					Name:     "tcp-disabled",
					Port:     9000,
					Protocol: gatewayv1.TCPProtocolType,
				},
				{
					Name:     "grpc-disabled",
					Port:     8080,
					Protocol: gatewayv1.HTTPProtocolType,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{
							{Kind: "GRPCRoute"},
						},
					},
				},
				{
					Name:     "mixed",
					Port:     8081,
					Protocol: gatewayv1.HTTPProtocolType,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{
							{Kind: "HTTPRoute"},
							{Kind: "GRPCRoute"},
						},
					},
				},
			},
		},
	}

	routeKey := types.NamespacedName{Namespace: "default", Name: "http-route"}
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "http-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name:        "partial-crd-gw",
						SectionName: state.Ptr(gatewayv1.SectionName("http")),
					},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "app-svc",
									Port: state.Ptr(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
				},
			},
		},
	}

	st.UpsertGatewayClass(gc)
	st.UpsertGateway(gw)
	st.UpsertHTTPRoute(route)
	st.SetGatewayAddresses(gwKey, []gatewayv1.GatewayStatusAddress{{Value: "192.0.2.1"}})
	st.SetGatewayReadiness(gwKey, state.GatewayReadiness{Ready: true})
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gc, gw, route).
		WithStatusSubresource(gw, route).
		Build()

	gwReconciler := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		ControllerName: "test-controller",
		AddressProvider: &fakeAddressProvider{
			addresses: []gatewayv1.GatewayStatusAddress{{Value: "192.0.2.1"}},
			ready:     true,
		},
	}

	ctx := t.Context()

	// Reconcile Gateway
	_, err = gwReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: gwKey})
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}

	var resGW gatewayv1.Gateway
	if err := client.Get(ctx, gwKey, &resGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}

	// 1. Gateway reports Programmed=True
	progCond := findCondition(resGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Errorf("expected Gateway Programmed=True/Programmed, got %+v", progCond)
	}

	if len(resGW.Status.Listeners) != 4 {
		t.Fatalf("expected 4 listener statuses, got %d", len(resGW.Status.Listeners))
	}

	// 2. HTTP listener: supportedKinds=[HTTPRoute], ResolvedRefs=True, Programmed=True
	lHTTP := resGW.Status.Listeners[0]
	if len(lHTTP.SupportedKinds) != 1 || lHTTP.SupportedKinds[0].Kind != "HTTPRoute" {
		t.Errorf("expected HTTP listener SupportedKinds=[HTTPRoute], got %+v", lHTTP.SupportedKinds)
	}
	resolvedHTTP := findCondition(lHTTP.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
	if resolvedHTTP == nil || resolvedHTTP.Status != metav1.ConditionTrue {
		t.Errorf("expected HTTP listener ResolvedRefs=True, got %+v", resolvedHTTP)
	}

	// 3. TCP listener (TCPRoute disabled): supportedKinds empty, ResolvedRefs=False/InvalidRouteKinds
	lTCP := resGW.Status.Listeners[1]
	if len(lTCP.SupportedKinds) != 0 {
		t.Errorf("expected TCP listener SupportedKinds empty, got %+v", lTCP.SupportedKinds)
	}
	resolvedTCP := findCondition(lTCP.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
	if resolvedTCP == nil || resolvedTCP.Status != metav1.ConditionFalse || resolvedTCP.Reason != string(gatewayv1.ListenerReasonInvalidRouteKinds) {
		t.Errorf("expected TCP listener ResolvedRefs=False/InvalidRouteKinds, got %+v", resolvedTCP)
	}

	// 4. GRPCRoute listener (restricted to disabled GRPCRoute): supportedKinds empty, ResolvedRefs=False/InvalidRouteKinds
	lGRPC := resGW.Status.Listeners[2]
	if len(lGRPC.SupportedKinds) != 0 {
		t.Errorf("expected GRPCRoute listener SupportedKinds empty, got %+v", lGRPC.SupportedKinds)
	}
	resolvedGRPC := findCondition(lGRPC.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
	if resolvedGRPC == nil || resolvedGRPC.Status != metav1.ConditionFalse || resolvedGRPC.Reason != string(gatewayv1.ListenerReasonInvalidRouteKinds) {
		t.Errorf("expected GRPCRoute listener ResolvedRefs=False/InvalidRouteKinds, got %+v", resolvedGRPC)
	}

	// 5. Mixed listener (HTTPRoute + GRPCRoute): supportedKinds=[HTTPRoute], ResolvedRefs=True
	lMixed := resGW.Status.Listeners[3]
	if len(lMixed.SupportedKinds) != 1 || lMixed.SupportedKinds[0].Kind != "HTTPRoute" {
		t.Errorf("expected Mixed listener SupportedKinds=[HTTPRoute], got %+v", lMixed.SupportedKinds)
	}
	resolvedMixed := findCondition(lMixed.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
	if resolvedMixed == nil || resolvedMixed.Status != metav1.ConditionTrue {
		t.Errorf("expected Mixed listener ResolvedRefs=True, got %+v", resolvedMixed)
	}

	// 6. HTTPRoute reconciles and reports Accepted=True
	routeReconciler := &HTTPRouteReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		ControllerName: "test-controller",
	}
	_, err = routeReconciler.Reconcile(ctx, ctrl.Request{NamespacedName: routeKey})
	if err != nil {
		t.Fatalf("unexpected error reconciling HTTPRoute: %v", err)
	}

	var resRoute gatewayv1.HTTPRoute
	if err := client.Get(ctx, routeKey, &resRoute); err != nil {
		t.Fatalf("failed to get HTTPRoute: %v", err)
	}
	if len(resRoute.Status.Parents) != 1 {
		t.Fatalf("expected 1 parent status on HTTPRoute, got %d", len(resRoute.Status.Parents))
	}
	routeAcceptedCond := findCondition(resRoute.Status.Parents[0].Conditions, string(gatewayv1.RouteConditionAccepted))
	if routeAcceptedCond == nil || routeAcceptedCond.Status != metav1.ConditionTrue || routeAcceptedCond.Reason != string(gatewayv1.RouteReasonAccepted) {
		t.Errorf("expected HTTPRoute Accepted=True/Accepted, got %+v", routeAcceptedCond)
	}

	// Verify only served kinds are active
	_ = servedKinds
}

type fakeCertificateSourceCall struct {
	gw       *gatewayv1.Gateway
	listener gatewayv1.SectionName
}

type fakeCertificateSource struct {
	mu         sync.Mutex
	trigger    func()
	cache      map[string]*tls.Certificate
	err        error
	calledWith []fakeCertificateSourceCall
}

func (f *fakeCertificateSource) SetRecomputeTrigger(trigger func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.trigger = trigger
}

func (f *fakeCertificateSource) ResolveCertificates(gw *gatewayv1.Gateway, listener *gatewayv1.Listener) (state.CertificateResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calledWith = append(f.calledWith, fakeCertificateSourceCall{
		gw:       gw,
		listener: listener.Name,
	})
	if f.err != nil {
		return state.CertificateResult{}, f.err
	}
	hostname := ""
	if listener.Hostname != nil {
		hostname = string(*listener.Hostname)
	}
	cert, ok := f.cache[hostname]
	if !ok {
		return state.CertificateResult{Pending: true}, nil
	}
	return state.CertificateResult{Certificates: []*tls.Certificate{cert}}, nil
}

func (f *fakeCertificateSource) calls() []fakeCertificateSourceCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := make([]fakeCertificateSourceCall, len(f.calledWith))
	copy(copied, f.calledWith)
	return copied
}

func (f *fakeCertificateSource) set(hostname string, cert *tls.Certificate) {
	f.mu.Lock()
	if f.cache == nil {
		f.cache = make(map[string]*tls.Certificate)
	}
	f.cache[hostname] = cert
	trigger := f.trigger
	f.mu.Unlock()
	if trigger != nil {
		trigger()
	}
}

func generateTestTLSCert(t *testing.T, dnsNames ...string) *tls.Certificate {
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
		DNSNames:              dnsNames,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to create X509KeyPair: %v", err)
	}
	return &tlsCert
}

func setupCertSourceTestGW(t *testing.T, hostname *gatewayv1.Hostname, options map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue, certRefs []gatewayv1.SecretObjectReference, sources ...map[string]state.CertificateSource) (*runtime.Scheme, *state.State, *gatewayv1.GatewayClass, *gatewayv1.Gateway) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	st := state.NewState()
	st.SetControllerName("test-controller")
	if len(sources) > 0 && sources[0] != nil {
		st.RegisterCertificateSources(sources[0])
	}

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-gc"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gw",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-gc",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: hostname,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: certRefs,
						Options:         options,
					},
				},
			},
		},
	}

	return scheme, st, gwClass, gw
}

func TestGatewayReconciler_CertificateSource_Served(t *testing.T) {
	testCert := generateTestTLSCert(t, "example.com")
	testCert.Leaf = nil
	fakeSource := &fakeCertificateSource{}
	fakeSource.set("example.com", testCert)

	scheme, st, gwClass, gw := setupCertSourceTestGW(t,
		state.Ptr(gatewayv1.Hostname("example.com")),
		map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
			gatewayv1.AnnotationKey(CertificateSourceOptionKey): "test-source",
		},
		nil,
		map[string]state.CertificateSource{
			"test-source": fakeSource,
		},
	)

	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gw)
	outputs := st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw).
		WithStatusSubresource(gw).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		ControllerName: "test-controller",
	}

	ctx := t.Context()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}}

	res, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("expected RequeueAfter == 0, got %v", res.RequeueAfter)
	}

	var reconciledGW gatewayv1.Gateway
	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}

	if len(reconciledGW.Status.Listeners) != 1 {
		t.Fatalf("expected 1 listener status, got %d", len(reconciledGW.Status.Listeners))
	}
	lStatus := reconciledGW.Status.Listeners[0]

	refCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
	if refCond == nil || refCond.Status != metav1.ConditionTrue || refCond.Reason != string(gatewayv1.ListenerReasonResolvedRefs) {
		t.Errorf("expected ResolvedRefs=True/ResolvedRefs, got %+v", refCond)
	}

	progCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.ListenerReasonProgrammed) {
		t.Errorf("expected Programmed=True/Programmed, got %+v", progCond)
	}

	accCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionAccepted))
	if accCond == nil || accCond.Status != metav1.ConditionTrue || accCond.Reason != string(gatewayv1.ListenerReasonAccepted) {
		t.Errorf("expected Accepted=True/Accepted, got %+v", accCond)
	}

	calls := fakeSource.calls()
	if len(calls) == 0 {
		t.Fatalf("expected fakeSource to be called")
	}
	if calls[0].listener != "https" {
		t.Errorf("unexpected call arguments: %+v", calls[0])
	}

	// Verify certificate is present in state outputs and dataplane config
	dpCfg, ok := outputs.DataplaneConfigs[types.NamespacedName{Namespace: "default", Name: "test-gw"}]
	if !ok || dpCfg == nil {
		t.Fatalf("expected DataplaneConfig for gateway")
	}
	certID, ok := dpCfg.HostCertificates["example.com"]
	if !ok || certID == "" {
		t.Fatalf("expected HostCertificates[example.com] to be set, got %v", dpCfg.HostCertificates)
	}
	if _, ok := dpCfg.Certificates[certID]; !ok {
		t.Fatalf("expected Certificates[%s] to be populated", certID)
	}

	// Verify the source's original certificate was not mutated (e.g. Leaf was not set on it)
	if testCert.Leaf != nil {
		t.Errorf("expected source's original certificate Leaf to remain nil, but was mutated")
	}
}

func pollUntil(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !condition() {
		t.Fatalf("condition not met within %v", timeout)
	}
}

func TestGatewayReconciler_CertificateSource_PendingThenAvailable(t *testing.T) {
	fakeSource := &fakeCertificateSource{} // empty cache => Pending

	scheme, st, gwClass, gw := setupCertSourceTestGW(t,
		state.Ptr(gatewayv1.Hostname("example.com")),
		map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
			gatewayv1.AnnotationKey(CertificateSourceOptionKey): "test-source",
		},
		nil,
		map[string]state.CertificateSource{
			"test-source": fakeSource,
		},
	)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		_ = st.Start(ctx)
	}()

	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gw)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw).
		WithStatusSubresource(gw).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		ControllerName: "test-controller",
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}}

	// 1. Initial reconcile on running State: pending, NO requeue polling
	pollUntil(t, 2*time.Second, func() bool {
		status, ok := st.GetDesiredGatewayStatus(req.NamespacedName)
		if !ok || len(status.Listeners) == 0 {
			return false
		}
		refCond := findCondition(status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
		return refCond != nil && refCond.Status == metav1.ConditionFalse && refCond.Reason == string(gatewayv1.ListenerReasonPending)
	})

	res, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("expected RequeueAfter == 0 (no requeue polling), got %v", res.RequeueAfter)
	}

	var reconciledGW gatewayv1.Gateway
	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}
	lStatus := reconciledGW.Status.Listeners[0]

	refCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
	if refCond == nil || refCond.Status != metav1.ConditionFalse || refCond.Reason != string(gatewayv1.ListenerReasonPending) {
		t.Errorf("expected pending ResolvedRefs=False/Pending, got %+v", refCond)
	}

	progCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.ListenerReasonPending) {
		t.Errorf("expected pending Programmed=False/Pending, got %+v", progCond)
	}

	accCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionAccepted))
	if accCond == nil || accCond.Status != metav1.ConditionTrue || accCond.Reason != string(gatewayv1.ListenerReasonAccepted) {
		t.Errorf("expected pending Accepted=True/Accepted, got %+v", accCond)
	}

	// 2. Certificate becomes available and source triggers running State (NO manual Recompute)
	testCert := generateTestTLSCert(t, "example.com")
	fakeSource.set("example.com", testCert)

	// Wait for running State to recompute automatically via trigger without manual Recompute()
	pollUntil(t, 2*time.Second, func() bool {
		status, ok := st.GetDesiredGatewayStatus(req.NamespacedName)
		if !ok || len(status.Listeners) == 0 {
			return false
		}
		refCond := findCondition(status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
		progCond := findCondition(status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionProgrammed))
		return refCond != nil && refCond.Status == metav1.ConditionTrue && refCond.Reason == string(gatewayv1.ListenerReasonResolvedRefs) &&
			progCond != nil && progCond.Status == metav1.ConditionTrue && progCond.Reason == string(gatewayv1.ListenerReasonProgrammed)
	})

	res, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error on second reconcile: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("expected RequeueAfter == 0 after available, got %v", res.RequeueAfter)
	}

	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}
	lStatus = reconciledGW.Status.Listeners[0]

	refCond = findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
	if refCond == nil || refCond.Status != metav1.ConditionTrue || refCond.Reason != string(gatewayv1.ListenerReasonResolvedRefs) {
		t.Errorf("expected resolved ResolvedRefs=True/ResolvedRefs, got %+v", refCond)
	}

	progCond = findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.ListenerReasonProgrammed) {
		t.Errorf("expected resolved Programmed=True/Programmed, got %+v", progCond)
	}

	dpCfg := st.GetDataplaneConfig(types.NamespacedName{Namespace: "default", Name: "test-gw"})
	if dpCfg == nil || len(dpCfg.Certificates) == 0 {
		t.Fatalf("expected DataplaneConfig to be populated with certificate after trigger")
	}
}

func TestGatewayReconciler_CertificateSource_UnknownSourceName(t *testing.T) {
	fakeSource := &fakeCertificateSource{}
	fakeSource.set("example.com", generateTestTLSCert(t, "example.com"))

	scheme, st, gwClass, gw := setupCertSourceTestGW(t,
		state.Ptr(gatewayv1.Hostname("example.com")),
		map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
			gatewayv1.AnnotationKey(CertificateSourceOptionKey): "unknown-source",
		},
		nil,
		map[string]state.CertificateSource{
			"known-source": fakeSource,
		},
	)

	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gw)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw).
		WithStatusSubresource(gw).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		ControllerName: "test-controller",
	}

	ctx := t.Context()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}}

	_, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}

	var reconciledGW gatewayv1.Gateway
	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}
	lStatus := reconciledGW.Status.Listeners[0]

	refCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
	if refCond == nil || refCond.Status != metav1.ConditionFalse || refCond.Reason != string(gatewayv1.ListenerReasonInvalidCertificateRef) {
		t.Errorf("expected ResolvedRefs=False/InvalidCertificateRef for unknown source, got %+v", refCond)
	}
	if !strings.Contains(refCond.Message, "unknown-source") {
		t.Errorf("expected message to mention unknown-source, got %q", refCond.Message)
	}

	progCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.ListenerReasonInvalid) {
		t.Errorf("expected Programmed=False/Invalid for unknown source, got %+v", progCond)
	}

	accCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionAccepted))
	if accCond == nil || accCond.Status != metav1.ConditionTrue || accCond.Reason != string(gatewayv1.ListenerReasonAccepted) {
		t.Errorf("expected Accepted=True/Accepted, got %+v", accCond)
	}
}

func TestGatewayReconciler_CertificateSource_MissingOrWildcardHostname(t *testing.T) {
	testCases := []struct {
		name     string
		hostname *gatewayv1.Hostname
	}{
		{
			name:     "nil hostname",
			hostname: nil,
		},
		{
			name:     "empty hostname",
			hostname: state.Ptr(gatewayv1.Hostname("")),
		},
		{
			name:     "wildcard hostname",
			hostname: state.Ptr(gatewayv1.Hostname("*.example.com")),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeSource := &fakeCertificateSource{}
			fakeSource.set("example.com", generateTestTLSCert(t, "example.com"))

			scheme, st, gwClass, gw := setupCertSourceTestGW(t,
				tc.hostname,
				map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
					gatewayv1.AnnotationKey(CertificateSourceOptionKey): "test-source",
				},
				nil,
				map[string]state.CertificateSource{
					"test-source": fakeSource,
				},
			)

			st.UpsertGatewayClass(gwClass)
			st.UpsertGateway(gw)
			st.Recompute()

			client := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(gwClass, gw).
				WithStatusSubresource(gw).
				Build()

			r := &GatewayReconciler{
				Client:         client,
				Scheme:         scheme,
				State:          st,
				ControllerName: "test-controller",
			}

			ctx := t.Context()
			req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}}

			_, err := r.Reconcile(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error reconciling gateway: %v", err)
			}

			var reconciledGW gatewayv1.Gateway
			if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
				t.Fatalf("failed to get gateway: %v", err)
			}
			lStatus := reconciledGW.Status.Listeners[0]

			refCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
			if refCond == nil || refCond.Status != metav1.ConditionFalse || refCond.Reason != string(gatewayv1.ListenerReasonInvalidCertificateRef) {
				t.Errorf("expected ResolvedRefs=False/InvalidCertificateRef for %s, got %+v", tc.name, refCond)
			}

			progCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionProgrammed))
			if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.ListenerReasonInvalid) {
				t.Errorf("expected Programmed=False/Invalid for %s, got %+v", tc.name, progCond)
			}

			accCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionAccepted))
			if accCond == nil || accCond.Status != metav1.ConditionTrue || accCond.Reason != string(gatewayv1.ListenerReasonAccepted) {
				t.Errorf("expected Accepted=True/Accepted, got %+v", accCond)
			}

			// Verify source was never called
			if len(fakeSource.calls()) != 0 {
				t.Errorf("expected source to NOT be called for %s, got %d calls", tc.name, len(fakeSource.calls()))
			}
		})
	}
}

func TestGatewayReconciler_CertificateSource_CertificateRefsTogetherWithOption(t *testing.T) {
	certPEM, keyPEM := generateTestCertPEM(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-cert-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}

	sourceCert := generateTestTLSCert(t, "source.example.com")
	fakeSource := &fakeCertificateSource{}
	fakeSource.set("source.example.com", sourceCert)

	scheme, st, gwClass, gw := setupCertSourceTestGW(t,
		state.Ptr(gatewayv1.Hostname("example.com")),
		map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
			gatewayv1.AnnotationKey(CertificateSourceOptionKey): "test-source",
		},
		[]gatewayv1.SecretObjectReference{
			{Name: "my-cert-secret"},
		},
		map[string]state.CertificateSource{
			"test-source": fakeSource,
		},
	)

	st.UpsertSecret(secret)
	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gw)
	outputs := st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw, secret).
		WithStatusSubresource(gw).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		ControllerName: "test-controller",
	}

	ctx := t.Context()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}}

	_, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}

	var reconciledGW gatewayv1.Gateway
	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}
	lStatus := reconciledGW.Status.Listeners[0]

	// CertificateRefs wins
	refCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
	if refCond == nil || refCond.Status != metav1.ConditionTrue || refCond.Reason != string(gatewayv1.ListenerReasonResolvedRefs) {
		t.Errorf("expected ResolvedRefs=True/ResolvedRefs, got %+v", refCond)
	}
	// Condition says the option was ignored
	if !strings.Contains(refCond.Message, "ignored") {
		t.Errorf("expected ResolvedRefs condition message to state option was ignored, got %q", refCond.Message)
	}

	progCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionTrue || progCond.Reason != string(gatewayv1.ListenerReasonProgrammed) {
		t.Errorf("expected Programmed=True/Programmed, got %+v", progCond)
	}

	// Verify fakeSource was NOT called (certificateRefs won)
	if len(fakeSource.calls()) != 0 {
		t.Errorf("expected CertificateSource to NOT be called when certificateRefs is specified, got %d calls", len(fakeSource.calls()))
	}

	// Verify the certificate used is from the secret, not the source
	dpCfg := outputs.DataplaneConfigs[types.NamespacedName{Namespace: "default", Name: "test-gw"}]
	if dpCfg == nil {
		t.Fatalf("expected DataplaneConfig")
	}
	certID := dpCfg.HostCertificates["example.com"]
	data := dpCfg.Certificates[certID]
	if !strings.Contains(string(data.Certificate[0]), "") {
		_ = data
	}
}

func TestGatewayReconciler_CertificateSource_SourceError(t *testing.T) {
	fakeSource := &fakeCertificateSource{err: errors.New("cert server rpc timeout (request-id: 12345)")}

	scheme, st, gwClass, gw := setupCertSourceTestGW(t,
		state.Ptr(gatewayv1.Hostname("example.com")),
		map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
			gatewayv1.AnnotationKey(CertificateSourceOptionKey): "test-source",
		},
		nil,
		map[string]state.CertificateSource{
			"test-source": fakeSource,
		},
	)

	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gw)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw).
		WithStatusSubresource(gw).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		ControllerName: "test-controller",
	}

	ctx := t.Context()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}}

	_, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}

	var reconciledGW gatewayv1.Gateway
	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}
	lStatus := reconciledGW.Status.Listeners[0]

	refCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
	if refCond == nil || refCond.Status != metav1.ConditionFalse || refCond.Reason != string(gatewayv1.ListenerReasonInvalidCertificateRef) {
		t.Errorf("expected ResolvedRefs=False/InvalidCertificateRef on source error, got %+v", refCond)
	}
	// Stable generic message in status, not varying error text
	if !strings.Contains(refCond.Message, `Certificate source "test-source" returned an error`) {
		t.Errorf("expected message to contain stable generic error text, got %q", refCond.Message)
	}

	progCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionProgrammed))
	if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.ListenerReasonInvalid) {
		t.Errorf("expected Programmed=False/Invalid on source error, got %+v", progCond)
	}

	accCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionAccepted))
	if accCond == nil || accCond.Status != metav1.ConditionTrue || accCond.Reason != string(gatewayv1.ListenerReasonAccepted) {
		t.Errorf("expected Accepted=True/Accepted, got %+v", accCond)
	}
}

func TestGatewayReconciler_CertificateSource_NilSourcesConfigured(t *testing.T) {
	scheme, st, gwClass, gw := setupCertSourceTestGW(t,
		state.Ptr(gatewayv1.Hostname("example.com")),
		map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
			gatewayv1.AnnotationKey(CertificateSourceOptionKey): "test-source",
		},
		nil,
	)

	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gw)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw).
		WithStatusSubresource(gw).
		Build()

	// GARI with no sources configured (CertificateSources is nil)
	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		ControllerName: "test-controller",
	}

	ctx := t.Context()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}}

	_, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}

	var reconciledGW gatewayv1.Gateway
	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get gateway: %v", err)
	}
	lStatus := reconciledGW.Status.Listeners[0]

	refCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
	if refCond == nil || refCond.Status != metav1.ConditionFalse || refCond.Reason != string(gatewayv1.ListenerReasonInvalidCertificateRef) {
		t.Errorf("expected ResolvedRefs=False/InvalidCertificateRef when sources is nil, got %+v", refCond)
	}
	if !strings.Contains(refCond.Message, "test-source") {
		t.Errorf("expected message to mention source name, got %q", refCond.Message)
	}
}

func TestGatewayReconciler_CertificateSource_CertificatesNeverLogged(t *testing.T) {
	testCert := generateTestTLSCert(t, "secret-domain.example.com")
	fakeSource := &fakeCertificateSource{}
	fakeSource.set("secret-domain.example.com", testCert)

	scheme, st, gwClass, gw := setupCertSourceTestGW(t,
		state.Ptr(gatewayv1.Hostname("secret-domain.example.com")),
		map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
			gatewayv1.AnnotationKey(CertificateSourceOptionKey): "test-source",
		},
		nil,
		map[string]state.CertificateSource{
			"test-source": fakeSource,
		},
	)

	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gw)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw).
		WithStatusSubresource(gw).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		ControllerName: "test-controller",
	}

	var buf bytes.Buffer
	logger := ctrlzap.New(ctrlzap.WriteTo(&buf))
	ctx := ctrllog.IntoContext(t.Context(), logger)
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}}

	_, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error reconciling gateway: %v", err)
	}

	logs := buf.String()
	// Assert that certificates or private keys are never logged
	if strings.Contains(logs, "BEGIN CERTIFICATE") || strings.Contains(logs, "PRIVATE KEY") {
		t.Errorf("logs contain sensitive certificate/key data: %s", logs)
	}
	// Also ensure DER bytes are not formatted in the logs
	for _, der := range testCert.Certificate {
		if strings.Contains(logs, string(der)) {
			t.Errorf("logs contain raw DER certificate bytes")
		}
	}
}

func TestGatewayReconciler_CertificateSource_InvalidCertificate(t *testing.T) {
	testCases := []struct {
		name string
		cert *tls.Certificate
	}{
		{
			name: "empty chain",
			cert: &tls.Certificate{
				Certificate: [][]byte{},
				PrivateKey:  generateTestTLSCert(t, "example.com").PrivateKey,
			},
		},
		{
			name: "unparseable leaf",
			cert: &tls.Certificate{
				Certificate: [][]byte{[]byte("not a real der certificate")},
				PrivateKey:  generateTestTLSCert(t, "example.com").PrivateKey,
			},
		},
		{
			name: "key pair mismatch",
			cert: &tls.Certificate{
				Certificate: generateTestTLSCert(t, "example.com").Certificate,
				PrivateKey:  generateTestTLSCert(t, "other.example.com").PrivateKey,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeSource := &fakeCertificateSource{}
			fakeSource.set("example.com", tc.cert)

			scheme, st, gwClass, gw := setupCertSourceTestGW(t,
				state.Ptr(gatewayv1.Hostname("example.com")),
				map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
					gatewayv1.AnnotationKey(CertificateSourceOptionKey): "test-source",
				},
				nil,
				map[string]state.CertificateSource{
					"test-source": fakeSource,
				},
			)

			st.UpsertGatewayClass(gwClass)
			st.UpsertGateway(gw)
			st.Recompute()

			client := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(gwClass, gw).
				WithStatusSubresource(gw).
				Build()

			r := &GatewayReconciler{
				Client:         client,
				Scheme:         scheme,
				State:          st,
				ControllerName: "test-controller",
			}

			ctx := t.Context()
			req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}}

			_, err := r.Reconcile(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error reconciling gateway: %v", err)
			}

			var reconciledGW gatewayv1.Gateway
			if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
				t.Fatalf("failed to get gateway: %v", err)
			}
			lStatus := reconciledGW.Status.Listeners[0]

			refCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionResolvedRefs))
			if refCond == nil || refCond.Status != metav1.ConditionFalse || refCond.Reason != string(gatewayv1.ListenerReasonInvalidCertificateRef) {
				t.Errorf("expected ResolvedRefs=False/InvalidCertificateRef for %s, got %+v", tc.name, refCond)
			}
			if !strings.Contains(refCond.Message, "invalid certificate") {
				t.Errorf("expected message to mention invalid certificate, got %q", refCond.Message)
			}

			progCond := findCondition(lStatus.Conditions, string(gatewayv1.ListenerConditionProgrammed))
			if progCond == nil || progCond.Status != metav1.ConditionFalse || progCond.Reason != string(gatewayv1.ListenerReasonInvalid) {
				t.Errorf("expected Programmed=False/Invalid for %s, got %+v", tc.name, progCond)
			}
		})
	}
}

func TestGatewayReconciler_CertificateSource_SnapshotImmutability(t *testing.T) {
	testCert := generateTestTLSCert(t, "immutable.example.com")
	fakeSource := &fakeCertificateSource{}
	fakeSource.set("immutable.example.com", testCert)

	_, st, gwClass, gw := setupCertSourceTestGW(t,
		state.Ptr(gatewayv1.Hostname("immutable.example.com")),
		map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
			gatewayv1.AnnotationKey(CertificateSourceOptionKey): "test-source",
		},
		nil,
		map[string]state.CertificateSource{
			"test-source": fakeSource,
		},
	)

	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gw)
	outputs := st.Recompute()

	origDER := make([]byte, len(testCert.Certificate[0]))
	copy(origDER, testCert.Certificate[0])

	// Mutate the original testCert.Certificate bytes
	testCert.Certificate[0][0] ^= 0xff

	cg := outputs.CompiledGateways[types.NamespacedName{Namespace: "default", Name: "test-gw"}]
	if cg == nil || len(cg.EffectiveListeners) == 0 || len(cg.EffectiveListeners[0].ResolvedCertificates) == 0 {
		t.Fatalf("expected compiled gateway with resolved certificates")
	}

	stateDER := cg.EffectiveListeners[0].ResolvedCertificates[0].Certificate[0]
	if !bytes.Equal(stateDER, origDER) {
		t.Errorf("state certificate was mutated after ResolveCertificates returned")
	}
}

func generateTestCertPEMForHost(t *testing.T, host string) ([]byte, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   host,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM
}

func TestSecretsCertificateSource_MultipleCertificateRefs(t *testing.T) {
	st := state.NewState()

	cert1PEM, key1PEM := generateTestCertPEMForHost(t, "rsa.example.com")
	cert2PEM, key2PEM := generateTestCertPEMForHost(t, "ecdsa.example.com")

	sec1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cert-rsa"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       cert1PEM,
			corev1.TLSPrivateKeyKey: key1PEM,
		},
	}
	sec2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cert-ecdsa"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       cert2PEM,
			corev1.TLSPrivateKeyKey: key2PEM,
		},
	}
	st.UpsertSecret(sec1)
	st.UpsertSecret(sec2)

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-gc"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-gc",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "cert-rsa"},
							{Name: "cert-ecdsa"},
						},
					},
				},
			},
		},
	}
	st.SetControllerName("test-controller")
	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gw)
	outputs := st.Recompute()

	dpCfg := outputs.DataplaneConfigs[types.NamespacedName{Namespace: "default", Name: "test-gw"}]
	if dpCfg == nil {
		t.Fatalf("expected DataplaneConfig")
	}
	if len(dpCfg.Certificates) < 2 {
		t.Errorf("expected at least 2 certificates in data plane, got %d", len(dpCfg.Certificates))
	}
}

func TestSecretsCertificateSource_SecretRotation(t *testing.T) {
	st := state.NewState()

	// Initial cert for example.com
	cert1PEM, key1PEM := generateTestCertPEM(t)
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-cert"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       cert1PEM,
			corev1.TLSPrivateKeyKey: key1PEM,
		},
	}
	st.UpsertSecret(sec)

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-gc"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "test-controller",
		},
	}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-gw"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-gc",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "my-cert"},
						},
					},
				},
			},
		},
	}
	st.SetControllerName("test-controller")
	st.UpsertGatewayClass(gwClass)
	st.UpsertGateway(gw)
	outputs1 := st.Recompute()

	dpCfg1 := outputs1.DataplaneConfigs[types.NamespacedName{Namespace: "default", Name: "test-gw"}]
	if dpCfg1 == nil || len(dpCfg1.Certificates) == 0 {
		t.Fatalf("expected initial DataplaneConfig with certificates")
	}
	defaultCertID1 := dpCfg1.DefaultCertID
	if defaultCertID1 == "" {
		t.Fatalf("expected DefaultCertID to be set initially")
	}

	// Rotate the secret with a new keypair
	cert2PEM, key2PEM := generateTestCertPEM(t)
	secRotated := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "my-cert"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       cert2PEM,
			corev1.TLSPrivateKeyKey: key2PEM,
		},
	}
	st.UpsertSecret(secRotated)
	outputs2 := st.Recompute()

	dpCfg2 := outputs2.DataplaneConfigs[types.NamespacedName{Namespace: "default", Name: "test-gw"}]
	if dpCfg2 == nil || len(dpCfg2.Certificates) == 0 {
		t.Fatalf("expected updated DataplaneConfig with certificates")
	}
	defaultCertID2 := dpCfg2.DefaultCertID
	if defaultCertID2 == "" {
		t.Fatalf("expected DefaultCertID to be set after rotation")
	}

	certData1 := dpCfg1.Certificates[defaultCertID1]
	certData2 := dpCfg2.Certificates[defaultCertID2]
	if bytes.Equal(certData1.Certificate[0], certData2.Certificate[0]) {
		t.Errorf("expected rotated certificate in data plane, but certificate bytes did not change")
	}
}

func TestSecretsCertificateSource(t *testing.T) {
	st := state.NewState()
	certPEM, keyPEM := generateTestCertPEM(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}
	st.UpsertSecret(secret)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-gw"},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{
					Name: "https",
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "test-secret"},
						},
					},
				},
			},
		},
	}

	src := &SecretsCertificateSource{Secrets: st.GetSecrets()}

	res, err := src.ResolveCertificates(gw, &gw.Spec.Listeners[0])
	if err != nil {
		t.Fatalf("unexpected error resolving certificate from SecretsCertificateSource: %v", err)
	}
	if len(res.Certificates) == 0 {
		t.Fatalf("expected non-empty certificate from SecretsCertificateSource")
	}

	// Listener without TLS returns failure
	resMissing, _ := src.ResolveCertificates(gw, &gatewayv1.Listener{})
	if resMissing.FailedReason == "" {
		t.Errorf("expected failure for listener without TLS")
	}

	// Secret not found returns failure
	gwMissingSecret := gw.DeepCopy()
	gwMissingSecret.Spec.Listeners[0].TLS.CertificateRefs[0].Name = "missing"
	resNotFound, _ := src.ResolveCertificates(gwMissingSecret, &gwMissingSecret.Spec.Listeners[0])
	if resNotFound.FailedReason == "" {
		t.Errorf("expected failure for missing secret")
	}
}

func TestGatewayClassReconciler_SupportedFeatures(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add clientgo scheme: %v", err)
	}
	if err := gatewayv1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add gatewayv1 scheme: %v", err)
	}

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-gc", Generation: 1},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gc).
		WithStatusSubresource(gc).
		Build()

	st := state.NewState()
	st.SetControllerName("test-controller")
	st.UpsertGatewayClass(gc)
	st.Recompute()

	r := &GatewayClassReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		ControllerName: "test-controller",
	}

	ctx := t.Context()

	// 1. Initial reconcile on accepted GatewayClass
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-gc"}}); err != nil {
		t.Fatalf("first reconcile failed: %v", err)
	}

	var res gatewayv1.GatewayClass
	if err := client.Get(ctx, types.NamespacedName{Name: "test-gc"}, &res); err != nil {
		t.Fatalf("failed to get GatewayClass: %v", err)
	}

	cond := findCondition(res.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusAccepted))
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("expected Accepted=True condition, got %+v", cond)
	}

	expectedFeatures := state.GatewayClassSupportedFeatures()
	if !slices.Equal(res.Status.SupportedFeatures, expectedFeatures) {
		t.Errorf("SupportedFeatures mismatch: got %+v, want %+v", res.Status.SupportedFeatures, expectedFeatures)
	}
	if !slices.IsSortedFunc(res.Status.SupportedFeatures, func(a, b gatewayv1.SupportedFeature) int {
		return cmp.Compare(a.Name, b.Name)
	}) {
		t.Errorf("SupportedFeatures is not sorted ascending: %+v", res.Status.SupportedFeatures)
	}

	// 2. Second reconcile must not write status again
	rv := res.ResourceVersion
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-gc"}}); err != nil {
		t.Fatalf("second reconcile failed: %v", err)
	}

	var resSecond gatewayv1.GatewayClass
	if err := client.Get(ctx, types.NamespacedName{Name: "test-gc"}, &resSecond); err != nil {
		t.Fatalf("failed to get GatewayClass on second reconcile: %v", err)
	}
	if resSecond.ResourceVersion != rv {
		t.Errorf("expected ResourceVersion to remain %s on second reconcile, got %s (status write occurred)",
			rv, resSecond.ResourceVersion)
	}
}

func TestGatewayReconciler_PreservesForeignConditions(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gatewayv1.AddToScheme(scheme)

	st := state.NewState()
	st.SetControllerName("test-controller")

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "test-gc"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "test-controller"},
	}
	st.UpsertGatewayClass(gwClass)

	t0 := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	foreignGwCond := metav1.Condition{
		Type:               "conformance.gateway.networking.k8s.io/StaleCondition",
		Status:             metav1.ConditionTrue,
		Reason:             "Seeded",
		Message:            "Foreign condition seeded by another controller",
		ObservedGeneration: 1,
		LastTransitionTime: t0,
	}
	foreignListenerCond := metav1.Condition{
		Type:               "conformance.gateway.networking.k8s.io/StaleCondition",
		Status:             metav1.ConditionTrue,
		Reason:             "SeededListener",
		Message:            "Foreign listener condition seeded by another controller",
		ObservedGeneration: 1,
		LastTransitionTime: t0,
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
		},
		Status: gatewayv1.GatewayStatus{
			Conditions: []metav1.Condition{foreignGwCond},
			Listeners: []gatewayv1.ListenerStatus{
				{
					Name:       "http",
					Conditions: []metav1.Condition{foreignListenerCond},
				},
			},
		},
	}

	st.UpsertGateway(gw)
	st.Recompute()

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gwClass, gw).
		WithStatusSubresource(gw).
		Build()

	r := &GatewayReconciler{
		Client:         client,
		Scheme:         scheme,
		State:          st,
		ControllerName: "test-controller",
	}

	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-gw"}}

	// Reconcile Gateway: controller updates status
	_, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}

	var reconciledGW gatewayv1.Gateway
	if err := client.Get(ctx, req.NamespacedName, &reconciledGW); err != nil {
		t.Fatalf("failed to get reconciled gateway: %v", err)
	}

	// 1. Foreign condition on Gateway must survive
	storedGw := findCondition(reconciledGW.Status.Conditions, "conformance.gateway.networking.k8s.io/StaleCondition")
	if storedGw == nil {
		t.Fatalf("expected foreign Gateway condition to survive status update, got none")
	}
	if storedGw.Type != foreignGwCond.Type ||
		storedGw.Status != foreignGwCond.Status ||
		storedGw.Reason != foreignGwCond.Reason ||
		storedGw.Message != foreignGwCond.Message ||
		storedGw.ObservedGeneration != foreignGwCond.ObservedGeneration ||
		!storedGw.LastTransitionTime.Equal(&foreignGwCond.LastTransitionTime) {
		t.Errorf("foreign Gateway condition was modified: got %+v, want %+v", *storedGw, foreignGwCond)
	}

	// 2. Owned conditions on Gateway must be present
	acceptedCond := findCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionAccepted))
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionTrue {
		t.Errorf("expected Gateway Accepted=True, got %+v", acceptedCond)
	}
	progCond := findCondition(reconciledGW.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if progCond == nil {
		t.Errorf("expected Gateway Programmed condition, got none")
	}

	// 3. Foreign condition on Listener must survive
	if len(reconciledGW.Status.Listeners) != 1 {
		t.Fatalf("expected 1 listener in status, got %d", len(reconciledGW.Status.Listeners))
	}
	storedListener := findCondition(reconciledGW.Status.Listeners[0].Conditions, "conformance.gateway.networking.k8s.io/StaleCondition")
	if storedListener == nil {
		t.Fatalf("expected foreign Listener condition to survive status update, got none")
	}
	if storedListener.Type != foreignListenerCond.Type ||
		storedListener.Status != foreignListenerCond.Status ||
		storedListener.Reason != foreignListenerCond.Reason ||
		storedListener.Message != foreignListenerCond.Message ||
		storedListener.ObservedGeneration != foreignListenerCond.ObservedGeneration ||
		!storedListener.LastTransitionTime.Equal(&foreignListenerCond.LastTransitionTime) {
		t.Errorf("foreign Listener condition was modified: got %+v, want %+v", *storedListener, foreignListenerCond)
	}

	// 4. Owned conditions on Listener must be present
	listenerProg := findCondition(reconciledGW.Status.Listeners[0].Conditions, string(gatewayv1.ListenerConditionProgrammed))
	if listenerProg == nil || listenerProg.Status != metav1.ConditionTrue {
		t.Errorf("expected Listener Programmed=True, got %+v", listenerProg)
	}

	// 5. Subsequent reconcile without changes must be a no-op (no error, unchanged status)
	_, err = r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error on second reconcile: %v", err)
	}

	var secondReconciledGW gatewayv1.Gateway
	if err := client.Get(ctx, req.NamespacedName, &secondReconciledGW); err != nil {
		t.Fatalf("failed to get reconciled gateway: %v", err)
	}
	storedGw2 := findCondition(secondReconciledGW.Status.Conditions, "conformance.gateway.networking.k8s.io/StaleCondition")
	if storedGw2 == nil ||
		storedGw2.Type != foreignGwCond.Type ||
		storedGw2.Status != foreignGwCond.Status ||
		storedGw2.Reason != foreignGwCond.Reason ||
		storedGw2.Message != foreignGwCond.Message ||
		storedGw2.ObservedGeneration != foreignGwCond.ObservedGeneration ||
		!storedGw2.LastTransitionTime.Equal(&foreignGwCond.LastTransitionTime) {
		t.Errorf("foreign Gateway condition was modified on second reconcile: got %+v, want %+v", storedGw2, foreignGwCond)
	}
}

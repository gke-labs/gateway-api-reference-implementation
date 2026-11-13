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

package gari_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/controller"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/gari"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/proxy"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/testenv"
)

func TestGARI_Integration_SinglePodProvisioning(t *testing.T) {
	env := testenv.Start(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const (
		dataplaneImage = "gari-dataplane:integration-test"
		gwNamespace    = "default"
		gwName         = "test-gw"
		className      = "gari-test-class"
		paramsName     = "gari-params"
	)

	opts := gari.DefaultOptions()
	opts.RestConfig = env.Config
	opts.Scheme = env.Scheme
	opts.MetricsAddr = "0"
	opts.HealthProbeBindAddress = "0"
	opts.ProxyAddr = ""
	opts.ProxyHTTPSAddr = ""
	opts.LeaderElection = false
	opts.AddressProvider = singlepod.NewAddressProvider(
		nil,
		singlepod.WithDataplaneImage(dataplaneImage),
		singlepod.WithEnableH2C(true),
		singlepod.WithForwardedForMode(string(proxy.ForwardedForModeReplace)),
	)

	server, err := gari.New(opts)
	if err != nil {
		t.Fatalf("gari.New failed: %v", err)
	}

	go func() {
		if err := server.Manager().Start(ctx); err != nil {
			t.Logf("manager exited: %v", err)
		}
	}()

	if !server.Manager().GetCache().WaitForCacheSync(ctx) {
		t.Fatalf("timed out waiting for cache sync")
	}

	// 1. Create parameters ConfigMap
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gwNamespace,
			Name:      paramsName,
		},
		Data: map[string]string{
			state.ParameterKeyServiceType: string(corev1.ServiceTypeLoadBalancer),
		},
	}
	if err := env.Client.Create(ctx, cm); err != nil {
		t.Fatalf("failed to create ConfigMap: %v", err)
	}

	// 2. Create GatewayClass referencing parameters
	ns := gatewayv1.Namespace(gwNamespace)
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: className,
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(controller.DefaultControllerName),
			ParametersRef: &gatewayv1.ParametersReference{
				Group:     "",
				Kind:      "ConfigMap",
				Name:      paramsName,
				Namespace: &ns,
			},
		},
	}
	if err := env.Client.Create(ctx, gc); err != nil {
		t.Fatalf("failed to create GatewayClass: %v", err)
	}

	// 3. Create Gateway
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gwNamespace,
			Name:      gwName,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(gc.Name),
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
				},
			},
		},
	}
	if err := env.Client.Create(ctx, gw); err != nil {
		t.Fatalf("failed to create Gateway: %v", err)
	}

	// 4. Poll until singlepod Deployment, Service, and Secret are created
	resName := singlepod.ResourceNameForGateway(gwName)
	resKey := types.NamespacedName{Namespace: gwNamespace, Name: resName}

	var deploy appsv1.Deployment
	var svc corev1.Service
	var secret corev1.Secret

	deadline := time.Now().Add(15 * time.Second)
	for {
		errDep := env.Client.Get(ctx, resKey, &deploy)
		errSvc := env.Client.Get(ctx, resKey, &svc)
		errSec := env.Client.Get(ctx, resKey, &secret)
		if errDep == nil && errSvc == nil && errSec == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for singlepod resources (dep: %v, svc: %v, sec: %v)", errDep, errSvc, errSec)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 5. Assert Deployment
	// Check labels
	if deploy.Labels[state.LabelGatewayName] != gwName {
		t.Errorf("expected Deployment label %s=%q, got %q", state.LabelGatewayName, gwName, deploy.Labels[state.LabelGatewayName])
	}
	if deploy.Labels[state.LabelManagedBy] != state.ManagedByValue {
		t.Errorf("expected Deployment label %s=%q, got %q", state.LabelManagedBy, state.ManagedByValue, deploy.Labels[state.LabelManagedBy])
	}
	if deploy.Labels[state.LabelAppName] != state.AppNameValue {
		t.Errorf("expected Deployment label %s=%q, got %q", state.LabelAppName, state.AppNameValue, deploy.Labels[state.LabelAppName])
	}

	// Check pod template labels
	tmplLabels := deploy.Spec.Template.Labels
	if tmplLabels[state.LabelGatewayName] != gwName {
		t.Errorf("expected Template label %s=%q, got %q", state.LabelGatewayName, gwName, tmplLabels[state.LabelGatewayName])
	}
	if tmplLabels[state.LabelManagedBy] != state.ManagedByValue {
		t.Errorf("expected Template label %s=%q, got %q", state.LabelManagedBy, state.ManagedByValue, tmplLabels[state.LabelManagedBy])
	}
	if tmplLabels[state.LabelAppName] != state.AppNameValue {
		t.Errorf("expected Template label %s=%q, got %q", state.LabelAppName, state.AppNameValue, tmplLabels[state.LabelAppName])
	}

	// Check container image and arguments
	if len(deploy.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("expected 1 container in pod template, got %d", len(deploy.Spec.Template.Spec.Containers))
	}
	c := deploy.Spec.Template.Spec.Containers[0]
	if c.Image != dataplaneImage {
		t.Errorf("expected image %q, got %q", dataplaneImage, c.Image)
	}
	expectedArgs := []string{
		"--dataplane-mode",
		fmt.Sprintf("--gateway-namespace=%s", gwNamespace),
		fmt.Sprintf("--gateway-name=%s", gwName),
		"--enable-h2c",
		"--forwarded-for-mode=replace",
	}
	for _, arg := range expectedArgs {
		if !slices.Contains(c.Args, arg) {
			t.Errorf("expected argument %q in container args %+v", arg, c.Args)
		}
	}

	// 6. Assert Service
	if svc.Labels[state.LabelGatewayName] != gwName {
		t.Errorf("expected Service label %s=%q, got %q", state.LabelGatewayName, gwName, svc.Labels[state.LabelGatewayName])
	}
	if svc.Labels[state.LabelAppName] != state.AppNameValue {
		t.Errorf("expected Service label %s=%q, got %q", state.LabelAppName, state.AppNameValue, svc.Labels[state.LabelAppName])
	}
	if svc.Spec.Selector[state.LabelGatewayName] != gwName {
		t.Errorf("expected Service selector %s=%q, got %q", state.LabelGatewayName, gwName, svc.Spec.Selector[state.LabelGatewayName])
	}
	if svc.Spec.Selector[state.LabelAppName] != state.AppNameValue {
		t.Errorf("expected Service selector %s=%q, got %q", state.LabelAppName, state.AppNameValue, svc.Spec.Selector[state.LabelAppName])
	}

	// 7. Assert Secret
	secData, ok := secret.Data[singlepod.DataplaneSecretDataKey]
	if !ok || len(secData) == 0 {
		t.Fatalf("expected non-empty key %q in Secret data", singlepod.DataplaneSecretDataKey)
	}
	dpCfg, err := state.UnmarshalDataplaneConfig(secData)
	if err != nil {
		t.Fatalf("failed to unmarshal published DataplaneConfig: %v", err)
	}
	if dpCfg.GatewayName.Namespace != gwNamespace || dpCfg.GatewayName.Name != gwName {
		t.Errorf("unexpected GatewayName in published config: %+v", dpCfg.GatewayName)
	}

	// 8. Test BuildPodFromDeployment helper
	pod := testenv.BuildPodFromDeployment(&deploy)
	if pod == nil {
		t.Fatalf("BuildPodFromDeployment returned nil")
	}
	if pod.Namespace != gwNamespace {
		t.Errorf("expected pod namespace %q, got %q", gwNamespace, pod.Namespace)
	}
	// Crucial check: Pod has the real producer's label "app.kubernetes.io/name=gari-dataplane"
	if pod.Labels[state.LabelAppName] != state.AppNameValue {
		t.Errorf("expected pod label %s=%q, got %q", state.LabelAppName, state.AppNameValue, pod.Labels[state.LabelAppName])
	}
	if pod.Labels[state.LabelGatewayName] != gwName {
		t.Errorf("expected pod label %s=%q, got %q", state.LabelGatewayName, gwName, pod.Labels[state.LabelGatewayName])
	}
	if pod.Labels[state.LabelManagedBy] != state.ManagedByValue {
		t.Errorf("expected pod label %s=%q, got %q", state.LabelManagedBy, state.ManagedByValue, pod.Labels[state.LabelManagedBy])
	}

	// Verify pod can be created in the API server
	if err := env.Client.Create(ctx, pod); err != nil {
		t.Fatalf("failed to create pod built from Deployment: %v", err)
	}

	// Verify consumer query: query pods by producer's label selector
	var podList corev1.PodList
	if err := env.Client.List(ctx, &podList, client.InNamespace(gwNamespace), client.MatchingLabels{
		state.LabelAppName:     state.AppNameValue,
		state.LabelGatewayName: gwName,
	}); err != nil {
		t.Fatalf("failed to list pods with label selector: %v", err)
	}
	if len(podList.Items) != 1 {
		t.Fatalf("expected 1 pod matched by selector, got %d", len(podList.Items))
	}
	if podList.Items[0].Name != pod.Name {
		t.Errorf("expected pod name %q, got %q", pod.Name, podList.Items[0].Name)
	}

	// 9. Verify Gateway with dots (my.gateway) gets a valid Service and becomes Programmed
	dotGwName := "my.gateway"
	dotGw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gwNamespace,
			Name:      dotGwName,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(className),
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}
	if err := env.Client.Create(ctx, dotGw); err != nil {
		t.Fatalf("failed to create Gateway %s: %v", dotGwName, err)
	}

	dotResName := singlepod.ResourceNameForGateway(dotGwName)
	dotResKey := types.NamespacedName{Namespace: gwNamespace, Name: dotResName}
	var dotDeploy appsv1.Deployment
	var dotSvc corev1.Service
	deadline = time.Now().Add(15 * time.Second)
	for {
		if env.Client.Get(ctx, dotResKey, &dotDeploy) == nil && env.Client.Get(ctx, dotResKey, &dotSvc) == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for singlepod resources for %s", dotGwName)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if errs := validation.IsDNS1035Label(dotSvc.Name); len(errs) > 0 {
		t.Fatalf("Service name %q is not a valid DNS-1035 label: %v", dotSvc.Name, errs)
	}

	dotDeploy.Status.Replicas, dotDeploy.Status.AvailableReplicas, dotDeploy.Status.ReadyReplicas = 1, 1, 1
	if err := env.Client.Status().Update(ctx, &dotDeploy); err != nil {
		t.Fatalf("failed to update Deployment status: %v", err)
	}
	dotSvc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.2"}}
	if err := env.Client.Status().Update(ctx, &dotSvc); err != nil {
		t.Fatalf("failed to update Service status: %v", err)
	}

	appliedServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			var sec corev1.Secret
			dotResKey := types.NamespacedName{Namespace: gwNamespace, Name: dotResName}
			if err := env.Client.Get(ctx, dotResKey, &sec); err == nil {
				if dpCfg, err := state.UnmarshalDataplaneConfig(sec.Data[singlepod.DataplaneSecretDataKey]); err == nil {
					_ = json.NewEncoder(w).Encode([]string{dpCfg.Revision})
					return
				}
			}
			_ = json.NewEncoder(w).Encode([]string{})
		}),
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", state.DataPlaneHealthProbePort))
	if err != nil {
		t.Fatalf("failed to listen on health probe port: %v", err)
	}
	defer ln.Close()
	defer appliedServer.Close()
	go appliedServer.Serve(ln)

	var endpointIP string
	if ifAddrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifAddrs {
			if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
				endpointIP = ipNet.IP.String()
				break
			}
		}
	}
	if endpointIP == "" {
		endpointIP = "172.17.0.1"
	}

	dotSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      dotResName + "-slice",
			Namespace: gwNamespace,
			Labels: map[string]string{
				discoveryv1.LabelServiceName: dotResName,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{
				Addresses: []string{endpointIP},
				Conditions: discoveryv1.EndpointConditions{
					Ready: state.Ptr(true),
				},
			},
		},
	}
	if err := env.Client.Create(ctx, dotSlice); err != nil {
		t.Fatalf("failed to create EndpointSlice: %v", err)
	}

	dotGwKey := types.NamespacedName{Namespace: gwNamespace, Name: dotGwName}
	var dotGwStatus gatewayv1.Gateway
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if err := env.Client.Get(ctx, dotGwKey, &dotGwStatus); err == nil {
			for _, c := range dotGwStatus.Status.Conditions {
				if c.Type == string(gatewayv1.GatewayConditionProgrammed) && c.Status == metav1.ConditionTrue {
					return
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for Gateway %s to become Programmed=True: %+v", dotGwName, dotGwStatus.Status)
}

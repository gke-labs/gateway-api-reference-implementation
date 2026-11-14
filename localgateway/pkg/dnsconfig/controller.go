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

package dnsconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/validation"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/provisioning/singlepod"
	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

// BuildRecords computes the deterministic list of DNS records from the controller State.
// It reads desired Gateway status computed by the state, includes only HTTP listeners
// that are accepted and programmed, skips loopback and unspecified addresses,
// and resolves conflicts deterministically by oldest creation time, then namespace and name.
func BuildRecords(controllerState *state.State) []Record {
	if controllerState == nil {
		return nil
	}

	gatewayStates := controllerState.GetGateways()
	var matchingGateways []*gatewayv1.Gateway
	for _, gatewayState := range gatewayStates {
		if gatewayState == nil || gatewayState.Gateway == nil || gatewayState.Gateway.DeletionTimestamp != nil {
			continue
		}
		matchingGateways = append(matchingGateways, gatewayState.Gateway)
	}

	// Beyond the Gateway API specification:
	// The controller gives the hostname to the oldest Gateway by creation time, breaking ties
	// by namespace and name, so that conflicting claims resolve deterministically across controllers.
	sort.Slice(matchingGateways, func(i, j int) bool {
		timeI := matchingGateways[i].CreationTimestamp
		timeJ := matchingGateways[j].CreationTimestamp
		if !timeI.Equal(&timeJ) {
			return timeI.Before(&timeJ)
		}
		if matchingGateways[i].Namespace != matchingGateways[j].Namespace {
			return matchingGateways[i].Namespace < matchingGateways[j].Namespace
		}
		return matchingGateways[i].Name < matchingGateways[j].Name
	})

	claimedHostnames := make(map[string]bool)
	var records []Record

	for _, gateway := range matchingGateways {
		gatewayKey := types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}
		status, ok := controllerState.GetDesiredGatewayStatus(gatewayKey)
		if !ok || !isGatewayProgrammed(status) {
			continue
		}

		var addressStrings []string
		for _, address := range status.Addresses {
			ip := net.ParseIP(address.Value)
			if ip == nil {
				continue
			}
			// Skip loopback (127.0.0.0/8, ::1) and unspecified (0.0.0.0, ::) addresses
			// because mDNS records advertise addresses reachable by other clients on the local network (RFC 6762).
			if ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			addressStrings = append(addressStrings, ip.String())
		}
		if len(addressStrings) == 0 {
			continue
		}

		for _, listener := range gateway.Spec.Listeners {
			if listener.Protocol != gatewayv1.HTTPProtocolType || listener.Hostname == nil {
				continue
			}
			rawHostname := string(*listener.Hostname)
			if err := validation.ValidateSingleLabelLocalHostname(rawHostname); err != nil {
				continue
			}
			if !isListenerAcceptedAndProgrammed(status, listener.Name) {
				continue
			}

			canonicalHostname := strings.ToLower(rawHostname)
			if claimedHostnames[canonicalHostname] {
				// Already claimed by an older Gateway (or earlier listener).
				continue
			}
			claimedHostnames[canonicalHostname] = true

			records = append(records, Record{
				Name:      canonicalHostname,
				Addresses: append([]string(nil), addressStrings...),
			})
		}
	}

	return records
}

func isGatewayProgrammed(status gatewayv1.GatewayStatus) bool {
	for _, condition := range status.Conditions {
		if condition.Type == string(gatewayv1.GatewayConditionProgrammed) && condition.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

func isListenerAcceptedAndProgrammed(status gatewayv1.GatewayStatus, listenerName gatewayv1.SectionName) bool {
	for _, listenerStatus := range status.Listeners {
		if listenerStatus.Name != listenerName {
			continue
		}
		var accepted, programmed bool
		for _, condition := range listenerStatus.Conditions {
			if condition.Type == string(gatewayv1.ListenerConditionAccepted) && condition.Status == metav1.ConditionTrue {
				accepted = true
			}
			if condition.Type == string(gatewayv1.ListenerConditionProgrammed) && condition.Status == metav1.ConditionTrue {
				programmed = true
			}
		}
		return accepted && programmed
	}
	return false
}

// Publisher distributes DNS data plane configuration into a dedicated Secret.
// The Secret is created in the controller's own namespace. When all Gateways are removed
// or unprogrammed, the Secret is deleted; uninstalling the controller deployment or namespace
// also removes the Secret.
type Publisher struct {
	// client is the Kubernetes client used to apply the configuration Secret.
	client client.Client

	// namespace is the controller's namespace where the Secret is written.
	namespace string

	// secretName is the name of the Secret holding the DNS config.
	secretName string

	// state is the controller State holding compiled Gateway statuses.
	state *state.State

	// queue rate-limits and retries publish operations in the background.
	queue workqueue.TypedRateLimitingInterface[reconcile.Request]
}

// NewPublisher constructs a new DNS config Publisher.
func NewPublisher(kubernetesClient client.Client, namespace, secretName string, controllerState *state.State) *Publisher {
	if namespace == "" {
		namespace = "default"
	}
	if secretName == "" {
		secretName = "localgateway-dns"
	}
	return &Publisher{
		client:     kubernetesClient,
		namespace:  namespace,
		secretName: secretName,
		state:      controllerState,
		queue:      workqueue.NewTypedRateLimitingQueue[reconcile.Request](workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]()),
	}
}

// Start implements manager.Runnable to process publish requests asynchronously until ctx is canceled.
func (p *Publisher) Start(ctx context.Context) error {
	defer p.queue.ShutDown()

	if p.state != nil && p.state.GatewaySource() != nil {
		if err := p.state.GatewaySource().Start(ctx, p.queue); err != nil {
			return fmt.Errorf("starting gateway source: %w", err)
		}
	}

	p.queue.Add(reconcile.Request{})

	for {
		item, shutdown := p.queue.Get()
		if shutdown {
			return nil
		}

		if err := p.publishOnce(ctx); err != nil {
			klog.Errorf("failed to publish DNS data plane config: %v", err)
			p.queue.AddRateLimited(item)
		} else {
			p.queue.Forget(item)
		}
		p.queue.Done(item)
	}
}

func (p *Publisher) publishOnce(ctx context.Context) error {
	publishCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	records := BuildRecords(p.state)
	var payload []byte
	if len(records) > 0 {
		dnsConfig := &Config{Records: records}
		revision, err := dnsConfig.ComputeRevision()
		if err != nil {
			return fmt.Errorf("computing revision: %w", err)
		}
		dnsConfig.Revision = revision

		payload, err = json.Marshal(dnsConfig)
		if err != nil {
			return fmt.Errorf("marshaling dns config: %w", err)
		}
	}

	return singlepod.WriteConfigSecret(publishCtx, p.client, p.namespace, p.secretName, nil, payload)
}

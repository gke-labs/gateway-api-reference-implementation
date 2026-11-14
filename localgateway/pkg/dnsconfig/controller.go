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
	"fmt"
	"net"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/gke-labs/gateway-api-reference-implementation/localgateway/pkg/validation"
)

// BuildRecords computes the deterministic list of DNS records from the compiled Gateways.
// It includes only listeners that are accepted and programmed, only HTTP listeners,
// and resolves conflicts deterministically by oldest creation time, then namespace and name.
func BuildRecords(gateways []*gatewayv1.Gateway, gatewayClassName string) []Record {
	var matchingGateways []*gatewayv1.Gateway
	for _, gateway := range gateways {
		if gateway == nil || gateway.DeletionTimestamp != nil {
			continue
		}
		if gatewayClassName != "" && string(gateway.Spec.GatewayClassName) != gatewayClassName {
			continue
		}
		matchingGateways = append(matchingGateways, gateway)
	}

	// Beyond the Gateway API specification:
	// When multiple Gateways claim the same hostname, the conflict resolution is deterministic:
	// the oldest Gateway by creation time holds the name, breaking ties by namespace and name.
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
		if !isGatewayProgrammed(gateway) {
			continue
		}

		var ipStrings []string
		for _, address := range gateway.Status.Addresses {
			if ip := net.ParseIP(address.Value); ip != nil {
				ipStrings = append(ipStrings, ip.String())
			}
		}
		if len(ipStrings) == 0 {
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
			if !isListenerAcceptedAndProgrammed(gateway, listener.Name) {
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
				Addresses: append([]string(nil), ipStrings...),
			})
		}
	}

	return records
}

// isGatewayProgrammed returns true if the Gateway has a Programmed condition with status True.
func isGatewayProgrammed(gateway *gatewayv1.Gateway) bool {
	for _, condition := range gateway.Status.Conditions {
		if condition.Type == string(gatewayv1.GatewayConditionProgrammed) && condition.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

// isListenerAcceptedAndProgrammed returns true if the specified listener has both Accepted
// and Programmed conditions with status True.
func isListenerAcceptedAndProgrammed(gateway *gatewayv1.Gateway, listenerName gatewayv1.SectionName) bool {
	for _, listenerStatus := range gateway.Status.Listeners {
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

// Publisher publishes DNS data plane configuration into its dedicated Secret.
type Publisher struct {
	client           client.Client
	namespace        string
	secretName       string
	gatewayClassName string
	lastRevision     string
}

// NewPublisher constructs a new DNS config Publisher.
func NewPublisher(cl client.Client, namespace, secretName, gatewayClassName string) *Publisher {
	if namespace == "" {
		namespace = DefaultSecretNamespace
	}
	if secretName == "" {
		secretName = DefaultSecretName
	}
	return &Publisher{
		client:           cl,
		namespace:        namespace,
		secretName:       secretName,
		gatewayClassName: gatewayClassName,
	}
}

// Publish computes DNS records from the provided Gateways and writes them to the config Secret.
func (p *Publisher) Publish(ctx context.Context, gateways []*gatewayv1.Gateway) error {
	records := BuildRecords(gateways, p.gatewayClassName)
	cfg := &Config{
		Records: records,
	}
	rev, err := cfg.ComputeRevision()
	if err != nil {
		return fmt.Errorf("computing revision: %w", err)
	}
	cfg.Revision = rev

	if p.lastRevision == rev {
		return nil
	}

	data, err := cfg.Marshal()
	if err != nil {
		return fmt.Errorf("marshaling dns config: %w", err)
	}

	var existing corev1.Secret
	err = p.client.Get(ctx, types.NamespacedName{Namespace: p.namespace, Name: p.secretName}, &existing)
	if apierrors.IsNotFound(err) {
		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: p.namespace,
				Name:      p.secretName,
			},
			Data: map[string][]byte{
				DefaultSecretDataKey: data,
			},
		}
		if err := p.client.Create(ctx, sec); err != nil {
			return fmt.Errorf("creating dns config secret: %w", err)
		}
	} else if err == nil {
		if existing.Data == nil {
			existing.Data = make(map[string][]byte)
		}
		existing.Data[DefaultSecretDataKey] = data
		if err := p.client.Update(ctx, &existing); err != nil {
			return fmt.Errorf("updating dns config secret: %w", err)
		}
	} else {
		return fmt.Errorf("getting dns config secret: %w", err)
	}

	p.lastRevision = rev
	return nil
}

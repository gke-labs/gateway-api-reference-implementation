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
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/state"
)

const (
	// DefaultConfigSecretName is the name of the Secret holding DNS data plane configuration.
	DefaultConfigSecretName = "localgateway-dns"

	// DefaultConfigSecretNamespace is the fallback namespace if the controller namespace is unset.
	DefaultConfigSecretNamespace = "default"

	// ConfigSecretDataKey is the key in the Secret holding serialized DNS configuration.
	ConfigSecretDataKey = "config.json"

	// FieldManager is the field manager name used for server-side apply of the DNS config Secret.
	FieldManager = "gari-provisioner"

	// retryBaseDelay is the initial backoff delay for retrying failed publishes.
	retryBaseDelay = 5 * time.Millisecond

	// retryMaxDelay caps the exponential backoff to bound the worst-case delay.
	retryMaxDelay = 30 * time.Second

	// syncPollDelay is the retry interval for checking if State has synced on startup.
	syncPollDelay = 50 * time.Millisecond

	// publishTimeout bounds how long a single publish operation may take against the API server.
	// 5 seconds gives generous headroom for server-side apply while ensuring slow servers do not block the worker.
	publishTimeout = 5 * time.Second

	// queueCoalesceKey is the single workqueue key used to coalesce publish requests into one apply.
	queueCoalesceKey = "dns-config"
)

// Publisher distributes DNS data plane configuration into a dedicated Secret.
// The Secret is created in the controller's own namespace. When all Gateways are removed
// or unprogrammed, the Secret is deleted. Because the Secret is published without an owner
// reference, it stays in the cluster until explicitly deleted or its namespace is removed.
type Publisher struct {
	// client is the Kubernetes client used to apply the configuration Secret.
	client client.Client

	// namespace is the controller's namespace where the Secret is written.
	namespace string

	// secretName is the name of the Secret holding the DNS config.
	secretName string

	// state is the controller State holding compiled Gateway statuses.
	state *state.State

	// queue rate-limits, retries, and coalesces publish operations in the background.
	queue workqueue.TypedRateLimitingInterface[string]
}

// NewPublisher constructs a new DNS config Publisher.
func NewPublisher(kubernetesClient client.Client, namespace, secretName string, controllerState *state.State) *Publisher {
	rateLimiter := workqueue.NewTypedItemExponentialFailureRateLimiter[string](
		retryBaseDelay,
		retryMaxDelay,
	)
	return &Publisher{
		client:     kubernetesClient,
		namespace:  namespace,
		secretName: secretName,
		state:      controllerState,
		queue:      workqueue.NewTypedRateLimitingQueue[string](rateLimiter),
	}
}

// Start implements manager.Runnable to process publish requests asynchronously until ctx is canceled.
func (p *Publisher) Start(ctx context.Context) error {
	defer p.queue.ShutDown()

	logger := log.FromContext(ctx).WithName("dns-publisher")

	go func() {
		<-ctx.Done()
		p.queue.ShutDown()
	}()

	gatewayQueue := workqueue.NewTypedRateLimitingQueue[reconcile.Request](workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer gatewayQueue.ShutDown()
	go func() {
		<-ctx.Done()
		gatewayQueue.ShutDown()
	}()

	if err := p.state.GatewaySource().Start(ctx, gatewayQueue); err != nil {
		return fmt.Errorf("starting gateway source: %w", err)
	}

	go func() {
		for {
			item, shutdown := gatewayQueue.Get()
			if shutdown {
				return
			}
			p.queue.Add(queueCoalesceKey)
			gatewayQueue.Done(item)
		}
	}()

	p.queue.Add(queueCoalesceKey)

	for {
		item, shutdown := p.queue.Get()
		if shutdown {
			return nil
		}

		if err := p.publishOnce(ctx); err != nil {
			logger.Error(err, "failed to publish DNS data plane config")
			p.queue.AddRateLimited(item)
		} else {
			p.queue.Forget(item)
		}
		p.queue.Done(item)
	}
}

func (p *Publisher) publishOnce(ctx context.Context) error {
	if !p.state.Synced() {
		p.queue.AddAfter(queueCoalesceKey, syncPollDelay)
		return nil
	}

	publishCtx, cancel := context.WithTimeout(ctx, publishTimeout)
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

	return publishSecret(publishCtx, p.client, p.namespace, p.secretName, payload)
}

// publishSecret writes or deletes the DNS configuration Secret.
// It verifies that no other owner holds the Secret, deletes the Secret when the payload is empty,
// and otherwise applies the Secret using server-side apply.
func publishSecret(ctx context.Context, kubernetesClient client.Client, namespace, name string, payload []byte) error {
	var existingSecret corev1.Secret
	err := kubernetesClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &existingSecret)
	if err == nil {
		if ref := metav1.GetControllerOf(&existingSecret); ref != nil {
			return &state.OwnershipConflictError{
				Message: fmt.Sprintf("conflict: existing Secret %s/%s is owned by %s %s", namespace, name, ref.Kind, ref.Name),
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to get config Secret %s/%s: %w", namespace, name, err)
	}

	if len(payload) == 0 {
		if err == nil {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      name,
				},
			}
			if err := kubernetesClient.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("failed to delete config Secret %s/%s: %w", namespace, name, err)
			}
		}
		return nil
	}

	secretApply := corev1ac.Secret(name, namespace).
		WithData(map[string][]byte{
			ConfigSecretDataKey: payload,
		})

	if err := kubernetesClient.Apply(ctx, secretApply, client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
		return fmt.Errorf("failed to apply config Secret %s/%s: %w", namespace, name, err)
	}
	return nil
}

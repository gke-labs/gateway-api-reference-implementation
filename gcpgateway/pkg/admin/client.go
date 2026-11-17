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

package admin

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
)

// AdminClient defines the subset of Google Cloud Compute API operations needed
// for administrative load-balancing management (frontend creation and deletion).
type AdminClient interface {
	// Addresses
	GetAddress(ctx context.Context, project, name string) (*compute.Address, error)
	CreateAddress(ctx context.Context, project string, addr *compute.Address) error
	DeleteAddress(ctx context.Context, project, name string) error

	// Health Checks
	GetHealthCheck(ctx context.Context, project, name string) (*compute.HealthCheck, error)
	CreateHealthCheck(ctx context.Context, project string, hc *compute.HealthCheck) error
	DeleteHealthCheck(ctx context.Context, project, name string) error

	// Firewall Rules
	GetFirewall(ctx context.Context, project, name string) (*compute.Firewall, error)
	CreateFirewall(ctx context.Context, project string, fw *compute.Firewall) error
	DeleteFirewall(ctx context.Context, project, name string) error

	// Network Endpoint Groups
	GetNEG(ctx context.Context, project, zone, name string) (*compute.NetworkEndpointGroup, error)
	CreateNEG(ctx context.Context, project, zone string, neg *compute.NetworkEndpointGroup) error
	DeleteNEG(ctx context.Context, project, zone, name string) error

	// Backend Services
	GetBackendService(ctx context.Context, project, name string) (*compute.BackendService, error)
	CreateBackendService(ctx context.Context, project string, bs *compute.BackendService) error
	UpdateBackendService(ctx context.Context, project, name string, bs *compute.BackendService) error
	DeleteBackendService(ctx context.Context, project, name string) error

	// Target TCP Proxies
	GetTargetTCPProxy(ctx context.Context, project, name string) (*compute.TargetTcpProxy, error)
	CreateTargetTCPProxy(ctx context.Context, project string, proxy *compute.TargetTcpProxy) error
	DeleteTargetTCPProxy(ctx context.Context, project, name string) error

	// Forwarding Rules
	GetForwardingRule(ctx context.Context, project, name string) (*compute.ForwardingRule, error)
	CreateForwardingRule(ctx context.Context, project string, fr *compute.ForwardingRule) error
	DeleteForwardingRule(ctx context.Context, project, name string) error

	// Zones
	ListZones(ctx context.Context, project, region string) ([]string, error)
}

// GCEAdminClient implements AdminClient backed by google.golang.org/api/compute/v1 using ADC.
type GCEAdminClient struct {
	svc *compute.Service
}

// NewGCEAdminClient creates a GCEAdminClient using Application Default Credentials.
func NewGCEAdminClient(ctx context.Context) (*GCEAdminClient, error) {
	svc, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating compute service: %w", err)
	}
	return &GCEAdminClient{svc: svc}, nil
}

func isNotFound(err error) bool {
	var gErr *googleapi.Error
	return errors.As(err, &gErr) && gErr.Code == 404
}

func (c *GCEAdminClient) waitGlobalOp(ctx context.Context, project string, op *compute.Operation) error {
	if op == nil {
		return nil
	}
	opName := op.Name
	for {
		if op != nil && op.Status == "DONE" {
			if op.Error != nil && len(op.Error.Errors) > 0 {
				var msgs []string
				for _, e := range op.Error.Errors {
					msgs = append(msgs, fmt.Sprintf("%s: %s", e.Code, e.Message))
				}
				return fmt.Errorf("operation %s failed: %s", opName, strings.Join(msgs, "; "))
			}
			return nil
		}
		var err error
		op, err = c.svc.GlobalOperations.Wait(project, opName).Context(ctx).Do()
		if err != nil {
			select {
			case <-ctx.Done():
				return fmt.Errorf("waiting for operation %s: %w", opName, ctx.Err())
			case <-time.After(1 * time.Second):
			}
			var getErr error
			op, getErr = c.svc.GlobalOperations.Get(project, opName).Context(ctx).Do()
			if getErr != nil {
				return fmt.Errorf("waiting for operation %s (wait error: %v, get error: %w)", opName, err, getErr)
			}
		}
	}
}

func (c *GCEAdminClient) waitZonalOp(ctx context.Context, project, zone string, op *compute.Operation) error {
	if op == nil {
		return nil
	}
	opName := op.Name
	for {
		if op != nil && op.Status == "DONE" {
			if op.Error != nil && len(op.Error.Errors) > 0 {
				var msgs []string
				for _, e := range op.Error.Errors {
					msgs = append(msgs, fmt.Sprintf("%s: %s", e.Code, e.Message))
				}
				return fmt.Errorf("operation %s failed: %s", opName, strings.Join(msgs, "; "))
			}
			return nil
		}
		var err error
		op, err = c.svc.ZoneOperations.Wait(project, zone, opName).Context(ctx).Do()
		if err != nil {
			select {
			case <-ctx.Done():
				return fmt.Errorf("waiting for operation %s: %w", opName, ctx.Err())
			case <-time.After(1 * time.Second):
			}
			var getErr error
			op, getErr = c.svc.ZoneOperations.Get(project, zone, opName).Context(ctx).Do()
			if getErr != nil {
				return fmt.Errorf("waiting for operation %s (wait error: %v, get error: %w)", opName, err, getErr)
			}
		}
	}
}

// Addresses

func (c *GCEAdminClient) GetAddress(ctx context.Context, project, name string) (*compute.Address, error) {
	addr, err := c.svc.GlobalAddresses.Get(project, name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return addr, nil
}

func (c *GCEAdminClient) CreateAddress(ctx context.Context, project string, addr *compute.Address) error {
	op, err := c.svc.GlobalAddresses.Insert(project, addr).Context(ctx).Do()
	if err != nil {
		return err
	}
	return c.waitGlobalOp(ctx, project, op)
}

func (c *GCEAdminClient) DeleteAddress(ctx context.Context, project, name string) error {
	op, err := c.svc.GlobalAddresses.Delete(project, name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	return c.waitGlobalOp(ctx, project, op)
}

// Health Checks

func (c *GCEAdminClient) GetHealthCheck(ctx context.Context, project, name string) (*compute.HealthCheck, error) {
	hc, err := c.svc.HealthChecks.Get(project, name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return hc, nil
}

func (c *GCEAdminClient) CreateHealthCheck(ctx context.Context, project string, hc *compute.HealthCheck) error {
	op, err := c.svc.HealthChecks.Insert(project, hc).Context(ctx).Do()
	if err != nil {
		return err
	}
	return c.waitGlobalOp(ctx, project, op)
}

func (c *GCEAdminClient) DeleteHealthCheck(ctx context.Context, project, name string) error {
	op, err := c.svc.HealthChecks.Delete(project, name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	return c.waitGlobalOp(ctx, project, op)
}

// Firewall Rules

func (c *GCEAdminClient) GetFirewall(ctx context.Context, project, name string) (*compute.Firewall, error) {
	fw, err := c.svc.Firewalls.Get(project, name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return fw, nil
}

func (c *GCEAdminClient) CreateFirewall(ctx context.Context, project string, fw *compute.Firewall) error {
	op, err := c.svc.Firewalls.Insert(project, fw).Context(ctx).Do()
	if err != nil {
		return err
	}
	return c.waitGlobalOp(ctx, project, op)
}

func (c *GCEAdminClient) DeleteFirewall(ctx context.Context, project, name string) error {
	op, err := c.svc.Firewalls.Delete(project, name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	return c.waitGlobalOp(ctx, project, op)
}

// Network Endpoint Groups

func (c *GCEAdminClient) GetNEG(ctx context.Context, project, zone, name string) (*compute.NetworkEndpointGroup, error) {
	neg, err := c.svc.NetworkEndpointGroups.Get(project, zone, name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return neg, nil
}

func (c *GCEAdminClient) CreateNEG(ctx context.Context, project, zone string, neg *compute.NetworkEndpointGroup) error {
	op, err := c.svc.NetworkEndpointGroups.Insert(project, zone, neg).Context(ctx).Do()
	if err != nil {
		return err
	}
	return c.waitZonalOp(ctx, project, zone, op)
}

func (c *GCEAdminClient) DeleteNEG(ctx context.Context, project, zone, name string) error {
	op, err := c.svc.NetworkEndpointGroups.Delete(project, zone, name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	return c.waitZonalOp(ctx, project, zone, op)
}

// Backend Services

func (c *GCEAdminClient) GetBackendService(ctx context.Context, project, name string) (*compute.BackendService, error) {
	bs, err := c.svc.BackendServices.Get(project, name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return bs, nil
}

func (c *GCEAdminClient) CreateBackendService(ctx context.Context, project string, bs *compute.BackendService) error {
	op, err := c.svc.BackendServices.Insert(project, bs).Context(ctx).Do()
	if err != nil {
		return err
	}
	return c.waitGlobalOp(ctx, project, op)
}

func (c *GCEAdminClient) UpdateBackendService(ctx context.Context, project, name string, bs *compute.BackendService) error {
	op, err := c.svc.BackendServices.Update(project, name, bs).Context(ctx).Do()
	if err != nil {
		return err
	}
	return c.waitGlobalOp(ctx, project, op)
}

func (c *GCEAdminClient) DeleteBackendService(ctx context.Context, project, name string) error {
	op, err := c.svc.BackendServices.Delete(project, name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	return c.waitGlobalOp(ctx, project, op)
}

// Target TCP Proxies

func (c *GCEAdminClient) GetTargetTCPProxy(ctx context.Context, project, name string) (*compute.TargetTcpProxy, error) {
	proxy, err := c.svc.TargetTcpProxies.Get(project, name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return proxy, nil
}

func (c *GCEAdminClient) CreateTargetTCPProxy(ctx context.Context, project string, proxy *compute.TargetTcpProxy) error {
	op, err := c.svc.TargetTcpProxies.Insert(project, proxy).Context(ctx).Do()
	if err != nil {
		return err
	}
	return c.waitGlobalOp(ctx, project, op)
}

func (c *GCEAdminClient) DeleteTargetTCPProxy(ctx context.Context, project, name string) error {
	op, err := c.svc.TargetTcpProxies.Delete(project, name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	return c.waitGlobalOp(ctx, project, op)
}

// Forwarding Rules

func (c *GCEAdminClient) GetForwardingRule(ctx context.Context, project, name string) (*compute.ForwardingRule, error) {
	fr, err := c.svc.GlobalForwardingRules.Get(project, name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return fr, nil
}

func (c *GCEAdminClient) CreateForwardingRule(ctx context.Context, project string, fr *compute.ForwardingRule) error {
	op, err := c.svc.GlobalForwardingRules.Insert(project, fr).Context(ctx).Do()
	if err != nil {
		return err
	}
	return c.waitGlobalOp(ctx, project, op)
}

func (c *GCEAdminClient) DeleteForwardingRule(ctx context.Context, project, name string) error {
	op, err := c.svc.GlobalForwardingRules.Delete(project, name).Context(ctx).Do()
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	return c.waitGlobalOp(ctx, project, op)
}

// Zones

func (c *GCEAdminClient) ListZones(ctx context.Context, project, region string) ([]string, error) {
	call := c.svc.Zones.List(project)
	var zones []string
	regionSuffix := fmt.Sprintf("/regions/%s", region)
	err := call.Pages(ctx, func(page *compute.ZoneList) error {
		for _, z := range page.Items {
			if strings.HasSuffix(z.Region, regionSuffix) || z.Region == region {
				zones = append(zones, z.Name)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(zones)
	return zones, nil
}

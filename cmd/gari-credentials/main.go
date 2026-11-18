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
	"errors"
	"fmt"
	"os"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/spiffe"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func main() {
	ctx := ctrl.SetupSignalHandler()
	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	namespace := os.Getenv("POD_NAMESPACE")
	restConfig, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("getting kubeconfig for credentials: %w", err)
	}
	return runWithConfig(ctx, restConfig, namespace)
}

func runWithConfig(ctx context.Context, restConfig *rest.Config, namespace string) error {
	if namespace == "" {
		return errors.New("POD_NAMESPACE environment variable is required")
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("adding corev1 to scheme: %w", err)
	}
	kubeClient, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("creating client for credentials: %w", err)
	}
	return spiffe.EnsureCredentials(ctx, kubeClient, namespace)
}

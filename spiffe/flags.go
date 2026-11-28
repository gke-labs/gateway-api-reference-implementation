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

package spiffe

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// DefaultOptions returns Options populated with defaults, reading
// AuthorityNamespace from the POD_NAMESPACE environment variable.
func DefaultOptions() Options {
	return Options{
		AuthorityNamespace: os.Getenv("POD_NAMESPACE"),
		RenewBefore:        DefaultRenewBefore,
	}
}

// BindFlags registers credential issuer command-line flags on flagSet.
func BindFlags(flagSet *flag.FlagSet, options *Options) {
	flagSet.StringVar(&options.AuthorityNamespace, "authority-namespace", options.AuthorityNamespace,
		"Namespace for the trust domain authority Secret. Defaults to the POD_NAMESPACE environment variable.")
	flagSet.DurationVar(&options.RenewBefore, "renew-before", options.RenewBefore,
		"Renew existing X.509-SVIDs whose remaining validity is at or below this duration.")
	flagSet.Var(&identityListFlag{identities: &options.Identities}, "identity",
		"Workload identity to issue as comma-separated key=value pairs "+
			"(required: namespace, service-account; optional: secret, bundle-configmap, service). Repeatable.")
}

// ParseIdentity parses a comma-separated key=value workload identity specification.
// Supported keys are namespace, service-account, secret, bundle-configmap, and service.
// Both namespace and service-account are required.
func ParseIdentity(specification string) (Identity, error) {
	if strings.TrimSpace(specification) == "" {
		return Identity{}, errors.New("identity specification must not be empty")
	}

	var identity Identity
	seenKeys := make(map[string]bool)
	for entry := range strings.SplitSeq(specification, ",") {
		key, value, ok := strings.Cut(entry, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || key == "" || value == "" {
			return Identity{}, fmt.Errorf("invalid identity entry %q: expected key=value", entry)
		}
		if seenKeys[key] {
			return Identity{}, fmt.Errorf("duplicate identity key %q", key)
		}
		seenKeys[key] = true

		switch key {
		case "namespace":
			identity.Namespace = value
		case "service-account":
			identity.ServiceAccount = value
		case "secret":
			identity.SecretName = value
		case "bundle-configmap":
			identity.BundleConfigMapName = value
		case "service":
			identity.ServiceName = value
		default:
			return Identity{}, fmt.Errorf("unknown identity key %q", key)
		}
	}

	if identity.Namespace == "" {
		return Identity{}, errors.New("identity requires namespace")
	}
	if identity.ServiceAccount == "" {
		return Identity{}, errors.New("identity requires service-account")
	}
	return identity, nil
}

type identityListFlag struct {
	identities *[]Identity
}

func (f *identityListFlag) String() string {
	if f.identities == nil {
		return ""
	}
	parts := make([]string, len(*f.identities))
	for i, identity := range *f.identities {
		parts[i] = fmt.Sprintf("namespace=%s,service-account=%s", identity.Namespace, identity.ServiceAccount)
	}
	return strings.Join(parts, ";")
}

func (f *identityListFlag) Set(value string) error {
	identity, err := ParseIdentity(value)
	if err != nil {
		return err
	}
	*f.identities = append(*f.identities, identity)
	return nil
}

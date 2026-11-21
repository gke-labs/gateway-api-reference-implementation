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

package gari

import (
	"flag"
	"strings"
)

type commaSeparatedSliceValue struct {
	slice *[]string
}

func (c commaSeparatedSliceValue) String() string {
	if c.slice == nil || len(*c.slice) == 0 {
		return ""
	}
	return strings.Join(*c.slice, ",")
}

func (c commaSeparatedSliceValue) Set(val string) error {
	for _, part := range strings.Split(val, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			*c.slice = append(*c.slice, trimmed)
		}
	}
	return nil
}

// CommaSeparatedSlice returns a flag.Value that binds a command-line flag
// to a string slice. Each occurrence of the flag is split on commas, trimmed of
// whitespace, and non-empty values are appended to the slice.
func CommaSeparatedSlice(slice *[]string) flag.Value {
	return commaSeparatedSliceValue{slice: slice}
}

type stringSliceValue struct {
	slice *[]string
}

func (s stringSliceValue) String() string {
	if s.slice == nil || len(*s.slice) == 0 {
		return ""
	}
	return strings.Join(*s.slice, ",")
}

func (s stringSliceValue) Set(val string) error {
	*s.slice = append(*s.slice, val)
	return nil
}

// StringSlice returns a flag.Value that appends flag values directly into the target slice.
func StringSlice(slice *[]string) flag.Value {
	return stringSliceValue{slice: slice}
}

// BindInternalAPIFlags registers the internal API server and client command-line flags on the given FlagSet.
func BindInternalAPIFlags(fs *flag.FlagSet, opts *Options) {
	fs.StringVar(&opts.InternalAPIAddress, "internal-api-address", opts.InternalAPIAddress, "Host and port of the controller's Service.")
	fs.StringVar(&opts.InternalAPIBindAddress, "internal-api-bind-address", opts.InternalAPIBindAddress, "The address the internal API server binds to (disabled by default).")
	fs.StringVar(&opts.InternalAPICAFile, "internal-api-ca-file", opts.InternalAPICAFile, "The trust bundle that verifies the controller's certificate.")
	fs.StringVar(&opts.InternalAPITLSCertFile, "internal-api-tls-cert-file", opts.InternalAPITLSCertFile, "Path to TLS server certificate file for internal API endpoint. The listener stays off until a certificate that data planes can verify is provided, and how it is provided is not settled.")
	fs.StringVar(&opts.InternalAPITLSKeyFile, "internal-api-tls-key-file", opts.InternalAPITLSKeyFile, "Path to TLS server private key file for internal API endpoint.")
	fs.StringVar(&opts.InternalAPITokenFile, "internal-api-token-file", opts.InternalAPITokenFile, "A projected ServiceAccount token with the audience the server expects.")
}

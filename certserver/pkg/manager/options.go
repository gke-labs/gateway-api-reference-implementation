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

package manager

import (
	"net/http"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/challenge"
	"github.com/gke-labs/gateway-api-reference-implementation/certserver/pkg/registry"
)

// Clock abstracts current time for testability.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time {
	return time.Now()
}

// Options configures the certserver Manager.
type Options struct {
	MaxHostnamesPerSet   int
	MaxHostnameLength    int
	MaxPendingOrders     int64
	RenewalRatio         float64
	RenewalJitterPercent float64
	InitialRetryBackoff  time.Duration
	MaxRetryBackoff      time.Duration
	RenewalCheckInterval time.Duration
	Clock                Clock
	BindingStore         registry.BindingStore
	ValidatedBindingTTL  time.Duration
	SelfCheckClient      *http.Client
	SelfCheckTimeout     time.Duration
	SelfCheckInterval    time.Duration
}

// DefaultOptions returns standard configuration defaults.
func DefaultOptions() Options {
	return Options{
		MaxHostnamesPerSet:   100,
		MaxHostnameLength:    253,
		MaxPendingOrders:     50,
		RenewalRatio:         2.0 / 3.0,
		RenewalJitterPercent: 0.05,
		InitialRetryBackoff:  1 * time.Minute,
		MaxRetryBackoff:      1 * time.Hour,
		RenewalCheckInterval: 1 * time.Minute,
		Clock:                realClock{},
		ValidatedBindingTTL:  challenge.DefaultValidatedBindingTTL,
		// SelfCheckTimeout is 15 seconds, comfortably longer than the GARI certificate source's
		// 1-second pending polling interval so that the controller has ample time to program
		// the data plane before self-check times out.
		SelfCheckTimeout:  15 * time.Second,
		SelfCheckInterval: 500 * time.Millisecond,
	}
}

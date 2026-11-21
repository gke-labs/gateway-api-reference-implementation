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

package state

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// ResourceNameForGateway computes the resource name for a Gateway within its namespace.
// The derived name is guaranteed to be a valid DNS-1035 label (at most 63 characters,
// lowercase alphanumeric and hyphens, starting with an alphabetic character and ending
// with an alphanumeric character) of the form "gari-<name>-<hash>".
func ResourceNameForGateway(gwName string) string {
	h := sha256.Sum256([]byte(gwName))
	hash := hex.EncodeToString(h[:4])

	var b strings.Builder
	for _, r := range strings.ToLower(gwName) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	clean := b.String()
	// Limit clean name length so "gari-<clean>-<hash>" stays within 63 characters.
	maxCleanLen := 63 - len("gari-") - len("-") - len(hash)
	if len(clean) > maxCleanLen {
		clean = clean[:maxCleanLen]
	}
	return fmt.Sprintf("gari-%s-%s", clean, hash)
}

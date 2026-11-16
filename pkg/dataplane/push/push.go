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

// Package push provides the transport protocol and types for direct configuration
// push from the controller to data planes.
package push

const (
	// MaxConfigMessageBytes is the maximum allowed size in bytes of a serialized
	// DataplaneConfig payload (4 MiB). This comfortably exceeds the 1 MiB Kubernetes
	// Secret limit. Because gRPC's default receive message limit applies to the
	// entire message including envelope and framing overhead, the server and client
	// raise their receive limit to cover it; the step that adds server and client
	// logic does so.
	MaxConfigMessageBytes = 4 * 1024 * 1024

	// MaxNACKReasonBytes is the maximum allowed length in bytes of a NACK reason string (1 KiB).
	// This bounds error message sizes while providing ample detail for diagnostics and Kubernetes
	// condition messages.
	MaxNACKReasonBytes = 1024
)

// HelloMessage wraps a Hello in a DataplaneMessage.
func HelloMessage(gatewayNamespace, gatewayName, appliedRevision string) *DataplaneMessage {
	return &DataplaneMessage{
		Body: &DataplaneMessage_Hello{
			Hello: &Hello{
				GatewayNamespace: gatewayNamespace,
				GatewayName:      gatewayName,
				AppliedRevision:  appliedRevision,
			},
		},
	}
}

// AckMessage wraps an Ack in a DataplaneMessage.
func AckMessage(appliedRevision string) *DataplaneMessage {
	return &DataplaneMessage{
		Body: &DataplaneMessage_Ack{
			Ack: &Ack{
				AppliedRevision: appliedRevision,
			},
		},
	}
}

// NackMessage wraps a Nack in a DataplaneMessage.
func NackMessage(revision, reason string) *DataplaneMessage {
	return &DataplaneMessage{
		Body: &DataplaneMessage_Nack{
			Nack: &Nack{
				Revision: revision,
				Reason:   reason,
			},
		},
	}
}

// ConfigMessage wraps a Config in a ControllerMessage.
func ConfigMessage(revision string, dataplaneConfig []byte) *ControllerMessage {
	return &ControllerMessage{
		Body: &ControllerMessage_Config{
			Config: &Config{
				Revision:        revision,
				DataplaneConfig: dataplaneConfig,
			},
		},
	}
}

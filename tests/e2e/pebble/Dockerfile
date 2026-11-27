# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM --platform=$BUILDPLATFORM golang:1.27.4 AS builder
WORKDIR /app
COPY certserver/api/go.mod certserver/api/go.sum ./certserver/api/
COPY certserver/go.mod certserver/go.sum certserver/go.work certserver/go.work.sum ./certserver/
WORKDIR /app/certserver
RUN --mount=type=cache,target=/go/pkg/mod go mod download
ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /pebble github.com/letsencrypt/pebble/v2/cmd/pebble

FROM gcr.io/distroless/static-debian12
COPY --from=builder /pebble /pebble
USER 65532:65532
ENTRYPOINT ["/pebble"]

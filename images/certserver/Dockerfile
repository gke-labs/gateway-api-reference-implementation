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
COPY go.mod go.sum ./
COPY certserver/api/go.mod certserver/api/go.sum ./certserver/api/
COPY certserver/go.mod certserver/go.sum certserver/go.work ./certserver/
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
WORKDIR /app/certserver
ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o certserver cmd/certserver/main.go

FROM gcr.io/distroless/static-debian12
WORKDIR /
COPY --from=builder /app/certserver/certserver .
USER 65532:65532
ENTRYPOINT ["/certserver"]

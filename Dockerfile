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

FROM golang:1.26.1 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o gari-operator cmd/gari-operator/main.go
RUN CGO_ENABLED=0 go build -o gari-gateway cmd/gari-gateway/main.go

FROM alpine:3.19
WORKDIR /
COPY --from=builder /app/gari-operator .
COPY --from=builder /app/gari-gateway .
USER 65532:65532
ENTRYPOINT ["/gari-operator"]

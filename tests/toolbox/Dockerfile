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

FROM golang:1.25.7 AS builder
WORKDIR /app
COPY main.go .
RUN CGO_ENABLED=0 go build -o toolbox main.go

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/toolbox .
ENTRYPOINT ["/app/toolbox"]

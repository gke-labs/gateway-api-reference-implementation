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

FROM golang:1.24

# Install git and other basics
RUN apt-get update && apt-get install -y git curl

# Install kind v0.31.0
RUN go install sigs.k8s.io/kind@v0.31.0

# Install kubectl v1.35.0
RUN arch=$(go env GOARCH) && \
    curl -LO "https://dl.k8s.io/release/v1.35.0/bin/linux/${arch}/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/

# Install docker CLI 29.2.1
RUN arch=$(go env GOARCH) && \
    if [ "$arch" = "amd64" ]; then docker_arch="x86_64"; \
    elif [ "$arch" = "arm64" ]; then docker_arch="aarch64"; \
    else docker_arch="$arch"; fi && \
    curl -sLo docker.tgz "https://download.docker.com/linux/static/stable/${docker_arch}/docker-29.2.1.tgz" && \
    tar -xzf docker.tgz --strip-components=1 docker/docker && \
    mv docker /usr/local/bin/ && \
    rm docker.tgz

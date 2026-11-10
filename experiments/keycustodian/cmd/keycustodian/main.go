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

//go:build linux || darwin

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	keycustodianv1alpha1 "github.com/gke-labs/gateway-api-reference-implementation/experiments/keycustodian/api/v1alpha1"
	"github.com/gke-labs/gateway-api-reference-implementation/experiments/keycustodian/pkg/custodian"
	"google.golang.org/grpc"
)

func parseIDList(input string) ([]uint32, error) {
	if input == "" {
		return nil, nil
	}
	parts := strings.Split(input, ",")
	results := make([]uint32, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid ID %q: %w", part, err)
		}
		results = append(results, uint32(id))
	}
	return results, nil
}

func main() {
	var (
		socketPath     string
		keysDirectory  string
		allowedUIDsRaw string
		allowedGIDsRaw string
	)

	flag.StringVar(&socketPath, "socket", "/var/run/keycustodian/keycustodian.sock", "Path to the Unix domain socket")
	flag.StringVar(&keysDirectory, "keys-dir", "", "Directory containing PEM private keys and certificates")
	flag.StringVar(&allowedUIDsRaw, "allowed-uids", "", "Comma-separated list of allowed caller UIDs")
	flag.StringVar(&allowedGIDsRaw, "allowed-gids", "", "Comma-separated list of allowed caller primary GIDs")
	flag.Parse()

	if socketPath == "" {
		log.Fatal("--socket is required")
	}

	allowedUIDs, err := parseIDList(allowedUIDsRaw)
	if err != nil {
		log.Fatalf("Invalid --allowed-uids: %v", err)
	}

	allowedGIDs, err := parseIDList(allowedGIDsRaw)
	if err != nil {
		log.Fatalf("Invalid --allowed-gids: %v", err)
	}

	if len(allowedUIDs) == 0 && len(allowedGIDs) == 0 {
		log.Fatal("at least one of --allowed-uids or --allowed-gids must be specified")
	}

	custodianServer, err := custodian.NewServer(keysDirectory)
	if err != nil {
		log.Fatalf("Failed to initialize custodian server: %v", err)
	}

	listener, err := custodian.ListenUnix(socketPath)
	if err != nil {
		log.Fatalf("Failed to listen on unix socket %s: %v", socketPath, err)
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil {
			log.Printf("Failed to close listener: %v", closeErr)
		}
		if removeErr := os.Remove(socketPath); removeErr != nil && !os.IsNotExist(removeErr) {
			log.Printf("Failed to remove socket: %v", removeErr)
		}
	}()

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(custodian.UnaryAuthInterceptor(allowedUIDs, allowedGIDs)),
		grpc.StreamInterceptor(custodian.StreamAuthInterceptor(allowedUIDs, allowedGIDs)),
	)
	keycustodianv1alpha1.RegisterKeyCustodianServiceServer(grpcServer, custodianServer)

	stopSignalChannel := make(chan os.Signal, 1)
	signal.Notify(stopSignalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopSignalChannel
		grpcServer.GracefulStop()
	}()

	log.Printf("keycustodian daemon listening on %s (mode 0660)", socketPath)
	if serveErr := grpcServer.Serve(listener); serveErr != nil {
		log.Fatalf("gRPC server error: %v", serveErr)
	}
}

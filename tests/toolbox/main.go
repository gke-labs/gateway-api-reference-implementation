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

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: toolbox <server|client> [args]")
	}

	mode := os.Args[1]
	switch mode {
	case "server":
		runServer()
	case "client":
		if len(os.Args) < 3 {
			log.Fatal("Usage: toolbox client <url> [hostname]")
		}
		hostname := ""
		if len(os.Args) >= 4 {
			hostname = os.Args[3]
		}
		runClient(os.Args[2], hostname)
	default:
		log.Fatalf("Unknown mode: %s", mode)
	}
}

func runServer() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request: %s %s %s", r.Method, r.URL.Path, r.Host)
		w.Header().Set("Content-Type", "application/json")

		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		body, _ := io.ReadAll(r.Body)

		resp := map[string]interface{}{
			"headers":  headers,
			"body":     string(body),
			"method":   r.Method,
			"path":     r.URL.Path,
			"hostname": r.Host,
		}

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("Failed to encode response: %v", err)
		}
	})

	log.Printf("Starting echo server on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func runClient(targetURL, hostname string) {
	log.Printf("Sending request to %s (Host: %s)", targetURL, hostname)
	client := &http.Client{}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}
	if hostname != "" {
		req.Host = hostname
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Body: %s\n", string(body))
}

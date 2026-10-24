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
	"flag"
	"fmt"
	"os"

	"github.com/gke-labs/gateway-api-reference-implementation/experiments/viewtypes/generator"
)

func main() {
	outDir := flag.String("out", ".", "Output directory for generated view types")
	flag.Parse()

	if err := generator.GenerateAll(*outDir); err != nil {
		fmt.Fprintf(os.Stderr, "viewgen error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully generated view types in %s\n", *outDir)
}

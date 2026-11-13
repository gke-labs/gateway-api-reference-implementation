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
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/certserver/api/jwt"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/api"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/certs"
	"github.com/gke-labs/gateway-api-reference-implementation/snigateway/pkg/frontend"
)

type stringSliceFlag []string

func (f *stringSliceFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringSliceFlag) Set(val string) error {
	*f = append(*f, val)
	return nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "generate-certs" {
		return runGenerateCerts(args[1:])
	}

	fs := flag.NewFlagSet("snigateway-frontend", flag.ContinueOnError)

	var listenAddrs stringSliceFlag
	fs.Var(&listenAddrs, "listen", "Address to listen on (can be specified multiple times, default :443)")
	var clientCAs stringSliceFlag
	fs.Var(&clientCAs, "client-ca", "Client CA allowlist entry in format <path-to-ca.crt>=<hostname-pattern>[,<hostname-pattern>...] (can be specified multiple times)")
	caCertPath := fs.String("ca-cert", "ca.crt", "Path to CA certificate PEM file (used when no --client-ca flags are specified)")
	serverCertPath := fs.String("server-cert", "server.crt", "Path to server certificate PEM file")
	serverKeyPath := fs.String("server-key", "server.key", "Path to server private key PEM file")
	internalHostname := fs.String("internal-hostname", api.DefaultInternalHostname, "Internal SNI hostname for mTLS management API")
	connectTimeout := fs.Duration("connect-timeout", 10*time.Second, "Timeout for client to dial back and claim pending connection")
	maxConnections := fs.Int("tcp-max-connections", 10000, "Maximum number of concurrent client connections per listener")
	idleTimeout := fs.Duration("tcp-idle-timeout", 0, "Idle timeout for spliced client connections (disabled by default)")
	maxHostnames := fs.Int("max-hostnames-per-session", frontend.DefaultMaxHostnamesPerSession, "Maximum number of hostnames a session may register")

	var jwtIssuers stringSliceFlag
	fs.Var(&jwtIssuers, "jwt-issuer", "JWT issuer URL for ServiceAccount token verification (repeatable)")
	var jwtJWKSFiles stringSliceFlag
	fs.Var(&jwtJWKSFiles, "jwt-jwks-file", "Path to JWKS file per issuer in format [<issuer>=]<path> (repeatable)")
	jwtAudience := fs.String("jwt-audience", jwt.DefaultAudience, "Required audience for ServiceAccount tokens")
	var clientSubjects stringSliceFlag
	fs.Var(&clientSubjects, "client-subject", "Client subject allowlist in format system:serviceaccount:<ns>:<sa>=<pattern>[,<pattern>...] (repeatable, <ns>:* allowed)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(listenAddrs) == 0 {
		listenAddrs = []string{":443"}
	}

	var jwtVerifier jwt.TokenVerifier
	if len(jwtIssuers) > 0 || len(jwtJWKSFiles) > 0 {
		var issuerConfigs []jwt.IssuerConfig
		jwksFileMap := make(map[string]string)
		for _, entry := range jwtJWKSFiles {
			if iss, filePath, ok := strings.Cut(entry, "="); ok && iss != "" && filePath != "" {
				jwksFileMap[jwt.NormalizeIssuer(iss)] = filePath
			} else {
				if len(jwtIssuers) == 1 {
					jwksFileMap[jwt.NormalizeIssuer(jwtIssuers[0])] = entry
				} else {
					return fmt.Errorf("bare --jwt-jwks-file %q is only valid when exactly one --jwt-issuer is configured; specify format <issuer>=<path> instead", entry)
				}
			}
		}

		for _, iss := range jwtIssuers {
			norm := jwt.NormalizeIssuer(iss)
			filePath := jwksFileMap[norm]
			delete(jwksFileMap, norm)
			issuerConfigs = append(issuerConfigs, jwt.IssuerConfig{
				IssuerURL: iss,
				JWKSFile:  filePath,
			})
		}
		for iss, filePath := range jwksFileMap {
			issuerConfigs = append(issuerConfigs, jwt.IssuerConfig{
				IssuerURL: iss,
				JWKSFile:  filePath,
			})
		}

		jwksCache, err := jwt.NewJWKSCache(issuerConfigs)
		if err != nil {
			return fmt.Errorf("initializing JWKS cache: %w", err)
		}
		jwtVerifier = jwt.NewVerifier(jwksCache, jwt.WithAudience(*jwtAudience))
	}

	var subjectAuthorizer frontend.Authorizer
	if len(clientSubjects) > 0 {
		var subjectRules []frontend.SubjectRule
		for _, entry := range clientSubjects {
			rule, err := frontend.ParseSubjectRule(entry)
			if err != nil {
				return fmt.Errorf("invalid --client-subject flag: %w", err)
			}
			subjectRules = append(subjectRules, rule)
		}
		subjectAuthorizer = frontend.NewSubjectAuthorizer(subjectRules)
	}

	clientCAPool := x509.NewCertPool()
	var caAuthorizer frontend.Authorizer

	if len(clientCAs) > 0 {
		allowedPatterns := make(map[string][]string)
		for _, entry := range clientCAs {
			caPath, patternsStr, ok := strings.Cut(entry, "=")
			if !ok || caPath == "" || patternsStr == "" {
				return fmt.Errorf("invalid --client-ca format %q, expected <path-to-ca.crt>=<hostname-pattern>[,<hostname-pattern>...]", entry)
			}

			caCertPEM, err := os.ReadFile(caPath)
			if err != nil {
				return fmt.Errorf("reading client CA cert from %s: %w", caPath, err)
			}

			parsedCerts, err := certs.ParseCertificatesFromPEM(caCertPEM)
			if err != nil {
				return fmt.Errorf("parsing client CA cert from %s: %w", caPath, err)
			}

			if !clientCAPool.AppendCertsFromPEM(caCertPEM) {
				return fmt.Errorf("failed to append client CA cert from %s to cert pool", caPath)
			}

			var patterns []string
			for _, p := range strings.Split(patternsStr, ",") {
				p = strings.Trim(strings.TrimSpace(p), "'\"")
				if p != "" {
					patterns = append(patterns, p)
				}
			}
			if len(patterns) == 0 {
				return fmt.Errorf("no patterns specified in --client-ca %q", entry)
			}

			for _, cert := range parsedCerts {
				fp := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
				allowedPatterns[fp] = append(allowedPatterns[fp], patterns...)
			}
		}
		caAuthorizer = frontend.NewCAAuthorizer(allowedPatterns)
	} else if jwtVerifier != nil {
		// In token mode without --client-ca, do not create an implicit CA grant.
		// Certificate clients alongside tokens must be explicitly authorized with --client-ca.
	} else {
		log.Printf("WARNING: No --client-ca flags specified. Registrations are unrestricted for CA %s", *caCertPath)
		caCertPEM, err := os.ReadFile(*caCertPath)
		if err != nil {
			return fmt.Errorf("reading CA cert from %s: %w", *caCertPath, err)
		}

		parsedCerts, err := certs.ParseCertificatesFromPEM(caCertPEM)
		if err != nil {
			return fmt.Errorf("parsing CA cert from %s: %w", *caCertPath, err)
		}

		if !clientCAPool.AppendCertsFromPEM(caCertPEM) {
			return fmt.Errorf("failed to append CA cert from %s to cert pool", *caCertPath)
		}

		allowedPatterns := make(map[string][]string)
		for _, cert := range parsedCerts {
			fp := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
			allowedPatterns[fp] = []string{"*"}
		}
		caAuthorizer = frontend.NewCAAuthorizer(allowedPatterns)
	}

	authorizer := frontend.NewCombinedAuthorizer(caAuthorizer, subjectAuthorizer)

	serverCertPEM, err := os.ReadFile(*serverCertPath)
	if err != nil {
		return fmt.Errorf("reading server cert from %s: %w", *serverCertPath, err)
	}

	serverKeyPEM, err := os.ReadFile(*serverKeyPath)
	if err != nil {
		return fmt.Errorf("reading server key from %s: %w", *serverKeyPath, err)
	}

	serverTLS, err := certs.NewServerTLSConfigWithCertPool(clientCAPool, serverCertPEM, serverKeyPEM)
	if err != nil {
		return fmt.Errorf("creating server TLS config: %w", err)
	}

	if jwtVerifier != nil {
		serverTLS.ClientAuth = tls.VerifyClientCertIfGiven
	} else {
		serverTLS.ClientAuth = tls.RequireAndVerifyClientCert
	}

	srv, err := frontend.NewServer(frontend.ServerConfig{
		ListenAddrs:            listenAddrs,
		InternalHostname:       *internalHostname,
		ServerTLSConfig:        serverTLS,
		ConnectTimeout:         *connectTimeout,
		Authorizer:             authorizer,
		MaxConnections:         *maxConnections,
		IdleTimeout:            *idleTimeout,
		MaxHostnamesPerSession: *maxHostnames,
		JWTVerifier:            jwtVerifier,
	})
	if err != nil {
		return fmt.Errorf("initializing frontend server: %w", err)
	}

	go func() {
		<-ctx.Done()
		log.Printf("Shutting down snigateway-frontend...")
		if err := srv.Close(); err != nil {
			log.Printf("failed to close frontend server: %v", err)
		}
	}()

	log.Printf("Starting snigateway-frontend listening on %v (internal SNI: %s)...", listenAddrs, *internalHostname)
	if err := srv.ListenAndServe(); err != nil {
		return fmt.Errorf("server stopped: %w", err)
	}

	return nil
}

func runGenerateCerts(args []string) error {
	fs := flag.NewFlagSet("generate-certs", flag.ContinueOnError)
	dir := fs.String("dir", ".", "Directory to write generated certificates to")
	serverName := fs.String("server-name", api.DefaultInternalHostname, "Server SNI hostname")
	clientCN := fs.String("client-name", "snigateway-client", "Client certificate CommonName")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := certs.GenerateAndWriteCertificates(*dir, *serverName, *clientCN); err != nil {
		return fmt.Errorf("generating certificates: %w", err)
	}

	fmt.Printf("Successfully generated certificates in %s:\n", *dir)
	fmt.Printf("  CA:     ca.crt, ca.key\n")
	fmt.Printf("  Server: server.crt, server.key\n")
	fmt.Printf("  Client: client.crt, client.key\n")
	return nil
}

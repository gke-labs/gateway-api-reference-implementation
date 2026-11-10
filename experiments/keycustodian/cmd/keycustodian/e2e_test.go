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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	keycustodianv1alpha1 "github.com/gke-labs/gateway-api-reference-implementation/experiments/keycustodian/api/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func createTestKey(dir, name string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644)
}

func startDaemon(t *testing.T, bin, keysDir, sockPath string, args ...string) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"--socket=" + sockPath, "--keys-dir=" + keysDir}, args...)...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start daemon: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		_ = os.Remove(sockPath)
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("unix", sockPath)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for socket: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func runClient(t *testing.T, sock string, expectDenied bool, uid uint32) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "KC_SOCK="+sock)
	if expectDenied {
		cmd.Env = append(cmd.Env, "KC_DENIED=1")
	}
	if uid != 0 && uid != uint32(os.Getuid()) {
		if os.Geteuid() != 0 {
			t.Skip("skipping denied caller test: running client as a different UID requires root or user namespace")
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		for p := filepath.Dir(os.Args[0]); p != "/" && p != "."; p = filepath.Dir(p) {
			_ = os.Chmod(p, 0755)
		}
		for p := filepath.Dir(sock); p != "/" && p != "."; p = filepath.Dir(p) {
			_ = os.Chmod(p, 0755)
		}
		_ = os.Chmod(sock, 0666)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("client failed: %v\noutput: %s", err, out)
	}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	sock := os.Getenv("KC_SOCK")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	conn, err := grpc.NewClient("unix://"+sock,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}),
	)
	if err != nil {
		log.Fatalf("connect failed: %v", err)
	}
	defer func() { _ = conn.Close() }()
	client := keycustodianv1alpha1.NewKeyCustodianServiceClient(conn)

	if os.Getenv("KC_DENIED") == "1" {
		digest := sha256.Sum256([]byte("test"))
		_, err := client.Sign(ctx, &keycustodianv1alpha1.SignRequest{
			Key:           "unknown-key",
			HashAlgorithm: keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256,
			Digest:        digest[:],
		})
		if status.Code(err) != codes.PermissionDenied {
			log.Fatalf("expected PermissionDenied on Sign, got: %v", err)
		}
		if _, err := client.ListKeys(ctx, &keycustodianv1alpha1.ListKeysRequest{}); status.Code(err) != codes.PermissionDenied {
			log.Fatalf("expected PermissionDenied on ListKeys, got: %v", err)
		}
		os.Exit(0)
	}

	listResp, err := client.ListKeys(ctx, &keycustodianv1alpha1.ListKeysRequest{})
	if err != nil || len(listResp.Keys) == 0 {
		log.Fatalf("ListKeys failed: %v, keys: %v", err, listResp.GetKeys())
	}
	chainResp, err := client.GetCertificateChain(ctx, &keycustodianv1alpha1.GetCertificateChainRequest{Key: listResp.Keys[0]})
	if err != nil {
		log.Fatalf("GetCertificateChain failed: %v", err)
	}
	block, _ := pem.Decode(chainResp.CertificateChain)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("ParseCertificate failed: %v", err)
	}
	digest := sha256.Sum256([]byte("payload"))
	signResp, err := client.Sign(ctx, &keycustodianv1alpha1.SignRequest{
		Key:           listResp.Keys[0],
		HashAlgorithm: keycustodianv1alpha1.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Digest:        digest[:],
	})
	if err != nil {
		log.Fatalf("Sign failed: %v", err)
	}
	pubKey := cert.PublicKey.(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(pubKey, digest[:], signResp.Signature) {
		log.Fatal("signature verification failed")
	}
	os.Exit(0)
}

func TestDaemonE2E(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "keycustodian")
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v: %s", err, out)
	}

	t.Run("RefusesEmptyAllowLists", func(t *testing.T) {
		cmd := exec.Command(bin, "--socket="+filepath.Join(t.TempDir(), "s.sock"), "--keys-dir="+t.TempDir())
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("expected daemon startup to fail with empty allow lists")
		}
		if !strings.Contains(string(out), "at least one of --allowed-uids or --allowed-gids must be specified") {
			t.Fatalf("unexpected output: %s", out)
		}
	})

	keysDir := t.TempDir()
	if err := createTestKey(keysDir, "p256"); err != nil {
		t.Fatalf("createTestKey failed: %v", err)
	}

	sockPath := filepath.Join(t.TempDir(), "kc.sock")
	startDaemon(t, bin, keysDir, sockPath, "--allowed-uids="+fmt.Sprint(os.Getuid()))

	t.Run("AllowedCaller", func(t *testing.T) {
		runClient(t, sockPath, false, 0)
	})

	t.Run("AllowedGIDCaller", func(t *testing.T) {
		gidSock := filepath.Join(t.TempDir(), "gid.sock")
		startDaemon(t, bin, keysDir, gidSock, "--allowed-gids="+fmt.Sprint(os.Getgid()))
		runClient(t, gidSock, false, 0)
	})

	t.Run("DeniedCaller_DifferentUID", func(t *testing.T) {
		runClient(t, sockPath, true, 65534)
	})

	t.Run("DeniedCaller_DisallowedUID", func(t *testing.T) {
		disallowedSock := filepath.Join(t.TempDir(), "disallowed.sock")
		startDaemon(t, bin, keysDir, disallowedSock, "--allowed-uids="+fmt.Sprint(os.Getuid()+9999))
		runClient(t, disallowedSock, true, 0)
	})
}

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

package push_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gke-labs/gateway-api-reference-implementation/pkg/dataplane/push"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// trivialPushServer implements push.PushServiceServer for protocol testing.
type trivialPushServer struct {
	push.UnimplementedPushServiceServer
	receivedMessages chan *push.DataplaneMessage
	sendConfigs      chan *push.ControllerMessage
	errors           chan error
}

func newTrivialPushServer() *trivialPushServer {
	return &trivialPushServer{
		receivedMessages: make(chan *push.DataplaneMessage, 10),
		sendConfigs:      make(chan *push.ControllerMessage, 10),
		errors:           make(chan error, 10),
	}
}

func (s *trivialPushServer) StreamConfig(stream grpc.BidiStreamingServer[push.DataplaneMessage, push.ControllerMessage]) error {
	// Goroutine to send configurations to the data plane.
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		for msg := range s.sendConfigs {
			if err := stream.Send(msg); err != nil {
				s.errors <- err
				return
			}
		}
	}()

	// Read messages from the data plane.
	for {
		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			s.errors <- err
			break
		}
		s.receivedMessages <- msg
	}

	<-sendDone
	return nil
}

func TestStreamConfig_Exchange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Start in-process gRPC server.
	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	server := newTrivialPushServer()
	grpcServer := grpc.NewServer()
	push.RegisterPushServiceServer(grpcServer, server)

	go func() {
		if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			t.Errorf("grpcServer.Serve error: %v", err)
		}
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		if err := lis.Close(); err != nil {
			t.Errorf("lis.Close error: %v", err)
		}
	})

	// 2. Connect client.
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
	)
	if err != nil {
		t.Fatalf("failed to dial bufnet: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("conn.Close error: %v", err)
		}
	})

	client := push.NewPushServiceClient(conn)
	stream, err := client.StreamConfig(ctx)
	if err != nil {
		t.Fatalf("StreamConfig failed: %v", err)
	}

	// 3. Data plane sends Hello message.
	helloMsg := push.HelloMessage("prod-gateway", "external-lb", "")
	if err := stream.Send(helloMsg); err != nil {
		t.Fatalf("client failed to send Hello: %v", err)
	}

	// Verify server received Hello.
	select {
	case received := <-server.receivedMessages:
		hello := received.GetHello()
		if hello == nil {
			t.Fatalf("expected Hello message, got: %v", received)
		}
		if hello.GetGatewayNamespace() != "prod-gateway" {
			t.Errorf("got gateway_namespace %q, want %q", hello.GetGatewayNamespace(), "prod-gateway")
		}
		if hello.GetGatewayName() != "external-lb" {
			t.Errorf("got gateway_name %q, want %q", hello.GetGatewayName(), "external-lb")
		}
		if hello.GetAppliedRevision() != "" {
			t.Errorf("got applied_revision %q, want empty", hello.GetAppliedRevision())
		}
	case err := <-server.errors:
		t.Fatalf("server encountered error: %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for Hello message on server")
	}

	// 4. Controller pushes Config message (rev-1).
	configPayload := []byte(`{"listeners":[{"port":80,"protocol":"HTTP"}]}`)
	server.sendConfigs <- push.ConfigMessage("rev-1", configPayload)

	// Verify client received Config.
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("client failed to receive Config: %v", err)
	}
	cfg := resp.GetConfig()
	if cfg == nil {
		t.Fatalf("expected Config message, got: %v", resp)
	}
	if cfg.GetRevision() != "rev-1" {
		t.Errorf("got revision %q, want %q", cfg.GetRevision(), "rev-1")
	}
	if !bytes.Equal(cfg.GetDataplaneConfig(), configPayload) {
		t.Errorf("got dataplane_config %q, want %q", cfg.GetDataplaneConfig(), configPayload)
	}

	// 5. Data plane replies with ACK.
	ackMsg := push.AckMessage("rev-1")
	if err := stream.Send(ackMsg); err != nil {
		t.Fatalf("client failed to send Ack: %v", err)
	}

	// Verify server received ACK.
	select {
	case received := <-server.receivedMessages:
		ack := received.GetAck()
		if ack == nil {
			t.Fatalf("expected Ack message, got: %v", received)
		}
		if ack.GetAppliedRevision() != "rev-1" {
			t.Errorf("got applied_revision %q, want %q", ack.GetAppliedRevision(), "rev-1")
		}
	case err := <-server.errors:
		t.Fatalf("server encountered error: %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for Ack message on server")
	}

	// 6. Controller pushes another Config message (rev-2).
	badPayload := []byte(`{"invalid"}`)
	server.sendConfigs <- push.ConfigMessage("rev-2", badPayload)

	// Verify client received Config (rev-2).
	resp2, err := stream.Recv()
	if err != nil {
		t.Fatalf("client failed to receive second Config: %v", err)
	}
	cfg2 := resp2.GetConfig()
	if cfg2 == nil {
		t.Fatalf("expected Config message, got: %v", resp2)
	}
	if cfg2.GetRevision() != "rev-2" {
		t.Errorf("got revision %q, want %q", cfg2.GetRevision(), "rev-2")
	}

	// 7. Data plane replies with NACK.
	const nackReason = "failed to parse DataplaneConfig: invalid JSON syntax"
	nackMsg := push.NackMessage("rev-2", nackReason)
	if err := stream.Send(nackMsg); err != nil {
		t.Fatalf("client failed to send Nack: %v", err)
	}

	// Verify server received NACK.
	select {
	case received := <-server.receivedMessages:
		nack := received.GetNack()
		if nack == nil {
			t.Fatalf("expected Nack message, got: %v", received)
		}
		if nack.GetRevision() != "rev-2" {
			t.Errorf("got revision %q, want %q", nack.GetRevision(), "rev-2")
		}
		if nack.GetReason() != nackReason {
			t.Errorf("got reason %q, want %q", nack.GetReason(), nackReason)
		}
	case err := <-server.errors:
		t.Fatalf("server encountered error: %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for Nack message on server")
	}

	// 8. Clean stream shutdown.
	close(server.sendConfigs)
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend failed: %v", err)
	}
}

// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Addr != ":8545" {
		t.Errorf("expected default addr :8545, got %q", cfg.Addr)
	}
	if cfg.MaxBatchSize <= 0 {
		t.Errorf("expected positive max batch size, got %d", cfg.MaxBatchSize)
	}
	if cfg.ReadTimeout <= 0 {
		t.Errorf("expected positive read timeout, got %v", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout <= 0 {
		t.Errorf("expected positive write timeout, got %v", cfg.WriteTimeout)
	}
}

func TestServerCreate_NoPanic(t *testing.T) {
	srv := NewServer(nil)
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
	if srv.handlers == nil {
		t.Error("handlers map not initialized")
	}
	srv.RegisterAdminMethod("test_admin")
	if srv.adminMethods == nil {
		t.Error("adminMethods map not initialized after registration")
	}
}

func TestServerCreate_WithConfig(t *testing.T) {
	cfg := &Config{
		Addr:            "127.0.0.1:9999",
		MaxBatchSize:    50,
		ReadTimeout:     10 * time.Second,
		WriteTimeout:    10 * time.Second,
		MaxBodySize:     1024 * 1024,
		MaxParamsLength: 512,
	}
	srv := NewServer(cfg)
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
}

func TestRegisterAndHandle(t *testing.T) {
	srv := NewServer(nil)
	srv.RegisterHandler("test_ping", func(_ context.Context, _ json.RawMessage) (any, *Error) {
		return "pong", nil
	})

	resp := srv.HandleRequest(context.Background(), &Request{
		JSONRPC: "2.0",
		Method:  "test_ping",
		ID:      1,
	})
	if resp.Result != "pong" {
		t.Errorf("expected pong, got %v", resp.Result)
	}
}

func TestHandleRequest_MissingMethod(t *testing.T) {
	srv := NewServer(nil)
	resp := srv.HandleRequest(context.Background(), &Request{
		JSONRPC: "2.0",
		ID:      1,
	})
	if resp.Error == nil {
		t.Error("expected error for empty method")
	}
}

func TestHandleRequest_WithError(t *testing.T) {
	srv := NewServer(nil)
	srv.RegisterHandler("test_fail", func(_ context.Context, _ json.RawMessage) (any, *Error) {
		return nil, NewError(-32000, "something went wrong")
	})

	resp := srv.HandleRequest(context.Background(), &Request{
		JSONRPC: "2.0",
		Method:  "test_fail",
		ID:      1,
	})
	if resp.Error == nil {
		t.Error("expected error from handler")
	}
}

func TestHandleBatchRequest_Empty(t *testing.T) {
	srv := NewServer(nil)
	responses := srv.HandleBatchRequest(context.Background(), nil)
	if len(responses) != 0 {
		t.Errorf("expected 0 responses, got %d", len(responses))
	}
}

func TestAdminMethodRegistration(t *testing.T) {
	srv := NewServer(nil)
	srv.RegisterAdminMethod("admin_secret")
	srv.RegisterAdminMethod("admin_secret")
}

func TestUnregisterHandler_NotFound(t *testing.T) {
	srv := NewServer(nil)
	srv.UnregisterHandler("nonexistent_method")
}

func TestHandleBatchRequest_Mixed(t *testing.T) {
	srv := NewServer(nil)
	srv.RegisterHandler("test_one", func(_ context.Context, _ json.RawMessage) (any, *Error) {
		return "one", nil
	})

	responses := srv.HandleBatchRequest(context.Background(), []Request{
		{JSONRPC: "2.0", Method: "test_one", ID: 1},
		{JSONRPC: "2.0", Method: "test_unknown", ID: 2},
	})
	if len(responses) != 2 {
		t.Fatalf("expected 2 responses, got %d", len(responses))
	}
	if responses[0].Result != "one" {
		t.Errorf("item 0: expected one, got %v", responses[0].Result)
	}
	if responses[1].Error == nil {
		t.Error("item 1: expected error for unknown method")
	}
}

func TestHTTPServer_StartStop(t *testing.T) {
	cfg := &Config{
		Addr:            "127.0.0.1:0",
		MaxBatchSize:    10,
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    5 * time.Second,
		MaxBodySize:     1 << 20,
		MaxParamsLength: 256,
	}
	srv := NewServer(cfg)

	done := make(chan error, 1)
	go func() {
		done <- srv.Start("127.0.0.1:0")
	}()

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Stop(ctx); err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

func TestHandleRequest_InvalidJSONRPC(t *testing.T) {
	srv := NewServer(nil)
	resp := srv.HandleRequest(context.Background(), &Request{
		JSONRPC: "1.0",
		Method:  "test",
		ID:      1,
	})
	if resp.Error == nil {
		t.Error("expected error for invalid JSONRPC version")
	}
}

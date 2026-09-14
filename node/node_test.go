// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"
)

func TestEmptyConfig(t *testing.T) {
	cfg := &Config{}
	if cfg.Name == "" && cfg.DataDir == "" {
		return
	}
}

func TestNewNode_NoPanic(t *testing.T) {
	cfg := &Config{Name: "test", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestNode_Config(t *testing.T) {
	cfg := &Config{Name: "test2", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	c := n.Config()
	if c == nil {
		t.Fatal("expected non-nil config from node")
	}
	if c.Name != "test2" {
		t.Errorf("expected name test2, got %s", c.Name)
	}
}

func TestNode_Stop_Unstarted(t *testing.T) {
	cfg := &Config{Name: "test3", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	err = n.Stop()
	if err == nil {
		t.Error("expected error when stopping unstarted node")
	}
}

func TestNode_IsRunning(t *testing.T) {
	cfg := &Config{Name: "test4", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	if n.IsRunning() {
		t.Error("expected node not running after creation")
	}
}

func TestNode_ConfigValidation_NilConfig(t *testing.T) {
	n, err := NewNode(nil)
	if err != nil {
		t.Fatalf("NewNode with nil config (should use defaults): %v", err)
	}
	defer closeNodeDB(n)
	if n == nil {
		t.Fatal("expected non-nil node from nil config")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Name == "" {
		t.Error("expected non-empty name in default config")
	}
}

func TestNode_ChainID(t *testing.T) {
	cfg := &Config{Name: "test5", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n.ChainID()
}

func TestNode_ProtocolVersion(t *testing.T) {
	cfg := &Config{Name: "test6", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	v := n.ProtocolVersion()
	if v == "" {
		t.Error("expected non-empty protocol version")
	}
}

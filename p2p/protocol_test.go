// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"
)

func TestProtocolRegistryRegister(t *testing.T) {
	r := NewProtocolRegistry()

	spec := ProtocolSpec{
		Name:    ProtocolBlockchain,
		Version: ProtocolBlockchainVersion,
		MsgTypes: map[uint8]bool{
			MsgTypeBlock: true,
			MsgTypeVote:  true,
		},
	}

	err := r.Register(spec)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if r.ProtocolCount() != 1 {
		t.Errorf("ProtocolCount = %d, want 1", r.ProtocolCount())
	}

	if r.EnabledProtocolCount() != 1 {
		t.Errorf("EnabledProtocolCount = %d, want 1", r.EnabledProtocolCount())
	}
}

func TestProtocolRegistryDuplicateRegister(t *testing.T) {
	r := NewProtocolRegistry()

	spec := ProtocolSpec{
		Name:     ProtocolBlockchain,
		Version:  1,
		MsgTypes: map[uint8]bool{MsgTypeBlock: true},
	}
	_ = r.Register(spec)

	err := r.Register(spec)
	if err == nil {
		t.Error("expected error for duplicate registration")
	}
}

func TestProtocolRegistryDuplicateMsgType(t *testing.T) {
	r := NewProtocolRegistry()

	spec1 := ProtocolSpec{
		Name:     "proto1",
		Version:  1,
		MsgTypes: map[uint8]bool{MsgTypeBlock: true},
	}
	_ = r.Register(spec1)

	spec2 := ProtocolSpec{
		Name:     "proto2",
		Version:  1,
		MsgTypes: map[uint8]bool{MsgTypeBlock: true},
	}
	err := r.Register(spec2)
	if err == nil {
		t.Error("expected error for duplicate message type")
	}
}

func TestProtocolRegistryUnregister(t *testing.T) {
	r := NewProtocolRegistry()

	spec := ProtocolSpec{
		Name:     ProtocolBlockchain,
		Version:  1,
		MsgTypes: map[uint8]bool{MsgTypeBlock: true},
	}
	_ = r.Register(spec)

	r.Unregister(ProtocolBlockchain)

	if r.ProtocolCount() != 0 {
		t.Errorf("ProtocolCount after unregister = %d, want 0", r.ProtocolCount())
	}

	if r.IsMessageSupported(MsgTypeBlock) {
		t.Error("MsgTypeBlock should not be supported after unregister")
	}
}

func TestProtocolRegistryGetProtocol(t *testing.T) {
	r := NewProtocolRegistry()

	spec := ProtocolSpec{
		Name:     ProtocolBlockchain,
		Version:  1,
		MsgTypes: map[uint8]bool{MsgTypeBlock: true},
	}
	_ = r.Register(spec)

	p := r.GetProtocol(ProtocolBlockchain)
	if p == nil {
		t.Fatal("GetProtocol returned nil")
	}
	if p.Spec.Name != ProtocolBlockchain {
		t.Errorf("Spec.Name = %q, want %q", p.Spec.Name, ProtocolBlockchain)
	}
	if !p.Enabled {
		t.Error("protocol should be enabled by default")
	}

	// Unknown protocol
	if r.GetProtocol("unknown") != nil {
		t.Error("GetProtocol for unknown should return nil")
	}
}

func TestProtocolRegistryRouteMessage(t *testing.T) {
	r := NewProtocolRegistry()

	called := false
	spec := ProtocolSpec{
		Name:     ProtocolBlockchain,
		Version:  1,
		MsgTypes: map[uint8]bool{MsgTypeBlock: true},
		Handler: func(msg *Message) error {
			called = true
			return nil
		},
	}
	_ = r.Register(spec)

	err := r.RouteMessage(&Message{Type: MsgTypeBlock, Payload: []byte("data")})
	if err != nil {
		t.Fatalf("RouteMessage failed: %v", err)
	}
	if !called {
		t.Error("handler was not called")
	}
}

func TestProtocolRegistryRouteUnsupported(t *testing.T) {
	r := NewProtocolRegistry()

	err := r.RouteMessage(&Message{Type: 99, Payload: []byte("data")})
	if err == nil {
		t.Error("expected error for unsupported message type")
	}
}

func TestProtocolRegistryRouteDisabled(t *testing.T) {
	r := NewProtocolRegistry()

	spec := ProtocolSpec{
		Name:     ProtocolBlockchain,
		Version:  1,
		MsgTypes: map[uint8]bool{MsgTypeBlock: true},
		Handler:  func(msg *Message) error { return nil },
	}
	_ = r.Register(spec)
	_ = r.DisableProtocol(ProtocolBlockchain)

	err := r.RouteMessage(&Message{Type: MsgTypeBlock, Payload: []byte("data")})
	if err == nil {
		t.Error("expected error for disabled protocol")
	}
}

func TestProtocolRegistryEnableDisable(t *testing.T) {
	r := NewProtocolRegistry()

	spec := ProtocolSpec{
		Name:     ProtocolBlockchain,
		Version:  1,
		MsgTypes: map[uint8]bool{MsgTypeBlock: true},
	}
	_ = r.Register(spec)

	if !r.IsProtocolEnabled(ProtocolBlockchain) {
		t.Error("protocol should be enabled initially")
	}

	err := r.DisableProtocol(ProtocolBlockchain)
	if err != nil {
		t.Fatalf("DisableProtocol failed: %v", err)
	}
	if r.IsProtocolEnabled(ProtocolBlockchain) {
		t.Error("protocol should be disabled")
	}
	if r.EnabledProtocolCount() != 0 {
		t.Errorf("EnabledProtocolCount = %d, want 0", r.EnabledProtocolCount())
	}

	err = r.EnableProtocol(ProtocolBlockchain)
	if err != nil {
		t.Fatalf("EnableProtocol failed: %v", err)
	}
	if !r.IsProtocolEnabled(ProtocolBlockchain) {
		t.Error("protocol should be enabled after re-enabling")
	}
}

func TestProtocolRegistryEnableDisableUnknown(t *testing.T) {
	r := NewProtocolRegistry()

	err := r.EnableProtocol("unknown")
	if err == nil {
		t.Error("expected error for enabling unknown protocol")
	}

	err = r.DisableProtocol("unknown")
	if err == nil {
		t.Error("expected error for disabling unknown protocol")
	}
}

func TestProtocolRegistrySupportedProtocols(t *testing.T) {
	r := NewProtocolRegistry()

	_ = r.Register(ProtocolSpec{
		Name:     ProtocolBlockchain,
		Version:  1,
		MsgTypes: map[uint8]bool{MsgTypeBlock: true},
	})
	_ = r.Register(ProtocolSpec{
		Name:     ProtocolConsensus,
		Version:  1,
		MsgTypes: map[uint8]bool{MsgTypeVote: true},
	})

	specs := r.SupportedProtocols()
	if len(specs) != 2 {
		t.Fatalf("len(SupportedProtocols) = %d, want 2", len(specs))
	}
}

func TestProtocolRegistryNegotiate(t *testing.T) {
	r := NewProtocolRegistry()

	_ = r.Register(ProtocolSpec{
		Name:     ProtocolBlockchain,
		Version:  1,
		MsgTypes: map[uint8]bool{MsgTypeBlock: true},
	})
	_ = r.Register(ProtocolSpec{
		Name:     ProtocolConsensus,
		Version:  1,
		MsgTypes: map[uint8]bool{MsgTypeVote: true},
	})

	peerProtocols := []ProtocolSpec{
		{Name: ProtocolBlockchain, Version: 1},
		{Name: ProtocolConsensus, Version: 2}, // Version mismatch
		{Name: "unknown_proto", Version: 1},
	}

	common := r.Negotiate(peerProtocols)
	if len(common) != 1 {
		t.Fatalf("len(Negotiate) = %d, want 1", len(common))
	}
	if common[0].Name != ProtocolBlockchain {
		t.Errorf("common[0].Name = %q, want %q", common[0].Name, ProtocolBlockchain)
	}
}

func TestProtocolRegistryGetMessageProtocol(t *testing.T) {
	r := NewProtocolRegistry()

	_ = r.Register(ProtocolSpec{
		Name:     ProtocolBlockchain,
		Version:  1,
		MsgTypes: map[uint8]bool{MsgTypeBlock: true},
	})

	protoName := r.GetMessageProtocol(MsgTypeBlock)
	if protoName != ProtocolBlockchain {
		t.Errorf("GetMessageProtocol(MsgTypeBlock) = %q, want %q", protoName, ProtocolBlockchain)
	}

	unknownProto := r.GetMessageProtocol(99)
	if unknownProto != "" {
		t.Errorf("GetMessageProtocol(99) = %q, want empty", unknownProto)
	}
}

func TestProtocolRegistryIsMessageSupported(t *testing.T) {
	r := NewProtocolRegistry()

	_ = r.Register(ProtocolSpec{
		Name:     ProtocolBlockchain,
		Version:  1,
		MsgTypes: map[uint8]bool{MsgTypeBlock: true},
	})

	if !r.IsMessageSupported(MsgTypeBlock) {
		t.Error("MsgTypeBlock should be supported")
	}
	if r.IsMessageSupported(99) {
		t.Error("type 99 should not be supported")
	}
}

func TestProtocolRegistryCaseInsensitive(t *testing.T) {
	r := NewProtocolRegistry()

	_ = r.Register(ProtocolSpec{
		Name:     "QAU_Blockchain",
		Version:  1,
		MsgTypes: map[uint8]bool{MsgTypeBlock: true},
	})

	// Should be accessible with lowercase
	p := r.GetProtocol("qau_blockchain")
	if p == nil {
		t.Error("GetProtocol should be case-insensitive")
	}

	// Should be accessible with uppercase
	p = r.GetProtocol("QAU_BLOCKCHAIN")
	if p == nil {
		t.Error("GetProtocol should be case-insensitive")
	}
}

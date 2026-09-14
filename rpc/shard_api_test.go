// Quantaureum Node source, version 1.0.0.
// Tests for the sharding RPC API (qau_shard*).
//
// P1-3 (2026-07-14): verifies nil-safety, read-only query paths,
// cross-shard message submission, and helper parsing functions.
package rpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
	qaucrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// --- Test helpers (local implementations, independent of consensus pkg internals) ---

// nilMainChainCommitter is a minimal MainChainCommitter for tests.
type nilMainChainCommitter struct{}

func (m *nilMainChainCommitter) SubmitShardCommitment(_ *consensus.ShardCommitment) error {
	return nil
}
func (m *nilMainChainCommitter) VerifyShardCommitment(_ *consensus.ShardCommitment) (bool, error) {
	return false, nil
}
func (m *nilMainChainCommitter) GetLatestSlot() uint64 { return 0 }

// mockElectionVerifierForRPC accepts all proposers (test-only).
type mockElectionVerifierForRPC struct{}

func (m *mockElectionVerifierForRPC) VerifyProposerElection(_ types.Address, _ []byte, _ types.Hash, _ uint64) error {
	return nil
}

// rpcTestKey caches Dilithium3 key pairs by address to avoid expensive
// regeneration across tests.
var rpcTestKeyCache = make(map[types.Address]*qaucrypto.KeyPair)

func getRPCTestKey(addr types.Address) *qaucrypto.KeyPair {
	if kp, ok := rpcTestKeyCache[addr]; ok {
		return kp
	}
	kp, err := qaucrypto.GenerateKeyPair()
	if err != nil {
		panic("failed to generate test key pair: " + err.Error())
	}
	rpcTestKeyCache[addr] = kp
	return kp
}

// setupShardAPIWithChain creates a ShardManager with one active shard and
// returns the API plus the chain + validators for further test setup.
func setupShardAPIWithChain(t *testing.T) (*ShardAPI, *consensus.ShardChain, []types.Address) {
	t.Helper()
	mc := &nilMainChainCommitter{}
	sm := consensus.NewShardManager(mc)

	validators := make([]types.Address, 3)
	for i := range validators {
		rand.Read(validators[i][:])
		validators[i][0] = byte(i + 1)
	}
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard failed: %v", err)
	}
	for _, v := range validators {
		kp := getRPCTestKey(v)
		chain.SetValidatorPubKey(v, kp.Public.Bytes())
	}
	chain.SetElectionVerifier(&mockElectionVerifierForRPC{})
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard failed: %v", err)
	}
	return NewShardAPI(sm), chain, validators
}

// computeCrossShardSigningHashForRPC replicates consensus.computeCrossShardMessageSigningHash
// so the rpc test package can sign messages without accessing unexported helpers.
func computeCrossShardSigningHashForRPC(msg *consensus.CrossShardMessage) []byte {
	h := sha3.New256()
	h.Write(msg.ID[:])
	var srcBytes, dstBytes, nonceBytes, tsBytes [8]byte
	for i := 0; i < 8; i++ {
		srcBytes[i] = byte(msg.SourceShard >> (8 * i))
		dstBytes[i] = byte(msg.DestShard >> (8 * i))
		nonceBytes[i] = byte(msg.Nonce >> (8 * i))
		tsBytes[i] = byte(msg.Timestamp >> (8 * i))
	}
	h.Write(srcBytes[:])
	h.Write(dstBytes[:])
	h.Write(msg.Sender[:])
	h.Write(msg.Recipient[:])
	h.Write(msg.Payload)
	h.Write(nonceBytes[:])
	h.Write(tsBytes[:])
	return h.Sum(nil)
}

// signCrossShardMsgForRPC signs a cross-shard message with the sender's key.
func signCrossShardMsgForRPC(sender types.Address, msg *consensus.CrossShardMessage) []byte {
	kp := getRPCTestKey(sender)
	sig, err := qaucrypto.Sign(kp.Private, computeCrossShardSigningHashForRPC(msg))
	if err != nil {
		panic("failed to sign: " + err.Error())
	}
	return sig
}

// --- Nil-safety tests ---

func TestShardAPI_NilManager_GetShardCount(t *testing.T) {
	api := NewShardAPI(nil)
	_, rerr := api.GetShardCount(context.Background(), nil)
	if rerr == nil {
		t.Fatal("expected error for nil manager")
	}
	if rerr.Code != -32601 {
		t.Errorf("expected code -32601, got %d", rerr.Code)
	}
}

func TestShardAPI_NilManager_GetActiveShardCount(t *testing.T) {
	api := NewShardAPI(nil)
	_, rerr := api.GetActiveShardCount(context.Background(), nil)
	if rerr == nil || rerr.Code != -32601 {
		t.Fatalf("expected -32601, got %v", rerr)
	}
}

func TestShardAPI_NilManager_GetShard(t *testing.T) {
	api := NewShardAPI(nil)
	params, _ := json.Marshal(map[string]any{"shardId": 1})
	_, rerr := api.GetShard(context.Background(), params)
	if rerr == nil || rerr.Code != -32601 {
		t.Fatalf("expected -32601, got %v", rerr)
	}
}

func TestShardAPI_NilManager_GetBlock(t *testing.T) {
	api := NewShardAPI(nil)
	params, _ := json.Marshal(map[string]any{"shardId": 1, "height": 1})
	_, rerr := api.GetBlock(context.Background(), params)
	if rerr == nil || rerr.Code != -32601 {
		t.Fatalf("expected -32601, got %v", rerr)
	}
}

func TestShardAPI_NilManager_SubmitCrossShardMessage(t *testing.T) {
	api := NewShardAPI(nil)
	params, _ := json.Marshal(map[string]any{})
	_, rerr := api.SubmitCrossShardMessage(context.Background(), params)
	if rerr == nil || rerr.Code != -32601 {
		t.Fatalf("expected -32601, got %v", rerr)
	}
}

func TestShardAPI_NilManager_GetReceipt(t *testing.T) {
	api := NewShardAPI(nil)
	params, _ := json.Marshal(map[string]any{"shardId": 1, "messageId": "0x" + strings.Repeat("00", 32)})
	_, rerr := api.GetReceipt(context.Background(), params)
	if rerr == nil || rerr.Code != -32601 {
		t.Fatalf("expected -32601, got %v", rerr)
	}
}

func TestShardAPI_NilManager_IsReceiptSpent(t *testing.T) {
	api := NewShardAPI(nil)
	params, _ := json.Marshal(map[string]any{"shardId": 1, "messageId": "0x" + strings.Repeat("00", 32)})
	_, rerr := api.IsReceiptSpent(context.Background(), params)
	if rerr == nil || rerr.Code != -32601 {
		t.Fatalf("expected -32601, got %v", rerr)
	}
}

// --- Read-only query tests ---

func TestShardAPI_GetShardCount(t *testing.T) {
	api, _, _ := setupShardAPIWithChain(t)
	count, rerr := api.GetShardCount(context.Background(), nil)
	if rerr != nil {
		t.Fatalf("unexpected error: %v", rerr)
	}
	if count.(int) != 1 {
		t.Errorf("expected 1 shard, got %d", count)
	}
}

func TestShardAPI_GetActiveShardCount(t *testing.T) {
	api, _, _ := setupShardAPIWithChain(t)
	count, rerr := api.GetActiveShardCount(context.Background(), nil)
	if rerr != nil {
		t.Fatalf("unexpected error: %v", rerr)
	}
	if count.(int) != 1 {
		t.Errorf("expected 1 active shard, got %d", count)
	}
}

func TestShardAPI_GetShard(t *testing.T) {
	api, chain, _ := setupShardAPIWithChain(t)
	params, _ := json.Marshal(map[string]any{"shardId": chain.ShardID()})
	result, rerr := api.GetShard(context.Background(), params)
	if rerr != nil {
		t.Fatalf("unexpected error: %v", rerr)
	}
	m := result.(map[string]any)
	if m["shardId"].(uint64) != chain.ShardID() {
		t.Errorf("shardId mismatch: got %v", m["shardId"])
	}
	if m["status"].(string) != "Active" {
		t.Errorf("expected Active, got %v", m["status"])
	}
	vals, ok := m["validators"].([]string)
	if !ok {
		t.Fatalf("validators should be []string, got %T", m["validators"])
	}
	if len(vals) != 3 {
		t.Errorf("expected 3 validators, got %d", len(vals))
	}
}

func TestShardAPI_GetShard_NotFound(t *testing.T) {
	api, _, _ := setupShardAPIWithChain(t)
	params, _ := json.Marshal(map[string]any{"shardId": 999})
	_, rerr := api.GetShard(context.Background(), params)
	if rerr == nil {
		t.Fatal("expected error for missing shard")
	}
	if rerr.Code != -32601 {
		t.Errorf("expected -32601, got %d", rerr.Code)
	}
}

func TestShardAPI_GetShard_ZeroShardID(t *testing.T) {
	api, _, _ := setupShardAPIWithChain(t)
	// Missing shardId field → zero value (0), which won't match any shard.
	params, _ := json.Marshal(map[string]any{})
	_, rerr := api.GetShard(context.Background(), params)
	if rerr == nil {
		t.Fatal("expected error for zero shardId")
	}
}

func TestShardAPI_GetBlock_NotFound(t *testing.T) {
	api, chain, _ := setupShardAPIWithChain(t)
	params, _ := json.Marshal(map[string]any{"shardId": chain.ShardID(), "height": 99})
	_, rerr := api.GetBlock(context.Background(), params)
	if rerr == nil {
		t.Fatal("expected error for missing block")
	}
}

func TestShardAPI_GetCommitment_NotFound(t *testing.T) {
	api, chain, _ := setupShardAPIWithChain(t)
	params, _ := json.Marshal(map[string]any{"shardId": chain.ShardID(), "height": 99})
	_, rerr := api.GetCommitment(context.Background(), params)
	if rerr == nil {
		t.Fatal("expected error for missing commitment")
	}
}

// --- Cross-shard message tests ---

func TestShardAPI_SubmitCrossShardMessage_InvalidAddress(t *testing.T) {
	api, chain, validators := setupShardAPIWithChain(t)
	params, _ := json.Marshal(map[string]any{
		"sourceShard": chain.ShardID(),
		"destShard":   chain.ShardID(),
		"sender":      "not-a-hex-address",
		"recipient":   "0x" + hex.EncodeToString(validators[1][:]),
		"payload":     "0xdeadbeef",
		"nonce":       1,
		"signature":   "0x",
	})
	_, rerr := api.SubmitCrossShardMessage(context.Background(), params)
	if rerr == nil {
		t.Fatal("expected error for invalid sender")
	}
	if rerr.Code != -32602 {
		t.Errorf("expected -32602 invalid params, got %d", rerr.Code)
	}
}

func TestShardAPI_SubmitCrossShardMessage_Success(t *testing.T) {
	api, chain, validators := setupShardAPIWithChain(t)
	// RPC-FIX: timestamp must be within ±5 minutes of current time.
	// Previously used a fixed 2009 timestamp which is now rejected by the
	// freshness check added in RPC-.
	msg := &consensus.CrossShardMessage{
		SourceShard: chain.ShardID(),
		DestShard:   chain.ShardID(),
		Sender:      validators[0],
		Recipient:   validators[1],
		Payload:     []byte{0xde, 0xad, 0xbe, 0xef},
		Nonce:       1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	msg.ID = consensus.GenerateCrossShardMessageID(msg.SourceShard, msg.DestShard, msg.Sender, msg.Nonce)
	msg.Signature = signCrossShardMsgForRPC(validators[0], msg)

	params, _ := json.Marshal(map[string]any{
		"sourceShard": msg.SourceShard,
		"destShard":   msg.DestShard,
		"sender":      "0x" + hex.EncodeToString(msg.Sender[:]),
		"recipient":   "0x" + hex.EncodeToString(msg.Recipient[:]),
		"payload":     "0x" + hex.EncodeToString(msg.Payload),
		"nonce":       msg.Nonce,
		"timestamp":   msg.Timestamp,
		"signature":   "0x" + hex.EncodeToString(msg.Signature),
	})

	result, rerr := api.SubmitCrossShardMessage(context.Background(), params)
	if rerr != nil {
		t.Fatalf("unexpected error: %v", rerr)
	}
	m := result.(map[string]any)
	if m["accepted"].(bool) != true {
		t.Error("expected accepted=true")
	}
	idHex, ok := m["messageId"].(string)
	if !ok || !strings.HasPrefix(idHex, "0x") {
		t.Errorf("invalid messageId: %v", m["messageId"])
	}
}

func TestShardAPI_GetReceipt_NotFound(t *testing.T) {
	api, chain, _ := setupShardAPIWithChain(t)
	zeroID := "0x" + strings.Repeat("00", 32)
	params, _ := json.Marshal(map[string]any{"shardId": chain.ShardID(), "messageId": zeroID})
	_, rerr := api.GetReceipt(context.Background(), params)
	if rerr == nil {
		t.Fatal("expected error for missing receipt")
	}
}

func TestShardAPI_IsReceiptSpent_NotFound(t *testing.T) {
	api, chain, _ := setupShardAPIWithChain(t)
	zeroID := "0x" + strings.Repeat("00", 32)
	params, _ := json.Marshal(map[string]any{"shardId": chain.ShardID(), "messageId": zeroID})
	result, rerr := api.IsReceiptSpent(context.Background(), params)
	if rerr != nil {
		t.Fatalf("unexpected error: %v", rerr)
	}
	// IsReceiptSpent returns false for unknown receipts (not an error).
	if result.(bool) != false {
		t.Errorf("expected false for unspent receipt, got %v", result)
	}
}

// --- Helper function tests ---

func TestParseHexAddress_With0x(t *testing.T) {
	expected := types.Address{0x01, 0x02, 0x03}
	got, err := parseHexAddress("0x" + hex.EncodeToString(expected[:]))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != expected {
		t.Errorf("expected %x, got %x", expected, got)
	}
}

func TestParseHexAddress_Without0x(t *testing.T) {
	expected := types.Address{0xaa, 0xbb}
	got, err := parseHexAddress(hex.EncodeToString(expected[:]))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != expected {
		t.Errorf("expected %x, got %x", expected, got)
	}
}

func TestParseHexAddress_Invalid(t *testing.T) {
	_, err := parseHexAddress("not-hex")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestParseHexHash_With0x(t *testing.T) {
	expected := types.Hash{0xab, 0xcd}
	got, err := parseHexHash("0x" + hex.EncodeToString(expected[:]))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != expected {
		t.Errorf("expected %x, got %x", expected, got)
	}
}

func TestParseHexHash_Invalid(t *testing.T) {
	_, err := parseHexHash("zzz")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

// --- RegisterHandlers smoke test ---

func TestShardAPI_RegisterHandlers(t *testing.T) {
	srv := NewServer(nil)
	api := NewShardAPI(nil)
	api.RegisterHandlers(srv)

	for _, method := range []string{
		"qau_shardGetShardCount",
		"qau_shardGetActiveShardCount",
		"qau_shardGetShard",
		"qau_shardGetBlock",
		"qau_shardGetCommitment",
		"qau_shardSubmitCrossShardMessage",
		"qau_shardGetReceipt",
		"qau_shardIsReceiptSpent",
	} {
		if _, ok := srv.handlers[method]; !ok {
			t.Errorf("method %s not registered", method)
		}
	}

	// SubmitCrossShardMessage should be admin-gated.
	if !srv.adminMethods["qau_shardSubmitCrossShardMessage"] {
		t.Error("qau_shardSubmitCrossShardMessage should be admin-gated")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// RPC- SubmitCrossShardMessage MUST reject timestamps too far from the
// current wall-clock. Without this check, an attacker can set msg.Timestamp to
// a far-future value to bypass engine future-window checks, or to a far-past
// value to have the message misclassified as expired.
// ─────────────────────────────────────────────────────────────────────────────

func TestShardAPI_SubmitCrossShardMessage_TimestampFreshness(t *testing.T) {
	api, chain, validators := setupShardAPIWithChain(t)

	now := uint64(time.Now().Unix())

	tests := []struct {
		name      string
		timestamp uint64
		wantErr   bool
		wantSubst string // substring expected in error message (empty = don't check)
	}{
		{"current timestamp accepted", now, false, ""},
		{"slightly past timestamp accepted (within ±5m)", now - 60, false, ""},
		{"slightly future timestamp accepted (within ±5m)", now + 60, false, ""},
		{"far past timestamp rejected (2009)", 1234567890, true, "past"},
		{"far future timestamp rejected (now + 1h)", now + 3600, true, "future"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &consensus.CrossShardMessage{
				SourceShard: chain.ShardID(),
				DestShard:   chain.ShardID(),
				Sender:      validators[0],
				Recipient:   validators[1],
				Payload:     []byte{0xde, 0xad, 0xbe, 0xef},
				Nonce:       1,
				Timestamp:   tt.timestamp,
			}
			msg.ID = consensus.GenerateCrossShardMessageID(msg.SourceShard, msg.DestShard, msg.Sender, msg.Nonce)
			msg.Signature = signCrossShardMsgForRPC(validators[0], msg)

			params, _ := json.Marshal(map[string]any{
				"sourceShard": msg.SourceShard,
				"destShard":   msg.DestShard,
				"sender":      "0x" + hex.EncodeToString(msg.Sender[:]),
				"recipient":   "0x" + hex.EncodeToString(msg.Recipient[:]),
				"payload":     "0x" + hex.EncodeToString(msg.Payload),
				"nonce":       msg.Nonce,
				"timestamp":   msg.Timestamp,
				"signature":   "0x" + hex.EncodeToString(msg.Signature),
			})

			_, rerr := api.SubmitCrossShardMessage(context.Background(), params)
			if tt.wantErr {
				if rerr == nil {
					t.Fatal("RPC- expected error, got nil")
				}
				if rerr.Code != -32602 {
					t.Fatalf("RPC- expected -32602, got code=%d msg=%q", rerr.Code, rerr.Message)
				}
				if tt.wantSubst != "" && !strings.Contains(rerr.Message, tt.wantSubst) {
					t.Fatalf("RPC- expected error containing %q, got %q", tt.wantSubst, rerr.Message)
				}
			} else {
				// For accepted timestamps, the freshness check must NOT fire.
				// The call may still fail for other reasons (engine internals),
				// but the error must NOT mention future/past freshness.
				if rerr != nil && (strings.Contains(rerr.Message, "future") || strings.Contains(rerr.Message, "past")) {
					t.Fatalf("RPC- REGRESSION: valid timestamp rejected: %q", rerr.Message)
				}
			}
		})
	}
}

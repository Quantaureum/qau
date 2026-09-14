// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/rollup"
	"github.com/quantaureum/qau/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// RPC- qau_qrngGetRandom MUST be registered as an admin method.
//
// Previously the handler was removed from PublicMethods but never registered
// via RegisterAdminMethod, leaving it callable by any authenticated user
// (non-admin). This allowed entropy-pool exhaustion and observation of
// consensus randomness. The fix registers it as admin-only.
// ─────────────────────────────────────────────────────────────────────────────

func TestRPC_R7_01_QrngGetRandomIsAdminMethod(t *testing.T) {
	srv := NewServer(nil)
	api := NewQuantumAPI(nil, nil, nil, nil)
	api.RegisterHandlers(srv)

	if !srv.isAdminMethod("qau_qrngGetRandom") {
		t.Fatal("RPC- REGRESSION: qau_qrngGetRandom is not registered as an admin method; " +
			"non-admin callers can drain the QRNG entropy pool or observe consensus entropy")
	}

	// The handler must still be registered so admin callers can invoke it.
	if _, ok := srv.handlers["qau_qrngGetRandom"]; !ok {
		t.Fatal("RPC- qau_qrngGetRandom handler not registered on server")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// RPC- SendBlobTransaction MUST derive tx.From using
// crypto.PublicKeyAddressFromBytes, not sha3.Sum256(pubKey)[:20].
//
// The previous derivation used a different hash algorithm than the rest of
// the codebase, allowing sender-address forgery: an attacker could craft a
// pubKey whose sha3.Sum256 matches a victim's address while the real
// Dilithium3 address derivation differs. The closure test verifies that the
// From field set inside SendBlobTransaction matches
// crypto.PublicKeyAddressFromBytes for a real Dilithium3 key.
// ─────────────────────────────────────────────────────────────────────────────

// spyTxPool captures the marshaled transaction passed to AddTransaction so
// the test can unmarshal it and inspect the From field set by
// SendBlobTransaction.
type spyTxPool struct {
	captured []byte
}

func (s *spyTxPool) AddTransaction(tx []byte) (types.Hash, error) {
	s.captured = make([]byte, len(tx))
	copy(s.captured, tx)
	return types.Hash{0x42}, nil
}
func (s *spyTxPool) AddVerifiedTransaction(tx *encoding.Transaction) (types.Hash, error) {
	return types.Hash{}, nil
}
func (s *spyTxPool) GetPendingTransactions() []any             { return nil }
func (s *spyTxPool) GetPendingCount() int                      { return 0 }
func (s *spyTxPool) GetQueuedCount() int                       { return 0 }
func (s *spyTxPool) GetPendingNonce(addr types.Address) uint64 { return 0 }
func (s *spyTxPool) SubmitCommitment(commitHash types.Hash, txHash types.Hash, sender types.Address) error {
	return nil
}
func (s *spyTxPool) AddUserOperation(uo *encoding.UserOperation) error        { return nil }
func (s *spyTxPool) GetUserOperation(hash types.Hash) *encoding.UserOperation { return nil }
func (s *spyTxPool) PendingUserOps() []*encoding.UserOperation                { return nil }

func TestRPC_R7_02_BlobTxUsesPublicKeyAddressFromBytes(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pubKey := kp.Public.Bytes()
	if len(pubKey) != crypto.Dilithium3PublicKeySize {
		t.Fatalf("pubKey size = %d, want %d", len(pubKey), crypto.Dilithium3PublicKeySize)
	}
	expectedAddr := crypto.PublicKeyAddressFromBytes(pubKey)

	// Build a valid blob sidecar (KZG is a keccak stub, deterministic).
	var blob encoding.Blob // 4096 bytes of zeros — valid for the stubbed KZG
	commitment := encoding.KZGCommitmentFromBlob(blob)
	proof, ok := encoding.ComputeBlobKZGProof(blob, commitment)
	if !ok {
		t.Fatal("ComputeBlobKZGProof returned !ok")
	}

	spy := &spyTxPool{}
	api := NewBlobAPI(nil, spy, newMockChainInfo())

	toAddr := types.Address{0xaa, 0xbb}
	req := SendBlobTxRequest{
		To:               "0x" + hex.EncodeToString(toAddr[:]),
		MaxFeePerBlobGas: "0x1",
		Blobs:            []string{"0x" + hex.EncodeToString(blob[:])},
		Commitments:      []string{"0x" + hex.EncodeToString(commitment[:])},
		Proofs:           []string{"0x" + hex.EncodeToString(proof[:])},
		PublicKey:        "0x" + hex.EncodeToString(pubKey),
		Signature:        "0x" + hex.EncodeToString(make([]byte, crypto.Dilithium3SignatureSize)),
	}

	hash, err := api.SendBlobTransaction(context.Background(), req)
	if err != nil {
		t.Fatalf("SendBlobTransaction: %v", err)
	}
	if hash != (types.Hash{0x42}) {
		t.Errorf("expected spy hash 0x42..., got %x", hash)
	}

	if len(spy.captured) == 0 {
		t.Fatal("spy txPool did not capture marshaled tx data")
	}
	tx, err := encoding.UnmarshalTransaction(spy.captured)
	if err != nil {
		t.Fatalf("UnmarshalTransaction: %v", err)
	}

	if tx.From != expectedAddr {
		t.Fatalf("RPC- REGRESSION: tx.From = %x, expected %x (crypto.PublicKeyAddressFromBytes). "+
			"A different derivation (e.g. sha3.Sum256) would allow sender-address forgery.",
			tx.From, expectedAddr)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// RPC- SubmitFraudProof MUST verify challenger address matches the
// provided public key.
//
// Without this check, an attacker could sign a fraud proof with their own
// Dilithium3 key but claim a victim's address as the challenger. The
// signature would verify against the attacker's key, but the proof's
// Challenger field would point to the victim — enabling false attribution,
// false slashing, or misdirected challenge rewards.
//
// Test 1 (mismatch): attacker's pubKey + victim's address → must be rejected
// at the RPC boundary with ErrCodeInvalidParams, BEFORE reaching the engine.
//
// Test 2 (match): matching pubKey + address → must NOT produce the mismatch
// error (it may fail later inside the engine for unrelated reasons; we only
// assert the mismatch check does not fire).
// ─────────────────────────────────────────────────────────────────────────────

func TestRPC_R7_03_ChallengerAddressMismatchRejected(t *testing.T) {
	victim, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (victim): %v", err)
	}
	attacker, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (attacker): %v", err)
	}

	victimAddr := crypto.PublicKeyAddressFromBytes(victim.Public.Bytes())
	attackerPubKey := attacker.Public.Bytes()

	engine, err := rollup.NewRollupEngine(rollup.DefaultRollupConfig())
	if err != nil {
		t.Fatalf("NewRollupEngine: %v", err)
	}
	api := NewRollupAPI(engine)

	// Attacker signs with their own key but claims the victim's address.
	params := buildRPC_R7_03_Params(t, victimAddr, attackerPubKey)

	_, rpcErr := api.SubmitFraudProof(context.Background(), params)
	if rpcErr == nil {
		t.Fatal("RPC- REGRESSION: SubmitFraudProof accepted mismatched " +
			"challenger address + public key (no error returned)")
	}
	if rpcErr.Code != ErrCodeInvalidParams {
		t.Fatalf("RPC- expected ErrCodeInvalidParams (%d), got code=%d msg=%q",
			ErrCodeInvalidParams, rpcErr.Code, rpcErr.Message)
	}
	if !strings.Contains(rpcErr.Message, "does not match") {
		t.Fatalf("RPC- expected mismatch error message, got %q", rpcErr.Message)
	}
}

func TestRPC_R7_03_ChallengerAddressMatchPassesCheck(t *testing.T) {
	challenger, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	challengerAddr := crypto.PublicKeyAddressFromBytes(challenger.Public.Bytes())
	challengerPubKey := challenger.Public.Bytes()

	engine, err := rollup.NewRollupEngine(rollup.DefaultRollupConfig())
	if err != nil {
		t.Fatalf("NewRollupEngine: %v", err)
	}
	api := NewRollupAPI(engine)

	params := buildRPC_R7_03_Params(t, challengerAddr, challengerPubKey)

	_, rpcErr := api.SubmitFraudProof(context.Background(), params)
	// The mismatch check must NOT fire. The call may still fail inside the
	// engine (e.g. batch not found, signature verification) — that's fine.
	// We only assert the failure (if any) is NOT the mismatch error.
	if rpcErr != nil {
		if rpcErr.Code == ErrCodeInvalidParams && strings.Contains(rpcErr.Message, "does not match") {
			t.Fatalf("RPC- REGRESSION: matching address+pubKey was rejected " +
				"by the mismatch check")
		}
	}
}

// buildRPC_R7_03_Params constructs a JSON-RPC params payload for
// SubmitFraudProof with the given challenger address and public key.
// Signature is a zero-filled Dilithium3-sized placeholder (the mismatch
// check runs BEFORE signature verification, so signature validity doesn't
// matter for these tests).
func buildRPC_R7_03_Params(t *testing.T, challengerAddr types.Address, pubKey []byte) json.RawMessage {
	t.Helper()
	sig := make([]byte, crypto.Dilithium3SignatureSize)
	// RPC-FIX: timestamp must be within ±5 minutes of current time.
	// Previously used a fixed 2009 timestamp which is now rejected by the
	// freshness check added in RPC-.
	payload := map[string]any{
		"type":             1, // InvalidBatch
		"batchIndex":       5,
		"challenger":       "0x" + hex.EncodeToString(challengerAddr[:]),
		"preStateRoot":     "0x" + hex.EncodeToString(make([]byte, 32)),
		"postStateRoot":    "0x" + hex.EncodeToString(make([]byte, 32)),
		"timestamp":        time.Now().Unix(),
		"challengerSig":    "0x" + hex.EncodeToString(sig),
		"challengerPubKey": "0x" + hex.EncodeToString(pubKey),
		"proofData":        "0xabcd",
	}
	// Wrap in the JSON-RPC params array convention used by unwrapParams.
	wrapped, err := json.Marshal([]any{payload})
	if err != nil {
		t.Fatalf("Marshal params: %v", err)
	}
	return wrapped
}

// ─────────────────────────────────────────────────────────────────────────────
// RPC- SubmitFraudProof MUST reject timestamps too far from the current
// wall-clock. Without this check, an attacker who obtains a historically valid
// signed fraud proof (Dilithium3 signatures bind the timestamp) can replay it
// indefinitely, since replaying requires reusing the original timestamp.
// ─────────────────────────────────────────────────────────────────────────────

func TestRPC_R7_05_FraudProofTimestampFreshness(t *testing.T) {
	challenger, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	challengerAddr := crypto.PublicKeyAddressFromBytes(challenger.Public.Bytes())
	challengerPubKey := challenger.Public.Bytes()

	engine, err := rollup.NewRollupEngine(rollup.DefaultRollupConfig())
	if err != nil {
		t.Fatalf("NewRollupEngine: %v", err)
	}
	api := NewRollupAPI(engine)

	now := time.Now().Unix()

	tests := []struct {
		name      string
		timestamp int64
		wantErr   bool
	}{
		{"current timestamp accepted", now, false},
		{"slightly past timestamp accepted (within ±5m)", now - 60, false},
		{"slightly future timestamp accepted (within ±5m)", now + 60, false},
		{"far past timestamp rejected (2009)", 1234567890, true},
		{"far future timestamp rejected (now + 1h)", now + 3600, true},
		{"zero timestamp rejected", 0, true},
		{"negative timestamp rejected", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]any{
				"type":             1, // InvalidBatch
				"batchIndex":       5,
				"challenger":       "0x" + hex.EncodeToString(challengerAddr[:]),
				"preStateRoot":     "0x" + hex.EncodeToString(make([]byte, 32)),
				"postStateRoot":    "0x" + hex.EncodeToString(make([]byte, 32)),
				"timestamp":        tt.timestamp,
				"challengerSig":    "0x" + hex.EncodeToString(make([]byte, crypto.Dilithium3SignatureSize)),
				"challengerPubKey": "0x" + hex.EncodeToString(challengerPubKey),
				"proofData":        "0xabcd",
			}
			wrapped, err := json.Marshal([]any{payload})
			if err != nil {
				t.Fatalf("Marshal params: %v", err)
			}
			_, rpcErr := api.SubmitFraudProof(context.Background(), wrapped)
			if tt.wantErr {
				if rpcErr == nil {
					t.Fatal("RPC- expected error, got nil")
				}
				if rpcErr.Code != ErrCodeInvalidParams {
					t.Fatalf("RPC- expected ErrCodeInvalidParams, got code=%d msg=%q",
						rpcErr.Code, rpcErr.Message)
				}
			} else {
				// For accepted timestamps, the freshness check must NOT fire.
				// The call may still fail for other reasons (engine internals),
				// but the error message must NOT mention "skew".
				if rpcErr != nil && strings.Contains(rpcErr.Message, "skew") {
					t.Fatalf("RPC- REGRESSION: valid timestamp rejected: %q", rpcErr.Message)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BRDG- (Info): qau_bridgeGetPendingTransfers MUST be registered as an
// admin method so the server's auth middleware (AuthManager.ValidateAdminRequest)
// enforces API-key + admin-IP checks before dispatching. The method exposes
// per-message financial data (amount, source/target addresses) for pending
// transfers, which is operationally necessary for admin triage but must not
// be enumerable by unauthenticated callers on the public RPC endpoint.
//
// The audit (Info severity) recommended:
//   1. Confirm admin method whitelist contains qau_bridgeGetPendingTransfers
//      → satisfied by RegisterHandlers → RegisterAdminMethod (bridge_api.go:36)
//   2. Caddy reverse-proxy must NOT expose admin methods on rpc.quantaureum.com
//      → ops/deployment concern, enforced by serving admin endpoints only on
//        rpc-admin.internal (not testable here)
//   3. Add second password verification (HTTP Basic Auth or mTLS)
//      → beyond Info-level scope; the existing API-key + admin-IP auth already
//        provides two-factor (something you have + somewhere you are)
//
// This test guards recommendation #1 against regression: if a future refactor
// drops the RegisterAdminMethod call, this test will fail.
// ─────────────────────────────────────────────────────────────────────────────

func TestBRDG_R7_10_BridgeGetPendingTransfersIsAdminMethod(t *testing.T) {
	srv := NewServer(nil)
	api := NewBridgeAPI(nil, nil, nil) // bridge disabled — RegisterHandlers must still work
	api.RegisterHandlers(srv)

	if !srv.isAdminMethod("qau_bridgeGetPendingTransfers") {
		t.Fatal("BRDG- REGRESSION: qau_bridgeGetPendingTransfers is not registered as " +
			"an admin method; unauthenticated callers could enumerate pending cross-chain " +
			"transfers and harvest commercially sensitive financial data")
	}

	// The handler must still be registered so admin callers can invoke it.
	if _, ok := srv.handlers["qau_bridgeGetPendingTransfers"]; !ok {
		t.Fatal("BRDG- qau_bridgeGetPendingTransfers handler not registered on server")
	}

	// The other two bridge methods are intentionally NOT admin (they expose
	// only aggregate counts / chain IDs, no per-message data).
	if srv.isAdminMethod("qau_bridgeGetStatus") {
		t.Error("BRDG- qau_bridgeGetStatus should NOT be admin-only (aggregate status, no sensitive data)")
	}
	if srv.isAdminMethod("qau_bridgeGetSupportedChains") {
		t.Error("BRDG- qau_bridgeGetSupportedChains should NOT be admin-only (public chain list)")
	}
}

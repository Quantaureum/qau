package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/bridge"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

type n22Refunder struct {
	calls []types.Address
	err   error
}

func (r *n22Refunder) RefundFailedLockAuthorized(ctx context.Context, lockID string, caller types.Address) error {
	r.calls = append(r.calls, caller)
	return r.err
}

// n22API builds a BridgeAPI that passes the "bridge enabled" check without a
// real bridge: a typed-nil *QuantumBridge satisfies the non-nil interface
// check, and RefundFailedLock never dereferences it.
func n22API(refunder *n22Refunder) *BridgeAPI {
	var disabled *bridge.QuantumBridge
	return NewBridgeAPI(disabled, nil, refunder)
}

func n22Nonce(deadline time.Time) string {
	return fmt.Sprintf("%d:%s", deadline.Unix(), "9f3a1c7e8b2d4f60")
}

func n22Params(t *testing.T, lockID string, kp *crypto.KeyPair, nonce, sigOverride, pubOverride string) json.RawMessage {
	t.Helper()
	if kp == nil {
		raw, _ := json.Marshal(map[string]string{"lockId": lockID})
		return json.RawMessage(raw)
	}
	caller := kp.Public.Address().ToHexAddress()
	msg := fmt.Sprintf("QAU-qau_bridgeRefundFailedLock|%s|%s|%s", caller, lockID, nonce)
	sig, err := kp.Private.Sign([]byte(msg))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sigHex := "0x" + hex.EncodeToString(sig)
	pubHex := "0x" + hex.EncodeToString(kp.Public.Bytes())
	if sigOverride != "" {
		sigHex = sigOverride
	}
	if pubOverride != "" {
		pubHex = pubOverride
	}
	raw, _ := json.Marshal(map[string]string{
		"lockId":    lockID,
		"caller":    caller,
		"nonce":     nonce,
		"signature": sigHex,
		"publicKey": pubHex,
	})
	return json.RawMessage(raw)
}

// SECURITY (audit N-22): a request that merely asserts an operator address,
// with no signature, must be rejected before the bridge layer is reached.
// Before the fix such a caller was trusted; after the fix it cannot be forged.
func TestN22_UnsignedRefundRequestRejected(t *testing.T) {
	ref := &n22Refunder{}
	api := n22API(ref)

	// Claim to be an operator by address only.
	params := json.RawMessage(`{"lockId":"lock-1","caller":"` + types.Address{0x42}.ToHexAddress() + `"}`)

	_, rpcErr := api.RefundFailedLock(context.Background(), params)
	if rpcErr == nil {
		t.Fatal("N-22 regression: unsigned request with a client-asserted caller was accepted")
	}
	if rpcErr.Code != -32003 {
		t.Fatalf("expected unauthorized (-32003), got %d: %s", rpcErr.Code, rpcErr.Message)
	}
	if len(ref.calls) != 0 {
		t.Fatalf("bridge refunder must not be invoked, got %d calls", len(ref.calls))
	}
}

// A signature from a different key cannot impersonate the claimed caller.
func TestN22_ForgedSignatureWithMismatchedKeyRejected(t *testing.T) {
	operator, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	attacker, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	nonce := n22Nonce(time.Now().Add(5 * time.Minute))
	// Claim the operator address but present the attacker's key/signature.
	msg := fmt.Sprintf("QAU-qau_bridgeRefundFailedLock|%s|%s|%s", operator.Public.Address().ToHexAddress(), "lock-1", nonce)
	sig, err := attacker.Private.Sign([]byte(msg))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	params, _ := json.Marshal(map[string]string{
		"lockId":    "lock-1",
		"caller":    operator.Public.Address().ToHexAddress(),
		"nonce":     nonce,
		"signature": "0x" + hex.EncodeToString(sig),
		"publicKey": "0x" + hex.EncodeToString(attacker.Public.Bytes()),
	})

	ref := &n22Refunder{}
	api := n22API(ref)

	_, rpcErr := api.RefundFailedLock(context.Background(), json.RawMessage(params))
	if rpcErr == nil || rpcErr.Code != -32003 {
		t.Fatalf("expected unauthorized (-32003), got %+v", rpcErr)
	}
	if !strings.Contains(rpcErr.Message, "public key does not match") {
		t.Fatalf("expected address/key mismatch, got: %s", rpcErr.Message)
	}
	if len(ref.calls) != 0 {
		t.Fatalf("bridge refunder must not be invoked, got %d calls", len(ref.calls))
	}
}

// A correctly signed request must reach the bridge layer with the proven
// caller address.
func TestN22_ValidSignedRequestReachesRefunder(t *testing.T) {
	operator, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	nonce := n22Nonce(time.Now().Add(5 * time.Minute))

	ref := &n22Refunder{}
	api := n22API(ref)

	res, rpcErr := api.RefundFailedLock(context.Background(), n22Params(t, "lock-1", operator, nonce, "", ""))
	if rpcErr != nil {
		t.Fatalf("valid signed request must be accepted: %+v", rpcErr)
	}
	if len(ref.calls) != 1 {
		t.Fatalf("expected exactly one refunder call, got %d", len(ref.calls))
	}
	if ref.calls[0] != operator.Public.Address() {
		t.Fatalf("refunder must receive the proven caller, got %x want %x",
			ref.calls[0], operator.Public.Address())
	}
	if m, ok := res.(map[string]any); !ok || m["success"] != true {
		t.Fatalf("unexpected success payload: %#v", res)
	}
}

// A valid signature for a DIFFERENT lock cannot be replayed on this lock.
func TestN22_SignatureForAnotherLockRejected(t *testing.T) {
	operator, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	nonce := n22Nonce(time.Now().Add(5 * time.Minute))

	// Sign lock-A, present the request as lock-B.
	params := n22Params(t, "lock-A", operator, nonce, "", "")
	var decoded map[string]string
	if err := json.Unmarshal(params, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	decoded["lockId"] = "lock-B"
	raw, _ := json.Marshal(decoded)

	ref := &n22Refunder{}
	api := n22API(ref)

	_, rpcErr := api.RefundFailedLock(context.Background(), json.RawMessage(raw))
	if rpcErr == nil || rpcErr.Code != -32003 {
		t.Fatalf("cross-lock replay must be rejected, got %+v", rpcErr)
	}
	if !strings.Contains(rpcErr.Message, "invalid caller signature") {
		t.Fatalf("expected signature failure, got: %s", rpcErr.Message)
	}
	if len(ref.calls) != 0 {
		t.Fatalf("bridge refunder must not be invoked, got %d calls", len(ref.calls))
	}
}

// Expired nonces are rejected by the shared freshness parser before any
// cryptographic work.
func TestN22_ExpiredNonceRejected(t *testing.T) {
	operator, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	nonce := n22Nonce(time.Now().Add(-1 * time.Hour))

	ref := &n22Refunder{}
	api := n22API(ref)

	_, rpcErr := api.RefundFailedLock(context.Background(), n22Params(t, "lock-1", operator, nonce, "", ""))
	if rpcErr == nil || rpcErr.Code != -32003 {
		t.Fatalf("expired nonce must be rejected, got %+v", rpcErr)
	}
	if len(ref.calls) != 0 {
		t.Fatalf("bridge refunder must not be invoked, got %d calls", len(ref.calls))
	}
}

// The RPC layer proves identity only; the operator-set authority remains in
// the bridge layer (fail-closed when the caller is not an operator).
func TestN22_ProvenNonOperatorStillBlockedByBridge(t *testing.T) {
	stranger, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	nonce := n22Nonce(time.Now().Add(5 * time.Minute))

	ref := &n22Refunder{err: bridge.ErrUnauthorizedOperator}
	api := n22API(ref)

	_, rpcErr := api.RefundFailedLock(context.Background(), n22Params(t, "lock-1", stranger, nonce, "", ""))
	if rpcErr == nil || rpcErr.Code != -32000 {
		t.Fatalf("bridge-layer operator check must reject, got %+v", rpcErr)
	}
	if len(ref.calls) != 1 {
		t.Fatalf("expected the proven caller to reach the bridge layer once, got %d", len(ref.calls))
	}
}

// SECURITY (audit memo on d327f6e): the deadline-embedded nonce must be
// consumed at most once. Before the replay-guard wiring the freshness check
// (ParseAuthNonceDeadline) only rejected EXPIRED nonces, so the very same
// signed request could be replayed until its deadline expired.
func TestN22_SameNonceReplayedRequestRejected(t *testing.T) {
	refunder := &n22Refunder{}
	api := n22API(refunder)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	nonce := n22Nonce(time.Now().Add(5 * time.Minute))
	params := n22Params(t, "lock-replay-1", kp, nonce, "", "")

	ctx := context.Background()
	if _, rpcErr := api.RefundFailedLock(ctx, params); rpcErr != nil {
		t.Fatalf("first request must pass: %v", rpcErr)
	}
	if len(refunder.calls) != 1 {
		t.Fatalf("first request must reach the refunder, got %d calls", len(refunder.calls))
	}

	// The exact same signed request (same lock, same nonce, same signature):
	// the nonce is now consumed, so the replay must be rejected before the
	// refunder is reached again.
	if _, rpcErr := api.RefundFailedLock(ctx, params); rpcErr == nil {
		t.Fatal("replayed request must be rejected")
	}
	if len(refunder.calls) != 1 {
		t.Fatalf("replayed request must not reach the refunder, got %d calls", len(refunder.calls))
	}

	// A different lock with a FRESH nonce still works. The nonce string is
	// "<unix-deadline>:<random>", so a different expiry minute guarantees a
	// different nonce without sleeping.
	freshNonce := n22Nonce(time.Now().Add(8 * time.Minute))
	fresh := n22Params(t, "lock-replay-2", kp, freshNonce, "", "")
	if _, rpcErr := api.RefundFailedLock(ctx, fresh); rpcErr != nil {
		t.Fatalf("fresh-nonce request must pass: %v", rpcErr)
	}
	if len(refunder.calls) != 2 {
		t.Fatalf("fresh-nonce request must reach the refunder, got %d calls", len(refunder.calls))
	}
}

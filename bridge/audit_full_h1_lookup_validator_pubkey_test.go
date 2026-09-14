// Quantaureum Node source, version 1.0.0.
package bridge

import (
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// AUDIT-FULL H-1 FIX (2026-08-14): regression tests for the real
// lookupValidatorPubKey registry.
//
// Symptom being fixed: lookupValidatorPubKey unconditionally returned
// (nil, false), so the R38-P1-11 burn-signature verification path
// (quantaureum_adapter.go ~line 928) could NEVER succeed — and could
// never even attempt Dilithium3 verification — on the Quantaureum
// adapter. A signed burn proof was always rejected with "no registered
// Dilithium3 pubkey" regardless of signature validity.

func auditFullH1Adapter(t *testing.T) (*QuantaureumChainAdapter, types.Address) {
	t.Helper()
	adapter := NewQuantaureumChainAdapter("quantaureum", "http://localhost:8545", "0x0000000000000000000000000000000000000001", 1, "0xinit")
	q := adapter.(*QuantaureumChainAdapter)
	q.SetGovernanceAddress("0xgov", "0xinit")
	return q, types.Address{0x11, 0x22, 0x33}
}

func TestAuditFull_H1_LookupFindsRegisteredKey(t *testing.T) {
	q, validatorAddr := auditFullH1Adapter(t)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := q.RegisterValidatorPubKey(validatorAddr, kp.Public.Bytes(), "0xgov"); err != nil {
		t.Fatalf("RegisterValidatorPubKey: %v", err)
	}

	pub, ok := q.lookupValidatorPubKey(validatorAddr)
	if !ok || pub == nil {
		t.Fatal("AUDIT-FULL H-1: registered key not found by lookupValidatorPubKey (stub returned nil,false)")
	}

	// The returned key must actually verify a signature from that keypair.
	msg := []byte("audit-full-h1 burn intent")
	sig, err := kp.Private.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !pub.Verify(msg, sig) {
		t.Fatal("AUDIT-FULL H-1: returned pubkey fails to verify a valid signature")
	}

	// Unregistered addresses must stay fail-closed.
	if other, ok := q.lookupValidatorPubKey(types.Address{0x99}); ok || other != nil {
		t.Fatal("AUDIT-FULL H-1: lookup returned a key for an unregistered address")
	}
}

func TestAuditFull_H1_RegisterRequiresGovernanceCaller(t *testing.T) {
	q, validatorAddr := auditFullH1Adapter(t)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	if err := q.RegisterValidatorPubKey(validatorAddr, kp.Public.Bytes(), "0xattacker"); err == nil {
		t.Fatal("AUDIT-FULL H-1: registration by non-governance caller accepted")
	}
	if err := q.RegisterValidatorPubKey(validatorAddr, kp.Public.Bytes(), ""); err == nil {
		t.Fatal("AUDIT-FULL H-1: registration by empty caller accepted")
	}
	// Nothing was registered by the rejected attempts.
	if _, ok := q.lookupValidatorPubKey(validatorAddr); ok {
		t.Fatal("AUDIT-FULL H-1: rejected registration attempts still mutated the registry")
	}

	// Governance caller succeeds.
	if err := q.RegisterValidatorPubKey(validatorAddr, kp.Public.Bytes(), "0xgov"); err != nil {
		t.Fatalf("RegisterValidatorPubKey by governance: %v", err)
	}
}

func TestAuditFull_H1_RegisterRejectsBadKey(t *testing.T) {
	q, validatorAddr := auditFullH1Adapter(t)

	if err := q.RegisterValidatorPubKey(validatorAddr, []byte{0x01, 0x02}, "0xgov"); err == nil {
		t.Fatal("AUDIT-FULL H-1: malformed pubkey accepted")
	}
	if err := q.RegisterValidatorPubKey(types.Address{}, make([]byte, crypto.Dilithium3PublicKeySize), "0xgov"); err == nil {
		t.Fatal("AUDIT-FULL H-1: zero validator address accepted")
	}
}

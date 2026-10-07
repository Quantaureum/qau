// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/crypto"
)

// TestAttachValidatorPublicKey_BindsRuntimeIdentity pins the R76 follow-up
// contract: a validator that joins through the staking path (ValidatorSet
// entry created without a key) gets its base Dilithium3 identity attached
// exactly once; malformed lengths are refused; the first key wins against
// later "re-keying" attempts.
func TestAttachValidatorPublicKey_BindsRuntimeIdentity(t *testing.T) {
	qpos, err := NewQPOS(createTestValidatorSet(t, 3))
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()

	var addr [20]byte
	addr[0] = 0xEE
	stake, ok := new(big.Int).SetString("32000000000000000000", 10)
	if !ok {
		t.Fatal("big.Int parse")
	}
	if !qpos.AddStakingValidator(addr, stake) {
		t.Fatal("AddStakingValidator returned false")
	}
	validator := qpos.GetValidatorSet().GetValidator(addr)
	if validator == nil || len(validator.PublicKeyBytes) != 0 {
		t.Fatalf("runtime-joined validator unexpectedly carries a key: %v", validator)
	}

	// Wrong length refused.
	if qpos.AttachValidatorPublicKey(addr, []byte{0x01, 0x02}) {
		t.Fatal("wrong-length key was attached")
	}
	// Well-formed key attached.
	key := make([]byte, crypto.Dilithium3PublicKeySize)
	key[0] = 0x5A
	if !qpos.AttachValidatorPublicKey(addr, key) {
		t.Fatal("well-formed key was refused")
	}
	// Idempotence: a second distinct key must not re-bind.
	key2 := make([]byte, crypto.Dilithium3PublicKeySize)
	key2[0] = 0xA5
	if qpos.AttachValidatorPublicKey(addr, key2) {
		t.Fatal("second key rebound an existing identity")
	}
	got := qpos.GetValidatorSet().GetValidator(addr).PublicKeyBytes
	if len(got) != crypto.Dilithium3PublicKeySize || got[0] != 0x5A {
		t.Fatalf("identity re-attached or corrupted: len=%d first=%x", len(got), got[0])
	}
	// Copy bound into the set (caller mutation must not leak back through).
	key[1] = 0xFF
	if got2 := qpos.GetValidatorSet().GetValidator(addr).PublicKeyBytes; got2[1] != 0x00 {
		t.Fatal("AttachValidatorPublicKey aliased the caller's slice")
	}
}

// TestAttachValidatorPublicKey_SurvivesRemoveReadd pins the R77 fix contract
// on the consensus side: a validator that is fully removed from the set
// (RemoveStakingValidator, e.g. after a complete unstake) and later re-added
// (AddStakingValidator) starts out keyless again, and a subsequent
// AttachValidatorPublicKey MUST bind the key to the fresh entry. The node
// layer's staking-tx mirror calls attach on every application precisely so a
// re-add can never be left keyless — a keyless active validator would make
// every DKG epoch-roster capture from that point on fail closed.
func TestAttachValidatorPublicKey_SurvivesRemoveReadd(t *testing.T) {
	qpos, err := NewQPOS(createTestValidatorSet(t, 3))
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()

	var addr [20]byte
	addr[0] = 0xEE
	stake, ok := new(big.Int).SetString("32000000000000000000", 10)
	if !ok {
		t.Fatal("big.Int parse")
	}

	// First join: add + attach + verify the key is present.
	if !qpos.AddStakingValidator(addr, stake) {
		t.Fatal("initial AddStakingValidator returned false")
	}
	key := make([]byte, crypto.Dilithium3PublicKeySize)
	key[0] = 0x5A
	if !qpos.AttachValidatorPublicKey(addr, key) {
		t.Fatal("initial attach refused")
	}

	// Full unstake: hard-remove the entry, then re-stake (re-add).
	if !qpos.RemoveStakingValidator(addr) {
		t.Fatal("RemoveStakingValidator returned false")
	}
	if !qpos.AddStakingValidator(addr, stake) {
		t.Fatal("re-add AddStakingValidator returned false")
	}
	// Re-add clears the key (the entry is recreated).
	if v := qpos.GetValidatorSet().GetValidator(addr); v == nil {
		t.Fatal("re-added validator missing from set")
	} else if len(v.PublicKeyBytes) != 0 {
		t.Fatalf("re-added entry unexpectedly retained a key: %d", len(v.PublicKeyBytes))
	}

	// The fix contract: re-attach binds the key on the fresh entry.
	if !qpos.AttachValidatorPublicKey(addr, key) {
		t.Fatal("re-attach after remove+re-add was refused")
	}
	got := qpos.GetValidatorSet().GetValidator(addr).PublicKeyBytes
	if len(got) != crypto.Dilithium3PublicKeySize || got[0] != 0x5A {
		t.Fatalf("re-added key not bound: len=%d", len(got))
	}
}

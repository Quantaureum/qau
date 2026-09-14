// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

func vkTestValidatorSet(t *testing.T, n int) (*ValidatorSet, []types.Address, [][]byte) {
	t.Helper()
	vals := make([]*Validator, 0, n)
	addrs := make([]types.Address, n)
	pks := make([][]byte, n)
	for i := 0; i < n; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		kpAddr := kp.Public.Address()
		var addr types.Address
		copy(addr[:], kpAddr[:])
		addrs[i] = addr
		pks[i] = kp.Public.Bytes()
		vals = append(vals, &Validator{
			Address:        addr,
			Stake:          big.NewInt(6000),
			Active:         true,
			PublicKeyBytes: pks[i],
		})
	}
	validators, err := NewValidatorSet(vals)
	if err != nil {
		t.Fatal(err)
	}
	return validators, addrs, pks
}

func TestVKRotateSessionLifecycle(t *testing.T) {
	vs, addrs, _ := vkTestValidatorSet(t, 2)
	q, err := NewQPOS(vs)
	if err != nil {
		t.Fatal(err)
	}
	v := addrs[0]

	// rotate: activate at epoch 5
	sessPK := make([]byte, crypto.Dilithium3PublicKeySize)
	sessPK[0] = 0xAA
	data := EncodeVKRotateSession(v, 5, sessPK)
	if err := q.ApplyValidatorKeyTx(v, data, 100, 3); err != nil {
		t.Fatalf("rotate apply: %v", err)
	}

	// before activation epoch: no effective session
	if _, ok := q.EffectiveSessionPubKey(v, 4); ok {
		t.Fatal("session must not be active before activation epoch")
	}
	// at activation: active
	got, ok := q.EffectiveSessionPubKey(v, 5)
	if !ok || !bytes.Equal(got, sessPK) {
		t.Fatal("session must be active at activation epoch")
	}
	// later epoch still active
	if _, ok := q.EffectiveSessionPubKey(v, 100); !ok {
		t.Fatal("session must remain active")
	}

	st := q.ValidatorKeyStatus(v)
	if st == nil || st.RotationCount != 1 || st.PendingPubKey != nil {
		t.Fatalf("bad status: %+v", st)
	}
}

func TestVKRotateBackdatedRejected(t *testing.T) {
	vs, addrs, _ := vkTestValidatorSet(t, 2)
	q, _ := NewQPOS(vs)
	v := addrs[0]
	sessPK := make([]byte, crypto.Dilithium3PublicKeySize)
	data := EncodeVKRotateSession(v, 3, sessPK)
	// currentEpoch=3 → activation must be > 3
	if err := q.ApplyValidatorKeyTx(v, data, 100, 3); err != ErrVKBadActivation {
		t.Fatalf("want ErrVKBadActivation, got %v", err)
	}
}

func TestVKRotateUnauthorized(t *testing.T) {
	vs, addrs, _ := vkTestValidatorSet(t, 2)
	q, _ := NewQPOS(vs)
	victim, attacker := addrs[0], addrs[1]
	sessPK := make([]byte, crypto.Dilithium3PublicKeySize)
	data := EncodeVKRotateSession(victim, 9, sessPK)
	if err := q.ApplyValidatorKeyTx(attacker, data, 100, 1); err != ErrVKUnauthorized {
		t.Fatalf("want ErrVKUnauthorized, got %v", err)
	}
}

func TestVKNotRegisteredValidator(t *testing.T) {
	vs, _, _ := vkTestValidatorSet(t, 2)
	q, _ := NewQPOS(vs)
	outsider := types.Address{0xDE, 0xAD}
	sessPK := make([]byte, crypto.Dilithium3PublicKeySize)
	data := EncodeVKRotateSession(outsider, 9, sessPK)
	if err := q.ApplyValidatorKeyTx(outsider, data, 100, 1); err != ErrVKNotValidator {
		t.Fatalf("want ErrVKNotValidator, got %v", err)
	}
}

func TestVKBindMasterAndRevoke(t *testing.T) {
	vs, addrs, _ := vkTestValidatorSet(t, 3)
	q, _ := NewQPOS(vs)
	v, master := addrs[0], addrs[2]

	// bind master
	if err := q.ApplyValidatorKeyTx(v, EncodeVKBindMaster(v, master), 10, 1); err != nil {
		t.Fatalf("bind master: %v", err)
	}
	st := q.ValidatorKeyStatus(v)
	if st.MasterAddress != master {
		t.Fatal("master not bound")
	}

	// rotate a session key then revoke
	sessPK := make([]byte, crypto.Dilithium3PublicKeySize)
	sessPK[3] = 7
	if err := q.ApplyValidatorKeyTx(v, EncodeVKRotateSession(v, 2, sessPK), 11, 1); err != nil {
		t.Fatal(err)
	}
	if _, ok := q.EffectiveSessionPubKey(v, 2); !ok {
		t.Fatal("session should activate at epoch 2")
	}

	// revoke by master
	if err := q.ApplyValidatorKeyTx(master, EncodeVKRevoke(v), 12, 2); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !q.IsValidatorRevoked(v) {
		t.Fatal("validator must be revoked")
	}
	// post-revoke: no pubkey resolution, and no further ops
	if _, ok := q.EffectiveSessionPubKey(v, 3); ok {
		t.Fatal("revoked validator must not resolve a session key")
	}
	if err := q.ApplyValidatorKeyTx(v, EncodeVKRotateSession(v, 9, sessPK), 13, 2); err != ErrVKValidatorDown {
		t.Fatalf("post-revoke op must fail: %v", err)
	}
}

func TestVKRevokeRequiresMaster(t *testing.T) {
	vs, addrs, _ := vkTestValidatorSet(t, 3)
	q, _ := NewQPOS(vs)
	v, attacker := addrs[0], addrs[1]
	// no master bound
	if err := q.ApplyValidatorKeyTx(attacker, EncodeVKRevoke(v), 10, 1); err != ErrVKNoMaster {
		t.Fatalf("want ErrVKNoMaster, got %v", err)
	}
	// bind master
	if err := q.ApplyValidatorKeyTx(v, EncodeVKBindMaster(v, addrs[0]), 11, 1); err != nil { // bind self as master
		t.Fatal(err)
	}
	// attacker tries revoke
	if err := q.ApplyValidatorKeyTx(attacker, EncodeVKRevoke(v), 12, 1); err != ErrVKUnauthorized {
		t.Fatalf("want ErrVKUnauthorized, got %v", err)
	}
}

func TestVKSnapshotRoundTrip(t *testing.T) {
	vs, addrs, _ := vkTestValidatorSet(t, 2)
	q1, _ := NewQPOS(vs)
	v := addrs[0]
	if err := q1.ApplyValidatorKeyTx(v, EncodeVKBindMaster(v, addrs[1]), 10, 1); err != nil {
		t.Fatal(err)
	}
	sessPK := make([]byte, crypto.Dilithium3PublicKeySize)
	sessPK[0] = 9
	if err := q1.ApplyValidatorKeyTx(v, EncodeVKRotateSession(v, 4, sessPK), 11, 1); err != nil {
		t.Fatal(err)
	}

	blob, err := q1.MarshalVKSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	q2, _ := NewQPOS(vs)
	if err := q2.LoadVKSnapshot(blob); err != nil {
		t.Fatal(err)
	}
	got, ok := q2.EffectiveSessionPubKey(v, 5)
	if !ok || !bytes.Equal(got, sessPK) {
		t.Fatal("snapshot round-trip lost session key")
	}
	st := q2.ValidatorKeyStatus(v)
	if st.MasterAddress != addrs[1] || st.RotationCount != 1 {
		t.Fatalf("snapshot status mismatch: %+v", st)
	}
}

func TestVKPayloadMalformed(t *testing.T) {
	vs, addrs, _ := vkTestValidatorSet(t, 1)
	q, _ := NewQPOS(vs)
	for name, data := range map[string][]byte{
		"empty":        {},
		"short":        []byte("QVK1"),
		"badmagic":     append([]byte("XXXX"), 0x01),
		"badop":        append(append([]byte("QVK1"), 0x77), make([]byte, 20)...),
		"rotate-short": append(append([]byte("QVK1"), VKOpRotateSession), make([]byte, 25)...),
	} {
		if err := q.ApplyValidatorKeyTx(addrs[0], data, 1, 0); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestVKVerifyAttestationIntegration(t *testing.T) {
	vs, addrs, pks := vkTestValidatorSet(t, 1)
	q, _ := NewQPOS(vs)
	v := addrs[0]
	vsValidators := vs.Validators()

	// In random mode we can't derive the base private key from the stored
	// public bytes, so we exercise the session-only flow (the production
	// case after a rotation).
	_ = pks

	// Instead: rotate to a session key we control, then sign with session.
	sessKp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := q.ApplyValidatorKeyTx(v, EncodeVKRotateSession(v, 2, sessKp.Public.Bytes()), 10, 1); err != nil {
		t.Fatal(err)
	}

	att := &Attestation{
		Slot:           64,
		ValidatorIndex: 0,
		KeyVersion:     0,
		Target:         AttestationCheckpoint{Epoch: 2},
	}
	if err := q.SignAttestation(att, sessKp.Private); err != nil {
		t.Fatal(err)
	}
	if err := q.verifyAttestationSignature(att, vsValidators); err != nil {
		t.Fatalf("session-signed attestation must verify: %v", err)
	}

	// mark revoked → verification fails
	if err := q.ApplyValidatorKeyTx(v, EncodeVKBindMaster(v, addrs[0]), 11, 1); err != nil {
		t.Fatal(err)
	}
	if err := q.ApplyValidatorKeyTx(v, EncodeVKRevoke(v), 12, 1); err != nil { // from==master(bound to self)
		t.Fatal(err)
	}
	if err := q.verifyAttestationSignature(att, vsValidators); err == nil {
		t.Fatal("revoked validator's attestation must fail verification")
	}
}

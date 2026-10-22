// Quantaureum Node source, version 1.0.0.
package keyrotation

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
)

func mustGenerateKeyPair(t *testing.T) *crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	return kp
}

func newLoadedManager(t *testing.T) (*KeyRotationManager, *crypto.KeyPair) {
	t.Helper()
	krm := NewKeyRotationManager(nil)
	current := mustGenerateKeyPair(t)
	if err := krm.SetCurrentKey(current); err != nil {
		t.Fatalf("SetCurrentKey: %v", err)
	}
	return krm, current
}

func signProof(t *testing.T, oldKey, newKey *KeyPairWrapper, timestamp int64) *RotationProof {
	t.Helper()
	message := createRotationMessage(oldKey.Public.Bytes(), newKey.Public.Bytes(), timestamp)
	signature, err := oldKey.Private.Sign(message)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	return &RotationProof{
		OldPublicKey: oldKey.Public.Bytes(),
		NewPublicKey: newKey.Public.Bytes(),
		Signature:    signature,
		Timestamp:    timestamp,
	}
}

func TestKeyRotationManager_FullLifecycle(t *testing.T) {
	krm := NewKeyRotationManager(nil)

	if !krm.ShouldRotate() {
		t.Fatal("manager without a current key must request rotation")
	}
	if _, err := krm.GetCurrentKey(); !errors.Is(err, ErrNoCurrentKey) {
		t.Fatalf("GetCurrentKey error = %v, want ErrNoCurrentKey", err)
	}
	if _, err := krm.GenerateProof(); !errors.Is(err, ErrNoCurrentKey) {
		t.Fatalf("GenerateProof error = %v, want ErrNoCurrentKey", err)
	}

	current := mustGenerateKeyPair(t)
	if err := krm.SetCurrentKey(current); err != nil {
		t.Fatalf("SetCurrentKey: %v", err)
	}
	if krm.ShouldRotate() {
		t.Fatal("freshly installed key must not request rotation")
	}

	if _, err := krm.GenerateProof(); !errors.Is(err, ErrNoPendingKey) {
		t.Fatalf("GenerateProof without pending key error = %v, want ErrNoPendingKey", err)
	}

	pending, err := krm.InitiateRotation()
	if err != nil {
		t.Fatalf("InitiateRotation: %v", err)
	}
	if !krm.IsRotationInProgress() {
		t.Fatal("rotation must be marked in progress")
	}
	active, err := krm.GetCurrentKey()
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}
	if pending.Version != active.Version+1 {
		t.Fatalf("pending version = %d, want %d", pending.Version, active.Version+1)
	}
	if _, err := krm.InitiateRotation(); !errors.Is(err, ErrRotationAlreadyActive) {
		t.Fatalf("second InitiateRotation error = %v, want ErrRotationAlreadyActive", err)
	}

	proof, err := krm.GenerateProof()
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	if !krm.VerifyProof(proof) {
		t.Fatal("freshly generated proof must verify")
	}
	if !VerifyRotationProof(proof) {
		t.Fatal("standalone verification of a fresh proof must succeed")
	}

	if err := krm.CompleteRotation(proof); err != nil {
		t.Fatalf("CompleteRotation: %v", err)
	}
	rotated, err := krm.GetCurrentKey()
	if err != nil {
		t.Fatalf("GetCurrentKey after rotation: %v", err)
	}
	if !bytes.Equal(rotated.Public.Bytes(), pending.Public.Bytes()) {
		t.Fatal("current key must be the former pending key after rotation")
	}
	if krm.IsRotationInProgress() {
		t.Fatal("rotation must be cleared after completion")
	}
	if _, err := krm.GetPendingKey(); !errors.Is(err, ErrNoPendingKey) {
		t.Fatalf("GetPendingKey error = %v, want ErrNoPendingKey", err)
	}
	// R72-PK-1: once pendingKey is nil, no proof may verify.
	if krm.VerifyProof(proof) {
		t.Fatal("proof must not verify after rotation completed")
	}
	if err := krm.CompleteRotation(proof); !errors.Is(err, ErrRotationNotInProgress) {
		t.Fatalf("second CompleteRotation error = %v, want ErrRotationNotInProgress", err)
	}
	if krm.ShouldRotate() {
		t.Fatal("just-rotated key must not request another rotation")
	}
}

func TestKeyRotationManager_CompleteRotationRejectsInvalidProof(t *testing.T) {
	krm, _ := newLoadedManager(t)
	if _, err := krm.InitiateRotation(); err != nil {
		t.Fatalf("InitiateRotation: %v", err)
	}
	before, err := krm.GetCurrentKey()
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}

	if err := krm.CompleteRotation(nil); !errors.Is(err, ErrInvalidRotationProof) {
		t.Fatalf("CompleteRotation(nil) error = %v, want ErrInvalidRotationProof", err)
	}
	if !krm.IsRotationInProgress() {
		t.Fatal("a rejected proof must not clear the rotation state")
	}

	proof, err := krm.GenerateProof()
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	other := mustGenerateKeyPair(t)
	tamperedNewKey := *proof
	tamperedNewKey.NewPublicKey = other.Public.Bytes()
	if err := krm.CompleteRotation(&tamperedNewKey); !errors.Is(err, ErrProofVerificationFailed) {
		t.Fatalf("tampered new key error = %v, want ErrProofVerificationFailed", err)
	}

	tamperedSig := *proof
	tamperedSig.Signature = append([]byte(nil), proof.Signature...)
	tamperedSig.Signature[0] ^= 0xFF
	if err := krm.CompleteRotation(&tamperedSig); !errors.Is(err, ErrProofVerificationFailed) {
		t.Fatalf("tampered signature error = %v, want ErrProofVerificationFailed", err)
	}

	after, err := krm.GetCurrentKey()
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}
	if !bytes.Equal(before.Public.Bytes(), after.Public.Bytes()) {
		t.Fatal("rejected rotations must leave the current key untouched")
	}
	if err := krm.CompleteRotation(proof); err != nil {
		t.Fatalf("valid proof rejected after prior failures: %v", err)
	}
}

func TestKeyRotationManager_RollbackRotation(t *testing.T) {
	krm, current := newLoadedManager(t)
	before, err := krm.GetCurrentKey()
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}

	if _, err := krm.InitiateRotation(); err != nil {
		t.Fatalf("InitiateRotation: %v", err)
	}
	if err := krm.RollbackRotation(); err != nil {
		t.Fatalf("RollbackRotation: %v", err)
	}
	if krm.IsRotationInProgress() {
		t.Fatal("rollback must clear the rotation state")
	}
	if _, err := krm.GetPendingKey(); !errors.Is(err, ErrNoPendingKey) {
		t.Fatalf("GetPendingKey error = %v, want ErrNoPendingKey", err)
	}
	after, err := krm.GetCurrentKey()
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}
	if !bytes.Equal(before.Public.Bytes(), after.Public.Bytes()) {
		t.Fatal("rollback must keep the original key active")
	}
	if !bytes.Equal(current.Public.Bytes(), after.Public.Bytes()) {
		t.Fatal("rollback must not replace the key that was active before rotation")
	}
	if err := krm.RollbackRotation(); !errors.Is(err, ErrRotationNotInProgress) {
		t.Fatalf("second RollbackRotation error = %v, want ErrRotationNotInProgress", err)
	}

	// The manager must be reusable after a rollback.
	if _, err := krm.InitiateRotation(); err != nil {
		t.Fatalf("InitiateRotation after rollback: %v", err)
	}
}

func TestKeyRotationManager_VerifyProofRejectsSkewAndWrongKeys(t *testing.T) {
	krm, _ := newLoadedManager(t)
	if _, err := krm.InitiateRotation(); err != nil {
		t.Fatalf("InitiateRotation: %v", err)
	}
	oldKey, err := krm.GetCurrentKey()
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}
	pending, err := krm.GetPendingKey()
	if err != nil {
		t.Fatalf("GetPendingKey: %v", err)
	}

	if !krm.VerifyProof(signProof(t, oldKey, pending, time.Now().UTC().Unix())) {
		t.Fatal("proof with current timestamp must verify")
	}
	if krm.VerifyProof(signProof(t, oldKey, pending, time.Now().Add(-10*time.Minute).Unix())) {
		t.Fatal("proof older than the skew window must be rejected")
	}
	if krm.VerifyProof(signProof(t, oldKey, pending, time.Now().Add(10*time.Minute).Unix())) {
		t.Fatal("proof from the future must be rejected")
	}

	other := mustGenerateKeyPair(t)
	otherWrapper := &KeyPairWrapper{Private: other.Private, Public: other.Public}
	if krm.VerifyProof(signProof(t, oldKey, otherWrapper, time.Now().UTC().Unix())) {
		t.Fatal("proof naming an unexpected pending key must be rejected")
	}
	attacker := mustGenerateKeyPair(t)
	attackerWrapper := &KeyPairWrapper{Private: attacker.Private, Public: attacker.Public}
	if krm.VerifyProof(signProof(t, attackerWrapper, pending, time.Now().UTC().Unix())) {
		t.Fatal("proof signed by an unexpected old key must be rejected")
	}

	if krm.VerifyProof(nil) {
		t.Fatal("nil proof must not verify")
	}
}

func TestProofVerifier_ValidateAndExpectedKeys(t *testing.T) {
	oldKey := mustGenerateKeyPair(t)
	newKey := mustGenerateKeyPair(t)
	oldWrapper := &KeyPairWrapper{Private: oldKey.Private, Public: oldKey.Public}
	newWrapper := &KeyPairWrapper{Private: newKey.Private, Public: newKey.Public}

	verifier := NewProofVerifier()
	if err := verifier.Verify(nil); !errors.Is(err, ErrEmptyProof) {
		t.Fatalf("Verify(nil) error = %v, want ErrEmptyProof", err)
	}
	if err := verifier.Verify(&RotationProof{}); !errors.Is(err, ErrInvalidProofFormat) {
		t.Fatalf("Verify(empty) error = %v, want ErrInvalidProofFormat", err)
	}

	valid := signProof(t, oldWrapper, newWrapper, time.Now().UTC().Unix())
	if err := verifier.Verify(valid); err != nil {
		t.Fatalf("Verify(valid): %v", err)
	}
	if err := verifier.VerifyWithExpectedKeys(valid, oldKey.Public, newKey.Public); err != nil {
		t.Fatalf("VerifyWithExpectedKeys(matching): %v", err)
	}
	if err := verifier.VerifyWithExpectedKeys(valid, newKey.Public, oldKey.Public); !errors.Is(err, ErrProofKeyMismatch) {
		t.Fatalf("VerifyWithExpectedKeys(mismatch) error = %v, want ErrProofKeyMismatch", err)
	}

	expired := signProof(t, oldWrapper, newWrapper, time.Now().Add(-25*time.Hour).Unix())
	if err := verifier.Verify(expired); !errors.Is(err, ErrProofExpired) {
		t.Fatalf("Verify(expired) error = %v, want ErrProofExpired", err)
	}
	future := signProof(t, oldWrapper, newWrapper, time.Now().Add(10*time.Minute).Unix())
	if err := verifier.Verify(future); !errors.Is(err, ErrProofTimestampFuture) {
		t.Fatalf("Verify(future) error = %v, want ErrProofTimestampFuture", err)
	}
}

func TestKeyManager_RotationLifecycle(t *testing.T) {
	dir := t.TempDir()
	cfg := &KeyRotationConfig{
		KeyDir:           filepath.Join(dir, "keys"),
		RotationInterval: time.Hour,
		GracePeriod:      time.Minute,
		MaxKeyAge:        time.Hour,
		BackupEnabled:    false,
	}
	km, err := NewKeyManager(cfg)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	if !km.IsRotationNeeded() {
		t.Fatal("manager without an active key must need rotation")
	}
	if _, _, err := km.GetActiveKey(); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("GetActiveKey error = %v, want ErrNoActiveKey", err)
	}

	key1, meta1, err := km.GenerateNodeKey()
	if err != nil {
		t.Fatalf("GenerateNodeKey: %v", err)
	}
	if meta1.State != KeyStatePending {
		t.Fatalf("generated key state = %q, want pending", meta1.State)
	}
	if err := km.ActivateKey(key1, meta1); err != nil {
		t.Fatalf("ActivateKey: %v", err)
	}
	if meta1.State != KeyStateActive {
		t.Fatalf("activated key state = %q, want active", meta1.State)
	}
	if km.IsRotationNeeded() {
		t.Fatal("freshly activated key must not need rotation")
	}

	var rotatedFrom, rotatedTo *KeyMetadata
	km.SetRotationCallback(func(oldKey, newKey *KeyMetadata) {
		rotatedFrom, rotatedTo = oldKey, newKey
	})

	key2, meta2, err := km.InitiateRotation()
	if err != nil {
		t.Fatalf("InitiateRotation: %v", err)
	}
	if _, _, err := km.InitiateRotation(); !errors.Is(err, ErrRotationInProgress) {
		t.Fatalf("second InitiateRotation error = %v, want ErrRotationInProgress", err)
	}
	if err := km.CompleteRotation(); err != nil {
		t.Fatalf("CompleteRotation: %v", err)
	}
	active, activeMeta, err := km.GetActiveKey()
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}
	if !bytes.Equal(active.Public.Bytes(), key2.Public.Bytes()) {
		t.Fatal("active key must be the rotated key")
	}
	if activeMeta != meta2 || meta1.State != KeyStateRetired {
		t.Fatal("rotation must retire the old key and activate the pending one")
	}
	if rotatedFrom != meta1 || rotatedTo != meta2 {
		t.Fatal("rotation callback must observe the retired and the new key")
	}
	if err := km.CompleteRotation(); err == nil {
		t.Fatal("CompleteRotation without a rotation must fail")
	}

	key3, _, err := km.InitiateRotation()
	if err != nil {
		t.Fatalf("InitiateRotation for cancel: %v", err)
	}
	if err := km.CancelRotation(); err != nil {
		t.Fatalf("CancelRotation: %v", err)
	}
	if err := km.CancelRotation(); err == nil {
		t.Fatal("CancelRotation without a rotation must fail")
	}
	active, _, err = km.GetActiveKey()
	if err != nil {
		t.Fatalf("GetActiveKey after cancel: %v", err)
	}
	if !bytes.Equal(active.Public.Bytes(), key2.Public.Bytes()) {
		t.Fatal("canceling a rotation must keep the previous key active")
	}
	if key3 == nil {
		t.Fatal("InitiateRotation must return the pending key")
	}
}

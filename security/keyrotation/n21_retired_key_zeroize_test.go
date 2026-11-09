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

// AUDIT N-21 (step 1) regression tests.
//
// Before the fix, both rotation paths marked the previous key as retired in
// metadata but kept its private material alive in memory: the old
// *crypto.PrivateKey stayed fully usable, so a leaked reference could still
// sign node messages after rotation. The fix zeroizes the retired private key
// immediately, and any later Sign call reports crypto.ErrInvalidPrivateKey.

func newTestKeyManager(t *testing.T) *KeyManager {
	t.Helper()
	cfg := &KeyRotationConfig{
		KeyDir:           filepath.Join(t.TempDir(), "keys"),
		RotationInterval: time.Hour,
		GracePeriod:      time.Minute,
		MaxKeyAge:        time.Hour,
		BackupEnabled:    false,
	}
	km, err := NewKeyManager(cfg)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	return km
}

func assertKeyUnusable(t *testing.T, keyPair *crypto.KeyPair, label string) {
	t.Helper()
	if keyPair == nil || keyPair.Private == nil {
		t.Fatalf("%s: key pair is nil", label)
	}
	if _, err := keyPair.Private.Sign([]byte("n21 retired key probe")); !errors.Is(err, crypto.ErrInvalidPrivateKey) {
		t.Fatalf("%s: retired key must no longer sign, got err=%v", label, err)
	}
}

func TestN21_CompleteRotationZeroizesRetiredKey(t *testing.T) {
	km := newTestKeyManager(t)

	oldKey, oldMeta, err := km.GenerateNodeKey()
	if err != nil {
		t.Fatalf("GenerateNodeKey: %v", err)
	}
	if err := km.ActivateKey(oldKey, oldMeta); err != nil {
		t.Fatalf("ActivateKey: %v", err)
	}
	if _, err := oldKey.Private.Sign([]byte("active key probe")); err != nil {
		t.Fatalf("active key must sign before rotation: %v", err)
	}

	newKey, _, err := km.InitiateRotation()
	if err != nil {
		t.Fatalf("InitiateRotation: %v", err)
	}
	if err := km.CompleteRotation(); err != nil {
		t.Fatalf("CompleteRotation: %v", err)
	}

	if oldMeta.State != KeyStateRetired {
		t.Fatalf("retired metadata state = %q, want %q", oldMeta.State, KeyStateRetired)
	}
	assertKeyUnusable(t, oldKey, "retired key")

	active, _, err := km.GetActiveKey()
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}
	if !bytes.Equal(active.Public.Bytes(), newKey.Public.Bytes()) {
		t.Fatal("active key must be the rotated key")
	}
	if _, err := active.Private.Sign([]byte("active key probe")); err != nil {
		t.Fatalf("new active key must still sign: %v", err)
	}
}

func TestN21_ActivateKeyZeroizesPreviousKey(t *testing.T) {
	km := newTestKeyManager(t)

	first, firstMeta, err := km.GenerateNodeKey()
	if err != nil {
		t.Fatalf("GenerateNodeKey: %v", err)
	}
	if err := km.ActivateKey(first, firstMeta); err != nil {
		t.Fatalf("ActivateKey(first): %v", err)
	}

	second, secondMeta, err := km.GenerateNodeKey()
	if err != nil {
		t.Fatalf("GenerateNodeKey(second): %v", err)
	}
	if err := km.ActivateKey(second, secondMeta); err != nil {
		t.Fatalf("ActivateKey(second): %v", err)
	}

	if firstMeta.State != KeyStateRetired {
		t.Fatalf("previous metadata state = %q, want %q", firstMeta.State, KeyStateRetired)
	}
	assertKeyUnusable(t, first, "previously activated key")
}

func TestN21_KeyRotationManagerCompleteRotationZeroizesRetiredKey(t *testing.T) {
	krm := NewKeyRotationManager(nil)
	old := mustGenerateKeyPair(t)
	if err := krm.SetCurrentKey(old); err != nil {
		t.Fatalf("SetCurrentKey: %v", err)
	}

	if _, err := krm.InitiateRotation(); err != nil {
		t.Fatalf("InitiateRotation: %v", err)
	}
	proof, err := krm.GenerateProof()
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	if err := krm.CompleteRotation(proof); err != nil {
		t.Fatalf("CompleteRotation: %v", err)
	}

	assertKeyUnusable(t, old, "retired manager key")

	active, err := krm.GetCurrentKey()
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}
	if _, err := active.Private.Sign([]byte("active key probe")); err != nil {
		t.Fatalf("new current key must still sign: %v", err)
	}
}

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

// AUDIT N-21 (step 2) regression tests.
//
// Before the fix the automatic trigger called KeyManager.CompleteRotation()
// directly, which has no concept of a RotationProof: every scheduled rotation
// replaced the node key without any authorization check. The trigger now
// requires a proof signed by the outgoing key and bound to the exact
// old/new public key pair; without one it fails closed and keeps the old key.

type n21Notifier struct {
	calls int
}

func (n *n21Notifier) OnKeyRotated(oldVersion, newVersion int, newPubKey []byte) {
	n.calls++
}

func newN21Trigger(t *testing.T) (*AutoTrigger, *n21Notifier) {
	t.Helper()
	cfg := &AutoTriggerConfig{
		CheckInterval: time.Hour,
		// A very short max key age makes the key expire right after
		// activation, so IsRotationNeeded() is deterministically true.
		MaxKeyAge:     50 * time.Millisecond,
		KeyDir:        filepath.Join(t.TempDir(), "keys"),
		BackupDir:     filepath.Join(t.TempDir(), "backup"),
		BackupEnabled: false,
	}
	notifier := &n21Notifier{}
	at, err := NewAutoTrigger(cfg, notifier)
	if err != nil {
		t.Fatalf("NewAutoTrigger: %v", err)
	}
	return at, notifier
}

func installN21ActiveKey(t *testing.T, at *AutoTrigger) *crypto.KeyPair {
	t.Helper()
	km := at.GetKeyManager()
	key, meta, err := km.GenerateNodeKey()
	if err != nil {
		t.Fatalf("GenerateNodeKey: %v", err)
	}
	if err := km.ActivateKey(key, meta); err != nil {
		t.Fatalf("ActivateKey: %v", err)
	}
	// Wait for the key to expire so the trigger actually attempts a rotation.
	time.Sleep(100 * time.Millisecond)
	if !km.IsRotationNeeded() {
		t.Fatal("test setup: key must be due for rotation")
	}
	return key
}

func validProofProvider(oldKey, newKey *crypto.KeyPair, timestamp int64) (*RotationProof, error) {
	return NewProofBuilder().
		WithOldKey(oldKey.Private).
		WithNewPublicKey(newKey.Public).
		WithTimestamp(timestamp).
		Build()
}

// No proof provider configured: the rotation must stop, the active key must be
// unchanged and no notifier callback may fire.
func TestN21_AutoTriggerRefusesRotationWithoutProofProvider(t *testing.T) {
	at, notifier := newN21Trigger(t)
	old := installN21ActiveKey(t, at)

	err := at.RotateNow()
	if !errors.Is(err, ErrAutoRotationRequiresProof) {
		t.Fatalf("RotateNow error = %v, want ErrAutoRotationRequiresProof", err)
	}

	active, meta, err := at.GetKeyManager().GetActiveKey()
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}
	if !bytes.Equal(active.Public.Bytes(), old.Public.Bytes()) {
		t.Fatal("refused rotation must not replace the active key")
	}
	if meta.Version != 1 {
		t.Fatalf("active key version = %d, want 1", meta.Version)
	}
	if notifier.calls != 0 {
		t.Fatalf("notifier must not observe a refused rotation, got %d calls", notifier.calls)
	}
	if _, err := old.Private.Sign([]byte("probe")); err != nil {
		t.Fatalf("active key must stay usable after a refused rotation: %v", err)
	}
}

// A provider that yields no proof is treated the same as no provider.
func TestN21_AutoTriggerRefusesNilProof(t *testing.T) {
	at, notifier := newN21Trigger(t)
	old := installN21ActiveKey(t, at)
	at.SetRotationProofProvider(func(oldKey, newKey *crypto.KeyPair, ts int64) (*RotationProof, error) {
		return nil, nil
	})

	if err := at.RotateNow(); !errors.Is(err, ErrAutoRotationRequiresProof) {
		t.Fatalf("RotateNow error = %v, want ErrAutoRotationRequiresProof", err)
	}
	active, _, err := at.GetKeyManager().GetActiveKey()
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}
	if !bytes.Equal(active.Public.Bytes(), old.Public.Bytes()) {
		t.Fatal("a nil proof must not replace the active key")
	}
	if notifier.calls != 0 {
		t.Fatalf("notifier must not observe a refused rotation, got %d calls", notifier.calls)
	}
}

// A proof signed by a different key (self-consistent but not authorized by the
// outgoing key) must be rejected.
func TestN21_AutoTriggerRejectsForgedProof(t *testing.T) {
	at, notifier := newN21Trigger(t)
	old := installN21ActiveKey(t, at)

	attacker, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	at.SetRotationProofProvider(func(oldKey, newKey *crypto.KeyPair, ts int64) (*RotationProof, error) {
		// Claim the real old public key while signing with the attacker key.
		msg := createRotationMessage(oldKey.Public.Bytes(), newKey.Public.Bytes(), ts)
		sig, signErr := attacker.Private.Sign(msg)
		if signErr != nil {
			return nil, signErr
		}
		return &RotationProof{
			OldPublicKey: oldKey.Public.Bytes(),
			NewPublicKey: newKey.Public.Bytes(),
			Signature:    sig,
			Timestamp:    ts,
		}, nil
	})

	err = at.RotateNow()
	if err == nil {
		t.Fatal("forged rotation proof must be rejected")
	}
	if !errors.Is(err, ErrProofVerificationFailed) {
		t.Fatalf("RotateNow error = %v, want ErrProofVerificationFailed", err)
	}
	active, _, getErr := at.GetKeyManager().GetActiveKey()
	if getErr != nil {
		t.Fatalf("GetActiveKey: %v", getErr)
	}
	if !bytes.Equal(active.Public.Bytes(), old.Public.Bytes()) {
		t.Fatal("a forged proof must not replace the active key")
	}
	if notifier.calls != 0 {
		t.Fatalf("notifier must not observe a refused rotation, got %d calls", notifier.calls)
	}
}

// A valid proof for a different pending key must be rejected: the proof has to
// bind the exact old/new key pair of this rotation.
func TestN21_AutoTriggerRejectsProofBoundToOtherKey(t *testing.T) {
	at, notifier := newN21Trigger(t)
	old := installN21ActiveKey(t, at)

	other, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	at.SetRotationProofProvider(func(oldKey, newKey *crypto.KeyPair, ts int64) (*RotationProof, error) {
		return validProofProvider(oldKey, other, ts)
	})

	err = at.RotateNow()
	if !errors.Is(err, ErrProofKeyMismatch) {
		t.Fatalf("RotateNow error = %v, want ErrProofKeyMismatch", err)
	}
	active, _, getErr := at.GetKeyManager().GetActiveKey()
	if getErr != nil {
		t.Fatalf("GetActiveKey: %v", getErr)
	}
	if !bytes.Equal(active.Public.Bytes(), old.Public.Bytes()) {
		t.Fatal("a misbound proof must not replace the active key")
	}
	if notifier.calls != 0 {
		t.Fatalf("notifier must not observe a refused rotation, got %d calls", notifier.calls)
	}
}

// With a valid proof the rotation proceeds normally.
func TestN21_AutoTriggerAcceptsValidProof(t *testing.T) {
	at, notifier := newN21Trigger(t)
	old := installN21ActiveKey(t, at)
	at.SetRotationProofProvider(validProofProvider)

	if err := at.RotateNow(); err != nil {
		t.Fatalf("RotateNow with a valid proof: %v", err)
	}
	active, meta, err := at.GetKeyManager().GetActiveKey()
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}
	if bytes.Equal(active.Public.Bytes(), old.Public.Bytes()) {
		t.Fatal("a valid proof must rotate to a new key")
	}
	if meta.Version != 2 {
		t.Fatalf("rotated key version = %d, want 2", meta.Version)
	}
	if notifier.calls != 1 {
		t.Fatalf("notifier calls = %d, want 1", notifier.calls)
	}
	// N-21 step 1: the outgoing key is zeroized as part of the rotation.
	if _, err := old.Private.Sign([]byte("probe")); !errors.Is(err, crypto.ErrInvalidPrivateKey) {
		t.Fatalf("retired key must be unusable after rotation, got err=%v", err)
	}
}

// First-time provisioning has no outgoing key to authorize, so it still works.
func TestN21_AutoTriggerProvisionsInitialKeyWithoutProof(t *testing.T) {
	at, notifier := newN21Trigger(t)

	if err := at.RotateNow(); err != nil {
		t.Fatalf("initial key provisioning must not require a proof: %v", err)
	}
	_, meta, err := at.GetKeyManager().GetActiveKey()
	if err != nil {
		t.Fatalf("GetActiveKey: %v", err)
	}
	if meta.Version != 1 {
		t.Fatalf("provisioned key version = %d, want 1", meta.Version)
	}
	if notifier.calls != 1 {
		t.Fatalf("notifier calls = %d, want 1", notifier.calls)
	}
}

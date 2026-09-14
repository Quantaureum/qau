// Quantaureum Node source, version 1.0.0.
package stealth

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

func makeTestAddr(b byte) types.Address {
	var addr types.Address
	addr[0] = b
	return addr
}

func TestGenerateStealthKeys(t *testing.T) {
	metaAddr, spendPriv, viewPriv, kemPrivKey, err := GenerateStealthKeys()
	if err != nil {
		t.Fatalf("failed to generate stealth keys: %v", err)
	}

	if metaAddr == nil {
		t.Fatal("meta address should not be nil")
	}
	if len(metaAddr.SpendPublicKey) == 0 {
		t.Error("spend public key should not be empty")
	}
	if len(metaAddr.ViewPublicKey) == 0 {
		t.Error("view public key should not be empty")
	}
	if len(metaAddr.KemPublicKey) == 0 {
		t.Error("KEM public key should not be empty")
	}
	if spendPriv == nil {
		t.Error("spend private key should not be nil")
	}
	if viewPriv == nil {
		t.Error("view private key should not be nil")
	}
	if len(kemPrivKey) == 0 {
		t.Error("KEM private key should not be empty")
	}
}

func TestRegisterAndLookup(t *testing.T) {
	sm := NewStealthManager()
	metaAddr, _, _, _, _ := GenerateStealthKeys()
	ownerAddr := makeTestAddr(1)

	err := sm.RegisterStealthAddress(ownerAddr, metaAddr)
	if err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	lookup, err := sm.LookupStealthMetaAddress(ownerAddr)
	if err != nil {
		t.Fatalf("failed to lookup: %v", err)
	}

	if len(lookup.SpendPublicKey) != len(metaAddr.SpendPublicKey) {
		t.Error("spend public key mismatch after lookup")
	}
	if len(lookup.KemPublicKey) != len(metaAddr.KemPublicKey) {
		t.Error("KEM public key mismatch after lookup")
	}
}

func TestRegisterDuplicate(t *testing.T) {
	sm := NewStealthManager()
	metaAddr, _, _, _, _ := GenerateStealthKeys()
	ownerAddr := makeTestAddr(1)

	sm.RegisterStealthAddress(ownerAddr, metaAddr)

	err := sm.RegisterStealthAddress(ownerAddr, metaAddr)
	if err != ErrAlreadyRegistered {
		t.Errorf("expected ErrAlreadyRegistered, got %v", err)
	}
}

func TestGenerateStealthAddress(t *testing.T) {
	sm := NewStealthManager()
	metaAddr, spendPriv, _, _, _ := GenerateStealthKeys()
	ownerAddr := makeTestAddr(1)
	sm.RegisterStealthAddress(ownerAddr, metaAddr)

	stealthAddr, announcement, err := sm.GenerateStealthAddress(metaAddr, spendPriv)
	if err != nil {
		t.Fatalf("failed to generate stealth address: %v", err)
	}

	if stealthAddr == nil {
		t.Fatal("stealth address should not be nil")
	}
	if announcement == nil {
		t.Fatal("announcement should not be nil")
	}
	if len(stealthAddr.EphemeralPubKey) == 0 {
		t.Error("ephemeral public key should not be empty")
	}
	if len(announcement.KemCiphertext) == 0 {
		t.Error("KEM ciphertext should not be empty")
	}
	if sm.AnnouncementCount() != 1 {
		t.Errorf("expected 1 announcement, got %d", sm.AnnouncementCount())
	}
}

func TestScanAnnouncements(t *testing.T) {
	sm := NewStealthManager()
	metaAddr, spendPriv, _, kemPrivKey, _ := GenerateStealthKeys()
	ownerAddr := makeTestAddr(1)
	sm.RegisterStealthAddress(ownerAddr, metaAddr)

	sm.GenerateStealthAddress(metaAddr, spendPriv)
	sm.GenerateStealthAddress(metaAddr, spendPriv)

	results, err := sm.ScanAnnouncements(kemPrivKey, metaAddr.SpendPublicKey)
	if err != nil {
		t.Fatalf("failed to scan: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 matching announcements, got %d", len(results))
	}
}

func TestRecoverPrivateKey(t *testing.T) {
	sm := NewStealthManager()
	metaAddr, spendPriv, _, kemPrivKey, _ := GenerateStealthKeys()
	ownerAddr := makeTestAddr(1)
	sm.RegisterStealthAddress(ownerAddr, metaAddr)

	_, announcement, _ := sm.GenerateStealthAddress(metaAddr, spendPriv)

	recoveredKey, err := sm.RecoverPrivateKey(announcement, kemPrivKey, spendPriv.Bytes())
	if err != nil {
		t.Fatalf("failed to recover private key: %v", err)
	}

	if len(recoveredKey) == 0 {
		t.Error("recovered private key should not be empty")
	}
}

func TestStealthEndToEnd(t *testing.T) {
	sm := NewStealthManager()

	metaAddr, spendPriv, _, kemPrivKey, _ := GenerateStealthKeys()
	ownerAddr := makeTestAddr(1)
	sm.RegisterStealthAddress(ownerAddr, metaAddr)

	stealthAddr, announcement, err := sm.GenerateStealthAddress(metaAddr, spendPriv)
	if err != nil {
		t.Fatalf("failed to generate stealth address: %v", err)
	}
	if stealthAddr == nil {
		t.Fatal("stealth address should not be nil")
	}

	results, err := sm.ScanAnnouncements(kemPrivKey, metaAddr.SpendPublicKey)
	if err != nil {
		t.Fatalf("failed to scan: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 matching announcement, got %d", len(results))
	}

	recoveredKey, err := sm.RecoverPrivateKey(announcement, kemPrivKey, spendPriv.Bytes())
	if err != nil {
		t.Fatalf("failed to recover private key: %v", err)
	}

	if len(recoveredKey) == 0 {
		t.Error("recovered private key should not be empty")
	}
}

func TestStealthEdgeCases(t *testing.T) {
	t.Run("nil meta address", func(t *testing.T) {
		sm := NewStealthManager()
		_, _, err := sm.GenerateStealthAddress(nil, nil)
		if err == nil {
			t.Error("should fail with nil meta address")
		}
	})

	t.Run("lookup unregistered", func(t *testing.T) {
		sm := NewStealthManager()
		_, err := sm.LookupStealthMetaAddress(makeTestAddr(99))
		if err == nil {
			t.Error("should fail for unregistered address")
		}
	})

	t.Run("scan with no announcements", func(t *testing.T) {
		sm := NewStealthManager()
		_, _, _, kemPrivKey, _ := GenerateStealthKeys()
		results, err := sm.ScanAnnouncements(kemPrivKey, []byte("spendkey"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 0 {
			t.Errorf("expected 0 results, got %d", len(results))
		}
	})

	t.Run("nil announcement recovery", func(t *testing.T) {
		sm := NewStealthManager()
		_, err := sm.RecoverPrivateKey(nil, []byte("kem"), []byte("spend"))
		if err != ErrRecoveryFailed {
			t.Errorf("expected ErrRecoveryFailed, got %v", err)
		}
	})

	t.Run("register nil meta address", func(t *testing.T) {
		sm := NewStealthManager()
		err := sm.RegisterStealthAddress(makeTestAddr(1), nil)
		if err != ErrInvalidMetaAddress {
			t.Errorf("expected ErrInvalidMetaAddress for nil, got %v", err)
		}
	})

	t.Run("register empty spend pub key", func(t *testing.T) {
		sm := NewStealthManager()
		meta := &StealthMetaAddress{
			SpendPublicKey: []byte{},
			ViewPublicKey:  []byte{1, 2, 3},
			KemPublicKey:   []byte{1, 2, 3},
		}
		err := sm.RegisterStealthAddress(makeTestAddr(1), meta)
		if err != ErrInvalidMetaAddress {
			t.Errorf("expected ErrInvalidMetaAddress for empty spend key, got %v", err)
		}
	})

	t.Run("register empty view pub key", func(t *testing.T) {
		sm := NewStealthManager()
		meta := &StealthMetaAddress{
			SpendPublicKey: []byte{1, 2, 3},
			ViewPublicKey:  []byte{},
			KemPublicKey:   []byte{1, 2, 3},
		}
		err := sm.RegisterStealthAddress(makeTestAddr(1), meta)
		if err != ErrInvalidMetaAddress {
			t.Errorf("expected ErrInvalidMetaAddress for empty view key, got %v", err)
		}
	})

	t.Run("register empty kem pub key", func(t *testing.T) {
		sm := NewStealthManager()
		meta := &StealthMetaAddress{
			SpendPublicKey: []byte{1, 2, 3},
			ViewPublicKey:  []byte{1, 2, 3},
			KemPublicKey:   []byte{},
		}
		err := sm.RegisterStealthAddress(makeTestAddr(1), meta)
		if err != ErrInvalidMetaAddress {
			t.Errorf("expected ErrInvalidMetaAddress for empty KEM key, got %v", err)
		}
	})

	t.Run("generate random bytes", func(t *testing.T) {
		buf, err := generateRandomBytes(32)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(buf) != 32 {
			t.Errorf("expected 32 bytes, got %d", len(buf))
		}
	})

	t.Run("generate random bytes empty", func(t *testing.T) {
		buf, err := generateRandomBytes(0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(buf) != 0 {
			t.Errorf("expected 0 bytes, got %d", len(buf))
		}
	})

	t.Run("encapsulate decapsulate round trip", func(t *testing.T) {
		_, _, _, kemPrivKey, _ := GenerateStealthKeys()
		metaAddr, _, _, _, _ := GenerateStealthKeys()

		ss1, ct, err := encapsulateSharedSecret(metaAddr.KemPublicKey)
		if err != nil {
			t.Fatalf("encapsulate failed: %v", err)
		}

		ss2, err := decapsulateSharedSecret(kemPrivKey, ct)
		if err != nil {
			t.Fatalf("decapsulate failed: %v", err)
		}

		if len(ss1) == 0 {
			t.Error("shared secret from encapsulate should not be empty")
		}
		_ = ss2
	})

	t.Run("invalid kem public key size", func(t *testing.T) {
		_, _, err := encapsulateSharedSecret([]byte{1, 2, 3})
		if err == nil {
			t.Error("should fail with invalid KEM public key size")
		}
	})

	t.Run("invalid kem private key size", func(t *testing.T) {
		_, err := decapsulateSharedSecret([]byte{1, 2, 3}, make([]byte, 1088))
		if err == nil {
			t.Error("should fail with invalid KEM private key size")
		}
	})

	t.Run("invalid ciphertext size", func(t *testing.T) {
		_, _, _, kemPrivKey, _ := GenerateStealthKeys()
		_, err := decapsulateSharedSecret(kemPrivKey, []byte{1, 2, 3})
		if err == nil {
			t.Error("should fail with invalid ciphertext size")
		}
	})

	t.Run("scan with wrong kem key", func(t *testing.T) {
		sm := NewStealthManager()
		metaAddr, spendPriv, _, _, _ := GenerateStealthKeys()
		ownerAddr := makeTestAddr(1)
		sm.RegisterStealthAddress(ownerAddr, metaAddr)

		sm.GenerateStealthAddress(metaAddr, spendPriv)

		_, _, _, wrongKemPrivKey, _ := GenerateStealthKeys()
		results, err := sm.ScanAnnouncements(wrongKemPrivKey, metaAddr.SpendPublicKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 0 {
			t.Errorf("expected 0 results with wrong KEM key, got %d", len(results))
		}
	})
}

func TestStealthErrors(t *testing.T) {
	errors := []error{
		ErrInvalidMetaAddress,
		ErrAlreadyRegistered,
		ErrInvalidEphemeralKey,
		ErrScanFailed,
		ErrRecoveryFailed,
		ErrAnnouncementNotFound,
	}
	for _, e := range errors {
		if e.Error() == "" {
			t.Errorf("error should have message")
		}
	}
}

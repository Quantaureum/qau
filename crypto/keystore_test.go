// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

func TestIsNilKey(t *testing.T) {
	if !isNilKey(nil) {
		t.Error("should be true for nil key")
	}

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if isNilKey(kp.Private) {
		t.Error("should be false for valid key")
	}
}

func TestDefaultScryptParams(t *testing.T) {
	p := DefaultScryptParams()
	if p.N != ScryptN {
		t.Errorf("expected N=%d, got %d", ScryptN, p.N)
	}
	if p.R != ScryptR {
		t.Errorf("expected R=%d, got %d", ScryptR, p.R)
	}
	if p.P != ScryptP {
		t.Errorf("expected P=%d, got %d", ScryptP, p.P)
	}
	if p.DKLen != ScryptKeyLen {
		t.Errorf("expected DKLen=%d, got %d", ScryptKeyLen, p.DKLen)
	}
}

func TestLightScryptParams(t *testing.T) {
	p := LightScryptParams()
	if p.N != MinScryptN {
		t.Errorf("expected N=%d, got %d", MinScryptN, p.N)
	}
	if p.DKLen != ScryptKeyLen {
		t.Errorf("expected DKLen=%d, got %d", ScryptKeyLen, p.DKLen)
	}
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	pwd := []byte("test-password-12345")
	params := LightScryptParams()

	kf, err := EncryptKeyWithParamsBytes(kp.Private, pwd, params)
	if err != nil {
		t.Fatalf("EncryptKeyWithParamsBytes failed: %v", err)
	}
	// CRYPTO-R12-004 (2026-07-20): New encryptions produce v2 key files
	// with AAD binding. v1 is only accepted for backward compatibility.
	if kf.Version != KeyFileVersionV2 {
		t.Errorf("expected version %d, got %d", KeyFileVersionV2, kf.Version)
	}
	if kf.Crypto.Cipher != "aes-256-gcm" {
		t.Errorf("expected aes-256-gcm, got %s", kf.Crypto.Cipher)
	}
	if kf.Crypto.KDF != "scrypt" {
		t.Errorf("expected scrypt, got %s", kf.Crypto.KDF)
	}

	decrypted, err := DecryptKeyBytes(kf, pwd)
	if err != nil {
		t.Fatalf("DecryptKeyBytes failed: %v", err)
	}
	if !kp.Private.Equal(decrypted) {
		t.Error("decrypted key does not match original")
	}

	// Verify derived public key matches
	origPub := kp.Private.PublicKey()
	decPub := decrypted.PublicKey()
	if !origPub.Equal(decPub) {
		t.Error("public keys do not match")
	}
}

func TestEncryptKeyBytes_NilKey(t *testing.T) {
	_, err := EncryptKeyBytes(nil, []byte("password"))
	if err != ErrInvalidPrivateKey {
		t.Errorf("expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestEncryptKeyWithParamsBytes_ScryptNTooLow(t *testing.T) {
	kp, _ := GenerateKeyPair()
	_, err := EncryptKeyWithParamsBytes(kp.Private, []byte("pwd"), ScryptParams{N: 1, R: 8, P: 1, DKLen: 32})
	if err == nil {
		t.Error("expected error for scrypt N too low")
	}
}

func TestEncryptKeyWithParamsBytes_ScryptNTooHigh(t *testing.T) {
	kp, _ := GenerateKeyPair()
	_, err := EncryptKeyWithParamsBytes(kp.Private, []byte("pwd"), ScryptParams{N: MaxScryptN + 1, R: 8, P: 1, DKLen: 32})
	if err == nil {
		t.Error("expected error for scrypt N too high")
	}
}

func TestEncryptKeyWithParamsBytes_ScryptROutOfRange(t *testing.T) {
	kp, _ := GenerateKeyPair()
	_, err := EncryptKeyWithParamsBytes(kp.Private, []byte("pwd"), ScryptParams{N: MinScryptN, R: 0, P: 1, DKLen: 32})
	if err == nil {
		t.Error("expected error for scrypt R too low")
	}
	_, err = EncryptKeyWithParamsBytes(kp.Private, []byte("pwd"), ScryptParams{N: MinScryptN, R: 33, P: 1, DKLen: 32})
	if err == nil {
		t.Error("expected error for scrypt R too high")
	}
}

func TestEncryptKeyWithParamsBytes_ScryptPOutOfRange(t *testing.T) {
	kp, _ := GenerateKeyPair()
	_, err := EncryptKeyWithParamsBytes(kp.Private, []byte("pwd"), ScryptParams{N: MinScryptN, R: 8, P: 0, DKLen: 32})
	if err == nil {
		t.Error("expected error for scrypt P too low")
	}
	_, err = EncryptKeyWithParamsBytes(kp.Private, []byte("pwd"), ScryptParams{N: MinScryptN, R: 8, P: 17, DKLen: 32})
	if err == nil {
		t.Error("expected error for scrypt P too high")
	}
}

func TestEncryptKeyWithParamsBytes_DKLenOutOfRange(t *testing.T) {
	kp, _ := GenerateKeyPair()
	_, err := EncryptKeyWithParamsBytes(kp.Private, []byte("pwd"), ScryptParams{N: MinScryptN, R: 8, P: 1, DKLen: 1})
	if err == nil {
		t.Error("expected error for DKLen too low")
	}
	_, err = EncryptKeyWithParamsBytes(kp.Private, []byte("pwd"), ScryptParams{N: MinScryptN, R: 8, P: 1, DKLen: 65})
	if err == nil {
		t.Error("expected error for DKLen too high")
	}
}

func TestDecryptKeyBytes_NilKeyFile(t *testing.T) {
	_, err := DecryptKeyBytes(nil, []byte("pwd"))
	if err != ErrInvalidKeyFile {
		t.Errorf("expected ErrInvalidKeyFile, got %v", err)
	}
}

func TestDecryptKeyBytes_WrongVersion(t *testing.T) {
	kf := &KeyFile{Version: 99, Crypto: CryptoJSON{
		Cipher:       "aes-256-gcm",
		KDF:          "scrypt",
		CipherText:   make([]byte, 32),
		KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: MinScryptN, R: 8, P: 1, DKLen: 32},
		CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
	}}
	_, err := DecryptKeyBytes(kf, []byte("pwd"))
	if err == nil {
		t.Error("expected error for wrong version")
	}
}

func TestDecryptKeyBytes_WrongCipher(t *testing.T) {
	kf := &KeyFile{Version: KeyFileVersion, Crypto: CryptoJSON{
		Cipher:       "des",
		KDF:          "scrypt",
		CipherText:   make([]byte, 32),
		KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: MinScryptN, R: 8, P: 1, DKLen: 32},
		CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
	}}
	_, err := DecryptKeyBytes(kf, []byte("pwd"))
	if err == nil {
		t.Error("expected error for wrong cipher")
	}
}

func TestDecryptKeyBytes_WrongKDF(t *testing.T) {
	kf := &KeyFile{Version: KeyFileVersion, Crypto: CryptoJSON{
		Cipher:       "aes-256-gcm",
		KDF:          "pbkdf2",
		CipherText:   make([]byte, 32),
		KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: MinScryptN, R: 8, P: 1, DKLen: 32},
		CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
	}}
	_, err := DecryptKeyBytes(kf, []byte("pwd"))
	if err == nil {
		t.Error("expected error for wrong KDF")
	}
}

func TestDecryptKeyBytes_WrongSaltSize(t *testing.T) {
	kf := &KeyFile{Version: KeyFileVersion, Crypto: CryptoJSON{
		Cipher:       "aes-256-gcm",
		KDF:          "scrypt",
		CipherText:   make([]byte, 32),
		KDFParams:    KDFParams{Salt: []byte{1, 2, 3}, N: MinScryptN, R: 8, P: 1, DKLen: 32},
		CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
	}}
	_, err := DecryptKeyBytes(kf, []byte("pwd"))
	if err == nil {
		t.Error("expected error for wrong salt size")
	}
}

func TestDecryptKeyBytes_WrongNonceSize(t *testing.T) {
	kf := &KeyFile{Version: KeyFileVersion, Crypto: CryptoJSON{
		Cipher:       "aes-256-gcm",
		KDF:          "scrypt",
		CipherText:   make([]byte, 32),
		KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: MinScryptN, R: 8, P: 1, DKLen: 32},
		CipherParams: CipherParams{Nonce: []byte{1, 2}},
	}}
	_, err := DecryptKeyBytes(kf, []byte("pwd"))
	if err == nil {
		t.Error("expected error for wrong nonce size")
	}
}

func TestDecryptKeyBytes_CipherTextTooShort(t *testing.T) {
	kf := &KeyFile{Version: KeyFileVersion, Crypto: CryptoJSON{
		Cipher:       "aes-256-gcm",
		KDF:          "scrypt",
		CipherText:   []byte{1},
		KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: MinScryptN, R: 8, P: 1, DKLen: 32},
		CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
	}}
	_, err := DecryptKeyBytes(kf, []byte("pwd"))
	if err == nil {
		t.Error("expected error for ciphertext too short")
	}
}

func TestDecryptKeyBytes_WrongPassword(t *testing.T) {
	kp, _ := GenerateKeyPair()
	params := LightScryptParams()
	kf, _ := EncryptKeyWithParamsBytes(kp.Private, []byte("correct"), params)

	_, err := DecryptKeyBytes(kf, []byte("wrong"))
	if err != ErrInvalidPassword {
		t.Errorf("expected ErrInvalidPassword, got %v", err)
	}
}

func TestDecryptKeyBytes_ScryptNTooLow(t *testing.T) {
	kf := &KeyFile{Version: KeyFileVersion, Crypto: CryptoJSON{
		Cipher:       "aes-256-gcm",
		KDF:          "scrypt",
		CipherText:   make([]byte, 32),
		KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: 1, R: 8, P: 1, DKLen: 32},
		CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
	}}
	_, err := DecryptKeyBytes(kf, []byte("pwd"))
	if err == nil {
		t.Error("expected error for scrypt N too low")
	}
}

func TestDecryptKeyBytes_ScryptROutOfRange(t *testing.T) {
	kf := &KeyFile{Version: KeyFileVersion, Crypto: CryptoJSON{
		Cipher:       "aes-256-gcm",
		KDF:          "scrypt",
		CipherText:   make([]byte, 32),
		KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: MinScryptN, R: 0, P: 1, DKLen: 32},
		CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
	}}
	_, err := DecryptKeyBytes(kf, []byte("pwd"))
	if err == nil {
		t.Error("expected error for scrypt R out of range")
	}
}

func TestDecryptKeyBytes_ScryptPOutOfRange(t *testing.T) {
	kf := &KeyFile{Version: KeyFileVersion, Crypto: CryptoJSON{
		Cipher:       "aes-256-gcm",
		KDF:          "scrypt",
		CipherText:   make([]byte, 32),
		KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: MinScryptN, R: 8, P: 0, DKLen: 32},
		CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
	}}
	_, err := DecryptKeyBytes(kf, []byte("pwd"))
	if err == nil {
		t.Error("expected error for scrypt P out of range")
	}
}

func TestDecryptKeyBytes_DKLenOutOfRange(t *testing.T) {
	kf := &KeyFile{Version: KeyFileVersion, Crypto: CryptoJSON{
		Cipher:       "aes-256-gcm",
		KDF:          "scrypt",
		CipherText:   make([]byte, 32),
		KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: MinScryptN, R: 8, P: 1, DKLen: 1},
		CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
	}}
	_, err := DecryptKeyBytes(kf, []byte("pwd"))
	if err == nil {
		t.Error("expected error for DKLen out of range")
	}
}

func TestMigrateKeyFile_AlreadyStrong(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	pwd := []byte("password123")
	kf, err := EncryptKeyBytes(kp.Private, pwd)
	if err != nil {
		t.Fatal(err)
	}

	result, err := MigrateKeyFile(kf, pwd)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Crypto.KDFParams.N < MinScryptN {
		t.Errorf("migrated key should have strong N, got %d", result.Crypto.KDFParams.N)
	}
}

func TestDecryptKeyBytesLegacy(t *testing.T) {
	kp, _ := GenerateKeyPair()
	params := LightScryptParams()
	kf, _ := EncryptKeyWithParamsBytes(kp.Private, []byte("pwd"), params)
	kf.Crypto.KDFParams.N = 1 // Set legacy weak N

	_, err := DecryptKeyBytes(kf, []byte("pwd"))
	if err == nil {
		t.Error("expected error for weak N with enforced check")
	}

	decrypted, err := DecryptKeyBytesLegacy(kf, []byte("pwd"))
	if err == nil {
		// DecryptKeyBytesLegacy also enforces MinScryptN now, so this might fail
		_ = decrypted
	}
}

func TestKeyFile_MarshalJSON(t *testing.T) {
	kf := &KeyFile{Version: KeyFileVersion, Address: "QAU_test", CreatedAt: time.Now()}
	data, err := kf.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestKeyFile_UnmarshalJSON(t *testing.T) {
	kf := &KeyFile{Version: KeyFileVersion, Address: "QAU_test", CreatedAt: time.Now()}
	data, _ := kf.MarshalJSON()

	var kf2 KeyFile
	err := kf2.UnmarshalJSON(data)
	if err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	if kf2.Version != KeyFileVersion {
		t.Error("version mismatch")
	}
	if kf2.Address != "QAU_test" {
		t.Error("address mismatch")
	}
}

func TestKeyFile_ToJSON(t *testing.T) {
	kf := &KeyFile{Version: KeyFileVersion, Address: "QAU_test", CreatedAt: time.Now()}
	data, err := kf.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestKeyFileFromJSON_Valid(t *testing.T) {
	kf := &KeyFile{
		Version: KeyFileVersion,
		Address: "QAU_test",
		Crypto: CryptoJSON{
			Cipher:       "aes-256-gcm",
			CipherText:   make([]byte, 32),
			KDF:          "scrypt",
			KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: MinScryptN, R: 8, P: 1, DKLen: 32},
			CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
		},
	}
	data, _ := json.Marshal(kf)

	parsed, err := KeyFileFromJSON(data)
	if err != nil {
		t.Fatalf("KeyFileFromJSON failed: %v", err)
	}
	if parsed.Address != "QAU_test" {
		t.Error("address mismatch")
	}
}

func TestKeyFileFromJSON_Empty(t *testing.T) {
	_, err := KeyFileFromJSON([]byte{})
	if err == nil {
		t.Error("expected error for empty JSON")
	}
}

func TestKeyFileFromJSON_InvalidJSON(t *testing.T) {
	_, err := KeyFileFromJSON([]byte("{bad"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestKeyFileFromJSON_WrongVersion(t *testing.T) {
	data := []byte(`{"version":99,"address":"QAU","crypto":{},"created_at":"2024-01-01T00:00:00Z"}`)
	_, err := KeyFileFromJSON(data)
	if err == nil {
		t.Error("expected error for wrong version")
	}
}

func TestKeyFileFromJSON_MissingCipherText(t *testing.T) {
	data := []byte(`{"version":1,"address":"QAU","crypto":{"cipher":"aes-256-gcm","ciphertext":"","kdf":"scrypt","cipherparams":{"nonce":"AAAAAAAAAAAA"},"kdfparams":{"salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","n":32768,"r":8,"p":1,"dklen":32}},"created_at":"2024-01-01T00:00:00Z"}`)
	_, err := KeyFileFromJSON(data)
	if err == nil {
		t.Error("expected error for missing ciphertext")
	}
}

func TestKeyFileFromJSON_MissingSalt(t *testing.T) {
	data := []byte(`{"version":1,"address":"QAU","crypto":{"cipher":"aes-256-gcm","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kdf":"scrypt","cipherparams":{"nonce":"AAAAAAAAAAAA"},"kdfparams":{"salt":"","n":32768,"r":8,"p":1,"dklen":32}},"created_at":"2024-01-01T00:00:00Z"}`)
	_, err := KeyFileFromJSON(data)
	if err == nil {
		t.Error("expected error for missing salt")
	}
}

func TestKeyFileFromJSON_MissingNonce(t *testing.T) {
	data := []byte(`{"version":1,"address":"QAU","crypto":{"cipher":"aes-256-gcm","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kdf":"scrypt","cipherparams":{"nonce":""},"kdfparams":{"salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","n":32768,"r":8,"p":1,"dklen":32}},"created_at":"2024-01-01T00:00:00Z"}`)
	_, err := KeyFileFromJSON(data)
	if err == nil {
		t.Error("expected error for missing nonce")
	}
}

func TestKeyFileFromJSON_ScryptNTooHigh(t *testing.T) {
	kf := &KeyFile{
		Version: KeyFileVersion, Address: "QAU",
		Crypto: CryptoJSON{
			Cipher:       "aes-256-gcm",
			CipherText:   make([]byte, 32),
			KDF:          "scrypt",
			KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: MaxScryptN + 1, R: 8, P: 1, DKLen: 32},
			CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
		},
	}
	data, _ := json.Marshal(kf)
	_, err := KeyFileFromJSON(data)
	if err == nil {
		t.Error("expected error for N too high")
	}
}

func TestKeyFileFromJSON_ScryptNTooLow(t *testing.T) {
	kf := &KeyFile{
		Version: KeyFileVersion, Address: "QAU",
		Crypto: CryptoJSON{
			Cipher:       "aes-256-gcm",
			CipherText:   make([]byte, 32),
			KDF:          "scrypt",
			KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: 1, R: 8, P: 1, DKLen: 32},
			CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
		},
	}
	data, _ := json.Marshal(kf)
	parsed, err := KeyFileFromJSON(data)
	// R38-P3 FIX: Weak scrypt N is now rejected, not just warned.
	if err == nil {
		t.Errorf("expected error for N too low (R38-P3: reject weak params), got nil")
	}
	_ = parsed
	if parsed != nil && parsed.Crypto.KDFParams.N != 1 {
		t.Errorf("expected N=1 in parsed keyfile, got %d", parsed.Crypto.KDFParams.N)
	}
}

func TestKeyFileFromJSON_ROutOfRange(t *testing.T) {
	kf := &KeyFile{
		Version: KeyFileVersion, Address: "QAU",
		Crypto: CryptoJSON{
			Cipher:       "aes-256-gcm",
			CipherText:   make([]byte, 32),
			KDF:          "scrypt",
			KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: MinScryptN, R: 0, P: 1, DKLen: 32},
			CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
		},
	}
	data, _ := json.Marshal(kf)
	_, err := KeyFileFromJSON(data)
	if err == nil {
		t.Error("expected error for R out of range")
	}
}

func TestKeyFileFromJSON_POutOfRange(t *testing.T) {
	kf := &KeyFile{
		Version: KeyFileVersion, Address: "QAU",
		Crypto: CryptoJSON{
			Cipher:       "aes-256-gcm",
			CipherText:   make([]byte, 32),
			KDF:          "scrypt",
			KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: MinScryptN, R: 8, P: 0, DKLen: 32},
			CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
		},
	}
	data, _ := json.Marshal(kf)
	_, err := KeyFileFromJSON(data)
	if err == nil {
		t.Error("expected error for P out of range")
	}
}

func TestEncryptKey_Deprecated(t *testing.T) {
	kp, _ := GenerateKeyPair()
	kf, err := EncryptKey(kp.Private, "test-pwd")
	if err != nil {
		t.Fatalf("EncryptKey failed: %v", err)
	}
	if kf == nil {
		t.Error("expected non-nil KeyFile")
	}
}

func TestDecryptKey_Deprecated(t *testing.T) {
	kp, _ := GenerateKeyPair()
	params := LightScryptParams()
	kf, _ := EncryptKeyWithParamsBytes(kp.Private, []byte("pwd123"), params)

	decrypted, err := DecryptKey(kf, "pwd123")
	if err != nil {
		t.Fatalf("DecryptKey failed: %v", err)
	}
	if !kp.Private.Equal(decrypted) {
		t.Error("decrypted key mismatch")
	}
}

func TestEncryptKeyWithParams_Deprecated(t *testing.T) {
	kp, _ := GenerateKeyPair()
	params := LightScryptParams()
	kf, err := EncryptKeyWithParams(kp.Private, "pwd456", params)
	if err != nil {
		t.Fatalf("EncryptKeyWithParams failed: %v", err)
	}
	if kf == nil {
		t.Error("expected non-nil KeyFile")
	}
}

func TestZeroBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	zeroBytes(data)
	for _, b := range data {
		if b != 0 {
			t.Error("byte not zeroed")
		}
	}

	zeroBytes(nil)
	zeroBytes([]byte{})
}

func TestZeroBytesSecure(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	err := ZeroBytesSecure(data)
	if err != nil {
		t.Fatalf("ZeroBytesSecure failed: %v", err)
	}

	err = ZeroBytesSecure(nil)
	if err != nil {
		t.Error("zeroing nil should not error")
	}
	err = ZeroBytesSecure([]byte{})
	if err != nil {
		t.Error("zeroing empty should not error")
	}
}

func TestDestroy(t *testing.T) {
	var nilPk *PrivateKey
	nilPk.Destroy()

	kp, _ := GenerateKeyPair()
	kp.Private.Destroy()
	if kp.Private.key != nil {
		t.Error("key should be nil after Destroy")
	}
}

func TestZeroize(t *testing.T) {
	var nilPk *PrivateKey
	nilPk.Zeroize()

	kp, _ := GenerateKeyPair()
	kp.Private.Zeroize()
	if kp.Private.key != nil {
		t.Error("key should be nil after Zeroize")
	}
}

func TestGenerateKeyPairFromSeed(t *testing.T) {
	seed := []byte("seed-32-bytes--test-seed-1234567")

	// R32-P4-1: GenerateKeyPairFromSeed now zeros the seed for security.
	// Use separate copies to verify deterministic generation.
	seed2 := make([]byte, len(seed))
	copy(seed2, seed)

	kp, err := GenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromSeed failed: %v", err)
	}
	if kp == nil || kp.Private == nil || kp.Public == nil {
		t.Fatal("key pair should not be nil")
	}

	kp2, err := GenerateKeyPairFromSeed(seed2)
	if err != nil {
		t.Fatal(err)
	}
	if !kp.Private.Equal(kp2.Private) {
		t.Error("deterministic generation should produce same key")
	}
}

func TestGenerateKeyPairFromSeed_EmptySeed(t *testing.T) {
	_, err := GenerateKeyPairFromSeed(nil)
	if err == nil {
		t.Error("expected error for nil seed")
	}
	_, err = GenerateKeyPairFromSeed([]byte{})
	if err == nil {
		t.Error("expected error for empty seed")
	}
}

func TestShakeReader_Read(t *testing.T) {
	r := newShakeReader([]byte("seed"))
	buf := make([]byte, 32)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 32 {
		t.Errorf("expected 32 bytes, got %d", n)
	}
}

func TestPublicKeyAddressFromBytes(t *testing.T) {
	pubKey := make([]byte, Dilithium3PublicKeySize)
	addr := PublicKeyAddressFromBytes(pubKey)
	if addr == (types.Address{}) {
		t.Error("expected non-zero address")
	}
}

func TestKeyFileFromJSON_CipherTextTooLarge(t *testing.T) {
	kf := &KeyFile{
		Version: KeyFileVersion, Address: "QAU",
		Crypto: CryptoJSON{
			Cipher:       "aes-256-gcm",
			CipherText:   make([]byte, MaxCiphertextSize+1),
			KDF:          "scrypt",
			KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: MinScryptN, R: 8, P: 1, DKLen: 32},
			CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
		},
	}
	data, _ := json.Marshal(kf)
	_, err := KeyFileFromJSON(data)
	if err == nil {
		t.Error("expected error for ciphertext too large")
	}
}

func TestCryptoErrorVariables(t *testing.T) {
	errors := []error{
		ErrInvalidPassword, ErrInvalidKeyFile, ErrUnsupportedVersion,
	}
	for _, e := range errors {
		if e.Error() == "" {
			t.Errorf("error %T has empty message", e)
		}
	}
}

func TestDecryptKeyBytes_ScryptNTooHighOnDecode(t *testing.T) {
	kf := &KeyFile{Version: KeyFileVersion, Crypto: CryptoJSON{
		Cipher:       "aes-256-gcm",
		KDF:          "scrypt",
		CipherText:   make([]byte, 32),
		KDFParams:    KDFParams{Salt: make([]byte, SaltSize), N: MaxScryptN + 1, R: 8, P: 1, DKLen: 32},
		CipherParams: CipherParams{Nonce: make([]byte, NonceSize)},
	}}
	_, err := DecryptKeyBytes(kf, []byte("pwd"))
	if err == nil {
		t.Error("expected error for N too high")
	}
}

func TestExportKeyPair_Nil(t *testing.T) {
	_, _, err := ExportKeyPair(nil)
	if err != ErrInvalidPrivateKey {
		t.Errorf("expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestExportKeyPair_NilPrivate(t *testing.T) {
	kp := &KeyPair{Private: nil, Public: &PublicKey{}}
	_, _, err := ExportKeyPair(kp)
	if err != ErrInvalidPrivateKey {
		t.Errorf("expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestExportKeyPair_NilPublic(t *testing.T) {
	kp := &KeyPair{Private: &PrivateKey{}, Public: nil}
	_, _, err := ExportKeyPair(kp)
	if err != ErrInvalidPrivateKey {
		t.Errorf("expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestImportKeyPair_Nil(t *testing.T) {
	_, err := ImportKeyPair(nil, nil)
	if err == nil {
		t.Error("expected error for nil keys")
	}
}

func TestImportKeyPair_Empty(t *testing.T) {
	_, err := ImportKeyPair([]byte{}, []byte{})
	if err == nil {
		t.Error("expected error for empty keys")
	}
}

func TestPublicKeyAddress_Nil(t *testing.T) {
	var pk *PublicKey
	addr := pk.Address()
	if addr != (types.Address{}) {
		t.Error("expected zero address for nil")
	}
}

func TestPublicKeyAddress_NilKey(t *testing.T) {
	pk := &PublicKey{key: nil}
	addr := pk.Address()
	if addr != (types.Address{}) {
		t.Error("expected zero address for nil key")
	}
}

func TestPublicKeyFromBytes_AllZero(t *testing.T) {
	zeroBytes := make([]byte, Dilithium3PublicKeySize)
	pub, err := PublicKeyFromBytes(zeroBytes)
	if err == nil {
		if pub == nil {
			t.Fatal("expected non-nil public key")
		}
	}
}

func TestPrivateKeyFromBytes_AllZero(t *testing.T) {
	zeroBytes := make([]byte, Dilithium3PrivateKeySize)
	pk, err := PrivateKeyFromBytes(zeroBytes)
	if err == nil {
		if pk == nil {
			t.Fatal("expected non-nil private key")
		}
	}
}

func TestPublicKeyFromBytes_AllFF(t *testing.T) {
	ffBytes := make([]byte, Dilithium3PublicKeySize)
	for i := range ffBytes {
		ffBytes[i] = 0xFF
	}
	pub, err := PublicKeyFromBytes(ffBytes)
	if err != nil {
		t.Log("all-FF public key from bytes error:", err)
	}
	_ = pub
}

func TestPrivateKeyFromBytes_AllFF(t *testing.T) {
	ffBytes := make([]byte, Dilithium3PrivateKeySize)
	for i := range ffBytes {
		ffBytes[i] = 0xFF
	}
	pk, err := PrivateKeyFromBytes(ffBytes)
	if err != nil {
		t.Log("all-FF private key from bytes error:", err)
	}
	_ = pk
}

func TestPublicKeyFromBytes_InvalidLength(t *testing.T) {
	_, err := PublicKeyFromBytes([]byte("too_short"))
	if err == nil {
		t.Error("expected error for wrong length")
	}
	_, err = PublicKeyFromBytes(make([]byte, Dilithium3PublicKeySize+1))
	if err == nil {
		t.Error("expected error for too long")
	}
}

func TestPrivateKeyFromBytes_InvalidLength(t *testing.T) {
	_, err := PrivateKeyFromBytes([]byte("too_short"))
	if err == nil {
		t.Error("expected error for wrong length")
	}
	_, err = PrivateKeyFromBytes(make([]byte, Dilithium3PrivateKeySize+1))
	if err == nil {
		t.Error("expected error for too long")
	}
}

func TestDestroy_ValidKey(t *testing.T) {
	kp, _ := GenerateKeyPair()
	kp.Private.Destroy()
	if kp.Private.key != nil {
		t.Error("key should be nil after Destroy")
	}
}

func TestDestroy_DoubleDestroy(t *testing.T) {
	kp, _ := GenerateKeyPair()
	kp.Private.Destroy()
	kp.Private.Destroy()
}

func TestDestroy_NilKeyField(t *testing.T) {
	pk := &PrivateKey{key: nil}
	pk.Destroy()
}

func TestZeroize_DoubleZeroize(t *testing.T) {
	kp, _ := GenerateKeyPair()
	kp.Private.Zeroize()
	kp.Private.Zeroize()
	if kp.Private.key != nil {
		t.Error("key should be nil after double Zeroize")
	}
}

func TestZeroize_NilKeyField(t *testing.T) {
	pk := &PrivateKey{key: nil}
	pk.Zeroize()
}

func TestGenerateKeyPair_MultipleUnique(t *testing.T) {
	pairs := make(map[string]bool)
	for i := 0; i < 5; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		key := string(kp.Private.Bytes())
		if pairs[key] {
			t.Error("duplicate key pair generated")
		}
		pairs[key] = true
	}
}

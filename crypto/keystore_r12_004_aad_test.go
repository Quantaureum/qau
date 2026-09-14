// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"golang.org/x/crypto/scrypt"
)

// =============================================================================
// CRYPTO-R12-004 (2026-07-20) tests: AES-256-GCM AAD binding
//
// These tests verify that:
//  1. New encryptions produce v2 key files (with AAD)
//  2. v2 key files decrypt correctly (round-trip)
//  3. Tampering with ANY metadata field causes decryption to fail
//  4. v1 key files (legacy, no AAD) still decrypt for backward compat
//  5. buildAAD is deterministic and includes all bound fields
// =============================================================================

// TestCRYPTO_R12_004_V2ProducedByDefault verifies that EncryptKeyWithParamsBytes
// produces a v2 key file (with AAD binding), not v1.
func TestCRYPTO_R12_004_V2ProducedByDefault(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	kf, err := EncryptKeyWithParamsBytes(kp.Private, []byte("password"), LightScryptParams())
	if err != nil {
		t.Fatalf("EncryptKeyWithParamsBytes failed: %v", err)
	}
	if kf.Version != KeyFileVersionV2 {
		t.Errorf("expected version %d (v2 with AAD), got %d", KeyFileVersionV2, kf.Version)
	}
}

// TestCRYPTO_R12_004_Roundtrip verifies that a v2 key file decrypts correctly.
func TestCRYPTO_R12_004_Roundtrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pwd := []byte("test-password-roundtrip")
	kf, err := EncryptKeyWithParamsBytes(kp.Private, pwd, LightScryptParams())
	if err != nil {
		t.Fatalf("EncryptKeyWithParamsBytes failed: %v", err)
	}
	if kf.Version != KeyFileVersionV2 {
		t.Fatalf("expected v2, got %d", kf.Version)
	}
	decrypted, err := DecryptKeyBytes(kf, pwd)
	if err != nil {
		t.Fatalf("DecryptKeyBytes failed: %v", err)
	}
	if !kp.Private.Equal(decrypted) {
		t.Fatal("decrypted key does not match original")
	}
}

// TestCRYPTO_R12_004_V1BackwardCompat verifies that v1 key files (no AAD)
// still decrypt successfully. This is critical for backward compatibility
// with existing user key files.
func TestCRYPTO_R12_004_V1BackwardCompat(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pwd := []byte("legacy-password-v1")
	// Encrypt to get a v2 key file, then manually downgrade to v1 by
	// re-encrypting the plaintext with nil AAD. This simulates a key
	// file created by the previous (pre-R12) software version.
	kf, err := EncryptKeyWithParamsBytes(kp.Private, pwd, LightScryptParams())
	if err != nil {
		t.Fatalf("EncryptKeyWithParamsBytes failed: %v", err)
	}
	// Re-encrypt with nil AAD to simulate a v1 key file.
	// We need to manually construct the ciphertext with nil AAD.
	v1KeyFile := manualEncryptV1(t, kp.Private, pwd, kf)
	if v1KeyFile.Version != KeyFileVersion {
		t.Fatalf("expected v1, got %d", v1KeyFile.Version)
	}
	// v1 key file must still decrypt
	decrypted, err := DecryptKeyBytes(v1KeyFile, pwd)
	if err != nil {
		t.Fatalf("DecryptKeyBytes failed for v1 key file: %v", err)
	}
	if !kp.Private.Equal(decrypted) {
		t.Fatal("decrypted key does not match original for v1 key file")
	}
}

// manualEncryptV1 re-encrypts the private key using the same derived key
// (same password+salt+params) but with nil AAD, simulating a v1 key file.
func manualEncryptV1(t *testing.T, priv *PrivateKey, password []byte, template *KeyFile) *KeyFile {
	t.Helper()
	// Use the salt and params from the template (v2) key file
	params := template.Crypto.KDFParams
	derivedKey, err := scrypt.Key(password, params.Salt, params.N, params.R, params.P, params.DKLen)
	if err != nil {
		t.Fatalf("scrypt.Key failed: %v", err)
	}
	defer func() { _ = zeroBytesSecure(derivedKey) }()
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %v", err)
	}
	// Reuse the same nonce (safe because we're using a different key file instance)
	nonce := template.Crypto.CipherParams.Nonce
	plaintext := priv.Bytes()
	defer func() { _ = zeroBytesSecure(plaintext) }()
	// Encrypt with nil AAD (v1 behavior)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return &KeyFile{
		Version: KeyFileVersion,
		Address: template.Address,
		Crypto: CryptoJSON{
			Cipher:     "aes-256-gcm",
			CipherText: ciphertext,
			CipherParams: CipherParams{
				Nonce: nonce,
			},
			KDF:       "scrypt",
			KDFParams: params,
		},
	}
}

// TestCRYPTO_R12_004_TamperAddress verifies that modifying the address field
// after encryption causes decryption to fail (GCM auth tag mismatch).
func TestCRYPTO_R12_004_TamperAddress(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pwd := []byte("tamper-test-pwd")
	kf, err := EncryptKeyWithParamsBytes(kp.Private, pwd, LightScryptParams())
	if err != nil {
		t.Fatalf("EncryptKeyWithParamsBytes failed: %v", err)
	}
	// Tamper: change the address field
	original := kf.Address
	kf.Address = "QAU0000000000000000000000000000TAMPERED"
	if kf.Address == original {
		t.Fatal("failed to tamper address")
	}
	// Decryption must fail because AAD doesn't match
	_, err = DecryptKeyBytes(kf, pwd)
	if err == nil {
		t.Fatal("expected decryption to fail when address is tampered, but it succeeded")
	}
	if err != ErrInvalidPassword {
		t.Logf("got expected error: %v", err)
	}
}

// TestCRYPTO_R12_004_TamperCipherName verifies that modifying the cipher name
// field after encryption causes decryption to fail.
func TestCRYPTO_R12_004_TamperCipherName(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pwd := []byte("tamper-cipher-pwd")
	kf, err := EncryptKeyWithParamsBytes(kp.Private, pwd, LightScryptParams())
	if err != nil {
		t.Fatalf("EncryptKeyWithParamsBytes failed: %v", err)
	}
	// Tamper: change cipher name (must still pass the early cipher-name check
	// at line 445, so we set it to a valid-looking but different value).
	// Actually, the cipher name check happens BEFORE decryption, so any change
	// to a non-"aes-256-gcm" value would be rejected early. We verify that
	// early rejection here, but the deeper test is tampering with fields that
	// DON'T have an early check (like address, salt, N, R, P, DKLen).
	kf.Crypto.Cipher = "aes-128-gcm"
	_, err = DecryptKeyBytes(kf, pwd)
	if err == nil {
		t.Fatal("expected decryption to fail when cipher name is tampered")
	}
}

// TestCRYPTO_R12_004_TamperKDFName verifies that modifying the KDF name
// after encryption causes decryption to fail.
func TestCRYPTO_R12_004_TamperKDFName(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pwd := []byte("tamper-kdf-pwd")
	kf, err := EncryptKeyWithParamsBytes(kp.Private, pwd, LightScryptParams())
	if err != nil {
		t.Fatalf("EncryptKeyWithParamsBytes failed: %v", err)
	}
	kf.Crypto.KDF = "argon2"
	_, err = DecryptKeyBytes(kf, pwd)
	if err == nil {
		t.Fatal("expected decryption to fail when KDF name is tampered")
	}
}

// TestCRYPTO_R12_004_TamperSalt verifies that modifying the salt after
// encryption causes decryption to fail. Note: changing the salt also changes
// the derived key, so this would fail even without AAD. But the AAD provides
// an additional layer of integrity binding.
func TestCRYPTO_R12_004_TamperSalt(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pwd := []byte("tamper-salt-pwd")
	kf, err := EncryptKeyWithParamsBytes(kp.Private, pwd, LightScryptParams())
	if err != nil {
		t.Fatalf("EncryptKeyWithParamsBytes failed: %v", err)
	}
	// Tamper: flip a bit in the salt (keep length the same to bypass length check)
	tamperedSalt := make([]byte, len(kf.Crypto.KDFParams.Salt))
	copy(tamperedSalt, kf.Crypto.KDFParams.Salt)
	tamperedSalt[0] ^= 0xFF
	kf.Crypto.KDFParams.Salt = tamperedSalt
	_, err = DecryptKeyBytes(kf, pwd)
	if err == nil {
		t.Fatal("expected decryption to fail when salt is tampered")
	}
}

// TestCRYPTO_R12_004_TamperN verifies that modifying the scrypt N parameter
// after encryption causes decryption to fail. Note: changing N also changes
// the derived key, but the AAD provides explicit binding.
func TestCRYPTO_R12_004_TamperN(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pwd := []byte("tamper-n-pwd")
	kf, err := EncryptKeyWithParamsBytes(kp.Private, pwd, LightScryptParams())
	if err != nil {
		t.Fatalf("EncryptKeyWithParamsBytes failed: %v", err)
	}
	// Tamper: change N to a different valid value (must still pass validation)
	originalN := kf.Crypto.KDFParams.N
	if originalN == MinScryptN {
		kf.Crypto.KDFParams.N = MinScryptN * 2
	} else {
		kf.Crypto.KDFParams.N = MinScryptN
	}
	_, err = DecryptKeyBytes(kf, pwd)
	if err == nil {
		t.Fatal("expected decryption to fail when N is tampered")
	}
}

// TestCRYPTO_R12_004_TamperDKLen verifies that modifying the DKLen parameter
// after encryption causes decryption to fail.
func TestCRYPTO_R12_004_TamperDKLen(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pwd := []byte("tamper-dklen-pwd")
	kf, err := EncryptKeyWithParamsBytes(kp.Private, pwd, LightScryptParams())
	if err != nil {
		t.Fatalf("EncryptKeyWithParamsBytes failed: %v", err)
	}
	// Change DKLen to 16 (would be rejected by the DKLen==32 check, but
	// this verifies that the AAD also catches the tampering)
	kf.Crypto.KDFParams.DKLen = 16
	_, err = DecryptKeyBytes(kf, pwd)
	if err == nil {
		t.Fatal("expected decryption to fail when DKLen is tampered")
	}
}

// TestCRYPTO_R12_004_BuildAAD_Deterministic verifies that buildAAD produces
// the same output for the same input (deterministic).
func TestCRYPTO_R12_004_BuildAAD_Deterministic(t *testing.T) {
	kdfParams := KDFParams{
		Salt:  []byte("0123456789abcdef0123456789abcdef"),
		N:     32768,
		R:     8,
		P:     1,
		DKLen: 32,
	}
	aad1 := buildAAD(2, "QAU000000000000000000000000000addr", "aes-256-gcm", "scrypt", kdfParams)
	aad2 := buildAAD(2, "QAU000000000000000000000000000addr", "aes-256-gcm", "scrypt", kdfParams)
	if !bytes.Equal(aad1, aad2) {
		t.Fatal("buildAAD is not deterministic")
	}
}

// TestCRYPTO_R12_004_BuildAAD_DifferentInputs verifies that buildAAD produces
// different outputs for different inputs.
func TestCRYPTO_R12_004_BuildAAD_DifferentInputs(t *testing.T) {
	kdfParams := KDFParams{
		Salt:  []byte("0123456789abcdef0123456789abcdef"),
		N:     32768,
		R:     8,
		P:     1,
		DKLen: 32,
	}
	base := buildAAD(2, "QAUaddr1", "aes-256-gcm", "scrypt", kdfParams)

	// Different version
	diff := buildAAD(1, "QAUaddr1", "aes-256-gcm", "scrypt", kdfParams)
	if bytes.Equal(base, diff) {
		t.Fatal("AAD should differ for different version")
	}

	// Different address
	diff = buildAAD(2, "QAUaddr2", "aes-256-gcm", "scrypt", kdfParams)
	if bytes.Equal(base, diff) {
		t.Fatal("AAD should differ for different address")
	}

	// Different cipher name
	diff = buildAAD(2, "QAUaddr1", "aes-128-gcm", "scrypt", kdfParams)
	if bytes.Equal(base, diff) {
		t.Fatal("AAD should differ for different cipher name")
	}

	// Different KDF name
	diff = buildAAD(2, "QAUaddr1", "aes-256-gcm", "argon2", kdfParams)
	if bytes.Equal(base, diff) {
		t.Fatal("AAD should differ for different KDF name")
	}

	// Different N
	diffParams := kdfParams
	diffParams.N = 65536
	diff = buildAAD(2, "QAUaddr1", "aes-256-gcm", "scrypt", diffParams)
	if bytes.Equal(base, diff) {
		t.Fatal("AAD should differ for different N")
	}

	// Different R
	diffParams = kdfParams
	diffParams.R = 16
	diff = buildAAD(2, "QAUaddr1", "aes-256-gcm", "scrypt", diffParams)
	if bytes.Equal(base, diff) {
		t.Fatal("AAD should differ for different R")
	}

	// Different P
	diffParams = kdfParams
	diffParams.P = 2
	diff = buildAAD(2, "QAUaddr1", "aes-256-gcm", "scrypt", diffParams)
	if bytes.Equal(base, diff) {
		t.Fatal("AAD should differ for different P")
	}

	// Different DKLen
	diffParams = kdfParams
	diffParams.DKLen = 64
	diff = buildAAD(2, "QAUaddr1", "aes-256-gcm", "scrypt", diffParams)
	if bytes.Equal(base, diff) {
		t.Fatal("AAD should differ for different DKLen")
	}

	// Different salt
	diffParams = kdfParams
	diffParams.Salt = []byte("fedcba9876543210fedcba9876543210")
	diff = buildAAD(2, "QAUaddr1", "aes-256-gcm", "scrypt", diffParams)
	if bytes.Equal(base, diff) {
		t.Fatal("AAD should differ for different salt")
	}
}

// TestCRYPTO_R12_004_BuildAAD_LengthPrefixes verifies that length prefixes
// are correctly encoded (uint16 big-endian) for variable-length fields.
func TestCRYPTO_R12_004_BuildAAD_LengthPrefixes(t *testing.T) {
	kdfParams := KDFParams{
		Salt:  []byte("0123456789abcdef0123456789abcdef"),
		N:     32768,
		R:     8,
		P:     1,
		DKLen: 32,
	}
	addr := "QAUtestaddr"
	cipher := "aes-256-gcm"
	kdf := "scrypt"
	aad := buildAAD(2, addr, cipher, kdf, kdfParams)

	// Layout:
	// [0]      = version (1 byte)
	// [1:3]    = addr_len (2 bytes, big-endian)
	// [3:3+L]  = addr
	// ... etc
	if len(aad) < 1 {
		t.Fatal("AAD too short")
	}
	if aad[0] != 2 {
		t.Errorf("expected version 2, got %d", aad[0])
	}
	// Verify address length prefix and content
	addrLen := int(aad[1])<<8 | int(aad[2])
	if addrLen != len(addr) {
		t.Errorf("expected addr length %d, got %d", len(addr), addrLen)
	}
	addrStart := 3
	addrEnd := addrStart + addrLen
	if string(aad[addrStart:addrEnd]) != addr {
		t.Errorf("expected addr %q, got %q", addr, aad[addrStart:addrEnd])
	}
}

// TestCRYPTO_R12_004_BuildAAD_EmptyStrings verifies that buildAAD handles
// empty strings gracefully (length prefix = 0, no data bytes).
func TestCRYPTO_R12_004_BuildAAD_EmptyStrings(t *testing.T) {
	kdfParams := KDFParams{
		Salt:  nil,
		N:     32768,
		R:     8,
		P:     1,
		DKLen: 32,
	}
	// Should not panic
	aad := buildAAD(2, "", "", "", kdfParams)
	if aad == nil {
		t.Fatal("AAD should not be nil")
	}
	if len(aad) == 0 {
		t.Fatal("AAD should not be empty")
	}
	// version + 3 empty length prefixes (6 bytes) + 4*4 bytes ints + 1 empty salt prefix (2 bytes) = 1 + 6 + 16 + 2 = 25
	if len(aad) != 25 {
		t.Errorf("expected AAD length 25, got %d", len(aad))
	}
}

// TestCRYPTO_R12_004_KeyFileFromJSON_AcceptsV2 verifies that KeyFileFromJSON
// accepts both v1 and v2 key files.
func TestCRYPTO_R12_004_KeyFileFromJSON_AcceptsV2(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pwd := []byte("json-v2-test")
	kf, err := EncryptKeyWithParamsBytes(kp.Private, pwd, LightScryptParams())
	if err != nil {
		t.Fatalf("EncryptKeyWithParamsBytes failed: %v", err)
	}
	jsonData, err := kf.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	parsed, err := KeyFileFromJSON(jsonData)
	if err != nil {
		t.Fatalf("KeyFileFromJSON failed for v2 key file: %v", err)
	}
	if parsed.Version != KeyFileVersionV2 {
		t.Errorf("expected version %d, got %d", KeyFileVersionV2, parsed.Version)
	}
	// Verify round-trip still works
	decrypted, err := DecryptKeyBytes(parsed, pwd)
	if err != nil {
		t.Fatalf("DecryptKeyBytes failed: %v", err)
	}
	if !kp.Private.Equal(decrypted) {
		t.Fatal("decrypted key does not match original")
	}
}

// TestCRYPTO_R12_004_KeyFileFromJSON_RejectsV3 verifies that KeyFileFromJSON
// rejects unknown versions (e.g. v3).
func TestCRYPTO_R12_004_KeyFileFromJSON_RejectsV3(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pwd := []byte("json-v3-test")
	kf, err := EncryptKeyWithParamsBytes(kp.Private, pwd, LightScryptParams())
	if err != nil {
		t.Fatalf("EncryptKeyWithParamsBytes failed: %v", err)
	}
	// Bump to v3 (unknown)
	kf.Version = 3
	jsonData, err := kf.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	_, err = KeyFileFromJSON(jsonData)
	if err != ErrUnsupportedVersion {
		t.Errorf("expected ErrUnsupportedVersion, got %v", err)
	}
}

// TestCRYPTO_R12_004_DecryptRejectsV3 verifies that DecryptKeyBytes rejects
// unknown versions (e.g. v3) at the decryption stage.
func TestCRYPTO_R12_004_DecryptRejectsV3(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pwd := []byte("decrypt-v3-test")
	kf, err := EncryptKeyWithParamsBytes(kp.Private, pwd, LightScryptParams())
	if err != nil {
		t.Fatalf("EncryptKeyWithParamsBytes failed: %v", err)
	}
	// Bump to v3 (unknown)
	kf.Version = 3
	_, err = DecryptKeyBytes(kf, pwd)
	if err != ErrUnsupportedVersion {
		t.Errorf("expected ErrUnsupportedVersion, got %v", err)
	}
}

// TestCRYPTO_R12_004_MigrateKeyFile_ProducesV2 verifies that MigrateKeyFile
// produces a v2 key file (with AAD binding) as its output.
func TestCRYPTO_R12_004_MigrateKeyFile_ProducesV2(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pwd := []byte("migration-v2-test")
	// Create a v1 key file with weak scrypt params by manually constructing one
	v1kf := manualEncryptV1Weak(t, kp.Private, pwd)
	if v1kf.Version != KeyFileVersion {
		t.Fatalf("expected v1 input, got %d", v1kf.Version)
	}
	// Migrate to strong params
	migrated, err := MigrateKeyFile(v1kf, pwd)
	if err != nil {
		t.Fatalf("MigrateKeyFile failed: %v", err)
	}
	// Migration must produce v2
	if migrated.Version != KeyFileVersionV2 {
		t.Errorf("expected migrated version %d (v2), got %d", KeyFileVersionV2, migrated.Version)
	}
	// Verify round-trip
	decrypted, err := DecryptKeyBytes(migrated, pwd)
	if err != nil {
		t.Fatalf("DecryptKeyBytes failed for migrated key: %v", err)
	}
	if !kp.Private.Equal(decrypted) {
		t.Fatal("migrated key does not decrypt to original")
	}
}

// manualEncryptV1Weak creates a v1 key file with weak scrypt params (N=4096)
// for migration testing.
func manualEncryptV1Weak(t *testing.T, priv *PrivateKey, password []byte) *KeyFile {
	t.Helper()
	// Use very weak scrypt params (N=4096, below MinScryptN=32768)
	// to simulate a legacy key file that needs migration.
	salt := make([]byte, SaltSize)
	for i := range salt {
		salt[i] = byte(i)
	}
	const weakN = 4096
	derivedKey, err := scrypt.Key(password, salt, weakN, 8, 1, 32)
	if err != nil {
		t.Fatalf("scrypt.Key failed: %v", err)
	}
	defer func() { _ = zeroBytesSecure(derivedKey) }()
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %v", err)
	}
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	plaintext := priv.Bytes()
	defer func() { _ = zeroBytesSecure(plaintext) }()
	// v1 behavior: nil AAD
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	pubKey := priv.PublicKey()
	return &KeyFile{
		Version: KeyFileVersion,
		Address: pubKey.Address().String(),
		Crypto: CryptoJSON{
			Cipher:     "aes-256-gcm",
			CipherText: ciphertext,
			CipherParams: CipherParams{
				Nonce: nonce,
			},
			KDF: "scrypt",
			KDFParams: KDFParams{
				Salt:  salt,
				N:     weakN,
				R:     8,
				P:     1,
				DKLen: 32,
			},
		},
	}
}

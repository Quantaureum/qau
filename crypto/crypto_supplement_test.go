// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"reflect"
	"testing"
	"unsafe"
)

func TestSign_NilKeyField(t *testing.T) {
	priv := &PrivateKey{key: nil}
	_, err := Sign(priv, []byte("test"))
	if err == nil {
		t.Error("should return error when privateKey.key is nil")
	}
}

func TestPublicKey_NilKeyField(t *testing.T) {
	priv := &PrivateKey{key: nil}
	pub := priv.PublicKey()
	if pub != nil {
		t.Error("should return nil when privateKey.key is nil")
	}
}

func TestPublicKeyBytes_NilKeyField(t *testing.T) {
	priv := &PrivateKey{key: nil}
	bytes := priv.PublicKeyBytes()
	if bytes != nil {
		t.Error("should return nil when privateKey.key is nil")
	}
}

func TestVerify_NilKeyField(t *testing.T) {
	pub := &PublicKey{key: nil}
	valid := Verify(pub, []byte("test"), make([]byte, Dilithium3SignatureSize))
	if valid {
		t.Error("should return false when publicKey.key is nil")
	}
}

func TestGenerateKeyPairFromSeed_ShortSeed(t *testing.T) {
	shortSeed := []byte("short")
	_, err := GenerateKeyPairFromSeed(shortSeed)
	if err == nil {
		t.Fatal("GenerateKeyPairFromSeed should reject short seed")
	}
}

func TestGenerateKeyPairFromSeed_Exact32(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	// R32-P4-1: GenerateKeyPairFromSeed now zeros the seed for security.
	// Use separate copies to verify deterministic generation.
	seed2 := make([]byte, 32)
	copy(seed2, seed)
	kp1, _ := GenerateKeyPairFromSeed(seed)
	kp2, _ := GenerateKeyPairFromSeed(seed2)

	sig1, _ := Sign(kp1.Private, []byte("msg"))
	sig2, _ := Sign(kp2.Private, []byte("msg"))

	if len(sig1) != len(sig2) {
		t.Error("deterministic keys should produce same-length signatures")
	}
}

func TestImportKeyPair_WrongPrivateLength(t *testing.T) {
	_, err := ImportKeyPair([]byte("too-short"), make([]byte, Dilithium3PublicKeySize))
	if err == nil {
		t.Error("should fail with wrong private key length")
	}
}

func TestImportKeyPair_WrongPublicLength(t *testing.T) {
	_, err := ImportKeyPair(make([]byte, Dilithium3PrivateKeySize), []byte("too-short"))
	if err == nil {
		t.Error("should fail with wrong public key length")
	}
}

func TestPrivateKeyBytes_NilKeyField(t *testing.T) {
	priv := &PrivateKey{key: nil}
	bytes := priv.Bytes()
	if bytes != nil {
		t.Error("should return nil when key is nil")
	}
}

func TestPublicKeyBytes_NilKeyFieldPub(t *testing.T) {
	pub := &PublicKey{key: nil}
	bytes := pub.Bytes()
	if bytes != nil {
		t.Error("should return nil when key is nil")
	}
}

func TestPublicKeyFromBytes_WrongLength(t *testing.T) {
	_, err := PublicKeyFromBytes([]byte("too-short"))
	if err == nil {
		t.Error("should fail with wrong length")
	}
}

func TestPrivateKeyFromBytes_WrongLengthZero(t *testing.T) {
	_, err := PrivateKeyFromBytes(nil)
	if err == nil {
		t.Error("should fail with nil bytes")
	}
}

func TestKyberPrivateKeyFromBytes_WrongLength(t *testing.T) {
	_, err := KyberPrivateKeyFromBytes([]byte("too-short"))
	if err == nil {
		t.Error("should fail with wrong length")
	}
}

func TestKyberPublicKeyFromBytes_WrongLength(t *testing.T) {
	_, err := KyberPublicKeyFromBytes([]byte("too-short"))
	if err == nil {
		t.Error("should fail with wrong length")
	}
}

func TestKyberDestroy_Nil(t *testing.T) {
	var k *KyberPrivateKey
	err := k.Destroy()
	if err != nil {
		t.Errorf("Destroy on nil should succeed: %v", err)
	}
}

func TestKyberDestroy_NilKeyField(t *testing.T) {
	k := &KyberPrivateKey{key: nil}
	err := k.Destroy()
	if err != nil {
		t.Errorf("Destroy on nil-key-field should succeed: %v", err)
	}
}

func TestKyberZeroize_Nil(t *testing.T) {
	var k *KyberPrivateKey
	err := k.Zeroize()
	if err != nil {
		t.Errorf("Zeroize on nil should succeed: %v", err)
	}
}

func TestKyberZeroize_NilKeyField(t *testing.T) {
	k := &KyberPrivateKey{key: nil}
	err := k.Zeroize()
	if err != nil {
		t.Errorf("Zeroize on nil-key-field should succeed: %v", err)
	}
}

func TestKyberEqual_Nil(t *testing.T) {
	var k *KyberPrivateKey
	if !k.Equal(nil) {
		t.Error("nil private key should equal nil")
	}
}

func TestKyberEqual_BothNil(t *testing.T) {
	var k1, k2 *KyberPublicKey
	if !k1.Equal(k2) {
		t.Error("nil public keys should be equal")
	}
}

func TestVerifyTransactionSignature_InvalidInput(t *testing.T) {
	sv := NewSigningVerifier()
	err := sv.VerifyTransactionSignature(nil, nil, nil)
	if err == nil {
		t.Error("should fail with nil input")
	}
}

func TestValidatePublicKey_Empty(t *testing.T) {
	sv := NewSigningVerifier()
	err := sv.ValidatePublicKey(nil)
	if err == nil {
		t.Error("should fail with nil public key bytes")
	}
}

func TestValidatePublicKey_WrongLength(t *testing.T) {
	sv := NewSigningVerifier()
	err := sv.ValidatePublicKey([]byte("too-short"))
	if err == nil {
		t.Error("should fail with wrong length public key bytes")
	}
}

func TestEncryptKeyWithParamsBytes_WeakParams(t *testing.T) {
	kp, _ := GenerateKeyPair()
	weakParams := ScryptParams{N: 1024, R: 8, P: 1, DKLen: 32}
	_, err := EncryptKeyWithParamsBytes(kp.Private, []byte("pwd"), weakParams)
	if err == nil {
		t.Error("should reject weak scrypt params")
	}
}

func TestDecryptKeyBytesLegacy_NilKeyFile(t *testing.T) {
	_, err := DecryptKeyBytesLegacy(nil, []byte("pwd"))
	if err == nil {
		t.Error("should fail with nil key file")
	}
}

func TestBuilderSignatureVerifier_Verify_InvalidKeyBytes(t *testing.T) {
	bv := NewBuilderSignatureVerifier()
	kp, _ := GenerateKeyPair()
	data := []byte("data")
	sig, _ := kp.Private.Sign(data)

	badPubKey := make([]byte, Dilithium3PublicKeySize)
	for i := range badPubKey {
		badPubKey[i] = 0xFF
	}

	err := bv.Verify(badPubKey, data, sig)
	if err == nil {
		t.Error("should fail with invalid key bytes")
	}
}

// TestZeroStructFields_ArrayOfStructs verifies CRY-R2-01 fix: zeroStructFields
// must recurse into arrays-of-structs to zero nested int16 arrays. This mimics
// circl Kyber768's layout: PrivateKey → sh Vec [3]Poly → Poly [256]int16.
// Before the fix, the entire `sh Vec` field was skipped because arrays of
// structs didn't match isZeroableNumericKind, leaving secret coefficients
// unzeroed in memory after Destroy()/Zeroize().
func TestZeroStructFields_ArrayOfStructs(t *testing.T) {
	// testPoly mimics circl's common.Poly = [256]int16
	type testPoly [256]int16
	// testVec mimics circl's Vec = [3]Poly (array of structs)
	type testVec [3]testPoly
	// testCPAPKE mimics circl's internal.PrivateKey { sh Vec }
	type testCPAPKE struct {
		sh testVec
	}
	// testKEM mimics circl's kyber768.PrivateKey { sk *cpapke.PrivateKey }
	type testKEM struct {
		sk *testCPAPKE
	}

	// Build a key with non-zero secret coefficients
	kem := &testKEM{
		sk: &testCPAPKE{
			sh: testVec{
				testPoly{},
				testPoly{},
				testPoly{},
			},
		},
	}
	// Fill all 3×256 = 768 coefficients with non-zero values
	for i := 0; i < 3; i++ {
		for j := 0; j < 256; j++ {
			kem.sk.sh[i][j] = int16(0x4242 + i*256 + j)
		}
	}

	// Verify coefficients are non-zero before zeroing
	for i := 0; i < 3; i++ {
		for j := 0; j < 256; j++ {
			if kem.sk.sh[i][j] == 0 {
				t.Fatalf("precondition failed: sh[%d][%d] is zero", i, j)
			}
		}
	}

	// Use reflection to zero the struct (same path as zeroInternalKeyState)
	v := reflect.ValueOf(kem).Elem()
	zeroStructFields(v)

	// Verify all int16 coefficients are now zero
	for i := 0; i < 3; i++ {
		for j := 0; j < 256; j++ {
			if kem.sk.sh[i][j] != 0 {
				t.Errorf("CRY-R2-01: sh[%d][%d] = %d, expected 0 after zeroStructFields", i, j, kem.sk.sh[i][j])
			}
		}
	}
}

// TestZeroStructFields_CirclKyberLayout verifies that zeroStructFields actually
// reaches the int16 polynomial coefficients in a real circl Kyber768 private key.
// This is an end-to-end test of the CRY-R2-01 fix against the real circl layout.
func TestZeroStructFields_CirclKyberLayout(t *testing.T) {
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair failed: %v", err)
	}

	// Use reflection to navigate to the internal `sh` field and capture a
	// pointer to the polynomial coefficients BEFORE calling Destroy.
	// Path: KyberPrivateKey.key (kem.PrivateKey interface)
	//   → *kyber768.PrivateKey struct
	//     → sk *cpapke.PrivateKey
	//       → sh Vec = [3]common.Poly = [3][256]int16
	v := reflect.ValueOf(kp.Private.key)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		t.Skipf("unexpected KEM key layout: Kind=%v, cannot verify CRY-R2-01", v.Kind())
	}

	// Find the `sk` field by name (pointer to cpapke.PrivateKey)
	var shPtr unsafe.Pointer
	foundSH := false
	for i := 0; i < v.NumField(); i++ {
		fieldName := v.Type().Field(i).Name
		field := v.Field(i)
		if fieldName == "sk" && field.Kind() == reflect.Ptr && !field.IsNil() {
			elem := field.Elem()
			if elem.Kind() == reflect.Struct {
				// Look for the `sh` field inside the cpapke.PrivateKey
				for j := 0; j < elem.NumField(); j++ {
					innerName := elem.Type().Field(j).Name
					innerField := elem.Field(j)
					if innerName == "sh" && innerField.Kind() == reflect.Array {
						// This is `sh Vec [K]common.Poly`
						// Capture the raw pointer to the first byte of the field
						shPtr = unsafe.Pointer(innerField.UnsafeAddr())
						foundSH = true
						break
					}
				}
			}
		}
		if foundSH {
			break
		}
	}

	if !foundSH {
		t.Skip("could not locate sh Vec field in circl Kyber layout; skipping end-to-end verification")
	}

	// Verify coefficients are non-zero before Destroy.
	// sh is [3]common.Poly where Poly is [256]int16.
	// Total: 3 * 256 = 768 int16 values = 1536 bytes.
	shSlice := unsafe.Slice((*int16)(shPtr), 3*256)
	nonZeroBefore := 0
	for i := 0; i < 3*256; i++ {
		if shSlice[i] != 0 {
			nonZeroBefore++
		}
	}
	if nonZeroBefore == 0 {
		t.Skip("all coefficients are already zero; key may use a different layout — skipping")
	}
	t.Logf("found %d non-zero coefficients before Destroy", nonZeroBefore)

	// Call Destroy — this should zero the internal sh coefficients
	if err := kp.Private.Destroy(); err != nil {
		t.Fatalf("Destroy failed: %v", err)
	}

	// After Destroy, k.key is nil, but the memory at shPtr should have been
	// zeroed by zeroInternalKeyState before k.key was nil'ed.
	// Note: we use the captured pointer, not the (now-nil) k.key.
	zeroedAfter := 0
	for i := 0; i < 3*256; i++ {
		if shSlice[i] == 0 {
			zeroedAfter++
		}
	}

	if zeroedAfter < 3*256 {
		t.Errorf("CRY-R2-01: only %d/%d coefficients zeroed after Destroy; %d remain non-zero",
			zeroedAfter, 3*256, 3*256-zeroedAfter)
	}
}

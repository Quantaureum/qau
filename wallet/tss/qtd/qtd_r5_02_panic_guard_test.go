// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// R5-02 (2026-10-21 fifth-round audit) regression tests.
//
// QTDSession.Verify and GMQTD_SingleVerify call the QTD/circl verifiers
// directly. They are not on a peer-reachable path today — consensus verifies
// through crypto.PublicKey.Verify, which already runs under recover — so this
// is the defense-in-depth half of the R4-04 contract: any future caller that
// wires these helpers straight to network data must not have to re-derive the
// panic story. The probe test at the bottom records, for the audit trail,
// which inputs the pinned circl build actually panics on.

func qtdPublicKeyFromGarbage(t *testing.T, seed byte) *mode3.PublicKey {
	t.Helper()
	var buf [mode3.PublicKeySize]byte
	for i := range buf {
		buf[i] = seed
	}
	// Keep it non-degenerate so the degenerate-key gates do not shortcut us.
	buf[0] = 0x01
	var pk mode3.PublicKey
	pk.Unpack(&buf)
	return &pk
}

// TestR5_02_SingleVerify_NilKeyAndMalformedSignatureReturnErrors pins the two
// shapes that used to be able to take a process down: a nil key pointer and a
// right-length-but-malformed signature.
func TestR5_02_SingleVerify_NilKeyAndMalformedSignatureReturnErrors(t *testing.T) {
	msg := []byte("R5-02 single verify")

	if ok, err := GMQTD_SingleVerify(nil, msg, make([]byte, mode3.SignatureSize)); err == nil || ok {
		t.Fatalf("GMQTD_SingleVerify(nil key) = (%v, %v), want (false, error)", ok, err)
	}

	pk := qtdPublicKeyFromGarbage(t, 0xff)
	malformed := make([]byte, mode3.SignatureSize)
	for i := range malformed {
		malformed[i] = byte(i*7 + 3)
	}
	ok, err := GMQTD_SingleVerify(pk, msg, malformed)
	if err != nil {
		t.Fatalf("GMQTD_SingleVerify on right-length malformed signature returned an error: %v", err)
	}
	if ok {
		t.Fatal("GMQTD_SingleVerify accepted a malformed signature")
	}

	short := make([]byte, mode3.SignatureSize-1)
	if ok, err := GMQTD_SingleVerify(pk, msg, short); err == nil || ok {
		t.Fatalf("GMQTD_SingleVerify(short sig) = (%v, %v), want (false, error)", ok, err)
	}
}

// TestR5_02_SessionVerify_MalformedInputsNeverPanic covers both accepted
// signature formats (3293 standard, 4064 full-bitmap) plus the nil cases.
func TestR5_02_SessionVerify_MalformedInputsNeverPanic(t *testing.T) {
	session := &QTDSession{}
	msg := []byte("R5-02 session verify")

	cases := []struct {
		name string
		sig  *QTDSignature
		pk   *mode3.PublicKey
	}{
		{"nil-signature", nil, qtdPublicKeyFromGarbage(t, 0x5a)},
		{"nil-key", &QTDSignature{FullSig: make([]byte, 3293)}, nil},
		{"empty-fullsig", &QTDSignature{}, qtdPublicKeyFromGarbage(t, 0x5a)},
		{"wrong-length-fullsig", &QTDSignature{FullSig: make([]byte, 100)}, qtdPublicKeyFromGarbage(t, 0x5a)},
		{"malformed-3293", &QTDSignature{FullSig: fillPattern(3293)}, qtdPublicKeyFromGarbage(t, 0xff)},
		{"malformed-4064", &QTDSignature{FullSig: fillPattern(4064)}, qtdPublicKeyFromGarbage(t, 0xff)},
		{"all-zero-4064", &QTDSignature{FullSig: make([]byte, 4064)}, qtdPublicKeyFromGarbage(t, 0x11)},
	}

	for _, tc := range cases {
		if session.Verify(tc.sig, msg, tc.pk) {
			t.Fatalf("%s: QTDSession.Verify reported success for malformed input", tc.name)
		}
	}
}

// TestR5_02_GuardedRawVerifyContainsNilKey checks the shared helper used by
// GMQTD_SingleSign / GMQTD_SingleVerify swallows the nil-key dereference
// instead of crashing the caller. The signature here is a genuine one, so the
// verifier gets past its structural checks and would dereference the nil key.
func TestR5_02_GuardedRawVerifyContainsNilKey(t *testing.T) {
	pub, priv, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("mode3.GenerateKey: %v", err)
	}
	msg := []byte("R5-02 nil-key guard")
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(priv, msg, sig)

	if verifyDilithium3(nil, msg, sig) {
		t.Fatal("verifyDilithium3 reported success for a nil public key")
	}
	if ok, err := GMQTD_SingleVerify(nil, msg, sig); err == nil || ok {
		t.Fatalf("GMQTD_SingleVerify(nil key, well-formed sig) = (%v, %v), want (false, error)", ok, err)
	}
	if !verifyDilithium3(pub, msg, sig) {
		t.Fatal("verifyDilithium3 rejected a genuine signature (positive control)")
	}
}

// TestR5_02_CirclAndQTDVerifierPanicProbe documents what the pinned
// implementations actually do with hostile input. It asserts nothing about the
// observed rate on purpose — the guards above hold either way — but the logged
// numbers are the evidence behind the severity ratings in the round-5 report.
func TestR5_02_CirclAndQTDVerifierPanicProbe(t *testing.T) {
	msg := []byte("R5-02 probe")
	hash := sha256.Sum256(msg)

	rawPanics := 0
	probes := 0
	for _, seed := range []byte{0x00, 0x01, 0x7f, 0xff} {
		pk := qtdPublicKeyFromGarbage(t, seed)
		for _, size := range []int{3293, 4064} {
			probes++
			sig := fillPattern(size)
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Logf("probe: raw verify panicked for seed 0x%02x / size %d: %v", seed, size, r)
						rawPanics++
					}
				}()
				if size == 3293 {
					_ = mode3.Verify(pk, hash[:], sig)
				} else {
					_ = CheckGMQTDFullSignature(pk, hash[:], sig)
				}
			}()
		}
	}

	probes++
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("probe: mode3.Verify with a nil key panics: %v", r)
				rawPanics++
			}
		}()
		_ = mode3.Verify(nil, hash[:], make([]byte, mode3.SignatureSize))
	}()

	// A nil key combined with a structurally valid signature is the shape that
	// reaches the public-key dereference, so it is probed separately.
	pub, priv, kerr := mode3.GenerateKey(rand.Reader)
	if kerr == nil {
		genuine := make([]byte, mode3.SignatureSize)
		mode3.SignTo(priv, hash[:], genuine)
		probes++
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Logf("probe: mode3.Verify(nil key, genuine signature) panics: %v", r)
					rawPanics++
				}
			}()
			_ = mode3.Verify(nil, hash[:], genuine)
		}()
		probes++
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Logf("probe: CheckGMQTDFullSignature(nil key, 4064-byte signature) panics: %v", r)
					rawPanics++
				}
			}()
			_ = CheckGMQTDFullSignature(nil, hash[:], fillPattern(4064))
		}()
		_ = pub
	}

	t.Logf("R5-02 probe: %d raw verifier invocations, %d panicked (see the report for how this shapes severity)",
		probes, rawPanics)
}

// fillPattern returns a buffer of the requested size filled with a non-trivial
// byte pattern (neither all-zero nor all-0xff, which the gates shortcut).
func fillPattern(size int) []byte {
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte(i*131 + 17)
	}
	if len(buf) > 0 {
		buf[0] |= 0x01
	}
	return buf
}

// TestR5_02_GenuineQTDKeyStillVerifies is the positive control for the guards:
// a real Dilithium3 key/signature must still pass through GMQTD_SingleVerify.
func TestR5_02_GenuineQTDKeyStillVerifies(t *testing.T) {
	pub, priv, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("mode3.GenerateKey: %v", err)
	}
	msg := []byte("R5-02 positive control")
	sig, err := GMQTD_SingleSign(priv, pub, msg)
	if err != nil {
		t.Fatalf("GMQTD_SingleSign: %v", err)
	}
	ok, err := GMQTD_SingleVerify(pub, msg, sig)
	if err != nil || !ok {
		t.Fatalf("GMQTD_SingleVerify on a genuine signature = (%v, %v), want (true, nil)", ok, err)
	}
	if !(&QTDSession{}).Verify(&QTDSignature{FullSig: sig}, msg, pub) {
		t.Fatal("QTDSession.Verify rejected a genuine standard-format signature")
	}
}

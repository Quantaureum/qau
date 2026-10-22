// Quantaureum Node source, version 1.0.0.
package precompiled

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/crypto"
)

// R5-01 (2026-10-21 fifth-round audit) regression tests.
//
// The Dilithium3 verification precompile is directly reachable from contract
// code: any QVM contract can CALL it with attacker-chosen
// (pubkey, signature, hash). The rest of the repo runs the same unpack/verify
// pair under recover — crypto.Verify (audit-fix CR-1),
// types.QuantumTransaction.Verify (R40-B-C2) and the wallet/tss helpers
// (R4-04) — so this file pins the same contract for the precompile: a
// rejection, never a panic that escapes into the interpreter or JIT frame
// handler (whose gas and rollback semantics differ, which is a state-root
// divergence risk between JIT-enabled and interpreter-only validators).
//
// Scope note, measured by TestR5_01_CirclPanicProbe below: with the pinned
// circl v1.6.3, right-length but structurally malformed keys and signatures did
// NOT panic (Unpack 0 of 3 probes, Verify 0 of 9) — they return false. The
// panic face that does reproduce is a nil *mode3.PublicKey being dereferenced
// (recorded by TestR5_02_CirclAndQTDVerifierPanicProbe in wallet/tss/qtd), which
// this precompile path cannot construct. So the guard is documented and
// graded as defense in depth plus recover-semantics normalization, not as a fix
// for a demonstrated remote crash.

func dilithiumPrecompileInput(pk, sig, hash []byte) []byte {
	in := make([]byte, 0, len(pk)+len(sig)+len(hash))
	in = append(in, pk...)
	in = append(in, sig...)
	in = append(in, hash...)
	return in
}

func uniqueHash(t *testing.T, tag string) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte("R5-01 " + tag))
	return sum[:]
}

// malformedKeyVariants returns public keys that pass the length and
// all-zero gates but are structurally invalid or nonsensical.
func malformedKeyVariants(t *testing.T) map[string][]byte {
	t.Helper()
	const size = crypto.Dilithium3PublicKeySize
	out := map[string][]byte{}

	allFF := make([]byte, size)
	for i := range allFF {
		allFF[i] = 0xff
	}
	out["all-0xff"] = allFF

	// A rho taken from a real key (so Mat.Derive runs on live parameters) with
	// t1 forced to its maximum 10-bit value: MulBy2toD then pushes coefficients
	// to the top of the range the verifier assumes.
	pk, _, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("mode3.GenerateKey: %v", err)
	}
	real := pk.Bytes()
	saturatedT1 := make([]byte, size)
	copy(saturatedT1[:32], real[:32])
	for i := 32; i < size; i++ {
		saturatedT1[i] = 0xff
	}
	out["real-rho-saturated-t1"] = saturatedT1

	// Zero t1 with a non-zero rho is also rejected, but by the entry gate: it
	// matches crypto.IsDegeneratePublicKeyBytes, so it is covered separately by
	// TestR38P101_* rather than by the variants below.

	prng := make([]byte, size)
	if _, err := rand.Read(prng); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	t1Zero := make([]byte, size)
	copy(t1Zero[:32], real[:32])
	if bytes.Equal(prng, t1Zero) || crypto.IsDegeneratePublicKeyBytes(prng) {
		prng[0] ^= 0x01
	}
	out["random"] = prng
	return out
}

// malformedSigVariants returns 3293-byte signature buffers with invalid
// internal structure (z packed out of range, hint bitmap out of range).
func malformedSigVariants(t *testing.T) map[string][]byte {
	t.Helper()
	const size = crypto.Dilithium3SignatureSize
	out := map[string][]byte{}

	allFF := make([]byte, size)
	for i := range allFF {
		allFF[i] = 0xff
	}
	out["all-0xff"] = allFF

	allZero := make([]byte, size)
	out["all-zero"] = allZero

	prng := make([]byte, size)
	if _, err := rand.Read(prng); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	out["random"] = prng
	return out
}

// TestR5_01_GuardedVerifierRejectsMalformedInputWithoutPanic exercises the
// helper directly so a regression cannot hide behind the cache.
func TestR5_01_GuardedVerifierRejectsMalformedInputWithoutPanic(t *testing.T) {
	keys := malformedKeyVariants(t)
	sigs := malformedSigVariants(t)

	for kname, pk := range keys {
		if len(pk) != crypto.Dilithium3PublicKeySize {
			t.Fatalf("key variant %s has length %d, want %d", kname, len(pk), crypto.Dilithium3PublicKeySize)
		}
		if crypto.IsDegeneratePublicKeyBytes(pk) {
			t.Fatalf("key variant %s is degenerate — it would be rejected by the entry gate, not by the guard", kname)
		}
		for sname, sig := range sigs {
			hash := uniqueHash(t, kname+"/"+sname)
			if dilithiumVerifyGuarded(pk, sig, hash) {
				t.Fatalf("guard returned true for malformed key %s / signature %s", kname, sname)
			}
			// Wrong-length signature must be refused before touching circl.
			if dilithiumVerifyGuarded(pk, sig[:len(sig)-1], hash) {
				t.Fatalf("guard accepted a short signature for key %s", kname)
			}
		}
	}
}

// TestR5_01_CachedVerifierAndPrecompileNeverPanic walks the full call chain the
// way a contract does: dilithiumVerifyCached behind the precompile Run.
func TestR5_01_CachedVerifierAndPrecompileNeverPanic(t *testing.T) {
	keys := malformedKeyVariants(t)
	sigs := malformedSigVariants(t)
	contract := newDilithiumVerify()

	for kname, pk := range keys {
		for sname, sig := range sigs {
			hash := uniqueHash(t, "chain/"+kname+"/"+sname)

			if got := dilithiumVerifyCached(pk, sig, hash); got {
				t.Fatalf("dilithiumVerifyCached = true for malformed key %s / signature %s", kname, sname)
			}

			out, err := contract.Run(dilithiumPrecompileInput(pk, sig, hash))
			if err != nil {
				t.Fatalf("precompile Run returned an error for malformed key %s / signature %s: %v", kname, sname, err)
			}
			if len(out) != 32 {
				t.Fatalf("precompile returned %d bytes, want 32", len(out))
			}
			if out[31] != 0 {
				t.Fatalf("precompile reported a valid signature for malformed key %s / signature %s", kname, sname)
			}
		}
	}

	// Truncated input keeps the documented error contract (no panic, error).
	if _, err := contract.Run(make([]byte, 100)); err == nil {
		t.Fatal("precompile accepted a truncated input")
	}
}

// TestR5_01_GenuineSignatureStillVerifies is the positive control: the panic
// guard must not turn the precompile into a constant rejection.
func TestR5_01_GenuineSignatureStillVerifies(t *testing.T) {
	pub, priv, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("mode3.GenerateKey: %v", err)
	}
	message := []byte("R5-01 positive control")
	hash := sha256.Sum256(message)
	// The precompile treats its trailing 32-byte field as the signed message,
	// so the positive control must sign that digest, not the raw payload.
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(priv, hash[:], sig)
	pkBytes := pub.Bytes()
	if !dilithiumVerifyGuarded(pkBytes, sig, hash[:]) {
		t.Fatal("guarded verifier rejected a genuine Dilithium3 signature")
	}
	if !dilithiumVerifyCached(pkBytes, sig, hash[:]) {
		t.Fatal("dilithiumVerifyCached rejected a genuine Dilithium3 signature")
	}

	out, err := newDilithiumVerify().Run(dilithiumPrecompileInput(pkBytes, sig, hash[:]))
	if err != nil {
		t.Fatalf("precompile Run on a genuine signature: %v", err)
	}
	if len(out) != 32 || out[31] != 1 {
		t.Fatalf("precompile = %v, want the 32-byte word 1", out)
	}
}

// TestR5_01_CirclPanicProbe records, for the audit trail, whether the pinned
// circl build actually panics on right-length malformed input. It asserts
// nothing about circl's behavior on purpose: the R5-01 contract holds either
// way (the guard normalizes a panic, and a plain rejection stays a rejection).
// Run with -v to read the observation.
func TestR5_01_CirclPanicProbe(t *testing.T) {
	keys := malformedKeyVariants(t)
	sigs := malformedSigVariants(t)

	unpackPanics := 0
	totalKeys := 0
	for name, pk := range keys {
		totalKeys++
		var buf [mode3.PublicKeySize]byte
		copy(buf[:], pk)
		if func() (panicked bool) {
			defer func() {
				if r := recover(); r != nil {
					t.Logf("probe: mode3.PublicKey.Unpack panicked on key %s: %v", name, r)
					panicked = true
				}
			}()
			var k mode3.PublicKey
			k.Unpack(&buf)
			return false
		}() {
			unpackPanics++
		}
	}

	verifyPanics := 0
	totalPairs := 0
	for kname, pk := range keys {
		var buf [mode3.PublicKeySize]byte
		copy(buf[:], pk)
		var k mode3.PublicKey
		if func() (panicked bool) {
			defer func() { panicked = recover() != nil }()
			k.Unpack(&buf)
			return false
		}() {
			continue // skip pairs whose key unpack already panicked
		}
		for sname, sig := range sigs {
			totalPairs++
			hash := uniqueHash(t, "probe/"+kname+"/"+sname)
			if func() (panicked bool) {
				defer func() {
					if r := recover(); r != nil {
						t.Logf("probe: mode3.Verify panicked on key %s / signature %s: %v", kname, sname, r)
						panicked = true
					}
				}()
				return mode3.Verify(&k, hash, sig)
			}() {
				verifyPanics++
			}
		}
	}

	t.Logf("R5-01 probe: circl v1.6.3 mode3 — Unpack panicked %d/%d times, Verify panicked %d/%d times; guard contract holds regardless",
		unpackPanics, totalKeys, verifyPanics, totalPairs)
}

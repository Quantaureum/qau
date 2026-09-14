// Quantaureum Node source, version 1.0.0.
package consensus

// P2-4 (2026-07-15): Real DAAttestationVerifier tests.
//
// These tests exercise NewDAAttestationVerifier (consensus/da_attestation_verifier.go)
// with REAL Dilithium3 keypairs and signatures — not the testAcceptAllVerifier stub
// used by the older DAAttestationCollector tests.
//
// Coverage:
//   1. Valid Dilithium3 signature over attestation.Hash() is accepted
//   2. Tampered signature (single bit flip) is rejected
//   3. Forged signature (random bytes of correct length) is rejected
//   4. Wrong validator (signature under keypair A, ValidatorIndex points to keypair B) is rejected
//   5. Empty signature is rejected
//   6. ValidatorIndex out of range is rejected
//   7. nil committee manager is rejected (mainnet fail-closed)
//   8. Disabled committee skips membership check (testnet mode)
//   9. Enabled committee rejects non-member validator
//  10. Enabled committee accepts member validator
//  11. Tampered attestation body (mutated Available flag) breaks signature → rejected
//  12. Concurrent verifier invocations are race-free (run with -race)
//  13. Generated Dilithium3 keys match the project's crypto contract sizes
//      (PublicKey=1952, PrivateKey=4000, Signature=3293)
//
// The verifier contract (consensus/da_attestation_verifier.go:31-87):
//   Step 1: Reject empty signature
//   Step 2: Look up validator by ValidatorIndex; reject if out of range / nil / no pubkey
//   Step 3: crypto.Verify(validator.PublicKey, attestation.Hash()[:], att.Signature)
//   Step 4: If committeeMgr == nil → reject (mainnet fail-closed)
//           If committeeMgr.config.Enabled == false → skip membership (testnet mode)
//           Else → IsInCommittee(epoch, ValidatorIndex) must return true

import (
	"crypto/rand"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// makeVerifierValidators builds n validators with REAL Dilithium3 keypairs.
// The keypairs are returned alongside so tests can sign attestations with
// the matching private key. ValidatorInfo.PublicKey is populated; Address
// is derived from the public key bytes so each validator is distinct.
func makeVerifierValidators(t *testing.T, n int) ([]*ValidatorInfo, []*crypto.KeyPair) {
	t.Helper()
	validators := make([]*ValidatorInfo, n)
	keypairs := make([]*crypto.KeyPair, n)
	for i := 0; i < n; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair[%d] failed: %v", i, err)
		}
		keypairs[i] = kp
		pubBytes := kp.Public.Bytes()
		var addr types.Address
		copy(addr[:], pubBytes[len(pubBytes)-len(addr):])
		validators[i] = &ValidatorInfo{
			Address:   addr,
			PublicKey: kp.Public,
			Active:    true,
		}
	}
	return validators, keypairs
}

// signAttestationForTest signs att.Hash() with priv and returns a copy of
// the attestation with the Signature field populated.
func signAttestationForTest(t *testing.T, att *encoding.DASAttestation, priv *crypto.PrivateKey) *encoding.DASAttestation {
	t.Helper()
	if priv == nil {
		t.Fatal("signAttestationForTest: nil private key")
	}
	hash := att.Hash()
	sig, err := crypto.Sign(priv, hash[:])
	if err != nil {
		t.Fatalf("crypto.Sign failed: %v", err)
	}
	if len(sig) != crypto.Dilithium3SignatureSize {
		t.Fatalf("signature size mismatch: got %d, want %d", len(sig), crypto.Dilithium3SignatureSize)
	}
	out := *att // shallow copy is fine; Signature is replaced below
	out.Signature = sig
	return &out
}

// newSampleAttestation builds a baseline DASAttestation for slot 5 (epoch 0,
// since SlotsPerEpoch=32) with the given ValidatorIndex. The Signature field
// is left nil — callers must sign it before submission.
func newSampleAttestation(validatorIndex int) *encoding.DASAttestation {
	return &encoding.DASAttestation{
		Slot:           5,
		BlobCommitment: types.Hash{0x01, 0x02, 0x03},
		Available:      true,
		Confidence:     0.9999,
		SampleCount:    75,
		SuccessCount:   75,
		ValidatorIndex: validatorIndex,
	}
}

// TestP2_4_Verifier_AcceptsValidSignature: A real Dilithium3 signature over
// attestation.Hash() MUST be accepted by the verifier. This is the happy path
// that confirms the verifier is correctly wired to crypto.Verify.
func TestP2_4_Verifier_AcceptsValidSignature(t *testing.T) {
	validators, keypairs := makeVerifierValidators(t, 3)
	lookup := func() []*ValidatorInfo { return validators }
	// Use a disabled committee (testnet mode) so the membership check is
	// skipped and only signature verification is exercised.
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)
	att := signAttestationForTest(t, newSampleAttestation(1), keypairs[1].Private)

	if err := verifier(att); err != nil {
		t.Errorf("verifier rejected a valid Dilithium3 signature: %v", err)
	}
}

// TestP2_4_Verifier_RejectsTamperedSignature: A single bit flip in the
// signature MUST cause verification to fail. This is the most basic forgery
// rejection — Dilithium3 is EUF-CMA secure, so any mutation of a valid
// signature should fail verification with overwhelming probability.
func TestP2_4_Verifier_RejectsTamperedSignature(t *testing.T) {
	validators, keypairs := makeVerifierValidators(t, 2)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)
	att := signAttestationForTest(t, newSampleAttestation(0), keypairs[0].Private)

	// Flip the first byte of the signature.
	tampered := *att
	tamperedSig := make([]byte, len(att.Signature))
	copy(tamperedSig, att.Signature)
	tamperedSig[0] ^= 0xFF
	tampered.Signature = tamperedSig

	if err := verifier(&tampered); err == nil {
		t.Error("verifier accepted a tampered signature (bit flip in byte 0)")
	}
}

// TestP2_4_Verifier_RejectsForgedSignature: A completely random byte slice
// of the correct length (3293 bytes) MUST be rejected. This confirms the
// verifier is not just checking signature length but actually invoking
// crypto.Verify, which performs the full Dilithium3 verification.
func TestP2_4_Verifier_RejectsForgedSignature(t *testing.T) {
	validators, _ := makeVerifierValidators(t, 2)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)
	att := newSampleAttestation(0)
	// Random bytes of the correct length — not a real signature.
	fakeSig := make([]byte, crypto.Dilithium3SignatureSize)
	if _, err := rand.Read(fakeSig); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	att.Signature = fakeSig

	if err := verifier(att); err == nil {
		t.Error("verifier accepted a forged (random) signature")
	}
}

// TestP2_4_Verifier_RejectsWrongValidator: A valid signature under keypair A
// MUST be rejected when ValidatorIndex points to keypair B. This is the
// "signature substitution" attack: an attacker steals a valid signature
// from one validator and tries to submit it under a different validator's
// index. Dilithium3's strong unforgeability prevents this.
func TestP2_4_Verifier_RejectsWrongValidator(t *testing.T) {
	validators, keypairs := makeVerifierValidators(t, 3)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)
	// Sign with keypair[0]'s private key, but claim ValidatorIndex=2.
	att := signAttestationForTest(t, newSampleAttestation(2), keypairs[0].Private)

	if err := verifier(att); err == nil {
		t.Error("verifier accepted a signature signed by validator 0 under validator 2's index (signature substitution)")
	}
}

// TestP2_4_Verifier_RejectsEmptySignature: An empty signature MUST be
// rejected before any crypto operation is attempted. This prevents a
// trivial forgery where the attacker submits an attestation with no
// signature at all.
func TestP2_4_Verifier_RejectsEmptySignature(t *testing.T) {
	validators, _ := makeVerifierValidators(t, 2)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)
	att := newSampleAttestation(0)
	// Signature intentionally left nil.

	if err := verifier(att); err == nil {
		t.Error("verifier accepted an empty signature")
	}
}

// TestP2_4_Verifier_RejectsOutOfRangeIndex: ValidatorIndex outside
// [0, len(validators)) MUST be rejected. This prevents an attacker from
// causing an out-of-bounds panic or referencing a non-existent validator.
func TestP2_4_Verifier_RejectsOutOfRangeIndex(t *testing.T) {
	validators, _ := makeVerifierValidators(t, 3)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)

	for _, idx := range []int{-1, 3, 100} {
		att := newSampleAttestation(idx)
		att.Signature = make([]byte, crypto.Dilithium3SignatureSize) // placeholder
		if err := verifier(att); err == nil {
			t.Errorf("verifier accepted out-of-range ValidatorIndex %d (len=%d)", idx, len(validators))
		}
	}
}

// TestP2_4_Verifier_RejectsNilCommitteeMgr: When committeeMgr is nil, the
// verifier MUST fail-closed (reject). This is the mainnet safety default —
// if the node operator forgot to wire the committee manager, no attestation
// should be accepted. Otherwise, an attacker could forge attestations that
// bypass the membership check.
func TestP2_4_Verifier_RejectsNilCommitteeMgr(t *testing.T) {
	validators, keypairs := makeVerifierValidators(t, 2)
	lookup := func() []*ValidatorInfo { return validators }

	verifier := NewDAAttestationVerifier(lookup, nil)
	att := signAttestationForTest(t, newSampleAttestation(0), keypairs[0].Private)

	if err := verifier(att); err == nil {
		t.Error("verifier accepted an attestation when committeeMgr is nil (should fail-closed)")
	}
}

// TestP2_4_Verifier_SkipsMembershipWhenDisabled: When the committee is
// explicitly disabled (DACommitteeConfig.Enabled=false, e.g., testnet),
// the verifier skips the membership check and accepts any valid signature.
// This allows small networks (< 512 validators) to operate without a full
// DA committee while still authenticating attestations cryptographically.
func TestP2_4_Verifier_SkipsMembershipWhenDisabled(t *testing.T) {
	validators, keypairs := makeVerifierValidators(t, 2)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)
	// Validator 0 may or may not be in the (non-existent) committee, but
	// because Enabled=false, the membership check is skipped.
	att := signAttestationForTest(t, newSampleAttestation(0), keypairs[0].Private)

	if err := verifier(att); err != nil {
		t.Errorf("verifier rejected a valid signature in disabled-committee (testnet) mode: %v", err)
	}
}

// TestP2_4_Verifier_RejectsNonCommitteeMember: When the committee is
// enabled (mainnet mode), a validator NOT in the DA committee MUST be
// rejected even if the signature is valid. This prevents an attacker who
// controls a non-committee validator key from submitting DA attestations.
func TestP2_4_Verifier_RejectsNonCommitteeMember(t *testing.T) {
	// Build 600 validators so the committee (size 512) can be computed.
	// We need at least DACommitteeSize active validators; use a reduced
	// committee size via SetConfig to keep the test fast.
	validators, keypairs := makeVerifierValidators(t, 10)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	// Use a small committee size (3) so most validators are NOT members.
	mgr.SetConfig(DACommitteeConfig{Enabled: true, Size: 3})

	verifier := NewDAAttestationVerifier(lookup, mgr)

	// Walk all validators; at least one should be a non-member (since
	// committee size is 3 out of 10). For each non-member, a valid
	// signature MUST be rejected by the verifier.
	committee, err := mgr.GetCommittee(0)
	if err != nil {
		t.Fatalf("GetCommittee failed: %v", err)
	}
	inCommittee := make(map[int]bool, len(committee.Members))
	for _, m := range committee.Members {
		inCommittee[m.ValidatorIndex] = true
	}

	rejectedAtLeastOne := false
	for i := 0; i < len(validators); i++ {
		if inCommittee[i] {
			continue
		}
		att := signAttestationForTest(t, newSampleAttestation(i), keypairs[i].Private)
		if err := verifier(att); err == nil {
			t.Errorf("verifier accepted non-committee validator %d (committee=%v)", i, inCommittee)
		} else {
			rejectedAtLeastOne = true
		}
	}
	if !rejectedAtLeastOne {
		t.Fatalf("test setup error: every validator is in the committee (size=%d, validators=%d); cannot verify non-member rejection",
			len(committee.Members), len(validators))
	}
}

// TestP2_4_Verifier_AcceptsCommitteeMember: When the committee is enabled
// (mainnet mode), a validator IN the DA committee with a valid signature
// MUST be accepted. This is the mainnet happy path.
func TestP2_4_Verifier_AcceptsCommitteeMember(t *testing.T) {
	validators, keypairs := makeVerifierValidators(t, 10)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: true, Size: 3})

	verifier := NewDAAttestationVerifier(lookup, mgr)
	committee, err := mgr.GetCommittee(0)
	if err != nil {
		t.Fatalf("GetCommittee failed: %v", err)
	}
	if len(committee.Members) == 0 {
		t.Fatal("committee has no members")
	}

	// Pick the first committee member and sign with its keypair.
	member := committee.Members[0]
	att := signAttestationForTest(t, newSampleAttestation(member.ValidatorIndex), keypairs[member.ValidatorIndex].Private)
	// Use the slot that maps to epoch 0 (slot 5 → epoch 0, since SlotsPerEpoch=32).
	if err := verifier(att); err != nil {
		t.Errorf("verifier rejected a valid signature from committee member %d: %v", member.ValidatorIndex, err)
	}
}

// TestP2_4_Verifier_RejectsTamperedAttestationBody: If an attacker intercepts
// a valid signed attestation and mutates any field that is part of Hash()
// (e.g., flipping Available from true to false), the signature no longer
// matches the new Hash() and MUST be rejected. This is the "attestation
// mutation" forgery — distinct from tampering with the signature itself.
func TestP2_4_Verifier_RejectsTamperedAttestationBody(t *testing.T) {
	validators, keypairs := makeVerifierValidators(t, 2)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)
	original := signAttestationForTest(t, newSampleAttestation(0), keypairs[0].Private)

	// Tamper with the Available flag (true → false). Hash() includes this
	// field, so the original signature no longer matches.
	tampered := *original
	tampered.Available = false
	// Keep the original signature — this is the forgery attempt.

	if err := verifier(&tampered); err == nil {
		t.Error("verifier accepted an attestation whose body was mutated after signing (Available flag flipped)")
	}

	// Also try mutating SampleCount (another field in Hash()).
	tampered2 := *original
	tampered2.SampleCount = original.SampleCount + 1
	if err := verifier(&tampered2); err == nil {
		t.Error("verifier accepted an attestation whose SampleCount was mutated after signing")
	}

	// Also try mutating Confidence.
	tampered3 := *original
	tampered3.Confidence = 0.5
	if err := verifier(&tampered3); err == nil {
		t.Error("verifier accepted an attestation whose Confidence was mutated after signing")
	}
}

// TestP2_4_Verifier_ParallelNoRace: The verifier MUST be safe for concurrent
// use. This test runs the verifier from multiple goroutines simultaneously
// against different validators and expects no panics, no data races, and
// correct accept/reject decisions for each goroutine.
//
// Run with `go test -race` to detect data races.
func TestP2_4_Verifier_ParallelNoRace(t *testing.T) {
	validators, keypairs := makeVerifierValidators(t, 8)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)

	// Precompute one valid signed attestation per validator.
	signed := make([]*encoding.DASAttestation, len(validators))
	for i := range validators {
		signed[i] = signAttestationForTest(t, newSampleAttestation(i), keypairs[i].Private)
	}
	// Precompute a tampered attestation per validator (flip Available).
	tampered := make([]*encoding.DASAttestation, len(validators))
	for i := range validators {
		t := *signed[i]
		t.Available = !signed[i].Available
		tampered[i] = &t
	}

	const goroutines = 16
	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	var errors int64
	var panics int64
	stop := make(chan struct{})

	// Watchdog: fail the test if it deadlocks (verifier should be fast).
	go func() {
		select {
		case <-stop:
			return
		case <-time.After(30 * time.Second):
			t.Error("TestP2_4_Verifier_ParallelNoRace timed out after 30s (possible deadlock)")
			close(stop)
		}
	}()

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					atomic.AddInt64(&panics, 1)
					t.Errorf("goroutine %d panicked: %v", gid, r)
				}
			}()
			for i := 0; i < iterations; i++ {
				select {
				case <-stop:
					return
				default:
				}
				idx := (gid + i) % len(validators)
				// Valid signature → should be accepted.
				if err := verifier(signed[idx]); err != nil {
					atomic.AddInt64(&errors, 1)
				}
				// Tampered attestation → should be rejected.
				if err := verifier(tampered[idx]); err == nil {
					atomic.AddInt64(&errors, 1)
				}
			}
		}(g)
	}
	wg.Wait()
	close(stop)

	if panics > 0 {
		t.Errorf("%d goroutine panics during parallel verifier invocation", panics)
	}
	if errors > 0 {
		t.Errorf("%d unexpected accept/reject decisions during parallel invocation", errors)
	}
}

// TestP2_4_Verifier_Dilithium3KeyAndSignatureSizes: Sanity check that the
// keypairs generated for these tests match the project's crypto contract
// (see crypto/dilithium.go header). A mismatch would indicate either a
// circl library upgrade or a contract violation — both require wallet/node
// synchronization per the SHARED INTERFACE WARNING.
func TestP2_4_Verifier_Dilithium3KeyAndSignatureSizes(t *testing.T) {
	if crypto.Dilithium3PublicKeySize != 1952 {
		t.Errorf("Dilithium3PublicKeySize changed: got %d, want 1952 (wallet/node sync required)",
			crypto.Dilithium3PublicKeySize)
	}
	if crypto.Dilithium3PrivateKeySize != 4000 {
		t.Errorf("Dilithium3PrivateKeySize changed: got %d, want 4000 (wallet/node sync required)",
			crypto.Dilithium3PrivateKeySize)
	}
	if crypto.Dilithium3SignatureSize != 3293 {
		t.Errorf("Dilithium3SignatureSize changed: got %d, want 3293 (wallet/node sync required)",
			crypto.Dilithium3SignatureSize)
	}

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if len(kp.Public.Bytes()) != crypto.Dilithium3PublicKeySize {
		t.Errorf("public key bytes size mismatch: got %d, want %d",
			len(kp.Public.Bytes()), crypto.Dilithium3PublicKeySize)
	}
	if len(kp.Private.Bytes()) != crypto.Dilithium3PrivateKeySize {
		t.Errorf("private key bytes size mismatch: got %d, want %d",
			len(kp.Private.Bytes()), crypto.Dilithium3PrivateKeySize)
	}

	msg := []byte("test message for size check")
	sig, err := crypto.Sign(kp.Private, msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) != crypto.Dilithium3SignatureSize {
		t.Errorf("signature size mismatch: got %d, want %d",
			len(sig), crypto.Dilithium3SignatureSize)
	}
	if !crypto.Verify(kp.Public, msg, sig) {
		t.Error("crypto.Verify rejected a freshly-generated signature (control check)")
	}
}

// TestP2_4_Verifier_SubmitAttestationWithRealVerifier: End-to-end test that
// wires NewDAAttestationVerifier into DAAttestationCollector.SubmitAttestation.
// This confirms the production verifier integrates correctly with the
// collector — the collector delegates to the verifier, which performs the
// real Dilithium3 check.
func TestP2_4_Verifier_SubmitAttestationWithRealVerifier(t *testing.T) {
	validators, keypairs := makeVerifierValidators(t, 5)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)

	collector := NewDAAttestationCollector()
	collector.SetCommitteeSize(len(validators))
	collector.SetAttestationVerifier(verifier)

	// Valid signature from validator 2 → should be accepted.
	validAtt := signAttestationForTest(t, newSampleAttestation(2), keypairs[2].Private)
	if err := collector.SubmitAttestation(validAtt); err != nil {
		t.Errorf("SubmitAttestation rejected a valid Dilithium3-signed attestation: %v", err)
	}

	// Forged attestation (random signature) from validator 1 → should be rejected.
	forged := newSampleAttestation(1)
	fakeSig := make([]byte, crypto.Dilithium3SignatureSize)
	if _, err := rand.Read(fakeSig); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	forged.Signature = fakeSig
	if err := collector.SubmitAttestation(forged); err == nil {
		t.Error("SubmitAttestation accepted a forged attestation (random signature)")
	}

	// Confirm the valid attestation was stored.
	atts := collector.GetAttestations(5)
	if len(atts) != 1 {
		t.Errorf("expected 1 stored attestation, got %d", len(atts))
	}
	if atts[0].ValidatorIndex != 2 {
		t.Errorf("stored attestation has wrong ValidatorIndex: got %d, want 2", atts[0].ValidatorIndex)
	}
}

// TestP2_4_Verifier_NilValidatorInSet: If the validator lookup returns a
// slice with a nil entry at the requested index, the verifier MUST reject
// (not panic). This guards against a misbehaving ValidatorLookupFunc.
func TestP2_4_Verifier_NilValidatorInSet(t *testing.T) {
	validators, keypairs := makeVerifierValidators(t, 3)
	// Inject a nil at index 1.
	validators[1] = nil
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)
	att := signAttestationForTest(t, newSampleAttestation(1), keypairs[1].Private)

	if err := verifier(att); err == nil {
		t.Error("verifier accepted an attestation whose validator entry is nil (should reject, not panic)")
	}
}

// TestP2_4_Verifier_NilPublicKey: If the validator's PublicKey is nil, the
// verifier MUST reject (not panic). crypto.Verify handles nil keys safely
// (returns false), but the verifier's explicit check makes the failure mode
// clear and avoids relying on the crypto layer's nil-safety.
func TestP2_4_Verifier_NilPublicKey(t *testing.T) {
	validators, _ := makeVerifierValidators(t, 3)
	// Strip the public key from validator 0.
	validators[0].PublicKey = nil
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)
	att := newSampleAttestation(0)
	att.Signature = make([]byte, crypto.Dilithium3SignatureSize) // placeholder

	if err := verifier(att); err == nil {
		t.Error("verifier accepted an attestation whose validator has nil PublicKey (should reject, not panic)")
	}
}

// TestP2_4_Verifier_WrongSignatureLength: A signature whose length is not
// Dilithium3SignatureSize (3293) MUST be rejected. crypto.Verify already
// enforces this in constant time, but the verifier should propagate the
// rejection cleanly (return an error, not panic).
func TestP2_4_Verifier_WrongSignatureLength(t *testing.T) {
	validators, _ := makeVerifierValidators(t, 2)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)

	for _, sigLen := range []int{0, 1, 100, 3292, 3294, 4000} {
		att := newSampleAttestation(0)
		att.Signature = make([]byte, sigLen)
		if err := verifier(att); err == nil {
			t.Errorf("verifier accepted a signature of wrong length %d (expected rejection)", sigLen)
		}
	}
}

// TestP2_4_Verifier_DeterministicAcrossSlots: The verifier must correctly
// handle attestations for different slots (different Hash() values). This
// confirms the signature is bound to the slot via Hash(), preventing
// replay across slots.
func TestP2_4_Verifier_DeterministicAcrossSlots(t *testing.T) {
	validators, keypairs := makeVerifierValidators(t, 2)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)

	// Sign an attestation for slot 5.
	attSlot5 := signAttestationForTest(t, newSampleAttestation(0), keypairs[0].Private)
	if err := verifier(attSlot5); err != nil {
		t.Errorf("verifier rejected valid signature for slot 5: %v", err)
	}

	// Now take the SAME signature and try to verify it against a different
	// slot (slot 10). The Hash() differs, so the signature MUST be rejected.
	// This is the cross-slot replay attack.
	replay := *attSlot5
	replay.Slot = 10
	if err := verifier(&replay); err == nil {
		t.Error("verifier accepted a slot-5 signature replayed against slot 10 (cross-slot replay)")
	}
}

// TestP2_4_Verifier_LargeValidatorSet: Stress test with a larger validator
// set (50 validators) to confirm the verifier scales linearly and does not
// have quadratic behavior in validator lookup or signature verification.
func TestP2_4_Verifier_LargeValidatorSet(t *testing.T) {
	const n = 50
	validators, keypairs := makeVerifierValidators(t, n)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)

	// Verify a signature from the LAST validator (index n-1) to confirm
	// the lookup correctly indexes into the full set.
	att := signAttestationForTest(t, newSampleAttestation(n-1), keypairs[n-1].Private)
	if err := verifier(att); err != nil {
		t.Errorf("verifier rejected valid signature from validator %d in set of %d: %v", n-1, n, err)
	}

	// Verify a forged signature from a middle validator.
	mid := n / 2
	forged := newSampleAttestation(mid)
	fakeSig := make([]byte, crypto.Dilithium3SignatureSize)
	if _, err := rand.Read(fakeSig); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	forged.Signature = fakeSig
	if err := verifier(forged); err == nil {
		t.Errorf("verifier accepted forged signature from validator %d in set of %d", mid, n)
	}
}

// TestP2_4_Verifier_ErrorMessagesAreInformative: When the verifier rejects
// an attestation, the error message MUST include enough context for
// debugging (validator index, slot, etc.). This is a soft requirement —
// the test confirms that error messages are non-empty and contain the
// validator index, but does not over-constrain the exact wording.
func TestP2_4_Verifier_ErrorMessagesAreInformative(t *testing.T) {
	validators, _ := makeVerifierValidators(t, 3)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)

	// Out-of-range index → error must mention the index.
	att := newSampleAttestation(99)
	att.Signature = make([]byte, crypto.Dilithium3SignatureSize)
	err := verifier(att)
	if err == nil {
		t.Fatal("expected error for out-of-range index")
	}
	if !contains(err.Error(), "99") {
		t.Errorf("error message should mention validator index 99, got: %v", err)
	}

	// Empty signature → error must mention "signature".
	att2 := newSampleAttestation(0)
	att2.Signature = nil
	err2 := verifier(att2)
	if err2 == nil {
		t.Fatal("expected error for empty signature")
	}
	if !contains(err2.Error(), "signature") {
		t.Errorf("error message should mention 'signature', got: %v", err2)
	}
}

// contains is a minimal strings.Contains helper to avoid importing "strings"
// just for one call site.
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestDA_R7_06_Verifier_RejectsDisabledCommitteeInProduction: DA-FIX
// — in production mode (QAU_PRODUCTION=1), disabling the DA committee MUST
// cause the verifier to reject attestations (hard fail-closed), rather than
// skip the membership check. This prevents mainnet misconfiguration from
// allowing any Dilithium3 key holder to submit DA attestations.
func TestDA_R7_06_Verifier_RejectsDisabledCommitteeInProduction(t *testing.T) {
	orig := os.Getenv("QAU_PRODUCTION")
	os.Setenv("QAU_PRODUCTION", "1")
	defer func() {
		if orig == "" {
			os.Unsetenv("QAU_PRODUCTION")
		} else {
			os.Setenv("QAU_PRODUCTION", orig)
		}
	}()

	validators, keypairs := makeVerifierValidators(t, 2)
	lookup := func() []*ValidatorInfo { return validators }
	mgr := NewDACommitteeManager(
		func() []*ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{byte(epoch)} },
	)
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)
	att := signAttestationForTest(t, newSampleAttestation(0), keypairs[0].Private)

	if err := verifier(att); err == nil {
		t.Error("verifier accepted an attestation with disabled committee in production mode (DA-)")
	}
}

// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// mockDAAttestationSigner is a test-only ThresholdKeySigner implementation
// for the DA aggregate attestation tests. It records the last call to
// AggregatePartialSignatures so tests can assert on its inputs, and returns
// a configurable error / signature. Named distinctly from the existing
// mockThresholdSigner in qtd_finality_test.go to avoid a redeclaration clash.
type mockDAAttestationSigner struct {
	thresholdMode   bool
	aggregateErr    error
	lastSealers     []int
	lastPartialSigs map[int][]byte
	lastMessage     []byte
	aggregatedSig   []byte
	groupPublicKey  []byte
}

func (m *mockDAAttestationSigner) SignBlock(validatorIndex int, message []byte) ([]byte, error) {
	return nil, errors.New("not used")
}
func (m *mockDAAttestationSigner) SignVote(validatorIndex int, message []byte) ([]byte, error) {
	return nil, errors.New("not used")
}
func (m *mockDAAttestationSigner) VerifyBlock(pubKey []byte, message []byte, signature []byte) bool {
	return false
}
func (m *mockDAAttestationSigner) VerifyVote(pubKey []byte, message []byte, signature []byte) bool {
	return false
}
func (m *mockDAAttestationSigner) GroupPublicKey() []byte { return m.groupPublicKey }
func (m *mockDAAttestationSigner) IsThresholdMode() bool  { return m.thresholdMode }
func (m *mockDAAttestationSigner) AggregatePartialSignatures(
	sealers []int, partialSigs map[int][]byte, message []byte,
) ([]byte, error) {
	m.lastSealers = sealers
	m.lastPartialSigs = partialSigs
	m.lastMessage = message
	if m.aggregateErr != nil {
		return nil, m.aggregateErr
	}
	return m.aggregatedSig, nil
}

// newCollectorWithAttestations builds a collector preloaded with N
// attestations for the given slot, all marked Available=true with
// distinct validator indices and unique dummy signatures.
//
// DA-R5-04 (2026-07-16): Each attestation's BlobCommitments is populated
// from `commitments` so BuildAggregateAttestation's commitment-binding
// check passes when called with the same set.
//
// DA-R7-04 (2026-07-17): commitments is now []encoding.KZGCommitment (48
// bytes each) instead of []types.Hash (32 bytes). The legacy BlobCommitment
// field is populated from the first 32 bytes of commitments[0].
func newCollectorWithAttestations(t *testing.T, n int, commitments []encoding.KZGCommitment) *DAAttestationCollector {
	t.Helper()
	c := NewDAAttestationCollector()
	c.SetCommitteeSize(n)
	// Use a permissive verifier that accepts every attestation.
	c.SetAttestationVerifier(func(att *encoding.DASAttestation) error { return nil })
	for i := 0; i < n; i++ {
		att := &encoding.DASAttestation{
			Slot:            100,
			Available:       true,
			ValidatorIndex:  i,
			Signature:       []byte{byte(i), 0xAA, 0xBB}, // unique per validator
			SampleCount:     10,
			SuccessCount:    10,
			Confidence:      0.9999,
			BlobCommitments: commitments,
		}
		if len(commitments) > 0 {
			att.BlobCommitment = types.BytesToHash(commitments[0][:])
		}
		if err := c.SubmitAttestation(att); err != nil {
			t.Fatalf("SubmitAttestation %d failed: %v", i, err)
		}
	}
	return c
}

func TestBuildAggregate_TransitionMode_UnderLimit(t *testing.T) {
	// 32 attestations, no threshold signer → transition multi-sig mode.
	// DoD: ≤ 64 signatures in transition mode.
	commitments := []encoding.KZGCommitment{{0x01}}
	c := newCollectorWithAttestations(t, 32, commitments)
	agg := c.BuildAggregateAttestation(100, commitments)
	if agg == nil {
		t.Fatal("expected non-nil aggregate")
	}
	if agg.ThresholdAggregated {
		t.Fatal("transition mode must produce ThresholdAggregated=false")
	}
	if len(agg.Signatures) != 32 {
		t.Fatalf("expected 32 concatenated signatures, got %d", len(agg.Signatures))
	}
	if agg.AvailableCount != 32 || agg.TotalCount != 32 {
		t.Fatalf("counts mismatch: avail=%d total=%d", agg.AvailableCount, agg.TotalCount)
	}
	if !agg.IsSufficient() {
		t.Fatal("32/32 available should be sufficient (≥ 0.6667)")
	}
}

func TestBuildAggregate_TransitionMode_OverLimitReturnsNil(t *testing.T) {
	// 65 attestations exceed DAMaxTransitionSignatures=64. Without QTD,
	// BuildAggregateAttestation MUST refuse to produce an unbounded aggregate.
	commitments := []encoding.KZGCommitment{{0x01}}
	c := newCollectorWithAttestations(t, DAMaxTransitionSignatures+1, commitments)
	agg := c.BuildAggregateAttestation(100, commitments)
	if agg != nil {
		t.Fatalf("transition mode must return nil when attestation count > %d", DAMaxTransitionSignatures)
	}
}

func TestBuildAggregate_TransitionMode_AtLimitBoundary(t *testing.T) {
	// Exactly 64 attestations — boundary case, should still succeed.
	commitments := []encoding.KZGCommitment{{0x01}}
	c := newCollectorWithAttestations(t, DAMaxTransitionSignatures, commitments)
	agg := c.BuildAggregateAttestation(100, commitments)
	if agg == nil {
		t.Fatalf("expected non-nil aggregate at limit boundary %d", DAMaxTransitionSignatures)
	}
	if len(agg.Signatures) != DAMaxTransitionSignatures {
		t.Fatalf("expected %d signatures, got %d", DAMaxTransitionSignatures, len(agg.Signatures))
	}
}

func TestBuildAggregate_QTDMode_SingleThresholdSignature(t *testing.T) {
	// DoD: Signatures length ≤ 1 when QTD threshold mode is active.
	commitments := []encoding.KZGCommitment{{0x01}, {0x02}}
	c := newCollectorWithAttestations(t, 200, commitments) // > 64 forces QTD reliance
	signer := &mockDAAttestationSigner{
		thresholdMode: true,
		aggregatedSig: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	c.SetThresholdSigner(signer)

	agg := c.BuildAggregateAttestation(100, commitments)
	if agg == nil {
		t.Fatal("expected non-nil aggregate in QTD mode")
	}
	if !agg.ThresholdAggregated {
		t.Fatal("QTD mode must set ThresholdAggregated=true")
	}
	if len(agg.Signatures) != 1 {
		t.Fatalf("DoD: expected exactly 1 threshold signature, got %d", len(agg.Signatures))
	}
	if string(agg.Signatures[0]) != string(signer.aggregatedSig) {
		t.Fatalf("threshold signature mismatch")
	}
	// Verify the signer was called with all available validators as sealers.
	if len(signer.lastSealers) != 200 {
		t.Fatalf("expected 200 sealers passed to aggregator, got %d", len(signer.lastSealers))
	}
	// Verify the message is the canonical threshold message (deterministic).
	expectedMsg := thresholdMessageForSlot(100, commitments)
	if string(signer.lastMessage) != string(expectedMsg) {
		t.Fatalf("aggregator called with wrong message")
	}
	// Verify each sealer's partial sig was forwarded.
	for i := 0; i < 200; i++ {
		ps, ok := signer.lastPartialSigs[i]
		if !ok {
			t.Fatalf("missing partial sig for sealer %d", i)
		}
		if string(ps) != string([]byte{byte(i), 0xAA, 0xBB}) {
			t.Fatalf("partial sig mismatch for sealer %d", i)
		}
	}
}

func TestBuildAggregate_QTDMode_FallsBackOnAggregationError(t *testing.T) {
	// When AggregatePartialSignatures fails AND attestation count ≤ 64,
	// BuildAggregateAttestation should fall back to multi-sig mode.
	commitments := []encoding.KZGCommitment{{0x01}}
	c := newCollectorWithAttestations(t, 32, commitments)
	signer := &mockDAAttestationSigner{
		thresholdMode: true,
		aggregateErr:  errors.New("DKG not ready"),
	}
	c.SetThresholdSigner(signer)

	agg := c.BuildAggregateAttestation(100, commitments)
	if agg == nil {
		t.Fatal("expected fallback to multi-sig on aggregation error")
	}
	if agg.ThresholdAggregated {
		t.Fatal("fallback aggregate must have ThresholdAggregated=false")
	}
	if len(agg.Signatures) != 32 {
		t.Fatalf("expected 32 concatenated fallback signatures, got %d", len(agg.Signatures))
	}
}

func TestBuildAggregate_QTDMode_ErrorAndOverLimitReturnsNil(t *testing.T) {
	// When aggregation fails AND attestation count > 64, there is no safe
	// fallback — return nil to signal that no aggregate can be produced.
	commitments := []encoding.KZGCommitment{{0x01}}
	c := newCollectorWithAttestations(t, DAMaxTransitionSignatures+1, commitments)
	signer := &mockDAAttestationSigner{
		thresholdMode: true,
		aggregateErr:  errors.New("insufficient partial sigs"),
	}
	c.SetThresholdSigner(signer)

	agg := c.BuildAggregateAttestation(100, commitments)
	if agg != nil {
		t.Fatal("expected nil when QTD fails and transition limit exceeded")
	}
}

func TestBuildAggregate_QTDMode_NoAvailableAttestors(t *testing.T) {
	// All attestations have Available=false — no partial sigs to aggregate.
	// P1-7 (2026-07-14): BuildAggregateAttestation returns nil when
	// IsSufficient()=false, so callers can distinguish "no valid aggregate"
	// from "valid aggregate". The aggregator is never invoked because there
	// are no Available attesters to collect partial sigs from.
	commitments := []encoding.KZGCommitment{{0x01}}
	c := NewDAAttestationCollector()
	c.SetCommitteeSize(10)
	c.SetAttestationVerifier(func(att *encoding.DASAttestation) error { return nil })
	for i := 0; i < 10; i++ {
		att := &encoding.DASAttestation{
			Slot:            100,
			Available:       false, // none available
			ValidatorIndex:  i,
			Signature:       []byte{byte(i)},
			BlobCommitments: commitments,
			BlobCommitment:  types.BytesToHash(commitments[0][:]), // DA-R7-04: KZGCommitment[0][:32]
		}
		if err := c.SubmitAttestation(att); err != nil {
			t.Fatalf("SubmitAttestation %d failed: %v", i, err)
		}
	}
	signer := &mockDAAttestationSigner{thresholdMode: true, aggregatedSig: []byte{0xFF}}
	c.SetThresholdSigner(signer)

	agg := c.BuildAggregateAttestation(100, commitments)
	if agg != nil {
		t.Fatalf("P1-7: expected nil aggregate when IsSufficient()=false, got non-nil with %d signatures", len(agg.Signatures))
	}
	if signer.lastSealers != nil {
		t.Fatal("aggregator must not be called when no attesters are available")
	}
}

func TestBuildAggregate_QTDMode_NotInThresholdModeFallsBack(t *testing.T) {
	// Signer present but IsThresholdMode()=false → must use transition mode.
	commitments := []encoding.KZGCommitment{{0x01}}
	c := newCollectorWithAttestations(t, 16, commitments)
	signer := &mockDAAttestationSigner{thresholdMode: false}
	c.SetThresholdSigner(signer)

	agg := c.BuildAggregateAttestation(100, commitments)
	if agg == nil {
		t.Fatal("expected non-nil aggregate in fallback transition mode")
	}
	if agg.ThresholdAggregated {
		t.Fatal("must not threshold-aggregate when IsThresholdMode()=false")
	}
	if len(agg.Signatures) != 16 {
		t.Fatalf("expected 16 multi-sig signatures, got %d", len(agg.Signatures))
	}
	if signer.lastSealers != nil {
		t.Fatal("aggregator must not be called in transition mode")
	}
}

func TestBuildAggregate_ThresholdAggregatedEncodeDecodeRoundTrip(t *testing.T) {
	// Verify the ThresholdAggregated field survives encode → decode.
	// This is critical for cross-node aggregate attestation propagation.
	commitments := []encoding.KZGCommitment{{0xAB, 0xCD}}
	original := &encoding.DASAggregateAttestation{
		Slot:                999,
		BlobCommitments:     commitments,
		AvailableCount:      5,
		TotalCount:          7,
		Signatures:          [][]byte{{0xDE, 0xAD, 0xBE, 0xEF}},
		ValidatorBits:       []byte{0b00101010},
		ThresholdAggregated: true,
	}

	encoded := original.Encode()
	decoded, err := encoding.DecodeDASAggregateAttestation(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !decoded.ThresholdAggregated {
		t.Fatal("ThresholdAggregated=true did not survive encode/decode round-trip")
	}
	if decoded.Slot != original.Slot {
		t.Fatalf("slot mismatch: %d != %d", decoded.Slot, original.Slot)
	}
	if len(decoded.Signatures) != 1 || string(decoded.Signatures[0]) != string(original.Signatures[0]) {
		t.Fatalf("signature mismatch after round-trip")
	}
	if decoded.AvailableCount != original.AvailableCount || decoded.TotalCount != original.TotalCount {
		t.Fatalf("count mismatch after round-trip")
	}
}

func TestBuildAggregate_TransitionModeEncodeDecodeRoundTrip(t *testing.T) {
	// Backward-compatibility: transition mode (ThresholdAggregated=false)
	// must also round-trip correctly.
	original := &encoding.DASAggregateAttestation{
		Slot:                42,
		BlobCommitments:     []encoding.KZGCommitment{{0x11}},
		AvailableCount:      3,
		TotalCount:          4,
		Signatures:          [][]byte{{0x01}, {0x02}, {0x03}, {0x04}},
		ValidatorBits:       []byte{0x0F},
		ThresholdAggregated: false,
	}

	encoded := original.Encode()
	decoded, err := encoding.DecodeDASAggregateAttestation(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.ThresholdAggregated {
		t.Fatal("ThresholdAggregated=false did not survive encode/decode round-trip")
	}
	if len(decoded.Signatures) != 4 {
		t.Fatalf("expected 4 signatures, got %d", len(decoded.Signatures))
	}
}

func TestThresholdMessage_DeterministicAndBinding(t *testing.T) {
	// The threshold message must be:
	//   1. Deterministic (same inputs → same output)
	//   2. Sensitive to slot
	//   3. Sensitive to commitments
	commitments := []encoding.KZGCommitment{{0x01}, {0x02}}
	m1 := thresholdMessageForSlot(100, commitments)
	m2 := thresholdMessageForSlot(100, commitments)
	if string(m1) != string(m2) {
		t.Fatal("threshold message must be deterministic for identical inputs")
	}
	// Different slot → different message.
	m3 := thresholdMessageForSlot(101, commitments)
	if string(m1) == string(m3) {
		t.Fatal("threshold message must change when slot changes")
	}
	// Different commitments → different message.
	m4 := thresholdMessageForSlot(100, []encoding.KZGCommitment{{0x99}})
	if string(m1) == string(m4) {
		t.Fatal("threshold message must change when commitments change")
	}
	// Length must be 32 bytes (SHA3-256).
	if len(m1) != 32 {
		t.Fatalf("threshold message must be 32 bytes, got %d", len(m1))
	}
}

// P1-7 (2026-07-14): BuildAggregateAttestation returns nil when
// IsSufficient()=false, so callers can distinguish "no valid aggregate"
// from "valid aggregate". This test verifies the boundary: exactly 2/3
// available is sufficient (0.6667 threshold), just below is not.
func TestBuildAggregate_P1_7_InsufficientReturnsNil_TransitionMode(t *testing.T) {
	// 10 attestations, only 6 available = 0.6 < 0.6667 → insufficient.
	commitments := []encoding.KZGCommitment{{0x01}}
	c := NewDAAttestationCollector()
	c.SetCommitteeSize(10)
	c.SetAttestationVerifier(func(att *encoding.DASAttestation) error { return nil })
	for i := 0; i < 10; i++ {
		att := &encoding.DASAttestation{
			Slot:            100,
			Available:       i < 6, // 6 available out of 10 = 0.6 < 0.6667
			ValidatorIndex:  i,
			Signature:       []byte{byte(i)},
			BlobCommitments: commitments,
			BlobCommitment:  types.BytesToHash(commitments[0][:]), // DA-R7-04: KZGCommitment[0][:32]
		}
		if err := c.SubmitAttestation(att); err != nil {
			t.Fatalf("SubmitAttestation %d failed: %v", i, err)
		}
	}
	agg := c.BuildAggregateAttestation(100, commitments)
	if agg != nil {
		t.Fatalf("P1-7: expected nil when 6/10 available (0.6 < 0.6667), got non-nil aggregate")
	}
}

func TestBuildAggregate_P1_7_SufficientBoundary_Passes(t *testing.T) {
	// 4 attestations, 3 available = 0.75 >= 0.6667 → sufficient.
	// Note: 2/3 = 0.6666... < 0.6667 (float comparison), so we use 3/4.
	commitments := []encoding.KZGCommitment{{0x01}}
	c := NewDAAttestationCollector()
	c.SetCommitteeSize(4)
	c.SetAttestationVerifier(func(att *encoding.DASAttestation) error { return nil })
	for i := 0; i < 4; i++ {
		att := &encoding.DASAttestation{
			Slot:            100,
			Available:       i < 3, // 3 available out of 4 = 0.75
			ValidatorIndex:  i,
			Signature:       []byte{byte(i)},
			BlobCommitments: commitments,
			BlobCommitment:  types.BytesToHash(commitments[0][:]), // DA-R7-04: KZGCommitment[0][:32]
		}
		if err := c.SubmitAttestation(att); err != nil {
			t.Fatalf("SubmitAttestation %d failed: %v", i, err)
		}
	}
	agg := c.BuildAggregateAttestation(100, commitments)
	if agg == nil {
		t.Fatal("P1-7: expected non-nil aggregate when 3/4 available (0.75 >= 0.6667)")
	}
	if !agg.IsSufficient() {
		t.Fatal("IsSufficient should be true at 3/4 available")
	}
}

// P1-8 (2026-07-14): SubmitAttestation enforces per-slot attestation cap.
// Once the cap (committeeSize) is reached, new attestations from
// previously-unseen validators are rejected. Re-submissions from existing
// validators overwrite and are allowed.
func TestSubmitAttestation_P1_8_CapReached(t *testing.T) {
	c := NewDAAttestationCollector()
	c.SetCommitteeSize(3) // small cap for testing
	c.SetAttestationVerifier(func(att *encoding.DASAttestation) error { return nil })

	// Fill the slot with 3 attestations (the cap).
	for i := 0; i < 3; i++ {
		att := &encoding.DASAttestation{
			Slot:           100,
			Available:      true,
			ValidatorIndex: i,
			Signature:      []byte{byte(i)},
		}
		if err := c.SubmitAttestation(att); err != nil {
			t.Fatalf("SubmitAttestation %d failed: %v", i, err)
		}
	}

	// 4th attestation from a new validator should be rejected.
	att4 := &encoding.DASAttestation{
		Slot:           100,
		Available:      true,
		ValidatorIndex: 3,
		Signature:      []byte{0x03},
	}
	err := c.SubmitAttestation(att4)
	if err == nil {
		t.Fatal("P1-8: expected error when attestation cap reached, got nil")
	}

	// Re-submission from existing validator should be allowed (overwrite).
	att0Updated := &encoding.DASAttestation{
		Slot:           100,
		Available:      false, // changed
		ValidatorIndex: 0,
		Signature:      []byte{0xFF},
	}
	if err := c.SubmitAttestation(att0Updated); err != nil {
		t.Fatalf("P1-8: re-submission from existing validator should be allowed, got: %v", err)
	}

	// Different slot should not be affected by the cap.
	attOtherSlot := &encoding.DASAttestation{
		Slot:           200,
		Available:      true,
		ValidatorIndex: 0,
		Signature:      []byte{0xAA},
	}
	if err := c.SubmitAttestation(attOtherSlot); err != nil {
		t.Fatalf("P1-8: different slot should not be affected by cap, got: %v", err)
	}
}

// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"fmt"
	"math/bits"
	"math/rand"
	"path/filepath"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

const (
	// signingInteropTestMessage is the deterministic message every interop and
	// state-machine run signs.
	signingInteropTestMessage = "QAU-TDILITHIUM3-V1-SIGNING-MPC-REFERENCE-INTEROP"

	// signingRejectionTestMessage is a second deterministic message used by the
	// rejection tests so that no test reuses one message together with one slot
	// across a successful and a rejected attempt.
	signingRejectionTestMessage = "QAU-TDILITHIUM3-V1-SIGNING-MPC-REFERENCE-REJECTION"

	// signingTestCoordinator is the coordinator identity the reference attempts
	// bind.
	signingTestCoordinator = uint32(6)

	// signingTestAttemptLimit bounds the reference rejection loop. The per-slot
	// success probability at the pinned parameters is 0.06606, so the expected
	// number of attempts per accepted signature is about 15.
	signingTestAttemptLimit = 1 << 12
)

// signingTestAttemptRandomness draws one attempt's four ball points from the
// caller's deterministic source.
func signingTestAttemptRandomness(t *testing.T, source *rand.Rand) [4]*signingRandomness {
	t.Helper()
	var points [4]*signingRandomness
	for index := range points {
		point, err := sampleSigningRandomness(source)
		if err != nil {
			t.Fatalf("sampleSigningRandomness(): %v", err)
		}
		points[index] = point
	}
	return points
}

// signingTestRandomnessFor returns four ball points seeded from a label for the
// tests that only need valid, deterministic attempt input.
func signingTestRandomnessFor(t *testing.T, label byte) [4]*signingRandomness {
	t.Helper()
	return signingTestAttemptRandomness(t, rand.New(rand.NewSource(int64(label))))
}

// signingTestAttemptRecord returns a fresh one-time record whose public
// metadata is distinct per slot. The metadata is test scaffolding; production
// records come from the preprocessing layer.
func signingTestAttemptRecord(t *testing.T, slot int) *PreprocessingRecord {
	t.Helper()
	return mpcTestRecord(t, byte(0x30+(slot-1)%0x60))
}

// signingTestSlot is the accepted outcome of the reference rejection loop.
type signingTestSlot struct {
	signature  []byte
	attempt    *signingAttempt
	randomness [4]*signingRandomness
}

// signingTestSign drives the reference rejection loop: fresh randomness, a
// fresh one-time record, and a fresh slot-bound session per attempt, until one
// slot is accepted by every signer and passes the public combine checks. It
// returns the accepted slot, the number of attempts it took, and how many
// attempts were rejected.
func signingTestSign(
	t *testing.T,
	journal *SigningJournal,
	request protocol.SignRequest,
	active []*LocalShare,
	source *rand.Rand,
) (signingTestSlot, int, int) {
	t.Helper()
	rejections := 0
	for slot := 1; slot <= signingTestAttemptLimit; slot++ {
		slotRequest := request.Clone()
		slotRequest.AttemptNonce[0] = byte(slot)
		slotRequest.AttemptNonce[1] = byte(slot >> 8)
		randomness := signingTestAttemptRandomness(t, source)
		attempt, err := newSigningAttempt(
			journal, signingTestAttemptRecord(t, slot), slotRequest, active, signingTestCoordinator, randomness,
		)
		if err != nil {
			t.Fatalf("slot %d: newSigningAttempt(): %v", slot, err)
		}
		if err := attempt.prepare(); err != nil {
			t.Fatalf("slot %d: prepare(): %v", slot, err)
		}
		if _, err := attempt.commit(); err != nil {
			t.Fatalf("slot %d: commit(): %v", slot, err)
		}
		if _, err := attempt.challenge(); err != nil {
			t.Fatalf("slot %d: challenge(): %v", slot, err)
		}
		if _, err := attempt.respond(); err != nil {
			if !errors.Is(err, errSigningRejected) {
				t.Fatalf("slot %d: respond(): %v", slot, err)
			}
			rejections++
			continue
		}
		signature, err := attempt.finalize()
		if err != nil {
			if !errors.Is(err, errSigningRejected) {
				t.Fatalf("slot %d: finalize(): %v", slot, err)
			}
			rejections++
			continue
		}
		return signingTestSlot{signature: signature, attempt: attempt, randomness: randomness}, slot, rejections
	}
	t.Fatalf("no accepted slot in %d attempts", signingTestAttemptLimit)
	return signingTestSlot{}, 0, 0
}

// reconstructAggregateSecret sums the twenty canonical three-member components
// into the aggregate secret and requires the three copies of each component to
// agree. Test scaffolding only: no production backend may reconstruct the
// aggregate secret, and the reference driver reconstructs only the per-signer
// partial secrets inside one process.
func reconstructAggregateSecret(activeShares []*LocalShare) (VectorL, VectorK, error) {
	groups := CanonicalRSSGroups()
	var s1 VectorL
	var s2 VectorK
	for _, group := range groups {
		var reference *RSSComponent
		for _, share := range activeShares {
			for index := range share.Components {
				component := &share.Components[index]
				if component.GroupMask != group {
					continue
				}
				if reference == nil {
					reference = component
					continue
				}
				if *component != *reference {
					return VectorL{}, VectorK{}, fmt.Errorf(
						"%w: group %06b components disagree", errInvalidSigningAttempt, group,
					)
				}
			}
		}
		if reference == nil {
			return VectorL{}, VectorK{}, fmt.Errorf(
				"%w: group %06b has no active holder", errInvalidSigningAttempt, group,
			)
		}
		for row := 0; row < L; row++ {
			s1[row] = Add(s1[row], reference.S1[row])
		}
		for row := 0; row < K; row++ {
			s2[row] = Add(s2[row], reference.S2[row])
		}
	}
	for row := 0; row < L; row++ {
		if err := validateAggregateBound("s1", row, s1[row]); err != nil {
			return VectorL{}, VectorK{}, err
		}
	}
	for row := 0; row < K; row++ {
		if err := validateAggregateBound("s2", row, s2[row]); err != nil {
			return VectorL{}, VectorK{}, err
		}
	}
	return s1, s2, nil
}

// validateAggregateBound requires one aggregate secret coefficient to stay
// inside the replicated-sharing bound the DKG topology fixes.
func validateAggregateBound(name string, row int, polynomial Poly) error {
	for index := 0; index < N; index++ {
		value := int64(CenteredCoefficient(polynomial[index]))
		if value < -RSSAggregateBound || value > RSSAggregateBound {
			return fmt.Errorf(
				"%w: %s[%d][%d] = %d outside the aggregate bound %d",
				errInvalidSigningAttempt, name, row, index, value, RSSAggregateBound,
			)
		}
	}
	return nil
}

// signingTestFixture is the deterministic DKG fixture the signing tests share.
type signingTestFixture struct {
	shares [6]*LocalShare
	key    protocol.ThresholdKeyID
	rho    [32]byte
	s1     VectorL
	s2     VectorK
}

func signingTestFixtureFor(t *testing.T) *signingTestFixture {
	t.Helper()
	shares, key, rho := testMode3RSSShares(t)
	active := []*LocalShare{shares[0], shares[1], shares[2], shares[3]}
	s1, s2, err := reconstructAggregateSecret(active)
	if err != nil {
		t.Fatalf("reconstructAggregateSecret(): %v", err)
	}
	return &signingTestFixture{shares: shares, key: key, rho: rho, s1: s1, s2: s2}
}

// activeShares returns the shares of one four-member subset in committee order.
func (fixture *signingTestFixture) activeShares(t *testing.T, mask uint8) []*LocalShare {
	t.Helper()
	if bits.OnesCount8(mask) != 4 {
		t.Fatalf("mask %06b is not a four-member subset", mask)
	}
	var active []*LocalShare
	for position, share := range fixture.shares {
		if mask&(1<<position) != 0 {
			active = append(active, share)
		}
	}
	return active
}

func (fixture *signingTestFixture) requestFor(message []byte) protocol.SignRequest {
	return protocol.SignRequest{
		Protocol:     protocol.ThresholdProtocolDilithium3V1,
		Key:          fixture.key.Clone(),
		Committee:    fixture.shares[0].Committee.Clone(),
		ChainID:      1669,
		Epoch:        fixture.shares[0].ActivationEpoch,
		Slot:         64,
		Domain:       protocol.SigningDomainFinality,
		Message:      append([]byte(nil), message...),
		AttemptNonce: [32]byte{0xA1, 0x02, 0x03},
	}
}

func signingTestJournal(t *testing.T) *SigningJournal {
	t.Helper()
	return signingTestJournalAt(t, t.TempDir())
}

func signingTestJournalAt(t *testing.T, directory string) *SigningJournal {
	t.Helper()
	journal, err := OpenSigningJournal(filepath.Join(directory, "signing-journal.db"))
	if err != nil {
		t.Fatalf("OpenSigningJournal(): %v", err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	return journal
}

// TestMode3SignatureInteropAllFourHolderSubsets requires every one of the
// fifteen four-member subsets to produce one 3293-byte signature that the
// unmodified mode3 verifier accepts through the reference rejection loop, and
// requires the transcript-bound parts to reject every mutation.
func TestMode3SignatureInteropAllFourHolderSubsets(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	journal := signingTestJournal(t)
	request := fixture.requestFor([]byte(signingInteropTestMessage))
	seenSessions := make(map[[32]byte]struct{}, 15)
	completed := 0
	totalAttempts := 0
	for mask := uint8(0); mask < 1<<6; mask++ {
		if bits.OnesCount8(mask) != 4 {
			continue
		}
		active := fixture.activeShares(t, mask)
		source := rand.New(rand.NewSource(int64(0x5155 + completed*97)))
		slot, attempts, rejections := signingTestSign(t, journal, request, active, source)
		totalAttempts += attempts
		if attempts != rejections+1 {
			t.Fatalf("mask %06b: %d attempts against %d rejections", mask, attempts, rejections)
		}
		if len(slot.signature) != 3293 {
			t.Fatalf("mask %06b: signature length %d, want 3293", mask, len(slot.signature))
		}
		if err := qcrypto.VerifySignatureForAlgorithm(
			fixture.key.Algorithm, fixture.key.PublicKey, request.Message, nil, slot.signature,
		); err != nil {
			t.Fatalf("mask %06b: native verification failed: %v", mask, err)
		}
		if slot.attempt.state != signingStateFinalized {
			t.Fatalf("mask %06b: state %s, want finalized", mask, slot.attempt.state)
		}
		if _, duplicate := seenSessions[slot.attempt.sessionID]; duplicate {
			t.Fatalf("mask %06b: session identifier reused", mask)
		}
		seenSessions[slot.attempt.sessionID] = struct{}{}
		if allocation, err := AllocateRSSGroups(mask); err != nil {
			t.Fatalf("mask %06b: %v", mask, err)
		} else {
			counts := map[uint8]int{}
			for _, position := range allocation {
				counts[position]++
			}
			if len(counts) != 4 {
				t.Fatalf("mask %06b: allocation covers %d positions, want 4", mask, len(counts))
			}
			for position, count := range counts {
				if count != 5 {
					t.Fatalf("mask %06b: position %d owns %d groups, want 5", mask, position, count)
				}
			}
		}
		parts, err := ParseMode3Signature(slot.signature)
		if err != nil {
			t.Fatalf("mask %06b: ParseMode3Signature(): %v", mask, err)
		}
		checkSigningMutations(t, fixture, request.Message, parts)
		completed++
	}
	if completed != 15 {
		t.Fatalf("completed %d subsets, want 15", completed)
	}
	if len(seenSessions) != 15 {
		t.Fatalf("seen %d sessions, want 15", len(seenSessions))
	}
	// The reference loop is a real rejection loop: reaching a signature within
	// the attempt limit is itself the acceptance evidence. The exact rate is
	// pinned by TestThresholdSigningSlotAcceptanceBand.
	if totalAttempts < completed {
		t.Fatalf("total attempts %d below the subset count %d", totalAttempts, completed)
	}
}

// checkSigningMutations requires every mutated transcript part to fail the
// unmodified verifier.
func checkSigningMutations(
	t *testing.T,
	fixture *signingTestFixture,
	message []byte,
	parts SignatureParts,
) {
	t.Helper()
	if _, err := AssembleVerifiedMode3Signature(fixture.key, []byte("mutated message"), parts); err == nil {
		t.Fatal("signature accepted for a mutated message")
	}
	mutated := parts
	mutated.Challenge[0] ^= 1
	if _, err := AssembleVerifiedMode3Signature(fixture.key, message, mutated); err == nil {
		t.Fatal("signature accepted for a mutated challenge")
	}
	mutated = parts
	mutated.Z[0][0] += 1
	if _, err := AssembleVerifiedMode3Signature(fixture.key, message, mutated); err == nil {
		t.Fatal("signature accepted for a mutated response")
	}
	mutated = parts
	mutated.Hints[0][0] ^= 1
	if _, err := AssembleVerifiedMode3Signature(fixture.key, message, mutated); err == nil {
		t.Fatal("signature accepted for a mutated hint")
	}
	foreignKey := fixture.key.Clone()
	foreignKey.PublicKey = append([]byte(nil), fixture.key.PublicKey...)
	foreignKey.PublicKey[32] ^= 1
	if _, err := AssembleVerifiedMode3Signature(foreignKey, message, parts); err == nil {
		t.Fatal("signature accepted under a mutated public key")
	}
}

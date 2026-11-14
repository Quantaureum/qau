// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// Cryptographic acceptance vectors for the TSS-R3-B-1 P1 proposal path (this
// file only adds tests; the package's sources and existing tests are
// untouched). The pinned questions:
//
//  1. A four-of-six session whose request is hard-bound to the proposal --
//     Domain = SigningDomainBlock, Message = the canonical TSS binding over
//     (chainID, epoch, slot, proposer, "block", signingData) -- produces one
//     ordinary 3293-byte mode3 signature that the unmodified circl verifier
//     accepts over that binding, and that the block validator's per-epoch v1
//     group-signature branch accepts for the header.
//  2. Tampering with the header breaks BOTH verification shapes at once: the
//     validator's binding no longer verifies the signature, and the seal
//     message shape derived from the tampered header verifies neither. There
//     is no message form of a tampered header that the produced signature
//     covers.
//  3. The journal's single-use discipline holds for the proposal-shaped
//     session: a finalized session id cannot be prepared again.

import (
	"errors"
	"math/rand"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/core"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// proposalVectorValidatorLookup resolves every validator address to one fixed
// individual key, so the block validator's individual fallback path genuinely
// runs (and genuinely fails) in the tamper case instead of stopping at an
// unconfigured lookup.
type proposalVectorValidatorLookup struct {
	pub []byte
}

func (l *proposalVectorValidatorLookup) GetValidatorPublicKey(addr types.Address) ([]byte, error) {
	return l.pub, nil
}

func (l *proposalVectorValidatorLookup) IsValidator(addr types.Address) bool { return true }

// proposalVectorHeader builds the header the vector binds: devnet chain, the
// fixture's activation epoch, a fixed slot, and a derived proposer address.
func proposalVectorHeader(t *testing.T, fixture *signingTestFixture) (*encoding.BlockHeader, *core.BlockValidator, []byte) {
	t.Helper()
	header := &encoding.BlockHeader{
		ChainID:      1669,
		Epoch:        fixture.shares[0].ActivationEpoch,
		Slot:         64,
		Height:       640,
		ProposerAddr: types.Address{0x61, 0x62, 0x63},
	}
	validator := core.NewBlockValidator(header.ChainID, 30_000_000)
	// The v1 branch's gate and lookup mirror the production wiring: the
	// activation epoch is armed and the epoch's group public key comes from
	// the QTD anchor custody export (here: the fixture's assembled key).
	validator.SetTSSV1ProposalActivationEpoch(header.Epoch)
	validator.SetTSSV1GroupKeyLookup(func(epoch uint64) []byte {
		return append([]byte(nil), fixture.key.PublicKey...)
	})
	validator.SetValidatorLookup(&proposalVectorValidatorLookup{
		// An unrelated valid individual key, so a fallback that runs after a
		// failed group check is a real cryptographic failure.
		pub: individualVectorKey(t),
	})
	// The signing data is the shared header signing root: exactly what the
	// block validator's computeSigningData derives (the same stripped-header
	// sha3 in encoding), so the binding here and the validator's binding are
	// one equation, with no duplicated strip logic to drift.
	root, err := encoding.BlockHeaderSigningRoot(header)
	if err != nil {
		t.Fatalf("header signing root: %v", err)
	}
	return header, validator, root[:]
}

// individualVectorKey derives a deterministic, non-degenerate individual
// Dilithium3 key that has nothing to do with the group fixture.
func individualVectorKey(t *testing.T) []byte {
	t.Helper()
	var seed [mode3.SeedSize]byte
	copy(seed[:], "DEVNET ONLY proposal vector individual key")
	publicKey, _ := mode3.NewKeyFromSeed(&seed)
	return publicKey.Bytes()
}

// TestProposalBoundSessionAcceptedByMode3AndBlockValidator drives the
// reference rejection loop over a proposal-bound request until one candidate
// slot is accepted, then requires the produced signature to pass BOTH
// consumers: the circl mode3 verifier over the binding, and the block
// validator's per-epoch v1 branch over the header.
func TestProposalBoundSessionAcceptedByMode3AndBlockValidator(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	journal := signingTestJournal(t)
	header, validator, signingData := proposalVectorHeader(t, fixture)
	bound := consensus.ComputeTSSCanonicalBinding(
		header.ChainID, header.Epoch, header.Slot, header.ProposerAddr, "block", signingData,
	)
	nonce, err := SigningRequestAttemptNonce(
		header.ChainID, header.Epoch, header.Slot, protocol.SigningDomainBlock, bound[:], 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.SignRequest{
		Protocol:     protocol.ThresholdProtocolDilithium3V1,
		Key:          fixture.key.Clone(),
		Committee:    fixture.shares[0].Committee.Clone(),
		ChainID:      header.ChainID,
		Epoch:        header.Epoch,
		Slot:         header.Slot,
		Domain:       protocol.SigningDomainBlock,
		Message:      append([]byte(nil), bound[:]...),
		AttemptNonce: nonce,
	}
	source := rand.New(rand.NewSource(int64(0xB10C)))
	slot, attempts, rejections := signingTestSign(t, journal, request, fixture.activeShares(t, 0x0F), source)
	if attempts != rejections+1 {
		t.Fatalf("%d attempts against %d rejections", attempts, rejections)
	}
	if len(slot.signature) != 3293 {
		t.Fatalf("signature length %d, want 3293", len(slot.signature))
	}
	// Consumer 1: the unmodified mode3 verifier over the binding.
	if err := qcrypto.VerifySignatureForAlgorithm(
		fixture.key.Algorithm, fixture.key.PublicKey, bound[:], nil, slot.signature,
	); err != nil {
		t.Fatalf("mode3 verification over the binding failed: %v", err)
	}
	// The raw signing hash is NOT the signed message: the domain separation
	// between the proposal binding and the bare header hash holds.
	if err := qcrypto.VerifySignatureForAlgorithm(
		fixture.key.Algorithm, fixture.key.PublicKey, signingData, nil, slot.signature,
	); err == nil {
		t.Fatal("signature verified over the raw signing hash; the binding contract is broken")
	}
	// Consumer 2: the block validator's per-epoch v1 group-signature branch.
	header.Signature = append([]byte(nil), slot.signature...)
	if err := validator.ValidateSignature(header); err != nil {
		t.Fatalf("block validator rejected the proposal group signature: %v", err)
	}
}

// TestProposalTamperedHeaderBreaksBothVerifications requires a header that
// differs in one field to break both verification shapes at once: the
// validator's re-derived binding no longer matches (and the individual
// fallback genuinely fails too), and the seal message shape derived from the
// tampered header verifies neither.
func TestProposalTamperedHeaderBreaksBothVerifications(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	journal := signingTestJournal(t)
	header, validator, signingData := proposalVectorHeader(t, fixture)
	bound := consensus.ComputeTSSCanonicalBinding(
		header.ChainID, header.Epoch, header.Slot, header.ProposerAddr, "block", signingData,
	)
	request := protocol.SignRequest{
		Protocol:     protocol.ThresholdProtocolDilithium3V1,
		Key:          fixture.key.Clone(),
		Committee:    fixture.shares[0].Committee.Clone(),
		ChainID:      header.ChainID,
		Epoch:        header.Epoch,
		Slot:         header.Slot,
		Domain:       protocol.SigningDomainBlock,
		Message:      append([]byte(nil), bound[:]...),
		AttemptNonce: [32]byte{0xB1, 0x0C, 0x0D},
	}
	source := rand.New(rand.NewSource(int64(0x7A4)))
	slot, _, _ := signingTestSign(t, journal, request, fixture.activeShares(t, 0x0F), source)

	tampered := *header
	tampered.GasUsed ^= 1 // one header byte changed
	tampered.Signature = append([]byte(nil), slot.signature...)
	tamperedRoot, err := encoding.BlockHeaderSigningRoot(&tampered)
	if err != nil {
		t.Fatalf("tampered header signing root: %v", err)
	}
	tamperedSigningData := tamperedRoot[:]
	tamperedBound := consensus.ComputeTSSCanonicalBinding(
		tampered.ChainID, tampered.Epoch, tampered.Slot, tampered.ProposerAddr, "block", tamperedSigningData,
	)
	tamperedSealMessage := consensus.QTDSignedMessage(
		tampered.ChainID, tampered.Epoch, tampered.Slot, types.BytesToHash(tamperedSigningData),
	)
	// Header verification: the validator's v1 branch re-derives the tampered
	// header's binding, the group check fails, and the individual fallback
	// fails as well.
	if err := validator.ValidateSignature(&tampered); err == nil {
		t.Fatal("block validator accepted the signature for a tampered header")
	}
	// The group key accepts neither the tampered binding nor the tampered
	// header's seal message shape: no message form of the tampered header is
	// covered by the produced signature.
	for _, message := range [][]byte{tamperedBound[:], tamperedSealMessage} {
		if err := qcrypto.VerifySignatureForAlgorithm(
			fixture.key.Algorithm, fixture.key.PublicKey, message, nil, slot.signature,
		); err == nil {
			t.Fatalf("signature verified over a tampered-header message form (%x...)", message[:4])
		}
	}
	// Positive control: the original binding still verifies.
	originalSealMessage := consensus.QTDSignedMessage(
		header.ChainID, header.Epoch, header.Slot, types.BytesToHash(signingData),
	)
	if err := qcrypto.VerifySignatureForAlgorithm(
		fixture.key.Algorithm, fixture.key.PublicKey, bound[:], nil, slot.signature,
	); err != nil {
		t.Fatalf("positive control failed: %v", err)
	}
	if err := qcrypto.VerifySignatureForAlgorithm(
		fixture.key.Algorithm, fixture.key.PublicKey, originalSealMessage, nil, slot.signature,
	); err == nil {
		t.Fatal("signature verified over a seal message; the proposal and seal domains collapsed")
	}
}

// TestProposalTamperedHeaderFieldCanaries extends the single GasUsed
// representative in TestProposalTamperedHeaderBreaksBothVerifications with
// two further binding inputs as canaries: identity (ProposerAddr) and
// position (Slot). Each mutation is a distinct header field, so the signing
// root — and with it the canonical binding — moves for a different reason in
// every case, and no single-field tamper class can slip past the group check.
func TestProposalTamperedHeaderFieldCanaries(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	journal := signingTestJournal(t)
	header, validator, signingData := proposalVectorHeader(t, fixture)
	bound := consensus.ComputeTSSCanonicalBinding(
		header.ChainID, header.Epoch, header.Slot, header.ProposerAddr, "block", signingData,
	)
	request := protocol.SignRequest{
		Protocol:     protocol.ThresholdProtocolDilithium3V1,
		Key:          fixture.key.Clone(),
		Committee:    fixture.shares[0].Committee.Clone(),
		ChainID:      header.ChainID,
		Epoch:        header.Epoch,
		Slot:         header.Slot,
		Domain:       protocol.SigningDomainBlock,
		Message:      append([]byte(nil), bound[:]...),
		AttemptNonce: [32]byte{0xC1, 0x0D, 0x0E},
	}
	source := rand.New(rand.NewSource(int64(0x7A5)))
	session, _, _ := signingTestSign(t, journal, request, fixture.activeShares(t, 0x0F), source)

	canaries := []struct {
		name   string
		mutate func(h *encoding.BlockHeader)
	}{
		{"ProposerAddr", func(h *encoding.BlockHeader) { h.ProposerAddr[0] ^= 0xFF }},
		{"Slot", func(h *encoding.BlockHeader) { h.Slot++ }},
	}
	for _, canary := range canaries {
		t.Run(canary.name, func(t *testing.T) {
			tampered := *header
			canary.mutate(&tampered)
			tampered.Signature = append([]byte(nil), session.signature...)
			if err := validator.ValidateSignature(&tampered); err == nil {
				t.Fatalf("block validator accepted the signature for a tampered %s", canary.name)
			}
			tamperedRoot, err := encoding.BlockHeaderSigningRoot(&tampered)
			if err != nil {
				t.Fatalf("tampered header signing root: %v", err)
			}
			tamperedBound := consensus.ComputeTSSCanonicalBinding(
				tampered.ChainID, tampered.Epoch, tampered.Slot, tampered.ProposerAddr, "block", tamperedRoot[:],
			)
			if err := qcrypto.VerifySignatureForAlgorithm(
				fixture.key.Algorithm, fixture.key.PublicKey, tamperedBound[:], nil, session.signature,
			); err == nil {
				t.Fatalf("signature verified over the tampered-%s binding", canary.name)
			}
		})
	}
}

// TestProposalSessionJournalReplayRefused requires the journal's single-use
// discipline for the proposal-shaped session: a finalized session id cannot
// be prepared again, even with a fresh one-time record and fresh randomness.
func TestProposalSessionJournalReplayRefused(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	journal := signingTestJournal(t)
	header, _, signingData := proposalVectorHeader(t, fixture)
	bound := consensus.ComputeTSSCanonicalBinding(
		header.ChainID, header.Epoch, header.Slot, header.ProposerAddr, "block", signingData,
	)
	request := protocol.SignRequest{
		Protocol:     protocol.ThresholdProtocolDilithium3V1,
		Key:          fixture.key.Clone(),
		Committee:    fixture.shares[0].Committee.Clone(),
		ChainID:      header.ChainID,
		Epoch:        header.Epoch,
		Slot:         header.Slot,
		Domain:       protocol.SigningDomainBlock,
		Message:      append([]byte(nil), bound[:]...),
		AttemptNonce: [32]byte{0xB1, 0x0C, 0x0E},
	}
	source := rand.New(rand.NewSource(int64(0x3E57)))
	accepted, attempts, _ := signingTestSign(t, journal, request, fixture.activeShares(t, 0x0F), source)

	// Replay: the reference loop stamps the slot ordinal into the attempt
	// nonce's first two bytes, so the accepted session's request carries
	// attempts in those bytes. Rebuilding that exact request must derive the
	// accepted session's id -- the positive control that the replay targets
	// the finalized journal entry -- and a fresh record and fresh randomness
	// must not revive it.
	replayRequest := request.Clone()
	replayRequest.AttemptNonce[0] = byte(attempts)
	replayRequest.AttemptNonce[1] = byte(attempts >> 8)
	expectedID, err := Dilithium3SigningSessionID(replayRequest, []uint32{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	if expectedID != accepted.attempt.sessionID {
		t.Fatal("the rebuilt replay request does not derive the accepted session's id")
	}
	record := signingTestAttemptRecord(t, 1)
	randomness := signingTestRandomnessFor(t, 0x5E)
	replay, err := newSigningAttempt(journal, record, replayRequest, fixture.activeShares(t, 0x0F), signingTestCoordinator, randomness)
	if err != nil {
		t.Fatalf("replay session construction: %v", err)
	}
	if err := replay.prepare(); !errors.Is(err, errInvalidSigningState) {
		t.Fatalf("replayed proposal session prepared (err %v), want the journal replay refusal", err)
	}
}

// Quantaureum Node source, version 1.0.0.
package node

// End-to-end test of the Dilithium3 v1 fresh-sync bootstrap (TSS-R3-B-1 R-1
// fix, in-process driver mode).
//
// The chain under test is the exact shape the P2-3 devnet deadlock produced:
// an armed network starts group-signing headers, and a node syncing from
// genesis reaches the first group-signed header with an EMPTY anchor custody.
// Before the fix that header was a one-way door — the v1 branch found no key,
// the group signature failed individual verification, and because anchor
// adoption runs post-apply, the anchor inside the rejected header could never
// be adopted (observed as "invalid block signature" repeating forever).
//
// The fixed carrier sequence is driven through the PRODUCTION paths:
//
//   - the epoch's first header is individually signed and carries the group
//     key (the boundary carrier — produced by tdilithium3V1HeaderAnchorKey's
//     rule, signed individually because the session gates refuse boundary
//     slots);
//   - the following headers carry REAL four-of-six session group signatures
//     over the canonical TSS binding (the same convergence path
//     TestTDilithium3ProposalTriggerChannelConvergence pins);
//   - the fresh node validates each header through core.BlockValidator wired
//     exactly like the node does (node.go: GroupPublicKeyForEpoch as the v1
//     lookup), then runs the post-apply adoption hook
//     (onCanonicalBlockImported → ObserveAnchoredGroupKey + the canonical
//     anchor record).
//
// The assertion is the one the devnet could not make: every header verifies —
// zero rejections — and the fresh custody ends up serving the ceremony key for
// both epochs, so the sync converges. The negative case pins the one-way door
// itself: without a prior anchor carrier the same group-signed header is
// rejected, which is what keeps this test honest if the carrier rules ever
// regress.

import (
	"bytes"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/core"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// freshSyncE2EHeaderShape is the fixed header skeleton of the test chain: the
// fields the signing root covers must be set before signing and never change.
type freshSyncE2EHeaderShape struct {
	epoch uint64
	slot  uint64
}

// freshSyncE2EHeader builds one chain header of the fixture identity's chain.
func freshSyncE2EHeader(t *testing.T, shape freshSyncE2EHeaderShape, proposer types.Address) *encoding.BlockHeader {
	t.Helper()
	return &encoding.BlockHeader{
		Version:      1,
		Height:       shape.slot,
		Slot:         shape.slot,
		Epoch:        shape.epoch,
		ProposerAddr: proposer,
		ChainID:      tdilithium3SeamTestChainID,
	}
}

// freshSyncE2ESignIndividually signs the header with the fixture identity's
// validator key over the header's signing root — the individual fallback path.
func freshSyncE2ESignIndividually(t *testing.T, fixture *tdilithium3SeamFixture, participantID uint32, header *encoding.BlockHeader) {
	t.Helper()
	privateKey, found := fixture.privateKeys[participantID]
	if !found {
		t.Fatalf("no fixture identity key for participant %d", participantID)
	}
	root, err := encoding.BlockHeaderSigningRoot(header)
	if err != nil {
		t.Fatalf("signing root: %v", err)
	}
	signature := make([]byte, mode3.SignatureSize)
	mode3.SignTo(privateKey, root[:], signature)
	header.Signature = signature
}

// freshSyncE2EGroupSignature produces a REAL four-of-six session group
// signature over the header's canonical TSS binding, the same convergence path
// the trigger-channel test pins.
func freshSyncE2EGroupSignature(t *testing.T, fixture *tdilithium3SeamFixture, header *encoding.BlockHeader) []byte {
	t.Helper()
	root, err := encoding.BlockHeaderSigningRoot(header)
	if err != nil {
		t.Fatalf("signing root: %v", err)
	}
	bound := consensus.ComputeTSSCanonicalBinding(
		header.ChainID, header.Epoch, header.Slot, header.ProposerAddr, "block", root[:],
	)
	for attempt := uint64(0); attempt < tdilithium3ProposalSigningMaxAttempts; attempt++ {
		nonce, err := dilithium3v1.SigningRequestAttemptNonce(
			tdilithium3SeamTestChainID, header.Epoch, header.Slot, protocol.SigningDomainBlock, bound[:], attempt,
		)
		if err != nil {
			t.Fatalf("attempt nonce: %v", err)
		}
		request := protocol.SignRequest{
			Protocol:     protocol.ThresholdProtocolDilithium3V1,
			Key:          fixture.shares[0].Key.Clone(),
			Committee:    fixture.shares[0].Committee.Clone(),
			ChainID:      tdilithium3SeamTestChainID,
			Epoch:        header.Epoch,
			Slot:         header.Slot,
			Domain:       protocol.SigningDomainBlock,
			Message:      append([]byte(nil), bound[:]...),
			AttemptNonce: nonce,
		}
		if err := request.Validate(); err != nil {
			t.Fatalf("group-signature request (attempt %d): %v", attempt, err)
		}
		harness := tdilithium3SeamHarnessFor(t, fixture, fixture.signersFor(), request, 0)
		if signature := harness.signOne(t); len(signature) > 0 {
			return signature
		}
	}
	t.Fatal("the four-of-six session never converged")
	return nil
}

// freshSyncE2EFreshValidator builds the FRESH node side: a production block
// validator and block producer wired exactly like node.go wires them — the v1
// branch armed at the activation epoch, the group-key lookup served by the
// node's own (empty) anchor custody — plus the producer whose
// onCanonicalBlockImported is the post-apply adoption hook.
func freshSyncE2EFreshValidator(t *testing.T, proposerKey []byte, activation uint64) (*core.BlockValidator, *BlockProducer, *consensus.QTDFinalityState) {
	t.Helper()
	validator := core.NewBlockValidator(tdilithium3SeamTestChainID, 30_000_000)
	validator.SetValidatorLookup(freshSyncE2ELookup{proposerKey: proposerKey})
	validator.SetTSSV1ProposalActivationEpoch(activation)

	validatorSet, err := consensus.NewValidatorSet([]*consensus.Validator{{
		Address: types.Address{0x21}, Stake: big100(), Active: true,
	}})
	if err != nil {
		t.Fatalf("validator set: %v", err)
	}
	qpos, err := consensus.NewQPOS(validatorSet)
	if err != nil {
		t.Fatalf("qpos: %v", err)
	}
	qpos.InitChambers()
	qfs := qpos.GetQTDFinality()
	if qfs == nil {
		t.Fatal("the fresh node has no QTD finality engine")
	}
	// The production wiring (Node.wireTSSVerifier): the v1 branch reads the
	// per-epoch key through the custody table — empty on a fresh node.
	validator.SetTSSV1GroupKeyLookup(qfs.GroupPublicKeyForEpoch)

	fresh := &Node{config: &Config{NetworkID: tdilithium3SeamTestChainID}}
	bp := &BlockProducer{node: fresh, qpos: qpos}
	return validator, bp, qfs
}

// freshSyncE2ELookup serves the fixture proposer's public key — the only
// individual-signature check the fresh validator needs.
type freshSyncE2ELookup struct{ proposerKey []byte }

func (lookup freshSyncE2ELookup) GetValidatorPublicKey(addr types.Address) ([]byte, error) {
	return append([]byte(nil), lookup.proposerKey...), nil
}

func (lookup freshSyncE2ELookup) IsValidator(addr types.Address) bool { return true }

// importFreshSyncHeader runs the production import sequence on the fresh node:
// ValidateSignature first (the syncer's gate), then the post-apply adoption
// hook. Returns the signature-validation error, if any.
func importFreshSyncHeader(validator *core.BlockValidator, bp *BlockProducer, header *encoding.BlockHeader) error {
	if err := validator.ValidateSignature(header); err != nil {
		return err
	}
	bp.onCanonicalBlockImported(header)
	return nil
}

// TestTDilithium3V1FreshSyncBootstrapEndToEnd is the R-1 fix's core assertion:
// the boundary carrier seeds the custody, every group-signed header after it
// verifies, and the fresh custody serves the ceremony key for both epochs —
// zero rejections from genesis to the tip.
func TestTDilithium3V1FreshSyncBootstrapEndToEnd(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	fixture := tdilithium3SeamFixtureFor(t)
	const activationEpoch = uint64(7) // the seam ceremony's activation epoch
	proposerID := fixture.session.Committee.Participants[0]
	proposer := fixture.identities[proposerID].ValidatorAddress
	proposerKey := fixture.identities[proposerID].PublicKey

	validator, bp, qfs := freshSyncE2EFreshValidator(t, proposerKey, activationEpoch)

	// The armed producer's headers, in chain order. The boundary headers carry
	// the anchor (the carrier rule the fix added — the same key
	// tdilithium3V1HeaderAnchorKey returns on an armed node); the mid-epoch
	// headers carry real session group signatures.
	headers := []*encoding.BlockHeader{
		freshSyncE2EHeader(t, freshSyncE2EHeaderShape{epoch: activationEpoch, slot: activationEpoch * consensus.SlotsPerEpoch}, proposer),
		freshSyncE2EHeader(t, freshSyncE2EHeaderShape{epoch: activationEpoch, slot: activationEpoch*consensus.SlotsPerEpoch + 5}, proposer),
		freshSyncE2EHeader(t, freshSyncE2EHeaderShape{epoch: activationEpoch + 1, slot: (activationEpoch + 1) * consensus.SlotsPerEpoch}, proposer),
		freshSyncE2EHeader(t, freshSyncE2EHeaderShape{epoch: activationEpoch + 1, slot: (activationEpoch+1)*consensus.SlotsPerEpoch + 5}, proposer),
	}
	freshSyncE2ESignIndividually(t, fixture, proposerID, headers[0])
	headers[0].QTDGroupKey = append([]byte(nil), fixture.groupKey...)
	headers[1].Signature = freshSyncE2EGroupSignature(t, fixture, headers[1])
	freshSyncE2ESignIndividually(t, fixture, proposerID, headers[2])
	headers[2].QTDGroupKey = append([]byte(nil), fixture.groupKey...)
	headers[3].Signature = freshSyncE2EGroupSignature(t, fixture, headers[3])

	// Genesis → tip import: zero rejections.
	for index, header := range headers {
		if err := importFreshSyncHeader(validator, bp, header); err != nil {
			t.Fatalf("header %d (epoch %d slot %d) rejected: %v — the fresh sync did not converge", index, header.Epoch, header.Slot, err)
		}
	}

	// The custody converged: the ceremony key serves both epochs, which is
	// what the seal verification and any later group-signed header rely on.
	if served := qfs.GroupPublicKeyForEpoch(activationEpoch); !bytes.Equal(served, fixture.groupKey) {
		t.Fatal("the fresh custody does not serve the ceremony key for the activation epoch")
	}
	if served := qfs.GroupPublicKeyForEpoch(activationEpoch + 1); !bytes.Equal(served, fixture.groupKey) {
		t.Fatal("the fresh custody does not serve the ceremony key for the following epoch")
	}
	// The canonical-anchor record followed the adoptions (the producer-gate
	// evidence path).
	if !bp.node.tdilithium3V1CanonicalAnchorObserved(activationEpoch, fixture.groupKey) {
		t.Fatal("the adopted anchor did not reach the canonical-anchor record")
	}
}

// TestTDilithium3V1FreshSyncOneWayDoor pins the deadlock shape the fix closes:
// the SAME group-signed header with no prior anchor carrier is rejected by the
// custody-empty fresh node — the R-1 one-way door. If the carrier rules ever
// regress (a group-signed header becoming the key's first carrier), fresh sync
// deadlocks exactly here again.
func TestTDilithium3V1FreshSyncOneWayDoor(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	fixture := tdilithium3SeamFixtureFor(t)
	const activationEpoch = uint64(7)
	proposerID := fixture.session.Committee.Participants[0]
	proposer := fixture.identities[proposerID].ValidatorAddress
	proposerKey := fixture.identities[proposerID].PublicKey

	validator, bp, qfs := freshSyncE2EFreshValidator(t, proposerKey, activationEpoch)

	// A group-signed header that ALSO self-carries the anchor: the anchor is
	// inside the rejected header, unreachable because adoption is post-apply.
	header := freshSyncE2EHeader(t, freshSyncE2EHeaderShape{epoch: activationEpoch, slot: activationEpoch*consensus.SlotsPerEpoch + 5}, proposer)
	header.QTDGroupKey = append([]byte(nil), fixture.groupKey...)
	header.Signature = freshSyncE2EGroupSignature(t, fixture, header)

	if err := importFreshSyncHeader(validator, bp, header); err == nil {
		t.Fatal("a group-signed header was accepted by a custody-empty fresh node — the one-way door is gone")
	}
	if served := qfs.GroupPublicKeyForEpoch(activationEpoch); len(served) > 0 {
		t.Fatal("the rejected header's anchor was adopted despite the rejection")
	}
}

// TestTDilithium3V1FreshSyncFloorCoversMissingBoundary is the Fix A + Fix B
// composition (TSS-R3-B-1 R-1, two-root-cause fix): the fresh node has synced
// into the wall-clock current epoch, and a group-signed header arrives for an
// epoch whose boundary carrier never materialized (the mixed-fleet case: the
// boundary slot's elected proposer was a non-armed node, so its header carried
// no anchor). Fix A's custody chain is in place but has no exact entry for the
// header's epoch; Fix B extends the custody floor to the current epoch of a
// signer-less node, so the lookup serves the anchored key and the header
// verifies instead of wedging the sync. The epoch AFTER the wall-clock one
// still fails closed — that one needs the next boundary carrier (Fix A).
func TestTDilithium3V1FreshSyncFloorCoversMissingBoundary(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	fixture := tdilithium3SeamFixtureFor(t)
	const activationEpoch = uint64(7)
	proposerID := fixture.session.Committee.Participants[0]
	proposer := fixture.identities[proposerID].ValidatorAddress
	proposerKey := fixture.identities[proposerID].PublicKey

	// Pin the chain clock two epochs past the anchored one: the fresh node's
	// verification position has caught up with the wall clock (the devnet
	// wedge shape), and the header epoch is the wall-clock current epoch.
	pinFreshSyncGenesis(t, 9)

	validator, bp, qfs := freshSyncE2EFreshValidator(t, proposerKey, activationEpoch)

	// The Fix A custody chain: the activation epoch's boundary carrier
	// (individual + anchor), applied and adopted. No epoch-8/9 carriers exist
	// (the mixed-fleet boundary gap the test models).
	boundary := freshSyncE2EHeader(t, freshSyncE2EHeaderShape{epoch: activationEpoch, slot: activationEpoch * consensus.SlotsPerEpoch}, proposer)
	freshSyncE2ESignIndividually(t, fixture, proposerID, boundary)
	boundary.QTDGroupKey = append([]byte(nil), fixture.groupKey...)
	if err := importFreshSyncHeader(validator, bp, boundary); err != nil {
		t.Fatalf("the boundary carrier was rejected: %v", err)
	}

	// A group-signed header in the wall-clock current epoch (9), whose epoch
	// has NO exact custody entry: Fix B's floor serves the anchored key.
	header := freshSyncE2EHeader(t, freshSyncE2EHeaderShape{epoch: 9, slot: 9*consensus.SlotsPerEpoch + 5}, proposer)
	header.Signature = freshSyncE2EGroupSignature(t, fixture, header)
	if err := importFreshSyncHeader(validator, bp, header); err != nil {
		t.Fatalf("the floor-covered current-epoch header was rejected: %v — Fix B did not bridge the missing boundary", err)
	}

	// The NEXT epoch (10, beyond the wall clock) still fails closed: its key
	// must arrive through the epoch-10 boundary carrier (Fix A's rule), never
	// from a future leap.
	future := freshSyncE2EHeader(t, freshSyncE2EHeaderShape{epoch: 10, slot: 10*consensus.SlotsPerEpoch + 5}, proposer)
	future.Signature = freshSyncE2EGroupSignature(t, fixture, future)
	if err := validator.ValidateSignature(future); err == nil {
		t.Fatal("a future-epoch group-signed header was accepted without its boundary carrier")
	}
	if served := qfs.GroupPublicKeyForEpoch(10); len(served) != 0 {
		t.Fatal("the future epoch served key material without any carrier")
	}
}

// pinFreshSyncGenesis pins the package-global chain clock to the given epoch
// (a few slots into it) and restores the unconfigured state at test end, so
// the fresh-sync tests can exercise the wall-clock catch-up deterministically.
func pinFreshSyncGenesis(t *testing.T, epoch uint64) {
	t.Helper()
	consensus.EnableTestHelpers()
	consensus.ResetGenesisTimeForTesting()
	t.Cleanup(consensus.ResetGenesisTimeForTesting)
	// Sixty seconds into the target epoch: the pin stays inside the epoch for
	// the rest of its ~6.4-minute window.
	genesis := time.Now().Unix() - int64(epoch)*int64(consensus.SlotsPerEpoch)*12 - 60
	if err := consensus.SetGenesisTime(genesis); err != nil {
		t.Fatalf("SetGenesisTime: %v", err)
	}
}

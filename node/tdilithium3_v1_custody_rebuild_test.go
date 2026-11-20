// Quantaureum Node source, version 1.0.0.
package node

// Regression tests for the cold-start anchor-custody recovery
// (tdilithium3_v1_custody_rebuild.go).
//
// The failure shape under test: a node restored from a snapshot (or rebuilt
// without its <datadir>.threshold-v1 store) holds canonical chain data but an
// empty anchor custody, so the first group-signed header after the restore tip
// is rejected forever. The tests drive the production startup rebuild against
// a real in-memory block store and assert the three required behaviors:
//
//  1. a chain carrying an epoch-boundary anchor rebuilds the custody at
//     startup, and the first group-signed block after the boundary validates;
//  2. the loud operator warning fires when the custody is empty and no share
//     store exists (and does not fire once a key source exists);
//  3. a healthy node (custody already covering the era) is untouched: the
//     rebuild is a no-op with no double registration.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/core"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// custodyRebuildChain builds a canonical chain in a fresh in-memory block
// store: heights 0..tipSlot with 1:1 height/slot mapping. Boundary blocks of
// the epochs named in anchoredEpochs carry the ceremony group key (the
// individually signed boundary carrier the armed producer writes).
func custodyRebuildChain(
	t *testing.T,
	fixture *tdilithium3SeamFixture,
	proposer types.Address,
	tipSlot uint64,
	anchoredEpochs map[uint64]bool,
) *block.BlockStore {
	t.Helper()
	store := block.NewBlockStore(db.NewMemDB())
	var parent types.Hash
	for height := uint64(0); height <= tipSlot; height++ {
		header := &encoding.BlockHeader{
			Version:      1,
			Height:       height,
			Slot:         height,
			Epoch:        height / consensus.SlotsPerEpoch,
			ParentHash:   parent,
			ProposerAddr: proposer,
			ChainID:      tdilithium3SeamTestChainID,
		}
		if anchoredEpochs[header.Epoch] && header.Slot%consensus.SlotsPerEpoch == 0 {
			header.QTDGroupKey = append([]byte(nil), fixture.groupKey...)
		}
		if err := store.PutBlock(&encoding.Block{Header: header}); err != nil {
			t.Fatalf("put block at height %d: %v", height, err)
		}
		parent = block.ComputeBlockHash(header)
	}
	return store
}

// custodyRebuildNode assembles the node under test: a production-shaped node
// with a real block store, a live QTD finality engine, and NO threshold share
// store (the DataDir is an empty temp directory).
func custodyRebuildNode(
	t *testing.T,
	store *block.BlockStore,
	qpos *consensus.QPOS,
	activation uint64,
) *Node {
	t.Helper()
	n := &Node{
		config: &Config{
			NetworkID:                    tdilithium3SeamTestChainID,
			TSSV1ProposalActivationEpoch: activation,
			DataDir:                      t.TempDir(),
		},
		blockStore: store,
	}
	n.blockProducer = &BlockProducer{node: n, qpos: qpos}
	return n
}

// custodyRebuildQPOS builds the live consensus engine with an empty anchor
// custody (the cold-start shape) and pins the package-global chain clock so
// the wall-clock current epoch is currentEpoch.
func custodyRebuildQPOS(t *testing.T, currentEpoch uint64) *consensus.QPOS {
	t.Helper()
	pinFreshSyncGenesis(t, currentEpoch)
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
	return qpos
}

// custodyRebuildValidator wires a production block validator exactly like the
// node does for the v1 branch (node.go: GroupPublicKeyForEpoch as the lookup).
func custodyRebuildValidator(activation uint64, proposerKey []byte, qfs *consensus.QTDFinalityState) *core.BlockValidator {
	validator := core.NewBlockValidator(tdilithium3SeamTestChainID, 30_000_000)
	validator.SetTSSV1ProposalActivationEpoch(activation)
	validator.SetTSSV1GroupKeyLookup(qfs.GroupPublicKeyForEpoch)
	if proposerKey != nil {
		validator.SetValidatorLookup(freshSyncE2ELookup{proposerKey: proposerKey})
	}
	return validator
}

// compareCustody reports whether two custody snapshots are identical.
func compareCustody(a, b map[uint64][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for epoch, key := range a {
		other, ok := b[epoch]
		if !ok || !bytes.Equal(key, other) {
			return false
		}
	}
	return true
}

// TestTDilithium3V1CustodyRebuildFromLocalChain is the restored-node fix: the
// threshold store is gone, the local canonical chain carries an epoch-boundary
// anchor, and the startup rebuild adopts it — so the first group-signed block
// after the boundary validates instead of wedging the node.
func TestTDilithium3V1CustodyRebuildFromLocalChain(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	fixture := tdilithium3SeamFixtureFor(t)
	const activationEpoch = uint64(7)
	const currentEpoch = uint64(9)
	proposerID := fixture.session.Committee.Participants[0]
	proposer := fixture.identities[proposerID].ValidatorAddress
	proposerKey := fixture.identities[proposerID].PublicKey

	tipSlot := currentEpoch*consensus.SlotsPerEpoch + 5
	store := custodyRebuildChain(t, fixture, proposer, tipSlot, map[uint64]bool{
		activationEpoch: true, 8: true, currentEpoch: true,
	})
	qpos := custodyRebuildQPOS(t, currentEpoch)
	qfs := qpos.GetQTDFinality()
	if qfs == nil {
		t.Fatal("no QTD finality engine")
	}
	n := custodyRebuildNode(t, store, qpos, activationEpoch)

	if qfs.HasGroupKeyCustodyAtOrAfter(activationEpoch) {
		t.Fatal("precondition: the cold-start custody must be empty")
	}

	// The exact restored-node failure, reproduced BEFORE the fix: with empty
	// custody the first group-signed header after the restore tip is rejected
	// (the v1 branch finds no key and the group signature fails individual
	// verification) — the stall the rebuild closes.
	validator := custodyRebuildValidator(activationEpoch, proposerKey, qfs)
	wedged := freshSyncE2EHeader(t, freshSyncE2EHeaderShape{epoch: currentEpoch, slot: tipSlot + 1}, proposer)
	wedged.Signature = freshSyncE2EGroupSignature(t, fixture, wedged)
	if err := validator.ValidateSignature(wedged); err == nil {
		t.Fatal("a group-signed header was accepted with empty custody — the incident shape is gone")
	}

	n.rebuildTDilithium3V1CustodyFromLocalChain()

	if served := qfs.GroupPublicKeyForEpoch(currentEpoch); !bytes.Equal(served, fixture.groupKey) {
		t.Fatal("the custody was not rebuilt from the local chain's boundary carrier")
	}
	// QTD-009: a future epoch fails closed until its own boundary carrier is
	// imported (the import path teaches it, exactly as for a live node).
	if served := qfs.GroupPublicKeyForEpoch(currentEpoch + 1); len(served) != 0 {
		t.Fatal("a future epoch served key material without its carrier")
	}
	// QTD-H03 floor semantics preserved: epochs below the adopted carrier have
	// no custody entry and fail closed, exactly as for a node that observed
	// only the most recent carrier live.
	if served := qfs.GroupPublicKeyForEpoch(activationEpoch); len(served) != 0 {
		t.Fatal("an epoch below the adopted carrier served key material")
	}
	// The rebuild adopts through ObserveAnchoredGroupKey only; it must not
	// touch the producer-gate canonical-anchor record (a restored node holds
	// no share, so the producer gate keeps its own stricter evidence rules).
	state := n.anchorState()
	if state.epoch != 0 || len(state.key) != 0 {
		t.Fatal("the custody rebuild touched the producer-gate canonical-anchor record")
	}

	// ...and fixed AFTER the rebuild: the same group-signed header now
	// validates under the rebuilt custody.
	header := freshSyncE2EHeader(t, freshSyncE2EHeaderShape{epoch: currentEpoch, slot: tipSlot + 1}, proposer)
	header.Signature = freshSyncE2EGroupSignature(t, fixture, header)
	if err := validator.ValidateSignature(header); err != nil {
		t.Fatalf("the first group-signed block after the rebuilt custody was rejected: %v", err)
	}
}

// TestTDilithium3V1CustodyRebuildGivesUpWithoutCarrier pins the bounded-scan
// contract: a chain whose epoch boundaries carry no anchor (mixed fleet) must
// leave the custody empty, and the operator warning must fire — restore the
// threshold store or set tssV1TrustedGroupKey.
func TestTDilithium3V1CustodyRebuildGivesUpWithoutCarrier(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	fixture := tdilithium3SeamFixtureFor(t)
	const activationEpoch = uint64(7)
	const currentEpoch = uint64(9)
	proposerID := fixture.session.Committee.Participants[0]
	proposer := fixture.identities[proposerID].ValidatorAddress

	tipSlot := currentEpoch*consensus.SlotsPerEpoch + 5
	store := custodyRebuildChain(t, fixture, proposer, tipSlot, nil) // no anchors at all
	qpos := custodyRebuildQPOS(t, currentEpoch)
	qfs := qpos.GetQTDFinality()
	n := custodyRebuildNode(t, store, qpos, activationEpoch)

	if n.tdilithium3V1LocalShareStoreExists() {
		t.Fatal("precondition: the temp DataDir must have no share store")
	}
	n.rebuildTDilithium3V1CustodyFromLocalChain()
	if qfs.HasGroupKeyCustodyAtOrAfter(activationEpoch) {
		t.Fatal("custody adopted key material from a chain with no anchor carrier")
	}
	advice, ok := n.tdilithium3V1CustodyAdvice()
	if !ok {
		t.Fatal("the unrecoverable-custody warning did not fire")
	}
	if !strings.Contains(advice, "threshold-v1") || !strings.Contains(advice, "tssV1TrustedGroupKey") {
		t.Fatalf("the advice does not name both remediations: %s", advice)
	}
	n.warnTDilithium3V1CustodyUnrecoverable() // smoke: the loud warning logs cleanly

	// A share store on disk (even without custody) means the operator has a
	// recovery path — the advice must stay quiet.
	paths, err := newThresholdProtocolPaths(n.config.DataDir, protocol.ThresholdProtocolDilithium3V1, 1, 1, 1)
	if err != nil {
		t.Fatalf("threshold paths: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(paths.Active), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(paths.Active, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !n.tdilithium3V1LocalShareStoreExists() {
		t.Fatal("the share-store existence probe missed the active share file")
	}
	if _, ok := n.tdilithium3V1CustodyAdvice(); ok {
		t.Fatal("the warning fired despite an existing share store")
	}
}

// TestTDilithium3V1CustodyRebuildNoOpWhenCustodyPresent is the healthy-node
// guard: with the custody already covering the era (a share-installed or
// trusted-key node), the rebuild must be a no-op — no rescan side effects, no
// double registration, no key change.
func TestTDilithium3V1CustodyRebuildNoOpWhenCustodyPresent(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	fixture := tdilithium3SeamFixtureFor(t)
	const activationEpoch = uint64(7)
	const currentEpoch = uint64(9)
	proposerID := fixture.session.Committee.Participants[0]
	proposer := fixture.identities[proposerID].ValidatorAddress

	tipSlot := currentEpoch*consensus.SlotsPerEpoch + 5
	store := custodyRebuildChain(t, fixture, proposer, tipSlot, map[uint64]bool{
		activationEpoch: true, 8: true, currentEpoch: true,
	})
	qpos := custodyRebuildQPOS(t, currentEpoch)
	qfs := qpos.GetQTDFinality()
	n := custodyRebuildNode(t, store, qpos, activationEpoch)

	// The healthy shape: registration re-rooted the custody to the active
	// ceremony's key (refreshTDilithium3SigningFinalitySigner's write path).
	qfs.ReRootGroupKeyCustody(activationEpoch, fixture.groupKey)
	before := qfs.GroupKeyCustodySnapshot()

	n.rebuildTDilithium3V1CustodyFromLocalChain()

	after := qfs.GroupKeyCustodySnapshot()
	if !compareCustody(before, after) {
		t.Fatalf("the rebuild mutated a healthy custody: before=%v after=%v", before, after)
	}
	if served := qfs.GroupPublicKeyForEpoch(currentEpoch); !bytes.Equal(served, fixture.groupKey) {
		t.Fatal("the healthy node's key changed")
	}
	if _, ok := n.tdilithium3V1CustodyAdvice(); ok {
		t.Fatal("the warning fired on a healthy node")
	}
}

// TestTDilithium3V1CustodyRebuildInactiveEra pins the era gate: before the
// activation epoch the rebuild must not scan or adopt anything.
func TestTDilithium3V1CustodyRebuildInactiveEra(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	fixture := tdilithium3SeamFixtureFor(t)
	const activationEpoch = uint64(7)
	const currentEpoch = uint64(5) // before activation
	proposerID := fixture.session.Committee.Participants[0]
	proposer := fixture.identities[proposerID].ValidatorAddress

	tipSlot := currentEpoch*consensus.SlotsPerEpoch + 3
	store := custodyRebuildChain(t, fixture, proposer, tipSlot, map[uint64]bool{3: true, 4: true, 5: true})
	qpos := custodyRebuildQPOS(t, currentEpoch)
	qfs := qpos.GetQTDFinality()
	n := custodyRebuildNode(t, store, qpos, activationEpoch)

	n.rebuildTDilithium3V1CustodyFromLocalChain()
	if len(qfs.GroupKeyCustodySnapshot()) != 0 {
		t.Fatal("the rebuild adopted anchors while the v1 era was inactive")
	}
	if _, ok := n.tdilithium3V1CustodyAdvice(); ok {
		t.Fatal("the warning fired before the v1 era was active")
	}
}

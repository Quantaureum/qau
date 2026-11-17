// Quantaureum Node source, version 1.0.0.
package node

// In-process end-to-end test of the skipped-epoch observer recovery
// (TSS-R3-B-1, P2-4 posture-r5). Full observer chain on the production code
// paths: the epoch-5 anchor is adopted through the canonical-block import
// hook, epoch 6 passes with NO anchor (the skip — clock-driven ceremonies
// outpaced chain time), the epoch-7 rotation anchor arrives with the epoch-5
// committee's handoff proof and is adopted through the skipped-epoch lane,
// and a group-signed epoch-7 header then verifies through the block
// validator's v1 group-signature branch under the adopted key. Before the
// epoch-7 anchor lands, the same header is rejected — that rejection is the
// P2-4 deadlock this fix removes.
//
// The handoff proof is an ordinary Dilithium3 signature under the previous
// committee's group public key — the same shape a threshold signing session
// produces (the v1 session output verifies as one mode3 signature under the
// group key). The proof PRODUCTION channel for the experimental runtime-DKG
// posture (which committee signs, and when) is the registered Wave F
// follow-up; this test stands in for it at the header level and drives
// everything downstream of the header on the real code paths. Test keys use
// deterministic DEVNET ONLY seeds.

import (
	"bytes"
	"crypto/sha3"
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/core"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// skipE2ESigningData mirrors the validator's computeSigningData stripping
// rule for the minimal fixture header (no stardust fields are set, so the
// signing data is the hash of the header with the signature fields nilled).
func skipE2ESigningData(header *encoding.BlockHeader) []byte {
	headerCopy := *header
	headerCopy.Signature = nil
	headerCopy.SyncCommitteeSig = nil
	headerCopy.SyncCommitteeBits = nil
	headerCopy.QTDSignature = nil
	headerCopy.ExecutiveSealers = nil
	headerCopy.ReviewAttestationRoot = types.Hash{}
	headerCopy.FinalityType = 0
	headerCopy.QTDGroupKey = nil
	headerCopy.QTDGroupKeyProof = nil
	raw, err := encoding.MarshalBlockHeader(&headerCopy)
	if err != nil || len(raw) == 0 {
		return nil
	}
	hash := sha3.Sum256(raw)
	return hash[:]
}

func TestTDilithium3SkippedEpochObserverRecoveryE2E(t *testing.T) {
	const chainID = uint64(1333)

	// Put the chain clock past epoch 10 so the observer's floor lookup serves
	// adopted keys for past epochs (the QTD-009 future-epoch rule fails closed
	// for epochs ahead of the chain clock). Restore afterwards; the genesis
	// clock is package-global.
	previousGenesis := consensus.GetGenesisTime()
	if err := consensus.SetGenesisTime(time.Now().Unix() - int64(consensus.EpochDuration/time.Second)*10 - 60); err != nil {
		t.Fatalf("set genesis time: %v", err)
	}
	t.Cleanup(func() { _ = consensus.SetGenesisTime(previousGenesis) })

	// Committee keys: epoch 5 (the last anchored era) and epoch 7 (the
	// rotation that must be adopted across the skipped epoch 6).
	kp5, err := qcrypto.GenerateKeyPairFromSeed([]byte("DEVNET ONLY skipped-epoch e2e head-5"))
	if err != nil {
		t.Fatalf("key5: %v", err)
	}
	key5 := kp5.Public.Bytes()
	kp7, err := qcrypto.GenerateKeyPairFromSeed([]byte("DEVNET ONLY skipped-epoch e2e rot-7"))
	if err != nil {
		t.Fatalf("key7: %v", err)
	}
	key7 := kp7.Public.Bytes()

	// Observer shell: no signer, real QPOS/QTD finality state, real producer
	// import hook, real block validator with the v1 group branch wired to the
	// custody export exactly as node.go's initConsensus does.
	qpos, err := consensus.NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qpos.InitChambers()
	qfs := qpos.GetQTDFinality()
	if qfs == nil {
		t.Fatal("QTD finality state not initialized")
	}
	qfs.SetChainID(chainID)

	n := &Node{}
	bp := &BlockProducer{node: n, qpos: qpos}

	validator := core.NewBlockValidator(chainID, 30_000_000)
	validator.SetTSSV1ProposalActivationEpoch(1)
	validator.SetTSSV1GroupKeyLookup(qfs.GroupPublicKeyForEpoch)

	proposer := types.BytesToAddress([]byte("skip-epoch-e2e-proposer"))

	// Epoch 5 boundary anchor: first establishment (observer, trust-on-first-
	// use to the canonical chain), unchanged discipline.
	epoch5Boundary := &encoding.BlockHeader{
		ChainID:      chainID,
		Epoch:        5,
		Slot:         consensus.EpochStartSlot(5),
		ProposerAddr: proposer,
		QTDGroupKey:  append([]byte(nil), key5...),
	}
	bp.onCanonicalBlockImported(epoch5Boundary)
	if got := qfs.GroupPublicKeyForEpoch(5); len(got) == 0 {
		t.Fatal("epoch-5 anchor not adopted on the import path")
	}

	// Epoch 6: SKIPPED — no block, no anchor. Nothing to import.

	// A group-signed epoch-7 header signed with the epoch-7 committee key: the
	// block the observer must be able to verify once the rotation lands.
	groupHeader := &encoding.BlockHeader{
		ChainID:      chainID,
		Epoch:        7,
		Slot:         consensus.EpochStartSlot(7) + 1,
		ProposerAddr: proposer,
	}
	signingData := skipE2ESigningData(groupHeader)
	if signingData == nil {
		t.Fatal("signing data serialization failed")
	}
	bound := consensus.ComputeTSSCanonicalBinding(chainID, 7, groupHeader.Slot, proposer, "block", signingData)
	groupSig, err := qcrypto.Sign(kp7.Private, bound[:])
	if err != nil {
		t.Fatalf("group sign: %v", err)
	}
	groupHeader.Signature = groupSig

	// Before the epoch-7 anchor lands, the observer cannot verify the
	// rotation's group signatures: the custody floor still serves the epoch-5
	// key, the group check fails, and the individual fallback fails too. This
	// is exactly the P2-4 deadlock state.
	if err := validator.ValidateSignature(groupHeader); err == nil {
		t.Fatal("group-signed epoch-7 header accepted before the rotation anchor landed")
	}

	// The epoch-7 boundary anchor with the epoch-5 committee's handoff proof
	// over exactly (chainID, 7, key7, committeeVersion 1). Through the import
	// hook this exercises the skipped-epoch lane end to end.
	proof, err := qcrypto.Sign(kp5.Private, consensus.QTDHandoffMessage(chainID, 7, key7, 1))
	if err != nil {
		t.Fatalf("handoff sign: %v", err)
	}
	epoch7Boundary := &encoding.BlockHeader{
		ChainID:          chainID,
		Epoch:            7,
		Slot:             consensus.EpochStartSlot(7),
		ProposerAddr:     proposer,
		QTDGroupKey:      append([]byte(nil), key7...),
		QTDGroupKeyProof: append([]byte(nil), proof...),
	}
	bp.onCanonicalBlockImported(epoch7Boundary)

	// The rotation is adopted and served; the deadlock is broken.
	if got := qfs.GroupPublicKeyForEpoch(7); len(got) == 0 || !bytes.Equal(got, key7) {
		t.Fatal("skipped-epoch rotation key not served after adoption")
	}
	if err := validator.ValidateSignature(groupHeader); err != nil {
		t.Fatalf("group-signed epoch-7 header rejected after the skipped-epoch adoption: %v", err)
	}
}

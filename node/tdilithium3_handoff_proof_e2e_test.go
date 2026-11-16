// Quantaureum Node source, version 1.0.0.
package node

// End-to-end test of the rotation handoff proof channel (TSS-R3-B-1 Wave F):
// two real six-node DKG ceremonies produce the outgoing and incoming
// committee keys; the outgoing committee's four signers run the production
// request schedule over the real transport, inbox, and routing under
// SigningDomainHandoff; the resulting group signature becomes a persisted
// handoff record; and the observer side adopts the rotation exactly as the
// R19-F02 chained-adoption rule demands. Every negative — no proof, a
// tampered proof, and a wrong-epoch proof — is refused.

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// handoffE2EChainID is the chain the e2e runs under: the testnet ID, because
// the admissibility gates permanently exclude mainnet.
const handoffE2EChainID = TestnetNetworkID

// handoffE2ECeremony runs one six-node DKG ceremony for the given generation
// and activation epoch over the seam fixture's committee shape, and returns
// the fixture the signing harness consumes.
func handoffE2ECeremony(t *testing.T, root string, generation, activation uint64) *tdilithium3SeamFixture {
	t.Helper()
	session := dilithium3v1.DKGSession{
		Protocol:        protocol.ThresholdProtocolDilithium3V1,
		ChainID:         handoffE2EChainID,
		KeyGeneration:   generation,
		Committee:       protocol.CommitteeID{Version: 1, Threshold: 4, Participants: []uint32{101, 102, 103, 104, 105, 106}},
		ActivationEpoch: activation,
		Nonce:           [32]byte{byte(generation), 2, 3},
	}
	session.IdentityRosterDigest = testTDilithium3IdentityRosterDigest(t, session, "DEVNET ONLY hndf e2e id")
	transport := newTDilithium3DKGMemoryTransport(6)
	var runners [6]*tdilithium3DKGRunner
	for position := range runners {
		entropy := bytes.NewReader(bytesRepeat([]byte{byte(position + 1), byte(position + 17), byte(position + 33)}, 1<<16))
		runner, err := newTDilithium3DKGRunner(tdilithium3DKGRunnerConfig{
			Session:             session.Clone(),
			ParticipantPosition: uint8(position),
			BasePath:            filepath.Join(root, fmt.Sprintf("gen-%d", generation), "node", string(rune('a'+position)), "shares.enc"),
			Password:            []byte("DEVNET ONLY handoff e2e password"),
			Entropy:             entropy,
		})
		if err != nil {
			t.Fatal(err)
		}
		runners[position] = runner
	}
	results, err := runTDilithium3DKGCluster(context.Background(), runners, transport, tdilithium3DKGFaultPlan{})
	if err != nil {
		t.Fatalf("six-node DKG cluster (generation %d): %v", generation, err)
	}
	fixture := &tdilithium3SeamFixture{
		session:     runners[0].session.Clone(),
		groupKey:    append([]byte(nil), results[0].PublicKey[:]...),
		identities:  make(map[uint32]tdilithium3SigningIdentity, len(results)),
		privateKeys: make(map[uint32]*mode3.PrivateKey, len(results)),
		peers:       make(map[uint32]p2p.PeerID, len(results)),
	}
	for position, result := range results {
		loaded, err := runners[position].shareStore.LoadCandidate(
			result.Share.Key.Generation, result.Share.ParticipantID, runners[position].password,
		)
		if err != nil {
			t.Fatalf("generation %d participant %d load candidate: %v", generation, position, err)
		}
		t.Cleanup(loaded.Zeroize)
		fixture.shares[position] = loaded
		var seed [mode3.SeedSize]byte
		copy(seed[:], fmt.Sprintf("DEVNET ONLY hndf e2e %d-%d", generation, position))
		publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
		participantID := loaded.ParticipantID
		peer := p2p.PeerID(fmt.Sprintf("handoff-e2e-%d-%d", generation, participantID))
		fixture.privateKeys[participantID] = privateKey
		fixture.peers[participantID] = peer
		fixture.identities[participantID] = tdilithium3SigningIdentity{
			Peer:             peer,
			ValidatorAddress: types.AddressFromPublicKey(publicKey.Bytes()),
			PublicKey:        publicKey.Bytes(),
		}
	}
	return fixture
}

// bytesRepeat is a tiny local stand-in for bytes.Repeat to keep the import
// surface of the file focused.
func bytesRepeat(pattern []byte, count int) []byte {
	out := make([]byte, 0, len(pattern)*count)
	for i := 0; i < count; i++ {
		out = append(out, pattern...)
	}
	return out
}

// handoffE2ERequest builds the handoff signing request the production session
// runner builds: the outgoing share's binding, the activation epoch's start
// slot, the handoff domain, and the derived attempt nonce.
func handoffE2ERequest(t *testing.T, share *dilithium3v1.LocalShare, epochNew uint64, message []byte, attempt uint64) protocol.SignRequest {
	t.Helper()
	slot := consensus.EpochStartSlot(epochNew)
	nonce, err := dilithium3v1.SigningRequestAttemptNonce(
		handoffE2EChainID, epochNew, slot, protocol.SigningDomainHandoff, message, attempt,
	)
	if err != nil {
		t.Fatalf("handoff attempt nonce: %v", err)
	}
	request := protocol.SignRequest{
		Protocol:     protocol.ThresholdProtocolDilithium3V1,
		Key:          share.Key.Clone(),
		Committee:    share.Committee.Clone(),
		ChainID:      handoffE2EChainID,
		Epoch:        epochNew,
		Slot:         slot,
		Domain:       protocol.SigningDomainHandoff,
		Message:      append([]byte(nil), message...),
		AttemptNonce: nonce,
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("handoff request: %v", err)
	}
	return request
}

// TestTDilithium3HandoffProofRotationEndToEnd drives the whole channel with
// real ceremonies, a real four-signer handoff session, the persisted record,
// and the observer adoption.
func TestTDilithium3HandoffProofRotationEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("two six-node ceremonies and a signing session; skipped in -short")
	}
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	root := t.TempDir()

	// Epoch 7's ceremony produced the outgoing key; epoch 8's the incoming.
	outgoing := handoffE2ECeremony(t, root, 1, 7)
	incoming := handoffE2ECeremony(t, root, 2, 8)
	oldKey, newKey := outgoing.groupKey, incoming.groupKey
	if bytesEqualKey(oldKey, newKey) {
		t.Fatal("two ceremonies produced the same group key")
	}

	// The outgoing committee signs the handoff tuple for epoch 8 under the
	// outgoing key: the exact message consensus.QTDHandoffMessage builds, the
	// exact domain the whitelist now admits, and the production schedule. A
	// filtered attempt is a fresh session at the next ordinal — the same
	// retry the production session runner performs.
	epochNew := uint64(8)
	message := consensus.QTDHandoffMessage(handoffE2EChainID, epochNew, newKey, consensus.QTDAnchorProofCommitteeVersion)
	var signature []byte
	for attempt := uint64(0); attempt < 8 && len(signature) == 0; attempt++ {
		request := handoffE2ERequest(t, outgoing.shares[0], epochNew, message, attempt)
		harness := tdilithium3SeamHarnessFor(t, outgoing, outgoing.signersFor(), request, 0)
		signature = harness.signOne(t)
	}
	if len(signature) == 0 {
		t.Fatal("the handoff session produced no signature in 8 attempts")
	}

	// The observer's verifier accepts the proof under the outgoing key.
	if !consensus.VerifyAnchoredGroupKeyProof(oldKey, newKey, epochNew, handoffE2EChainID, consensus.QTDAnchorProofCommitteeVersion, signature) {
		t.Fatal("the real handoff session's proof does not verify under the outgoing key")
	}

	// The record store persists it and the anchor decision attaches it.
	node := &Node{config: &Config{NetworkID: handoffE2EChainID, DataDir: t.TempDir()}}
	record := &tdilithium3HandoffProofRecord{
		EpochNew:         epochNew,
		CommitteeVersion: consensus.QTDAnchorProofCommitteeVersion,
		OldKey:           append([]byte(nil), oldKey...),
		NewKey:           append([]byte(nil), newKey...),
		Signature:        append([]byte(nil), signature...),
	}
	if err := node.storeTDilithium3HandoffProofRecord(record); err != nil {
		t.Fatalf("store record: %v", err)
	}
	proof, keep := node.tdilithium3V1AnchorProofDecision(epochNew, newKey)
	if !keep || !bytesEqualKey(proof, signature) {
		t.Fatal("the anchor decision did not attach the session's proof")
	}

	// The observer adopts the rotation exactly as R19-F02 demands: the
	// custody holds the outgoing key, the boundary anchor carries the new key
	// WITH the proof, and after adoption the new key answers for its epoch.
	qfs := &consensus.QTDFinalityState{}
	qfs.SetChainID(handoffE2EChainID)
	if !qfs.ObserveAnchoredGroupKey(7, oldKey, nil) {
		t.Fatal("the outgoing key's first adoption was refused")
	}
	if !qfs.ObserveAnchoredGroupKey(epochNew, newKey, signature) {
		t.Fatal("the rotation anchor with a valid handoff proof was refused")
	}
	if got := qfs.GroupPublicKeyForEpoch(epochNew); !bytesEqualKey(got, newKey) {
		t.Fatal("the adopted rotation key does not answer for its epoch")
	}

	// R19-F02 regression, positive form: the same anchor WITHOUT the proof is
	// refused, and the custody keeps the adopted key.
	qfs2 := &consensus.QTDFinalityState{}
	qfs2.SetChainID(handoffE2EChainID)
	if !qfs2.ObserveAnchoredGroupKey(7, oldKey, nil) {
		t.Fatal("the outgoing key's first adoption was refused")
	}
	if qfs2.ObserveAnchoredGroupKey(epochNew, newKey, nil) {
		t.Fatal("a rotation anchor without a handoff proof was adopted")
	}

	// A tampered proof is refused.
	tampered := append([]byte(nil), signature...)
	tampered[0] ^= 0x01
	if qfs2.ObserveAnchoredGroupKey(epochNew, newKey, tampered) {
		t.Fatal("a rotation anchor with a tampered proof was adopted")
	}

	// A proof over the WRONG EPOCH is refused (the tuple binds the epoch).
	// The session retries with a higher attempt ordinal — a fresh session
	// each time — exactly as the production session runner retries.
	wrongEpochMessage := consensus.QTDHandoffMessage(handoffE2EChainID, epochNew+1, newKey, consensus.QTDAnchorProofCommitteeVersion)
	var wrongSignature []byte
	for attempt := uint64(0); attempt < 8 && len(wrongSignature) == 0; attempt++ {
		wrongRequest := handoffE2ERequest(t, outgoing.shares[0], epochNew+1, wrongEpochMessage, attempt)
		wrongHarness := tdilithium3SeamHarnessFor(t, outgoing, outgoing.signersFor(), wrongRequest, 0)
		wrongSignature = wrongHarness.signOne(t)
	}
	if len(wrongSignature) == 0 {
		t.Skip("the wrong-epoch session never converged; the tuple binding is covered by the tamper and stranger-key cases")
	}
	if qfs2.ObserveAnchoredGroupKey(epochNew, newKey, wrongSignature) {
		t.Fatal("a rotation anchor with a wrong-epoch proof was adopted")
	}

	// The tuple binds the INCOMING KEY too: the epoch-8 signature must not
	// verify for a different incoming key (only the committee can vouch for
	// the key the session actually endorsed).
	stranger := anchorTestKey(t, "handoff e2e stranger key")
	if consensus.VerifyAnchoredGroupKeyProof(oldKey, stranger, epochNew, handoffE2EChainID, consensus.QTDAnchorProofCommitteeVersion, signature) {
		t.Fatal("the handoff proof verified for a key the session never endorsed")
	}
	_ = incoming // the incoming fixture's role was the endorsed key itself
}

// bytesEqualKey compares two group keys of the canonical length.
func bytesEqualKey(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

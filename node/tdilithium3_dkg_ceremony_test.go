// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// Wiring tests for the Dilithium3 v1 DKG ceremony (session-derivation design,
// section 7, items 1-6). They exercise the production entry point that used to
// have no caller: session derivation from chain state, the roster epoch rule
// (D1), the committee rule (D2), the identity-key agreement check (D6) and the
// backend selection that must never fall back to the legacy group key (D8/D9).

// tdilithium3DKGCeremonyTestIdentity is one DEVNET-only committee member: the
// roster entry every participant would read plus the private key that makes it
// the local validator of a test node.
type tdilithium3DKGCeremonyTestIdentity struct {
	Entry tdilithium3DKGEpochRosterEntry
	Key   *qcrypto.PrivateKey
}

// tdilithium3DKGCeremonyTestIdentities derives count real Dilithium3 identities
// and returns them in canonical ascending-address order, which is the order the
// roster digest is defined over.
func tdilithium3DKGCeremonyTestIdentities(t *testing.T, count int) []tdilithium3DKGCeremonyTestIdentity {
	t.Helper()
	identities := make([]tdilithium3DKGCeremonyTestIdentity, 0, count)
	seen := make(map[types.Address]bool, count)
	for position := 0; position < count; position++ {
		pair, err := qcrypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("generate identity %d: %v", position, err)
		}
		address := pair.Public.Address()
		if seen[address] {
			t.Fatalf("generated a duplicate identity address at position %d", position)
		}
		seen[address] = true
		identities = append(identities, tdilithium3DKGCeremonyTestIdentity{
			Entry: tdilithium3DKGEpochRosterEntry{Address: address, PublicKey: pair.Public.Bytes()},
			Key:   pair.Private,
		})
	}
	sort.Slice(identities, func(left, right int) bool {
		return bytes.Compare(identities[left].Entry.Address[:], identities[right].Entry.Address[:]) < 0
	})
	return identities
}

func tdilithium3DKGCeremonyTestEntries(identities []tdilithium3DKGCeremonyTestIdentity) []tdilithium3DKGEpochRosterEntry {
	entries := make([]tdilithium3DKGEpochRosterEntry, len(identities))
	for position := range identities {
		entries[position] = identities[position].Entry
	}
	return entries
}

// tdilithium3DKGCeremonyTestNode builds a node that satisfies everything the
// ceremony needs before its first outbound message: a data dir, a genesis block
// and a block producer whose local identity is identities[position].
func tdilithium3DKGCeremonyTestNode(t *testing.T, identities []tdilithium3DKGCeremonyTestIdentity, position int) *Node {
	t.Helper()
	return &Node{
		config: &Config{
			DataDir:              t.TempDir(),
			NetworkID:            TestnetNetworkID,
			ValidatorKeyPassword: "DEVNET ONLY ceremony wiring test password",
		},
		genesisBlock: &encoding.Block{Header: &encoding.BlockHeader{Height: 0, Slot: 0, Epoch: 0}},
		blockProducer: &BlockProducer{
			validatorKey:  identities[position].Key,
			validatorAddr: identities[position].Entry.Address,
		},
	}
}

// captureTDilithium3DKGCeremonyRoster captures epochs 5..activation-1 so that the
// store's bootstrap boundary (5) sits strictly below the roster epoch the
// ceremony reads (activation-1 = 6 for activation epoch 7).
func captureTDilithium3DKGCeremonyRoster(t *testing.T, node *Node, entries []tdilithium3DKGEpochRosterEntry) {
	t.Helper()
	store := node.tdilithium3DKGEpochRosterStoreForUse()
	if store == nil {
		t.Fatal("the roster sidecar was not created with the gates open and a data dir")
	}
	if err := store.capture(5, tdilithium3DKGRosterTestHash(0x90), entries, 4); err != nil {
		t.Fatalf("capture epoch 5: %v", err)
	}
	if err := store.capture(6, tdilithium3DKGRosterTestHash(0x91), entries, 5); err != nil {
		t.Fatalf("capture epoch 6: %v", err)
	}
}

func openTDilithium3DKGCeremonyGates(t *testing.T) {
	t.Helper()
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
}

// TestTDilithium3DKGSessionDerivationIsDeterministicAndChainBound covers design
// section 7 item 1. Two nodes built independently from the same chain state and
// the same roster derive the same session digest — which is what lets a
// restarted node resume the attempt it was already in, because the journal is
// keyed by that digest. Every chain-anchored input changes the digest.
func TestTDilithium3DKGSessionDerivationIsDeterministicAndChainBound(t *testing.T) {
	openTDilithium3DKGCeremonyGates(t)
	identities := tdilithium3DKGCeremonyTestIdentities(t, 6)
	entries := tdilithium3DKGCeremonyTestEntries(identities)

	first := tdilithium3DKGCeremonyTestNode(t, identities, 2)
	captureTDilithium3DKGCeremonyRoster(t, first, entries)
	second := tdilithium3DKGCeremonyTestNode(t, identities, 2)
	captureTDilithium3DKGCeremonyRoster(t, second, entries)

	baseline, err := first.deriveTDilithium3DKGSession(7)
	if err != nil {
		t.Fatalf("derive session: %v", err)
	}
	repeated, err := second.deriveTDilithium3DKGSession(7)
	if err != nil {
		t.Fatalf("derive session on the second node: %v", err)
	}
	baselineDigest, err := baseline.Digest()
	if err != nil {
		t.Fatalf("session digest: %v", err)
	}
	repeatedDigest, err := repeated.Digest()
	if err != nil {
		t.Fatalf("second session digest: %v", err)
	}
	if baselineDigest != repeatedDigest {
		t.Fatal("two nodes with the same chain state derived different sessions")
	}
	if baseline.Committee.Threshold != 4 || len(baseline.Committee.Participants) != 6 {
		t.Fatalf("derived session is not the four-of-six profile: %+v", baseline.Committee)
	}
	if baseline.ActivationEpoch != 7 {
		t.Fatalf("derived session activation epoch = %d, want 7", baseline.ActivationEpoch)
	}
	if baseline.KeyGeneration != 7 {
		t.Fatalf("derived session key generation = %d, want the activation epoch (D4)", baseline.KeyGeneration)
	}

	// A different activation epoch reads a different roster epoch and therefore a
	// different session, so an aborted attempt is never retried as the same one.
	if err := first.tdilithium3DKGEpochRosterStore.capture(7, tdilithium3DKGRosterTestHash(0x92), entries, 6); err != nil {
		t.Fatalf("capture epoch 7: %v", err)
	}
	later, err := first.deriveTDilithium3DKGSession(8)
	if err != nil {
		t.Fatalf("derive session for the next epoch: %v", err)
	}
	laterDigest, err := later.Digest()
	if err != nil {
		t.Fatalf("next-epoch session digest: %v", err)
	}
	if laterDigest == baselineDigest {
		t.Fatal("a different activation epoch produced the same session digest")
	}

	// A different chain id, a different genesis block and a different roster all
	// have to change the digest, otherwise two chains or two forks could collide.
	for name, mutate := range map[string]func(node *Node){
		"chain id":      func(node *Node) { node.config.NetworkID = TestnetNetworkID + 1 },
		"genesis block": func(node *Node) { node.genesisBlock.Header.Epoch = 1 },
	} {
		node := tdilithium3DKGCeremonyTestNode(t, identities, 2)
		captureTDilithium3DKGCeremonyRoster(t, node, entries)
		mutate(node)
		mutated, err := node.deriveTDilithium3DKGSession(7)
		if err != nil {
			t.Fatalf("%s: derive session: %v", name, err)
		}
		mutatedDigest, err := mutated.Digest()
		if err != nil {
			t.Fatalf("%s: session digest: %v", name, err)
		}
		if mutatedDigest == baselineDigest {
			t.Fatalf("the session digest did not change when the %s changed", name)
		}
	}

	// Replacing a not-yet-finalized epoch's boundary legitimately replaces the
	// roster, so the same epoch now digests differently. Only a member other than
	// the local validator is replaced, so the local node stays a committee member
	// and the digest change is the only difference.
	swapped := append([]tdilithium3DKGEpochRosterEntry(nil), entries...)
	swapped[0] = tdilithium3DKGCeremonyTestIdentities(t, 1)[0].Entry
	replaced := tdilithium3DKGCeremonyTestNode(t, identities, 2)
	captureTDilithium3DKGCeremonyRoster(t, replaced, entries)
	if err := replaced.tdilithium3DKGEpochRosterStore.capture(6, tdilithium3DKGRosterTestHash(0x93), swapped, 5); err != nil {
		t.Fatalf("replace the epoch 6 roster: %v", err)
	}
	replacedSession, err := replaced.deriveTDilithium3DKGSession(7)
	if err != nil {
		t.Fatalf("derive session over the replaced roster: %v", err)
	}
	replacedDigest, err := replacedSession.Digest()
	if err != nil {
		t.Fatalf("replaced-roster session digest: %v", err)
	}
	if replacedDigest == baselineDigest {
		t.Fatal("a different roster produced the same session digest")
	}

	// Epoch 1 has no lower boundary to anchor on.
	if _, err := first.deriveTDilithium3DKGSession(1); !errors.Is(err, errTDilithium3DKGSessionUnavailable) {
		t.Fatalf("activation epoch 1 was accepted: %v", err)
	}
	// A node without a genesis block cannot bind the session to this chain.
	orphan := tdilithium3DKGCeremonyTestNode(t, identities, 2)
	orphan.genesisBlock = nil
	captureTDilithium3DKGCeremonyRoster(t, orphan, entries)
	if _, err := orphan.deriveTDilithium3DKGSession(7); !errors.Is(err, errTDilithium3DKGSessionUnavailable) {
		t.Fatalf("a node without a genesis block derived a session: %v", err)
	}
	// A roster that was never captured fails closed instead of falling back
	// to the live validator set. The bootstrap boundary itself is servable:
	// it is the first boundary this node observed while applying its own
	// blocks, so the whole boundary was captured (session-derivation spec,
	// bootstrap-rule revision, R74).
	uncaptured, err := first.deriveTDilithium3DKGSession(10)
	if !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("an uncaptured roster epoch produced a session (%v, %v)", uncaptured.ActivationEpoch, err)
	}
	if _, err := first.tdilithium3DKGEpochRosterBindings(baseline, 4); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("an epoch below the bootstrap boundary was served as a roster epoch: %v", err)
	}
	if _, err := first.tdilithium3DKGEpochRosterBindings(baseline, 5); err != nil {
		t.Fatalf("the bootstrap boundary was not servable as a roster epoch: %v", err)
	}
}

// TestTDilithium3DKGCommitteeFollowsRosterOrder covers design section 7 item 2.
// The committee is the roster in canonical order with participant IDs
// position+1, and the local node's recipient position is its roster position.
func TestTDilithium3DKGCommitteeFollowsRosterOrder(t *testing.T) {
	openTDilithium3DKGCeremonyGates(t)
	identities := tdilithium3DKGCeremonyTestIdentities(t, 6)
	entries := tdilithium3DKGCeremonyTestEntries(identities)

	for position := range identities {
		node := tdilithium3DKGCeremonyTestNode(t, identities, position)
		captureTDilithium3DKGCeremonyRoster(t, node, entries)
		roster, err := node.capturedEpochValidatorRoster(6)
		if err != nil {
			t.Fatalf("read the captured roster: %v", err)
		}
		committee, local, err := node.tdilithium3DKGCommitteeForRoster(roster)
		if err != nil {
			t.Fatalf("committee for roster: %v", err)
		}
		if committee.Version != 1 || committee.Threshold != 4 {
			t.Fatalf("committee = %+v, want version 1 threshold 4", committee)
		}
		want := []uint32{1, 2, 3, 4, 5, 6}
		if len(committee.Participants) != len(want) {
			t.Fatalf("committee participants = %v, want %v", committee.Participants, want)
		}
		for index, participantID := range committee.Participants {
			if participantID != want[index] {
				t.Fatalf("committee participants = %v, want %v", committee.Participants, want)
			}
		}
		if int(local) != position {
			t.Fatalf("local validator %s landed at committee position %d, want %d",
				identities[position].Entry.Address.String(), local, position)
		}
	}

	// A roster whose size differs from the profile is refused rather than
	// subsetted, and a node that is not in the roster has no position.
	candidates := tdilithium3DKGCeremonyTestIdentities(t, 7)
	node := tdilithium3DKGCeremonyTestNode(t, candidates, 0)
	captureTDilithium3DKGCeremonyRoster(t, node, tdilithium3DKGCeremonyTestEntries(candidates[:6]))
	roster, err := node.capturedEpochValidatorRoster(6)
	if err != nil {
		t.Fatalf("read the captured roster: %v", err)
	}
	if _, _, err := node.tdilithium3DKGCommitteeForRoster(nil); !errors.Is(err, errTDilithium3DKGSessionUnavailable) {
		t.Fatalf("a missing roster produced a committee: %v", err)
	}
	shrunk := *roster
	shrunk.Entries = roster.Entries[:5]
	if _, _, err := node.tdilithium3DKGCommitteeForRoster(&shrunk); !errors.Is(err, errTDilithium3DKGSessionUnavailable) {
		t.Fatalf("a five-member roster produced a committee: %v", err)
	}
	// The seventh identity is deliberately outside the six-member roster.
	foreign := tdilithium3DKGCeremonyTestNode(t, candidates, 6)
	if _, _, err := foreign.tdilithium3DKGCommitteeForRoster(roster); !errors.Is(err, errTDilithium3DKGSessionUnavailable) {
		t.Fatalf("a node outside the roster produced a committee: %v", err)
	}
}

// TestTDilithium3DKGIdentityKeyMustMatchRosterEntry covers design section 7 item
// 4 (D6). A node whose signing key is not the identity key its roster position
// publishes must refuse to start, because every peer would reject its envelopes.
func TestTDilithium3DKGIdentityKeyMustMatchRosterEntry(t *testing.T) {
	openTDilithium3DKGCeremonyGates(t)
	identities := tdilithium3DKGCeremonyTestIdentities(t, 6)
	entries := tdilithium3DKGCeremonyTestEntries(identities)

	node := tdilithium3DKGCeremonyTestNode(t, identities, 3)
	captureTDilithium3DKGCeremonyRoster(t, node, entries)
	roster, err := node.capturedEpochValidatorRoster(6)
	if err != nil {
		t.Fatalf("read the captured roster: %v", err)
	}
	if err := node.tdilithium3DKGVerifyLocalIdentity(roster, 3); err != nil {
		t.Fatalf("the matching identity key was rejected: %v", err)
	}
	if err := node.tdilithium3DKGVerifyLocalIdentity(roster, 2); !errors.Is(err, errTDilithium3DKGIdentityKeyMismatch) {
		t.Fatalf("a mismatched roster position was accepted: %v", err)
	}
	if err := node.tdilithium3DKGVerifyLocalIdentity(roster, 9); !errors.Is(err, errTDilithium3DKGSessionUnavailable) {
		t.Fatalf("an out-of-range roster position was accepted: %v", err)
	}
	unkeyed := tdilithium3DKGCeremonyTestNode(t, identities, 3)
	unkeyed.blockProducer = &BlockProducer{}
	if err := unkeyed.tdilithium3DKGVerifyLocalIdentity(roster, 3); !errors.Is(err, errTDilithium3DKGIdentityKeyMismatch) {
		t.Fatalf("a node without a validator key was accepted: %v", err)
	}
}

// TestNodeConsensusDKGRunnerSelectsV1BackendWithoutFallback covers design section
// 7 items 5 and 6 (D8/D9). The v1 branch is taken exactly when the gates are open
// on a non-mainnet network; a failing v1 ceremony returns the error and never the
// legacy group key, and a node that keeps the gates closed stays on the legacy
// path byte for byte.
func TestNodeConsensusDKGRunnerSelectsV1BackendWithoutFallback(t *testing.T) {
	legacyRunner := func(networkID uint64) *nodeConsensusDKGRunner {
		return &nodeConsensusDKGRunner{node: &Node{config: &Config{NetworkID: networkID}}}
	}
	// The legacy path reports its own missing-manager error, which is how these
	// cases prove the v1 ceremony was not entered.
	const legacyError = "consensus DKG runner is not wired"

	baseline := legacyRunner(TestnetNetworkID)
	if _, err := baseline.RunDistributedDKG(7, 4, 6); err == nil || !strings.Contains(err.Error(), legacyError) {
		t.Fatalf("with the gates closed the legacy path was not taken: %v", err)
	}

	openTDilithium3DKGCeremonyGates(t)
	if _, err := baseline.RunDistributedDKG(7, 4, 6); errors.Is(err, nil) || strings.Contains(err.Error(), legacyError) {
		t.Fatalf("with the gates open the v1 ceremony was not entered: %v", err)
	} else if !errors.Is(err, errTDilithium3DKGSessionUnavailable) {
		t.Fatalf("the v1 ceremony failed with an unexpected error: %v", err)
	}

	// No fallback: the ceremony failed, and no key was substituted for it.
	identities := tdilithium3DKGCeremonyTestIdentities(t, 6)
	unreachable := &nodeConsensusDKGRunner{node: tdilithium3DKGCeremonyTestNode(t, identities, 0)}
	captureTDilithium3DKGCeremonyRoster(t, unreachable.node, tdilithium3DKGCeremonyTestEntries(identities))
	publicKey, err := unreachable.RunDistributedDKG(7, 4, 6)
	if err == nil {
		t.Fatal("a ceremony without a P2P host succeeded")
	}
	if publicKey != nil {
		t.Fatalf("a failed ceremony returned %d bytes instead of an error", len(publicKey))
	}

	// Mainnet is permanently excluded, so it stays on the legacy path even with
	// both gates open.
	if _, err := legacyRunner(MainnetNetworkID).RunDistributedDKG(7, 4, 6); err == nil || !strings.Contains(err.Error(), legacyError) {
		t.Fatalf("mainnet entered the v1 ceremony: %v", err)
	}

	// The ceremony itself refuses to start on mainnet or with the gates closed,
	// so no caller can reach it around the runner.
	mainnet := tdilithium3DKGCeremonyTestNode(t, identities, 0)
	mainnet.config.NetworkID = MainnetNetworkID
	captureTDilithium3DKGCeremonyRoster(t, mainnet, tdilithium3DKGCeremonyTestEntries(identities))
	if _, err := mainnet.runTDilithium3DKGCeremony(context.Background(), 7); !errors.Is(err, errTDilithium3DKGCeremonyDisabled) {
		t.Fatalf("the ceremony started on mainnet: %v", err)
	}
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "0")
	if _, err := mainnet.runTDilithium3DKGCeremony(context.Background(), 7); !errors.Is(err, errTDilithium3DKGCeremonyDisabled) {
		t.Fatalf("the ceremony started with the experimental gate closed: %v", err)
	}
}

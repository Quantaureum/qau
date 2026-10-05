// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// Finalized-epoch validator roster snapshot tests (Dilithium3 v1 CNF-RSS
// design, "Finalized-Epoch Validator Snapshot", option 2). They cover the two
// properties the DKG Round 0 commitment depends on: two nodes that processed the
// same blocks derive the same roster, and a restarted node serves the same
// roster it captured. Every other outcome must fail closed on the named
// errTDilithium3DKGEpochRosterUnavailable error rather than fall back to the
// node's live validator set.

// tdilithium3DKGRosterTestValidators derives count DEVNET-only Dilithium3
// identities and returns the live validator pointers (in derivation order) and
// the canonical roster entries derived from them.
func tdilithium3DKGRosterTestValidators(t *testing.T, count int) ([]*consensus.Validator, []tdilithium3DKGEpochRosterEntry) {
	t.Helper()
	validators := make([]*consensus.Validator, 0, count)
	for position := 0; position < count; position++ {
		var seed [mode3.SeedSize]byte
		// The seed buffer is only mode3.SeedSize bytes, so the prefix must stay
		// short enough for the position to survive the copy.
		copy(seed[:], fmt.Sprintf("DEVNET ONLY roster %02d", position))
		publicKey, _ := mode3.NewKeyFromSeed(&seed)
		validators = append(validators, &consensus.Validator{
			Address:        types.AddressFromPublicKey(publicKey.Bytes()),
			Stake:          big.NewInt(1_000_000),
			Active:         true,
			PublicKeyBytes: publicKey.Bytes(),
		})
	}
	entries, err := tdilithium3DKGActiveRosterEntries(validators)
	if err != nil {
		t.Fatalf("canonical roster entries: %v", err)
	}
	return validators, entries
}

// tdil3TestCapture calls capture with an unset sampling seed: every test
// written before the v2 sidecar used that contract (the sampler never reads
// the seed for rosters within the pinned committee row).
func tdil3TestCapture(store *tdilithium3DKGEpochRosterStore, epoch uint64, boundary types.Hash, entries []tdilithium3DKGEpochRosterEntry, finalized uint64) error {
	return store.capture(epoch, boundary, types.Hash{}, false, entries, finalized)
}

// tdil3TestDigest is the v2 digest of a record with no sampling seed.
func tdil3TestDigest(chainID uint64, genesis types.Hash, epoch uint64, boundary types.Hash, entries []tdilithium3DKGEpochRosterEntry) [32]byte {
	return tdilithium3DKGEpochRosterDigest(chainID, genesis, epoch, boundary, types.Hash{}, false, entries)
}

func tdilithium3DKGRosterTestHash(seed byte) types.Hash {
	var hash types.Hash
	hash[0] = seed
	hash[len(hash)-1] = seed
	return hash
}

func tdilithium3DKGRosterTestPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), tdilithium3DKGEpochRosterFileName)
}

// TestTDilithium3DKGEpochRosterEntriesAreCanonicalAndChainBound covers the
// determinism claim: the roster is ordered by address (not by the validator
// set's insertion order), so two nodes that received the same validators in
// different orders digest identical bytes; and the digest is bound to the chain
// and the boundary block, so the same epoch on another chain or fork cannot
// collide.
func TestTDilithium3DKGEpochRosterEntriesAreCanonicalAndChainBound(t *testing.T) {
	validators, entries := tdilithium3DKGRosterTestValidators(t, 6)

	reversed := make([]*consensus.Validator, len(validators))
	for index := range validators {
		reversed[index] = validators[len(validators)-1-index]
	}
	shuffled, err := tdilithium3DKGActiveRosterEntries(reversed)
	if err != nil {
		t.Fatalf("canonical roster entries from the reversed set: %v", err)
	}
	if !reflect.DeepEqual(shuffled, entries) {
		t.Fatal("two insertion orders produced different roster entries")
	}
	if len(entries) != 6 {
		t.Fatalf("expected 6 roster entries, got %d", len(entries))
	}
	for index := 1; index < len(entries); index++ {
		if strings.Compare(string(entries[index-1].Address[:]), string(entries[index].Address[:])) >= 0 {
			t.Fatal("roster entries are not in ascending address order")
		}
	}

	genesis := tdilithium3DKGRosterTestHash(0x11)
	boundary := tdilithium3DKGRosterTestHash(0x22)
	digest := tdil3TestDigest(TestnetNetworkID, genesis, 7, boundary, entries)

	for name, other := range map[string][32]byte{
		"chain id":       tdil3TestDigest(TestnetNetworkID+1, genesis, 7, boundary, entries),
		"genesis hash":   tdil3TestDigest(TestnetNetworkID, tdilithium3DKGRosterTestHash(0x12), 7, boundary, entries),
		"epoch":          tdil3TestDigest(TestnetNetworkID, genesis, 8, boundary, entries),
		"boundary hash":  tdil3TestDigest(TestnetNetworkID, genesis, 7, tdilithium3DKGRosterTestHash(0x23), entries),
		"roster length":  tdil3TestDigest(TestnetNetworkID, genesis, 7, boundary, entries[:5]),
		"identity key":   tdil3TestDigest(TestnetNetworkID, genesis, 7, boundary, append(append([]tdilithium3DKGEpochRosterEntry(nil), entries[:5]...), tdilithium3DKGEpochRosterEntry{Address: entries[5].Address, PublicKey: entries[0].PublicKey})),
		"member address": tdil3TestDigest(TestnetNetworkID, genesis, 7, boundary, append(append([]tdilithium3DKGEpochRosterEntry(nil), entries[:5]...), tdilithium3DKGEpochRosterEntry{Address: entries[0].Address, PublicKey: entries[5].PublicKey})),
	} {
		if other == digest {
			t.Fatalf("digest did not change when the %s changed", name)
		}
	}
}

// TestTDilithium3DKGActiveRosterEntriesRejectsDegenerateSets covers the
// fail-closed projection: an incomplete validator set yields an error, never a
// partial roster that a peer would then digest differently.
func TestTDilithium3DKGActiveRosterEntriesRejectsDegenerateSets(t *testing.T) {
	validators, entries := tdilithium3DKGRosterTestValidators(t, 3)
	if len(entries) != 3 {
		t.Fatalf("expected 3 roster entries, got %d", len(entries))
	}

	inactive := make([]*consensus.Validator, len(validators))
	copy(inactive, validators)
	inactive[0].Active = false
	filtered, err := tdilithium3DKGActiveRosterEntries(inactive)
	if err != nil {
		t.Fatalf("inactive validator should be skipped, not rejected: %v", err)
	}
	if len(filtered) != 2 {
		t.Fatalf("inactive validator was not filtered: got %d entries", len(filtered))
	}

	cases := map[string][]*consensus.Validator{
		"empty address": {
			{Address: types.Address{}, Stake: big.NewInt(1), Active: true, PublicKeyBytes: validators[0].PublicKeyBytes},
		},
		"duplicate address": {
			{Address: validators[0].Address, Stake: big.NewInt(1), Active: true, PublicKeyBytes: validators[0].PublicKeyBytes},
			{Address: validators[0].Address, Stake: big.NewInt(1), Active: true, PublicKeyBytes: validators[1].PublicKeyBytes},
		},
		"missing identity key": {
			{Address: validators[0].Address, Stake: big.NewInt(1), Active: true},
		},
		"truncated identity key": {
			{Address: validators[0].Address, Stake: big.NewInt(1), Active: true, PublicKeyBytes: validators[0].PublicKeyBytes[:64]},
		},
		"degenerate identity key": {
			{Address: validators[0].Address, Stake: big.NewInt(1), Active: true, PublicKeyBytes: make([]byte, len(validators[0].PublicKeyBytes))},
		},
	}
	for name, candidate := range cases {
		if _, err := tdilithium3DKGActiveRosterEntries(candidate); err == nil {
			t.Fatalf("%s: degenerate validator set produced a roster", name)
		}
	}
}

// TestTDilithium3DKGEpochRosterStorePersistsAndReloads covers the restart
// property: a node that recovers from the sidecar serves the same roster, the
// same boundary hash and the same digest as the node that captured it.
func TestTDilithium3DKGEpochRosterStorePersistsAndReloads(t *testing.T) {
	path := tdilithium3DKGRosterTestPath(t)
	genesis := tdilithium3DKGRosterTestHash(0x31)
	_, entries := tdilithium3DKGRosterTestValidators(t, 6)

	store := newTDilithium3DKGEpochRosterStore(path, TestnetNetworkID, genesis)
	if err := tdil3TestCapture(store, 6, tdilithium3DKGRosterTestHash(0x41), entries, 5); err != nil {
		t.Fatalf("capture epoch 6: %v", err)
	}
	if err := tdil3TestCapture(store, 6, tdilithium3DKGRosterTestHash(0x41), entries, 5); err != nil {
		t.Fatalf("re-capturing the same boundary must be idempotent: %v", err)
	}
	boundary := tdilithium3DKGRosterTestHash(0x42)
	if err := tdil3TestCapture(store, 7, boundary, entries, 7); err != nil {
		t.Fatalf("capture epoch 7: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("sidecar was not written: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("sidecar is empty")
	}

	reloaded := newTDilithium3DKGEpochRosterStore(path, TestnetNetworkID, genesis)
	roster, err := reloaded.lookup(7, 7)
	if err != nil {
		t.Fatalf("lookup after reload: %v", err)
	}
	want := tdil3TestDigest(TestnetNetworkID, genesis, 7, boundary, entries)
	if roster.Digest != want || roster.BoundaryHash != boundary || roster.Epoch != 7 {
		t.Fatal("reloaded roster does not reproduce the captured epoch")
	}
	if !reflect.DeepEqual(roster.Entries, entries) {
		t.Fatal("reloaded roster entries differ from the captured entries")
	}
	// The first captured epoch is the bootstrap boundary: epochs strictly below
	// it may have been observed only during a partially processed sync, so they
	// are not servable. The boundary itself was observed while applying the
	// node's own blocks, so it is servable (R74 bootstrap rule revision).
	if _, err := reloaded.lookup(5, 7); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("an epoch below the bootstrap boundary was served: %v", err)
	}
	// The first observed boundary is servable: a node that captured it while
	// applying its own block saw the whole boundary, not a partial sync.
	if _, err := reloaded.lookup(6, 7); err != nil {
		t.Fatalf("the bootstrap boundary was not servable: %v", err)
	}
}

// TestTDilithium3DKGEpochRosterStoreIsBoundedByEpochBudget covers the bounded
// sidecar: the file cannot grow with the chain.
func TestTDilithium3DKGEpochRosterStoreIsBoundedByEpochBudget(t *testing.T) {
	path := tdilithium3DKGRosterTestPath(t)
	genesis := tdilithium3DKGRosterTestHash(0x34)
	_, entries := tdilithium3DKGRosterTestValidators(t, 1)

	store := newTDilithium3DKGEpochRosterStore(path, TestnetNetworkID, genesis)
	for epoch := uint64(1); epoch <= uint64(tdilithium3DKGEpochRosterEpochBudget)+6; epoch++ {
		if err := tdil3TestCapture(store, epoch, tdilithium3DKGRosterTestHash(byte(epoch)), entries, epoch); err != nil {
			t.Fatalf("capture epoch %d: %v", epoch, err)
		}
	}
	last := uint64(tdilithium3DKGEpochRosterEpochBudget) + 6
	reloaded := newTDilithium3DKGEpochRosterStore(path, TestnetNetworkID, genesis)
	if _, err := reloaded.lookup(last, last); err != nil {
		t.Fatalf("the newest epoch was pruned: %v", err)
	}
	reloaded.mu.Lock()
	kept := len(reloaded.epochs)
	reloaded.mu.Unlock()
	if kept != tdilithium3DKGEpochRosterEpochBudget {
		t.Fatalf("expected %d retained epochs, got %d", tdilithium3DKGEpochRosterEpochBudget, kept)
	}
	if _, err := reloaded.lookup(last-uint64(tdilithium3DKGEpochRosterEpochBudget), last); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("the oldest epoch was retained past the budget: %v", err)
	}
}

// TestTDilithium3DKGEpochRosterStoreReorgAndFinality covers the two mutation
// rules: an unfinalized epoch may be replaced by the new canonical boundary
// after a reorg, and a finalized epoch may not change.
func TestTDilithium3DKGEpochRosterStoreReorgAndFinality(t *testing.T) {
	path := tdilithium3DKGRosterTestPath(t)
	genesis := tdilithium3DKGRosterTestHash(0x35)
	_, entries := tdilithium3DKGRosterTestValidators(t, 3)

	store := newTDilithium3DKGEpochRosterStore(path, TestnetNetworkID, genesis)
	if err := tdil3TestCapture(store, 6, tdilithium3DKGRosterTestHash(0x51), entries, 5); err != nil {
		t.Fatalf("capture epoch 6: %v", err)
	}
	if err := tdil3TestCapture(store, 7, tdilithium3DKGRosterTestHash(0x52), entries, 6); err != nil {
		t.Fatalf("capture epoch 7: %v", err)
	}
	// Epoch 7 is not finalized, so the reorged boundary replaces the old one.
	reorged := tdilithium3DKGRosterTestHash(0x53)
	if err := tdil3TestCapture(store, 7, reorged, entries, 6); err != nil {
		t.Fatalf("unfinalized epoch must accept the new canonical boundary: %v", err)
	}
	roster, err := store.lookup(7, 7)
	if err != nil {
		t.Fatalf("lookup epoch 7: %v", err)
	}
	if roster.BoundaryHash != reorged {
		t.Fatal("the reorged boundary did not replace the unfinalized boundary")
	}
	// Re-delivering the same boundary only advances the finalized floor.
	if err := tdil3TestCapture(store, 7, reorged, entries, 7); err != nil {
		t.Fatalf("re-delivering the same boundary must be idempotent: %v", err)
	}
	if err := tdil3TestCapture(store, 7, tdilithium3DKGRosterTestHash(0x54), entries, 7); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("a finalized epoch was rewritten: %v", err)
	}
}

// TestTDilithium3DKGEpochRosterStoreFailsClosed covers every outcome that must
// not degrade into a live-validator-set fallback.
func TestTDilithium3DKGEpochRosterStoreFailsClosed(t *testing.T) {
	path := tdilithium3DKGRosterTestPath(t)
	genesis := tdilithium3DKGRosterTestHash(0x36)
	_, entries := tdilithium3DKGRosterTestValidators(t, 3)

	store := newTDilithium3DKGEpochRosterStore(path, TestnetNetworkID, genesis)
	if err := tdil3TestCapture(store, 6, tdilithium3DKGRosterTestHash(0x61), nil, 6); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("an empty roster was captured: %v", err)
	}
	if err := tdil3TestCapture(store, 6, tdilithium3DKGRosterTestHash(0x61), entries, 5); err != nil {
		t.Fatalf("capture epoch 6: %v", err)
	}
	if err := tdil3TestCapture(store, 7, tdilithium3DKGRosterTestHash(0x62), entries, 6); err != nil {
		t.Fatalf("capture epoch 7: %v", err)
	}
	if _, err := store.lookup(7, 6); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("an unfinalized epoch was served: %v", err)
	}
	if _, err := store.lookup(7, 0); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("the persisted finalized floor was ignored: %v", err)
	}
	if _, err := store.lookup(5, 7); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("an epoch below the bootstrap boundary was served: %v", err)
	}
	if _, err := store.lookup(6, 7); err != nil {
		t.Fatalf("the bootstrap boundary epoch was not servable: %v", err)
	}
	if _, err := store.lookup(9, 9); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("an uncaptured epoch was served: %v", err)
	}
	for name, foreign := range map[string]*tdilithium3DKGEpochRosterStore{
		"another chain":   newTDilithium3DKGEpochRosterStore(path, TestnetNetworkID+1, genesis),
		"another genesis": newTDilithium3DKGEpochRosterStore(path, TestnetNetworkID, tdilithium3DKGRosterTestHash(0x37)),
	} {
		if _, err := foreign.lookup(7, 7); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
			t.Fatalf("%s: a sidecar captured for another chain was reused: %v", name, err)
		}
	}

	// A missing sidecar is an empty store, never an error: the node may simply
	// have started after the bootstrap boundary.
	empty := newTDilithium3DKGEpochRosterStore(tdilithium3DKGRosterTestPath(t), TestnetNetworkID, genesis)
	if _, err := empty.lookup(7, 7); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("a missing sidecar was served: %v", err)
	}
}

// TestTDilithium3DKGEpochRosterStoreRefusesTamperedSidecar covers the read side:
// a file whose version, digest or roster was altered by hand is refused instead
// of being repaired or partially trusted.
func TestTDilithium3DKGEpochRosterStoreRefusesTamperedSidecar(t *testing.T) {
	path := tdilithium3DKGRosterTestPath(t)
	genesis := tdilithium3DKGRosterTestHash(0x38)
	_, entries := tdilithium3DKGRosterTestValidators(t, 3)

	store := newTDilithium3DKGEpochRosterStore(path, TestnetNetworkID, genesis)
	if err := tdil3TestCapture(store, 6, tdilithium3DKGRosterTestHash(0x71), entries, 5); err != nil {
		t.Fatalf("capture epoch 6: %v", err)
	}
	if err := tdil3TestCapture(store, 7, tdilithium3DKGRosterTestHash(0x72), entries, 7); err != nil {
		t.Fatalf("capture epoch 7: %v", err)
	}

	readDocument := func(t *testing.T) map[string]any {
		t.Helper()
		blob, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read sidecar: %v", err)
		}
		var document map[string]any
		if err := json.Unmarshal(blob, &document); err != nil {
			t.Fatalf("parse sidecar: %v", err)
		}
		return document
	}
	writeDocument := func(t *testing.T, document map[string]any) {
		t.Helper()
		blob, err := json.Marshal(document)
		if err != nil {
			t.Fatalf("encode sidecar: %v", err)
		}
		if err := os.WriteFile(path, blob, 0o600); err != nil {
			t.Fatalf("write sidecar: %v", err)
		}
	}
	epochSeven := func(t *testing.T, document map[string]any) map[string]any {
		t.Helper()
		epochs, ok := document["epochs"].([]any)
		if !ok || len(epochs) != 2 {
			t.Fatalf("unexpected sidecar layout: %v", document["epochs"])
		}
		record, ok := epochs[1].(map[string]any)
		if !ok {
			t.Fatalf("unexpected sidecar record: %v", epochs[1])
		}
		return record
	}

	document := readDocument(t)
	document["version"] = float64(tdilithium3DKGEpochRosterFileVersion + 1)
	writeDocument(t, document)
	if _, err := newTDilithium3DKGEpochRosterStore(path, TestnetNetworkID, genesis).lookup(7, 7); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("a future sidecar version was accepted: %v", err)
	}

	document = readDocument(t)
	epochSeven(t, document)["digest"] = strings.Repeat("00", 32)
	writeDocument(t, document)
	if _, err := newTDilithium3DKGEpochRosterStore(path, TestnetNetworkID, genesis).lookup(7, 7); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("a sidecar whose digest did not match its contents was accepted: %v", err)
	}

	document = readDocument(t)
	epochSeven(t, document)["entries"] = []any{}
	writeDocument(t, document)
	if _, err := newTDilithium3DKGEpochRosterStore(path, TestnetNetworkID, genesis).lookup(7, 7); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("a sidecar with an empty roster was accepted: %v", err)
	}

	document = readDocument(t)
	epochSeven(t, document)["entries"] = []any{
		map[string]any{"address": "not-hex", "public_key": strings.Repeat("00", 1952)},
	}
	writeDocument(t, document)
	if _, err := newTDilithium3DKGEpochRosterStore(path, TestnetNetworkID, genesis).lookup(7, 7); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("a sidecar with a malformed roster address was accepted: %v", err)
	}
}

// TestTDilithium3DKGEpochRosterBindingsFollowFinalizedRoster covers the consumer
// side: the Round 0 bindings come from the roster captured one epoch below the
// activation epoch, and a session that commits a different roster never reaches
// the inbox.
func TestTDilithium3DKGEpochRosterBindingsFollowFinalizedRoster(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")

	_, entries := tdilithium3DKGRosterTestValidators(t, 6)
	node := &Node{config: &Config{DataDir: t.TempDir(), NetworkID: TestnetNetworkID}}
	store := node.tdilithium3DKGEpochRosterStoreForUse()
	if store == nil {
		t.Fatal("the roster sidecar was not created with the gates open and a data dir")
	}
	if err := tdil3TestCapture(store, 5, tdilithium3DKGRosterTestHash(0x80), entries, 4); err != nil {
		t.Fatalf("capture epoch 5: %v", err)
	}
	if err := tdil3TestCapture(store, 6, tdilithium3DKGRosterTestHash(0x81), entries, 5); err != nil {
		t.Fatalf("capture epoch 6: %v", err)
	}
	if err := tdil3TestCapture(store, 7, tdilithium3DKGRosterTestHash(0x82), entries, 7); err != nil {
		t.Fatalf("capture epoch 7: %v", err)
	}

	session := testTDilithium3DKGSession()
	// A session activates for epoch 7, so its identity roster is the boundary
	// roster of epoch 6 (D1).
	rosterEpoch := session.ActivationEpoch - 1
	if rosterEpoch != 6 {
		t.Fatalf("unexpected activation epoch %d in the test session", session.ActivationEpoch)
	}
	bindings := make([]dilithium3v1.DKGIdentityBinding, len(entries))
	for position, entry := range entries {
		bindings[position] = dilithium3v1.DKGIdentityBinding{
			ParticipantID:    session.Committee.Participants[position],
			ValidatorAddress: [20]byte(entry.Address),
			PublicKey:        entry.PublicKey,
		}
	}
	digest, err := dilithium3v1.DKGIdentityRosterDigest(session.Committee, bindings)
	if err != nil {
		t.Fatalf("identity roster digest: %v", err)
	}
	session.IdentityRosterDigest = digest

	got, err := node.tdilithium3DKGEpochRosterBindings(session, rosterEpoch)
	if err != nil {
		t.Fatalf("bindings from the captured roster: %v", err)
	}
	if !reflect.DeepEqual(got, bindings) {
		t.Fatal("bindings do not reproduce the captured roster positionally")
	}

	peers := make(map[types.Address]p2p.PeerID, len(entries))
	for position, entry := range entries {
		peers[entry.Address] = p2p.PeerID(fmt.Sprintf("peer-%d", position))
	}
	resolve := func(address types.Address) (p2p.PeerID, bool) {
		peer, found := peers[address]
		return peer, found
	}
	if _, err := node.newTDilithium3DKGInboxFromCapturedEpochRoster(session, 1, rosterEpoch, resolve); err != nil {
		t.Fatalf("inbox from the captured roster: %v", err)
	}

	tampered := session.Clone()
	tampered.IdentityRosterDigest[0] ^= 1
	if _, err := node.tdilithium3DKGEpochRosterBindings(tampered, rosterEpoch); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("a session committing another roster was accepted: %v", err)
	}

	foreignChain := session.Clone()
	foreignChain.ChainID = TestnetNetworkID + 1
	if _, err := node.tdilithium3DKGEpochRosterBindings(foreignChain, rosterEpoch); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("a session for another chain was accepted: %v", err)
	}

	// The bootstrap boundary itself is servable: it is the first boundary the
	// node observed while applying its own blocks, so it was fully captured.
	// Epochs strictly below it are refused.
	if _, err := node.tdilithium3DKGEpochRosterBindings(session, 5); err != nil {
		t.Fatalf("the bootstrap boundary roster was not servable: %v", err)
	}
	if _, err := node.tdilithium3DKGEpochRosterBindings(session, 4); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("an epoch below the bootstrap boundary was served: %v", err)
	}

	// Epoch 8 has not been captured yet, so a session activating for epoch 9
	// has no anchor and fails closed even though the live validator set would
	// happily answer.
	unavailable := session.Clone()
	unavailable.ActivationEpoch = 9
	if _, err := node.tdilithium3DKGEpochRosterBindings(unavailable, 8); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("an epoch without a snapshot was served: %v", err)
	}

	// A roster whose size differs from the committee is refused rather than
	// subsetted, because the committee-selection rule is consensus state.
	_, fewerEntries := tdilithium3DKGRosterTestValidators(t, 3)
	if err := tdil3TestCapture(store, 8, tdilithium3DKGRosterTestHash(0x83), fewerEntries, 8); err != nil {
		t.Fatalf("capture epoch 8: %v", err)
	}
	if _, err := node.tdilithium3DKGEpochRosterBindings(unavailable, 8); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("a roster smaller than the committee was accepted: %v", err)
	}

	for name, candidate := range map[string]*Node{
		"nil node":    nil,
		"nil config":  {},
		"no data dir": {config: &Config{NetworkID: TestnetNetworkID}},
	} {
		if _, err := candidate.tdilithium3DKGEpochRosterBindings(session, rosterEpoch); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
			t.Fatalf("%s: an unconfigured node produced bindings: %v", name, err)
		}
	}

	// With the experimental gates closed the sidecar is never created.
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "0")
	disabled := &Node{config: &Config{DataDir: t.TempDir(), NetworkID: TestnetNetworkID}}
	if disabled.tdilithium3DKGEpochRosterStoreForUse() != nil {
		t.Fatal("the sidecar was created with the experimental gate closed")
	}
	if _, err := disabled.tdilithium3DKGEpochRosterBindings(session, rosterEpoch); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("a node with the gate closed produced bindings: %v", err)
	}
}

// TestTDilithium3DKGCaptureHookRecordsOnlyEpochBoundaries covers the block hook:
// only a boundary block whose header epoch agrees with its slot is captured, and
// a closed gate never touches the disk.
func TestTDilithium3DKGCaptureHookRecordsOnlyEpochBoundaries(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")

	validators, entries := tdilithium3DKGRosterTestValidators(t, 6)
	validatorSet, err := consensus.NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("validator set: %v", err)
	}
	qpos, err := consensus.NewQPOS(validatorSet)
	if err != nil {
		t.Fatalf("QPOS: %v", err)
	}
	builder := func() *Node {
		return &Node{
			config:        &Config{DataDir: t.TempDir(), NetworkID: TestnetNetworkID},
			blockProducer: &BlockProducer{qpos: qpos},
		}
	}

	for name, header := range map[string]*encoding.BlockHeader{
		"mid-epoch slot":         {Height: 225, Slot: consensus.SlotsPerEpoch + 1, Epoch: 7},
		"genesis slot":           {Height: 0, Slot: 0, Epoch: 0},
		"header epoch disagrees": {Height: 224, Slot: consensus.SlotsPerEpoch * 7, Epoch: 6},
	} {
		node := builder()
		node.captureTDilithium3DKGEpochRosterFromBlock(&encoding.Block{Header: header})
		if node.tdilithium3DKGEpochRosterStore != nil {
			t.Fatalf("%s: a block that is not a valid epoch boundary created the roster sidecar", name)
		}
	}

	boundary := &encoding.BlockHeader{Height: 224, Slot: consensus.SlotsPerEpoch * 7, Epoch: 7}
	node := builder()
	node.captureTDilithium3DKGEpochRosterFromBlock(&encoding.Block{Header: boundary})
	store := node.tdilithium3DKGEpochRosterStore
	if store == nil {
		t.Fatal("a valid boundary block did not create the roster sidecar")
	}
	store.mu.Lock()
	roster := store.epochs[7]
	bootstrap, bootstrapSet := store.bootstrap, store.bootstrapSet
	store.mu.Unlock()
	if roster == nil {
		t.Fatal("the boundary block did not capture epoch 7")
	}
	if !bootstrapSet || bootstrap != 7 {
		t.Fatalf("the first captured epoch did not become the bootstrap boundary: %d", bootstrap)
	}
	boundaryHash := block.ComputeBlockHash(boundary)
	if roster.BoundaryHash != boundaryHash {
		t.Fatal("the captured roster is not bound to the boundary block hash")
	}
	if want := tdil3TestDigest(TestnetNetworkID, store.genesis, 7, boundaryHash, entries); roster.Digest != want {
		t.Fatal("the captured roster digest does not match the canonical entries")
	}
	if !reflect.DeepEqual(roster.Entries, entries) {
		t.Fatal("the captured roster entries are not the canonical live entries")
	}

	// The first captured epoch is the bootstrap boundary and is servable:
	// a node that observed it while applying its own block saw the whole
	// boundary, not a partial sync. Epochs strictly below it are refused.
	if _, err := store.lookup(7, 8); err != nil {
		t.Fatalf("the bootstrap boundary epoch was not served: %v", err)
	}
	if _, err := store.lookup(6, 8); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("an epoch below the bootstrap boundary was served: %v", err)
	}
	// The node-level accessor only serves epochs the consensus engine has
	// finalized, so before finality is known it fails closed instead of serving
	// a captured-but-unfinalized epoch.
	if _, err := node.finalizedEpochValidatorRoster(8); !errors.Is(err, errTDilithium3DKGEpochRosterUnavailable) {
		t.Fatalf("an epoch the consensus engine has not finalized was served: %v", err)
	}

	// With the gate closed the hook is a no-op and never creates the file.
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "0")
	disabled := builder()
	disabled.captureTDilithium3DKGEpochRosterFromBlock(&encoding.Block{Header: boundary})
	if disabled.tdilithium3DKGEpochRosterStore != nil {
		t.Fatal("the capture hook ran with the experimental gate closed")
	}
	if _, err := os.Stat(filepath.Join(disabled.config.DataDir, tdilithium3DKGEpochRosterFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the capture hook touched the disk with the gate closed: %v", err)
	}
}

// TestTDilithium3DKGCaptureHookCoversMissedBoundarySlot covers the R101
// missed-boundary-slot rule: when the boundary slot produced no block, the
// epoch's first canonical block captures the roster anchored at the
// epoch-boundary chain tip (its parent hash); a mid-epoch block captures
// nothing, a fully skipped epoch is never captured, and a block whose parent
// is unavailable fails closed. Devnet acceptance showed missed boundary slots
// are routine on real networks, and without this rule every rotation anchored
// on the uncaptured epoch bricked itself (fail closed) permanently.
func TestTDilithium3DKGCaptureHookCoversMissedBoundarySlot(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")

	validators, entries := tdilithium3DKGRosterTestValidators(t, 6)
	validatorSet, err := consensus.NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("validator set: %v", err)
	}
	qpos, err := consensus.NewQPOS(validatorSet)
	if err != nil {
		t.Fatalf("QPOS: %v", err)
	}
	newNode := func(bs *block.BlockStore) *Node {
		return &Node{
			config:        &Config{DataDir: t.TempDir(), NetworkID: TestnetNetworkID},
			blockProducer: &BlockProducer{qpos: qpos},
			blockStore:    bs,
		}
	}
	storeBlock := func(t *testing.T, bs *block.BlockStore, header *encoding.BlockHeader) {
		t.Helper()
		if err := bs.PutBlockWithIndex(&encoding.Block{Header: header}); err != nil {
			t.Fatalf("PutBlockWithIndex height=%d: %v", header.Height, err)
		}
	}

	t.Run("missed boundary slot captures at the first block anchored at the tip", func(t *testing.T) {
		bs := block.NewBlockStore(db.NewMemDB())
		node := newNode(bs)
		// Parent: height 62 at slot 63, the last slot of epoch 1. Boundary
		// slot 64 produced no block; the epoch-2 first block is slot 66.
		parent := &encoding.BlockHeader{Height: 62, Slot: 63, Epoch: 63 / consensus.SlotsPerEpoch}
		storeBlock(t, bs, parent)
		first := &encoding.BlockHeader{Height: 63, Slot: 66, Epoch: 66 / consensus.SlotsPerEpoch, ParentHash: block.ComputeBlockHash(parent)}
		storeBlock(t, bs, first)
		node.captureTDilithium3DKGEpochRosterFromBlock(&encoding.Block{Header: first})

		store := node.tdilithium3DKGEpochRosterStore
		if store == nil {
			t.Fatal("the epoch's first block did not create the roster sidecar")
		}
		store.mu.Lock()
		roster := store.epochs[2]
		bootstrap, bootstrapSet := store.bootstrap, store.bootstrapSet
		store.mu.Unlock()
		if roster == nil {
			t.Fatal("a missed boundary slot left epoch 2 uncaptured")
		}
		if roster.BoundaryHash != first.ParentHash {
			t.Fatal("the anchor is not the epoch-boundary chain tip (the first block's parent hash)")
		}
		if roster.BoundaryHash == block.ComputeBlockHash(first) {
			t.Fatal("a non-boundary first block anchored the roster at its own hash")
		}
		if !bootstrapSet || bootstrap != 2 {
			t.Fatalf("the first captured epoch did not become the bootstrap boundary: %d", bootstrap)
		}
		if !reflect.DeepEqual(roster.Entries, entries) {
			t.Fatal("the captured roster entries are not the canonical live entries")
		}

		// A mid-epoch block is not the epoch's first block: it captures
		// nothing and must not overwrite the first-block capture.
		mid := &encoding.BlockHeader{Height: 64, Slot: 70, Epoch: 70 / consensus.SlotsPerEpoch, ParentHash: block.ComputeBlockHash(first)}
		storeBlock(t, bs, mid)
		node.captureTDilithium3DKGEpochRosterFromBlock(&encoding.Block{Header: mid})
		store.mu.Lock()
		again := store.epochs[2]
		count := len(store.epochs)
		store.mu.Unlock()
		if count != 1 || again == nil || again.BoundaryHash != first.ParentHash {
			t.Fatal("a mid-epoch block overwrote the first-block capture")
		}
	})

	t.Run("fully skipped epoch is never captured", func(t *testing.T) {
		bs := block.NewBlockStore(db.NewMemDB())
		node := newNode(bs)
		parent := &encoding.BlockHeader{Height: 100, Slot: 95, Epoch: 95 / consensus.SlotsPerEpoch}
		storeBlock(t, bs, parent)
		// Epoch 3 has no block at all; the next canonical block opens epoch 4
		// and anchors epoch 4 at the tip, while epoch 3 stays uncapturable.
		first := &encoding.BlockHeader{Height: 101, Slot: 130, Epoch: 130 / consensus.SlotsPerEpoch, ParentHash: block.ComputeBlockHash(parent)}
		node.captureTDilithium3DKGEpochRosterFromBlock(&encoding.Block{Header: first})

		store := node.tdilithium3DKGEpochRosterStore
		if store == nil {
			t.Fatal("the epoch-4 first block did not create the roster sidecar")
		}
		store.mu.Lock()
		epochThree, epochFour := store.epochs[3], store.epochs[4]
		store.mu.Unlock()
		if epochThree != nil {
			t.Fatal("an epoch with no canonical block was captured")
		}
		if epochFour == nil || epochFour.BoundaryHash != first.ParentHash {
			t.Fatal("the epoch after a fully skipped epoch was not captured at the tip anchor")
		}
	})

	t.Run("missing parent fails closed without touching the disk", func(t *testing.T) {
		bs := block.NewBlockStore(db.NewMemDB())
		node := newNode(bs)
		orphan := &encoding.BlockHeader{Height: 500, Slot: 200, Epoch: 200 / consensus.SlotsPerEpoch, ParentHash: tdilithium3DKGRosterTestHash(0x99)}
		node.captureTDilithium3DKGEpochRosterFromBlock(&encoding.Block{Header: orphan})
		if node.tdilithium3DKGEpochRosterStore != nil {
			t.Fatal("a block whose parent is unavailable created the roster sidecar")
		}
	})
}

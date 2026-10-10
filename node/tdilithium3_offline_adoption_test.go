// Quantaureum Node source, version 1.0.0.
package node

import (
	"crypto/rand"
	"errors"
	"os"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func TestOfflineTDilithium3SealingGates(t *testing.T) {
	var nilNode *Node
	if nilNode.offlineTDilithium3SealingConfigured() || nilNode.offlineTDilithium3SealingArmed(100) {
		t.Fatal("nil node reports armed")
	}
	plain := &Node{config: &Config{}}
	if plain.offlineTDilithium3SealingConfigured() || plain.offlineTDilithium3SealingArmed(1) {
		t.Fatal("default config (unset epoch) must not arm the offline sealing path")
	}
	armed := &Node{config: &Config{TSSV1SealingActivationEpoch: 42}}
	if !armed.offlineTDilithium3SealingConfigured() {
		t.Fatal("configured epoch must report configured")
	}
	if armed.offlineTDilithium3SealingArmed(41) {
		t.Fatal("epoch 41 must not arm activation at epoch 42")
	}
	if !armed.offlineTDilithium3SealingArmed(42) || !armed.offlineTDilithium3SealingArmed(43) {
		t.Fatal("epoch >= activation must report armed")
	}
	// The executor gate never opens without the consensus engine present,
	// even when armed — sealing only engages once block production exists.
	if tdilithium3SealExecutorEnabled(armed) {
		t.Fatal("executor gate opened without a block producer")
	}
}

func TestOfflineTDilithium3AdoptionRequiresArmedEpoch(t *testing.T) {
	n := &Node{config: &Config{TSSV1SealingActivationEpoch: 42}}
	if _, handled, err := n.offlineTDilithium3AdoptionGroupKey(t.Context(), 41); err != nil || handled {
		t.Fatalf("pre-activation epoch must defer (handled=%v err=%v)", handled, err)
	}
}

func TestCandidateSharePublicIdentityRoundTrip(t *testing.T) {
	entries := offlineCeremonyTestEntries(t)
	var genesis [32]byte
	copy(genesis[:], "DEVNET ONLY adoption gate genesis")
	session, err := OfflineCeremonySession(1668, genesis, 7, entries)
	if err != nil {
		t.Fatal(err)
	}
	shares, _, _, err := dilithium3v1.DealShares(session, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, share := range shares {
			share.Zeroize()
		}
	}()

	dataDir := t.TempDir()
	password := []byte("DEVNET ONLY candidate probe password")
	store := newThresholdShareStore(dataDir)
	if _, _, _, _, err := store.CandidateSharePublicIdentity(password); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing candidate must surface ErrNotExist, got %v", err)
	}
	if err := store.Store(shares[2], password); err != nil {
		t.Fatal(err)
	}
	epoch, key, threshold, pid, err := store.CandidateSharePublicIdentity(password)
	if err != nil {
		t.Fatal(err)
	}
	if epoch != 7 || threshold != 4 || pid != shares[2].ParticipantID {
		t.Fatalf("probe mismatch: epoch=%d threshold=%d pid=%d", epoch, threshold, pid)
	}
	if len(key) != 1952 {
		t.Fatalf("group key length %d, want 1952", len(key))
	}

	// A wrong store password must fail closed on the probe.
	if _, _, _, _, err := store.CandidateSharePublicIdentity([]byte("DEVNET ONLY wrong password x")); err == nil {
		t.Fatal("wrong password accepted by candidate probe")
	}
}

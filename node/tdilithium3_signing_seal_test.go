// Quantaureum Node source, version 1.0.0.
package node

// Tests of the seal executor wiring: the fixed four-signer projection, the
// attempt ordinal of a seal request payload, the gate, the store's activation
// epoch probe, and the single-session manager. The end-to-end drive needs a
// live four-node session (four shares, four p2p hosts), so the development
// network integration covers it; every input these tests can reach fails
// closed.

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestTDilithium3SealSigningOrdinal(t *testing.T) {
	short := make([]byte, tdilithium3SealSigningRequestBaseLen)
	if got := tdilithium3SealSigningOrdinal(short); got != 0 {
		t.Fatalf("legacy payload ordinal = %d, want 0", got)
	}
	if got := tdilithium3SealSigningOrdinal(nil); got != 0 {
		t.Fatalf("empty payload ordinal = %d, want 0", got)
	}
	truncated := make([]byte, tdilithium3SealSigningRequestBaseLen+7)
	if got := tdilithium3SealSigningOrdinal(truncated); got != 0 {
		t.Fatalf("truncated ordinal payload = %d, want 0", got)
	}
	retry := make([]byte, tdilithium3SealSigningRequestBaseLen+8)
	binary.BigEndian.PutUint64(retry[tdilithium3SealSigningRequestBaseLen:], 3)
	if got := tdilithium3SealSigningOrdinal(retry); got != 3 {
		t.Fatalf("retry ordinal = %d, want 3", got)
	}
	zero := make([]byte, tdilithium3SealSigningRequestBaseLen+8)
	if got := tdilithium3SealSigningOrdinal(zero); got != 0 {
		t.Fatalf("explicit zero ordinal = %d, want 0", got)
	}
}

// TestTDilithium3SealSigningSignersForRoster requires the fixed selection to be
// the first four committee participants, to report the local validator's
// membership by roster position, and to refuse incomplete or unordered inputs.
func TestTDilithium3SealSigningSignersForRoster(t *testing.T) {
	fixture := tdilithium3SigningBindingTestFixtureFor(t)
	signers, localSigner, err := tdilithium3SealSigningSignersForRoster(
		fixture.roster, fixture.committee, fixture.roster.Entries[2].Address,
	)
	if err != nil {
		t.Fatalf("signers: %v", err)
	}
	if !slices.Equal(signers, []uint32{1, 2, 3, 4}) {
		t.Fatalf("signers = %v, want the first four participants", signers)
	}
	if !localSigner {
		t.Fatal("position 2 is not reported as a signer")
	}
	if _, localSigner, err = tdilithium3SealSigningSignersForRoster(
		fixture.roster, fixture.committee, fixture.roster.Entries[4].Address,
	); err != nil || localSigner {
		t.Fatalf("position 4 membership = %v (err %v), want outside the four", localSigner, err)
	}
	if _, _, err := tdilithium3SealSigningSignersForRoster(
		fixture.roster, fixture.committee, types.Address{0xEE},
	); err == nil {
		t.Fatal("validator outside the roster accepted")
	}
	if _, _, err := tdilithium3SealSigningSignersForRoster(
		nil, fixture.committee, fixture.roster.Entries[0].Address,
	); err == nil {
		t.Fatal("missing roster accepted")
	}
	shortCommittee := fixture.committee.Clone()
	shortCommittee.Participants = shortCommittee.Participants[:4]
	if _, _, err := tdilithium3SealSigningSignersForRoster(
		fixture.roster, shortCommittee, fixture.roster.Entries[0].Address,
	); err == nil {
		t.Fatal("committee that does not match the roster accepted")
	}
	unordered := fixture.committee.Clone()
	unordered.Participants = []uint32{1, 2, 4, 3, 5, 6}
	if _, _, err := tdilithium3SealSigningSignersForRoster(
		fixture.roster, unordered, fixture.roster.Entries[0].Address,
	); err == nil {
		t.Fatal("unordered committee accepted")
	}
}

// TestTDilithium3SealExecutorEnabled requires the gate to stay closed unless the
// experimental switch is open and the network is not the mainnet.
func TestTDilithium3SealExecutorEnabled(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "0")
	if tdilithium3SealExecutorEnabled(nil) {
		t.Fatal("nil node enabled")
	}
	testnet := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	mainnet := &Node{config: &Config{NetworkID: MainnetNetworkID}}
	if tdilithium3SealExecutorEnabled(testnet) || tdilithium3SealExecutorEnabled(mainnet) {
		t.Fatal("gate closed but the executor is enabled")
	}
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	if !tdilithium3SealExecutorEnabled(testnet) {
		t.Fatal("open gate on the testnet did not enable the executor")
	}
	if tdilithium3SealExecutorEnabled(mainnet) {
		t.Fatal("open gate enabled the executor on the mainnet")
	}
}

// TestTDilithium3SealSigningStartFailsClosed requires the start path to refuse
// a node without the pieces a session needs, before any session state exists.
func TestTDilithium3SealSigningStartFailsClosed(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	var unconfigured *Node
	if unconfigured.tdilithium3SealSigningStart(1, types.Hash{0x01}, 0) {
		t.Fatal("unconfigured node started a session")
	}
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	if node.tdilithium3SealSigningStart(1, types.Hash{0x01}, 0) {
		t.Fatal("node without a block producer started a session")
	}
	if len(node.tdilithium3SealSigningSessions) != 0 {
		t.Fatal("refused start left session state behind")
	}
}

// TestTDilithium3SealSigningSessionManager requires one executor session at a
// time per node, and the ordinal bookkeeping: advancing a live session, never
// forgetting a newer one, and releasing exactly once per acquire.
func TestTDilithium3SealSigningSessionManager(t *testing.T) {
	node := &Node{}
	ctx := context.Background()
	// The permit bounds concurrent slots: up to maxConcurrentSlots acquires
	// succeed, the next one with a canceled context fails.
	for i := 0; i < tdilithium3SealSigningMaxConcurrentSlots; i++ {
		if !node.acquireTDilithium3SealSigning(ctx, uint64(7+i)) {
			t.Fatalf("acquire %d of %d failed", i+1, tdilithium3SealSigningMaxConcurrentSlots)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if node.acquireTDilithium3SealSigning(canceled, 99) {
		t.Fatal("an acquire beyond the permit limit succeeded")
	}
	for i := 0; i < tdilithium3SealSigningMaxConcurrentSlots; i++ {
		node.releaseTDilithium3SealSigning()
	}
	if !node.acquireTDilithium3SealSigning(ctx, 7) {
		t.Fatal("acquire after release failed")
	}
	node.releaseTDilithium3SealSigning()
	node.releaseTDilithium3SealSigning() // must stay quiet, not panic

	session := &tdilithium3SealSigningSession{attempt: 1}
	node.tdilithium3SealSigningSessions = map[uint64]*tdilithium3SealSigningSession{7: session}
	if !node.tdilithium3SealSigningAdvance(7, session, 2) || session.attempt != 2 {
		t.Fatalf("advance left attempt = %d, want 2", session.attempt)
	}
	newer := &tdilithium3SealSigningSession{attempt: 3}
	if node.tdilithium3SealSigningAdvance(7, newer, 4) {
		t.Fatal("a foreign session was advanced")
	}
	node.tdilithium3SealSigningForget(7, newer)
	if node.tdilithium3SealSigningSessions[7] != session {
		t.Fatal("forget dropped a newer session")
	}
	node.tdilithium3SealSigningForget(7, session)
	if node.tdilithium3SealSigningSessions[7] != nil {
		t.Fatal("forget left the session behind")
	}
}

// TestThresholdActiveSharePublicIdentity requires the probe to report the
// installed share's activation epoch and group public key, to fail closed
// without an active share, and to refuse a wrong password.
func TestThresholdActiveSharePublicIdentity(t *testing.T) {
	base := filepath.Join(t.TempDir(), "shares.enc")
	store := newThresholdShareStore(base)
	password := []byte("DEVNET ONLY seal executor activation epoch probe")
	share := testThresholdStoreShare(t, 2)
	if _, _, _, err := store.ActiveSharePublicIdentity(password); !os.IsNotExist(err) {
		t.Fatalf("probe without an active share: %v, want os.ErrNotExist", err)
	}
	if err := store.Store(share, password); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.ActiveSharePublicIdentity(password); !os.IsNotExist(err) {
		t.Fatalf("probe of a stored but unactivated share: %v, want os.ErrNotExist", err)
	}
	certificate, sessionDigest, verifier, bindings := testThresholdActivationCertificate(t, share)
	if err := store.ActivateCandidate(certificate, sessionDigest, share.ActivationEpoch, verifier, bindings, password); err != nil {
		t.Fatal(err)
	}
	epoch, publicKey, threshold, err := store.ActiveSharePublicIdentity(password)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if epoch != share.ActivationEpoch {
		t.Fatalf("activation epoch = %d, want %d", epoch, share.ActivationEpoch)
	}
	if !bytes.Equal(publicKey, share.Key.PublicKey) {
		t.Fatal("public identity reported another group key")
	}
	if threshold != share.Committee.Threshold {
		t.Fatalf("threshold = %d, want %d", threshold, share.Committee.Threshold)
	}
	if _, _, _, err := store.ActiveSharePublicIdentity([]byte("wrong password")); err == nil {
		t.Fatal("probe accepted a wrong password")
	}
	if _, _, _, err := store.ActiveSharePublicIdentity(nil); err == nil {
		t.Fatal("probe accepted an empty password")
	}
}

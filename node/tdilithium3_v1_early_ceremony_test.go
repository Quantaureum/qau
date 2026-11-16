// Quantaureum Node source, version 1.0.0.
package node

// Tests of the early-ceremony beat (TSS-R3-B-1 lag fix, see
// tdilithium3_v1_early_ceremony.go): the deferred activation commit of a
// ceremony that converged ahead of its activation epoch, and the produce-loop
// tick that commits the park exactly when the chain enters the activation
// epoch. The exchange test drives the REAL activation exchange over the
// six-node network harness, so the deferral is proven on the production path,
// not on a stub.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// earlyCeremonyMarker reads the launch-attempt marker under the same mutex the
// production code guards it with.
func earlyCeremonyMarker(node *Node) uint64 {
	node.tdilithium3EarlyCeremonyMu.Lock()
	defer node.tdilithium3EarlyCeremonyMu.Unlock()
	return node.tdilithium3EarlyCeremonyAttemptEpoch
}

func setEarlyCeremonyMarker(node *Node, epoch uint64) {
	node.tdilithium3EarlyCeremonyMu.Lock()
	node.tdilithium3EarlyCeremonyAttemptEpoch = epoch
	node.tdilithium3EarlyCeremonyMu.Unlock()
}

// TestTDilithium3ActivationExchangeDefersAheadOfActivationEpoch runs one
// node's REAL activation exchange while the chain clock sits below the
// session's activation epoch, and pins the three outcomes the early-ceremony
// beat depends on: the exchange reports the deferred sentinel, the active
// share is NOT committed, and the produce-loop tick commits the parked
// certificate exactly at the activation epoch's boundary slot.
func TestTDilithium3ActivationExchangeDefersAheadOfActivationEpoch(t *testing.T) {
	if testing.Short() {
		// Timing-sensitive six-node pre-work (randomness + twenty group
		// rounds); mirrors the skip discipline of the exchange network test.
		t.Skip("skipping the timing-sensitive deferred-activation test in -short mode")
	}
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	// The chain clock at "now" puts the current epoch at 0 — far below the
	// harness session's activation epoch 7 — which is exactly the early-beat
	// situation: the ceremony converged one epoch before its activation.
	_ = consensus.SetGenesisTime(time.Now().Unix())

	harness := newTDilithium3DKGNetworkHarness(t)
	const activationEpoch = uint64(7)
	boundarySlot := activationEpoch * consensus.SlotsPerEpoch

	// Give the observed node the chain clock the deferral reads, plus the
	// host and producer shell the tick's guards demand. GetCurrentEpoch
	// derives from the genesis clock set above; the QPOS value itself is
	// never mutated by it.
	observed := harness.nodes[0]
	host, err := p2p.NewHost(nil)
	if err != nil {
		t.Fatalf("p2p host: %v", err)
	}
	observed.p2pHost = host
	observed.blockProducer = &BlockProducer{node: observed, qpos: &consensus.QPOS{}}
	t.Cleanup(func() { observed.closeTDilithium3SigningJournals() })

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	harness.mustCompleteRandomness(t, ctx)
	groups := dilithium3v1.CanonicalRSSGroups()
	driveGroups(t, harness, ctx, groups[:])

	results := make([]tdilithium3DKGResult, 6)
	for position, runner := range harness.runners {
		result, err := tdilithium3DKGFinalize(runner)
		if err != nil {
			t.Fatalf("node %d finalize: %v", position, err)
		}
		results[position] = result
	}

	// Pre-encode every committee member's acknowledgement so the exchange's
	// sink can be fed deterministically (the harness broadcast is a no-op).
	envelopes := make([][]byte, 6)
	for position := range harness.nodes {
		envelopes[position], err = encodeTDilithium3DKGActivationEnvelope(
			harness.session, results[position].Share, harness.sign(position),
		)
		if err != nil {
			t.Fatalf("node %d encode activation envelope: %v", position, err)
		}
	}

	runner := harness.runners[0]
	// The tick's commit builds its store from the node's DataDir; point it at
	// the runner's store (and use the runner's store password) so the commit
	// reads the candidate the exchange persisted — in production both are the
	// node's own DataDir and validator-key password.
	observed.config.DataDir = runner.basePath
	observed.config.ValidatorKeyPassword = string(runner.password)
	exchangeCtx, stopExchange := context.WithTimeout(context.Background(), tdilithium3DKGActivationExchangeTimeout)
	defer stopExchange()
	exchangeErr := make(chan error, 1)
	go func() {
		exchangeErr <- observed.runTDilithium3DKGActivationExchange(
			exchangeCtx,
			harness.session, runner, results[0],
			observed.tdilithium3DKGInbox.verifyIdentity,
			observed.tdilithium3DKGInbox.IdentityBindings(),
			harness.sign(0),
			func(uint8, []byte) error { return nil },
		)
	}()
	redeliver := time.NewTicker(500 * time.Millisecond)
	defer redeliver.Stop()
	var exchangeResult error
waitExchange:
	for {
		select {
		case exchangeResult = <-exchangeErr:
			break waitExchange
		case <-redeliver.C:
			for peer := range harness.nodes {
				if peer == 0 {
					continue
				}
				observed.deliverTDilithium3DKGActivation(envelopes[peer])
			}
		case <-time.After(tdilithium3DKGActivationExchangeTimeout):
			t.Fatal("the deferred exchange deadline exceeded")
		}
	}
	if !errors.Is(exchangeResult, errTDilithium3ActivationDeferred) {
		t.Fatalf("the exchange returned %v, want the deferred sentinel", exchangeResult)
	}
	pending := observed.takeTDilithium3PendingActivation()
	if pending == nil || pending.activationEpoch != activationEpoch {
		t.Fatalf("the exchange parked %v, want a pending activation for epoch %d", pending, activationEpoch)
	}
	if !bytesEqualPrefix(pending.groupPublicKey, results[0].PublicKey[:]) {
		t.Fatal("the parked activation carries a different group key than the finalized share")
	}
	// The active share is untouched: the signing gates of the current epoch
	// keep serving the pre-activation identity.
	if _, _, _, err := newThresholdShareStore(runner.basePath).ActiveSharePublicIdentity(runner.password); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the active share was committed ahead of the activation epoch (err=%v)", err)
	}

	// Re-park and run the produce-loop tick at the activation epoch's boundary
	// slot: the promotion commits BEFORE the boundary header would be built.
	// The launch section is pre-empted through the attempt marker (the
	// launch's own ceremony path is covered by the guard test below).
	observed.parkTDilithium3PendingActivation(pending)
	setEarlyCeremonyMarker(observed, activationEpoch+1)
	observed.tdilithium3V1EarlyCeremonyTick(boundarySlot)

	loaded, err := newThresholdShareStore(runner.basePath).LoadActiveAtEpoch(
		activationEpoch,
		observed.tdilithium3DKGInbox.verifyIdentity,
		runner.password,
	)
	if err != nil {
		t.Fatalf("the boundary tick did not commit the parked activation: %v", err)
	}
	if loaded.ParticipantID != harness.session.Committee.Participants[0] {
		t.Fatalf("the committed share holds participant %d, want %d", loaded.ParticipantID, harness.session.Committee.Participants[0])
	}
	if !bytesEqualPrefix(loaded.Key.PublicKey, results[0].PublicKey[:]) {
		t.Fatal("the committed share holds a different group key")
	}
	loaded.Zeroize()
	if remaining := observed.takeTDilithium3PendingActivation(); remaining != nil {
		t.Fatal("the committed activation was left parked")
	}
}

// bytesEqualPrefix compares two byte slices for equality, tolerating the
// [1952]byte array versus slice shapes of the group key.
func bytesEqualPrefix(a, b []byte) bool {
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

// TestTDilithium3EarlyCeremonyTickGuards pins the tick's posture guards and
// the launch-marker lifecycle: the beat is inert outside the experimental
// runtime-DKG posture (offline configured, gate closed), a pre-marked
// activation epoch suppresses the launch, and a launch that refuses for a
// startup-order reason clears its marker so the next tick retries.
func TestTDilithium3EarlyCeremonyTickGuards(t *testing.T) {
	newTickNode := func(t *testing.T) *Node {
		return newEarlyCeremonyTickNode(t)
	}

	// Offline posture configured: the beat is fully inert, including the
	// promotion section (the offline path owns its activation timing).
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	offline := newTickNode(t)
	offline.config.TSSV1SealingActivationEpoch = 7
	offline.parkTDilithium3PendingActivation(&tdilithium3PendingActivation{activationEpoch: 7})
	offline.tdilithium3V1EarlyCeremonyTick(7 * consensus.SlotsPerEpoch)
	if earlyCeremonyMarker(offline) != 0 {
		t.Fatal("the beat launched a ceremony in the offline posture")
	}
	if pending := offline.takeTDilithium3PendingActivation(); pending == nil {
		t.Fatal("the beat consumed a parked activation in the offline posture")
	}

	// Experimental gate closed (mainnet's posture): equally inert.
	closed := newTickNode(t)
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "")
	_ = os.Unsetenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1")
	closed.tdilithium3V1EarlyCeremonyTick(7 * consensus.SlotsPerEpoch)
	if earlyCeremonyMarker(closed) != 0 {
		t.Fatal("the beat launched a ceremony with the experimental gate closed")
	}

	// Gate open again for the launch lifecycle cases.
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")

	// Gate open, marker pre-set for the target: the launch is suppressed.
	marked := newTickNode(t)
	setEarlyCeremonyMarker(marked, 8)
	marked.tdilithium3V1EarlyCeremonyTick(7 * consensus.SlotsPerEpoch)
	if earlyCeremonyMarker(marked) != 8 {
		t.Fatal("the tick disturbed a pre-marked activation epoch")
	}

	// Gate open, no marker, no roster: the launch fires (the marker is set
	// synchronously) and the retryable roster refusal clears the marker so
	// the next tick retries.
	launch := newTickNode(t)
	launch.tdilithium3V1EarlyCeremonyTick(7 * consensus.SlotsPerEpoch)
	if earlyCeremonyMarker(launch) != 8 {
		t.Fatalf("the early beat did not launch (marker=%d, want 8)", earlyCeremonyMarker(launch))
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if earlyCeremonyMarker(launch) == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if earlyCeremonyMarker(launch) != 0 {
		t.Fatal("a retryable launch refusal did not clear the attempt marker")
	}

	// A parked activation that is not due yet survives the tick untouched.
	notDue := newTickNode(t)
	notDue.parkTDilithium3PendingActivation(&tdilithium3PendingActivation{activationEpoch: 9})
	setEarlyCeremonyMarker(notDue, 10)
	notDue.tdilithium3V1EarlyCeremonyTick(7 * consensus.SlotsPerEpoch)
	if pending := notDue.takeTDilithium3PendingActivation(); pending == nil || pending.activationEpoch != 9 {
		t.Fatalf("a not-yet-due park was committed or dropped (pending=%v)", pending)
	}
}

// newEarlyCeremonyTickNode builds the minimal node the early-ceremony tick's
// guards demand: a config with a data directory and store password, a p2p
// host, and a producer shell carrying a QPOS whose epoch derives from the
// global genesis clock.
func newEarlyCeremonyTickNode(t *testing.T) *Node {
	t.Helper()
	host, err := p2p.NewHost(nil)
	if err != nil {
		t.Fatalf("p2p host: %v", err)
	}
	node := &Node{config: &Config{
		NetworkID:            TestnetNetworkID,
		DataDir:              t.TempDir(),
		ValidatorKeyPassword: "DEVNET ONLY tick guard password",
	}, p2pHost: host}
	node.blockProducer = &BlockProducer{node: node, qpos: &consensus.QPOS{}}
	t.Cleanup(func() { node.closeTDilithium3SigningJournals() })
	return node
}

// TestTDilithium3DeferredActivationStaleParkDropped pins the stale-park rule
// (audit round-3 low): a parked activation whose activation epoch the chain
// has already PASSED must be dropped, never committed — the commit would
// re-root the custody to a dead key and, through the re-root's purge of
// different-key entries, destroy the newer entries the import path already
// adopted. Only an activation epoch EQUAL to the chain's tick epoch commits.
func TestTDilithium3DeferredActivationStaleParkDropped(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	node := newEarlyCeremonyTickNode(t)
	setEarlyCeremonyMarker(node, 99) // suppress the launch section

	node.parkTDilithium3PendingActivation(&tdilithium3PendingActivation{activationEpoch: 5})
	// The chain clock is at epoch 0 (genesis "now"); tick a slot in epoch 7:
	// the park for epoch 5 is strictly behind.
	node.tdilithium3V1EarlyCeremonyTick(7 * consensus.SlotsPerEpoch)
	if pending := node.takeTDilithium3PendingActivation(); pending != nil {
		t.Fatalf("a stale park was kept (pending epoch %d)", pending.activationEpoch)
	}
	if _, _, _, err := newThresholdShareStore(node.config.DataDir).ActiveSharePublicIdentity([]byte(node.config.ValidatorKeyPassword)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a stale park was committed (err=%v)", err)
	}

	// A park for the CURRENT tick epoch still commits the normal path — no
	// certificate here means the commit fails and the park is re-tried, which
	// is the pre-existing retry contract, asserted to keep the boundary exact.
	node.parkTDilithium3PendingActivation(&tdilithium3PendingActivation{activationEpoch: 7})
	node.tdilithium3V1EarlyCeremonyTick(7*consensus.SlotsPerEpoch + 3)
	if pending := node.takeTDilithium3PendingActivation(); pending == nil || pending.activationEpoch != 7 {
		t.Fatalf("a due park was not re-parked after a failed commit (pending=%v)", pending)
	}
}

// TestTDilithium3EarlyCeremonyRetryableClassifiesDeterministicRefusals pins
// the retry classifier (audit round-3 low): a not-in-committee refusal is
// deterministic for the epoch (roster fixed at the boundary), so it must NOT
// clear the attempt marker, while the startup-order refusals stay retryable.
func TestTDilithium3EarlyCeremonyRetryableClassifiesDeterministicRefusals(t *testing.T) {
	notMember := fmt.Errorf("%w: local validator 0xabc is not in the epoch 7 committee: %w",
		errTDilithium3DKGSessionUnavailable, errTDilithium3DKGLocalNotACommitteeMember)
	if tdilithium3EarlyCeremonyRetryable(notMember) {
		t.Fatal("a deterministic not-in-committee refusal was classified retryable")
	}
	if !errors.Is(notMember, errTDilithium3DKGSessionUnavailable) {
		t.Fatal("the dual-sentinel wrap lost the refusal contract")
	}
	if !tdilithium3EarlyCeremonyRetryable(errTDilithium3DKGSessionUnavailable) ||
		!tdilithium3EarlyCeremonyRetryable(errTDilithium3DKGEpochRosterUnavailable) ||
		!tdilithium3EarlyCeremonyRetryable(errTDilithium3DKGCeremonyActive) {
		t.Fatal("a startup-order refusal lost its retryable classification")
	}
}

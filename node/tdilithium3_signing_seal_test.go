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
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
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

// TestTDilithium3SealSigningSignersForRoster requires the slot's attempt
// subset to report the local validator's membership by roster position, and
// the selection to refuse incomplete or unordered inputs.
func TestTDilithium3SealSigningSignersForRoster(t *testing.T) {
	fixture := tdilithium3SigningBindingTestFixtureFor(t)
	const slot, attempt = 0, 0
	signers, localSigner, err := tdilithium3SealSigningSignersForRoster(
		fixture.roster, fixture.committee, fixture.roster.Entries[2].Address, slot, attempt, tdilithium3SealSigningWeights{},
	)
	if err != nil {
		t.Fatalf("signers: %v", err)
	}
	if len(signers) != 4 {
		t.Fatalf("signers = %v, want four", signers)
	}
	for _, position := range []int{0, 1, 2, 3, 4, 5} {
		member := slices.Contains(signers, fixture.committee.Participants[position])
		if _, local, err := tdilithium3SealSigningSignersForRoster(
			fixture.roster, fixture.committee, fixture.roster.Entries[position].Address, slot, attempt, tdilithium3SealSigningWeights{},
		); err != nil || local != member {
			t.Fatalf("position %d membership = %v (err %v), want %v", position, local, err, member)
		}
	}
	_ = localSigner
	if _, _, err := tdilithium3SealSigningSignersForRoster(
		fixture.roster, fixture.committee, types.Address{0xEE}, slot, attempt, tdilithium3SealSigningWeights{},
	); err == nil {
		t.Fatal("validator outside the roster accepted")
	}
	if _, _, err := tdilithium3SealSigningSignersForRoster(
		nil, fixture.committee, fixture.roster.Entries[0].Address, slot, attempt, tdilithium3SealSigningWeights{},
	); err == nil {
		t.Fatal("missing roster accepted")
	}
	shortCommittee := fixture.committee.Clone()
	shortCommittee.Participants = shortCommittee.Participants[:4]
	if _, _, err := tdilithium3SealSigningSignersForRoster(
		fixture.roster, shortCommittee, fixture.roster.Entries[0].Address, slot, attempt, tdilithium3SealSigningWeights{},
	); err == nil {
		t.Fatal("committee that does not match the roster accepted")
	}
	unordered := fixture.committee.Clone()
	unordered.Participants = []uint32{1, 2, 4, 3, 5, 6}
	if _, _, err := tdilithium3SealSigningSignersForRoster(
		fixture.roster, unordered, fixture.roster.Entries[0].Address, slot, attempt, tdilithium3SealSigningWeights{},
	); err == nil {
		t.Fatal("unordered committee accepted")
	}
}

// tdilithium3SealSubsetTestCommittee is a committee of the given size with
// participant IDs 1..size.
func tdilithium3SealSubsetTestCommittee(size int) []uint32 {
	participants := make([]uint32, size)
	for index := range participants {
		participants[index] = uint32(index + 1)
	}
	return participants
}

// tdilithium3SealSubsetTestExcluded returns the participants a subset leaves out.
func tdilithium3SealSubsetTestExcluded(participants, subset []uint32) []uint32 {
	var excluded []uint32
	for _, participant := range participants {
		if !slices.Contains(subset, participant) {
			excluded = append(excluded, participant)
		}
	}
	return excluded
}

// The seal signers of a slot rotate over the committee so one offline member
// cannot stop sealing: within one slot the three attempts exclude disjoint
// pairs, so any single member is left out of one attempt; across the round
// every pair is left out once, so two offline members still let some slots
// seal. The selection is a pure function of the committee, slot, and attempt.
func TestTDilithium3SealSigningSubsetRotation(t *testing.T) {
	for _, size := range []int{6, 7} {
		participants := tdilithium3SealSubsetTestCommittee(size)
		threshold := (2*size + 2) / 3
		rounds := size - 1
		if size%2 == 1 {
			rounds = size
		}
		pairsPerRound := uint64(size / 2)
		if tdilithium3SealSigningMaxAttempts < 2*pairsPerRound {
			t.Fatalf("C=%d: %d attempts per slot do not walk the round's %d pairs twice",
				size, tdilithium3SealSigningMaxAttempts, pairsPerRound)
		}
		pairsSeen := make(map[[2]uint32]int)
		for slot := uint64(0); slot < uint64(rounds); slot++ {
			// The second walk repeats the first: a member that sits out one
			// attempt of the slot sits out a second one too, so a slot with
			// one member offline gets two attempts that can seal.
			for attempt := uint64(0); attempt < pairsPerRound; attempt++ {
				first, _ := tdilithium3SealSigningSubset(participants, threshold, slot, attempt, tdilithium3SealSigningWeights{})
				second, _ := tdilithium3SealSigningSubset(participants, threshold, slot, attempt+pairsPerRound, tdilithium3SealSigningWeights{})
				if !slices.Equal(first, second) {
					t.Fatalf("C=%d slot %d: attempt %d and %d select %v and %v", size, slot, attempt, attempt+pairsPerRound, first, second)
				}
			}
			excludedInSlot := make(map[uint32]int)
			for attempt := uint64(0); attempt < pairsPerRound; attempt++ {
				subset, err := tdilithium3SealSigningSubset(participants, threshold, slot, attempt, tdilithium3SealSigningWeights{})
				if err != nil {
					t.Fatalf("C=%d slot %d attempt %d: %v", size, slot, attempt, err)
				}
				if len(subset) != threshold || !slices.IsSorted(subset) {
					t.Fatalf("C=%d slot %d attempt %d: subset %v is not %d ascending signers", size, slot, attempt, subset, threshold)
				}
				again, _ := tdilithium3SealSigningSubset(participants, threshold, slot, attempt, tdilithium3SealSigningWeights{})
				if !slices.Equal(subset, again) {
					t.Fatalf("C=%d slot %d attempt %d: selection is not deterministic", size, slot, attempt)
				}
				excluded := tdilithium3SealSubsetTestExcluded(participants, subset)
				if len(excluded) != 2 {
					t.Fatalf("C=%d slot %d attempt %d: excluded %v, want one pair", size, slot, attempt, excluded)
				}
				for _, participant := range excluded {
					excludedInSlot[participant]++
				}
				pairsSeen[[2]uint32{excluded[0], excluded[1]}]++
			}
			for participant, count := range excludedInSlot {
				if count != 1 {
					t.Fatalf("C=%d slot %d: participant %d excluded %d times, want once", size, slot, participant, count)
				}
			}
			// Every member but at most one (the odd committee's bye) sits out
			// one attempt of the slot.
			if want := size - size%2; len(excludedInSlot) != want {
				t.Fatalf("C=%d slot %d: %d members sit out an attempt, want %d", size, slot, len(excludedInSlot), want)
			}
		}
		if want := size * (size - 1) / 2; len(pairsSeen) != want {
			t.Fatalf("C=%d: %d distinct pairs left out over a round, want all %d", size, len(pairsSeen), want)
		}
		for pair, count := range pairsSeen {
			if count != 1 {
				t.Fatalf("C=%d: pair %v left out %d times in one round", size, pair, count)
			}
		}
	}
	if _, err := tdilithium3SealSigningSubset(tdilithium3SealSubsetTestCommittee(6), 7, 0, 0, tdilithium3SealSigningWeights{}); err == nil {
		t.Fatal("a threshold above the committee size was accepted")
	}
	if _, err := tdilithium3SealSigningSubset(nil, 4, 0, 0, tdilithium3SealSigningWeights{}); err == nil {
		t.Fatal("an empty committee was accepted")
	}
}

// A seal attempt moves on to the next ordinal when its candidate slots were
// all filtered or when one of its signers is unreachable from this node (the
// next attempt's subset may exclude that signer); any other failure stops.
func TestTDilithium3SealAttemptRetryable(t *testing.T) {
	unreachable := fmt.Errorf("Dilithium3 v1 seal executor binding: %w",
		fmt.Errorf("%w: signer 0x11 has no peer binding", errTDilithium3SigningSignerUnreachable))
	exhausted := fmt.Errorf("%w: 11 candidate slots all filtered", errTDilithium3SigningRequestExhausted)
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{"exhausted request", exhausted, true},
		{"unreachable signer", unreachable, true},
		{"not a signer of this attempt", errTDilithium3SealSigningNotASigner, false},
		{"structural binding failure", fmt.Errorf("Dilithium3 signing share committee does not match the epoch roster"), false},
		{"no error", nil, false},
	} {
		if got := tdilithium3SealAttemptRetryable(test.err); got != test.want {
			t.Fatalf("%s: retryable = %v, want %v", test.name, got, test.want)
		}
	}
}

// A slot moves on to its next attempt only for a retryable failure, while
// ordinals remain, and while its retry window lasts; the window keeps slots
// whose attempts keep timing out from piling up behind the concurrent-session
// cap.
func TestTDilithium3SealSigningRetryAllowed(t *testing.T) {
	exhausted := fmt.Errorf("%w: all filtered", errTDilithium3SigningRequestExhausted)
	if !tdilithium3SealSigningRetryAllowed(exhausted, 0, true) {
		t.Fatal("a fresh exhausted attempt was not retried")
	}
	if tdilithium3SealSigningRetryAllowed(exhausted, tdilithium3SealSigningMaxAttempts-1, true) {
		t.Fatal("the last ordinal was retried")
	}
	if tdilithium3SealSigningRetryAllowed(exhausted, 0, false) {
		t.Fatal("a slot past its retry window was retried")
	}
	if tdilithium3SealSigningRetryAllowed(errTDilithium3SealSigningNotASigner, 0, true) {
		t.Fatal("a non-retryable failure was retried")
	}
}

// The retry window is anchored to the sealed slot's start on the chain clock,
// so every member, however late it joined the slot, stops starting the slot's
// attempts at the same time.
func TestTDilithium3SealRetryWindowIsSlotAnchored(t *testing.T) {
	consensus.EnableTestHelpers()
	consensus.ResetGenesisTimeForTesting()
	defer consensus.ResetGenesisTimeForTesting()
	if !tdilithium3SealWithinRetryWindow(5, time.Now()) {
		t.Fatal("without a chain clock the window must not bound anything")
	}
	if err := consensus.SetGenesisTime(1700000000); err != nil {
		t.Fatal(err)
	}
	const slot = 40
	start := consensus.GetSlotStartTime(slot)
	if !tdilithium3SealWithinRetryWindow(slot, start.Add(tdilithium3SealSigningRetryWindow)) {
		t.Fatal("the window's last instant was rejected")
	}
	if tdilithium3SealWithinRetryWindow(slot, start.Add(tdilithium3SealSigningRetryWindow+time.Second)) {
		t.Fatal("an instant past the window was accepted")
	}
}

// Attempts advance one ordinal at a time: a node admits only the first attempt
// or the retry after it until it has seen an attempt, and afterwards at most
// one past the highest it admitted. The ordinal history outlives the run.
func TestTDilithium3SealOrdinalAdmission(t *testing.T) {
	node := &Node{}
	const slot = 12
	if !node.tdilithium3SealOrdinalAdmissible(slot, 0) || !node.tdilithium3SealOrdinalAdmissible(slot, 1) {
		t.Fatal("the first attempt or the retry after it was refused on a fresh slot")
	}
	if node.tdilithium3SealOrdinalAdmissible(slot, 2) {
		t.Fatal("a fresh slot admitted a skip to attempt 2")
	}
	node.tdilithium3SealOrdinalRecord(slot, 1)
	if !node.tdilithium3SealOrdinalAdmissible(slot, 2) {
		t.Fatal("the next attempt was refused")
	}
	if !node.tdilithium3SealOrdinalAdmissible(slot, 1) {
		t.Fatal("re-entry with an admitted ordinal was refused")
	}
	if node.tdilithium3SealOrdinalAdmissible(slot, 3) {
		t.Fatal("a skip of two ordinals was admitted")
	}
	node.tdilithium3SealOrdinalRecord(slot, 0)
	if node.tdilithium3SealOrdinalAdmissible(slot, 3) {
		t.Fatal("recording a lower ordinal lowered the slot's high-water mark")
	}
	for later := uint64(slot + 1); later < slot+1+3*tdilithium3SealOrdinalHistorySlots; later++ {
		node.tdilithium3SealOrdinalRecord(later, 0)
	}
	if len(node.tdilithium3SealSigningOrdinals) > 2*tdilithium3SealOrdinalHistorySlots+1 {
		t.Fatalf("ordinal history holds %d slots, want it pruned", len(node.tdilithium3SealSigningOrdinals))
	}
}

// A member can announce only the attempt after one it signs, and only one
// ordinal past what the receivers saw, so it cannot skip the attempts that
// leave it out: those always run. Walk the attack from the review: a member of
// the pair excluded at attempt 0 tries to jump the slot straight to an attempt
// it belongs to.
func TestTDilithium3SealRetryCannotSkipExcludingAttempts(t *testing.T) {
	participants := tdilithium3SealSubsetTestCommittee(6)
	const slot = 3
	first, err := tdilithium3SealSigningSubset(participants, 4, slot, 0, tdilithium3SealSigningWeights{})
	if err != nil {
		t.Fatal(err)
	}
	attacker := tdilithium3SealSubsetTestExcluded(participants, first)[0]
	node := &Node{}
	node.tdilithium3SealOrdinalRecord(slot, 0)
	for ordinal := uint64(1); ordinal < tdilithium3SealSigningMaxAttempts; ordinal++ {
		admitted := node.tdilithium3SealOrdinalAdmissible(slot, ordinal)
		authorized, err := tdilithium3SealRetryAnnouncerAllowed(participants, 4, slot, ordinal, attacker, tdilithium3SealSigningWeights{})
		if err != nil {
			t.Fatal(err)
		}
		if admitted && authorized {
			t.Fatalf("participant %d, left out of attempt 0, could start attempt %d before attempt 0 ended", attacker, ordinal)
		}
	}
}

// A subset never leaves out a pair whose exclusion would drop the signers
// below the stake the finality engine requires; with equal stakes the
// selection is the plain round. Here one member holds most of the stake, so
// every admissible pair keeps it in, and attempts still rotate over the
// admissible pairs.
func TestTDilithium3SealSigningSubsetMeetsRequiredStake(t *testing.T) {
	participants := tdilithium3SealSubsetTestCommittee(6)
	equal := tdilithium3SealSigningWeights{required: big.NewInt(4), stakes: []*big.Int{
		big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1),
	}}
	for slot := uint64(0); slot < 10; slot++ {
		for attempt := uint64(0); attempt < tdilithium3SealSigningMaxAttempts; attempt++ {
			plain, _ := tdilithium3SealSigningSubset(participants, 4, slot, attempt, tdilithium3SealSigningWeights{})
			weighted, _ := tdilithium3SealSigningSubset(participants, 4, slot, attempt, equal)
			if !slices.Equal(plain, weighted) {
				t.Fatalf("slot %d attempt %d: equal stakes changed the subset %v -> %v", slot, attempt, plain, weighted)
			}
		}
	}
	// Stakes 100,100,100,100,101,101 require 402: only pairs that keep both
	// 101 holders and drop two 100 holders leave 402 behind.
	skewed := tdilithium3SealSigningWeights{required: big.NewInt(402), stakes: []*big.Int{
		big.NewInt(100), big.NewInt(100), big.NewInt(100), big.NewInt(100), big.NewInt(101), big.NewInt(101),
	}}
	for slot := uint64(0); slot < 10; slot++ {
		seen := map[string]bool{}
		for attempt := uint64(0); attempt < tdilithium3SealSigningMaxAttempts; attempt++ {
			subset, err := tdilithium3SealSigningSubset(participants, 4, slot, attempt, skewed)
			if err != nil {
				t.Fatal(err)
			}
			weight := int64(0)
			for _, participant := range subset {
				weight += skewed.stakes[participant-1].Int64()
			}
			if weight < 402 {
				t.Fatalf("slot %d attempt %d: subset %v holds %d < 402", slot, attempt, subset, weight)
			}
			seen[fmt.Sprint(subset)] = true
		}
		if len(seen) < 2 {
			t.Fatalf("slot %d: attempts did not rotate over the admissible pairs", slot)
		}
	}
	// No admissible pair at all: the first t participants, as before rotation.
	impossible := tdilithium3SealSigningWeights{required: big.NewInt(1000), stakes: skewed.stakes}
	subset, err := tdilithium3SealSigningSubset(participants, 4, 7, 2, impossible)
	if err != nil || !slices.Equal(subset, participants[:4]) {
		t.Fatalf("unsatisfiable stake view selected %v (err %v), want the first four", subset, err)
	}
}

// A retry announcement from a non-proposer is admitted only from a signer of
// the attempt that just failed, and only for a bounded ordinal.
func TestTDilithium3SealRetryAnnouncerRule(t *testing.T) {
	participants := tdilithium3SealSubsetTestCommittee(6)
	const slot = 9
	for ordinal := uint64(1); ordinal < tdilithium3SealSigningMaxAttempts; ordinal++ {
		previous, err := tdilithium3SealSigningSubset(participants, 4, slot, ordinal-1, tdilithium3SealSigningWeights{})
		if err != nil {
			t.Fatal(err)
		}
		for _, participant := range participants {
			admitted, err := tdilithium3SealRetryAnnouncerAllowed(participants, 4, slot, ordinal, participant, tdilithium3SealSigningWeights{})
			if err != nil {
				t.Fatal(err)
			}
			if want := slices.Contains(previous, participant); admitted != want {
				t.Fatalf("ordinal %d participant %d admitted = %v, want %v", ordinal, participant, admitted, want)
			}
		}
	}
	if admitted, _ := tdilithium3SealRetryAnnouncerAllowed(participants, 4, slot, 0, 1, tdilithium3SealSigningWeights{}); admitted {
		t.Fatal("a first attempt from a non-proposer was admitted")
	}
	if admitted, _ := tdilithium3SealRetryAnnouncerAllowed(participants, 4, slot, tdilithium3SealSigningMaxAttempts, 1, tdilithium3SealSigningWeights{}); admitted {
		t.Fatal("an ordinal beyond the attempt bound was admitted")
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
	if !node.tdilithium3SealOrdinalAdmissible(7, 3) || node.tdilithium3SealOrdinalAdmissible(7, 4) {
		t.Fatal("advancing did not record the ordinal")
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

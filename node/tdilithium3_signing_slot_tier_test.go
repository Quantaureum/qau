// Quantaureum Node source, version 1.0.0.
package node

// Tests of the domain-tiered per-slot deadline (TSS-R3-B-1 Wave C). The
// proposal path (block domain) bounds one candidate slot with the shorter
// proposal window, so a failed attempt's silence ends within it instead of
// waiting out the seal-sized default; the seal path (finality domain) keeps
// the default window. The behavioral test drives the real request schedule
// over scripted hanging slots -- the shape of a candidate whose peers never
// respond -- and bounds the failed attempt's wall-clock duration by the tier.

import (
	"context"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// TestTDilithium3SigningSlotTimeoutTieringByDomain pins the domain-to-deadline
// mapping: the block domain takes the proposal tier, and the finality domain
// (like every other domain) returns zero, which the production schedule
// substitutes with the seal-sized default window.
func TestTDilithium3SigningSlotTimeoutTieringByDomain(t *testing.T) {
	if got := tdilithium3SigningSlotTimeoutFor(protocol.SigningDomainBlock); got != tdilithium3ProposalSigningSlotTimeout {
		t.Fatalf("block domain slot timeout = %s, want the proposal tier %s", got, tdilithium3ProposalSigningSlotTimeout)
	}
	if got := tdilithium3SigningSlotTimeoutFor(protocol.SigningDomainFinality); got != 0 {
		t.Fatalf("finality domain slot timeout = %s, want zero (the seal keeps the default window)", got)
	}
	for _, domain := range []protocol.SigningDomain{protocol.SigningDomainUnknown, protocol.SigningDomainVote} {
		if got := tdilithium3SigningSlotTimeoutFor(domain); got != 0 {
			t.Fatalf("domain %d slot timeout = %s, want zero (non-block domains keep the default)", domain, got)
		}
	}
}

// TestTDilithium3SigningSealDefaultWindowPinned pins the seal-sized default
// window the finality domain keeps: a change to it must be deliberate,
// because the window has to outlast the seal path's measured ~6s signer start
// spread (a signer begins a slot only once it holds the block and the pending
// seal), not merely the four-round exchange.
func TestTDilithium3SigningSealDefaultWindowPinned(t *testing.T) {
	if tdilithium3SigningSlotTimeout != 15*time.Second {
		t.Fatalf("default slot timeout = %s, want the seal's 15s window", tdilithium3SigningSlotTimeout)
	}
}

// TestTDilithium3ProposalSigningSilentAttemptEndsWithinTier requires a
// proposal-tier request whose candidates never hear from their peers -- the
// silence shape of a failed attempt -- to end within the tiered window with
// every candidate's one-time material consumed. The bounds follow the tier
// constant (currently 5.5s: the band is [5.0s, 7.5s]); the upper bound is the
// tier plus scheduling slop, and the lower bound proves the candidates waited
// the slot deadline rather than failing early, so the test pins the tier
// value itself, not merely some shorter bound.
func TestTDilithium3ProposalSigningSilentAttemptEndsWithinTier(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	// An empty script leaves every candidate hanging: no peer message ever
	// arrives, so each driver runs to its slot deadline and starves -- the
	// production silence shape of a failed attempt.
	factory, built := tdilithium3SigningScheduleTestFactory(t, tdilithium3SigningScheduleTestScript{})
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	schedule, err := newTDilithium3SigningRequestSchedule(
		node, factory, 2, tdilithium3SigningSlotTimeoutFor(protocol.SigningDomainBlock),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	_, _, runErr := schedule.run(ctx)
	elapsed := time.Since(start)
	if runErr == nil {
		t.Fatalf("silent attempt returned no error; want the candidates' starve failure")
	}
	if elapsed < tdilithium3ProposalSigningSlotTimeout-500*time.Millisecond {
		t.Fatalf("silent attempt ended after %s, before the %s tier: the candidates did not wait the slot deadline",
			elapsed, tdilithium3ProposalSigningSlotTimeout)
	}
	if elapsed > tdilithium3ProposalSigningSlotTimeout+2*time.Second {
		t.Fatalf("silent attempt ended after %s, past the %s tier plus slop", elapsed, tdilithium3ProposalSigningSlotTimeout)
	}
	for index, stub := range *built {
		if !stub.wasBurned() {
			t.Fatalf("candidate %d left its material live after the tiered deadline", index+1)
		}
	}
}

// TestTDilithium3ProposalSigningSlotTimeoutPinned pins the proposal tier
// absolutely, mirroring the seal window's literal pin: the value itself, and
// the invariant that the tier stays under the producer's overall budget, so a
// silent attempt ends by the slot deadline (with its outcomes recorded)
// before the budget cancel can preempt the schedule.
func TestTDilithium3ProposalSigningSlotTimeoutPinned(t *testing.T) {
	if tdilithium3ProposalSigningSlotTimeout != 5500*time.Millisecond {
		t.Fatalf("proposal slot timeout = %s, want the pinned 5.5s tier", tdilithium3ProposalSigningSlotTimeout)
	}
	if tdilithium3ProposalSigningSlotTimeout >= tdilithium3ProposalSigningBudget {
		t.Fatalf("proposal slot timeout %s must stay under the producer budget %s so the slot deadline precedes the budget cancel",
			tdilithium3ProposalSigningSlotTimeout, tdilithium3ProposalSigningBudget)
	}
}

// TestSignWithTDilithium3SigningHandsDownTheTieredSlotTimeout captures, end to
// end through the production entry, the per-slot deadline the proposal and
// seal wiring hand down: a Block-domain request waits the 5.5s proposal tier
// and a Finality-domain request waits the seal's 15s default window. The
// capture is the wall-clock duration of a fully silent request -- a real
// ceremony-backed binding with real parties and a no-op broadcast, so no peer
// message ever arrives and every candidate starves at exactly the deadline
// the wiring configured. A lost or misrouted wiring line shows up as the
// wrong duration: the tier leaked onto the seal domain collapses the
// Finality case to ~5.5s, and a dropped wiring line stretches the Block case
// out to the 15s default.
func TestSignWithTDilithium3SigningHandsDownTheTieredSlotTimeout(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	fixture := tdilithium3SeamFixtureFor(t)
	signers := fixture.signersFor()
	share, err := fixture.shareOf(signers[0])
	if err != nil {
		t.Fatal(err)
	}
	privateKey := fixture.privateKeys[share.ParticipantID]
	identities := make(map[uint32]tdilithium3SigningIdentity, len(signers))
	for _, signer := range signers {
		identities[signer] = fixture.identities[signer]
	}
	journal, err := dilithium3v1.OpenSigningJournal(filepath.Join(t.TempDir(), "wiring-journal.db"))
	if err != nil {
		t.Fatalf("wiring journal: %v", err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	binding := &tdilithium3SigningBinding{
		Share: share, Signers: signers, Identities: identities,
		Sign: func(message []byte) ([]byte, error) {
			signature := make([]byte, mode3.SignatureSize)
			mode3.SignTo(privateKey, message, signature)
			return signature, nil
		},
		Broadcast: func(uint8, []byte) error { return nil }, // full silence: no peer ever answers
		Journal:   journal,
		Entropy:   rand.Reader,
		chainID:   tdilithium3SeamTestChainID,
	}
	node := &Node{config: &Config{NetworkID: tdilithium3SeamTestChainID}}

	cases := []struct {
		name   string
		domain protocol.SigningDomain
		slot   uint64
		lower  time.Duration
		upper  time.Duration
	}{
		// The block domain waits the proposal tier (5.5s); the finality
		// domain the seal's default window (15s). The bands carry generous
		// slop for the finish path and scheduler jitter.
		{"block domain takes the proposal tier", protocol.SigningDomainBlock, 71,
			tdilithium3ProposalSigningSlotTimeout - 500*time.Millisecond,
			tdilithium3ProposalSigningSlotTimeout + 2500*time.Millisecond},
		{"finality domain keeps the seal default", protocol.SigningDomainFinality, 72,
			tdilithium3SigningSlotTimeout - time.Second,
			tdilithium3SigningSlotTimeout + 2500*time.Millisecond},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// A parent deadline far above both windows only bounds a broken
			// run; the per-slot deadline under test stays the binding one.
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			message := []byte("QAU-TDILITHIUM3-V1-WIRING-" + testCase.name)
			start := time.Now()
			_, _, runErr := node.signWithTDilithium3Signing(
				ctx, binding, fixture.session.ActivationEpoch, testCase.slot, testCase.domain, message, 0,
			)
			elapsed := time.Since(start)
			if !errors.Is(runErr, errTDilithium3SigningRequestExhausted) {
				t.Fatalf("silent request error = %v, want %v", runErr, errTDilithium3SigningRequestExhausted)
			}
			if elapsed < testCase.lower || elapsed > testCase.upper {
				t.Fatalf("silent domain %d request ended after %s, outside [%s, %s]",
					testCase.domain, elapsed, testCase.lower, testCase.upper)
			}
		})
	}
}

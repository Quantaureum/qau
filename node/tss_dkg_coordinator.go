// Quantaureum Node source, version 1.0.0.
package node

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// dkgRoundWaitTimeout bounds each network wait (Round1 commitments, Round2
// shares) of a distributed DKG attempt. It is sized so that a peer which
// still verifies the previous round's post-quantum material on a loaded
// machine is waited for instead of abandoned; the attempt as a whole is
// bounded by the round window in runDistributedDKGBackground.
const dkgRoundWaitTimeout = 120 * time.Second

// ============================================================================
// Task 5 — node-layer distributed DKG wiring: DKGCoordinator
//
// The coordinator wires the wallet-layer distributed DKG pieces into the
// TSSManager at node startup when the TSSDistributedDKG switch is enabled
// (non-mainnet only — mainnet is hard-blocked by Config.Validate()):
//
//   - creates a real qtd.DistributedDKGRunner (protocol state machine) bound
//     to the DKG session (sessionID/rho),
//   - creates a P2PDKGTransport (cross-participant message exchange over the
//     P2P network),
//   - injects both into the TSSManager so GenerateKeyShares() takes the
//     multi-party distributed path instead of the single-process simulated
//     trusted-dealer path.
//
// When TSSDistributedDKG is OFF (default), no coordinator is created and node
// behavior is identical to previous releases.
// ============================================================================

// DKGCoordinator owns the distributed DKG wiring for this node. It is only
// ever constructed when the TSSDistributedDKG switch is enabled.
type DKGCoordinator struct {
	mgr       *tss.TSSManager
	transport *P2PDKGTransport
	sessionID []byte
	rho       [32]byte
}

// NewCoordinator constructs a DKGCoordinator for the given TSSManager and
// DKG round participant ID (1-based), and immediately wires a real runner +
// P2P transport into the manager so GenerateKeyShares() takes the
// multi-party distributed path.
//
// sessionID/rho must be agreed across all participants before starting the
// round; the node layer derives them from the genesis hash so all validators
// agree. host may be nil (outbound sends then fail closed with a clear
// error). Returns nil when mgr is nil.
func NewCoordinator(mgr *tss.TSSManager, participantID int, sessionID []byte, rho [32]byte, host *p2p.Host) *DKGCoordinator {
	if mgr == nil {
		return nil
	}
	c := &DKGCoordinator{
		mgr:       mgr,
		sessionID: append([]byte(nil), sessionID...),
		rho:       rho,
		transport: NewP2PDKGTransport(host, participantID, sessionID),
	}
	// Inject the real distributed runner + transport so GenerateKeyShares()
	// takes the multi-party distributed path.
	mgr.SetDistributedDKGRunner(qtd.NewRealDistributedDKGRunner(c.sessionID, c.rho))
	mgr.SetDKGTransport(c.transport)
	return c
}

// Transport returns the P2P DKG transport this coordinator created and
// injected. It is used by handleTSSMessage to route incoming DKG round
// messages (IngestCommitment / IngestShare) and by the node layer to install
// the participantID → peer resolver.
func (c *DKGCoordinator) Transport() *P2PDKGTransport {
	return c.transport
}

// SessionID returns the DKG session ID the coordinator bound to.
func (c *DKGCoordinator) SessionID() []byte {
	return append([]byte(nil), c.sessionID...)
}

// wireDKGCoordinator builds and wires the distributed DKG coordinator when
// the TSSDistributedDKG switch is enabled. It derives the DKG session binding
// (sessionID/rho) from the genesis hash MIXED WITH the round-window index so
// (a) all wall-clock-aligned participants in the same window agree on the same
// binding, and (b) each window is a cryptographically INDEPENDENT DKG instance
// — a stale message from a neighbor's other window is rejected at the handler
// (TSS-R7-11) and cannot poison this round (previously caused VSS failures).
// Resolves this node's participant ID (1-based validator index; falls back to
// 1 when the validator set is not yet available) and installs the
// participantID → P2P peer resolver so private shares are delivered
// point-to-point (never broadcast). Returns nil when no TSSManager is present.
func (n *Node) wireDKGCoordinator(windowIndex int64) *DKGCoordinator {
	if n.tssManager == nil {
		return nil
	}
	pid := n.getMyParticipantID()
	if pid < 1 {
		pid = 1
	}
	// Base seed: genesis hash (all nodes agree) or a fixed label pre-genesis.
	var base []byte
	if n.genesisBlock != nil {
		gh := block.ComputeBlockHash(n.genesisBlock.Header)
		base = gh[:]
	} else {
		base = []byte("quantaureum-distributed-dkg-v1")
	}
	// Mix the round-window index into both sessionID and rho so each window is
	// an independent instance. sha256(base || "dkg-window" || windowIndex).
	var wbuf [8]byte
	binary.BigEndian.PutUint64(wbuf[:], uint64(windowIndex))
	h := sha256.New()
	h.Write(base)
	h.Write([]byte("dkg-window"))
	h.Write(wbuf[:])
	sessionID := h.Sum(nil)
	var rho [32]byte
	copy(rho[:], sessionID[:32])
	c := NewCoordinator(n.tssManager, pid, sessionID, rho, n.p2pHost)
	if c == nil {
		return nil
	}
	c.Transport().SetPeerResolver(n.snapshotDKGPeerResolver())
	c.Transport().SetWaitTimeout(dkgRoundWaitTimeout)
	return c
}

// snapshotDKGPeerResolver captures the validator list ONCE, outside every TSS
// lock, and returns a resolver that afterwards only consults the P2P host's
// validator<->peer map. DKG and reshare rounds call the resolver while they
// own protocol state; resolving through QPOS.GetValidatorSet at that point
// takes qpos.mu and re-creates the lock inversion fixed in
// generateKeySharesDistributed (2026-09 six-node deadlock). A round is also
// bound to one validator set by construction, so the snapshot is the
// semantically right input: participant i is validator index i-1 of the set
// the round was started with.
func (n *Node) snapshotDKGPeerResolver() func(participantID int) (p2p.PeerID, bool) {
	var addrs []types.Address
	if n.blockProducer != nil && n.blockProducer.qpos != nil {
		if vs := n.blockProducer.qpos.GetValidatorSet(); vs != nil {
			for _, v := range vs.Validators() {
				addrs = append(addrs, v.Address)
			}
		}
	}
	host := n.p2pHost
	return func(participantID int) (p2p.PeerID, bool) {
		if host == nil || participantID < 1 || participantID > len(addrs) {
			return "", false
		}
		return host.GetPeerIDForValidator(addrs[participantID-1])
	}
}

// peerIDForDKGParticipant maps a DKG participant ID (1-based validator index)
// to its P2P peer ID for point-to-point share delivery. Fail-closed: returns
// false when the validator set or peer mapping is unavailable — private DKG
// shares must never fall back to broadcast.
func (n *Node) peerIDForDKGParticipant(participantID int) (p2p.PeerID, bool) {
	if n.p2pHost == nil || n.blockProducer == nil || n.blockProducer.qpos == nil {
		return "", false
	}
	vs := n.blockProducer.qpos.GetValidatorSet()
	if vs == nil {
		return "", false
	}
	validators := vs.Validators()
	if participantID < 1 || participantID > len(validators) {
		return "", false
	}
	return n.p2pHost.GetPeerIDForValidator(validators[participantID-1].Address)
}

// dkgResolverReady reports whether every OTHER participant (1..total, excluding
// this node) currently resolves to a P2P peer ID. Round2 of the distributed
// DKG delivers private shares point-to-point through this resolver, so DKG must
// not start until all recipients are deliverable — otherwise Round1 (gossip)
// succeeds but Round2 share delivery silently drops for unresolved peers and
// the round stalls in WaitShares. TSS-R7-12.
func (n *Node) dkgResolverReady(total int) bool {
	myPid := n.getMyParticipantID()
	for pid := 1; pid <= total; pid++ {
		if pid == myPid {
			continue
		}
		if _, ok := n.peerIDForDKGParticipant(pid); !ok {
			return false
		}
	}
	return true
}

// TSS-R7-08 (2026-09): background distributed-DKG driver.
//
// runDistributedDKGBackground closes the three startup-ordering bugs found in
// the 3-node testnet run (participant-ID collision, Round1 timeout before peer
// connect, fatal-on-failure). It is launched from Start() AFTER startServices
// so the blockProducer (which resolves this node's participant ID) exists and
// the P2P host is accepting peers.
//
// Flow:
//  1. Wait until this node's participant ID is resolvable (blockProducer ready
//     AND our validator address is in the set) — fixes participant=1 collision.
//  2. Wait until enough peers are connected to reach the DKG participant count
//     — fixes the Round1 "have 0 commitments" timeout.
//  3. Wire a FRESH coordinator (runner + transport) and run GenerateKeyShares.
//     On failure, retry with a fresh coordinator (the runner is single-use:
//     its state machine cannot be rewound), bounded by maxAttempts.
//  4. On success, persist the encrypted share + group key if configured.
//
// Non-fatal throughout: a node that cannot complete DKG keeps running without
// threshold signing (liveness continues; finality waits for the group key).
func (n *Node) runDistributedDKGBackground() {
	const (
		readyPollInterval = 2 * time.Second
		readyMaxWait      = 5 * time.Minute
		maxAttempts       = 10
		// TSS-R7-10 (2026-09): attempts are aligned to wall-clock round windows
		// instead of each node retrying on its own clock. All nodes compute the
		// same window boundary and start every attempt together, so their Round1
		// commitment broadcasts overlap in the same window. Without this,
		// independent retry timers drift: when a quorum finishes attempt N and
		// stops broadcasting, a lagging node on attempt N+1 sees zero commitments
		// and can never catch up. roundWindow must comfortably exceed the full
		// DKG round duration (settle 10s + Round1 wait 30s + Round2 wait 30s +
		// VSS/crypto + safetyMargin). At 90s the worst-case ~70s of work plus a
		// 5s end margin leaves room for VSS over the ~727KB commitments (TSS-R7-12).
		// Measured on a 6-node development box: Round1 commitment
		// verification costs roughly 5s per peer and Round2 share (VSS)
		// verification tens of seconds per peer, so a 6-party round spends
		// minutes in pure crypto before any network wait. Five minutes
		// leaves room for the 10s settle delay, both network waits
		// (dkgRoundWaitTimeout) and slower machines.
		roundWindow = 300 * time.Second
	)
	if n.tssManager == nil {
		return
	}
	total := n.config.TSSTotalShares

	// Phase 1+2: wait for a resolvable participant ID and enough peers. A
	// genesis DKG needs EVERY participant, so a validator that comes up late
	// must not make the others give up: keep waiting, warning once per
	// readyMaxWait, until the node shuts down. Observed 2026-09 on the
	// six-node testnet: one node could not bind its ports at start and the
	// other five abandoned the DKG for good after a fixed five-minute grace.
	nextWarn := time.Now().Add(readyMaxWait)
	for {
		if n.ctx.Err() != nil {
			return
		}
		pid := n.getMyParticipantID()
		peers := 0
		if n.p2pHost != nil {
			peers = n.p2pHost.PeerCount()
		}
		// Need our own valid pid, enough total participants reachable
		// (peers + self >= total), AND every other participant resolvable to a
		// P2P peer ID so Round2 private-share delivery can reach all recipients
		// (TSS-R7-12: peer count alone is not enough — the validator→peerID
		// resolver populates asynchronously from signed STATUS messages, and
		// starting before it is complete makes Round2 stall in WaitShares).
		// Committee-subset liveness (threshold-only) is a separate follow-up;
		// for genesis-set DKG all N must be present.
		if pid >= 1 && peers+1 >= total && n.dkgResolverReady(total) {
			nodeLog.Info("TSS-R7-08: DKG readiness met (participant=%d, peers=%d, need total=%d, resolver=complete) — starting distributed DKG",
				pid, peers, total)
			break
		}
		if time.Now().After(nextWarn) {
			nodeLog.Warn("TSS-R7-08: still waiting for DKG readiness after %v (participant=%d, peers=%d, need total=%d, resolverReady=%v); "+
				"the genesis DKG needs every validator online — finality will not advance until it completes",
				readyMaxWait, pid, peers, total, n.dkgResolverReady(total))
			nextWarn = time.Now().Add(readyMaxWait)
		} else {
			nodeLog.Debug("TSS-R7-08: waiting for DKG readiness (participant=%d, peers=%d, need total=%d, resolverReady=%v)", pid, peers, total, n.dkgResolverReady(total))
		}
		select {
		case <-n.ctx.Done():
			return
		case <-time.After(readyPollInterval):
		}
	}

	// Phase 3: run DKG with retries, fresh coordinator per attempt, aligned to
	// shared wall-clock round windows so all nodes broadcast in the same window.
	var lastErr error
	// safetyMargin keeps every attempt strictly inside its own window. See the
	// absolute-deadline note below (TSS-R7-12).
	const safetyMargin = 5 * time.Second
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Sleep until the next shared round-window boundary so every node starts
		// this attempt at (approximately) the same wall-clock instant. All nodes
		// compute the same boundary from UTC, so their Round1 broadcasts overlap.
		now := time.Now().UnixNano()
		windowNs := roundWindow.Nanoseconds()
		windowIndex := (now / windowNs) + 1
		windowStart := windowIndex * windowNs
		windowEnd := windowStart + windowNs
		time.Sleep(time.Duration(windowStart - now))

		// TSS-R7-08 in-round barrier fix: wire the fresh coordinator FIRST (its
		// transport starts buffering inbound commitments/shares immediately), then
		// wait a short settle delay before GenerateKeyShares broadcasts Round1.
		// Because all nodes align to the same window boundary, they all wire their
		// coordinators within ~1s; the settle delay guarantees every node's
		// receiver is live BEFORE any node broadcasts, so no early commitment is
		// dropped (the previous fire-and-forget race left nodes at "have 3/5").
		const settleDelay = 10 * time.Second

		// A runner is single-use; rewire a fresh coordinator each attempt so a
		// failed/partial round does not leave the state machine wedged. The
		// windowIndex binds this attempt's sessionID/rho so all aligned nodes
		// share one instance and stale cross-window messages are rejected.
		n.dkgCoordinator = n.wireDKGCoordinator(windowIndex)
		if n.dkgCoordinator == nil {
			lastErr = fmt.Errorf("wireDKGCoordinator returned nil")
			continue
		}
		nodeLog.Info("TSS-R7-08: distributed DKG attempt %d/%d wired (participant=%d, session=%x); settling %v before Round1 broadcast",
			attempt, maxAttempts, n.dkgCoordinator.Transport().ParticipantID(), n.dkgCoordinator.SessionID()[:8], settleDelay)
		time.Sleep(settleDelay)

		// Run GenerateKeyShares bounded by an ABSOLUTE deadline tied to this
		// window's END boundary (TSS-R7-12), NOT a relative duration measured
		// from now. This is the fix for a permanent-desync bug: previously the
		// bound was a full roundWindow measured after the settle delay, so a node
		// that ran the whole round woke ~settleDelay INTO the next window and
		// computed the boundary after that — skipping a window. Meanwhile a node
		// that failed fast (via the transport's internal 30s+30s waits, ~70s)
		// caught the next boundary. The two land on different windows → different
		// sessionIDs → TSS-R7-11 rejects each other → the round never converges.
		// Anchoring the deadline to windowEnd-safetyMargin guarantees every node
		// — whether it fails fast or runs the full round — finishes inside the
		// SAME window and loops back to sleep for the SAME next boundary.
		type dkgResult struct {
			err error
		}
		resCh := make(chan dkgResult, 1)
		attemptDone := make(chan struct{})
		go func() {
			defer close(attemptDone)
			defer func() {
				if r := recover(); r != nil {
					resCh <- dkgResult{err: fmt.Errorf("GenerateKeyShares panic: %v", r)}
				}
			}()
			attemptDeadline := time.Unix(0, windowEnd-safetyMargin.Nanoseconds())
			attemptCtx, cancelAttempt := context.WithDeadline(n.ctx, attemptDeadline)
			gpk, gerr := n.tssManager.GenerateKeySharesCtx(attemptCtx)
			cancelAttempt()
			if gerr == nil && gpk == nil {
				gerr = fmt.Errorf("GenerateKeyShares returned nil result")
			}
			resCh <- dkgResult{err: gerr}
		}()

		// Bound the wait by the ABSOLUTE window end as well: the ctx deadline
		// unwinds the network waits, but a round stuck in a call that ignores
		// ctx must not wedge this loop. The manager no longer holds its lock
		// during a round, so an abandoned round cannot block the node; the
		// next attempt fails fast with tss.ErrDKGInProgress until the stuck
		// goroutine unwinds, which stays visible in the logs.
		windowTimer := time.NewTimer(time.Until(time.Unix(0, windowEnd)))
		var err error
		select {
		case r := <-resCh:
			err = r.err
		case <-attemptDone:
			// The goroutine sends its result before closing attemptDone, so
			// drain resCh before concluding it exited without one.
			select {
			case r := <-resCh:
				err = r.err
			default:
				err = fmt.Errorf("GenerateKeyShares exited without a result (stuck round abandoned; realigning next window)")
			}
		case <-windowTimer.C:
			err = fmt.Errorf("GenerateKeyShares did not finish before the window end (stuck round abandoned; realigning next window)")
		case <-n.ctx.Done():
			windowTimer.Stop()
			return
		}
		windowTimer.Stop()

		if err == nil {
			gpk := n.tssManager.GroupPublicKey()
			fp := sha256.Sum256(gpk)
			nodeLog.Info("TSS-R7-08: distributed DKG COMPLETE on attempt %d — group public key size=%d, fingerprint=%x, shareCount=%d",
				attempt, len(gpk), fp[:8], n.tssManager.ShareCount())
			n.dkgPending = false
			n.persistDKGArtifacts()
			if n.blockProducer != nil && n.blockProducer.QPOS() != nil {
				qpos := n.blockProducer.QPOS()
				// Re-register the threshold signer with QTD finality. At startup
				// the signer was rejected (QTD-H01) because no share existed yet;
				// InitChambers re-runs that registration now that the group key
				// and this node's share are in place. Without it the executive
				// chamber activates but every seal fails with "qtdSigner not
				// configured" (observed on the 2026-09 six-node run).
				qpos.InitChambers()
				if qfs := qpos.GetQTDFinality(); qfs != nil {
					// Report the outcome, not the intent. InitChambers was just
					// called, but setQTDSignerLocked silently rejects a signer
					// that does not report threshold mode (QTD-H01) and mutates
					// nothing. This line used to claim registration regardless,
					// which hid a nil qtdSigner until the first seal failed with
					// "qtdSigner not configured" — on the 2026-09 six-node run it
					// logged success in the same millisecond as the rejection.
					// The finality type is the observable evidence: it stays
					// CasperFFG unless a signer was actually recorded.
					if qfs.GetFinalityType() == consensus.FinalityQTDInstant {
						nodeLog.Info("TSS-R7-08: QTD finality signer registered after distributed DKG (mode=%s)", qfs.GetFinalityType().String())
					} else if experimentalTDilithium3V1Enabled() {
						nodeLog.Debug("TSS-R7-08: QTD finality signer not registered after legacy DKG (mode=%s) — expected when the Dilithium3 v1 experimental gate is open; the v1 signer will be registered after the activation ceremony completes", qfs.GetFinalityType().String())
					} else {
						nodeLog.Warn("TSS-R7-08: QTD finality signer NOT registered after distributed DKG (mode=%s) — QTD-H01 rejected the signer because it does not report threshold mode; the executive chamber will activate but every seal will fail with \"qtdSigner not configured\"", qfs.GetFinalityType().String())
					}
				}
				coordinator := qpos.GetChambersCoordinator()
				if coordinator != nil {
					if !coordinator.CompleteDKGViaDistributedRunner(qpos.GetCurrentEpoch()) && n.config.NetworkID != MainnetNetworkID && !n.config.TSSDistributedDKG {
						coordinator.TriggerDKG(gpk)
					}
				}
			}
			return
		}
		lastErr = err
		nodeLog.Warn("TSS-R7-08: distributed DKG attempt %d/%d failed: %v (retrying next round window)",
			attempt, maxAttempts, err)
	}
	nodeLog.Error("TSS-R7-08: distributed DKG failed after %d attempts (last error: %v) — "+
		"node continues without threshold signing; finality will not advance until DKG completes",
		maxAttempts, lastErr)
}

// persistDKGArtifacts writes the encrypted share + group key to the configured
// files after a successful distributed DKG, so a restart re-imports instead of
// re-running DKG. Best-effort: logs errors, never fatal.
func (n *Node) persistDKGArtifacts() {
	if n.config.TSSKeyShareFile != "" {
		if err := n.persistTSSKeyState(); err != nil {
			nodeLog.Error("Failed to persist encrypted TSS state: %v", err)
		}
	}
	if n.config.TSSGroupKeyFile != "" {
		if data, err := n.tssManager.ExportGroupPublicKey(); err == nil {
			if werr := os.WriteFile(n.config.TSSGroupKeyFile, data, 0600); werr != nil {
				nodeLog.Error("TSS-R7-08: failed to write group key to %s: %v", n.config.TSSGroupKeyFile, werr)
			} else {
				nodeLog.Info("TSS-R7-08: group public key exported to %s", n.config.TSSGroupKeyFile)
			}
		}
	}
}

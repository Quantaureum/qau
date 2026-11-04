// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"sync"
)

// ErrVDFSeedUnavailable is returned when the hardened proposer seed cannot be
// derived for an epoch at or after the consensus-hardening activation epoch.
// Every node stands down for that epoch instead of each node falling back to
// a different unhardened seed (audit QR-21).
var ErrVDFSeedUnavailable = errors.New("consensus hardening: VDF seed unavailable, refusing to elect for this epoch (QR-21)")

// consensusHardeningState holds the shared epoch-gated protocol switches for
// the QR-22/QR-42/QR-40/QR-28/QR-21 audit batch.
//
// It owns a dedicated mutex on purpose: these methods are called from paths
// that already hold q.mu (read or write). Nesting a second q.mu.RLock can
// deadlock when a writer is waiting, so this state must never use q.mu.
//
// Zero value is ready to use; activationEpoch == 0 means every hardening
// behavior stays off and the consensus paths are byte-identical to legacy.
type consensusHardeningState struct {
	mu                sync.RWMutex
	activationEpoch   uint64
	stalledChainProbe func(epoch uint64) bool
	vdfStopped        map[uint64]struct{}
}

// SetConsensusHardeningEpoch sets the first epoch at which the coordinated
// hardening semantics apply. 0 / unset keeps the legacy behavior on every
// path. MUST be identical on every node of the network: a divergent value
// changes the accepted block set at the activation epoch and forks the chain.
// Called once at node startup before the first epoch transition.
func (q *QPOS) SetConsensusHardeningEpoch(epoch uint64) {
	q.hardening.mu.Lock()
	q.hardening.activationEpoch = epoch
	q.hardening.mu.Unlock()
}

// ConsensusHardeningEpoch returns the configured activation epoch (0 = off).
func (q *QPOS) ConsensusHardeningEpoch() uint64 {
	q.hardening.mu.RLock()
	epoch := q.hardening.activationEpoch
	q.hardening.mu.RUnlock()
	return epoch
}

// HardeningActive reports whether the coordinated semantics apply to epoch.
func (q *QPOS) HardeningActive(epoch uint64) bool {
	q.hardening.mu.RLock()
	n := q.hardening.activationEpoch
	q.hardening.mu.RUnlock()
	return n > 0 && epoch >= n
}

// SetStalledChainProbe wires the QR-28/QR-42 canonical-chain probe:
// probe(epoch) reports whether the canonical chain holds NO block in epoch,
// i.e. no node can ever hold that epoch's VRF accumulator. The node layer
// supplies the implementation (it owns the block store); nil disables the
// probe and keeps the fail-closed behavior.
func (q *QPOS) SetStalledChainProbe(probe func(epoch uint64) bool) {
	q.hardening.mu.Lock()
	q.hardening.stalledChainProbe = probe
	q.hardening.mu.Unlock()
}

// ChainHasNoBlockInEpoch reports the canonical-chain evidence for a missing
// accumulator. False when no probe is wired (fail-closed).
func (q *QPOS) ChainHasNoBlockInEpoch(epoch uint64) bool {
	q.hardening.mu.RLock()
	probe := q.hardening.stalledChainProbe
	q.hardening.mu.RUnlock()
	if probe == nil {
		return false
	}
	return probe(epoch)
}

// vdfSeedActiveFor reports whether a hardened VDF seed is expected for the
// shuffle epoch. vdfSeedFor returns ok=false both when the feature is not
// configured yet (a normal pre-activation state) and when an evaluation
// genuinely failed; only the latter may pin the epoch. Caller must hold q.mu
// (at least RLock) because vdfSeedCfg is written under the write lock.
func (q *QPOS) vdfSeedActiveFor(epoch uint64) bool {
	cfg := q.vdfSeedCfg
	return cfg != nil && epoch >= cfg.ActivationEpoch
}

// MarkVDFSeedStopped pins an epoch whose hardened VDF seed could not be
// derived. Election entry points consult VDFSeedStopped and stand down.
func (q *QPOS) MarkVDFSeedStopped(epoch uint64) {
	q.hardening.mu.Lock()
	if q.hardening.vdfStopped == nil {
		q.hardening.vdfStopped = make(map[uint64]struct{})
	}
	q.hardening.vdfStopped[epoch] = struct{}{}
	q.hardening.mu.Unlock()
}

// VDFSeedStopped reports whether election must stand down for epoch.
func (q *QPOS) VDFSeedStopped(epoch uint64) bool {
	q.hardening.mu.RLock()
	_, ok := q.hardening.vdfStopped[epoch]
	q.hardening.mu.RUnlock()
	return ok
}

// ClearVDFSeedStopped releases a stop pin, e.g. after a reorg invalidated the
// accumulator that produced the failure. Safe to call for unknown epochs.
func (q *QPOS) ClearVDFSeedStopped(epoch uint64) {
	q.hardening.mu.Lock()
	delete(q.hardening.vdfStopped, epoch)
	q.hardening.mu.Unlock()
}

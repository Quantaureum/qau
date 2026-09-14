// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
)

// MinistryRites is the governance ministry. P1-T6 (2026-07-15): The in-memory
// proposal system (CreateProposal/CastVote/TallyProposal/ExecuteProposal) has
// been removed — it was 100% dead code in production with zero callers outside
// tests. All governance proposals now flow through economics.GovernanceManager
// (the production path, exposed via qau_createProposal / qau_castVote /
// qau_finalizeProposal / qau_executeProposal RPC methods).
//
// MinistryRites' sole production responsibility is implementing the
// economics.EmergencyActionHandler interface: when GovernanceManager executes
// an Emergency-type proposal, it delegates the consensus-layer side effect
// (blacklisting all validators via Defense ministry) to HandleEmergencyAction.
type MinistryRites struct {
	mu sync.RWMutex

	qpos        *QPOS
	coordinator *ThreeChambersCoordinator
	registry    *MinistryRegistry

	operations uint64
	errors     uint64
	lastActive time.Time
}

func NewMinistryRites(qpos *QPOS, coordinator *ThreeChambersCoordinator, registry *MinistryRegistry) *MinistryRites {
	return &MinistryRites{
		qpos:        qpos,
		coordinator: coordinator,
		registry:    registry,
	}
}

// HandleEmergencyAction implements the economics.EmergencyActionHandler interface.
// P1-T6 (2026-07-14): Called by economics.GovernanceManager.ExecuteProposal when
// an Emergency-type proposal is executed. This is the PRODUCTION path for
// emergency chain halts — GovernanceManager is the single source of truth for
// proposal state, and delegates the consensus-layer side effect (blacklisting
// all validators via Defense ministry) to this method.
//
// This method does NOT acquire mr.mu to avoid potential deadlock with
// GovernanceManager.mu (which is already released before this is called) and
// QPOS.mu (acquired by GetValidatorSet). The emergency halt only reads
// mr.registry and mr.qpos (both immutable after construction) and calls
// Defense.AddToBlacklist (which has its own lock).
func (mr *MinistryRites) HandleEmergencyAction(proposalID uint64, proposer types.Address, title, description string) error {
	// GOV-R7-09 (Low): proposer is the real account that created the
	// emergency proposal. It is recorded in the MinistryRites audit log
	// so emergency halts are attributable to a real account. The
	// AddToBlacklist authorization still uses getVotingSystemCaller()
	// because AddToBlacklist requires a system-caller (proposer is a
	// regular account and would be rejected by isSystemCaller); the
	// system caller is the consensus-internal delegate that actually
	// performs the blacklisting, while proposer is preserved for
	// audit traceability.
	caller := getVotingSystemCaller()
	mr.executeEmergencyHaltUnlocked(caller, proposer, proposalID, title)
	return nil
}

// executeEmergencyHaltUnlocked blacklists ALL validators via the Defense
// ministry, effectively halting block production, attestation, and sealing.
// P1-T6 (2026-07-14): Extracted from the now-removed ExecuteProposal to share
// between HandleEmergencyAction (production path from GovernanceManager).
//
// caller is the system-caller used to authorize AddToBlacklist (must pass
// isSystemCaller). proposer is the real account that submitted the emergency
// proposal — recorded in the audit log for traceability (GOV-R7-09).
//
// Caller is responsible for lock management. When called from
// HandleEmergencyAction: no lock held (production path from GovernanceManager).
//
// This is safe because executeEmergencyHaltUnlocked only reads immutable fields
// (mr.registry, mr.qpos) and calls Defense.AddToBlacklist (own lock).
func (mr *MinistryRites) executeEmergencyHaltUnlocked(caller, proposer types.Address, proposalID uint64, title string, blockTime ...int64) {
	if mr.registry == nil || mr.registry.Defense() == nil || mr.qpos == nil {
		qposAdvLogger.Warnf("governance: emergency action proposal %d executed but Defense/QPOS unavailable: %s", proposalID, title)
		return
	}
	md := mr.registry.Defense()
	vs := mr.qpos.GetValidatorSet()
	if vs == nil {
		qposAdvLogger.Warnf("governance: emergency action proposal %d executed but validator set is nil: %s", proposalID, title)
		return
	}
	halted := 0
	for i := range vs.Validators() {
		// Permanent blacklist (duration=0) — requires manual
		// removal via RemoveFromBlacklist to resume.
		if err := md.AddToBlacklist(caller, i, fmt.Sprintf("emergency halt via proposal %d", proposalID), 0, blockTime...); err == nil {
			halted++
		}
	}
	// GOV-R7-09: Attribute the emergency halt to the real proposer in
	// the audit log. The Defense ministry's blacklist_add audit entries
	// will reference the system caller (required for authorization), so
	// this Rites-level entry is the canonical link from proposalID →
	// real account for post-incident review.
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}
	if mr.registry != nil {
		mr.registry.logAudit(MinistryIDRites, "emergency_halt", proposer,
			fmt.Sprintf("proposalID=%d title=%s halted=%d", proposalID, title, halted),
			"ok", now)
	}
	qposAdvLogger.Warnf("governance: EMERGENCY ACTION proposal %d executed by %x: %d validators blacklisted, chain halted: %s", proposalID, proposer[:4], halted, title)
}

func (mr *MinistryRites) GetStatus() map[string]any {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	return map[string]any{
		"ministry":    MinistryIDRites.String(),
		"displayName": MinistryIDRites.DisplayName(),
		"active":      true,
		"operations":  mr.operations,
		"errors":      mr.errors,
		"lastActive":  mr.lastActive,
		// P1-T6 (2026-07-15): Proposal count fields removed. Governance
		// proposals are handled by economics.GovernanceManager. Use
		// qau_getProposalCount / qau_getActiveProposals RPC methods to
		// query real governance data.
	}
}

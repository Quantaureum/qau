// Quantaureum Node source, version 1.0.0.
package consensus

// run-4 follow-up (node 8245a07 port): regression coverage for the consensus
// call sites keyed on params.IsProductionFailClosed(GetAttestationNetworkID()).
//
// IsProductionFailClosed treats an UNSET network ID (0 = unknown identity) as
// production. These call sites were previously vulnerable to a fail-open
// regression: if any of them reverted to params.IsProduction(networkID) or
// params.IsProductionEnv(), a node that never declared its network identity
// would silently run with the production guard disarmed.
//
// Covered here (behavioural branches):
//   - QPOS.CanPropose              (consensus/block.go, no-chamber + chamber paths)
//   - NewDAAttestationVerifier     (consensus/da_attestation_verifier.go, disabled committee)
//   - DAAttestationCollector.BuildAggregateAttestation
//     (consensus/da_committee.go, legacy attestation with empty BlobCommitments)
//   - ThreeChambersCoordinator.AssignExecutive (consensus/provinces.go)
//
// CheckDAAvailability (consensus/block.go) is already pinned by
// production_gate_networkid_test.go.
//
// Deliberately NOT covered, with rationale:
//   - consensus/qtd_finality.go and consensus/sealed_bid.go branch on the same
//     predicate but only to choose the LOG LEVEL (Error vs Warn); the control
//     flow is identical in both modes (the partial signature is accepted and
//     the lottery phase stays pinned). Asserting log severity would require a
//     global logger capture harness that this package does not have today, so
//     the cost outweighs the regression value. Behaviour in these two files is
//     pinned by their existing tests.
//
// These tests mutate the package-wide attestation network identity, so none of
// them may call t.Parallel().

import (
	"errors"
	"strings"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/types"
)

// unknownNetworkIDFailClosed leaves the attestation network identity UNSET (0)
// with QAU_PRODUCTION unset, restoring devnet after the test.
func unknownNetworkIDFailClosed(t *testing.T) {
	t.Helper()
	EnableTestHelpers()
	ResetAttestationNetworkIDForTesting()
	t.Setenv("QAU_PRODUCTION", "")
	t.Cleanup(func() {
		SetAttestationNetworkID(params.DevnetChainID)
	})
	if got := GetAttestationNetworkID(); got != 0 {
		t.Fatalf("test setup: attestation network ID = %d, want 0", got)
	}
}

// TestProductionGate_CanPropose_UnknownNetworkID pins the DA hard-reject in
// both the legacy (no chambers) and the chamber-based CanPropose paths.
func TestProductionGate_CanPropose_UnknownNetworkID(t *testing.T) {
	unknownNetworkIDFailClosed(t)

	qpos, err := NewQPOS(createTestValidatorSet(t, 4))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qpos.SetDAAvailabilityChecker(func(slot uint64) error {
		return errors.New("DA sampling failed")
	})
	if qpos.CanPropose(0, 1) {
		t.Fatal("CanPropose must hard-reject when the network identity is unknown (0)")
	}

	chambered, err := NewQPOS(createTestValidatorSet(t, 10))
	if err != nil {
		t.Fatalf("NewQPOS (chambers): %v", err)
	}
	chambered.InitChambers()
	chambered.SetDAAvailabilityChecker(func(slot uint64) error {
		return errors.New("DA sampling failed")
	})
	if chambered.CanPropose(0, 1) {
		t.Fatal("chambered CanPropose must hard-reject when the network identity is unknown (0)")
	}

	// Control: once a non-mainnet network is declared the soft check returns.
	SetAttestationNetworkID(params.DevnetChainID)
	if !qpos.CanPropose(0, 1) {
		t.Fatal("devnet CanPropose must stay soft (liveness priority) on DA failure")
	}
}

// TestProductionGate_DAAttestationVerifier_UnknownNetworkID pins the disabled-
// committee hard reject. The attestation carries a real Dilithium3 signature
// so the failure under test is the production gate, not a signature failure.
func TestProductionGate_DAAttestationVerifier_UnknownNetworkID(t *testing.T) {
	validators, keypairs := makeVerifierValidators(t, 2)
	lookup := func() []*ValidatorInfo { return validators }

	mgr := NewDACommitteeManager(lookup, func(epoch uint64) types.Hash {
		return types.Hash{byte(epoch)}
	})
	mgr.SetConfig(DACommitteeConfig{Enabled: false, Size: 0})

	verifier := NewDAAttestationVerifier(lookup, mgr)
	att := signAttestationForTest(t, newSampleAttestation(0), keypairs[0].Private)

	unknownNetworkIDFailClosed(t)
	err := verifier(att)
	if err == nil {
		t.Fatal("verifier must reject a disabled committee when the network identity is unknown (0)")
	}
	if !strings.Contains(err.Error(), "production") {
		t.Fatalf("expected the production fail-closed error, got: %v", err)
	}

	// Control: devnet keeps the small-network exemption (membership skipped).
	SetAttestationNetworkID(params.DevnetChainID)
	if err := verifier(att); err != nil {
		t.Fatalf("devnet must skip the membership check for a disabled committee: %v", err)
	}
}

// TestProductionGate_BuildAggregateAttestation_UnknownNetworkID pins the
// rejection of legacy attestations (empty BlobCommitments) when the caller
// supplies a non-empty commitment set. Legacy attestations bind only to
// commitments[0], so production must refuse them.
func TestProductionGate_BuildAggregateAttestation_UnknownNetworkID(t *testing.T) {
	commitments := []encoding.KZGCommitment{{0x01, 0x02, 0x03}}
	const n = 2

	c := NewDAAttestationCollector()
	c.SetCommitteeSize(n)
	c.SetAttestationVerifier(func(att *encoding.DASAttestation) error { return nil })
	for i := 0; i < n; i++ {
		att := &encoding.DASAttestation{
			Slot:           100,
			Available:      true,
			ValidatorIndex: i,
			Signature:      []byte{byte(i), 0xAA},
			SampleCount:    10,
			SuccessCount:   10,
			Confidence:     0.9999,
			// Legacy binding: only the truncated 32-byte field, no trailing set.
			BlobCommitment: types.BytesToHash(commitments[0][:]),
		}
		if err := c.SubmitAttestation(att); err != nil {
			t.Fatalf("SubmitAttestation %d: %v", i, err)
		}
	}

	unknownNetworkIDFailClosed(t)
	if agg := c.BuildAggregateAttestation(100, commitments); agg != nil {
		t.Fatal("BuildAggregateAttestation must reject legacy attestations when the network identity is unknown (0)")
	}

	// Control: devnet keeps the legacy fallback (matching BlobCommitment).
	SetAttestationNetworkID(params.DevnetChainID)
	agg := c.BuildAggregateAttestation(100, commitments)
	if agg == nil {
		t.Fatal("devnet must accept legacy attestations whose BlobCommitment matches")
	}
	if agg.AvailableCount != n || agg.TotalCount != n {
		t.Fatalf("aggregate counts mismatch: available=%d total=%d, want %d/%d",
			agg.AvailableCount, agg.TotalCount, n, n)
	}
}

// TestProductionGate_AssignExecutive_UnknownNetworkID pins the direct-assignment
// ban independent of requireDistributedDKG and QAU_PRODUCTION.
func TestProductionGate_AssignExecutive_UnknownNetworkID(t *testing.T) {
	unknownNetworkIDFailClosed(t)

	qpos, err := NewQPOS(createTestValidatorSet(t, 10))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("coordinator is nil")
	}

	err = coordinator.AssignExecutive([]int{0, 1, 2}, 999)
	if err != ErrAssignExecutiveDisabledInProduction {
		t.Fatalf("AssignExecutive with unknown network identity = %v, want %v",
			err, ErrAssignExecutiveDisabledInProduction)
	}

	// Control: devnet allows the test/net-only direct assignment.
	SetAttestationNetworkID(params.DevnetChainID)
	if err := coordinator.AssignExecutive([]int{0, 1, 2}, 999); err != nil {
		t.Fatalf("devnet AssignExecutive must succeed: %v", err)
	}
}

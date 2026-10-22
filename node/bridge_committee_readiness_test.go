// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/bridge"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/lightclient"
)

// Compile-time assertion: the concrete verifier injected at startup must
// expose committee readiness so mainnet strict mode can detect an empty
// committee (R3-02).
var _ bridge.SyncCommitteeReadiness = (*lightclient.SyncCommitteeVerifier)(nil)

type headerOnlyChecker struct{}

func (headerOnlyChecker) VerifyBlockHeader(*encoding.BlockHeader) error { return nil }

func TestExternalChainSyncCommitteeReadiness(t *testing.T) {
	v := bridge.NewBridgeHeaderVerifier()
	if v.IsExternalChainSyncCommitteeReady() {
		t.Fatal("unconfigured verifier reported ready")
	}

	// Configured but empty committee: not ready to verify signatures.
	sc := lightclient.NewSyncCommitteeVerifier()
	v.SetExternalChainSyncCommittee(sc)
	if !v.HasExternalChainSyncCommittee() {
		t.Fatal("configured checker not reported as present")
	}
	if v.IsExternalChainSyncCommitteeReady() {
		t.Fatal("empty committee reported as ready")
	}

	// Once a committee is loaded, readiness flips to true.
	sc.UpdateCurrentCommittee(&lightclient.SyncCommitteeInfo{
		ValidatorPubKeys: [][]byte{{0x01}},
	})
	if !v.IsExternalChainSyncCommitteeReady() {
		t.Fatal("populated committee not reported as ready")
	}

	// A checker that cannot report readiness is assumed ready (it may use an
	// aggregate key rather than a member list).
	v.SetExternalChainSyncCommittee(headerOnlyChecker{})
	if !v.IsExternalChainSyncCommitteeReady() {
		t.Fatal("checker without readiness interface reported as not ready")
	}
}

// R4-02: mainnet must not run the bridge with hash-only external-chain header
// verification unless a committee is actually loaded or the operator opts in.
func TestBridgeHeaderVerificationPolicyMainnetFailClosed(t *testing.T) {
	if err := checkBridgeHeaderVerificationPolicy(MainnetNetworkID, true, ""); err != nil {
		t.Fatalf("loaded committee must be accepted: %v", err)
	}
	if err := checkBridgeHeaderVerificationPolicy(MainnetNetworkID, false, ""); err == nil {
		t.Fatal("mainnet accepted an inactive sync committee without an explicit opt-in")
	}
	if err := checkBridgeHeaderVerificationPolicy(MainnetNetworkID, false, "1"); err != nil {
		t.Fatalf("explicit degraded opt-in should be accepted: %v", err)
	}
	// Non-mainnet networks keep the permissive behavior so test bridges start.
	for _, id := range []uint64{TestnetNetworkID, DevnetNetworkID} {
		if err := checkBridgeHeaderVerificationPolicy(id, false, ""); err != nil {
			t.Fatalf("network %d rejected degraded header verification: %v", id, err)
		}
	}
}

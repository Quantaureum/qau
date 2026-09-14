// Quantaureum Node source, version 1.0.0.
package bridge

import (
	"crypto/rand"
	"testing"

	circl "github.com/cloudflare/circl/sign/dilithium/mode3"
)

// R32-P2-12: Tests use a valid 0x-prefixed 32-byte hex hash as proposalID.
// validateGovernanceProposalID (bridge.go) enforces this format.
const testProposalID = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

// TestBRIDGE_P0_01_SetRelayerKeys_RejectsNonGovernanceCaller verifies the
// BRIDGE-P0-01 fix: SetRelayerKeys must reject callers that do not match
// the configured governance address. Previously, SetRelayerKeys only
// checked governanceAddress != "" and proposalID != "", allowing any
// caller (RPC, internal module) to replace relayer keys with
// attacker-controlled keys — enabling forgery of cross-chain messages
// and theft of locked assets.
//
// Setup:
//   - governanceAddress = "0xGovEth" (set via SetGovernanceAddress with initializer)
//   - attacker caller = "0xAttacker"
//
// Expected:
//   - SetRelayerKeys with caller="0xAttacker" returns authorization error
//   - SetRelayerKeys with caller="0xGovEth" (correct) succeeds
func TestBRIDGE_P0_01_SetRelayerKeys_RejectsNonGovernanceCaller(t *testing.T) {
	ethAdapter := newExternalChainAdapterForTest(t)
	govAddr := "0xGovEth"

	// Initialize: set governance address using initializer.
	// BRIDGE-P0-01: caller must be the initializer for the first set.
	if err := ethAdapter.SetGovernanceAddress(govAddr, "0xInitializer"); err != nil {
		t.Fatalf("SetGovernanceAddress: %v", err)
	}

	// Generate dummy keys (we won't actually sign anything).
	pub, priv := generateDummyDilithium3Keys(t)

	// Attack: caller is NOT the governance address — must be rejected.
	err := ethAdapter.SetRelayerKeys(pub, priv, testProposalID, "0xAttacker")
	if err == nil {
		t.Fatal("BRIDGE-P0-01 NOT FIXED: SetRelayerKeys accepted non-governance caller (0xAttacker)")
	}

	// Verify error message mentions authorization.
	if !containsString(err.Error(), "unauthorized") {
		t.Errorf("SetRelayerKeys error = %q, want error containing 'unauthorized'", err.Error())
	}

	// Legitimate call: caller IS the governance address — must succeed.
	if err := ethAdapter.SetRelayerKeys(pub, priv, testProposalID, govAddr); err != nil {
		t.Errorf("SetRelayerKeys with correct caller failed: %v", err)
	}
}

// TestBRIDGE_P0_01_SetValidatorKeys_RejectsNonGovernanceCaller is the
// QuantaureumChainAdapter equivalent of the test above.
func TestBRIDGE_P0_01_SetValidatorKeys_RejectsNonGovernanceCaller(t *testing.T) {
	qauAdapter := newQuantaureumChainAdapterForTest(t)
	govAddr := "0xGovQau"

	// Initialize: set governance address using initializer.
	// BRIDGE-P0-01: caller must be the initializer for the first set.
	if err := qauAdapter.SetGovernanceAddress(govAddr, "0xInitializer"); err != nil {
		t.Fatalf("SetGovernanceAddress: %v", err)
	}

	pub, priv := generateDummyDilithium3Keys(t)

	// Attack: caller is NOT the governance address — must be rejected.
	err := qauAdapter.SetValidatorKeys(pub, priv, testProposalID, "0xAttacker")
	if err == nil {
		t.Fatal("BRIDGE-P0-01 NOT FIXED: SetValidatorKeys accepted non-governance caller (0xAttacker)")
	}

	if !containsString(err.Error(), "unauthorized") {
		t.Errorf("SetValidatorKeys error = %q, want error containing 'unauthorized'", err.Error())
	}

	// Legitimate call: caller IS the governance address — must succeed.
	if err := qauAdapter.SetValidatorKeys(pub, priv, testProposalID, govAddr); err != nil {
		t.Errorf("SetValidatorKeys with correct caller failed: %v", err)
	}
}

// TestBRIDGE_P0_01_SetRelayerKeys_RequiresGovernanceAddressConfigured
// verifies that SetRelayerKeys still fails-closed when governance address
// is not configured (existing R69-GOV-2 behavior, must be preserved).
func TestBRIDGE_P0_01_SetRelayerKeys_RequiresGovernanceAddressConfigured(t *testing.T) {
	ethAdapter := newExternalChainAdapterForTest(t)
	// Note: SetGovernanceAddress NOT called — governanceAddress is empty.

	pub, priv := generateDummyDilithium3Keys(t)

	err := ethAdapter.SetRelayerKeys(pub, priv, testProposalID, "0xGovEth")
	if err == nil {
		t.Fatal("SetRelayerKeys should fail when governance address is not configured")
	}
	if !containsString(err.Error(), "governance address not configured") {
		t.Errorf("SetRelayerKeys error = %q, want 'governance address not configured'", err.Error())
	}
}

// TestBRIDGE_P0_01_SetValidatorKeys_RequiresGovernanceAddressConfigured
// is the QuantaureumChainAdapter equivalent.
func TestBRIDGE_P0_01_SetValidatorKeys_RequiresGovernanceAddressConfigured(t *testing.T) {
	qauAdapter := newQuantaureumChainAdapterForTest(t)
	// Note: SetGovernanceAddress NOT called — governanceAddress is empty.

	pub, priv := generateDummyDilithium3Keys(t)

	err := qauAdapter.SetValidatorKeys(pub, priv, testProposalID, "0xGovQau")
	if err == nil {
		t.Fatal("SetValidatorKeys should fail when governance address is not configured")
	}
	if !containsString(err.Error(), "governance address not configured") {
		t.Errorf("SetValidatorKeys error = %q, want 'governance address not configured'", err.Error())
	}
}

// TestBRIDGE_P0_01_SetRelayerKeys_RejectsEmptyProposalID verifies that
// even with the correct caller, an empty proposal ID is rejected.
// This preserves the R69-GOV-2 fix on top of the BRIDGE-P0-01 caller auth.
func TestBRIDGE_P0_01_SetRelayerKeys_RejectsEmptyProposalID(t *testing.T) {
	ethAdapter := newExternalChainAdapterForTest(t)
	govAddr := "0xGovEth"

	// BRIDGE-P0-01: caller must be the initializer for the first set.
	if err := ethAdapter.SetGovernanceAddress(govAddr, "0xInitializer"); err != nil {
		t.Fatalf("SetGovernanceAddress: %v", err)
	}

	pub, priv := generateDummyDilithium3Keys(t)

	// Correct caller but empty proposalID — must be rejected.
	err := ethAdapter.SetRelayerKeys(pub, priv, "", govAddr)
	if err == nil {
		t.Fatal("SetRelayerKeys should fail with empty proposalID")
	}
	if !containsString(err.Error(), "governance proposal ID required") {
		t.Errorf("SetRelayerKeys error = %q, want 'governance proposal ID required'", err.Error())
	}
}

// newExternalChainAdapterForTest creates a minimal ExternalChainAdapter
// suitable for BRIDGE-P0-01 unit tests (no full bridge initialization).
func newExternalChainAdapterForTest(t *testing.T) *ExternalChainAdapter {
	t.Helper()
	return &ExternalChainAdapter{
		chainID:            "ethereum",
		initializerAddress: "0xInitializer",
	}
}

// newQuantaureumChainAdapterForTest creates a minimal QuantaureumChainAdapter.
func newQuantaureumChainAdapterForTest(t *testing.T) *QuantaureumChainAdapter {
	t.Helper()
	return &QuantaureumChainAdapter{
		chainID:            "quantaureum",
		initializerAddress: "0xInitializer",
		lastNonces:         make(map[ChainID]uint64),
	}
}

// generateDummyDilithium3Keys generates a deterministic Dilithium3 keypair
// for testing. We use circl's key generation directly.
func generateDummyDilithium3Keys(t *testing.T) (*circl.PublicKey, *circl.PrivateKey) {
	t.Helper()
	pub, priv, err := circl.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

// containsString is a simple substring helper (avoids importing strings).
// Renamed from `contains` to avoid redeclaration conflict with header_verifier_test.go.
func containsString(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

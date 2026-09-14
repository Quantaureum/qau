// Quantaureum Node source, version 1.0.0.
// R39-P0-02 (2026-08-02) regression tests.
//
// The legacy 0x66 MultisigPrecompiled.RunWithContextV2 is the QVM-internal
// CALL target (executePrecompiledAtomicV2 → Registry.RunWithContextV2 →
// this method). R38-P0-01 left walletAddr bound to attacker-supplied
// calldata, allowing an attacker to register any victim EOA as a wallet
// and drain its funds. R39-P0-02 fail-closes the four mutators
// (registerWallet / createProposal / approveProposal / executeProposal)
// on this QVM execution path, while leaving the read-only queries
// (getWalletConfig / getProposal / getProposalsForSigner / isSigner)
// functional so existing inspection tools keep working. These tests pin
// that gate.
package precompiled

import (
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// noOpCtx is a minimal non-empty PrecompileContext used only to drive the
// V1 RunWithContextV2 entry point. The mutator gate fires BEFORE ctx fields
// are inspected, so its contents do not matter for the rejection tests.
func r39P002Ctx() PrecompileContext {
	return PrecompileContext{
		Caller:    types.Address{0xAB},
		Origin:    types.Address{0xAB},
		BlockTime: 1,
		ChainID:   1668,
	}
}

// TestR39_P0_02_Legacy066_MutatorGate_FailClosedOnV2ExecPath verifies that
// every 0x66 mutator dispatched through RunWithContextV2 (the QVM executor
// production entry point) is rejected, regardless of the caller or calldata
// contents. This is the structural closure of the
// "register-an-arbitrary-victim-as-own-multisig" theft path.
func TestR39_P0_02_Legacy066_MutatorGate_FailClosedOnV2ExecPath(t *testing.T) {
	c := newMultisigPrecompiled()
	db := newFakeV2StateDB()
	ctx := r39P002Ctx()

	cases := []struct {
		name   string
		funcID byte
	}{
		{"registerWallet", MultisigFuncRegisterWallet},
		{"createProposal", MultisigFuncCreateProposal},
		{"approveProposal", MultisigFuncApproveProposal},
		{"executeProposal", MultisigFuncExecuteProposal},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Minimum plausible calldata: funcID + a few sentinel bytes.
			// The gate fires on funcID alone, so payload contents do not
			// affect the rejection.
			input := []byte{tc.funcID, 0xAA, 0xBB, 0xCC}
			_, err := c.RunWithContextV2(ctx, db, input)
			if err == nil {
				t.Fatalf("0x66 %s via RunWithContextV2 must be rejected (R39-P0-02), got nil", tc.name)
			}
			if !strings.Contains(err.Error(), "R39-P0-02") && !strings.Contains(err.Error(), "use the V2") {
				t.Fatalf("expected R39-P0-02 closure error for %s, got: %v", tc.name, err)
			}
		})
	}
}

// TestR39_P0_02_Legacy066_QueryPath_StillCallable confirms read-only
// queries are NOT blocked on the V2 exec path, so inspection tooling keeps
// working even though the mutator surface is fail-closed.
func TestR39_P0_02_Legacy066_QueryPath_StillCallable(t *testing.T) {
	c := newMultisigPrecompiled()
	db := newFakeV2StateDB()
	ctx := r39P002Ctx()

	// getWalletConfig for an unregistered wallet should return a clean
	// "not registered" error, NOT the R39-P0-02 mutator gate error.
	// This proves the gate is targeted at mutators only.
	calls := []struct {
		name   string
		funcID byte
	}{
		{"getWalletConfig", MultisigFuncGetWalletConfig},
		{"isSigner", MultisigFuncIsSigner},
	}
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte{tc.funcID}
			// Pad with zeros so length checks inside the queries don't trip
			// on "input too short"; the queries read a wallet address
			// (20 bytes) from input[1:21].
			input = append(input, make([]byte, 32)...)
			_, err := c.RunWithContextV2(ctx, db, input)
			// We accept ANY non-nil error as long as it is NOT the R39-P0-02
			// gate error — the point is that the dispatch reached the
			// query implementation (it may return "not registered" or
			// similar), proving the mutator gate did NOT fire.
			if err != nil && strings.Contains(err.Error(), "R39-P0-02") {
				t.Fatalf("0x66 query %s must NOT be gate-blocked, got: %v", tc.name, err)
			}
		})
	}
}

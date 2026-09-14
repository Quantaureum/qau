// Quantaureum Node source, version 1.0.0.
package economics

import "math/big"

// newTestDeFiIncentiveManager returns a DeFiIncentiveManager configured with
// the *permissive fail-open* posture, for unit tests that exercise pure
// accounting / lifecycle logic without caring about creator authorization or
// action verification.
//
// R38-P1-13 FIX (2026-08-01): the production constructor now defaults to
// fail-closed (empty authorizedCreators => CreateProgram rejected; nil
// actionVerifier => ClaimReward rejected). Pre-existing economics unit tests
// were written against the old fail-open default and do not assert auth / Sybil
// behavior; they would now break if they kept using the raw constructor.
//
// Tests that explicitly assert fail-closed behavior (see
// r38_p1_13_defi_failclosed_test.go) must NOT use this helper — they must call
// NewDeFiIncentiveManager directly so the fail-closed default is in effect.
func newTestDeFiIncentiveManager(initialBudget *big.Int) *DeFiIncentiveManager {
	dim := NewDeFiIncentiveManager(initialBudget)
	dim.AllowAllCreators()
	dim.AllowAllClaims()
	return dim
}

// allowAllCreatorsAndClaims is a tiny convenience to opt an existing manager
// into the permissive posture inline, when a test wants to retain calls to the
// production constructor (e.g. to assert specific budget arithmetic).
func allowAllCreatorsAndClaims(dim *DeFiIncentiveManager) {
	if dim == nil {
		return
	}
	dim.AllowAllCreators()
	dim.AllowAllClaims()
}

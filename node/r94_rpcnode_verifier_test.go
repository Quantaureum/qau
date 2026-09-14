// Quantaureum Node source, version 1.0.0.
package node

import "testing"

// R94-RPCNODE-VERIFIER regression test.
//
// A pure RPC observer node may be configured with validatorEnabled=false,
// blockProducer=false, syncOnlyMode=false, and DevMode=false. Such a node can
// import blocks normally while catching up, then fail closed after initial
// sync if its election verifier was never initialized.
//
// ROOT CAUSE: startServices had three production branches —
//  1. sealer            (validatorEnabled && blockProducer)  → create + Start
//  2. verify-only       (validatorEnabled && !blockProducer)  → create, no Start
//  3. (nothing)         validatorEnabled == false             → n.blockProducer stays nil
//
// wireElectionVerifier is gated on `n.blockProducer != nil &&
// n.blockProducer.QPOS() != nil`, so case 3 wired no verifier at all. That is
// survivable only while core.BlockValidator is in syncingMode, where a nil
// verifier degrades to "skip + WARN" (R38-P1-08 conservative path). Once
// SetSyncingMode(false) runs, ValidateBlock reaches its fail-closed
// `else if !devMode` branch and rejects EVERY subsequent block. The node can
// never leave that state: the rejection happens before ProcessBlock, so nothing
// repairs it.
//
// Net effect: a pure RPC/observer node could not complete production
// validation after initial sync.
//
// FIX: case 3 must also create the BlockProducer purely to initialize QPOS so
// the verifier gets wired. wireElectionVerifier then flags it a non-sealer and
// calls SetTrustCanonicalProposer(true) (R58-ELEC-TRUST, geth's post-merge
// execution-layer model), which is the correct semantics for a node that does
// not seal.
func TestR94_ElectionVerifierProducerNeededForNonValidatorRPCNode(t *testing.T) {
	// A representative pure observer configuration.
	const (
		devMode          = false
		validatorEnabled = false
		blockProducer    = false
		syncOnlyMode     = false
	)

	if shouldStartProducingBlocks(devMode, validatorEnabled, blockProducer, syncOnlyMode) {
		t.Fatal("a pure RPC node must NOT produce blocks")
	}
	if !shouldCreateElectionVerifierProducer(devMode, validatorEnabled, blockProducer, syncOnlyMode) {
		t.Error("shouldCreateElectionVerifierProducer = false for a pure RPC observer " +
			"(validatorEnabled=false, blockProducer=false, syncOnlyMode=false); without a " +
			"BlockProducer, wireElectionVerifier no-ops, the election verifier stays nil, and " +
			"ValidateBlock fail-closes on every block once syncingMode ends " +
			"(R94-RPCNODE-VERIFIER)")
	}
}

// TestR94_ProducerCreationTruthTable pins the full decision table so the fix
// cannot silently widen (e.g. making a sealer skip its production loop, or
// creating a producer for a genesis-less SyncOnlyMode node).
func TestR94_ProducerCreationTruthTable(t *testing.T) {
	tests := []struct {
		name                                               string
		devMode, validatorEnabled, blockProducer, syncOnly bool
		wantProduce, wantVerifierOnly                      bool
	}{
		{
			name:             "production validator block producer",
			validatorEnabled: true, blockProducer: true,
			wantProduce: true, wantVerifierOnly: false,
		},
		{
			name:             "production validator with block production disabled (verify-only)",
			validatorEnabled: true, blockProducer: false,
			wantProduce: false, wantVerifierOnly: true,
		},
		{
			name:             "pure RPC observer (non-validator)",
			validatorEnabled: false, blockProducer: false,
			wantProduce: false, wantVerifierOnly: true,
		},
		{
			// Defensive: blockProducer=true is meaningless without
			// validatorEnabled; it must not start producing, but it still
			// needs the verifier.
			name:             "config conflict: blockProducer=true but validatorEnabled=false",
			validatorEnabled: false, blockProducer: true,
			wantProduce: false, wantVerifierOnly: true,
		},
		{
			// SyncOnlyMode has no authoritative genesis until it syncs one,
			// so QPOS cannot be initialized — deliberately excluded.
			name:             "SyncOnlyMode (no canonical genesis, QPOS not built)",
			validatorEnabled: false, blockProducer: false, syncOnly: true,
			wantProduce: false, wantVerifierOnly: false,
		},
		{
			name:             "SyncOnlyMode validators still do not build QPOS",
			validatorEnabled: true, blockProducer: true, syncOnly: true,
			wantProduce: false, wantVerifierOnly: false,
		},
		{
			// DevMode uses SetDevMode(true) on the validator instead of an
			// election verifier, and has its own producer branch.
			name:    "DevMode",
			devMode: true, validatorEnabled: true, blockProducer: true,
			wantProduce: false, wantVerifierOnly: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldStartProducingBlocks(tc.devMode, tc.validatorEnabled, tc.blockProducer, tc.syncOnly)
			if got != tc.wantProduce {
				t.Errorf("shouldStartProducingBlocks = %v, want %v", got, tc.wantProduce)
			}
			got = shouldCreateElectionVerifierProducer(tc.devMode, tc.validatorEnabled, tc.blockProducer, tc.syncOnly)
			if got != tc.wantVerifierOnly {
				t.Errorf("shouldCreateElectionVerifierProducer = %v, want %v", got, tc.wantVerifierOnly)
			}
		})
	}
}

// TestR94_ProducerDecisionsAreMutuallyExclusive guarantees the two predicates
// can never both fire, which would create the BlockProducer twice and leak the
// first one (it holds goroutines and a QPOS instance).
func TestR94_ProducerDecisionsAreMutuallyExclusive(t *testing.T) {
	for i := range 16 {
		dev := i&1 != 0
		val := i&2 != 0
		bp := i&4 != 0
		so := i&8 != 0
		if shouldStartProducingBlocks(dev, val, bp, so) && shouldCreateElectionVerifierProducer(dev, val, bp, so) {
			t.Errorf("both predicates true for devMode=%v validatorEnabled=%v blockProducer=%v syncOnlyMode=%v — "+
				"BlockProducer would be constructed twice", dev, val, bp, so)
		}
	}
}

// Quantaureum Node source, version 1.0.0.
package core

// R39-P0-03 (2026-08-02) regression tests for the block_validator's
// stake/unstake signature domain fix.
//
// Audit finding (R39-P0-03): "stake/unstake signature domains inconsistent between the two sides" — R38-P0-02
// migrated RPC + txpool admission to the canonical StakeAuthorizationHash
// domain (encoding.VerifyTransactionAuthorization), but block_validator's
// reconstructStakingMessage kept the legacy "stake|chainID|addr|nonce|
// params" string domain. So every stake/unstake tx signed via RPC would
// pass txpool (canonical) but FAIL block-level verification (legacy) →
// honest-validator majority rejected the block → staking/unstaking was
// permanently broken on-chain.
//
// FIX: BlockValidator.validateTransactions (line ~1790-1822) now re-routes
// stake/unstake through encoding.VerifyTransactionAuthorization (same
// canonical arbiter as txpool admission), EXCLUDED from the BatchVerify
// items slice. Tests in this file pin this invariant: when a Block contains
// a stake tx signed over the LEGACY string domain (i.e., NOT the canonical
// ComputeStakeAuthorizationHash), BlockValidator.validateTransactions MUST
// reject it with an error carrying the "staking authorization" marker (the
// R39-P0-03 contract). Any future refactor that re-introduces the legacy
// string domain for stake/unstake verification would re-introduce the
// functional deadlock — this test catches it.
//
// Test design:
//
//   - Test 1 (happy path): a stake tx signed over the CANONICAL
//     ComputeStakeAuthorizationHash domain passes validateTransactions's
//     stake branch. This pins that the canonical R39-P0-03 path is the
//     accepted arbiter — any regression that mistakenly rejects canonical
//     stake txs would re-break the on-chain staking functionality.
//
//   - Test 2 (legacy-domain rejection): a stake tx structurally valid
//     but whose signature is computed over the LEGACY
//     "stake|chainID|addr|nonce|params" string domain MUST be rejected
//     by validateTransactions with the "staking authorization" marker.
//     The canonical arbiter checks the signature over the canonical
//     StakeAuthorizationHash; a legacy-domain signature will fail
//     verification → the audit's exploit is closed.
//
//   - Test 3 (negative control — missing SigningVerifier): when
//     v.signingVerifier == nil, validateTransactions MUST NOT reach the
//     R39-P0-03 stake branch at all (the early `if sv != nil` gate at
//     line ~1789). The block passes with no staking-authorization error.
//     This pins the contract that R39-P0-03 ONLY fires when signature
//     verification is configured — defenseless configs (no signing
//     verifier) are explicitly NOT propositions we test the stake branch
//     against, matching the existing semantics.

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// r39P0_03_makeCanonicalStakeTx constructs a stake tx signed over the
// canonical ComputeStakeAuthorizationHash domain — exactly what the V2
// RPC builder produces and what VerifyTransactionAuthorization verifies.
// Returns the tx ready to embed in a Block for validateTransactions.
//
// We build it manually (rather than call encoding's private makeStakeAuthTx
// across packages) so this test lives entirely within package core using
// only exported encoding / types / crypto APIs.
func r39P0_03_makeCanonicalStakeTx(t *testing.T, chainID uint64) *encoding.Transaction {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	priv := kp.Private
	pub, err := priv.PublicKeySafe()
	if err != nil {
		t.Fatalf("derive pub: %v", err)
	}
	from := pub.Address()
	recipient := types.Address{18: 0x10, 19: 0x01} // canonical staking contract

	value := big.NewInt(1_000_000_000_000_000_000) // 1 QAU
	commission := uint32(1000)
	nonce := "1700000000"

	// Reconstruct tx.Data the same way encoding does:
	// commission(4 BE) + nonceLen(2 BE) + nonce(nonceLen).
	nonceBytes := []byte(nonce)
	txData := make([]byte, 4+2+len(nonceBytes))
	txData[0] = byte(commission >> 24)
	txData[1] = byte(commission >> 16)
	txData[2] = byte(commission >> 8)
	txData[3] = byte(commission)
	txData[4] = byte(len(nonceBytes) >> 8)
	txData[5] = byte(len(nonceBytes))
	copy(txData[6:], nonceBytes)

	// Sign over the canonical ComputeStakeAuthorizationHash.
	authHash, err := types.ComputeStakeAuthorizationHash(
		chainID, from, recipient,
		types.StakeAuthTypeStake,
		value, commission, nonce,
	)
	if err != nil {
		t.Fatalf("compute canonical stake auth hash: %v", err)
	}
	signature, err := priv.Sign(authHash[:])
	if err != nil {
		t.Fatalf("sign canonical auth hash: %v", err)
	}

	return &encoding.Transaction{
		Type:      encoding.TxTypeStake,
		Nonce:     1,
		ChainID:   chainID,
		From:      from,
		To:        &recipient,
		Value:     new(big.Int).Set(value),
		Data:      txData,
		GasLimit:  100000,
		GasPrice:  big.NewInt(1),
		PublicKey: pub.Bytes(),
		Signature: signature,
	}
}

// r39P0_03_makeLegacyDomainStakeTx constructs a structurally valid stake
// tx whose signature is computed over the LEGACY
// "stake|chainID|addr|nonce|params" string domain — the pre-R38-P0-02
// shape. A canonical-domain verifier (encoding.VerifyTransactionAuthorization)
// will reject it because it doesn't verify over the canonical
// ComputeStakeAuthorizationHash.
//
// We deliberately sign over a legacy-shaped buffer (NOT the canonical
// hash). The exact byte layout of the legacy domain doesn't matter —
// what matters is that the signature is NOT the canonical one. We use
// the transaction's SigningHash as a stand-in for the legacy string
// domain (any non-canonical buffer would do; SigningHash is a
// deterministic, non-canonical 32-byte hash that's easy to construct
// and sign).
func r39P0_03_makeLegacyDomainStakeTx(t *testing.T, chainID uint64) *encoding.Transaction {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	priv := kp.Private
	pub, err := priv.PublicKeySafe()
	if err != nil {
		t.Fatalf("derive pub: %v", err)
	}
	from := pub.Address()
	recipient := types.Address{18: 0x10, 19: 0x01}

	value := big.NewInt(1_000_000_000_000_000_000)
	commission := uint32(1000)
	nonce := "1700000000"
	nonceBytes := []byte(nonce)
	txData := make([]byte, 4+2+len(nonceBytes))
	txData[0] = byte(commission >> 24)
	txData[1] = byte(commission >> 16)
	txData[2] = byte(commission >> 8)
	txData[3] = byte(commission)
	txData[4] = byte(len(nonceBytes) >> 8)
	txData[5] = byte(len(nonceBytes))
	copy(txData[6:], nonceBytes)

	// Construct the tx first so we can compute SigningHash (which the
	// Transfer/Contract/Create canonical verifier uses), then sign over
	// SigningHash. This signature is ALSO a valid canonical signature for
	// TxTypeStake in a totally-canonical world — but the canonical
	// stake arbiter signs over ComputeStakeAuthorizationHash, NOT
	// SigningHash. So this signature will FAIL the canonical stake
	// verification path.
	tx := &encoding.Transaction{
		Type:      encoding.TxTypeStake,
		Nonce:     1,
		ChainID:   chainID,
		From:      from,
		To:        &recipient,
		Value:     new(big.Int).Set(value),
		Data:      txData,
		GasLimit:  100000,
		GasPrice:  big.NewInt(1),
		PublicKey: pub.Bytes(),
	}
	signingHash, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("compute SigningHash (legacy stand-in): %v", err)
	}
	signature, err := priv.Sign(signingHash[:])
	if err != nil {
		t.Fatalf("sign legacy SigningHash: %v", err)
	}
	tx.Signature = signature
	return tx
}

// ── Test 1: canonical stake tx passes validateTransactions. ──

// TestR39_P0_03_CanonicalStakeTxAccepted pins the canonical R39-P0-03
// happy path: a stake tx signed over ComputeStakeAuthorizationHash
// MUST pass the stake branch of validateTransactions (no error). Any
// regression that rejects canonical stake txs would re-break the
// staking functionality on-chain — the original R38-P0-02 bug.
func TestR39_P0_03_CanonicalStakeTxAccepted(t *testing.T) {
	chainID := uint64(1668)
	v := NewBlockValidator(chainID, 30_000_000)
	v.SetSigningVerifier(crypto.NewSigningVerifier())

	tx := r39P0_03_makeCanonicalStakeTx(t, chainID)

	block := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			ChainID:      chainID,
			Height:       2,
			Timestamp:    2,
			ParentHash:   types.Hash{},
			ProposerAddr: types.Address{1},
		},
		Transactions: []*encoding.Transaction{tx},
	}

	// We expect NO staking-authorization error. The canonical stake tx
	// should pass the R39-P0-03 stake branch (line ~1816).
	err := v.validateTransactions(block)
	if err != nil {
		// A staking-authorization failure means the canonical path is
		// rejected — regression. Other errors (e.g., Block.Validate
		// structural) would be a harness bug; let's surface either way.
		if strings.Contains(err.Error(), "staking authorization") {
			t.Fatalf("R39-P0-03: canonical stake tx was rejected with staking-authorization error — %v — the canonical ComputeStakeAuthorizationHash path is broken; stake/unstake would be rejected by the honest-validator majority (the R38-P0-02 functional deadlock would return)", err)
		}
		// Other errors are most likely from the BatchVerify items
		// slice — but stake txs are EXCLUDED from that path (the
		// canonical verification is the only check). If anything else
		// fails here it's likely a pre-existing harness issue; report
		// it explicitly so it's distinguishable from a P0-03
		// regression.
		t.Fatalf("R39-P0-03: canonical stake tx was rejected with a non-staking-authorization error — %v — investigate the harness or the validateTransactions path; this is NOT the expected P0-03 contract (canonical stake txs should pass cleanly)", err)
	}
}

// ── Test 2: legacy-domain stake tx is rejected with the staking authorization marker. ──

// TestR39_P0_03_LegacyDomainStakeTxRejected pins the audit's primary
// exploit-closure contract: a stake tx signed over the LEGACY string
// domain (NOT ComputeStakeAuthorizationHash) MUST be rejected by
// validateTransactions with the "staking authorization" error marker
// (line ~1817: `return fmt.Errorf("block tx %d: staking authorization:
// %w", si.index, err)`).
//
// Without this rejection, a future refactor that re-introduced the
// legacy string domain for stake/unstake verification would silently
// accept legacy-domain signatures — and stake/unstake signed via RPC
// (canonical) would either be rejected by the legacy block path (the
// R38-P0-02 functional deadlock), or legacy-domain signed txs would
// be accepted (a re-opening of the pre-R38-P0-02 forgery vector).
func TestR39_P0_03_LegacyDomainStakeTxRejected(t *testing.T) {
	chainID := uint64(1668)
	v := NewBlockValidator(chainID, 30_000_000)
	v.SetSigningVerifier(crypto.NewSigningVerifier())

	tx := r39P0_03_makeLegacyDomainStakeTx(t, chainID)

	block := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			ChainID:      chainID,
			Height:       2,
			Timestamp:    2,
			ParentHash:   types.Hash{},
			ProposerAddr: types.Address{1},
		},
		Transactions: []*encoding.Transaction{tx},
	}

	err := v.validateTransactions(block)
	if err == nil {
		t.Fatalf("R39-P0-03: legacy-domain stake tx was ACCEPTED by validateTransactions — the audit's exploit is reopened; a stake tx signed over the legacy string domain must be rejected because the canonical arbiter (encoding.VerifyTransactionAuthorization) only accepts signatures over ComputeStakeAuthorizationHash")
	}
	// R42-REFACTOR (2026-08-xx): stake/unstake verification was unified into
	// DefaultValidator.ValidateTxBatch along with all other tx types, so the
	// rejection now surfaces as "block tx N: authorization failed: verify tx
	// authorization: invalid signature" (wrap of encoding.ErrAuthInvalidSignature)
	// rather than the pre-refactor "staking authorization" marker. The security
	// contract (canonical-arbiter rejection) is unchanged; only the marker moved.
	// Accept either the legacy marker or the unified canonical-arbiter marker.
	if !strings.Contains(err.Error(), "staking authorization") &&
		!strings.Contains(err.Error(), "verify tx authorization") {
		t.Fatalf("R39-P0-03: legacy-domain stake tx was rejected (good) but the error MUST carry the canonical-arbiter marker ('staking authorization' or 'verify tx authorization') for log aggregator grep; got: %v", err)
	}

	// The error must WRAP a canonical-verification failure — i.e., the
	// error chain from encoding.VerifyTransactionAuthorization is
	// carried as the wrap target. We assert that the error is not
	// some OTHER unrelated validation error (e.g., the structural
	// tx.Validate() path) — those would point to a harness bug rather
	// than the R39-P0-03 contract.
	if !errors.Is(err, encoding.ErrAuthInvalidSignature) &&
		!strings.Contains(err.Error(), "invalid signature") &&
		!strings.Contains(err.Error(), "VerifyTransactionAuthorization") {
		// ErrAuthInvalidSignature (or its string form) is the most
		// likely underlying error. Any err carrying "invalid signature"
		// is acceptable; otherwise flag it as a non-canonical path.
		// We're deliberately lenient here since the exact wrapping in
		// encoding.VerifyTransactionAuthorization may surface different
		// sentinel errors (ErrAuthStakeBadRecipient etc.) depending on
		// which canonical check fires first.
		t.Fatalf("R39-P0-03: legacy-domain stake tx rejection error doesn't carry an invalid-signature / VerifyTransactionAuthorization cause; got: %v — investigate whether the rejection is genuinely from the canonical stake arbiter", err)
	}
}

// ── Test 3: no signing verifier → R39-P0-03 stake branch does NOT fire. ──

// TestR39_P0_03_NoSigningVerifier_StakeBranchSkipped pins the
// defenseless-config negative control: when v.signingVerifier == nil
// (the constructor default), validateTransactions takes the early
// `if sv != nil && len(pendingSigs) > 0` gate (line ~1789) and skips
// the R39-P0-03 stake branch entirely. The block passes with no
// staking-authorization error.
//
// This pins the contract that R39-P0-03 ONLY fires when signature
// verification is configured — matching existing semantics. Defenseless
// configs are explicitly not propositions we test the stake branch
// against; we only test that the gate cleanly skips the branch (no
// nil-pointer crash, no spurious staking-authorization error).
func TestR39_P0_03_NoSigningVerifier_StakeBranchSkipped(t *testing.T) {
	chainID := uint64(1668)
	v := NewBlockValidator(chainID, 30_000_000)
	// Deliberately DO NOT call SetSigningVerifier — sv stays nil,
	// matching the constructor default.

	// Use a canonical stake tx (any structurally valid stake tx would
	// do; the canonical one is the realistic case — a defenseless
	// config in production would still receive blocks containing
	// canonical stake txs via honest proposers).
	tx := r39P0_03_makeCanonicalStakeTx(t, chainID)

	block := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			ChainID:      chainID,
			Height:       2,
			Timestamp:    2,
			ParentHash:   types.Hash{},
			ProposerAddr: types.Address{1},
		},
		Transactions: []*encoding.Transaction{tx},
	}

	err := v.validateTransactions(block)
	// We explicitly expect NO error here — sv==nil means signature
	// verification (including the R39-P0-03 stake branch) is skipped,
	// and no other path in validateTransactions fires the
	// staking-authorization marker.
	if err != nil {
		if strings.Contains(err.Error(), "staking authorization") {
			t.Fatalf("R39-P0-03: defenseless config (sv==nil) reached the staking-authorization branch — the early `if sv != nil` gate at line ~1789 is missing or wrong; got error: %v", err)
		}
		// Other errors (e.g., a structural tx.Validate failure) would
		// be a harness bug; surface so distinguishable from P0-03
		// regression.
		t.Fatalf("R39-P0-03: defenseless config (sv==nil) returned a non-staking-authorization error — investigate harness; got: %v", err)
	}
}

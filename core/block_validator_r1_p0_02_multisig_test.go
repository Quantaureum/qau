// Quantaureum Node source, version 1.0.0.
package core

// AUDIT-FULL-ROUND1-2026-08-15 P0-02 (2026-08-15) regression tests —
// BlockValidator MultiSig routing to encoding.VerifyMultiSigAuthorization.
//
// Audit context: encoding.VerifyTransactionAuthorization fail-closed on
// TxTypeMultiSig with ErrAuthMultiSigUnsupported. The canonical helper
// encoding.VerifyMultiSigAuthorization was available but BlockValidator
// never routed MultiSig txns to it — every MultiSig-containing block was
// rejected (silent fail, no exploit, but the routing gap meant MultiSig
// could NEVER be used at the block level). P0-02 closes the gap by
// injecting a MultiSigRosterProvider into BlockValidator and re-routing
// MultiSig txns out of the ordinary pendingSigs batch (which would reject
// them with ErrAuthMultiSigUnsupported) into the N-of-M path.
//
// These tests pin three contracts:
//   1. nil provider + MultiSig tx present → block rejected (fail-closed,
//      same posture as the previous ErrAuthMultiSigUnsupported outcome).
//   2. provider set with a roster where N≥threshold of M signatures
//      verify → block accepted.
//   3. provider set but N<threshold signatures verify → block rejected.
//
// Test design note: we directly call v.validateTransactions on a block
// containing a single MultiSig tx wired to a stub MultiSigRosterProvider.
// No node wiring, no RPC, no executor — surgical coverage of the routing
// switch in validateTransactions (the actual production gap P0-02 closes).

import (
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// r1P0_02_stubRoster is a test-only MultiSigRosterProvider that returns a
// caller-supplied roster for any walletAddress. A nil-roster return tuple
// lets the test exercise the fail-closed "wallet not registered" path.
type r1P0_02_stubRoster struct {
	rosters map[types.Address][][]byte
}

func (s *r1P0_02_stubRoster) GetSignerRoster(addr types.Address) ([][]byte, error) {
	if s.rosters == nil {
		return nil, nil
	}
	roster, ok := s.rosters[addr]
	if !ok {
		return nil, nil
	}
	return roster, nil
}

// r1P0_02_makeMultiSigTx builds a MultiSig tx for walletAddress `from`
// with `threshold`-of-`M` signatures from the supplied signers (the first
// `threshold` signers' bits are set in MultiSigSignerBitmap). Used only
// for regression coverage of the validateTransactions routing switch.
func r1P0_02_makeMultiSigTx(t *testing.T, chainID uint64, from types.Address,
	signers []*crypto.PrivateKey, threshold int) *encoding.Transaction {
	t.Helper()
	M := len(signers)
	if threshold < 1 || threshold > M {
		t.Fatalf("threshold %d out of range [1, %d]", threshold, M)
	}

	// Construct tx first so SigningHash is available for signing.
	// Note on tx.Signature: tx.Validate() requires len(tx.Signature) > 0
	// for every tx type (line ~419 proto.go). MultiSig tx stores the
	// actual signer signatures in MultiSigSignatures + bitmap; the single
	// tx.Signature field is a placeholder here so that validateTransactions's
	// upfront `tx.Validate()` does not reject the tx before the MultiSig
	// routing branch can run. Real production MultiSig builders must also
	// set this placeholder (a single-byte array suffices), or the
	// block-level admission gate would reject MultiSig before reaching
	// the N-of-M path.
	tx := &encoding.Transaction{
		Type:                 encoding.TxTypeMultiSig,
		Nonce:                1,
		ChainID:              chainID,
		From:                 from,
		To:                   &from,
		Value:                big.NewInt(0),
		GasLimit:             100_000,
		GasPrice:             big.NewInt(1),
		MultiSigRequiredSigs: threshold,
		MultiSigTotalSigners: M,
		MultiSigSignerBitmap: make([]byte, (M+7)/8),
		Signature:            make([]byte, 1), // placeholder for tx.Validate gate
	}
	// Set first `threshold` bits in the bitmap.
	for i := 0; i < threshold; i++ {
		tx.MultiSigSignerBitmap[i/8] |= 1 << (uint(i) % 8)
	}

	signingHash, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}
	// Sign with the first `threshold` signers; signatures appear in bitmap
	// order (low bit first) — matches VerifyMultiSigAuthorization contract.
	tx.MultiSigSignatures = make([][]byte, 0, threshold)
	for i := 0; i < threshold; i++ {
		sig, err := signers[i].Sign(signingHash[:])
		if err != nil {
			t.Fatalf("sign[%d]: %v", i, err)
		}
		tx.MultiSigSignatures = append(tx.MultiSigSignatures, sig)
	}
	return tx
}

// r1P0_02_newBlock builds a minimal valid-for-validateTransactions block
// envelope around the given txns. We only need the fields
// validateTransactions inspects (Header.ChainID, Transactions).
func r1P0_02_newBlock(chainID uint64, txs ...*encoding.Transaction) *encoding.Block {
	return &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			ChainID:      chainID,
			Height:       2,
			Timestamp:    2,
			ParentHash:   types.Hash{},
			ProposerAddr: types.Address{1},
		},
		Transactions: txs,
	}
}

// ── Test 1: nil provider + MultiSig tx → fail-closed rejection. ──

// TestR1_P0_02_NilProvider_RejectsMultiSigBlock catches the most
// dangerous regression: a future refactor that makes the provider-
// optional path silently SKIP MultiSig verification (e.g., set a
// default "empty provider" so validateTransactions never errors on
// MultiSig). The audit's contract is fail-closed identical to
// ErrAuthMultiSigUnsupported; this test guarantees that.
func TestR1_P0_02_NilProvider_RejectsMultiSigBlock(t *testing.T) {
	chainID := uint64(1668)
	v := NewBlockValidator(chainID, 30_000_000)
	v.SetSigningVerifier(crypto.NewSigningVerifier())
	// Note: we deliberately DO NOT call SetMultiSigRosterProvider.
	// v.multisigRosterProvider remains nil — the fail-closed default.

	// Just need a structurally-valid MultiSig tx; no need to verify sigs
	// since the routing never reaches the VerifyMultiSigAuthorization
	// call (the nil-provider gate fails first).
	kp, _ := crypto.GenerateKeyPair()
	priv := kp.Private
	from, _ := priv.PublicKeySafe()
	walletAddr := from.Address()
	tx := r1P0_02_makeMultiSigTx(t, chainID, walletAddr, []*crypto.PrivateKey{priv}, 1)

	block := r1P0_02_newBlock(chainID, tx)
	err := v.validateTransactions(block)
	if err == nil {
		t.Fatal("R1-P0-02: nil provider + MultiSig tx was accepted — expected fail-closed rejection (regression: validateTransactions incorrectly silent-skip MultiSig verification when no roster provider is wired)")
	}
	if !strings.Contains(err.Error(), "P0-02 fail-closed") {
		t.Fatalf("R1-P0-02: nil-provider rejection error did NOT contain the P0-02 marker; got %v — the error message contract was broken (audit regression tests rely on the marker to distinguish routing failures from other validation errors)", err)
	}
}

// ── Test 2: provider set + N≥threshold valid sigs → block accepted. ──

// TestR1_P0_02_RosterProvider_ThresholdMet_AcceptsMultiSigBlock pins the
// happy path: BlockValidator routes a MultiSig tx with N-of-M valid
// Dilithium3 signatures to encoding.VerifyMultiSigAuthorization and
// accepts the block. A future regression that drops the routing (e.g.,
// falls back to ValidateTxBatch which returns ErrAuthMultiSigUnsupported)
// would turn this test red.
func TestR1_P0_02_RosterProvider_ThresholdMet_AcceptsMultiSigBlock(t *testing.T) {
	chainID := uint64(1668)
	v := NewBlockValidator(chainID, 30_000_000)
	v.SetSigningVerifier(crypto.NewSigningVerifier())

	// 5 signers, threshold 3 — first 3 sign.
	M := 5
	threshold := 3
	signers := make([]*crypto.PrivateKey, M)
	rosterM := make([][]byte, M)
	walletAddr := types.Address{0x70, 0xa0, 0x10, 0x20} // wallet address ≠ any signer
	for i := 0; i < M; i++ {
		kp, _ := crypto.GenerateKeyPair()
		signers[i] = kp.Private
		pub, _ := signers[i].PublicKeySafe()
		rosterM[i] = pub.Bytes()
	}
	stub := &r1P0_02_stubRoster{
		rosters: map[types.Address][][]byte{walletAddr: rosterM},
	}
	v.SetMultiSigRosterProvider(stub)

	tx := r1P0_02_makeMultiSigTx(t, chainID, walletAddr, signers, threshold)
	block := r1P0_02_newBlock(chainID, tx)
	if err := v.validateTransactions(block); err != nil {
		t.Fatalf("R1-P0-02 (happy path): 3-of-5 valid MultiSig tx was REJECTED — %v — the routing to encoding.VerifyMultiSigAuthorization is broken; the block validator is either failing to call VerifyMultiSigAuthorization with the roster from the provider, or VerifyMultiSigAuthorization itself regressed. The block MUST pass when the roster is provided and N≥threshold signatures verify.", err)
	}
}

// ── Test 3: provider set + N<threshold sigs → block rejected. ──

// TestR1_P0_02_RosterProvider_BelowThreshold_RejectsMultiSigBlock
// closes the counter-exploit contract: when the provider is set but the
// number of valid signatures is strictly below the threshold, the block
// MUST be rejected. This catches a regression that mistakenly accepted
// fewer-than-threshold signatures (e.g. off-by-one in the
// VerifyMultiSigAuthorization validCount < required comparison).
func TestR1_P0_02_RosterProvider_BelowThreshold_RejectsMultiSigBlock(t *testing.T) {
	chainID := uint64(1668)
	v := NewBlockValidator(chainID, 30_000_000)
	v.SetSigningVerifier(crypto.NewSigningVerifier())

	// 5 signers in the roster but we only sign with the first 2.
	// Threshold claimed = 3 — but only 2 signatures verify. Block MUST
	// be rejected because validCount(2) < MultiSigRequiredSigs(3).
	M := 5
	threshold := 3
	signers := make([]*crypto.PrivateKey, M)
	rosterM := make([][]byte, M)
	walletAddr := types.Address{0x70, 0xa0, 0x10, 0x20}
	for i := 0; i < M; i++ {
		kp, _ := crypto.GenerateKeyPair()
		signers[i] = kp.Private
		pub, _ := signers[i].PublicKeySafe()
		rosterM[i] = pub.Bytes()
	}
	stub := &r1P0_02_stubRoster{
		rosters: map[types.Address][][]byte{walletAddr: rosterM},
	}
	v.SetMultiSigRosterProvider(stub)

	// Construct tx claiming threshold=3, but only provide 2 signatures
	// and set only the first 2 bits in the bitmap. VerifyMultiSigAuthorization
	// MUST reject with "valid signatures < required".
	tx := &encoding.Transaction{
		Type:                 encoding.TxTypeMultiSig,
		Nonce:                1,
		ChainID:              chainID,
		From:                 walletAddr,
		To:                   &walletAddr,
		Value:                big.NewInt(0),
		GasLimit:             100_000,
		GasPrice:             big.NewInt(1),
		MultiSigRequiredSigs: threshold,          // 3
		MultiSigTotalSigners: M,                  // 5
		MultiSigSignerBitmap: []byte{0b00000011}, // bits 0 and 1 set → 2 signers
		Signature:            make([]byte, 1),    // placeholder for tx.Validate gate (see helper comment)
	}
	signingHash, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}
	for i := 0; i < 2; i++ {
		sig, err := signers[i].Sign(signingHash[:])
		if err != nil {
			t.Fatalf("sign[%d]: %v", i, err)
		}
		tx.MultiSigSignatures = append(tx.MultiSigSignatures, sig)
	}

	block := r1P0_02_newBlock(chainID, tx)
	err = v.validateTransactions(block)
	if err == nil {
		t.Fatal("R1-P0-02: below-threshold MultiSig tx was ACCEPTED — expected rejection (regression: VerifyMultiSigAuthorization's validCount < required gate was incorrectly satisfied, off-by-one or threshold field mismatch)")
	}
	if !strings.Contains(err.Error(), "MultiSig authorization failed") {
		t.Fatalf("R1-P0-02: below-threshold rejection error did NOT carry the 'MultiSig authorization failed' marker; got %v — the rotation-routed error message contract was broken (downstream bug reports rely on this marker)", err)
	}
}

// ── Test 4: provider set but wallet is unregistered (nil roster) → block rejected. ──

// TestR1_P0_02_UnregisteredWallet_RejectsMultiSigBlock pins the
// fail-closed contract when the roster provider is set but returns a nil
// roster (GetSignerRoster returns nil for an unregistered wallet). The
// block validator MUST reject — if a regression silently accepted nil
// rosters, an unregistered MultiSig tx would bypass verification.
func TestR1_P0_02_UnregisteredWallet_RejectsMultiSigBlock(t *testing.T) {
	chainID := uint64(1668)
	v := NewBlockValidator(chainID, 30_000_000)
	v.SetSigningVerifier(crypto.NewSigningVerifier())

	// Provider installed, but it returns nil for the walletAddress.
	stub := &r1P0_02_stubRoster{
		rosters: map[types.Address][][]byte{}, // empty
	}
	v.SetMultiSigRosterProvider(stub)

	// Single signer whose pubkey will NOT match any roster entry.
	kp, _ := crypto.GenerateKeyPair()
	priv := kp.Private
	walletAddr := types.Address{0x70, 0xa0, 0x10, 0x20}
	tx := r1P0_02_makeMultiSigTx(t, chainID, walletAddr, []*crypto.PrivateKey{priv}, 1)

	block := r1P0_02_newBlock(chainID, tx)
	err := v.validateTransactions(block)
	if err == nil {
		t.Fatal("R1-P0-02: MultiSig tx for an unregistered wallet was ACCEPTED — expected fail-closed rejection (regression: nil roster returned by provider was NOT treated as unregistered → destructive bypass)")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("R1-P0-02: nil-roster rejection error did NOT carry the 'not registered' marker; got %v — the error contract for unregistered MultiSig wallets was broken", err)
	}
}

// ── Negative control: a regular Transfer tx still works after the
// routing addition. Guards against a regression where the MultiSig
// routing branch accidentally short-circuited ALL txns. ──

func TestR1_P0_02_RegularTransferTxStillAccepted(t *testing.T) {
	chainID := uint64(1668)
	v := NewBlockValidator(chainID, 30_000_000)
	v.SetSigningVerifier(crypto.NewSigningVerifier())

	// Keep a positive roster provider wired (ensures the routing switch
	// doesn't gain unwanted branches that affect non-MultiSig types).
	stub := &r1P0_02_stubRoster{}
	v.SetMultiSigRosterProvider(stub)

	kp, _ := crypto.GenerateKeyPair()
	priv := kp.Private
	pub, _ := priv.PublicKeySafe()
	from := pub.Address()
	to := types.Address{2}
	tx := &encoding.Transaction{
		Type:      encoding.TxTypeTransfer,
		Nonce:     1,
		ChainID:   chainID,
		From:      from,
		To:        &to,
		Value:     big.NewInt(1),
		GasLimit:  100_000,
		GasPrice:  big.NewInt(1),
		PublicKey: pub.Bytes(),
	}
	h, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}
	sig, err := priv.Sign(h[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tx.Signature = sig

	block := r1P0_02_newBlock(chainID, tx)
	if err := v.validateTransactions(block); err != nil {
		t.Fatalf("R1-P0-02: a regular signed Transfer tx was rejected after the MultiSig routing addition — %v — the routing logic MUST NOT change behavior for non-MultiSig tx types (regression)", err)
	}
}

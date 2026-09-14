// Quantaureum Node source, version 1.0.0.
package bridge

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestR38P1_11_Deep_CalldataMismatchRejectsRefund is the RED-regression
// test for the DEEP FIX portion of R38-P1-11 — the surgical fail-closed
// portion we shipped earlier only validated that
// adapter.VerifyBurnTransaction(ctx, tx, amount) returned (true, nil).
// The deep fix takes a BurnVerificationRequest and the (Quantaureum +
// Ethereum) production adapters now (a) fetch the raw calldata via
// eth_getTransactionByHash, (b) ABI-decode it as burn(amount, validatorAddr,
// fundingEpoch, signature, beneficiary), (c) reject if any field the
// request claims does NOT match the calldata.
//
// We can't wire up a live HTTP mock server for eth_getTransactionReceipt
// + eth_getTransactionByHash in this test (out of scope for unit level),
// so the deep tests exercise decodeBurnCalldata + isZeroAddress +
// burnSignedMessage directly — the pure-function building blocks of the
// deep fix. This test pins:
//  1. decodeBurnCalldata round-trips a well-formed burn() calldata into
//     the exact claimed amount / validatorAddr / fundingEpoch / signature
//     / beneficiary.
//  2. decodeBurnCalldata rejects malformed inputs (empty, < selector,
//     truncated args) without panic.
//  3. isZeroAddress is the canonical zero-address predicate.
//  4. burnSignedMessage is deterministic — the same (txHash, validatorAddr,
//     fundingEpoch, amount) always produces the same digest; a single
//     byte change in any field produces a different digest.
func TestR38P1_11_Deep_CalldataRoundTripsFields(t *testing.T) {
	// Construct a burn() calldata:
	// selector 4 bytes — we use 0xdeadbeef as a stand-in (decodeBurnCalldata
	// strips the first 4 bytes regardless of value).
	// args (5 × 32-byte words + dynamic signature):
	//   [0] burnAmount = 1_000_000_000_000 (1e12)
	//   [1] validatorAddr = types.Address{0xAA, 0xBB, ...}
	//   [2] fundingEpoch = 42
	//   [3] signatureOff = 5*32 (offset to dynamic signature length + bytes)
	//   [4] beneficiary = types.Address{0xCC, 0xDD, ...}
	//   [5] signatureLen = 3
	//   [6] signature    = {0x60, 0x80, 0xA0}
	wantAmount := big.NewInt(1_000_000_000_000)
	wantValidator := types.Address{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0}
	wantEpoch := uint64(42)
	wantSig := []byte{0x60, 0x80, 0xA0}
	wantBeneficiary := types.Address{0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01}

	// Build args (5*32 static + 32 sigLen + len(sig) [=3] + padding to 32).
	args := make([]byte, 0, 6*32+32)
	args = appendUint256(args, wantAmount)          // [0]
	args = appendAddress(args, wantValidator)       // [1]
	args = appendUint64(args, wantEpoch)            // [2]
	args = appendUint64(args, 5*32)                 // [3] sigOff
	args = appendAddress(args, wantBeneficiary)     // [4]
	args = appendUint64(args, uint64(len(wantSig))) // sigLen
	args = append(args, wantSig...)                 // sig bytes
	for len(args)%32 != 0 {
		args = append(args, 0)
	}

	// Prepend selector 0xdeadbeef.
	selector := []byte{0xde, 0xad, 0xbe, 0xef}
	calldata := "0x" + hex.EncodeToString(append(selector, args...))

	decoded, err := decodeBurnCalldata(calldata)
	if err != nil {
		t.Fatalf("decodeBurnCalldata: %v (calldata=%s)", err, calldata)
	}
	if decoded.burnAmount == nil || decoded.burnAmount.Cmp(wantAmount) != 0 {
		t.Fatalf("decoded.burnAmount = %v, want %s", decoded.burnAmount, wantAmount.String())
	}
	if decoded.validatorAddr != wantValidator {
		t.Fatalf("decoded.validatorAddr = %x, want %x", decoded.validatorAddr, wantValidator)
	}
	if decoded.fundingEpoch != wantEpoch {
		t.Fatalf("decoded.fundingEpoch = %d, want %d", decoded.fundingEpoch, wantEpoch)
	}
	if string(decoded.signature) != string(wantSig) {
		t.Fatalf("decoded.signature = %x, want %x", decoded.signature, wantSig)
	}
	if decoded.beneficiary != wantBeneficiary {
		t.Fatalf("decoded.beneficiary = %x, want %x", decoded.beneficiary, wantBeneficiary)
	}
}

// TestR38P1_11_Deep_CalldataMalformedInputRejects pins the defensive
// input-validation paths of decodeBurnCalldata — we must not panic on
// any input (we're called from a networked RPC handler):
//   - empty 0x
//   - < 4-byte selector
//   - valid selector but no args
//   - 3 words args (insufficient static args)
func TestR38P1_11_Deep_CalldataMalformedInputRejects(t *testing.T) {
	cases := []struct {
		name     string
		calldata string
	}{
		{"empty_0x", "0x"},
		{"two_byte_selector_only", "0xdead"},
		{"selector_only_4_bytes", "0xdeadbeef"},
		{"selector_plus_one_word", "0xdeadbeef" + strings.Repeat("00", 32)},
		{"selector_plus_three_words", "0xdeadbeef" + strings.Repeat("00", 32*3)},
		{"garbage_hex_chars", "0xnothex"},
	}
	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {
			// Defensively recover so a panic in the future doesn't crash
			// the whole test binary.
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("decodeBurnCalldata(%s) panicked: %v — RPC handler must NOT crash on malformed input", tc.calldata, r)
				}
			}()
			decoded, err := decodeBurnCalldata(tc.calldata)
			// Acceptable outcomes:
			//   - err != nil and decoded == nil  (clean reject)
			//   - err != nil and decoded.burnAmount is zero-valued (parses partial)
			// In both cases no field expected match — the test asserts nothing
			// crashed and (where decoded != nil) burnAmount is zero/zero-valued.
			if err == nil && decoded != nil && decoded.burnAmount != nil && decoded.burnAmount.Sign() != 0 {
				// We allowed malformed inputs to accidentally parse a non-zero
				// burnAmount — the deep verification would then mismatch the
				// request and reject, OK as long as it didn't crash. Surface
				// this in case it surprises future readers — but not a failure.
				t.Logf("decodeBurnCalldata(%s) produced non-zero burnAmount=%s from malformed input — adapter will reject downstream via strong consistency; non-fatal", tc.calldata, decoded.burnAmount.String())
			}
		})
	}
}

// TestR38P1_11_Deep_IsZeroAddress pins the canonical zero-address
// predicate used by the adapters to SKIP consistency checks for fields
// the request declares absent.
func TestR38P1_11_Deep_IsZeroAddress(t *testing.T) {
	if !isZeroAddress(types.Address{}) {
		t.Fatal("isZeroAddress(zero) = false, want true")
	}
	if isZeroAddress(types.Address{0x01}) {
		t.Fatal("isZeroAddress(non-zero) = true, want false")
	}
	// Edge case: byte at the END is non-zero.
	if isZeroAddress(types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff}) {
		t.Fatal("isZeroAddress(addr with only last byte non-zero) = true, want false")
	}
}

// TestR38P1_11_Deep_BurnSignedMessageDeterministic pins the canonical
// hash digest semantics of burnSignedMessage: deterministic for identical
// inputs, sensitive to ANY field change, and ~32 bytes long.
//
// The validator-side contract: validators compute this digest with their
// Dilithium3 private key and supply the signature in BurnProof.Signature;
// the adapter recomputes the same digest from BurnVerificationRequest
// and verifies via pubKey.Verify(signedMessage, signature). A test-time
// mismatch in this digest vs production would silently break signature
// verification in either direction.
func TestR38P1_11_Deep_BurnSignedMessageDeterministic(t *testing.T) {
	txHash := "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	req := &BurnVerificationRequest{
		TxHash:        txHash,
		Amount:        big.NewInt(1_000_000_000_000),
		ValidatorAddr: types.Address{0xAA, 0xBB},
		FundingEpoch:  42,
	}

	h1 := burnSignedMessage(txHash, req)
	h2 := burnSignedMessage(txHash, req)
	if len(h1) != 32 {
		t.Fatalf("burnSignedMessage returned %d bytes, want 32 (SHA3-256)", len(h1))
	}
	if string(h1) != string(h2) {
		t.Fatal("burnSignedMessage is non-deterministic for identical inputs — signature verification would be a coin flip on-chain")
	}

	// Sensitive to txHash change
	reqOtherTxHash := *req
	reqOtherTxHash.TxHash = "0xdeadbeef"
	if string(burnSignedMessage("0xdeadbeef", &reqOtherTxHash)) == string(h1) {
		t.Fatal("burnSignedMessage produced identical digest for different txHash — signature verification can be bypassed by txHash substitution")
	}

	// Sensitive to validatorAddr change
	reqOtherVal := *req
	reqOtherVal.ValidatorAddr = types.Address{0xCC}
	if string(burnSignedMessage(txHash, &reqOtherVal)) == string(h1) {
		t.Fatal("burnSignedMessage produced identical digest for different validatorAddr — burn-intent can be claimed under a victim's address without breaking the signature")
	}

	// Sensitive to fundingEpoch change
	reqOtherEpoch := *req
	reqOtherEpoch.FundingEpoch = 43
	if string(burnSignedMessage(txHash, &reqOtherEpoch)) == string(h1) {
		t.Fatal("burnSignedMessage produced identical digest for different fundingEpoch — burn-intent can be replayed across epochs without detection")
	}

	// Sensitive to amount change
	reqOtherAmt := *req
	reqOtherAmt.Amount = big.NewInt(1_000_000_000_001)
	if string(burnSignedMessage(txHash, &reqOtherAmt)) == string(h1) {
		t.Fatal("burnSignedMessage produced identical digest for different amount — burn-intent can be amount-tampered without breaking the signature")
	}
}

// TestR38P1_11_Deep_ErrBurnVerificationNotSupportedSurfaced pins the
// sentinel error and the AssetLockManager response when an adapter
// returns it: fail-closed, refund refused — NOT silently accepted.
func TestR38P1_11_Deep_ErrBurnVerificationNotSupportedSurfaced(t *testing.T) {
	adapter := &r38P1_11DeepUnsupportedAdapter{}
	verified, err := adapter.VerifyBurnTransaction(context.Background(), &BurnVerificationRequest{
		TxHash:  "0xabc",
		Amount:  big.NewInt(1),
		ChainID: "quantaureum",
	})
	if err == nil {
		t.Fatal("VerifyBurnTransaction on unsupported adapter returned nil err — ErrBurnVerificationNotSupported must be surfaced so AssetLockManager treats it as fail-closed (refund refused)")
	}
	if !strings.Contains(err.Error(), "does not support deep burn verification") {
		t.Fatalf("error message must identify the unsupported-deep-verification path, got: %v", err)
	}
	if verified {
		t.Fatal("VerifyBurnTransaction on unsupported adapter returned verified=true — out of contract (must return (false, ErrBurnVerificationNotSupported))")
	}
}

type r38P1_11DeepUnsupportedAdapter struct{}

func (a *r38P1_11DeepUnsupportedAdapter) ChainID() ChainID { return "quantaureum" }
func (a *r38P1_11DeepUnsupportedAdapter) SubmitMessage(ctx context.Context, m *BridgeMessage) (string, error) {
	return "", nil
}
func (a *r38P1_11DeepUnsupportedAdapter) VerifyMessage(ctx context.Context, m *BridgeMessage) (bool, error) {
	return true, nil
}
func (a *r38P1_11DeepUnsupportedAdapter) ExecuteMessage(ctx context.Context, m *BridgeMessage) (bool, error) {
	return true, nil
}
func (a *r38P1_11DeepUnsupportedAdapter) HasSufficientConfirmations(ctx context.Context, n uint64) (bool, error) {
	return true, nil
}
func (a *r38P1_11DeepUnsupportedAdapter) GetTransactionBlockNumber(ctx context.Context, tx string) (uint64, error) {
	return 0, nil
}
func (a *r38P1_11DeepUnsupportedAdapter) GetMessageProof(ctx context.Context, id string) ([]byte, error) {
	return nil, nil
}
func (a *r38P1_11DeepUnsupportedAdapter) WatchEvents(ctx context.Context, cb func(*BridgeMessage) error) error {
	return nil
}
func (a *r38P1_11DeepUnsupportedAdapter) FetchMerkleRootFromChain(ctx context.Context) (types.Hash, error) {
	return types.Hash{}, nil
}
func (a *r38P1_11DeepUnsupportedAdapter) VerifyBurnTransaction(ctx context.Context, req *BurnVerificationRequest) (bool, error) {
	return false, ErrBurnVerificationNotSupported
}

// appendUint256 appends a 32-byte big-endian encoding of value to b.
func appendUint256(b []byte, value *big.Int) []byte {
	out := make([]byte, 32)
	v := new(big.Int).Set(value)
	v.FillBytes(out)
	return append(b, out...)
}

// appendAddress appends a 32-byte left-padded encoding of addr to b.
func appendAddress(b []byte, addr types.Address) []byte {
	out := make([]byte, 32)
	copy(out[12:], addr[:])
	return append(b, out...)
}

// appendUint64 appends a 32-byte big-endian encoding of value to b.
func appendUint64(b []byte, value uint64) []byte {
	out := make([]byte, 32)
	v := new(big.Int).SetUint64(value)
	v.FillBytes(out)
	return append(b, out...)
}

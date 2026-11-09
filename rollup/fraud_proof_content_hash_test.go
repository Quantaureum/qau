// Quantaureum Node source, version 1.0.0.
package rollup

// run-4 node/rollup-fraudproof-pointer-identity regression tests.
//
// verifyStateTransitionFraud used to locate the offending transaction with
// `btx == proof.InvalidTx`. A proof decoded at the RPC boundary
// (rpc.parseInvalidTx) is a freshly allocated object with a zero Hash, so it
// can never be pointer-identical to a stored batch entry: every honest
// challenge was rejected and the fraud-proof path was unusable. Identity is
// now the transaction CONTENT hash (rollup.ComputeTxContentHash) and the
// batch's own object is re-simulated.
//
// These tests pin both halves of the contract:
//   - an RPC-shaped proof (copy, zero Hash, no envelope fields) is ACCEPTED;
//   - tampering with ANY hashed field is still REJECTED, including when the
//     challenger also forges the Hash field.

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// newFraudProofFixture builds a batch 0 whose recorded PostStateRoot is
// tampered (i.e. genuinely fraudulent), and returns the prover plus the roots
// a valid proof must carry.
func newFraudProofFixture(t *testing.T) (*FraudProver, types.Hash, types.Hash, *RollupTransaction) {
	t.Helper()
	cfg := DefaultRollupConfig()
	from := types.Address{0x11}
	to := types.Address{0x22}

	sm := NewStateManager(cfg)
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance = new(big.Int).SetInt64(1_000_000)
	pre0 := sm.computeStateRoot()

	bm := NewBatchManager(cfg, pre0)
	fp := NewFraudProver(cfg, sm)
	fp.SetBatchLookup(bm)
	fp.SetRequireSignatureVerifier(false)
	bm.SetFraudProver(fp)

	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(500),
		Data:     []byte{0x01, 0x02},
		From:     from,
		To:       &to,
		ChainID:  1669,
	}
	if err := bm.AddTransaction(tx); err != nil {
		t.Fatalf("AddTransaction: %v", err)
	}
	batch, err := bm.BuildBatch()
	if err != nil {
		t.Fatalf("BuildBatch: %v", err)
	}
	if _, _, err := sm.ProcessBatch(batch.Index, pre0, []*RollupTransaction{tx}); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	tampered := batch.PostStateRoot
	if tampered == (types.Hash{}) {
		tampered = types.Hash{0xFF}
	} else {
		tampered[0] ^= 0xFF
	}
	if err := bm.SubmitBatch(batch.Index, tampered, types.Hash{}); err != nil {
		t.Fatalf("SubmitBatch: %v", err)
	}
	return fp, pre0, tampered, tx
}

// rpcShapedTxCopy reproduces what rpc.parseInvalidTx produces: a fresh object
// with the hashed fields populated, Hash left zero and the signature envelope
// (PublicKey/Signature) omitted.
func rpcShapedTxCopy(tx *RollupTransaction) *RollupTransaction {
	var toCopy *types.Address
	if tx.To != nil {
		a := *tx.To
		toCopy = &a
	}
	var valueCopy *big.Int
	if tx.Value != nil {
		valueCopy = new(big.Int).Set(tx.Value)
	}
	return &RollupTransaction{
		Nonce:    tx.Nonce,
		GasPrice: tx.GasPrice,
		GasLimit: tx.GasLimit,
		To:       toCopy,
		Value:    valueCopy,
		Data:     append([]byte(nil), tx.Data...),
		From:     tx.From,
		ChainID:  tx.ChainID,
	}
}

func newFraudProof(proofTx *RollupTransaction, pre, post types.Hash) *FraudProof {
	return &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    0,
		Challenger:    types.Address{0x99},
		PreStateRoot:  pre,
		PostStateRoot: post,
		InvalidTx:     proofTx,
		ChallengerSig: []byte{0x01},
		Timestamp:     time.Now().Unix(),
	}
}

// TestFraudProof_AcceptsRPCDecodedTxByContentHash proves the fix: a proof that
// arrives as a distinct, Hash-less object is now accepted because the
// offending transaction is located by content.
func TestFraudProof_AcceptsRPCDecodedTxByContentHash(t *testing.T) {
	fp, pre, tampered, tx := newFraudProofFixture(t)
	rpcTx := rpcShapedTxCopy(tx)
	if rpcTx == tx {
		t.Fatal("fixture invariant: RPC copy must not be pointer-identical")
	}
	if rpcTx.Hash != (types.Hash{}) {
		t.Fatal("fixture invariant: RPC copy must carry no Hash (parseInvalidTx does not set it)")
	}
	if ComputeTxContentHash(rpcTx) != ComputeTxContentHash(tx) {
		t.Fatal("fixture invariant: RPC copy must hash to the same content hash")
	}
	if err := fp.SubmitFraudProof(newFraudProof(rpcTx, pre, tampered)); err != nil {
		t.Fatalf("RPC-shaped fraud proof rejected: %v", err)
	}
	if !fp.HasFraudProof(0) {
		t.Fatal("accepted fraud proof was not registered for batch 0")
	}
}

// TestFraudProof_RejectsTamperedHashedFields proves that content-hash identity
// did not loosen validation: mutating any field covered by encodeTxForHash
// makes the proof invalid.
func TestFraudProof_RejectsTamperedHashedFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*RollupTransaction)
	}{
		{"nonce", func(tx *RollupTransaction) { tx.Nonce++ }},
		{"gasPrice", func(tx *RollupTransaction) { tx.GasPrice++ }},
		{"gasLimit", func(tx *RollupTransaction) { tx.GasLimit++ }},
		{"value", func(tx *RollupTransaction) { tx.Value.Add(tx.Value, big.NewInt(1)) }},
		{"data", func(tx *RollupTransaction) { tx.Data = append(tx.Data, 0xFF) }},
		{"to", func(tx *RollupTransaction) {
			other := types.Address{0x33}
			tx.To = &other
		}},
		{"to-nil", func(tx *RollupTransaction) { tx.To = nil }},
		{"from", func(tx *RollupTransaction) { tx.From = types.Address{0x44} }},
		{"chainID", func(tx *RollupTransaction) { tx.ChainID++ }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fp, pre, tampered, tx := newFraudProofFixture(t)
			rpcTx := rpcShapedTxCopy(tx)
			tc.mutate(rpcTx)
			err := fp.SubmitFraudProof(newFraudProof(rpcTx, pre, tampered))
			if err != ErrFraudProofInvalid {
				t.Fatalf("tampered field %q: expected ErrFraudProofInvalid, got %v", tc.name, err)
			}
			if fp.HasFraudProof(0) {
				t.Fatalf("tampered field %q: invalid proof was registered", tc.name)
			}
		})
	}
}

// TestFraudProof_ChallengerHashCannotBypassContentCheck proves the submitted
// Hash field is ignored: even with a forged Hash equal to the real transaction's
// hash, altered fields still fail.
func TestFraudProof_ChallengerHashCannotBypassContentCheck(t *testing.T) {
	fp, pre, tampered, tx := newFraudProofFixture(t)
	rpcTx := rpcShapedTxCopy(tx)
	rpcTx.Hash = tx.Hash
	if tx.Hash == (types.Hash{}) {
		t.Fatal("fixture invariant: AddTransaction must set tx.Hash")
	}
	rpcTx.Value = big.NewInt(999999)
	rpcTx.GasLimit = 30000
	if err := fp.SubmitFraudProof(newFraudProof(rpcTx, pre, tampered)); err != ErrFraudProofInvalid {
		t.Fatalf("forged Hash field bypassed the content check: got %v", err)
	}
	if fp.HasFraudProof(0) {
		t.Fatal("proof with forged Hash was registered")
	}
}

// TestFraudProof_RejectsTxNotInBatch keeps the "not found ⇒ reject" contract.
func TestFraudProof_RejectsTxNotInBatch(t *testing.T) {
	fp, pre, tampered, _ := newFraudProofFixture(t)
	to := types.Address{0x55}
	absent := &RollupTransaction{
		Nonce:    7,
		GasPrice: 2,
		GasLimit: 21000,
		Value:    big.NewInt(4),
		From:     types.Address{0x66},
		To:       &to,
		ChainID:  1669,
	}
	if err := fp.SubmitFraudProof(newFraudProof(absent, pre, tampered)); err != ErrFraudProofInvalid {
		t.Fatalf("proof for a tx absent from the batch: expected ErrFraudProofInvalid, got %v", err)
	}
	if fp.HasFraudProof(0) {
		t.Fatal("proof for an absent tx was registered")
	}
}

// TestFraudProof_GetProofCopyPreservesContentHash guards the deep copy: a
// proof retrieved via GetFraudProof must still hash to the same transaction
// (ChainID is part of the hash and used to be dropped by the copy).
func TestFraudProof_GetProofCopyPreservesContentHash(t *testing.T) {
	fp, pre, tampered, tx := newFraudProofFixture(t)
	if err := fp.SubmitFraudProof(newFraudProof(rpcShapedTxCopy(tx), pre, tampered)); err != nil {
		t.Fatalf("SubmitFraudProof: %v", err)
	}
	stored, ok := fp.GetFraudProof(0)
	if !ok || stored == nil || stored.InvalidTx == nil {
		t.Fatal("GetFraudProof returned no proof")
	}
	if ComputeTxContentHash(stored.InvalidTx) != ComputeTxContentHash(tx) {
		t.Fatal("GetFraudProof copy no longer matches the batch transaction's content hash")
	}
}

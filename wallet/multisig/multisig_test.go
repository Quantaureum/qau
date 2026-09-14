// Quantaureum Node source, version 1.0.0.
package multisig

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/quantum"
	"github.com/quantaureum/qau/types"
)

func generateTestKeys(t *testing.T, count int) ([][]byte, []*crypto.PrivateKey) {
	t.Helper()
	pubkeys := make([][]byte, count)
	privkeys := make([]*crypto.PrivateKey, count)

	for i := 0; i < count; i++ {
		keyPair, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("failed to generate key pair %d: %v", i, err)
		}
		pubkeys[i] = keyPair.Public.Bytes()
		privkeys[i] = keyPair.Private
	}

	return pubkeys, privkeys
}

func TestNewMultiSigWallet(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)

	config := &MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	}

	wallet, err := NewMultiSigWallet(config)
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	if wallet.Address() == (types.Address{}) {
		t.Error("wallet address should not be zero")
	}

	if wallet.Config().RequiredSignatures != 2 {
		t.Errorf("expected required signatures 2, got %d", wallet.Config().RequiredSignatures)
	}

	if wallet.Nonce() != 0 {
		t.Errorf("expected initial nonce 0, got %d", wallet.Nonce())
	}
}

func TestNewMultiSigWalletInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config *MultiSigConfig
	}{
		{
			name: "required exceeds total",
			config: &MultiSigConfig{
				RequiredSignatures: 5,
				TotalSigners:       3,
				PublicKeys:         make([][]byte, 3),
			},
		},
		{
			name: "zero required",
			config: &MultiSigConfig{
				RequiredSignatures: 0,
				TotalSigners:       3,
				PublicKeys:         make([][]byte, 3),
			},
		},
		{
			name: "mismatched pubkey count",
			config: &MultiSigConfig{
				RequiredSignatures: 2,
				TotalSigners:       3,
				PublicKeys:         make([][]byte, 2),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMultiSigWallet(tt.config)
			if err == nil {
				t.Error("expected error for invalid config")
			}
		})
	}
}

func TestGenerateMultiSigAddressDeterministic(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)

	addr1 := GenerateMultiSigAddress(pubkeys, 2)
	addr2 := GenerateMultiSigAddress(pubkeys, 2)

	if addr1 != addr2 {
		t.Error("address generation should be deterministic")
	}
}

func TestGenerateMultiSigAddressDifferentForDifferentKeys(t *testing.T) {
	pubkeys1, _ := generateTestKeys(t, 3)
	pubkeys2, _ := generateTestKeys(t, 3)

	addr1 := GenerateMultiSigAddress(pubkeys1, 2)
	addr2 := GenerateMultiSigAddress(pubkeys2, 2)

	if addr1 == addr2 {
		t.Error("different keys should produce different addresses")
	}
}

func TestCollectSignature(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)

	config := &MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	}

	wallet, err := NewMultiSigWallet(config)
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	tx, err := wallet.ProposeTransaction(0, []byte("to"), []byte("value"), nil, 21000, []byte("gasprice"), 0)
	if err != nil {
		t.Fatalf("failed to propose transaction: %v", err)
	}

	sig, err := privkeys[0].Sign(tx.TxHash)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	err = wallet.CollectSignature(tx.TxHash, sig, 0)
	if err != nil {
		t.Fatalf("failed to collect signature: %v", err)
	}

	retrieved, err := wallet.GetTransaction(tx.TxHash)
	if err != nil {
		t.Fatalf("failed to get transaction: %v", err)
	}

	if retrieved.Status != TxStatusPartiallySigned {
		t.Errorf("expected status partially_signed, got %s", retrieved.Status)
	}
}

func TestCollectSignatureDuplicate(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)

	config := &MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	}

	wallet, _ := NewMultiSigWallet(config)
	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("value"), nil, 21000, []byte("gasprice"), 0)

	sig, _ := privkeys[0].Sign(tx.TxHash)
	wallet.CollectSignature(tx.TxHash, sig, 0)

	err := wallet.CollectSignature(tx.TxHash, sig, 0)
	if err != ErrAlreadySigned {
		t.Errorf("expected ErrAlreadySigned, got %v", err)
	}
}

func TestIsReadyToExecute(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)

	config := &MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	}

	wallet, _ := NewMultiSigWallet(config)
	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("value"), nil, 21000, []byte("gasprice"), 0)

	ready, _ := wallet.IsReadyToExecute(tx.TxHash)
	if ready {
		t.Error("should not be ready with 0 signatures")
	}

	sig0, _ := privkeys[0].Sign(tx.TxHash)
	wallet.CollectSignature(tx.TxHash, sig0, 0)

	ready, _ = wallet.IsReadyToExecute(tx.TxHash)
	if ready {
		t.Error("should not be ready with 1 signature (need 2)")
	}

	sig1, _ := privkeys[1].Sign(tx.TxHash)
	wallet.CollectSignature(tx.TxHash, sig1, 1)

	ready, _ = wallet.IsReadyToExecute(tx.TxHash)
	if !ready {
		t.Error("should be ready with 2 signatures")
	}
}

func TestExecuteMultiSigTx(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)

	config := &MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	}

	wallet, _ := NewMultiSigWallet(config)
	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("value"), nil, 21000, []byte("gasprice"), 0)

	sig0, _ := privkeys[0].Sign(tx.TxHash)
	sig1, _ := privkeys[1].Sign(tx.TxHash)
	wallet.CollectSignature(tx.TxHash, sig0, 0)
	wallet.CollectSignature(tx.TxHash, sig1, 1)

	executor := NewMultiSigExecutor(wallet)
	_, aggSig, err := executor.Execute(tx.TxHash)
	if err != nil {
		t.Fatalf("failed to execute: %v", err)
	}

	if aggSig == nil {
		t.Error("aggregated signature should not be nil")
	}

	retrieved, _ := wallet.GetTransaction(tx.TxHash)
	if retrieved.Status != TxStatusExecuted {
		t.Errorf("expected status executed, got %s", retrieved.Status)
	}
}

func TestExecuteInsufficientSigs(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)

	config := &MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	}

	wallet, _ := NewMultiSigWallet(config)
	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("value"), nil, 21000, []byte("gasprice"), 0)

	sig0, _ := privkeys[0].Sign(tx.TxHash)
	wallet.CollectSignature(tx.TxHash, sig0, 0)

	executor := NewMultiSigExecutor(wallet)
	_, _, err := executor.Execute(tx.TxHash)
	if err != ErrNotReadyToExecute {
		t.Errorf("expected ErrNotReadyToExecute, got %v", err)
	}
}

func TestRevokeMultiSigTx(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)

	config := &MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	}

	wallet, _ := NewMultiSigWallet(config)
	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("value"), nil, 21000, []byte("gasprice"), 0)

	revokeMsg := generateRevokeMessage(wallet.Address(), tx.TxHash, wallet.config.ChainID)
	sig0, _ := privkeys[0].Sign(revokeMsg)
	sig1, _ := privkeys[1].Sign(revokeMsg)
	revokerSigs := [][]byte{sig0, sig1}

	err := wallet.Revoke(tx.TxHash, revokerSigs)
	if err != nil {
		t.Fatalf("failed to revoke: %v", err)
	}

	retrieved, _ := wallet.GetTransaction(tx.TxHash)
	if retrieved.Status != TxStatusRevoked {
		t.Errorf("expected status revoked, got %s", retrieved.Status)
	}
}

func TestUpdateSigners(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)

	config := &MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	}

	wallet, _ := NewMultiSigWallet(config)
	oldAddr := wallet.Address()

	newPubkeys, _ := generateTestKeys(t, 5)

	updateMsg := generateUpdateData(wallet.Address(), newPubkeys, wallet.config.ChainID)
	sig0, _ := privkeys[0].Sign(updateMsg)
	sig1, _ := privkeys[1].Sign(updateMsg)
	approverSigs := [][]byte{sig0, sig1}

	err := wallet.UpdateSigners(newPubkeys, approverSigs)
	if err != nil {
		t.Fatalf("failed to update signers: %v", err)
	}

	newAddr := wallet.Address()
	if newAddr == oldAddr {
		t.Error("address should change after signer update")
	}

	if wallet.Config().TotalSigners != 5 {
		t.Errorf("expected 5 total signers, got %d", wallet.Config().TotalSigners)
	}
}

func TestMultiSigEdgeCases(t *testing.T) {
	t.Run("1-of-1", func(t *testing.T) {
		pubkeys, privkeys := generateTestKeys(t, 1)
		config := &MultiSigConfig{
			RequiredSignatures: 1,
			TotalSigners:       1,
			PublicKeys:         pubkeys,
		}

		wallet, err := NewMultiSigWallet(config)
		if err != nil {
			t.Fatalf("failed to create 1-of-1 wallet: %v", err)
		}

		tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("value"), nil, 21000, []byte("gasprice"), 0)
		sig, _ := privkeys[0].Sign(tx.TxHash)
		wallet.CollectSignature(tx.TxHash, sig, 0)

		executor := NewMultiSigExecutor(wallet)
		_, _, err = executor.Execute(tx.TxHash)
		if err != nil {
			t.Fatalf("failed to execute 1-of-1: %v", err)
		}
	})

	t.Run("N-of-N", func(t *testing.T) {
		n := 3
		pubkeys, privkeys := generateTestKeys(t, n)
		config := &MultiSigConfig{
			RequiredSignatures: n,
			TotalSigners:       n,
			PublicKeys:         pubkeys,
		}

		wallet, _ := NewMultiSigWallet(config)
		tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("value"), nil, 21000, []byte("gasprice"), 0)

		for i := 0; i < n; i++ {
			sig, _ := privkeys[i].Sign(tx.TxHash)
			wallet.CollectSignature(tx.TxHash, sig, i)
		}

		executor := NewMultiSigExecutor(wallet)
		_, _, err := executor.Execute(tx.TxHash)
		if err != nil {
			t.Fatalf("failed to execute N-of-N: %v", err)
		}
	})

	t.Run("invalid signer index", func(t *testing.T) {
		pubkeys, _ := generateTestKeys(t, 3)
		config := &MultiSigConfig{
			RequiredSignatures: 2,
			TotalSigners:       3,
			PublicKeys:         pubkeys,
		}

		wallet, _ := NewMultiSigWallet(config)
		tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("value"), nil, 21000, []byte("gasprice"), 0)

		err := wallet.CollectSignature(tx.TxHash, []byte("sig"), 99)
		if err != ErrInvalidSignerIndex {
			t.Errorf("expected ErrInvalidSignerIndex, got %v", err)
		}
	})
}

func TestMultiSigTxStatus_String(t *testing.T) {
	tests := []struct {
		status   MultiSigTxStatus
		expected string
	}{
		{TxStatusPending, "pending"},
		{TxStatusPartiallySigned, "partially_signed"},
		{TxStatusReadyToExecute, "ready_to_execute"},
		{TxStatusExecuted, "executed"},
		{TxStatusExpired, "expired"},
		{TxStatusRevoked, "revoked"},
		{MultiSigTxStatus(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.expected {
			t.Errorf("TxStatus(%d).String() = %q, want %q", tt.status, got, tt.expected)
		}
	}
}

func TestComputeAggregatedTxHash(t *testing.T) {
	tx := &MultiSigTransaction{
		To:       []byte("to_addr"),
		Value:    []byte("1000"),
		Data:     []byte("data"),
		GasPrice: []byte("gasprice"),
	}
	hash := ComputeAggregatedTxHash(tx)
	if len(hash) == 0 {
		t.Error("expected non-empty hash")
	}
}

func TestComputeSigningHash(t *testing.T) {
	tx := &MultiSigTransaction{
		To:       []byte("to_addr"),
		Value:    []byte("1000"),
		Data:     []byte("data"),
		GasPrice: []byte("gasprice"),
		Nonce:    5,
	}
	hash := ComputeSigningHash(tx)
	if len(hash) == 0 {
		t.Error("expected non-empty hash")
	}
}

func TestNewSigningSession(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	session := NewSigningSession(wallet, []byte("txhash"))
	if session == nil {
		t.Fatal("expected non-nil session")
	}
	if session.wallet != wallet {
		t.Error("wallet mismatch")
	}
}

func TestSignWithAccount(t *testing.T) {
	_, privkeys := generateTestKeys(t, 1)
	txHash := []byte("test transaction hash for signing")

	sig, err := SignWithAccount(txHash, privkeys[0])
	if err != nil {
		t.Fatalf("SignWithAccount failed: %v", err)
	}
	if len(sig) == 0 {
		t.Error("expected non-empty signature")
	}
}

func TestSignWithAccount_NilKey(t *testing.T) {
	_, err := SignWithAccount([]byte("txhash"), nil)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestVerifySignature(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	txHash := []byte("test tx hash for verify")
	sig, _ := kp.Private.Sign(txHash)

	err = VerifySignature(txHash, sig, kp.Public.Bytes())
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
}

func TestVerifySignature_InvalidPubKeySize(t *testing.T) {
	err := VerifySignature([]byte("hash"), []byte("sig"), []byte("short"))
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestVerifySignature_InvalidPubKey(t *testing.T) {
	invalidPubKey := make([]byte, crypto.Dilithium3PublicKeySize)
	for i := range invalidPubKey {
		invalidPubKey[i] = 0xFF
	}
	err := VerifySignature([]byte("hash"), []byte("sig"), invalidPubKey)
	if err == nil {
		t.Error("expected error for invalid public key")
	}
}

func TestVerifySignature_BadSignature(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	err = VerifySignature([]byte("hash"), []byte("bad sig"), kp.Public.Bytes())
	if err == ErrSignatureVerification {
		// Expected: signature verification should fail
	} else if err == nil {
		t.Error("expected failure for bad signature")
	}
}

func TestVerifySignerBelongsToWallet(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	idx, err := VerifySignerBelongsToWallet(pubkeys[1], wallet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx != 1 {
		t.Errorf("expected index 1, got %d", idx)
	}
}

func TestVerifySignerNotInWallet(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	otherKeys, _ := generateTestKeys(t, 1)
	_, err := VerifySignerBelongsToWallet(otherKeys[0], wallet)
	if err != ErrSignerNotInWallet {
		t.Errorf("expected ErrSignerNotInWallet, got %v", err)
	}
}

func TestVerifyMultiSigSignature_Valid(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("val"), nil, 21000, []byte("gp"), 0)
	sig0, _ := privkeys[0].Sign(tx.TxHash)
	sig1, _ := privkeys[1].Sign(tx.TxHash)
	wallet.CollectSignature(tx.TxHash, sig0, 0)
	wallet.CollectSignature(tx.TxHash, sig1, 1)

	agg := NewMultiSigAggregator(wallet)
	aggSig, err := agg.AggregateSignatures(tx.TxHash)
	if err != nil {
		t.Fatalf("aggregation failed: %v", err)
	}

	err = VerifyMultiSigSignature(tx.TxHash, aggSig, pubkeys, 2)
	if err != nil {
		t.Fatalf("VerifyMultiSigSignature failed: %v", err)
	}
}

func TestVerifyMultiSigSignature_InsufficientSigs(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)

	aggSig := &quantum.AggregatedSignature{
		Signatures: [][]byte{[]byte("sig")},
	}

	err := VerifyMultiSigSignature([]byte("txhash"), aggSig, pubkeys, 3)
	if err != ErrInsufficientSigs {
		t.Errorf("expected ErrInsufficientSigs, got %v", err)
	}
}

func TestVerifyMultiSigSignature_SigCountMismatch(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)

	aggSig := &quantum.AggregatedSignature{
		Signatures: [][]byte{[]byte("sig1"), []byte("sig2")},
	}

	err := VerifyMultiSigSignature([]byte("txhash"), aggSig, pubkeys[:1], 1)
	if err == nil {
		t.Error("expected error for sig count mismatch")
	}
}

func TestNewMultiSigExecutor(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	exec := NewMultiSigExecutor(wallet)
	if exec == nil {
		t.Fatal("expected non-nil executor")
	}
}

func TestNewMultiSigAggregator(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	agg := NewMultiSigAggregator(wallet)
	if agg == nil {
		t.Fatal("expected non-nil aggregator")
	}
}

func TestNewMultiSigWallet_NilConfig(t *testing.T) {
	_, err := NewMultiSigWallet(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestNewMultiSigWallet_TotalSignersZero(t *testing.T) {
	_, err := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 1,
		TotalSigners:       0,
		PublicKeys:         make([][]byte, 0),
	})
	if err == nil {
		t.Error("expected error for zero total signers")
	}
}

func TestNewMultiSigWallet_InvalidPubKeySize(t *testing.T) {
	_, err := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 1,
		TotalSigners:       1,
		PublicKeys:         [][]byte{[]byte("too_short")},
	})
	if err == nil {
		t.Error("expected error for invalid pubkey size")
	}
}

func TestNewMultiSigWallet_DuplicateSigner(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 1)
	_, err := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 1,
		TotalSigners:       2,
		PublicKeys:         [][]byte{pubkeys[0], pubkeys[0]},
	})
	if err == nil {
		t.Error("expected error for duplicate signer")
	}
}

func TestProposeTransaction_InvalidIndex(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	_, err := wallet.ProposeTransaction(-1, []byte("to"), []byte("v"), nil, 21000, []byte("gp"), 0)
	if err != ErrInvalidSignerIndex {
		t.Errorf("expected ErrInvalidSignerIndex, got %v", err)
	}

	_, err = wallet.ProposeTransaction(3, []byte("to"), []byte("v"), nil, 21000, []byte("gp"), 0)
	if err != ErrInvalidSignerIndex {
		t.Errorf("expected ErrInvalidSignerIndex, got %v", err)
	}
}

func TestCollectSignature_TxNotFound(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	err := wallet.CollectSignature(make([]byte, 32), []byte("sig"), 0)
	if err != ErrTxNotFound {
		t.Errorf("expected ErrTxNotFound, got %v", err)
	}
}

func TestCollectSignature_NegativeIndex(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("v"), nil, 21000, []byte("gp"), 0)

	err := wallet.CollectSignature(tx.TxHash, []byte("sig"), -1)
	if err != ErrInvalidSignerIndex {
		t.Errorf("expected ErrInvalidSignerIndex, got %v", err)
	}
}

func TestGetTransaction_NotFound(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	_, err := wallet.GetTransaction(make([]byte, 32))
	if err != ErrTxNotFound {
		t.Errorf("expected ErrTxNotFound, got %v", err)
	}
}

func TestIsReadyToExecute_NotFound(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	_, err := wallet.IsReadyToExecute(make([]byte, 32))
	if err != ErrTxNotFound {
		t.Errorf("expected ErrTxNotFound, got %v", err)
	}
}

func TestIsReadyToExecute_Executed(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("v"), nil, 21000, []byte("gp"), 0)
	sig0, _ := privkeys[0].Sign(tx.TxHash)
	sig1, _ := privkeys[1].Sign(tx.TxHash)
	wallet.CollectSignature(tx.TxHash, sig0, 0)
	wallet.CollectSignature(tx.TxHash, sig1, 1)

	exec := NewMultiSigExecutor(wallet)
	exec.Execute(tx.TxHash)

	ready, _ := wallet.IsReadyToExecute(tx.TxHash)
	if ready {
		t.Error("should not be ready after execution")
	}
}

func TestCollectSignature_TxExecuted(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("v"), nil, 21000, []byte("gp"), 0)
	sig0, _ := privkeys[0].Sign(tx.TxHash)
	sig1, _ := privkeys[1].Sign(tx.TxHash)
	wallet.CollectSignature(tx.TxHash, sig0, 0)
	wallet.CollectSignature(tx.TxHash, sig1, 1)

	exec := NewMultiSigExecutor(wallet)
	exec.Execute(tx.TxHash)

	err := wallet.CollectSignature(tx.TxHash, []byte("sig"), 2)
	if err != ErrTxAlreadyExecuted {
		t.Errorf("expected ErrTxAlreadyExecuted, got %v", err)
	}
}

func TestCollectSignature_TxRevoked(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("v"), nil, 21000, []byte("gp"), 0)

	revokeMsg := generateRevokeMessage(wallet.Address(), tx.TxHash, wallet.config.ChainID)
	sig0, _ := privkeys[0].Sign(revokeMsg)
	sig1, _ := privkeys[1].Sign(revokeMsg)
	wallet.Revoke(tx.TxHash, [][]byte{sig0, sig1})

	err := wallet.CollectSignature(tx.TxHash, []byte("sig"), 2)
	if err != ErrTxRevoked {
		t.Errorf("expected ErrTxRevoked, got %v", err)
	}
}

func TestAggregateSignatures_TxNotFound(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	agg := NewMultiSigAggregator(wallet)
	_, err := agg.AggregateSignatures([]byte("unknown_hash"))
	if err != ErrTxNotFound {
		t.Errorf("expected ErrTxNotFound, got %v", err)
	}
}

func TestAggregateSignatures_Insufficient(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("v"), nil, 21000, []byte("gp"), 0)
	sig0, _ := privkeys[0].Sign(tx.TxHash)
	wallet.CollectSignature(tx.TxHash, sig0, 0)

	agg := NewMultiSigAggregator(wallet)
	_, err := agg.AggregateSignatures(tx.TxHash)
	if err != ErrInsufficientSigs {
		t.Errorf("expected ErrInsufficientSigs, got %v", err)
	}
}

func TestListPendingTransactions(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	txs := wallet.ListPendingTransactions()
	if len(txs) != 0 {
		t.Errorf("expected 0 pending txs, got %d", len(txs))
	}

	wallet.ProposeTransaction(0, []byte("to1"), []byte("v1"), nil, 21000, []byte("gp"), 0)
	wallet.ProposeTransaction(1, []byte("to2"), []byte("v2"), nil, 21000, []byte("gp"), 0)

	txs = wallet.ListPendingTransactions()
	if len(txs) != 2 {
		t.Errorf("expected 2 pending txs, got %d", len(txs))
	}
}

func TestRevoke_InsufficientSigs(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("v"), nil, 21000, []byte("gp"), 0)

	err := wallet.Revoke(tx.TxHash, [][]byte{[]byte("sig")})
	if err != ErrRevokeRequiresSigs {
		t.Errorf("expected ErrRevokeRequiresSigs, got %v", err)
	}
}

func TestRevoke_TxNotFound(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	sig0, _ := privkeys[0].Sign([]byte("dummy"))
	sig1, _ := privkeys[1].Sign([]byte("dummy"))

	err := wallet.Revoke(make([]byte, 32), [][]byte{sig0, sig1})
	if err != ErrTxNotFound {
		t.Errorf("expected ErrTxNotFound, got %v", err)
	}
}

func TestRevoke_AlreadyExecuted(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("v"), nil, 21000, []byte("gp"), 0)
	sig0, _ := privkeys[0].Sign(tx.TxHash)
	sig1, _ := privkeys[1].Sign(tx.TxHash)
	wallet.CollectSignature(tx.TxHash, sig0, 0)
	wallet.CollectSignature(tx.TxHash, sig1, 1)

	exec := NewMultiSigExecutor(wallet)
	exec.Execute(tx.TxHash)

	revokeMsg := generateRevokeMessage(wallet.Address(), tx.TxHash, wallet.config.ChainID)
	revSig0, _ := privkeys[0].Sign(revokeMsg)
	revSig1, _ := privkeys[1].Sign(revokeMsg)
	err := wallet.Revoke(tx.TxHash, [][]byte{revSig0, revSig1})
	if err != ErrTxAlreadyExecuted {
		t.Errorf("expected ErrTxAlreadyExecuted, got %v", err)
	}
}

func TestUpdateSigners_InsufficientSigs(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	err := wallet.UpdateSigners(make([][]byte, 1), [][]byte{})
	if err != ErrUpdateRequiresSigs {
		t.Errorf("expected ErrUpdateRequiresSigs, got %v", err)
	}
}

func TestErrorValues(t *testing.T) {
	errors := []error{
		ErrInvalidConfig, ErrInvalidPublicKey, ErrDuplicateSigner,
		ErrInvalidSignerIndex, ErrAlreadySigned, ErrInsufficientSigs,
		ErrNotReadyToExecute, ErrTimeLockActive, ErrTxNotFound,
		ErrTxAlreadyExecuted, ErrTxRevoked, ErrRevokeRequiresSigs,
		ErrUpdateRequiresSigs, ErrAggregationFailed, ErrNoSignatures,
		ErrSigCountMismatch, ErrInvalidSignature, ErrSignerNotInWallet,
		ErrSignatureVerification, ErrExecutionFailed,
	}

	for _, e := range errors {
		if e.Error() == "" {
			t.Errorf("error %T has empty message", e)
		}
	}
}

func TestExecute_TxNotFound(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	exec := NewMultiSigExecutor(wallet)
	_, _, err := exec.Execute([]byte("unknown"))
	if err != ErrTxNotFound {
		t.Errorf("expected ErrTxNotFound, got %v", err)
	}
}

func TestExecute_AlreadyExecuted(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("v"), nil, 21000, []byte("gp"), 0)
	sig0, _ := privkeys[0].Sign(tx.TxHash)
	sig1, _ := privkeys[1].Sign(tx.TxHash)
	wallet.CollectSignature(tx.TxHash, sig0, 0)
	wallet.CollectSignature(tx.TxHash, sig1, 1)

	exec := NewMultiSigExecutor(wallet)
	exec.Execute(tx.TxHash)

	_, _, err := exec.Execute(tx.TxHash)
	if err != ErrTxAlreadyExecuted {
		t.Errorf("expected ErrTxAlreadyExecuted, got %v", err)
	}
}

func TestExecute_TxRevoked(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("v"), nil, 21000, []byte("gp"), 0)
	revokeMsg := generateRevokeMessage(wallet.Address(), tx.TxHash, wallet.config.ChainID)
	revSig0, _ := privkeys[0].Sign(revokeMsg)
	revSig1, _ := privkeys[1].Sign(revokeMsg)
	wallet.Revoke(tx.TxHash, [][]byte{revSig0, revSig1})

	exec := NewMultiSigExecutor(wallet)
	_, _, err := exec.Execute(tx.TxHash)
	if err != ErrTxRevoked {
		t.Errorf("expected ErrTxRevoked, got %v", err)
	}
}

func TestExecute_TimeLockActive(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
		TimeLock:           9999999999,
	})

	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("v"), nil, 21000, []byte("gp"), 0)
	sig0, _ := privkeys[0].Sign(tx.TxHash)
	sig1, _ := privkeys[1].Sign(tx.TxHash)
	wallet.CollectSignature(tx.TxHash, sig0, 0)
	wallet.CollectSignature(tx.TxHash, sig1, 1)

	exec := NewMultiSigExecutor(wallet)
	_, _, err := exec.Execute(tx.TxHash)
	if err != ErrTimeLockActive {
		t.Errorf("expected ErrTimeLockActive, got %v", err)
	}
}

func TestGenerateMultiSigAddress_OrderInvariant(t *testing.T) {
	pubkeys1, _ := generateTestKeys(t, 3)
	pubkeys2 := make([][]byte, 3)
	pubkeys2[0] = pubkeys1[1]
	pubkeys2[1] = pubkeys1[2]
	pubkeys2[2] = pubkeys1[0]

	addr1 := GenerateMultiSigAddress(pubkeys1, 2)
	addr2 := GenerateMultiSigAddress(pubkeys2, 2)

	if addr1 != addr2 {
		t.Error("address should be order-invariant (keys are sorted)")
	}
}

// TestSerializeDeserializeWalletBinary_RoundTrip verifies that
// SerializeWalletBinary followed by DeserializeWalletBinary faithfully
// reproduces every field of a WalletConfig, including aliases and the
// LargeAmountThreshold. R4-C2 FIX (2026-07-06).
func TestSerializeDeserializeWalletBinary_RoundTrip(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)

	original := &WalletConfig{
		Address: types.BytesToAddress([]byte("1234567890abcdefghij")),
		Signers: []SignerInfo{
			{PublicKey: pubkeys[0], Alias: "alice"},
			{PublicKey: pubkeys[1], Alias: "bob-the-builder"},
			{PublicKey: pubkeys[2]}, // empty alias
		},
		Threshold:            2,
		LargeAmountThreshold: new(big.Int).SetUint64(1_000_000_000_000),
		CreatedAt:            1700000000,
	}

	store := NewMultisigStateStore()
	data, err := store.SerializeWalletBinary(original)
	if err != nil {
		t.Fatalf("SerializeWalletBinary failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("serialized data should not be empty")
	}

	decoded, err := store.DeserializeWalletBinary(data)
	if err != nil {
		t.Fatalf("DeserializeWalletBinary failed: %v", err)
	}

	if decoded.Address != original.Address {
		t.Errorf("Address mismatch: got %x, want %x", decoded.Address, original.Address)
	}
	if decoded.Threshold != original.Threshold {
		t.Errorf("Threshold mismatch: got %d, want %d", decoded.Threshold, original.Threshold)
	}
	if decoded.CreatedAt != original.CreatedAt {
		t.Errorf("CreatedAt mismatch: got %d, want %d", decoded.CreatedAt, original.CreatedAt)
	}
	if decoded.LargeAmountThreshold == nil {
		t.Fatal("LargeAmountThreshold should not be nil")
	}
	if decoded.LargeAmountThreshold.Cmp(original.LargeAmountThreshold) != 0 {
		t.Errorf("LargeAmountThreshold mismatch: got %s, want %s",
			decoded.LargeAmountThreshold.String(), original.LargeAmountThreshold.String())
	}
	if len(decoded.Signers) != len(original.Signers) {
		t.Fatalf("Signers count mismatch: got %d, want %d", len(decoded.Signers), len(original.Signers))
	}
	for i, si := range original.Signers {
		if string(decoded.Signers[i].PublicKey) != string(si.PublicKey) {
			t.Errorf("signer %d PublicKey mismatch", i)
		}
		if decoded.Signers[i].Alias != si.Alias {
			t.Errorf("signer %d Alias mismatch: got %q, want %q", i, decoded.Signers[i].Alias, si.Alias)
		}
	}
}

// TestSerializeDeserializeWalletBinary_NilLargeAmount verifies that a nil
// LargeAmountThreshold round-trips back to nil (all-zero 32-byte field).
// R4-C2 FIX (2026-07-06).
func TestSerializeDeserializeWalletBinary_NilLargeAmount(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 1)
	original := &WalletConfig{
		Address:   types.BytesToAddress([]byte("0987654321abcdefghij")),
		Signers:   []SignerInfo{{PublicKey: pubkeys[0], Alias: "solo"}},
		Threshold: 1,
		CreatedAt: 99,
		// LargeAmountThreshold left nil
	}

	store := NewMultisigStateStore()
	data, err := store.SerializeWalletBinary(original)
	if err != nil {
		t.Fatalf("SerializeWalletBinary failed: %v", err)
	}

	decoded, err := store.DeserializeWalletBinary(data)
	if err != nil {
		t.Fatalf("DeserializeWalletBinary failed: %v", err)
	}
	if decoded.LargeAmountThreshold != nil {
		t.Errorf("LargeAmountThreshold should be nil, got %s", decoded.LargeAmountThreshold.String())
	}
	if decoded.Threshold != 1 {
		t.Errorf("Threshold mismatch: got %d, want 1", decoded.Threshold)
	}
}

// TestDeserializeWalletBinary_TooShort verifies that truncated input is
// rejected with an error rather than panicking. R4-C2 FIX (2026-07-06).
func TestDeserializeWalletBinary_TooShort(t *testing.T) {
	store := NewMultisigStateStore()
	_, err := store.DeserializeWalletBinary([]byte("way too short"))
	if err == nil {
		t.Error("expected error for truncated data, got nil")
	}
}

// TestHashWalletConfig_Deterministic verifies that HashWalletConfig produces
// identical hashes for identical configs and different hashes for different
// configs. R4-C2 FIX (2026-07-06).
func TestHashWalletConfig_Deterministic(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 2)

	cfg := &WalletConfig{
		Address:              types.BytesToAddress([]byte("1234567890abcdefghij")),
		Signers:              []SignerInfo{{PublicKey: pubkeys[0], Alias: "a"}, {PublicKey: pubkeys[1], Alias: "b"}},
		Threshold:            2,
		LargeAmountThreshold: big.NewInt(42),
		CreatedAt:            100,
	}

	store := NewMultisigStateStore()
	h1, err := store.HashWalletConfig(cfg)
	if err != nil {
		t.Fatalf("HashWalletConfig failed: %v", err)
	}
	if h1 == (types.Hash{}) {
		t.Fatal("hash should not be zero")
	}

	h2, err := store.HashWalletConfig(cfg)
	if err != nil {
		t.Fatalf("second HashWalletConfig failed: %v", err)
	}
	if h1 != h2 {
		t.Error("identical configs should produce identical hashes")
	}

	// Mutate one field — the hash must change.
	cfg.Threshold = 3
	h3, err := store.HashWalletConfig(cfg)
	if err != nil {
		t.Fatalf("third HashWalletConfig failed: %v", err)
	}
	if h1 == h3 {
		t.Error("different configs should produce different hashes")
	}
}

// R31-MED-2: short/long txHash inputs must be rejected with
// ErrInvalidParams BEFORE any lookup — `copy(key[:], txHash)` previously
// zero-padded short hashes so different prefixes collided on one store key.
func TestTxHashStrictLengthContract(t *testing.T) {
	pubkeys, _ := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	badHashes := [][]byte{
		nil,
		[]byte("short"),
		make([]byte, 31),
		make([]byte, 33),
	}
	for i, h := range badHashes {
		if err := wallet.CollectSignature(h, []byte("sig"), 0); err == nil {
			t.Errorf("case %d: CollectSignature accepted invalid-length hash", i)
		}
		if _, err := wallet.GetTransaction(h); err == nil {
			t.Errorf("case %d: GetTransaction accepted invalid-length hash", i)
		}
		if _, err := wallet.IsReadyToExecute(h); err == nil {
			t.Errorf("case %d: IsReadyToExecute accepted invalid-length hash", i)
		}
		if err := wallet.Revoke(h, nil); err == nil {
			t.Errorf("case %d: Revoke accepted invalid-length hash", i)
		}
		if err := wallet.CollectTSSSignature(h, []byte("sig")); err == nil {
			t.Errorf("case %d: CollectTSSSignature accepted invalid-length hash", i)
		}
	}
}

// R31-MED-2: UpdateSigners must RESET the retained pending transactions'
// signature state — bit N in the old bitmap refers to a position in the
// PREVIOUS signer list and must not credit approvals under the new set.
func TestUpdateSignersResetsSignatureState(t *testing.T) {
	pubkeys, privkeys := generateTestKeys(t, 3)
	wallet, _ := NewMultiSigWallet(&MultiSigConfig{
		RequiredSignatures: 2,
		TotalSigners:       3,
		PublicKeys:         pubkeys,
	})

	tx, _ := wallet.ProposeTransaction(0, []byte("to"), []byte("v"), nil, 21000, []byte("gp"), 0)

	sig0, _ := privkeys[0].Sign(tx.TxHash)
	if err := wallet.CollectSignature(tx.TxHash, sig0, 0); err != nil {
		t.Fatalf("CollectSignature: %v", err)
	}

	got, err := wallet.GetTransaction(tx.TxHash)
	if err != nil {
		t.Fatalf("GetTransaction: %v", err)
	}
	if got.Status != TxStatusPartiallySigned {
		t.Fatalf("expected PartiallySigned after first sig, got %v", got.Status)
	}

	// Rotate the signer set (same threshold, new keys).
	newPubkeys, _ := generateTestKeys(t, 3)
	updateMsgSigs := make([][]byte, len(pubkeys))
	msg := generateUpdateData(wallet.Address(), newPubkeys, wallet.Config().ChainID)
	for i := range pubkeys {
		updateMsgSigs[i], _ = privkeys[i].Sign(msg)
	}
	if err := wallet.UpdateSigners(newPubkeys, updateMsgSigs); err != nil {
		t.Fatalf("UpdateSigners: %v", err)
	}

	got, err = wallet.GetTransaction(tx.TxHash)
	if err != nil {
		t.Fatalf("GetTransaction after update: %v", err)
	}
	// Signature state must be reset: no approvals carried over.
	for i, b := range got.SignerBitmap {
		if b != 0 {
			t.Fatalf("SignerBitmap not reset at byte %d: %08b", i, b)
		}
	}
	if got.Status == TxStatusReadyToExecute || got.Status == TxStatusPartiallySigned {
		t.Fatalf("stale signature status carried over: %v", got.Status)
	}
}

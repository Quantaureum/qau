// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/multisig"
)

// TestR4KEYS01_RegisterWalletWithRealPublicKeys verifies that RegisterWallet
// stores the real 1952-byte Dilithium3 public key (not the 20-byte address)
// when signerPublicKeys is provided.
//
// AUDIT R4-KEYS-01 (2026-07-15): Previously RegisterWallet stored
// SignerInfo.PublicKey = address[:] (20 bytes), but ApproveProposal calls
// crypto.PublicKeyFromBytes which requires 1952 bytes → every approval was
// rejected → multisig funds permanently locked.
func TestR4KEYS01_RegisterWalletWithRealPublicKeys(t *testing.T) {
	store := multisig.NewMultisigStateStore()
	api := NewMultisigAPI(store, newMockStateReader(), &mockChainStateDB{})

	// Generate a real Dilithium3 key pair for the signer.
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	signerPubKey := keyPair.Public.Bytes()
	signerAddr := crypto.PublicKeyAddressFromBytes(signerPubKey)

	if len(signerPubKey) != crypto.Dilithium3PublicKeySize {
		t.Fatalf("public key size = %d, want %d", len(signerPubKey), crypto.Dilithium3PublicKeySize)
	}

	// Register wallet with real public keys.
	req := map[string]any{
		"address":   "0x" + hex.EncodeToString(signerAddr[:]),
		"threshold": 1,
		"signers":   []string{"0x" + hex.EncodeToString(signerAddr[:])},
		"signerPublicKeys": map[string]string{
			"0x" + hex.EncodeToString(signerAddr[:]): "0x" + hex.EncodeToString(signerPubKey),
		},
	}
	params, _ := json.Marshal(req)

	result, apiErr := api.RegisterWallet(context.Background(), params)
	if apiErr != nil {
		t.Fatalf("RegisterWallet failed: %v", apiErr)
	}

	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}
	if resultMap["success"] != true {
		t.Fatalf("expected success=true, got %v", resultMap["success"])
	}

	// Verify the stored SignerInfo has the real 1952-byte public key.
	walletConfig := store.GetWallet(signerAddr)
	if walletConfig == nil {
		t.Fatal("wallet not found in store after registration")
	}
	if len(walletConfig.Signers) == 0 {
		t.Fatal("no signers in wallet config")
	}
	storedKey := walletConfig.Signers[0].PublicKey
	if len(storedKey) != crypto.Dilithium3PublicKeySize {
		t.Fatalf("stored SignerInfo.PublicKey size = %d, want %d (R4-KEYS-01: "+
			"RegisterWallet must store real Dilithium3 public key, not address)",
			len(storedKey), crypto.Dilithium3PublicKeySize)
	}

	// Verify the stored key matches the input.
	for i := 0; i < crypto.Dilithium3PublicKeySize; i++ {
		if storedKey[i] != signerPubKey[i] {
			t.Fatalf("stored SignerInfo.PublicKey mismatch at byte %d", i)
		}
	}
}

// TestR4KEYS01_RegisterWalletRejectsMismatchedPubKey verifies that
// RegisterWallet rejects a public key that doesn't derive to the claimed
// address (prevents registering an attacker's key under a victim's address).
func TestR4KEYS01_RegisterWalletRejectsMismatchedPubKey(t *testing.T) {
	store := multisig.NewMultisigStateStore()
	api := NewMultisigAPI(store, newMockStateReader(), &mockChainStateDB{})

	// Generate two key pairs — use signer1's address but signer2's public key.
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	addr1 := crypto.PublicKeyAddressFromBytes(kp1.Public.Bytes())
	pubKey2 := kp2.Public.Bytes()

	req := map[string]any{
		"address":   "0x" + hex.EncodeToString(addr1[:]),
		"threshold": 1,
		"signers":   []string{"0x" + hex.EncodeToString(addr1[:])},
		"signerPublicKeys": map[string]string{
			"0x" + hex.EncodeToString(addr1[:]): "0x" + hex.EncodeToString(pubKey2),
		},
	}
	params, _ := json.Marshal(req)

	_, apiErr := api.RegisterWallet(context.Background(), params)
	if apiErr == nil {
		t.Fatal("RegisterWallet should reject mismatched public key/address pair " +
			"(attacker could register their key under victim's address)")
	}
	if !strings.Contains(apiErr.Message, "does not match") && !strings.Contains(apiErr.Message, "mismatch") {
		t.Fatalf("expected mismatch error, got: %s", apiErr.Message)
	}
}

// TestR4KEYS01_ApproveProposalWithRealPubKey verifies the full approve flow:
// register wallet with real public key → create proposal → sign → approve.
// This is the core regression test for R4-KEYS-01.
func TestR4KEYS01_ApproveProposalWithRealPubKey(t *testing.T) {
	store := multisig.NewMultisigStateStore()
	api := NewMultisigAPI(store, newMockStateReader(), &mockChainStateDB{})
	api.SetChainInfo(newMockChainInfo())

	// Generate a real Dilithium3 key pair.
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	signerPubKey := keyPair.Public.Bytes()
	signerAddr := crypto.PublicKeyAddressFromBytes(signerPubKey)

	// Step 1: Register wallet with real public key.
	regReq := map[string]any{
		"address":   "0x" + hex.EncodeToString(signerAddr[:]),
		"threshold": 1,
		"signers":   []string{"0x" + hex.EncodeToString(signerAddr[:])},
		"signerPublicKeys": map[string]string{
			"0x" + hex.EncodeToString(signerAddr[:]): "0x" + hex.EncodeToString(signerPubKey),
		},
	}
	regParams, _ := json.Marshal(regReq)
	_, apiErr := api.RegisterWallet(context.Background(), regParams)
	if apiErr != nil {
		t.Fatalf("RegisterWallet: %v", apiErr)
	}

	// Step 2: Create a proposal.
	createReq := map[string]any{
		"from":  "0x" + hex.EncodeToString(signerAddr[:]),
		"to":    "0x" + hex.EncodeToString(signerAddr[:]),
		"value": "100",
	}
	createParams, _ := json.Marshal(createReq)
	createResult, apiErr := api.CreateProposal(context.Background(), createParams)
	if apiErr != nil {
		t.Fatalf("CreateProposal: %v", apiErr)
	}

	createMap := createResult.(map[string]any)
	proposalHashHex, ok := createMap["hash"].(string)
	if !ok {
		t.Fatalf("proposal hash not found or wrong type: %T", createMap["hash"])
	}

	// Step 3: Sign the proposal hash with the signer's private key.
	hashBytes, err := hex.DecodeString(strings.TrimPrefix(proposalHashHex, "0x"))
	if err != nil {
		t.Fatalf("decode proposal hash: %v", err)
	}
	signingHash := hashBytes
	if len(signingHash) > 32 {
		signingHash = signingHash[:32]
	}
	signature, err := crypto.Sign(keyPair.Private, signingHash)
	if err != nil {
		t.Fatalf("crypto.Sign: %v", err)
	}

	// Step 4: Approve the proposal with the signature.
	approveReq := map[string]any{
		"proposalHash":  proposalHashHex,
		"signerAddress": "0x" + hex.EncodeToString(signerAddr[:]),
		"signature":     "0x" + hex.EncodeToString(signature),
	}
	approveParams, _ := json.Marshal(approveReq)
	approveResult, apiErr := api.ApproveProposal(context.Background(), approveParams)
	if apiErr != nil {
		t.Fatalf("ApproveProposal FAILED (R4-KEYS-01 regression — signature "+
			"verification should succeed with real public key): %v", apiErr)
	}

	// Step 5: Verify the approval was accepted (signerCount >= 1).
	approveMap, ok := approveResult.(map[string]any)
	if !ok {
		t.Fatalf("unexpected approve result type: %T", approveResult)
	}
	// proposalToMap returns signerCount as int (p.SignerCount()).
	var signerCount int
	switch v := approveMap["signerCount"].(type) {
	case int:
		signerCount = v
	case float64:
		signerCount = int(v)
	default:
		t.Fatalf("signerCount not found or wrong type: %T", approveMap["signerCount"])
	}
	if signerCount < 1 {
		t.Fatalf("signerCount = %v, want >= 1 (R4-KEYS-01: approval was not counted)", signerCount)
	}

	t.Log("=== R4-KEYS-01: multisig approve with real Dilithium3 public key PASS ===")
}

// TestR4KEYS01_LegacyWalletWithoutPubKeyFailsVerification verifies that a
// wallet registered WITHOUT signerPublicKeys (legacy mode) stores 20-byte
// address entries, and that signature verification FAILS for those signers
// (fail-closed — no fund theft, but multisig is unusable until re-registered
// with real public keys).
func TestR4KEYS01_LegacyWalletWithoutPubKeyFailsVerification(t *testing.T) {
	store := multisig.NewMultisigStateStore()
	api := NewMultisigAPI(store, newMockStateReader(), &mockChainStateDB{})
	api.SetChainInfo(newMockChainInfo())

	// Generate a key pair to get a real address, but DON'T pass the public key.
	keyPair, _ := crypto.GenerateKeyPair()
	signerAddr := crypto.PublicKeyAddressFromBytes(keyPair.Public.Bytes())

	// Register WITHOUT signerPublicKeys (legacy mode).
	regReq := map[string]any{
		"address":   "0x" + hex.EncodeToString(signerAddr[:]),
		"threshold": 1,
		"signers":   []string{"0x" + hex.EncodeToString(signerAddr[:])},
	}
	regParams, _ := json.Marshal(regReq)
	_, apiErr := api.RegisterWallet(context.Background(), regParams)
	if apiErr != nil {
		t.Fatalf("RegisterWallet: %v", apiErr)
	}

	// Verify the stored SignerInfo has only 20 bytes (address, not real key).
	walletConfig := store.GetWallet(signerAddr)
	if walletConfig == nil {
		t.Fatal("wallet not found")
	}
	storedKey := walletConfig.Signers[0].PublicKey
	if len(storedKey) != 20 {
		t.Fatalf("legacy mode should store 20-byte address, got %d bytes", len(storedKey))
	}

	// Create a proposal.
	createReq := map[string]any{
		"from":  "0x" + hex.EncodeToString(signerAddr[:]),
		"to":    "0x" + hex.EncodeToString(signerAddr[:]),
		"value": "100",
	}
	createParams, _ := json.Marshal(createReq)
	createResult, _ := api.CreateProposal(context.Background(), createParams)
	createMap := createResult.(map[string]any)
	proposalHashHex := createMap["hash"].(string)

	// Sign the proposal hash.
	hashBytes, _ := hex.DecodeString(strings.TrimPrefix(proposalHashHex, "0x"))
	signingHash := hashBytes
	if len(signingHash) > 32 {
		signingHash = signingHash[:32]
	}
	signature, _ := crypto.Sign(keyPair.Private, signingHash)

	// Approve — should FAIL because the stored public key is only 20 bytes.
	approveReq := map[string]any{
		"proposalHash":  proposalHashHex,
		"signerAddress": "0x" + hex.EncodeToString(signerAddr[:]),
		"signature":     "0x" + hex.EncodeToString(signature),
	}
	approveParams, _ := json.Marshal(approveReq)
	_, apiErr = api.ApproveProposal(context.Background(), approveParams)
	if apiErr == nil {
		t.Fatal("ApproveProposal should FAIL for legacy wallet (20-byte address " +
			"stored as PublicKey, but verification requires 1952 bytes) — " +
			"if this passes, the fail-closed property is broken")
	}

	// Verify the error is about signature verification (not about signer not found).
	if !strings.Contains(apiErr.Message, "signature") && !strings.Contains(apiErr.Message, "valid") {
		t.Fatalf("expected signature verification error, got: %s", apiErr.Message)
	}

	t.Log("=== R4-KEYS-01: legacy wallet (no pubkey) correctly fails signature verification (fail-closed) ===")
}

// Ensure big.Int import is used (for potential future test extensions).
var _ = big.NewInt

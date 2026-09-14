// Quantaureum Node source, version 1.0.0.
// Copyright (c) 2026 Quantaureum Project
// SPDX-License-Identifier: MIT
//
// ECON-R14-H03 (2026-07-21): regression test for RefundFailedLock
// SourceAddress bug. Previously the refund BridgeMessage set
// SourceAddress to lock.TokenAddress (the token contract address) with
// a misleading "bridge holding address" comment, AND set both
// SourceChain and TargetChain to lock.SourceChain (tripping the
// "source and target chains must be different" validation).
//
// Both bugs caused the refund to fail — the owner's locked funds stayed
// permanently locked with no recovery path. These tests exercise
// buildRefundMessage directly (extracted from RefundFailedLock) because
// bridge.SubmitMessage fails-closed in tests when no trusted validator
// keys are configured.
package bridge

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// TestECON_R14H03_RefundMessageSourceAddressIsOwner verifies that the
// refund message sets SourceAddress to the lock OWNER's address, not
// the token contract address. This is the regression test for the
// ECON-R14-H03 fix.
func TestECON_R14H03_RefundMessageSourceAddressIsOwner(t *testing.T) {
	b := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	defer b.Stop(context.Background())
	alm := NewAssetLockManager(b, types.Address{})

	// Use DISTINCT owner and token addresses so the test can detect
	// which one ends up in SourceAddress.
	ownerAddr := types.Address{0xAA, 0xBB, 0xCC}
	tokenAddr := types.Address{0x11, 0x22, 0x33}
	lock := &AssetLock{
		ID:           "lock-r14-h03-refund",
		SourceChain:  "source-chain",
		TargetChain:  "target-chain",
		AssetType:    AssetTypeQRC20,
		TokenAddress: tokenAddr,
		Amount:       big.NewInt(1000),
		Owner:        ownerAddr,
		Recipient:    types.Address{0xBB},
		Status:       LockStatusFailed,
		FailedAt:     time.Now().Unix(),
		FailedReason: "mint submit failed: simulated (was Locked)",
	}

	msg := alm.buildRefundMessage(lock)

	expectedSource := ownerAddr.ToHexAddress()
	expectedTarget := ownerAddr.ToHexAddress()
	tokenHex := tokenAddr.ToHexAddress()

	if msg.SourceAddress != expectedSource {
		t.Errorf("ECON-R14-H03 regression: refund SourceAddress = %q, want owner address %q (token contract address was %q)",
			msg.SourceAddress, expectedSource, tokenHex)
	}
	if msg.SourceAddress == tokenHex {
		t.Errorf("ECON-R14-H03 regression: refund SourceAddress matches TokenAddress %q — funds would be permanently locked",
			tokenHex)
	}
	if msg.TargetAddress != expectedTarget {
		t.Errorf("refund TargetAddress = %q, want owner address %q",
			msg.TargetAddress, expectedTarget)
	}
}

// TestECON_R14H03_RefundMessageRoutesFromTargetToSource verifies that
// the refund message routes FROM the target chain (where the mint
// failure was observed) TO the source chain (where the locked funds
// must be released). This mirrors the UnlockAsset routing pattern and
// passes the bridge's "source and target chains must be different"
// validation. Previously both chains were set to lock.SourceChain,
// which failed validation and caused the refund to never reach the
// adapter.
func TestECON_R14H03_RefundMessageRoutesFromTargetToSource(t *testing.T) {
	b := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	defer b.Stop(context.Background())
	alm := NewAssetLockManager(b, types.Address{})

	lock := &AssetLock{
		ID:           "lock-r14-h03-routing",
		SourceChain:  "source-chain",
		TargetChain:  "target-chain",
		AssetType:    AssetTypeQRC20,
		TokenAddress: types.Address{0x11},
		Amount:       big.NewInt(1000),
		Owner:        types.Address{0xAA},
		Recipient:    types.Address{0xBB},
		Status:       LockStatusFailed,
		FailedAt:     time.Now().Unix(),
		FailedReason: "mint submit failed",
	}

	msg := alm.buildRefundMessage(lock)

	// Refund routes FROM target chain (failure side) TO source chain
	// (release side), matching UnlockAsset's routing pattern.
	if msg.SourceChain != "target-chain" {
		t.Errorf("refund SourceChain = %q, want %q (target chain where failure was observed)",
			msg.SourceChain, "target-chain")
	}
	if msg.TargetChain != "source-chain" {
		t.Errorf("refund TargetChain = %q, want %q (source chain where funds are locked)",
			msg.TargetChain, "source-chain")
	}
}

// TestECON_R14H03_RefundMessageFieldsComplete verifies all other
// message fields are correctly populated from the lock — amount,
// asset type, asset ID, message type, status, and nonce.
func TestECON_R14H03_RefundMessageFieldsComplete(t *testing.T) {
	b := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	defer b.Stop(context.Background())
	alm := NewAssetLockManager(b, types.Address{})

	lock := &AssetLock{
		ID:           "lock-fields",
		SourceChain:  "source-chain",
		TargetChain:  "target-chain",
		AssetType:    AssetTypeQRC20,
		TokenAddress: types.Address{0x11, 0x22},
		Amount:       big.NewInt(5000),
		Owner:        types.Address{0xAA},
		Recipient:    types.Address{0xBB},
		Status:       LockStatusFailed,
		FailedAt:     time.Now().Unix(),
	}

	msg := alm.buildRefundMessage(lock)

	if msg.ID != "lock-fields-refund" {
		t.Errorf("refund ID = %q, want %q", msg.ID, "lock-fields-refund")
	}
	if msg.AssetType != AssetTypeQRC20 {
		t.Errorf("refund AssetType = %q, want %q", msg.AssetType, AssetTypeQRC20)
	}
	expectedTokenAddr := types.Address{0x11, 0x22}
	expectedAssetID := expectedTokenAddr.ToHexAddress()
	if msg.AssetID != expectedAssetID {
		t.Errorf("refund AssetID = %q, want %q", msg.AssetID, expectedAssetID)
	}
	if msg.Amount != "5000" {
		t.Errorf("refund Amount = %q, want %q", msg.Amount, "5000")
	}
	if msg.MessageType != MessageTypeAssetTransfer {
		t.Errorf("refund MessageType = %q, want %q", msg.MessageType, MessageTypeAssetTransfer)
	}
	if msg.Status != MessageStatusPending {
		t.Errorf("refund Status = %q, want %q", msg.Status, MessageStatusPending)
	}
	if msg.Nonce == 0 {
		t.Error("refund Nonce should be non-zero (monotonic counter)")
	}
}

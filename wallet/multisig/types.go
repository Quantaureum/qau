// Quantaureum Node source, version 1.0.0.
package multisig

import "github.com/quantaureum/qau/types"

type MultiSigTxStatus uint8

const (
	TxStatusPending         MultiSigTxStatus = 0
	TxStatusPartiallySigned MultiSigTxStatus = 1
	TxStatusReadyToExecute  MultiSigTxStatus = 2
	TxStatusExecuted        MultiSigTxStatus = 3
	TxStatusExpired         MultiSigTxStatus = 4
	TxStatusRevoked         MultiSigTxStatus = 5
)

func (s MultiSigTxStatus) String() string {
	switch s {
	case TxStatusPending:
		return "pending"
	case TxStatusPartiallySigned:
		return "partially_signed"
	case TxStatusReadyToExecute:
		return "ready_to_execute"
	case TxStatusExecuted:
		return "executed"
	case TxStatusExpired:
		return "expired"
	case TxStatusRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

type MultiSigTransaction struct {
	TxHash   []byte
	To       []byte
	Value    []byte
	Data     []byte
	Nonce    uint64
	GasLimit uint64
	GasPrice []byte
	// ChainID binds this transaction to a specific chain to prevent cross-chain
	// replay. R7-DEPLOY FIX: previously absent, so the same multisig tx could be
	// replayed on another network. Covered by ComputeSigningHash.
	ChainID uint64
	// WalletAddr binds this transaction to a specific multisig wallet to
	// prevent cross-wallet signature replay. AUDIT (2026) KEYS-R3-01:
	// Without this, a signer shared across multiple multisig wallets could
	// replay a signature from wallet A to wallet B (same tx fields → same
	// hash → same signature verifies on both).
	WalletAddr   types.Address
	Signatures   [][]byte
	SignerBitmap []byte
	TSSSignature []byte
	Status       MultiSigTxStatus
	Proposer     int
	CreatedAt    int64
	ExpiresAt    int64
}

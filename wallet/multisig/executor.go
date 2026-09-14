// Quantaureum Node source, version 1.0.0.
package multisig

import (
	"errors"
	"fmt"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/quantum"
)

var (
	ErrExecutionFailed = errors.New("multisig: execution failed")
)

type MultiSigExecutor struct {
	wallet *MultiSigWallet
}

func NewMultiSigExecutor(wallet *MultiSigWallet) *MultiSigExecutor {
	return &MultiSigExecutor{wallet: wallet}
}

func (e *MultiSigExecutor) Execute(txHash []byte) ([]byte, *quantum.AggregatedSignature, error) {
	e.wallet.mu.Lock()
	defer e.wallet.mu.Unlock()

	var key [32]byte
	copy(key[:], txHash)

	tx, ok := e.wallet.pendingTxs[key]
	if !ok {
		return nil, nil, ErrTxNotFound
	}

	if tx.Status == TxStatusExecuted {
		return nil, nil, ErrTxAlreadyExecuted
	}

	if tx.Status == TxStatusRevoked {
		return nil, nil, ErrTxRevoked
	}

	// SECURITY FIX H-8: Check transaction expiration before execution.
	// Previously the ExpiresAt field was ignored, allowing stale transactions
	// to be executed long after their intended validity window. This could
	// enable replay of outdated authorized actions (e.g., outdated price
	// transfers, revoked-but-not-on-chain approvals).
	if tx.ExpiresAt > 0 && time.Now().Unix() > tx.ExpiresAt {
		tx.Status = TxStatusExpired
		return nil, nil, ErrTxExpired
	}

	sigCount := e.wallet.countSignatures(tx)
	if sigCount < e.wallet.config.RequiredSignatures {
		return nil, nil, ErrNotReadyToExecute
	}

	// AUDIT (2026) KEYS-07: Previously `if TimeLock > 0` unconditionally
	// returned ErrTimeLockActive without comparing against current time.
	// This permanently locked all funds in any wallet with TimeLock set,
	// contradicting IsReadyToExecute (wallet.go:425) which correctly checks
	// `time.Now() < TimeLock`. Fix: match IsReadyToExecute's logic — only
	// reject if the current time is still before the TimeLock timestamp.
	if e.wallet.config.TimeLock > 0 && time.Now().Unix() < int64(e.wallet.config.TimeLock) {
		return nil, nil, ErrTimeLockActive
	}

	signatures := make([][]byte, 0, sigCount)
	publicKeys := make([][]byte, 0, sigCount)

	expectedBitmapLen := (e.wallet.config.TotalSigners + 7) / 8
	if len(tx.SignerBitmap) < expectedBitmapLen {
		return nil, nil, fmt.Errorf("%w: signer bitmap too short (len=%d, need=%d)",
			ErrExecutionFailed, len(tx.SignerBitmap), expectedBitmapLen)
	}
	if len(tx.Signatures) < e.wallet.config.TotalSigners {
		return nil, nil, fmt.Errorf("%w: signatures slice too short (len=%d, need=%d)",
			ErrExecutionFailed, len(tx.Signatures), e.wallet.config.TotalSigners)
	}
	if len(e.wallet.config.PublicKeys) < e.wallet.config.TotalSigners {
		return nil, nil, fmt.Errorf("%w: public keys slice too short (len=%d, need=%d)",
			ErrExecutionFailed, len(e.wallet.config.PublicKeys), e.wallet.config.TotalSigners)
	}

	for i := 0; i < e.wallet.config.TotalSigners; i++ {
		byteIndex := i / 8
		bitIndex := uint(i % 8)
		if tx.SignerBitmap[byteIndex]&(1<<bitIndex) != 0 {
			signatures = append(signatures, tx.Signatures[i])
			publicKeys = append(publicKeys, e.wallet.config.PublicKeys[i])
		}
	}

	for i, sig := range signatures {
		if i >= len(publicKeys) {
			break
		}
		pubKey, err := crypto.PublicKeyFromBytes(publicKeys[i])
		if err != nil {
			return nil, nil, fmt.Errorf("%w: invalid public key %d: %v", ErrExecutionFailed, i, err)
		}
		if !pubKey.Verify(tx.TxHash, sig) {
			return nil, nil, fmt.Errorf("%w: signature verification failed for signer %d", ErrExecutionFailed, i)
		}
	}

	aggSig, err := e.wallet.aggregator.Aggregate(tx.TxHash, signatures, publicKeys)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: aggregation failed: %v", ErrExecutionFailed, err)
	}

	tx.Status = TxStatusExecuted

	executionData := make([]byte, 0)
	executionData = append(executionData, tx.TxHash...)
	executionData = append(executionData, tx.To...)
	executionData = append(executionData, tx.Value...)

	return executionData, aggSig, nil
}

// Quantaureum Node source, version 1.0.0.
package multisig

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/quantum"
)

var (
	ErrAggregationFailed = errors.New("multisig: signature aggregation failed")
	ErrNoSignatures      = errors.New("multisig: no signatures to aggregate")
	ErrSigCountMismatch  = errors.New("multisig: signature count exceeds available public keys")
)

type MultiSigAggregator struct {
	wallet *MultiSigWallet
}

func NewMultiSigAggregator(wallet *MultiSigWallet) *MultiSigAggregator {
	return &MultiSigAggregator{wallet: wallet}
}

func (a *MultiSigAggregator) AggregateSignatures(txHash []byte) (*quantum.AggregatedSignature, error) {
	a.wallet.mu.RLock()
	defer a.wallet.mu.RUnlock()

	var key [32]byte
	copy(key[:], txHash)

	tx, ok := a.wallet.pendingTxs[key]
	if !ok {
		return nil, ErrTxNotFound
	}

	sigCount := a.wallet.countSignatures(tx)
	if sigCount < a.wallet.config.RequiredSignatures {
		return nil, ErrInsufficientSigs
	}

	signatures := make([][]byte, 0, sigCount)
	publicKeys := make([][]byte, 0, sigCount)

	for i := 0; i < a.wallet.config.TotalSigners; i++ {
		byteIndex := i / 8
		bitIndex := uint(i % 8)
		if tx.SignerBitmap[byteIndex]&(1<<bitIndex) != 0 {
			signatures = append(signatures, tx.Signatures[i])
			publicKeys = append(publicKeys, a.wallet.config.PublicKeys[i])
		}
	}

	if len(signatures) == 0 {
		return nil, ErrNoSignatures
	}

	aggSig, err := a.wallet.aggregator.Aggregate(tx.TxHash, signatures, publicKeys)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAggregationFailed, err)
	}

	return aggSig, nil
}

func VerifyMultiSigSignature(txHash []byte, aggSig *quantum.AggregatedSignature, publicKeys [][]byte, requiredSigs int) error {
	if len(aggSig.Signatures) < requiredSigs {
		return ErrInsufficientSigs
	}

	for i, sig := range aggSig.Signatures {
		if i >= len(publicKeys) {
			return fmt.Errorf("%w: got %d signatures but only %d public keys",
				ErrSigCountMismatch, len(aggSig.Signatures), len(publicKeys))
		}

		pubKey, err := crypto.PublicKeyFromBytes(publicKeys[i])
		if err != nil {
			return fmt.Errorf("invalid public key %d: %w", i, err)
		}

		if !pubKey.Verify(txHash, sig) {
			return fmt.Errorf("signature verification failed for signer %d", i)
		}
	}

	return nil
}

// Deprecated: use computeTxHash instead. This function produces a different
// hash than computeTxHash for the same transaction (different field ordering
// and hash construction). Kept for backward compatibility with external callers.
func ComputeAggregatedTxHash(tx *MultiSigTransaction) []byte {
	h := sha256.New()
	// AUDIT (2026) KEYS-R3-01: Bind to wallet address to prevent
	// cross-wallet signature replay.
	h.Write(tx.WalletAddr[:])
	h.Write(tx.To)
	h.Write(tx.Value)
	h.Write(tx.Data)
	h.Write(tx.GasPrice)
	// audit fix (CRITICAL): Nonce and GasLimit added, matching computeTxHash/ComputeSigningHash
	var nonceBuf [8]byte
	binary.BigEndian.PutUint64(nonceBuf[:], tx.Nonce)
	h.Write(nonceBuf[:])
	var gasBuf [8]byte
	binary.BigEndian.PutUint64(gasBuf[:], tx.GasLimit)
	h.Write(gasBuf[:])
	// audit-fix HIGH: Include ChainID to prevent cross-chain signature replay.
	// Without ChainID, the same aggregated multisig signature could be replayed
	// on a different chain. This mirrors the protection in ComputeSigningHash
	// and computeTxHash.
	var chainBuf [8]byte
	binary.BigEndian.PutUint64(chainBuf[:], tx.ChainID)
	h.Write(chainBuf[:])
	return h.Sum(nil)
}

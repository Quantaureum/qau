// Quantaureum Node source, version 1.0.0.
package multisig

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/quantaureum/qau/crypto"
	"golang.org/x/crypto/sha3"
)

var (
	ErrInvalidSignature      = errors.New("multisig: invalid signature")
	ErrSignerNotInWallet     = errors.New("multisig: signer not in wallet")
	ErrSignatureVerification = errors.New("multisig: signature verification failed")
)

type SigningSession struct {
	wallet    *MultiSigWallet
	txHash    []byte
	collected int
}

func NewSigningSession(wallet *MultiSigWallet, txHash []byte) *SigningSession {
	return &SigningSession{
		wallet: wallet,
		txHash: txHash,
	}
}

func SignWithAccount(txHash []byte, accountPrivateKey *crypto.PrivateKey) ([]byte, error) {
	if accountPrivateKey == nil {
		return nil, ErrInvalidSignature
	}

	signature, err := accountPrivateKey.Sign(txHash)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func VerifySignature(txHash []byte, signature []byte, publicKey []byte) error {
	if len(publicKey) != crypto.Dilithium3PublicKeySize {
		return ErrInvalidSignature
	}

	pubKey, err := crypto.PublicKeyFromBytes(publicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	if !pubKey.Verify(txHash, signature) {
		return ErrSignatureVerification
	}

	return nil
}

func VerifySignerBelongsToWallet(publicKey []byte, wallet *MultiSigWallet) (int, error) {
	wallet.mu.RLock()
	defer wallet.mu.RUnlock()

	for i, pk := range wallet.config.PublicKeys {
		if len(pk) == len(publicKey) && subtle.ConstantTimeCompare(pk, publicKey) == 1 {
			return i, nil
		}
	}

	return -1, ErrSignerNotInWallet
}

// Deprecated: use computeTxHash instead. This function uses SHA3-256 while the
// canonical computeTxHash uses SHA-256, producing inconsistent hashes for the
// same transaction. Kept for backward compatibility with external callers.
func ComputeSigningHash(tx *MultiSigTransaction) []byte {
	h := sha3.New256()
	// AUDIT (2026) KEYS-R3-01: Bind to wallet address to prevent
	// cross-wallet signature replay.
	h.Write(tx.WalletAddr[:])
	h.Write(tx.To)
	h.Write(tx.Value)
	h.Write(tx.Data)
	h.Write(tx.GasPrice)
	// R7-Crypto FIX: Nonce was written as a single byte (byte(tx.Nonce)), so
	// nonces 0 and 256, 1 and 257, etc. produced identical signing hashes —
	// a signature-reuse / replay vector. Encode all 8 bytes canonically.
	var nonceBuf [8]byte
	binary.BigEndian.PutUint64(nonceBuf[:], tx.Nonce)
	h.Write(nonceBuf[:])
	// R7-Crypto FIX: GasLimit was not covered by the signature, so a malicious
	// signer relayer could bump GasLimit after collection without invalidating
	// signatures. Cover it.
	var gasBuf [8]byte
	binary.BigEndian.PutUint64(gasBuf[:], tx.GasLimit)
	h.Write(gasBuf[:])
	// R7-DEPLOY FIX: ChainID was not covered, so the same signed multisig tx
	// could be replayed on another chain. Bind it.
	var chainBuf [8]byte
	binary.BigEndian.PutUint64(chainBuf[:], tx.ChainID)
	h.Write(chainBuf[:])
	return h.Sum(nil)
}

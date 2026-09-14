// Quantaureum Node source, version 1.0.0.
package tss

import (
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// SignMessage produces a partial signature from a single share using the QTD protocol.
// The resulting PartialSignature contains the Round 1 commitment.
// Callers should collect commitments from all participants, call SubmitRound1,
// then call CompleteSign for each participant, and finally CombineSignatures.
func (m *TSSManager) SignMessage(message []byte, shareIndex int) (*PartialSignature, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.qtdShares[shareIndex]
	if !ok {
		return nil, ErrShareNotFound
	}

	participants := make([]int, 0, len(m.qtdShares))
	for pid := range m.qtdShares {
		participants = append(participants, pid)
	}

	if len(participants) < m.config.Threshold {
		return nil, ErrInsufficientShares
	}

	key := sessionKey(participants, message)
	session, ok := m.activeSessions[key]
	if !ok {
		return nil, fmt.Errorf("%w: no active session. Use CreateSigningSession first", ErrShareNotFound)
	}

	commitment, err := session.Round1Commitment(shareIndex)
	if err != nil {
		return nil, fmt.Errorf("round1 commitment failed: %w", err)
	}

	data := make([]byte, 32+16)
	copy(data[:32], commitment.Commitment)
	copy(data[32:48], commitment.Nonce)

	return &PartialSignature{
		Index:     shareIndex,
		Signature: data,
	}, nil
}

// CombinePartialSignatures combines partial signatures via the QTD protocol
// and returns a standard Dilithium3-compatible signature.
// Deprecated: Use CreateSigningSession + BeginSign + SubmitRound1 + CompleteSign + CombineSignatures
// for proper multi-round QTD signing flow.
func (m *TSSManager) CombinePartialSignatures(sessionKey string, partialSigs []*PartialSignature) ([]byte, error) {
	return m.CombineSignatures(sessionKey, partialSigs)
}

// VerifyCombinedSignature verifies a combined QTD signature against the group public key.
func (m *TSSManager) VerifyCombinedSignature(signature []byte, message []byte) error {
	m.mu.RLock()
	groupPK := m.qtdPubKey
	m.mu.RUnlock()

	if groupPK == nil {
		return ErrInsufficientShares
	}

	if len(signature) == 0 {
		return ErrSignatureVerificationFailed
	}

	var pk mode3.PublicKey
	// R38-P1-01 FIX (2026-08-01): use `!=` instead of `<`. A too-long
	// `groupPK.PubKey` would silently satisfy the old `<` gate, then
	// `Unpack` would only consume the first `mode3.PublicKeySize` bytes
	// while the trailing bytes were ignored — masking a corrupted/stale
	// key that failed the canonical crypto.PublicKeyFromBytes length
	// check. Mirroring the canonical hardening at crypto/generate.go:768.
	if len(groupPK.PubKey) != mode3.PublicKeySize {
		return fmt.Errorf("%w: public key wrong length (%d bytes, expected %d)", ErrSignatureVerificationFailed, len(groupPK.PubKey), mode3.PublicKeySize)
	}
	pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK.PubKey))

	// R38-P1-01 (2026-08-01) FIX: Reject all-zero public keys. A zero
	// public key unpacks successfully but mode3.Verify may accept a
	// zero signature, allowing an attacker to forge signatures when
	// the group public key has not been initialized (e.g., before DKG
	// completes or after a corrupt state reset). Use the canonical
	// constant-time helper from the crypto package — matches the R37
	// sibling-path hardening at crypto/verify.go:73.
	if crypto.IsZeroPublicKeyBytes(groupPK.PubKey) {
		return fmt.Errorf("%w: group public key is all zeros (DKG not initialized?)", ErrSignatureVerificationFailed)
	}

	return verifyWithPubKey(&pk, message, signature)
}

// VerifySignatureWithPublicKey verifies a signature against an explicitly
// provided public key, rather than the current group public key.
//
// R33 CONS-02 FIX (2026-07-28): Required for DKG rotation correctness. After
// a DKG rotation, the group public key changes. When verifying old blocks
// produced by the previous group, callers pass the historical public key.
// Without this, VerifyBlock would silently use the new group key and reject
// all historical QTD signatures, causing nodes to disagree on finality and
// split the chain. The adapter at node/adapters.go:VerifyBlock now calls
// this method when pubKey is non-empty.
func (m *TSSManager) VerifySignatureWithPublicKey(pubKey []byte, message []byte, signature []byte) error {
	if len(signature) == 0 {
		return ErrSignatureVerificationFailed
	}
	// R38-P1-01 FIX (2026-08-01): same `!=` + constant-time zero-key
	// hardening as VerifyCombinedSignature. This is the path used by
	// consensus QTDFinalityState (via node/adapters.go:VerifyBlock) to
	// verify seals under historical group keys loaded from the QTD
	// history table — so this is the live sibling-path verifier.
	if len(pubKey) != mode3.PublicKeySize {
		return fmt.Errorf("%w: provided public key wrong length (%d bytes, expected %d)", ErrSignatureVerificationFailed, len(pubKey), mode3.PublicKeySize)
	}
	var pk mode3.PublicKey
	pk.Unpack((*[mode3.PublicKeySize]byte)(pubKey[:mode3.PublicKeySize]))

	// R38-P1-01 (2026-08-01) FIX: Reject all-zero public keys. Use the
	// canonical constant-time helper from crypto.IsZeroPublicKeyBytes.
	if crypto.IsZeroPublicKeyBytes(pubKey[:mode3.PublicKeySize]) {
		return fmt.Errorf("%w: provided public key is all zeros", ErrSignatureVerificationFailed)
	}

	return verifyWithPubKey(&pk, message, signature)
}

// verifyWithPubKey is the shared inner verifier for VerifyCombinedSignature
// and VerifySignatureWithPublicKey. It accepts an already-unpacked public key
// so callers can pass either the current group key or a historical one.
func verifyWithPubKey(pk *mode3.PublicKey, message, signature []byte) error {
	var ok bool
	switch len(signature) {
	case 3293:
		ok = mode3.Verify(pk, message, signature)
	case crypto.GMQTDCombinedSignatureSize:
		// Security fix (Round 4): remove production debug logging.
		// Previously [TSS-DEBUG] logs here included hex fragments of messages, public keys, and signatures,
		// potentially leaking sensitive material into production logs. For debugging, build with the
		// "-tags debug" tag and re-enable logging in the debug build.
		ok = qtd.CheckGMQTDFullSignature(pk, message, signature)
	}

	if !ok {
		return fmt.Errorf("%w: signature verification failed (len=%d)", ErrSignatureVerificationFailed, len(signature))
	}

	return nil
}

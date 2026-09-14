// Quantaureum Node source, version 1.0.0.
// R131 — block-producer side session-key support.
//
// Loads an (optional) encrypted session signing key at startup and selects it
// for attestation signing whenever the on-chain session-key registry says the
// session is active for this validator's address at the attestation epoch.
package node

import (
	"bytes"
	"fmt"
	"os"

	"github.com/quantaureum/qau/crypto"
)

// loadSessionKeyIfConfigured reads the session key from the paths given by
// environment variables (container/systemd-friendly, no flags needed):
//
//	QAU_SESSION_KEY_FILE           — encrypted KeyFile v2 JSON (required to enable)
//	QAU_SESSION_KEY_PASSWORD_FILE  — file holding the password (agreed scheme)
//	QAU_SESSION_KEY_PASSWORD       — password env var (dev/test only fallback)
func (bp *BlockProducer) loadSessionKeyIfConfigured() {
	keyPath := os.Getenv("QAU_SESSION_KEY_FILE")
	if keyPath == "" {
		return
	}
	data, err := os.ReadFile(keyPath) // #nosec G304 -- operator-controlled path
	if err != nil {
		bpLog.Error("R131 session-key file unreadable (%s): %v — falling back to base identity key", keyPath, err)
		return
	}
	var password []byte
	if pwf := os.Getenv("QAU_SESSION_KEY_PASSWORD_FILE"); pwf != "" {
		if pw, err := os.ReadFile(pwf); err == nil { // #nosec G304
			password = bytes.TrimRight(pw, "\r\n")
		}
	}
	if len(password) == 0 {
		if pw := os.Getenv("QAU_SESSION_KEY_PASSWORD"); pw != "" {
			password = []byte(pw)
			defer func() { crypto.ZeroBytesSecure(password) }()
		}
	}
	if len(password) == 0 {
		bpLog.Error("R131 session-key password missing (QAU_SESSION_KEY_PASSWORD_FILE) — session key disabled")
		return
	}
	keyFile, err := crypto.KeyFileFromJSON(data)
	if err != nil {
		bpLog.Error("R131 session-key parse failed: %v", err)
		return
	}
	priv, err := crypto.DecryptKeyBytes(keyFile, password)
	if len(password) > 0 {
		crypto.ZeroBytesSecure(password)
	}
	if err != nil {
		bpLog.Error("R131 session-key decrypt failed (wrong password?): %v", err)
		return
	}
	bp.sessionKey = priv
	bp.sessionPub = priv.PublicKey().Bytes()
	bpLog.Info("R131 session key loaded (pubkey-prefix %x) — activates only after on-chain rotation takes effect", bp.sessionPub[:4])
}

// activeSigningKey returns the key that must sign the given attestation.
//
// Rules (fail-closed):
//   - If the validator identity is revoked → error (no signing at all).
//   - If a session key is active at att.Target.Epoch AND the local session key
//     matches the on-chain registered pubkey → session key.
//   - If a session key is active but the local copy is missing/mismatched →
//     error (better to skip the attestation than to sign garbage with the
//     stale base key, which would just be rejected by the network).
//   - Otherwise → base identity key (pre-rotation behavior).
func (bp *BlockProducer) activeSigningKey(attEpoch uint64) (*crypto.PrivateKey, error) {
	qpos := bp.qpos
	if qpos == nil {
		return bp.validatorKey, nil
	}
	if qpos.IsValidatorRevoked(bp.validatorAddr) {
		return nil, fmt.Errorf("validator identity %x is revoked on-chain — refusing to sign", bp.validatorAddr)
	}
	active, onChain := qpos.EffectiveSessionPubKey(bp.validatorAddr, attEpoch)
	if !onChain {
		return bp.validatorKey, nil
	}
	if bp.sessionKey == nil || !bytes.Equal(bp.sessionPub, active) {
		return nil, fmt.Errorf("session key must sign attestations from epoch %d, but local session key missing/mismatched (registered=%08x, local=%08x)",
			attEpoch, tracePK(active), tracePK(bp.sessionPub))
	}
	return bp.sessionKey, nil
}

func tracePK(b []byte) []byte {
	if len(b) > 4 {
		return b[:4]
	}
	return b
}

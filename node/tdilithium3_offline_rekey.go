// Quantaureum Node source, version 1.0.0.
package node

// Offline-ceremony re-key support for Dilithium3 v1 sealing.
//
// A re-key installs a new ceremony's shares as candidates and arms a later
// activation epoch while the replaced ceremony's share is still the active
// one. Two rules keep the replaced key out of use from that point on:
//
//   - On the offline path the only usable share is the one of the armed
//     ceremony: an active share whose activation epoch differs from the armed
//     epoch is superseded. It is never signed with, never anchored on a
//     boundary block, and never registered as the finality key, so the
//     replaced key goes quiet the moment the operator arms the new epoch
//     rather than when the new share activates.
//   - A verify-only node, which holds no share, learns the armed ceremony's
//     group key from its operator (tssV1TrustedGroupKey) and re-roots its
//     group-key custody to it. Boundary anchors of the new key then chain
//     onto it; anchors of any other key, the replaced one included, are
//     refused by the chained-adoption rule.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	qcrypto "github.com/quantaureum/qau/crypto"
)

// errTDilithium3ActiveShareSuperseded reports an active share that belongs to
// an earlier ceremony than the one the offline path is armed for.
var errTDilithium3ActiveShareSuperseded = errors.New("Dilithium3 v1 active share is superseded by the armed ceremony")

// offlineTDilithium3ShareSuperseded reports whether an active share with the
// given activation epoch must not be used: the offline path is armed for a
// different ceremony and the experimental runtime-DKG path (which rotates
// shares itself) is not the one in charge.
func (n *Node) offlineTDilithium3ShareSuperseded(shareActivationEpoch uint64) bool {
	if n == nil || n.config == nil || experimentalTDilithium3V1EnabledForNetwork(n.config.NetworkID) {
		return false
	}
	armed, ok := n.offlineTDilithium3SealingActivation()
	return ok && armed != shareActivationEpoch
}

// parseTDilithium3TrustedGroupKey decodes a configured trusted group key.
func parseTDilithium3TrustedGroupKey(encoded string) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(encoded), "0x"))
	if err != nil {
		return nil, fmt.Errorf("not hex: %w", err)
	}
	if len(key) != qcrypto.Dilithium3PublicKeySize {
		return nil, fmt.Errorf("%d bytes, want %d", len(key), qcrypto.Dilithium3PublicKeySize)
	}
	if qcrypto.IsDegeneratePublicKeyBytes(key) {
		return nil, fmt.Errorf("all-zero key")
	}
	return key, nil
}

// offlineTDilithium3TrustedGroupKey returns the operator-configured group key
// of the armed ceremony and its activation epoch, for a node that holds no
// share of that ceremony. A share holder (active or candidate at the armed
// epoch) uses its share's key instead and gets ok=false, with an error if the
// configured key is not its share's key (a wrong manifest or a wrong share);
// so does a node with no trusted key configured. The experimental runtime-DKG
// path rotates keys through handoff proofs and is never re-rooted.
func (n *Node) offlineTDilithium3TrustedGroupKey() (uint64, []byte, bool, error) {
	if n == nil || n.config == nil || n.config.TSSV1TrustedGroupKey == "" ||
		experimentalTDilithium3V1EnabledForNetwork(n.config.NetworkID) {
		return 0, nil, false, nil
	}
	activation, armed := n.offlineTDilithium3SealingActivation()
	if !armed {
		return 0, nil, false, fmt.Errorf("tssV1TrustedGroupKey requires tssV1SealingActivationEpoch")
	}
	key, err := parseTDilithium3TrustedGroupKey(n.config.TSSV1TrustedGroupKey)
	if err != nil {
		return 0, nil, false, fmt.Errorf("tssV1TrustedGroupKey: %w", err)
	}
	if n.config.DataDir != "" && n.config.ValidatorKeyPassword != "" {
		store := newThresholdShareStore(n.config.DataDir)
		password := []byte(n.config.ValidatorKeyPassword)
		if epoch, shareKey, _, err := store.ActiveSharePublicIdentity(password); err == nil && epoch == activation {
			return 0, nil, false, trustedGroupKeyMismatch(key, shareKey)
		}
		if epoch, shareKey, _, _, err := store.CandidateSharePublicIdentity(password); err == nil && epoch == activation {
			return 0, nil, false, trustedGroupKeyMismatch(key, shareKey)
		}
	}
	return activation, key, true, nil
}

// trustedGroupKeyMismatch reports a share holder whose configured trusted key
// differs from its own share's group key.
func trustedGroupKeyMismatch(configured, shareKey []byte) error {
	if bytes.Equal(configured, shareKey) {
		return nil
	}
	return fmt.Errorf("tssV1TrustedGroupKey %x… does not match the installed share's group key %x…", configured[:4], shareKey[:min(4, len(shareKey))])
}

// applyTDilithium3TrustedGroupKey re-roots a verify-only node's group-key
// custody to the operator-configured key of the armed ceremony. It runs at
// startup, before blocks are imported, and is a quiet no-op on share holders
// and on nodes without a configured key.
func (n *Node) applyTDilithium3TrustedGroupKey() {
	activation, key, ok, err := n.offlineTDilithium3TrustedGroupKey()
	if err != nil {
		nodeLog.Warn("Dilithium3 v1 trusted group key not applied: %v", err)
		return
	}
	if !ok || n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return
	}
	qfs := n.blockProducer.QPOS().GetQTDFinality()
	if qfs == nil {
		return
	}
	qfs.ReRootGroupKeyCustody(activation, key)
	nodeLog.Info("Dilithium3 v1 group-key custody re-rooted to the configured ceremony key (activation epoch %d, key prefix %x)",
		activation, key[:4])
}

// Quantaureum Node source, version 1.0.0.
package node

// The Dilithium3 v1 executor's surface on consensus.ThresholdKeySigner (design
// note, Slice 4). The executor produces one ordinary 3293-byte mode3 signature
// from a four-signer session; the finality layer needs exactly three things
// from a signer: the t-of-n shape the seal quorum derives from, the group
// public key of the epoch, and verification of that signature. Everything a
// single signer could do alone is refused here: a session needs four
// participants, so SignBlock, SignVote, and AggregatePartialSignatures fail
// closed instead of pretending to be threshold operations.
//
// Registration binds the surface to one activation epoch through
// qfs.SetQTDSignerForEpoch, which records the group key under that epoch and
// makes the QTD finality engine verify with it. Only the finality engine is
// rebound: the QPOS-level signer (block and vote signing) is left untouched, so
// the experimental path changes nothing that the legacy path owns. Both entry
// points are gated and fail closed, and the startup refresh lets a restarted
// node pick up an already installed share.

import (
	"fmt"

	"github.com/quantaureum/qau/consensus"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// tdilithium3SigningFinalitySigner is the executor's ThresholdKeySigner. It
// holds the epoch's group public key and verifies ordinary mode3 signatures
// with it.
type tdilithium3SigningFinalitySigner struct {
	groupPublicKey []byte
	groupKey       *qcrypto.PublicKey
}

// newTDilithium3SigningFinalitySigner checks the group public key is a
// canonical non-degenerate Dilithium3 key before it becomes the verification
// key of an epoch.
func newTDilithium3SigningFinalitySigner(groupPublicKey []byte) (*tdilithium3SigningFinalitySigner, error) {
	if len(groupPublicKey) != qcrypto.Dilithium3PublicKeySize || qcrypto.IsZeroPublicKeyBytes(groupPublicKey) {
		return nil, fmt.Errorf(
			"Dilithium3 v1 finality signer requires a non-zero %d-byte group public key",
			qcrypto.Dilithium3PublicKeySize,
		)
	}
	key, err := qcrypto.PublicKeyFromBytes(groupPublicKey)
	if err != nil {
		return nil, fmt.Errorf("Dilithium3 v1 finality signer group public key: %w", err)
	}
	return &tdilithium3SigningFinalitySigner{
		groupPublicKey: append([]byte(nil), groupPublicKey...),
		groupKey:       key,
	}, nil
}

// IsThresholdMode reports the executor's shape: a four-of-six session is a
// threshold operation, so the finality engine may derive its seal quorum from
// Threshold.
func (signer *tdilithium3SigningFinalitySigner) IsThresholdMode() bool {
	return signer != nil && len(signer.groupPublicKey) > 0
}

// Threshold returns the t of the v1 profile's t-of-n shape.
func (signer *tdilithium3SigningFinalitySigner) Threshold() int {
	return int(protocol.ThresholdV1Threshold)
}

// GroupPublicKey returns the epoch's group public key, copied so no caller can
// mutate the verification key.
func (signer *tdilithium3SigningFinalitySigner) GroupPublicKey() []byte {
	if signer == nil {
		return nil
	}
	return append([]byte(nil), signer.groupPublicKey...)
}

// VerifyBlock verifies one seal signature with the caller's key when it names
// one, and with this signer's epoch key otherwise, exactly like the legacy
// adapter's contract. The executor's signature is an ordinary mode3 signature,
// so this is plain Dilithium3 verification.
func (signer *tdilithium3SigningFinalitySigner) VerifyBlock(pubKey []byte, message []byte, signature []byte) bool {
	if signer == nil || len(message) == 0 || len(signature) == 0 {
		return false
	}
	key := signer.groupKey
	if len(pubKey) > 0 {
		parsed, err := qcrypto.PublicKeyFromBytes(pubKey)
		if err != nil || parsed == nil {
			return false
		}
		key = parsed
	}
	if key == nil {
		return false
	}
	return qcrypto.Verify(key, message, signature)
}

// VerifyVote mirrors VerifyBlock: votes and seals share one verification.
func (signer *tdilithium3SigningFinalitySigner) VerifyVote(pubKey []byte, message []byte, signature []byte) bool {
	return signer.VerifyBlock(pubKey, message, signature)
}

// SignBlock is refused: a single call cannot run a four-signer session, and
// pretending otherwise would hand one node the group signature.
func (signer *tdilithium3SigningFinalitySigner) SignBlock(validatorIndex int, message []byte) ([]byte, error) {
	return nil, fmt.Errorf("Dilithium3 v1 signing executor offers no single-signer block signing")
}

// SignVote is refused for the same reason as SignBlock.
func (signer *tdilithium3SigningFinalitySigner) SignVote(validatorIndex int, message []byte) ([]byte, error) {
	return nil, fmt.Errorf("Dilithium3 v1 signing executor offers no single-signer vote signing")
}

// AggregatePartialSignatures is refused: the executor's only aggregation is the
// interactive session itself, and accepting standalone partial signatures here
// would let a caller assemble a signature the four signers never agreed to.
func (signer *tdilithium3SigningFinalitySigner) AggregatePartialSignatures(
	sealers []int, partialSigs map[int][]byte, message []byte,
) ([]byte, error) {
	return nil, fmt.Errorf("Dilithium3 v1 signing executor aggregates only inside its four-signer session")
}

// registerTDilithium3SigningFinalitySigner binds the executor's finality
// surface to one activation epoch. Callers are the activation wiring and the
// development-network integration; every precondition is checked here because a
// half-registered surface would verify seals with no key or the wrong one.
func (n *Node) registerTDilithium3SigningFinalitySigner(activationEpoch uint64, groupPublicKey []byte) error {
	if !tdilithium3SealExecutorEnabled(n) {
		return fmt.Errorf("Dilithium3 v1 finality signer requires the open experimental gate off the mainnet")
	}
	if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return fmt.Errorf("Dilithium3 v1 finality signer requires the consensus engine")
	}
	if activationEpoch == 0 {
		return fmt.Errorf("Dilithium3 v1 finality signer requires a non-zero activation epoch")
	}
	qfs := n.blockProducer.QPOS().GetQTDFinality()
	if qfs == nil {
		return fmt.Errorf("Dilithium3 v1 finality signer requires the QTD finality engine")
	}
	signer, err := newTDilithium3SigningFinalitySigner(groupPublicKey)
	if err != nil {
		return err
	}
	qfs.SetQTDSignerForEpoch(signer, activationEpoch)
	return nil
}

// refreshTDilithium3SigningFinalitySigner binds the surface to the installed
// active share when the gate is open, so a node restarted with an existing
// share seals without extra wiring. A missing share is the normal first-run
// case and stays quiet; anything else is logged.
func (n *Node) refreshTDilithium3SigningFinalitySigner() {
	if !tdilithium3SealExecutorEnabled(n) || n.config.DataDir == "" || n.config.ValidatorKeyPassword == "" {
		return
	}
	store := newThresholdShareStore(n.config.DataDir)
	activationEpoch, groupPublicKey, err := store.ActiveSharePublicIdentity([]byte(n.config.ValidatorKeyPassword))
	if err != nil {
		nodeLog.Debug("Dilithium3 v1 finality signer not refreshed (no loadable active share): %v", err)
		return
	}
	if err := n.registerTDilithium3SigningFinalitySigner(activationEpoch, groupPublicKey); err != nil {
		nodeLog.Warn("Dilithium3 v1 finality signer refresh failed: %v", err)
		return
	}
	nodeLog.Info("Dilithium3 v1 signing executor finality surface registered (activation epoch %d)", activationEpoch)
}

// ensure the adapter satisfies the consensus threshold-signer contract.
var _ consensus.ThresholdKeySigner = (*tdilithium3SigningFinalitySigner)(nil)

// Quantaureum Node source, version 1.0.0.
// Package p2p signature_verifier.go implements message-level Dilithium3
// signature verification for application-layer P2P messages.
//
// P2P-R11-CRIT-001 / P2P-R11-CRIT-002 (2026-07-20) FIX:
// The GossipSub and direct-P2P message paths previously only validated
// message size, format, and replay — never the cryptographic signature
// on the payload. mTLS authenticates the connection, but a compromised
// peer (or man-in-the-middle after mTLS termination) could inject forged
// block/vote/transaction payloads that propagate through the network
// wasting bandwidth and potentially causing consensus divergence
// before application-layer validation rejects them.
//
// This file adds:
//   - PayloadSignatureVerifier: pluggable verifier interface
//   - Dilithium3PayloadVerifier: concrete verifier that:
//   - Fully verifies KindTransaction (tx carries its own PublicKey)
//   - Delegates KindBlock / KindVote verification to caller-provided
//     callbacks (the signing-hash / signing-message computation lives
//     in core/consensus packages and is duplicated here only via the
//     callback contract, avoiding drift)
//
// The verifier is OPTIONAL. When unset, behavior is unchanged (backward
// compatible). When set, ValidateMessage / GossipSub.deliverMessage
// invoke it for sensitive message types and drop messages whose
// signature does not verify.
package p2p

import (
	"errors"
	"fmt"

	"github.com/quantaureum/qau/encoding"
)

// MessageKind classifies a P2P payload for signature verification.
// Derived from p2p.MsgType* (direct path) or gossipsub.Topic* (gossip path).
type MessageKind uint8

const (
	KindUnknown MessageKind = iota
	KindBlock
	KindVote
	KindTransaction
	// KindCRL covers CRL snapshot messages propagated via GossipSub.
	// R14-MED (2026-07-21): previously TopicCRL fell through to KindOther,
	// which skipped payload signature verification entirely. A compromised
	// authenticated peer (mTLS connection) could inject forged CRL entries
	// that merged monotonically into the local CRL via MergeCRLSnapshot,
	// causing legitimate certificates to be wrongly rejected. KindCRL
	// routes through CRLVerifyFunc when configured; when nil, falls back
	// to KindOther behavior (fail-open for backward compat).
	KindCRL
	// KindOther covers message types that do not carry an application-level
	// Dilithium3 signature (e.g. handshake, status, ping/pong, findnode).
	// The verifier skips these.
	KindOther
)

// PayloadSignatureVerifier verifies the cryptographic signature embedded
// in a P2P payload before the message is propagated to handlers or mesh peers.
//
// Returns nil if the payload's signature is valid (or if the kind does not
// require signature verification). Returns a non-nil error if the signature
// is missing, malformed, or fails verification — the caller MUST drop the
// message and penalize the source peer.
//
// Implementations MUST be safe for concurrent use.
type PayloadSignatureVerifier interface {
	VerifyPayload(kind MessageKind, payload []byte) error
}

// BlockSignatureVerifyFunc is a caller-provided callback that verifies a
// marshaled block payload's proposer signature. The node layer implements
// this using core.BlockValidator.ValidateSignature (which computes the
// header signing hash and looks up the proposer's public key).
//
// Returns nil if the signature is valid, an error otherwise.
type BlockSignatureVerifyFunc func(payload []byte) error

// VoteSignatureVerifyFunc is a caller-provided callback that verifies a
// marshaled vote/attestation payload's validator signature. The node layer
// implements this using consensus.QPOS.verifyAttestationSignature (which
// computes the attestation signing message and looks up the validator's
// public key by index).
//
// Returns nil if the signature is valid, an error otherwise.
type VoteSignatureVerifyFunc func(payload []byte) error

// CRLSignatureVerifyFunc is a caller-provided callback that verifies a
// marshaled CRL snapshot payload's authorized-publisher signature.
// R14-MED (2026-07-21): without this, a compromised authenticated peer
// (one with a valid mTLS certificate) could inject forged CRL entries
// that merge monotonically into the local CRL via MergeCRLSnapshot,
// causing legitimate certificates to be wrongly rejected across the
// network. The verifier should validate that the snapshot was signed
// by an authorized CRL publisher (e.g., a designated validator or the
// network's CA).
//
// Returns nil if the signature is valid, an error otherwise.
type CRLSignatureVerifyFunc func(payload []byte) error

// Dilithium3PayloadVerifier is the default PayloadSignatureVerifier.
// It verifies:
//   - KindTransaction: decodes encoding.Transaction and verifies the
//     signature using tx.SigningHash() + tx.PublicKey + crypto.Verify.
//     Transactions carry their own PublicKey, so no lookup is needed.
//   - KindBlock: delegates to BlockVerifyFunc (caller-provided).
//     If BlockVerifyFunc is nil, block verification is SKIPPED (the
//     operator must wire up a callback or block messages will pass
//     through unverified — fail-open by design for backward compat).
//   - KindVote: delegates to VoteVerifyFunc (caller-provided).
//     Same fail-open semantics as KindBlock.
//   - KindCRL: delegates to CRLVerifyFunc (caller-provided).
//     R14-MED (2026-07-21): if CRLVerifyFunc is nil, CRL verification
//     is SKIPPED (fail-open for backward compat). Operators SHOULD
//     wire up a callback that validates the CRL publisher's signature
//     to prevent forged CRL injection by compromised authenticated peers.
//   - KindOther / KindUnknown: skipped (no signature required).
//
// Fail-open for block/vote/CRL when no callback is set is intentional: it
// preserves backward compatibility for deployments that haven't yet
// wired up the callbacks. To fail-closed, install a callback that
// returns an error when the validator lookup is unavailable.
type Dilithium3PayloadVerifier struct {
	// BlockVerify verifies a marshaled block payload.
	// May be nil — block messages will be accepted unverified.
	BlockVerify BlockSignatureVerifyFunc

	// VoteVerify verifies a marshaled vote/attestation payload.
	// May be nil — vote messages will be accepted unverified.
	VoteVerify VoteSignatureVerifyFunc

	// CRLVerify verifies a marshaled CRL snapshot payload.
	// R14-MED (2026-07-21): May be nil — CRL messages will be accepted
	// unverified (backward compat). Operators SHOULD wire up a callback
	// that validates the CRL publisher's signature.
	CRLVerify CRLSignatureVerifyFunc
}

// NewDilithium3PayloadVerifier creates a verifier with the given callbacks.
// Any callback may be nil, in which case the corresponding message kind
// is accepted unverified (backward compatible).
func NewDilithium3PayloadVerifier(blockVerify BlockSignatureVerifyFunc, voteVerify VoteSignatureVerifyFunc) *Dilithium3PayloadVerifier {
	return &Dilithium3PayloadVerifier{
		BlockVerify: blockVerify,
		VoteVerify:  voteVerify,
	}
}

// ErrSignatureMissing is returned when a payload that should carry a
// Dilithium3 signature has none.
var ErrSignatureMissing = errors.New("payload signature missing")

// ErrSignatureInvalid is returned when the payload's signature fails
// cryptographic verification.
var ErrSignatureInvalid = errors.New("payload signature invalid")

// VerifyPayload implements PayloadSignatureVerifier.
//
// R45-P2P-01 (2026-08-05) FIX: previously the empty-payload check ran
// BEFORE the kind switch, so KindOther messages that legitimately carry
// an empty payload (e.g. MsgTypePing / MsgTypePong) were rejected with
// ErrSignatureMissing. Ping/Pong failures accumulated on every peer and
// caused P2P mesh degradation + chain divergence. The empty-payload
// guard is now applied only to kinds that actually require a signature.
func (v *Dilithium3PayloadVerifier) VerifyPayload(kind MessageKind, payload []byte) error {
	if v == nil {
		return nil
	}

	switch kind {
	case KindTransaction:
		if len(payload) == 0 {
			return ErrSignatureMissing
		}
		return v.verifyTransaction(payload)
	case KindBlock:
		if len(payload) == 0 {
			return ErrSignatureMissing
		}
		if v.BlockVerify == nil {
			// Fail-open: no callback configured. Operator must wire up
			// block verification to actually enforce signatures.
			return nil
		}
		return v.BlockVerify(payload)
	case KindVote:
		if len(payload) == 0 {
			return ErrSignatureMissing
		}
		if v.VoteVerify == nil {
			// Fail-open: no callback configured.
			return nil
		}
		return v.VoteVerify(payload)
	case KindCRL:
		// R14-MED (2026-07-21): CRL snapshot signature verification.
		// Fail-open when no callback is configured (backward compat);
		// operators SHOULD wire up a callback to prevent forged CRL
		// injection by compromised authenticated peers.
		if len(payload) == 0 {
			return ErrSignatureMissing
		}
		if v.CRLVerify == nil {
			return nil
		}
		return v.CRLVerify(payload)
	case KindOther, KindUnknown:
		// No signature required for these message kinds. Ping/Pong and
		// other control messages may carry an empty payload.
		return nil
	default:
		return nil
	}
}

// verifyTransaction decodes an encoding.Transaction and verifies its
// Dilithium3 signature through the canonical
// encoding.VerifyTransactionAuthorization helper.
//
// R43-P2PSIG-01 (2026-08-03): previously this method OPEN-CODED the
// verification (PublicKeyFromBytes + SigningHash + crypto.Verify) — a
// hand-rolled duplicate of the encoding package's canonical path. That
// duplicate DRIFTED from canonical: it did NOT verify that the public key
// derives tx.From (the R38-P0-02 "signature scope detach" fix), it did
// NOT enforce the canonical stake/unstake recipient binding, and it did
// NOT dispatch on TxType — meaning a TxTypeStake tx with a tampered
// tx.To would pass the P2P-level check while being rejected (or, in
// some legacy paths, silently accepted) at the block boundary.
//
// Routing to the canonical helper means every future extension to
// VerifyTransactionAuthorization (e.g. R43-TYPEDISP-01's
// DynamicFee/Blob/MultiSig dispatch + R43-ERR-CHAINID-01's chain-ID
// sentinel) is automatically enforced at the P2P layer too. We map
// the canonical error sentinels to p2p.ErrSignatureInvalid /
// p2p.ErrSignatureMissing so the caller-supplied metrics/logs that
// classify on these p2p-level sentinels keep working.
func (v *Dilithium3PayloadVerifier) verifyTransaction(payload []byte) error {
	tx, err := encoding.UnmarshalTransaction(payload)
	if err != nil {
		return fmt.Errorf("%w: failed to decode transaction: %v", ErrSignatureInvalid, err)
	}
	if tx == nil {
		return ErrSignatureMissing
	}
	if err := encoding.VerifyTransactionAuthorization(tx); err != nil {
		// Map canonical → p2p sentinels. ErrAuthNoPublicKey and
		// ErrAuthNoSignature map to ErrSignatureMissing; everything
		// else (incl. signature verify failure, addr binding
		// mismatch, dispatch error) maps to ErrSignatureInvalid. The
		// wrapped canonical error is preserved for log introspection.
		switch err {
		case encoding.ErrAuthNoPublicKey, encoding.ErrAuthNoSignature:
			return fmt.Errorf("%w: %v", ErrSignatureMissing, err)
		default:
			return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
		}
	}
	// R43-P2PSIG-01: canonical VerifyTransactionAuthorization returns
	// ErrAuthMultiSigUnsupported for TxTypeMultiSig because the encoding
	// package cannot import the on-chain signer roster (cycle). The P2P
	// layer, similarly, has no roster; the consensus block validator
	// owns the roster lookup and verifies MultiSig at block-admit time.
	// Forward ErrAuthMultiSigUnsupported as ErrSignatureInvalid so the
	// peer is penalized; the block validator path will re-check.
	// (Already covered by the default branch above.)
	return nil
}

// KindFromMessageType maps a p2p.MsgType* constant to a MessageKind.
// Returns KindOther for message types that do not carry Dilithium3 signatures.
func KindFromMessageType(msgType uint8) MessageKind {
	switch msgType {
	case MsgTypeBlock:
		return KindBlock
	case MsgTypeVote:
		return KindVote
	case MsgTypeTransaction:
		return KindTransaction
	default:
		return KindOther
	}
}

// GossipSub topic name constants. These MUST match the corresponding
// constants in p2p/gossipsub/gossipsub.go (TopicBlocks, TopicTransactions,
// TopicVotes, TopicAttestations). They are duplicated here to avoid a
// circular import (p2p/gossipsub cannot import p2p).
const (
	gossipTopicBlocks       = "qau_blocks_v1"
	gossipTopicTransactions = "qau_txs_v1"
	gossipTopicVotes        = "qau_votes_v1"
	gossipTopicAttestations = "qau_attestations_v1"
	// R14-MED (2026-07-21): CRL topic for KindCRL routing. Matches
	// gossipsub.TopicCRL ("qau_crl_v1"); duplicated here to avoid an
	// import cycle (p2p/gossipsub already imports p2p for the verifier
	// interface, so p2p cannot import gossipsub for the constant).
	gossipTopicCRL = "qau_crl_v1"
)

// KindFromTopic maps a GossipSub topic name to a MessageKind.
// Returns KindOther for topics that do not carry Dilithium3-signed
// application payloads (e.g. shard blocks have their own signature
// path inside the consensus layer and are not verified here).
//
// R14-MED (2026-07-21): TopicCRL is now mapped to KindCRL so it can
// be routed through CRLVerifyFunc when configured. Previously it fell
// through to KindOther, skipping payload signature verification.
func KindFromTopic(topic string) MessageKind {
	switch topic {
	case gossipTopicBlocks:
		return KindBlock
	case gossipTopicVotes, gossipTopicAttestations:
		return KindVote
	case gossipTopicTransactions:
		return KindTransaction
	case gossipTopicCRL:
		return KindCRL
	default:
		return KindOther
	}
}

// TopicPayloadVerifierAdapter wraps a Dilithium3PayloadVerifier so it can
// be used where a topic-based verifier is expected (e.g. the
// gossipsub.PayloadSignatureVerifier interface, which takes a topic
// string instead of a MessageKind).
//
// This adapter is necessary because Dilithium3PayloadVerifier.VerifyPayload
// has signature (MessageKind, []byte) error, while the gossipsub interface
// expects (string, []byte) error — same name, different signature, so the
// verifier cannot directly satisfy both.
type TopicPayloadVerifierAdapter struct {
	V *Dilithium3PayloadVerifier
}

// VerifyPayload adapts the topic-based interface to the kind-based one.
// Returns nil if the adapter or its underlying verifier is nil (fail-open).
func (a *TopicPayloadVerifierAdapter) VerifyPayload(topic string, payload []byte) error {
	if a == nil || a.V == nil {
		return nil
	}
	return a.V.VerifyPayload(KindFromTopic(topic), payload)
}

// NewTopicPayloadVerifierAdapter creates an adapter wrapping v that
// satisfies the topic-based verifier interface.
func NewTopicPayloadVerifierAdapter(v *Dilithium3PayloadVerifier) *TopicPayloadVerifierAdapter {
	return &TopicPayloadVerifierAdapter{V: v}
}

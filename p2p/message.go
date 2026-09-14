// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// MaxMessageSize is the unified maximum message size across all P2P protocols.
// SECURITY (audit P2-R2-08): Previously, different layers used different limits
// (10MB/16MB/1MB). This unified constant prevents bypass via layer mismatch.
// P2P-R19-H06 (2026-07-24) FIX: This is the absolute upper bound (10MB) that
// accommodates full block messages (1428 Dilithium3 txs ≈ 7.3MB). For
// non-block messages, DefaultMaxMessageSize (1MB) provides tighter DoS
// protection via the per-type message validator. The transport layer
// (encrypted_transport.go) and message validator now default to 1MB for
// non-block traffic, closing the 10MB DoS vector on control messages.
const MaxMessageSize = 10 * 1024 * 1024 // 10MB

// Topic names for message broadcasting
const (
	TopicBlocks       = "/qau/blocks/1.0.0"
	TopicTransactions = "/qau/txs/1.0.0"
	TopicVotes        = "/qau/votes/1.0.0"
)

// Message types
// Protocol-based message type ranges:
//
//	0:       Protocol negotiation request (MsgTypeProtocolNegotiate)
//	1-9:     Base protocol (qau): Block, Transaction, Vote, BlockReq, BlockResp, TxReq, TxResp, Status, Ping
//	10-19:   Base protocol (qau) continued: Pong, Challenge, ChallengeResponse, Batch, PoW
//	15-19:   Discovery protocol (qau_discovery): FindNode, Neighbors, QNR
//	20-29:   Consensus protocol (qau_consensus): Attestation, AggregateAttest, *Slashing, Checkpoint*, QTD*, Commit
//	30-39:   Expert protocol (qau_expert): Expert
//	40-49:   Snap sync protocol (qau_snap): SnapStateReq, SnapStateResp, SnapRangeReq, SnapRangeResp,
//	         SnapStorageReq/Resp, SnapBytecodeReq/Resp, HeaderReq/HeaderResp (Ethereum-parity sync)
//	50-59:   DAS protocol (qau_das): DASSampleReq, DASSampleResp, DASAttestation, DASAggregateAttest
//	60-69:   Protocol negotiation response + sync extensions (qau_proto): ReceiptReq/ReceiptResp
//	70-79:   TSS protocol (qau_tss): SessionInit, Round1, Round2, Signature, DKG
//	80-89:   Shard protocol (qau_shard): ShardBlock, ShardBlockReq/Resp, ShardAttestation, CrossShardMsg/Receipt
//
// R4-H4 FIX (2026-07-06): MsgTypeProtocolNegotiateResp moved from 61 to 60.
// Previously at 61 (was 50, conflicted with DASSampleReq), which was in an
// undocumented gap. Now properly documented in the 60-69 range.
const (
	// Protocol negotiation
	MsgTypeProtocolNegotiate     uint8 = 0  // Protocol negotiation request
	MsgTypeProtocolNegotiateResp uint8 = 62 // Protocol negotiation response (R4-H4: moved from 61 to 62; 60=GossipSub, 61=old value, 62=properly documented)

	// ETHEREUM-PARITY SYNC (2026-08-13): receipts sync — Ethereum fetches
	// recent receipts during snap sync (for heal + bloom queries). Receipts
	// are requested by block hash and validated against the block header's
	// ReceiptRoot.
	MsgTypeReceiptReq  uint8 = 63
	MsgTypeReceiptResp uint8 = 64

	// Base protocol (qau) — 1-14 range
	MsgTypeBlock             uint8 = 1
	MsgTypeTransaction       uint8 = 2
	MsgTypeVote              uint8 = 3
	MsgTypeBlockReq          uint8 = 4
	MsgTypeBlockResp         uint8 = 5
	MsgTypeTxReq             uint8 = 6
	MsgTypeTxResp            uint8 = 7
	MsgTypeStatus            uint8 = 8
	MsgTypePing              uint8 = 9
	MsgTypePong              uint8 = 10
	MsgTypeChallenge         uint8 = 11
	MsgTypeChallengeResponse uint8 = 12
	MsgTypeBatch             uint8 = 13
	MsgTypeProofOfWork       uint8 = 14

	// Discovery protocol (qau_discovery) — 15-19 range
	MsgTypeFindNode  uint8 = 15
	MsgTypeNeighbors uint8 = 16
	MsgTypeQNR       uint8 = 17

	// Consensus protocol (qau_consensus) — 20-29 range
	MsgTypeAttestation      uint8 = 20
	MsgTypeAggregateAttest  uint8 = 21
	MsgTypeProposerSlashing uint8 = 22
	MsgTypeAttesterSlashing uint8 = 23
	MsgTypeCheckpointSig    uint8 = 24 // Checkpoint signature broadcast
	MsgTypeCheckpointReq    uint8 = 25 // Checkpoint request/response
	// P1-4: QTD partial seal messages for three chambers finality.
	MsgTypeQTDSealRequest uint8 = 26 // Executive chamber requests partial seals
	MsgTypeQTDPartialSeal uint8 = 27 // Executive member submits partial seal
	// HIGH-01 (R18, 2026-07-23): QTD seal announcement. Broadcast by the
	// proposer after a QTD seal is completed, so syncing nodes can attach
	// the seal to their copy of the block (which they received bare).
	MsgTypeQTDSealAnnouncement uint8 = 28 // Completed QTD seal (slot + hash + signature)
	// R45 (2026-08-12): Commit-reveal front-running protection gossip.
	// When a client submits qau_submitCommitment to one node, the node
	// broadcasts the Commitment (CommitHash + TxHash + Sender + CreatedAt
	// + BlockHeight) to all peers via this message type. Each receiving
	// validator stores it into its own CommitRevealManager.commitsBySender
	// map so that the subsequent AddTransaction with matching tx.Hash()
	// passes HasValidPendingCommit locally and gets included in a block.
	// Replaces the prior SSH-based commit broadcast in cmd/transfer_commit
	// (an ops-only tool unusable by browser wallets).
	MsgTypeCommit uint8 = 29 // Commit-reveal commitment propagated via P2P

	// Expert protocol (qau_expert) — 30-39 range
	MsgTypeExpert uint8 = 30

	// Snap sync protocol (qau_snap) — 40-49 range
	MsgTypeSnapStateReq  uint8 = 40
	MsgTypeSnapStateResp uint8 = 41
	MsgTypeSnapRangeReq  uint8 = 42
	MsgTypeSnapRangeResp uint8 = 43

	// ETHEREUM-PARITY SYNC (2026-08-13): completes the qau_snap protocol to
	// feature parity with Ethereum's snap/1 protocol. Storage and bytecode
	// encoders existed in p2p/snap_sync.go but had no wire type assigned.
	MsgTypeSnapStorageReq   uint8 = 44 // per-account storage slot range
	MsgTypeSnapStorageResp  uint8 = 45
	MsgTypeSnapBytecodeReq  uint8 = 46 // bytecode by code hash
	MsgTypeSnapBytecodeResp uint8 = 47

	// Header-first (skeleton) sync — Ethereum's GetBlockHeaders equivalent.
	// Supports hash origin, skip and reverse so headers can be fetched
	// independently of bodies.
	MsgTypeHeaderReq  uint8 = 48
	MsgTypeHeaderResp uint8 = 49

	// DAS protocol (qau_das) — 50-59 range
	MsgTypeDASSampleReq       uint8 = 50
	MsgTypeDASSampleResp      uint8 = 51
	MsgTypeDASAttestation     uint8 = 52
	MsgTypeDASAggregateAttest uint8 = 53

	// Compact propagation protocol (qau_compact) — 54-59 range
	// TPS OPTIMIZATION: Reduces P2P bandwidth by 99% for txs and 90% for blocks.
	// Instead of broadcasting full 5.5KB Dilithium3 transactions, only 32-byte
	// hashes are broadcast. Peers request full txs only for hashes they don't have.
	MsgTypeTxHashAnnounce uint8 = 54 // Broadcast tx hashes (compact)
	MsgTypeTxHashRequest  uint8 = 55 // Request full txs for given hashes
	MsgTypeTxHashResponse uint8 = 56 // Return full txs for requested hashes
	MsgTypeCompactBlock   uint8 = 57 // Compact block: header + tx hashes

	// TSS (Threshold Signature Scheme) protocol (qau_tss) — 70-79 range
	// Distributed threshold signing messages for QTD (Quantum Threshold Distance).
	// These messages coordinate multi-party Dilithium3 threshold signing across
	// validator nodes. See wallet/tss/qtd/ for the cryptographic protocol.
	MsgTypeTSSSessionInit   uint8 = 70 // Aggregator initiates a signing session (broadcast)
	MsgTypeTSSRound1Commit  uint8 = 71 // Round 1 commitment: 52 bytes per participant (broadcast)
	MsgTypeTSSRound2Reveal  uint8 = 72 // Round 2 public reveal: ~8.5KB per participant (P2P to aggregator)
	MsgTypeTSSRound2Private uint8 = 73 // Round 2 private share: ~3.8KB, ENCRYPTED P2P only (ScShare = private key material)
	MsgTypeTSSSignature     uint8 = 74 // Final aggregated signature: 3293 bytes (broadcast)
	MsgTypeTSSDKGShare      uint8 = 75 // DKG key share exchange for distributed key generation
	MsgTypeTSSKeyExchange   uint8 = 76 // Kyber768 public key exchange for encrypted TSS channels
	// Task 5 (node-layer distributed DKG): multi-party DKG round messages.
	// 77 = Round1 commitment (public, broadcast-safe); 78 = Round1 open /
	// share delivery (point-to-point — carries a Shamir share of s1/s2/t0).
	// Payloads are JSON-encoded qtd.Round1CommitmentMessage /
	// qtd.Round1OpenMessage.
	MsgTypeTSSDKGCommitment uint8 = 77 // Distributed DKG Round1 commitment (broadcast)
	MsgTypeTSSDKGAck        uint8 = 78 // Distributed DKG Round1 open / share delivery (P2P)

	// Shard protocol (qau_shard) — 80-89 range
	// P1-1 (2026-07-14): P2P message channel for shard block propagation,
	// cross-shard message relay, and shard finalization attestations.
	// Without this, shard blocks and cross-shard messages only exist in a
	// single node's memory — the shard subsystem cannot work multi-node.
	MsgTypeShardBlock        uint8 = 80 // Shard block broadcast (proposer → validators)
	MsgTypeShardBlockReq     uint8 = 81 // Shard block request (sync: request by height)
	MsgTypeShardBlockResp    uint8 = 82 // Shard block response (sync: return requested block)
	MsgTypeShardAttestation  uint8 = 83 // Shard block finalization attestation (validator → proposer)
	MsgTypeCrossShardMsg     uint8 = 84 // Cross-shard message propagation (source → dest shard nodes)
	MsgTypeCrossShardReceipt uint8 = 85 // Cross-shard receipt propagation (relay confirmation)
)

// Message flags
const (
	MsgFlagCompressed = 0x80 // Message is compressed
)

// Message header size and limits
const (
	MsgHeaderSize         = 9                // 1 byte flags+type + 4 bytes length + 4 bytes checksum
	MaxMsgSize            = 10 * 1024 * 1024 // 10 MB max message size
	MaxBatchMessages      = 1000             // Maximum sub-messages in a batch
	MaxBlockRequestHashes = 256              // Maximum hashes in a block request

	// ETHEREUM-PARITY SYNC limits (2026-08-13)
	MaxHeaderRequestCount  = 1024 // Maximum headers per HeaderReq (eth caps at 1024)
	MaxReceiptRequestCount = 128  // Maximum block hashes per ReceiptReq
)

// Errors
var (
	ErrInvalidMsgType   = errors.New("invalid message type")
	ErrMsgTooLarge      = errors.New("message too large")
	ErrInvalidChecksum  = errors.New("invalid checksum")
	ErrMalformedMessage = errors.New("malformed message")
)

// Message represents a P2P message
type Message struct {
	Type      uint8
	Payload   []byte
	Timestamp time.Time
	From      PeerID
	// FIX: RequestID for end-to-end request tracing across P2P and RPC layers.
	// Enables correlation of request/response pairs and debugging of message flows.
	RequestID uint64
}

// PeerInfo contains information about a peer
type PeerInfo struct {
	ID        PeerID
	Addr      string
	Latency   time.Duration
	Connected bool
	Direction Direction
	Version   string
}

// StatusMessage contains node status information.
//
// Protocol V2 status requirements:
//
//   - The signed domain includes protocol version, chain/network ID, genesis
//     hash, best height/hash, validator address, validator public key hash,
//     sender peer-ID hash, timestamp, and a random session nonce.
//   - Public key length is exact and nonzero; its derived address must equal
//     ValidatorAddress.
//   - Timestamp must be within the configured freshness window and the
//     (validator, peer, sessionNonce) tuple must not replay.
//   - Protocol V1 optional-address/optional-signature status frames are
//     rejected on the Protocol V2 network.
//
// Required verifier boundary:
//
//	type ActiveValidatorIdentityVerifier interface {
//	    VerifyActiveValidator(address types.Address, publicKey []byte) error
//	}
//
//	func (h *Host) SetActiveValidatorIdentityVerifier(v ActiveValidatorIdentityVerifier)
type StatusMessage struct {
	Version          uint32
	NetworkID        uint64
	BestHeight       uint64
	BestHash         [32]byte
	GenesisHash      [32]byte
	ValidatorAddress [20]byte // TSS: validator's Dilithium3 address for Address→PeerID mapping

	// R37-FIX P2-P2P-01 (2026-07-30): Dilithium3 public key + signature so
	// that RegisterValidatorPeer can cryptographically verify the peer
	// actually holds the validator private key before trusting the mapping.
	// Without this, any peer can claim an arbitrary validator address,
	// hijacking TSS message routing. Both fields are optional for backward
	// wire compatibility; when present they MUST be verified.
	ValidatorPublicKey []byte // Dilithium3 public key (1952 bytes)
	ValidatorSignature []byte // Dilithium3 signature (3293 bytes) over the 104-byte base payload

	// R38-P2-01 DEEP FIX (Protocol V2, 2026-08-02): freshness + anti-replay
	// fields, both OPTIONAL and ZERO on legacy R37 nodes. When Timestamp > 0
	// the receiver MUST apply a clock-skew window check against its local
	// wall clock. When SessionNonce != [16]byte{} the receiver MUST register
	// (ValidatorAddress, SenderPeerID, SessionNonce) in a node-local replay
	// tracker and reject the status if the tuple has been seen before.
	//
	// Both fields are part of the PROTOCOL V2 SIGNED DOMAIN: when both are
	// nonzero the Verifier / ValidatorSignature is computed over
	// base[:128] (the legacy 104 bytes + Timestamp[8] + SessionNonce[16]).
	// Legacy R37 signers only sign base[:104] so the receiver falls back
	// to the legacy 104-byte range when the timestamp is zero, preserving
	// backward wire compatibility (see EncodeStatusMessage /
	// DecodeStatusMessage + host.go's VerifyStatusSignature path).
	Timestamp    uint64   // Unix seconds (wall clock); 0 = legacy R37 (no skew check)
	SessionNonce [16]byte // Random per-session nonce; all-zero = legacy R37 (no replay check)

	// ETHEREUM-PARITY SYNC (2026-08-13): fork id — Ethereum's eth/66 forkid
	// equivalent. Digest over (genesis hash, network id, fork epoch markers)
	// that lets a receiver reject peers on an incompatible fork BEFORE
	// accepting their advertised height. OPTIONAL: all-zero on legacy nodes,
	// in which case the receiver skips the forkid check (wire compatible).
	// Carried in the V3 status extension block; NOT part of the signed
	// domain — it is an informational chain-compatibility marker and cannot
	// grant any privilege by itself (height acceptance is still gated by
	// NetworkID + GenesisHash + block-hash validation).
	ForkID [32]byte
}

// PeerMessage wraps a payload with the sender's PeerID.
// audit-fix R2-M4: used for block requests so the handler can reply to the requester.
type PeerMessage struct {
	From    PeerID
	Type    uint8 // Message type (e.g., MsgTypeTSSRound1Commit)
	Payload []byte
}

// BlockRequest requests blocks by height or hash
type BlockRequest struct {
	FromHeight uint64
	ToHeight   uint64
	Hashes     [][32]byte
}

// BlockResponse contains requested blocks
type BlockResponse struct {
	Blocks [][]byte // Serialized blocks
}

// ETHEREUM-PARITY SYNC (2026-08-13): header-first (skeleton) sync messages.
// Modeled on Ethereum's GetBlockHeaders/BlockHeaders (eth/66): the request
// carries a request ID for response correlation plus an origin that can be
// either a block hash or a height, a count, a skip interval and a direction
// flag. Headers are fetched independently of bodies so a node can validate
// the chain skeleton (linkage + proposer signatures) before backfilling
// bodies via the existing BlockReq path.

// HeaderRequest requests block headers by hash or height origin.
type HeaderRequest struct {
	RequestID    uint64   // Correlates the response (eth/66 style)
	OriginHash   [32]byte // If non-zero, origin is this block hash
	OriginHeight uint64   // Used when OriginHash is zero
	Count        uint32   // Number of headers requested (<= MaxHeaderRequestCount)
	Skip         uint32   // Headers to skip between results (0 = contiguous)
	Reverse      bool     // true = walk backwards from origin
}

// EncodeHeaderRequest encodes a header request.
// Wire: RequestID(8) || OriginHash(32) || OriginHeight(8) || Count(4) || Skip(4) || Reverse(1)
func EncodeHeaderRequest(req *HeaderRequest) []byte {
	data := make([]byte, 8+32+8+4+4+1)
	binary.BigEndian.PutUint64(data[0:8], req.RequestID)
	copy(data[8:40], req.OriginHash[:])
	binary.BigEndian.PutUint64(data[40:48], req.OriginHeight)
	binary.BigEndian.PutUint32(data[48:52], req.Count)
	binary.BigEndian.PutUint32(data[52:56], req.Skip)
	if req.Reverse {
		data[56] = 1
	}
	return data
}

// DecodeHeaderRequest decodes a header request.
func DecodeHeaderRequest(data []byte) (*HeaderRequest, error) {
	if len(data) < 57 {
		return nil, ErrMalformedMessage
	}
	req := &HeaderRequest{
		RequestID:    binary.BigEndian.Uint64(data[0:8]),
		OriginHeight: binary.BigEndian.Uint64(data[40:48]),
		Count:        binary.BigEndian.Uint32(data[48:52]),
		Skip:         binary.BigEndian.Uint32(data[52:56]),
		Reverse:      data[56] == 1,
	}
	copy(req.OriginHash[:], data[8:40])
	if req.Count == 0 || req.Count > MaxHeaderRequestCount {
		return nil, ErrMalformedMessage
	}
	return req, nil
}

// HeaderResponse carries the requested headers.
type HeaderResponse struct {
	RequestID uint64   // Echoes HeaderRequest.RequestID
	Headers   [][]byte // Serialized block headers (encoding.MarshalBlockHeader)
}

// EncodeHeaderResponse encodes a header response.
// Wire: RequestID(8) || Count(4) || [HeaderLen(4) || Header]*
func EncodeHeaderResponse(resp *HeaderResponse) []byte {
	size := 8 + 4
	for _, h := range resp.Headers {
		size += 4 + len(h)
	}
	data := make([]byte, size)
	binary.BigEndian.PutUint64(data[0:8], resp.RequestID)
	binary.BigEndian.PutUint32(data[8:12], uint32(len(resp.Headers)))
	offset := 12
	for _, h := range resp.Headers {
		binary.BigEndian.PutUint32(data[offset:offset+4], uint32(len(h)))
		offset += 4
		copy(data[offset:offset+len(h)], h)
		offset += len(h)
	}
	return data
}

// DecodeHeaderResponse decodes a header response.
func DecodeHeaderResponse(data []byte) (*HeaderResponse, error) {
	if len(data) < 12 {
		return nil, ErrMalformedMessage
	}
	resp := &HeaderResponse{
		RequestID: binary.BigEndian.Uint64(data[0:8]),
	}
	count := binary.BigEndian.Uint32(data[8:12])
	if count > MaxHeaderRequestCount {
		return nil, ErrMalformedMessage
	}
	offset := 12
	resp.Headers = make([][]byte, 0, count)
	for i := uint32(0); i < count; i++ {
		if len(data) < offset+4 {
			return nil, ErrMalformedMessage
		}
		hLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		offset += 4
		if hLen <= 0 || hLen > MaxMsgSize || len(data) < offset+hLen {
			return nil, ErrMalformedMessage
		}
		hdr := make([]byte, hLen)
		copy(hdr, data[offset:offset+hLen])
		offset += hLen
		resp.Headers = append(resp.Headers, hdr)
	}
	return resp, nil
}

// ETHEREUM-PARITY SYNC (2026-08-13): receipts sync messages. Ethereum's
// snap protocol fetches recent receipts so a synced node can serve bloom/
// log queries and validate receipt roots without re-executing history.

// ReceiptRequest requests all receipts of the given blocks.
type ReceiptRequest struct {
	RequestID   uint64
	BlockHashes [][32]byte // <= MaxReceiptRequestCount
}

// EncodeReceiptRequest encodes a receipt request.
// Wire: RequestID(8) || Count(4) || Hashes(32*count)
func EncodeReceiptRequest(req *ReceiptRequest) []byte {
	data := make([]byte, 8+4+len(req.BlockHashes)*32)
	binary.BigEndian.PutUint64(data[0:8], req.RequestID)
	binary.BigEndian.PutUint32(data[8:12], uint32(len(req.BlockHashes)))
	for i, h := range req.BlockHashes {
		copy(data[12+i*32:12+(i+1)*32], h[:])
	}
	return data
}

// DecodeReceiptRequest decodes a receipt request.
func DecodeReceiptRequest(data []byte) (*ReceiptRequest, error) {
	if len(data) < 12 {
		return nil, ErrMalformedMessage
	}
	req := &ReceiptRequest{RequestID: binary.BigEndian.Uint64(data[0:8])}
	count := binary.BigEndian.Uint32(data[8:12])
	if count > MaxReceiptRequestCount {
		return nil, ErrMalformedMessage
	}
	if len(data) < 12+int(count)*32 {
		return nil, ErrMalformedMessage
	}
	req.BlockHashes = make([][32]byte, count)
	for i := uint32(0); i < count; i++ {
		copy(req.BlockHashes[i][:], data[12+i*32:12+(i+1)*32])
	}
	return req, nil
}

// ReceiptSet groups the receipts of a single block.
type ReceiptSet struct {
	BlockHash [32]byte
	Receipts  [][]byte // Serialized receipts (encoding.MarshalReceipt)
}

// ReceiptResponse carries receipts grouped by block.
type ReceiptResponse struct {
	RequestID uint64
	Sets      []ReceiptSet
}

// EncodeReceiptResponse encodes a receipt response.
// Wire: RequestID(8) || SetCount(4) || [BlockHash(32) || RCount(4) || [RLen(4)||R]*]*
func EncodeReceiptResponse(resp *ReceiptResponse) []byte {
	size := 8 + 4
	for _, set := range resp.Sets {
		size += 32 + 4
		for _, r := range set.Receipts {
			size += 4 + len(r)
		}
	}
	data := make([]byte, size)
	binary.BigEndian.PutUint64(data[0:8], resp.RequestID)
	binary.BigEndian.PutUint32(data[8:12], uint32(len(resp.Sets)))
	offset := 12
	for _, set := range resp.Sets {
		copy(data[offset:offset+32], set.BlockHash[:])
		offset += 32
		binary.BigEndian.PutUint32(data[offset:offset+4], uint32(len(set.Receipts)))
		offset += 4
		for _, r := range set.Receipts {
			binary.BigEndian.PutUint32(data[offset:offset+4], uint32(len(r)))
			offset += 4
			copy(data[offset:offset+len(r)], r)
			offset += len(r)
		}
	}
	return data
}

// DecodeReceiptResponse decodes a receipt response.
func DecodeReceiptResponse(data []byte) (*ReceiptResponse, error) {
	if len(data) < 12 {
		return nil, ErrMalformedMessage
	}
	resp := &ReceiptResponse{RequestID: binary.BigEndian.Uint64(data[0:8])}
	setCount := binary.BigEndian.Uint32(data[8:12])
	if setCount > MaxReceiptRequestCount {
		return nil, ErrMalformedMessage
	}
	offset := 12
	resp.Sets = make([]ReceiptSet, 0, setCount)
	for i := uint32(0); i < setCount; i++ {
		if len(data) < offset+36 {
			return nil, ErrMalformedMessage
		}
		var set ReceiptSet
		copy(set.BlockHash[:], data[offset:offset+32])
		offset += 32
		rCount := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		if rCount > 100000 {
			return nil, ErrMalformedMessage
		}
		set.Receipts = make([][]byte, 0, rCount)
		for j := uint32(0); j < rCount; j++ {
			if len(data) < offset+4 {
				return nil, ErrMalformedMessage
			}
			rLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
			offset += 4
			if rLen <= 0 || rLen > MaxMsgSize || len(data) < offset+rLen {
				return nil, ErrMalformedMessage
			}
			r := make([]byte, rLen)
			copy(r, data[offset:offset+rLen])
			offset += rLen
			set.Receipts = append(set.Receipts, r)
		}
		resp.Sets = append(resp.Sets, set)
	}
	return resp, nil
}

// TxRequest requests transactions by hash
type TxRequest struct {
	Hashes [][32]byte
}

// TxResponse contains requested transactions
type TxResponse struct {
	Transactions [][]byte // Serialized transactions
}

// BatchMessage contains multiple sub-messages
// This allows combining multiple small messages into a single batch to reduce network overhead
// Requirements: 10.4, 12.1, 12.2, 13.2, 13.3
// #nosec audit-remediation: batch message structure

type BatchMessage struct {
	Messages []*Message // Sub-messages
}

// SubMessage contains a single message within a batch
// Used for serialization purposes
// #nosec audit-remediation: batch sub-message structure
type SubMessage struct {
	Type    uint8  // Message type
	Payload []byte // Message payload
}

// EncodeSubMessage encodes a sub-message for inclusion in a batch
func EncodeSubMessage(msg *Message) ([]byte, error) {
	// Format: type (1) + length (4) + payload
	data := make([]byte, 5+len(msg.Payload))
	data[0] = msg.Type
	binary.BigEndian.PutUint32(data[1:5], uint32(len(msg.Payload))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	copy(data[5:], msg.Payload)
	return data, nil
}

// DecodeSubMessage decodes a sub-message from batch data
func DecodeSubMessage(data []byte) (*SubMessage, error) {
	if len(data) < 5 {
		return nil, ErrMalformedMessage
	}

	msgType := data[0]
	length := binary.BigEndian.Uint32(data[1:5])

	if len(data) < 5+int(length) {
		return nil, ErrMalformedMessage
	}

	payload := data[5 : 5+length]
	return &SubMessage{Type: msgType, Payload: payload}, nil
}

// EncodeBatchMessage encodes a batch message
func EncodeBatchMessage(batch *BatchMessage) ([]byte, error) {
	if len(batch.Messages) == 0 {
		return nil, ErrMalformedMessage
	}

	// Calculate total size needed
	totalSize := 4 // message count (4 bytes)
	for _, msg := range batch.Messages {
		// Each sub-message: type (1) + length (4) + payload
		totalSize += 5 + len(msg.Payload)
	}

	// Build serialized batch
	data := make([]byte, totalSize)
	binary.BigEndian.PutUint32(data[0:4], uint32(len(batch.Messages))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction

	offset := 4
	for _, msg := range batch.Messages {
		// Encode sub-message
		subData, err := EncodeSubMessage(msg)
		if err != nil {
			return nil, err
		}

		// Copy to batch buffer
		copy(data[offset:], subData)
		offset += len(subData)
	}

	return data, nil
}

// DecodeBatchMessage decodes a batch message
func DecodeBatchMessage(data []byte) (*BatchMessage, error) {
	if len(data) < 4 {
		return nil, ErrMalformedMessage
	}

	// Read message count
	msgCount := binary.BigEndian.Uint32(data[0:4])
	if msgCount == 0 || msgCount > MaxBatchMessages {
		return nil, ErrMalformedMessage
	}

	// Decode individual messages
	batch := &BatchMessage{Messages: make([]*Message, 0, msgCount)}
	offset := 4

	for i := uint32(0); i < msgCount; i++ {
		// Check if we have enough data for at least one more sub-message
		if offset+5 > len(data) {
			return nil, ErrMalformedMessage
		}

		// Get sub-message length
		subMsgLen := 5 + int(binary.BigEndian.Uint32(data[offset+1:offset+5]))
		if offset+subMsgLen > len(data) {
			return nil, ErrMalformedMessage
		}

		// Decode sub-message
		subMsg, err := DecodeSubMessage(data[offset : offset+subMsgLen])
		if err != nil {
			return nil, err
		}

		// Create Message object
		msg := &Message{
			Type:      subMsg.Type,
			Payload:   subMsg.Payload,
			Timestamp: time.Now(),
		}

		batch.Messages = append(batch.Messages, msg)
		offset += subMsgLen
	}

	return batch, nil
}

var (
	// Global message compressor (thread-safe for concurrent use)
	msgCompressor = NewMessageCompressor(128, true)
	// Global optimized codec (thread-safe for concurrent use)
	optimizedCodec = NewOptimizedCodec()
)

// EncodeMessage encodes a message with header
func EncodeMessage(msgType uint8, payload []byte) ([]byte, error) {
	if len(payload) > MaxMsgSize {
		return nil, ErrMsgTooLarge
	}

	// Compress payload if needed using existing MessageCompressor
	processedPayload, compressed, err := msgCompressor.CompressIfNeeded(payload)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	// Calculate checksum (simple CRC32) on the processed payload
	checksum := crc32Checksum(processedPayload)

	// Build message: flags+type (1) + length (4) + checksum (4) + payload
	msg := make([]byte, MsgHeaderSize+len(processedPayload))

	// Set flags and type (compress flag in highest bit)
	msgTypeWithFlags := msgType
	if compressed {
		msgTypeWithFlags |= MsgFlagCompressed
	}
	msg[0] = msgTypeWithFlags

	binary.BigEndian.PutUint32(msg[1:5], uint32(len(processedPayload))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	binary.BigEndian.PutUint32(msg[5:9], checksum)
	copy(msg[MsgHeaderSize:], processedPayload)

	return msg, nil
}

// DecodeMessage decodes a message with header
func DecodeMessage(data []byte) (*Message, error) {
	if len(data) < MsgHeaderSize {
		return nil, ErrMalformedMessage
	}

	// Extract flags and type
	msgTypeWithFlags := data[0]
	msgType := msgTypeWithFlags &^ MsgFlagCompressed // Clear compression flag
	isCompressed := (msgTypeWithFlags & MsgFlagCompressed) != 0

	length := binary.BigEndian.Uint32(data[1:5])
	checksum := binary.BigEndian.Uint32(data[5:9])

	if length > MaxMsgSize {
		return nil, ErrMsgTooLarge
	}

	if len(data) < MsgHeaderSize+int(length) {
		return nil, ErrMalformedMessage
	}

	processedPayload := data[MsgHeaderSize : MsgHeaderSize+length]

	// Verify checksum on processed payload
	if crc32Checksum(processedPayload) != checksum {
		return nil, ErrInvalidChecksum
	}

	// Decompress if needed using existing MessageCompressor
	payload, err := msgCompressor.DecompressIfNeeded(processedPayload, isCompressed)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress message: %w", err)
	}

	return &Message{
		Type:      msgType,
		Payload:   payload,
		Timestamp: time.Now(),
	}, nil
}

// crc32Checksum calculates a simple CRC32 checksum.
//
// R40-M9 FIX: SECURITY NOTE — CRC32 is NOT cryptographically secure and MUST NOT
// be relied upon for integrity against adversarial tampering. An attacker can
// forge a message with a valid CRC32 in negligible time. This checksum is used
// ONLY for error detection (bit-flip, corruption during transport). Actual message
// integrity and authenticity are provided by the RLPx encryption layer (ECIES +
// AES-CTR + HMAC-SHA256) that wraps all P2P messages before they hit the wire.
// If a shared secret is available from the connection, consider replacing this
// with HMAC-SHA256 for defense-in-depth.
func crc32Checksum(data []byte) uint32 {
	var crc uint32 = 0xFFFFFFFF
	for _, b := range data {
		crc ^= uint32(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

// EncodeStatusMessage encodes a status message.
// R37 P2-P2P-01: appends length-prefixed ValidatorPublicKey and
// ValidatorSignature after the 104-byte base payload for backward
// wire compatibility.
//
// R38-P2-01 DEEP FIX (Protocol V2, 2026-08-02): when both Timestamp > 0
// AND SessionNonce != [16]byte{}, appends ANOTHER length-prefixed
// extension block AFTER the signature containing the V2 signed-domain
// bytes (Timestamp 8B + SessionNonce 16B = 24B). Legacy R37 decoders
// stop reading at the end of the signature and silently ignore this
// trailing block, preserving wire compatibility. The V2 host's
// VerifyStatusSignature path, when the extension is present, signs over
// base[:104] || Timestamp || SessionNonce (NOT the len-prefixed
// extension header — only the 24 value bytes are part of the signed
// domain).
func EncodeStatusMessage(status *StatusMessage) []byte {
	base := make([]byte, 4+8+8+32+32+20)
	binary.BigEndian.PutUint32(base[0:4], status.Version)
	binary.BigEndian.PutUint64(base[4:12], status.NetworkID)
	binary.BigEndian.PutUint64(base[12:20], status.BestHeight)
	copy(base[20:52], status.BestHash[:])
	copy(base[52:84], status.GenesisHash[:])
	copy(base[84:104], status.ValidatorAddress[:])

	if len(status.ValidatorPublicKey) == 0 && len(status.ValidatorSignature) == 0 {
		return base
	}

	// Append length-prefixed public key and signature.
	pkLen := make([]byte, 4)
	binary.BigEndian.PutUint32(pkLen, uint32(len(status.ValidatorPublicKey)))
	sigLen := make([]byte, 4)
	binary.BigEndian.PutUint32(sigLen, uint32(len(status.ValidatorSignature)))

	data := make([]byte, 0, len(base)+8+len(status.ValidatorPublicKey)+len(status.ValidatorSignature)+4+24)
	data = append(data, base...)
	data = append(data, pkLen...)
	data = append(data, status.ValidatorPublicKey...)
	data = append(data, sigLen...)
	data = append(data, status.ValidatorSignature...)

	// R38-P2-01 DEEP FIX (Protocol V2, 2026-08-02): append optional V2
	// extension block (Timestamp + SessionNonce) AFTER the signature. The
	// 24-byte extension is length-prefixed (4-byte BE) so legacy R37
	// decoders stop reading at the end of the sig and silently ignore the
	// trailing block — wire compatibility preserved.
	//
	// The SIGNED DOMAIN is base[:104] || Timestamp || SessionNonce, NOT
	// the len-prefixed header. When the V2 host calls
	// VerifyStatusSignature it must use msg.Payload[:104] +
	// msg.Payload[end-24:end] (the last 24 bytes ARE the extension value
	// bytes — see VerifyStatusSignature in host.go).
	hasV2Ext := status.Timestamp > 0 || status.SessionNonce != ([16]byte{})
	hasForkID := status.ForkID != ([32]byte{})
	if hasV2Ext || hasForkID {
		// V3 extension block (2026-08-13): length-prefixed trailer carrying
		// Timestamp(8) + SessionNonce(16) [+ ForkID(32)]. extLen==24 is the
		// legacy V2 form; extLen==36 is the V3 form with fork id. Legacy
		// decoders stop at the signature and ignore this block entirely.
		extLen := 24
		if hasForkID {
			extLen = 36
		}
		extLenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(extLenBuf, uint32(extLen))
		ts := make([]byte, 8)
		binary.BigEndian.PutUint64(ts, status.Timestamp)
		data = append(data, extLenBuf...)
		data = append(data, ts...)
		data = append(data, status.SessionNonce[:]...)
		if hasForkID {
			data = append(data, status.ForkID[:]...)
		}
	}
	return data
}

// DecodeStatusMessage decodes a status message.
// R37 P2-P2P-01: parses optional length-prefixed ValidatorPublicKey and
// ValidatorSignature from trailing bytes.
//
// R38-P2-01 DEEP FIX (Protocol V2, 2026-08-02): if trailing bytes remain
// AFTER the signature, parses the optional V2 extension block
// (Timestamp uint64 + SessionNonce [16]byte). When the extension is
// absent (legacy R37 or non-fresh status), Timestamp=0 and SessionNonce=0.
// Host.go's VerifyStatusSignature checks `Timestamp > 0` to decide whether
// to apply the clock-skew + replay-protection checks.
func DecodeStatusMessage(data []byte) (*StatusMessage, error) {
	if len(data) < 84 {
		return nil, ErrMalformedMessage
	}

	status := &StatusMessage{
		Version:    binary.BigEndian.Uint32(data[0:4]),
		NetworkID:  binary.BigEndian.Uint64(data[4:12]),
		BestHeight: binary.BigEndian.Uint64(data[12:20]),
	}
	copy(status.BestHash[:], data[20:52])
	copy(status.GenesisHash[:], data[52:84])

	// ValidatorAddress is optional (appended for TSS support).
	// Old nodes that don't send it will have a zero address, which is ignored.
	if len(data) >= 104 {
		copy(status.ValidatorAddress[:], data[84:104])
	}

	// R37 P2-P2P-01: parse optional public key + signature from trailing bytes.
	offset := 104
	if len(data) >= offset+4 {
		pkLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		offset += 4
		if len(data) >= offset+pkLen {
			status.ValidatorPublicKey = make([]byte, pkLen)
			copy(status.ValidatorPublicKey, data[offset:offset+pkLen])
			offset += pkLen
		}
		if len(data) >= offset+4 {
			sigLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
			offset += 4
			if len(data) >= offset+sigLen {
				status.ValidatorSignature = make([]byte, sigLen)
				copy(status.ValidatorSignature, data[offset:offset+sigLen])
				offset += sigLen

				// R38-P2-01 DEEP FIX (V2 protocol): if trailing bytes remain
				// after the signature, parse the V2 extension block.
				// Format: extLen(4B BE) || Timestamp(8B BE) || SessionNonce(16B).
				// We sanity-check extLen>=24 (forward-compat: future V2.x
				// extension fields may extend the block; we read the first 24
				// bytes which is the V2 spec Timestamp+Nonce).
				//
				// V3 (2026-08-13): extLen==36 additionally carries ForkID(32B)
				// after the nonce.
				if len(data) >= offset+4 {
					extLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
					offset += 4
					if extLen >= 24 && len(data) >= offset+24 {
						status.Timestamp = binary.BigEndian.Uint64(data[offset : offset+8])
						copy(status.SessionNonce[:], data[offset+8:offset+24])
						if extLen >= 36 && len(data) >= offset+36 {
							copy(status.ForkID[:], data[offset+24:offset+36])
						}
					}
				}
			}
		}
	}

	return status, nil
}

// EncodeBlockRequest encodes a block request
func EncodeBlockRequest(req *BlockRequest) []byte {
	hashCount := len(req.Hashes)
	data := make([]byte, 8+8+4+hashCount*32)
	binary.BigEndian.PutUint64(data[0:8], req.FromHeight)
	binary.BigEndian.PutUint64(data[8:16], req.ToHeight)
	binary.BigEndian.PutUint32(data[16:20], uint32(hashCount)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	for i, h := range req.Hashes {
		copy(data[20+i*32:20+(i+1)*32], h[:])
	}
	return data
}

// DecodeBlockRequest decodes a block request
func DecodeBlockRequest(data []byte) (*BlockRequest, error) {
	if len(data) < 20 {
		return nil, ErrMalformedMessage
	}

	req := &BlockRequest{
		FromHeight: binary.BigEndian.Uint64(data[0:8]),
		ToHeight:   binary.BigEndian.Uint64(data[8:16]),
	}

	hashCount := binary.BigEndian.Uint32(data[16:20])
	if hashCount > MaxBlockRequestHashes {
		return nil, ErrMalformedMessage
	}
	if len(data) < 20+int(hashCount)*32 {
		return nil, ErrMalformedMessage
	}

	req.Hashes = make([][32]byte, hashCount)
	for i := uint32(0); i < hashCount; i++ {
		copy(req.Hashes[i][:], data[20+i*32:20+(i+1)*32])
	}

	return req, nil
}

func EncodeBlockResponse(resp *BlockResponse) []byte {
	blockCount := len(resp.Blocks)
	size := 4
	for _, b := range resp.Blocks {
		size += 4 + len(b)
	}
	data := make([]byte, size)
	binary.BigEndian.PutUint32(data[0:4], uint32(blockCount))
	offset := 4
	for _, b := range resp.Blocks {
		binary.BigEndian.PutUint32(data[offset:offset+4], uint32(len(b)))
		offset += 4
		copy(data[offset:offset+len(b)], b)
		offset += len(b)
	}
	return data
}

func DecodeBlockResponse(data []byte) (*BlockResponse, error) {
	if len(data) < 4 {
		return nil, ErrMalformedMessage
	}
	blockCount := binary.BigEndian.Uint32(data[0:4])
	// P2P-MSG-01 FIX (deep-audit 2026-07-12): bound the capacity hint to what the
	// payload can actually hold — each block needs at least a 4-byte length
	// prefix. A peer-supplied blockCount (up to 2^32) otherwise forces ~100GB of
	// slice-header pre-allocation from a 4-byte payload. The loop below still
	// validates and appends each entry, so correctness is unchanged.
	allocHint := int(blockCount)
	if rem := (len(data) - 4) / 4; allocHint > rem {
		allocHint = rem
	}
	resp := &BlockResponse{
		Blocks: make([][]byte, 0, allocHint),
	}
	offset := 4
	for i := uint32(0); i < blockCount; i++ {
		if offset+4 > len(data) {
			return nil, ErrMalformedMessage
		}
		blockLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		if offset+int(blockLen) > len(data) {
			return nil, ErrMalformedMessage
		}
		blockData := make([]byte, blockLen)
		copy(blockData, data[offset:offset+int(blockLen)])
		offset += int(blockLen)
		resp.Blocks = append(resp.Blocks, blockData)
	}
	return resp, nil
}
func ValidateMessage(msg *Message) error {
	if msg == nil {
		return ErrMalformedMessage
	}

	switch msg.Type {
	case MsgTypeBlock, MsgTypeTransaction, MsgTypeVote:
		if len(msg.Payload) == 0 {
			return ErrMalformedMessage
		}
	case MsgTypeBlockReq, MsgTypeTxReq:
		if len(msg.Payload) < 20 {
			return ErrMalformedMessage
		}
	case MsgTypeBlockResp, MsgTypeTxResp:
		if len(msg.Payload) == 0 {
			return ErrMalformedMessage
		}
	case MsgTypeStatus:
		// Status can have variable length payload
	case MsgTypePing, MsgTypePong:
		// Ping/pong can have empty payload
	case MsgTypeFindNode:
		if len(msg.Payload) != 32 {
			return ErrMalformedMessage
		}
	case MsgTypeNeighbors:
		if len(msg.Payload) < 2 {
			return ErrMalformedMessage
		}
	case MsgTypeQNR:
		if len(msg.Payload) < 100 || len(msg.Payload) > 8000 {
			return ErrMalformedMessage
		}
	case MsgTypeChallenge, MsgTypeChallengeResponse:
		if len(msg.Payload) == 0 {
			return ErrMalformedMessage
		}
	case MsgTypeBatch:
		if len(msg.Payload) < 4 {
			return ErrMalformedMessage
		}
	// audit-fix R7-7: accept QPOS consensus and expert message types
	case MsgTypeAttestation, MsgTypeAggregateAttest,
		MsgTypeProposerSlashing, MsgTypeAttesterSlashing:
		if len(msg.Payload) == 0 {
			return ErrMalformedMessage
		}
	case MsgTypeCheckpointSig:
		if len(msg.Payload) < 64 {
			return ErrMalformedMessage
		}
	case MsgTypeCheckpointReq:
		if len(msg.Payload) < 8 {
			return ErrMalformedMessage
		}
	case MsgTypeExpert:
		// Expert messages can have variable payload
	case MsgTypeSnapStateReq:
		if len(msg.Payload) < 8 {
			return ErrMalformedMessage
		}
	case MsgTypeSnapStateResp:
		if len(msg.Payload) < 4 {
			return ErrMalformedMessage
		}
	case MsgTypeSnapRangeReq:
		if len(msg.Payload) < 8 {
			return ErrMalformedMessage
		}
	case MsgTypeSnapRangeResp:
		if len(msg.Payload) < 4 {
			return ErrMalformedMessage
		}
	// ETHEREUM-PARITY SYNC (2026-08-13): snap storage/bytecode, header and
	// receipt messages. Minimum sizes mirror the fixed wire prefixes.
	case MsgTypeSnapStorageReq:
		if len(msg.Payload) < 8+32+32+4 {
			return ErrMalformedMessage
		}
	case MsgTypeSnapStorageResp:
		if len(msg.Payload) < 8+32+1+4 {
			return ErrMalformedMessage
		}
	case MsgTypeSnapBytecodeReq:
		if len(msg.Payload) < 8+4+4 {
			return ErrMalformedMessage
		}
	case MsgTypeSnapBytecodeResp:
		if len(msg.Payload) < 8+1+4 {
			return ErrMalformedMessage
		}
	case MsgTypeHeaderReq:
		if len(msg.Payload) < 57 {
			return ErrMalformedMessage
		}
	case MsgTypeHeaderResp:
		if len(msg.Payload) < 12 {
			return ErrMalformedMessage
		}
	case MsgTypeReceiptReq:
		if len(msg.Payload) < 12 {
			return ErrMalformedMessage
		}
	case MsgTypeReceiptResp:
		if len(msg.Payload) < 12 {
			return ErrMalformedMessage
		}
	case MsgTypeProtocolNegotiate, MsgTypeProtocolNegotiateResp:
		if len(msg.Payload) < 2 {
			return ErrMalformedMessage
		}
	// TSS protocol messages — qau_tss (70-79 range)
	case MsgTypeTSSSessionInit:
		// SessionID(32) + MessageHash(32) + ParticipantCount(4) = 68 bytes min
		if len(msg.Payload) < 68 {
			return ErrMalformedMessage
		}
	case MsgTypeTSSRound1Commit:
		// SessionID(32) + ParticipantID(4) + Commitment(32) + Nonce(16) = 84 bytes
		if len(msg.Payload) != 84 {
			return ErrMalformedMessage
		}
	case MsgTypeTSSRound2Reveal:
		// SessionID(32) + ParticipantID(4) + WShare + ZShare + Nonce(16)
		// WShare = 4608 bytes, ZShare = 3840 bytes → 32+4+4608+3840+16 = 8500
		if len(msg.Payload) < 100 || len(msg.Payload) > 20*1024 {
			return ErrMalformedMessage
		}
	case MsgTypeTSSRound2Private:
		// Encrypted payload (variable size, contains ScShare under encryption)
		if len(msg.Payload) < 64 || len(msg.Payload) > 20*1024 {
			return ErrMalformedMessage
		}
	case MsgTypeTSSSignature:
		// SessionID(32) + Signature(3293 or 4064)
		if len(msg.Payload) < 100 || len(msg.Payload) > 10*1024 {
			return ErrMalformedMessage
		}
	case MsgTypeTSSDKGShare:
		// DKG share exchange (variable, encrypted)
		if len(msg.Payload) < 64 || len(msg.Payload) > 50*1024 {
			return ErrMalformedMessage
		}
	case MsgTypeTSSDKGCommitment, MsgTypeTSSDKGAck:
		// Task 5 (node-layer distributed DKG): JSON-encoded round messages
		// (qtd.Round1CommitmentMessage / qtd.Round1OpenMessage). Reject empty
		// payloads; upper bound prevents unbounded memory from base64-encoded
		// polynomial vectors (a full open+share JSON stays well below 128KB).
		if len(msg.Payload) < 16 || len(msg.Payload) > 128*1024 {
			return ErrMalformedMessage
		}
	// Shard protocol messages — qau_shard (80-89 range)
	// P1-1 (2026-07-14): Size bounds prevent DoS via oversized payloads.
	// ShardBlock: JSON-encoded ShardBlock (header + txs + crossMsgs), bounded at 2MB
	// ShardBlockReq: shardID(8) + height(8) = 16 bytes
	// ShardBlockResp: JSON-encoded ShardBlock, bounded at 2MB
	// ShardAttestation: shardID(8) + height(8) + sig(3293) + addr(20) = ~3330 bytes, bounded at 4KB
	// CrossShardMsg: JSON-encoded CrossShardMessage, bounded at 64KB (ShardCrossMsgMaxSize)
	// CrossShardReceipt: JSON-encoded CrossShardReceipt, bounded at 4KB
	case MsgTypeShardBlock:
		if len(msg.Payload) < 32 || len(msg.Payload) > 2*1024*1024 {
			return ErrMalformedMessage
		}
	case MsgTypeShardBlockReq:
		if len(msg.Payload) != 16 {
			return ErrMalformedMessage
		}
	case MsgTypeShardBlockResp:
		if len(msg.Payload) < 32 || len(msg.Payload) > 2*1024*1024 {
			return ErrMalformedMessage
		}
	case MsgTypeShardAttestation:
		if len(msg.Payload) < 32 || len(msg.Payload) > 4*1024 {
			return ErrMalformedMessage
		}
	case MsgTypeCrossShardMsg:
		if len(msg.Payload) < 32 || len(msg.Payload) > 64*1024 {
			return ErrMalformedMessage
		}
	case MsgTypeCrossShardReceipt:
		if len(msg.Payload) < 32 || len(msg.Payload) > 4*1024 {
			return ErrMalformedMessage
		}
	default:
		return fmt.Errorf("%w: %d", ErrInvalidMsgType, msg.Type)
	}

	return nil
}

// ProtocolNegotiateMessage is sent during handshake to negotiate supported sub-protocols.
type ProtocolNegotiateMessage struct {
	Protocols []ProtocolSpec
}

// EncodeProtocolNegotiate encodes a protocol negotiation message.
func EncodeProtocolNegotiate(msg *ProtocolNegotiateMessage) ([]byte, error) {
	count := len(msg.Protocols)
	if count == 0 || count > 32 {
		return nil, ErrMalformedMessage
	}

	totalLen := 2 // count (2 bytes)
	for _, p := range msg.Protocols {
		totalLen += 1 + len(p.Name) + 2 // nameLen(1) + name + version(2)
	}

	data := make([]byte, totalLen)
	binary.BigEndian.PutUint16(data[0:2], uint16(count))
	offset := 2

	for _, p := range msg.Protocols {
		nameBytes := []byte(p.Name)
		data[offset] = byte(len(nameBytes))
		offset++
		copy(data[offset:], nameBytes)
		offset += len(nameBytes)
		binary.BigEndian.PutUint16(data[offset:offset+2], uint16(p.Version))
		offset += 2
	}

	return data, nil
}

// DecodeProtocolNegotiate decodes a protocol negotiation message.
func DecodeProtocolNegotiate(data []byte) (*ProtocolNegotiateMessage, error) {
	if len(data) < 2 {
		return nil, ErrMalformedMessage
	}

	count := int(binary.BigEndian.Uint16(data[0:2]))
	if count == 0 || count > 32 {
		return nil, ErrMalformedMessage
	}

	protocols := make([]ProtocolSpec, 0, count)
	offset := 2

	for i := 0; i < count; i++ {
		if offset >= len(data) {
			return nil, ErrMalformedMessage
		}

		nameLen := int(data[offset]) // #nosec G602 -- offset<len(data) checked above
		offset++

		if offset+nameLen+2 > len(data) {
			return nil, ErrMalformedMessage
		}

		name := string(data[offset : offset+nameLen])
		offset += nameLen

		version := uint(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		protocols = append(protocols, ProtocolSpec{
			Name:    name,
			Version: version,
		})
	}

	return &ProtocolNegotiateMessage{Protocols: protocols}, nil
}

// ProtocolNegotiateRespMessage is the response to a protocol negotiation request.
type ProtocolNegotiateRespMessage struct {
	AgreedProtocols []ProtocolSpec
}

// EncodeProtocolNegotiateResp encodes a protocol negotiation response.
func EncodeProtocolNegotiateResp(msg *ProtocolNegotiateRespMessage) ([]byte, error) {
	negotiate := &ProtocolNegotiateMessage{Protocols: msg.AgreedProtocols}
	return EncodeProtocolNegotiate(negotiate)
}

// DecodeProtocolNegotiateResp decodes a protocol negotiation response.
func DecodeProtocolNegotiateResp(data []byte) (*ProtocolNegotiateRespMessage, error) {
	negotiate, err := DecodeProtocolNegotiate(data)
	if err != nil {
		return nil, err
	}
	return &ProtocolNegotiateRespMessage{AgreedProtocols: negotiate.Protocols}, nil
}

// CheckpointSigMessage carries a validator's checkpoint signature for P2P broadcast.
// This enables all validators to collect each other's signatures for checkpoint finalization.
type CheckpointSigMessage struct {
	Height        uint64
	BlockHash     [32]byte
	StateRoot     [32]byte
	Epoch         uint64
	ValidatorAddr [20]byte
	Signature     []byte // Dilithium3 signature
}

// EncodeCheckpointSig encodes a checkpoint signature message.
func EncodeCheckpointSig(msg *CheckpointSigMessage) []byte {
	data := make([]byte, 8+32+32+8+20+4+len(msg.Signature))
	binary.BigEndian.PutUint64(data[0:8], msg.Height)
	copy(data[8:40], msg.BlockHash[:])
	copy(data[40:72], msg.StateRoot[:])
	binary.BigEndian.PutUint64(data[72:80], msg.Epoch)
	copy(data[80:100], msg.ValidatorAddr[:])
	binary.BigEndian.PutUint32(data[100:104], uint32(len(msg.Signature)))
	copy(data[104:], msg.Signature)
	return data
}

// DecodeCheckpointSig decodes a checkpoint signature message.
func DecodeCheckpointSig(data []byte) (*CheckpointSigMessage, error) {
	if len(data) < 104 {
		return nil, ErrMalformedMessage
	}
	msg := &CheckpointSigMessage{
		Height: binary.BigEndian.Uint64(data[0:8]),
		Epoch:  binary.BigEndian.Uint64(data[72:80]),
	}
	copy(msg.BlockHash[:], data[8:40])
	copy(msg.StateRoot[:], data[40:72])
	copy(msg.ValidatorAddr[:], data[80:100])
	sigLen := binary.BigEndian.Uint32(data[100:104])
	// SECURITY (audit DATA-07): Cap signature length to Dilithium3 size (3293 bytes).
	// Without this, a uint32 sigLen up to ~4GB could cause excessive allocation
	// on 64-bit platforms and integer overflow on 32-bit platforms.
	if sigLen > 3293 {
		return nil, ErrMalformedMessage
	}
	if len(data) < 104+int(sigLen) {
		return nil, ErrMalformedMessage
	}
	msg.Signature = make([]byte, sigLen)
	copy(msg.Signature, data[104:104+int(sigLen)])
	return msg, nil
}

// CheckpointReqMessage requests a finalized checkpoint by height.
type CheckpointReqMessage struct {
	Height uint64
}

// EncodeCheckpointReq encodes a checkpoint request.
func EncodeCheckpointReq(msg *CheckpointReqMessage) []byte {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data[0:8], msg.Height)
	return data
}

// DecodeCheckpointReq decodes a checkpoint request.
func DecodeCheckpointReq(data []byte) (*CheckpointReqMessage, error) {
	if len(data) < 8 {
		return nil, ErrMalformedMessage
	}
	return &CheckpointReqMessage{
		Height: binary.BigEndian.Uint64(data[0:8]),
	}, nil
}

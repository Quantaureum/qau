// Quantaureum Node source, version 1.0.0.
package lightclient

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
)

var (
	ErrSyncCommitteeNotAvailable  = errors.New("sync committee not available")
	ErrInsufficientSyncSignatures = errors.New("insufficient sync committee signatures")
	ErrInvalidSyncCommitteeBits   = errors.New("invalid sync committee bitfield")
	ErrSyncCommitteeSigMismatch   = errors.New("sync committee signature count mismatch with bitfield")
)

const (
	MinSyncCommitteeParticipation = 2.0 / 3.0 // At least 2/3 of committee must sign
)

// SyncCommitteeInfo holds the sync committee data needed by light clients.
type SyncCommitteeInfo struct {
	Period           uint64
	ValidatorPubKeys [][]byte // Public keys of committee members (Dilithium3)
	AggregatePubKey  []byte   // For BLS-compatible systems (not used with Dilithium3)
}

// SyncCommitteeVerifier verifies block headers using sync committee signatures.
type SyncCommitteeVerifier struct {
	currentCommittee *SyncCommitteeInfo
	nextCommittee    *SyncCommitteeInfo
}

// NewSyncCommitteeVerifier creates a new sync committee verifier.
func NewSyncCommitteeVerifier() *SyncCommitteeVerifier {
	return &SyncCommitteeVerifier{}
}

// UpdateCurrentCommittee updates the current sync committee.
func (v *SyncCommitteeVerifier) UpdateCurrentCommittee(info *SyncCommitteeInfo) {
	v.currentCommittee = info
}

// UpdateNextCommittee updates the next sync committee.
func (v *SyncCommitteeVerifier) UpdateNextCommittee(info *SyncCommitteeInfo) {
	v.nextCommittee = info
}

// RotateCommittee rotates to the next sync committee.
func (v *SyncCommitteeVerifier) RotateCommittee() {
	v.currentCommittee = v.nextCommittee
	v.nextCommittee = nil
}

// GetCurrentCommittee returns the current sync committee info.
func (v *SyncCommitteeVerifier) GetCurrentCommittee() *SyncCommitteeInfo {
	return v.currentCommittee
}

// VerifyBlockHeader verifies a block header using the sync committee signature.
// Returns true if the sync committee signature is valid.
func (v *SyncCommitteeVerifier) VerifyBlockHeader(header *encoding.BlockHeader) error {
	if header == nil {
		return ErrInvalidHeader
	}

	if v.currentCommittee == nil || len(v.currentCommittee.ValidatorPubKeys) == 0 {
		// AUDIT (2026) CRIT-02: Fail-closed when committee is not
		// configured but the header carries sync committee signatures.
		// Previously, empty sig/bits returned nil (valid) — fail-open.
		if len(header.SyncCommitteeSig) > 0 || len(header.SyncCommitteeBits) > 0 {
			return ErrSyncCommitteeNotAvailable
		}
		return nil // No sync committee data and no committee configured — pre-sync-committee block
	}

	committeeSize := len(v.currentCommittee.ValidatorPubKeys)
	bitfield := header.SyncCommitteeBits

	// AUDIT (2026) CRIT-02: Reject oversized bitfields. An attacker can
	// set bits at indices >= committeeSize to inflate participantCount without
	// any actual signature verification (the verification loop only iterates
	// [0, committeeSize)). Limit bitfield to exactly ceil(committeeSize/8) bytes.
	maxBitfieldLen := (committeeSize + 7) / 8
	if len(bitfield) > maxBitfieldLen {
		return fmt.Errorf("%w: bitfield length %d exceeds maximum %d for committee size %d",
			ErrInvalidSyncCommitteeBits, len(bitfield), maxBitfieldLen, committeeSize)
	}

	// AUDIT (2026) CRIT-02: Fail-closed when signatures/bits are empty
	// but committee is configured. Previously returned nil (valid).
	if len(header.SyncCommitteeSig) == 0 || len(bitfield) == 0 {
		return ErrInsufficientSyncSignatures
	}

	// Count participating members from bitfield — only in-bounds bits.
	participantCount := 0
	for i := 0; i < committeeSize; i++ {
		if isBitSet(bitfield, i) {
			participantCount++
		}
	}
	if participantCount == 0 {
		return ErrInsufficientSyncSignatures
	}

	// Check minimum participation (2/3)
	minRequired := int(float64(committeeSize) * MinSyncCommitteeParticipation)
	if minRequired < 1 {
		minRequired = 1
	}
	if participantCount < minRequired {
		return fmt.Errorf("%w: got %d, need at least %d of %d",
			ErrInsufficientSyncSignatures, participantCount, minRequired, committeeSize)
	}

	// Parse concatenated signatures
	signatures := parseConcatenatedSignatures(header.SyncCommitteeSig, bitfield, committeeSize)
	if len(signatures) != participantCount {
		return ErrSyncCommitteeSigMismatch
	}

	// Compute the signing data (same as what committee members signed)
	signingData := computeSyncCommitteeSigningData(header)

	// Verify each signature
	sigIdx := 0
	for i := 0; i < committeeSize; i++ {
		if !isBitSet(bitfield, i) {
			continue
		}
		if sigIdx >= len(signatures) {
			return ErrSyncCommitteeSigMismatch
		}

		pubKeyBytes := v.currentCommittee.ValidatorPubKeys[i]
		pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
		if err != nil {
			return fmt.Errorf("invalid committee member public key at index %d: %w", i, err)
		}

		if !crypto.Verify(pubKey, signingData, signatures[sigIdx]) {
			return fmt.Errorf("sync committee signature verification failed at index %d", i)
		}
		sigIdx++
	}

	return nil
}

// syncCommitteeDomainTag is the domain separation tag prepended to sync
// committee signing data. It binds signatures to the Quantaureum sync
// committee context, preventing reuse of the same signature for other
// signing purposes (e.g., attestation, block proposal) that might use a
// similar data layout.
const syncCommitteeDomainTag = "QuantaureumSyncCommittee"

// computeSyncCommitteeSigningData computes the data that sync committee members sign.
//
// AUDIT-FULL ROUND4 (2026-08-15) INFO-02: The comment below about "mainnet
// would also verify on testnet" refers to the pre-fix behavior. The BRDG-10
// fix (domain separation tag + ChainID) already resolved this — no further
// action needed. Non-defect informational finding.
//
// AUDIT (2026) BRDG-10 FIX: Add domain separation tag and ChainID to
// prevent cross-chain replay and cross-context signature reuse. Previously
// the signing data was only [slot(8) + blockRoot(32) + epoch(8)] with no
// domain tag or chain identifier — a signature valid for Quantaureum
// mainnet would also verify on testnet (or any chain using the same slot/
// blockRoot/epoch layout), and the same byte sequence could be replayed
// in any other signing context that happens to use the same layout.
//
// Format (length-prefixed domain separation per RFC 8701 §4.2 to prevent
// concatenation ambiguity):
//
//	domain || uint32(len(message)) || message
//
// where message = slot(8) || blockRoot(32) || epoch(8) || chainID(8).
func computeSyncCommitteeSigningData(header *encoding.BlockHeader) []byte {
	blockHash := computeHeaderHash(header)

	// Message body: slot || blockRoot || epoch || chainID
	const msgLen = 8 + 32 + 8 + 8
	var msg [msgLen]byte
	binary.BigEndian.PutUint64(msg[0:8], header.Slot)
	copy(msg[8:40], blockHash[:])
	binary.BigEndian.PutUint64(msg[40:48], header.Epoch)
	binary.BigEndian.PutUint64(msg[48:56], header.ChainID)

	// Length-prefixed domain separation: domain || uint32(len(message)) || message
	var buf bytes.Buffer
	buf.WriteString(syncCommitteeDomainTag)
	var msgLenBytes [4]byte
	binary.BigEndian.PutUint32(msgLenBytes[:], msgLen)
	buf.Write(msgLenBytes[:])
	buf.Write(msg[:])
	return buf.Bytes()
}

// countSetBits counts the number of set bits in a bitfield.
func countSetBits(bitfield []byte) int {
	count := 0
	for _, b := range bitfield {
		for i := 0; i < 8; i++ {
			if b&(1<<i) != 0 {
				count++
			}
		}
	}
	return count
}

// isBitSet checks if a specific bit is set in the bitfield.
func isBitSet(bitfield []byte, index int) bool {
	if index < 0 {
		return false
	}
	byteIdx := index / 8
	if byteIdx >= len(bitfield) {
		return false
	}
	bitIdx := index % 8
	return bitfield[byteIdx]&(1<<bitIdx) != 0
}

// parseConcatenatedSignatures parses concatenated Dilithium3 signatures based on the bitfield.
// Each Dilithium3 signature is 3293 bytes.
// AUDIT (2026) CRIT-02: Only count in-bounds bits (indices < committeeSize).
func parseConcatenatedSignatures(aggregatedSig []byte, bitfield []byte, committeeSize int) [][]byte {
	participantCount := 0
	for i := 0; i < committeeSize; i++ {
		if isBitSet(bitfield, i) {
			participantCount++
		}
	}
	if participantCount == 0 {
		return nil
	}

	// Dilithium3 signature size
	const dilithium3SigSize = 3293

	expectedLen := participantCount * dilithium3SigSize
	if len(aggregatedSig) < expectedLen {
		// Try variable-length parsing
		return parseVariableLengthSignatures(aggregatedSig, participantCount)
	}

	signatures := make([][]byte, 0, participantCount)
	for i := 0; i < participantCount; i++ {
		start := i * dilithium3SigSize
		end := start + dilithium3SigSize
		if end > len(aggregatedSig) {
			break
		}
		sig := make([]byte, dilithium3SigSize)
		copy(sig, aggregatedSig[start:end])
		signatures = append(signatures, sig)
	}
	return signatures
}

// parseVariableLengthSignatures parses signatures with length prefixes.
func parseVariableLengthSignatures(data []byte, expectedCount int) [][]byte {
	signatures := make([][]byte, 0, expectedCount)
	offset := 0
	for offset+2 <= len(data) && len(signatures) < expectedCount {
		sigLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if offset+sigLen > len(data) {
			break
		}
		sig := make([]byte, sigLen)
		copy(sig, data[offset:offset+sigLen])
		signatures = append(signatures, sig)
		offset += sigLen
	}
	return signatures
}

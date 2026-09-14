// Quantaureum Node source, version 1.0.0.
// Package rpc provides RPC handling for the Quantaureum blockchain.
//
// =============================================================================
// SHARED INTERFACE WARNING - DO NOT MODIFY WITHOUT SYNCING WITH WALLET
// =============================================================================
// This file implements SHARED SIGNATURE PARSING with Quantaureum Wallet
// (app/scripts/lib/signature/quantum-signature.ts).
// The |QUANTUM| delimiter format MUST be supported by both sides.
//
// Signature encoding format (Wallet -> Core):
//
//	0x{ecdsaCompatSignatureHex}|QUANTUM|{quantumSignatureHex}:{quantumPublicKeyHex}
//
// Where:
//   - ecdsaCompatSignature: 65 bytes (r:32 + s:32 + v:1) for compatibility
//   - quantumSignature: 3293 bytes (Dilithium3 signature)
//   - quantumPublicKey: 1952 bytes (Dilithium3 public key)
//   - Delimiter: |QUANTUM| (unique, cannot appear in hex output)
//
// Wallet implementation: the quantaureum-wallet repo
// =============================================================================
package rpc

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/quantaureum/qau/crypto"
)

const (
	// QuantumDelimiter is the unique delimiter used to separate ECDSA-compatible
	// signature from quantum signature data. This delimiter cannot appear in hex
	// output (hex only uses 0-9a-f), making it unambiguous.
	QuantumDelimiter = "|QUANTUM|"

	// LegacyQuantumMarker is the old delimiter format for backward compatibility
	LegacyQuantumMarker = "QUANTUM:"
)

var (
	// ErrNoQuantumData is returned when no quantum data is found in signature
	ErrNoQuantumData = errors.New("no quantum signature data found")

	// ErrInvalidQuantumDataFormat is returned when quantum data format is invalid
	ErrInvalidQuantumDataFormat = errors.New("invalid quantum signature data format")

	// ErrInvalidSignatureLength is returned when signature length is invalid
	ErrInvalidSignatureLength = errors.New("invalid quantum signature length")

	// ErrInvalidPublicKeyLength is returned when public key length is invalid
	ErrInvalidPublicKeyLength = errors.New("invalid quantum public key length")
)

// QuantumSignatureData holds the extracted quantum signature components
type QuantumSignatureData struct {
	// HasQuantumData indicates whether quantum data was found
	HasQuantumData bool

	// EcdsaCompatSignature is the ECDSA-compatible signature (r||s||v)
	EcdsaCompatSignature []byte

	// QuantumSignature is the Dilithium3 signature (3293 bytes)
	QuantumSignature []byte

	// QuantumPublicKey is the Dilithium3 public key (1952 bytes)
	QuantumPublicKey []byte

	// Version is the signature format version for backward compatibility
	// Version history:
	//   "1.0" - Initial format (LEGACY, QUANTUM: delimiter)
	//   "2.0" - Current format with |QUANTUM| delimiter
	// Wallet implementation: the quantaureum-wallet repo
	Version string
}

// ExtractQuantumDataFromSignature extracts quantum signature data from a
// combined signature string that uses the |QUANTUM| delimiter format.
//
// This function supports both formats:
//   - New format: 0x{ecdsaHex}|QUANTUM|{sigHex}:{pkHex}
//   - Legacy format: 0x{ecdsaHex}QUANTUM:{sigHex}:{pkHex}
//
// The function validates that extracted signatures match expected Dilithium3 sizes.
func ExtractQuantumDataFromSignature(signature string) (*QuantumSignatureData, error) {
	result := &QuantumSignatureData{
		HasQuantumData: false,
	}

	if signature == "" {
		return result, ErrNoQuantumData
	}

	// Remove 0x prefix if present
	sig := strings.TrimPrefix(signature, "0x")

	// Find the delimiter position
	var dataStart int
	delimiterFound := false
	isNewFormat := false

	if idx := strings.Index(sig, QuantumDelimiter); idx != -1 {
		result.EcdsaCompatSignature = decodeHex(sig[:idx])
		dataStart = idx + len(QuantumDelimiter)
		delimiterFound = true
		isNewFormat = true
	} else if idx := strings.Index(sig, LegacyQuantumMarker); idx != -1 {
		// audit-fix P5-L8: Use exact-case match instead of ToUpper to avoid
		// misinterpreting hex data that happens to contain "QUANTUM:" after
		// uppercasing. The legacy marker is always emitted in uppercase by the
		// wallet, so a case-sensitive search is both correct and safer.
		result.EcdsaCompatSignature = decodeHex(sig[:idx])
		dataStart = idx + len(LegacyQuantumMarker)
		delimiterFound = true
		isNewFormat = false
	}

	if !delimiterFound {
		return result, ErrNoQuantumData
	}

	// audit-fix P5-L8: Validate ECDSA-compatible signature length.
	// The ECDSA compat portion must be exactly 65 bytes (r:32 + s:32 + v:1).
	// Rejecting incorrect lengths early prevents downstream parsing errors.
	if len(result.EcdsaCompatSignature) != 0 && len(result.EcdsaCompatSignature) != 65 {
		return result, ErrInvalidQuantumDataFormat
	}

	// Parse the quantum data part: {sigHex}:{pkHex}
	quantumData := sig[dataStart:]
	parts := strings.Split(quantumData, ":")
	if len(parts) != 2 {
		return result, ErrInvalidQuantumDataFormat
	}

	// Decode quantum signature
	sigBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return result, ErrInvalidQuantumDataFormat
	}

	// Decode quantum public key
	pkBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return result, ErrInvalidQuantumDataFormat
	}

	// Validate lengths match expected Dilithium3 parameters
	if len(sigBytes) != crypto.Dilithium3SignatureSize {
		return result, ErrInvalidSignatureLength
	}
	if len(pkBytes) != crypto.Dilithium3PublicKeySize {
		return result, ErrInvalidPublicKeyLength
	}

	result.HasQuantumData = true
	result.QuantumSignature = sigBytes
	result.QuantumPublicKey = pkBytes

	// Set version based on delimiter type
	if isNewFormat {
		result.Version = "2.0" // New format with |QUANTUM| delimiter
	} else {
		result.Version = "1.0" // Legacy format with QUANTUM: marker
	}

	return result, nil
}

// HasQuantumSignature checks if a signature contains quantum data
func HasQuantumSignature(signature string) bool {
	data, err := ExtractQuantumDataFromSignature(signature)
	return err == nil && data.HasQuantumData
}

// decodeHex safely decodes a hex string, returning nil on error
func decodeHex(s string) []byte {
	// Remove 0x prefix if present
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// EncodeQuantumSignature creates the combined signature format with |QUANTUM| delimiter.
// This is the Core-side implementation matching the Wallet's encodeQuantumSignature.
func EncodeQuantumSignature(
	quantumSignature []byte,
	quantumPublicKey []byte,
	ecdsaCompatSignature []byte,
) string {
	return "0x" +
		hex.EncodeToString(ecdsaCompatSignature) +
		QuantumDelimiter +
		hex.EncodeToString(quantumSignature) +
		":" +
		hex.EncodeToString(quantumPublicKey)
}

// Quantaureum Node source, version 1.0.0.
package log

import (
	"regexp"
	"strings"
)

// sensitiveFieldPatterns matches field keys that contain sensitive data.
// When a field key matches any of these patterns, its value is redacted.
var sensitiveFieldPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^private[_-]?key$`),
	regexp.MustCompile(`(?i)^secret[_-]?key$`),
	// L6-052 FIX: publicKey is intentionally NOT redacted. Public keys are, by
	// definition, public (Dilithium3 1952-byte pubkeys, Kyber768 pubkeys, BLS
	// pubkeys, validator pubkey hex). Redacting them makes logs useless for
	// debugging validator identity, attestation/aggregate verification, and
	// peer correlation. Only PRIVATE keys and secrets are redacted. Do NOT
	// re-add publicKey here.
	regexp.MustCompile(`(?i)^password$`),
	regexp.MustCompile(`(?i)^passphrase$`),
	regexp.MustCompile(`(?i)^secret$`),
	regexp.MustCompile(`(?i)^token$`),
	regexp.MustCompile(`(?i)^api[_-]?key$`),
	regexp.MustCompile(`(?i)^auth[_-]?token$`),
	regexp.MustCompile(`(?i)^access[_-]?token$`),
	regexp.MustCompile(`(?i)^refresh[_-]?token$`),
	regexp.MustCompile(`(?i)^mnemonic$`),
	regexp.MustCompile(`(?i)^seed$`),
	regexp.MustCompile(`(?i)^credentials?$`),
	regexp.MustCompile(`(?i)^authorization$`),
	regexp.MustCompile(`(?i)^cookie$`),
	regexp.MustCompile(`(?i)^encryption[_-]?passphrase$`),
	regexp.MustCompile(`(?i)^encryption[_-]?key$`),
	// L12-037 [P3] FIX: 'signer' fields may contain signing key material.
	regexp.MustCompile(`(?i)^signer$`),
	regexp.MustCompile(`(?i)^signer[_-]?key$`),
}

// sensitiveValuePatterns matches values that look like sensitive data
// (e.g., hex-encoded private keys, BIP-39 mnemonic fragments).
//
// L9-054 NOTE: The 64+ hex char pattern below intentionally has false positives:
// it also matches public data such as transaction hashes (64 hex chars),
// block hashes (64 hex chars), Dilithium3 public keys (3904 hex chars), and
// Dilithium3 signatures (6586 hex chars). This is an acceptable trade-off for
// security - it is better to over-redact a public hash than to leak a private
// key. To mitigate the debugging impact, publicHexFields (below) lists field
// keys whose values are known to contain public hex data and skips value-level
// sanitization for those fields.
var sensitiveValuePatterns = []*regexp.Regexp{
	// Long hex strings (64+ chars) that look like private keys or secrets.
	//
	// L11-038 /  \b word-boundary limitation. \b only fires at transitions
	// between word chars and non-word chars. 0x-prefixed values are covered by
	// the second pattern below (L18-024 fix). For non-0x-prefixed hex values
	// embedded in word-character contexts (rare in practice), the \b pattern
	// may not match. This is acceptable because:
	// 1) Private keys in Quantaureum are always 0x-prefixed or standalone hex
	// 2) The field-level sanitization (sensitiveFieldNames) catches key field names
	// 3) The 64+ char threshold is high enough to avoid false positives on short hex
	regexp.MustCompile(`\b[0-9a-fA-F]{64,}\b`),
	// L18-024 / FIX: Also match 0x/0X-prefixed hex strings (64+ chars).
	// \b word boundary does not fire between x and the first hex char
	// (both are word chars), so 0x-prefixed private keys slip through.
	regexp.MustCompile(`0[xX][0-9a-fA-F]{64,}`),
	// Base64-encoded data that could be keys/tokens (44+ chars with padding)
	regexp.MustCompile(`\b[A-Za-z0-9+/]{40,}={0,2}\b`),
}

// redactedValue is the replacement for sensitive field values.
const redactedValue = "[REDACTED]"

// SanitizeString redacts sensitive information from a log message string.
// It scans for patterns that resemble private keys, tokens, and other secrets.
func SanitizeString(s string) string {
	for _, pat := range sensitiveValuePatterns {
		s = pat.ReplaceAllString(s, redactedValue)
	}
	return s
}

// publicHexFields lists field keys whose values are known to contain public
// hex data (hashes, public keys, signatures). Values for these keys are
// exempt from value-level sanitization (SanitizeString) to preserve debugging
// utility, while still being subject to field-level redaction if the key
// itself matches a sensitive pattern.
//
// L9-054 FIX: prevents false-positive redaction of public data that
// SanitizeString's broad hex pattern would otherwise redact.
var publicHexFields = map[string]bool{
	"hash":          true,
	"txHash":        true,
	"tx_hash":       true,
	"blockHash":     true,
	"block_hash":    true,
	"parentHash":    true,
	"parent_hash":   true,
	"stateRoot":     true,
	"state_root":    true,
	"txRoot":        true,
	"tx_root":       true,
	"receiptRoot":   true,
	"receipt_root":  true,
	"publicKey":     true,
	"public_key":    true,
	"pubkey":        true,
	"signature":     true,
	"sig":           true,
	"vrfProof":      true,
	"vrf_proof":     true,
	"vrfValue":      true,
	"vrf_value":     true,
	"qtdSignature":  true,
	"qtd_signature": true,
	"attestations":  true,
	"nullifier":     true,
	"commitment":    true,
	// N19-008 FIX: Added missing public hex fields that were absent from the
	// whitelist, causing false-positive redaction of public blockchain data
	// (block header roots, logs bloom, transaction input data, etc.) in logs.
	// Block header roots (32 bytes = 64 hex chars, matches sensitive value pattern)
	"transactionsRoot":  true,
	"transactions_root": true,
	"receiptsRoot":      true, // JSON field name has trailing 's' (was missing)
	"receipts_root":     true,
	"logsBloom":         true, // 256 bytes = 512 hex chars (was missing!)
	"logs_bloom":        true,
	"bloom":             true,
	"extraData":         true,
	"extra_data":        true,
	"mixHash":           true,
	"mix_hash":          true,
	"prevRandao":        true,
	"prev_randao":       true,
	"withdrawalsRoot":   true,
	"withdrawals_root":  true,
	"uncleHash":         true,
	"uncle_hash":        true,
	"sha3Uncles":        true,
	"sha3_uncles":       true,
	"beaconRoot":        true,
	"beacon_root":       true,
	"requestsHash":      true,
	"requests_hash":     true,
	"root":              true, // state root alias
	"ommerHash":         true,
	"ommer_hash":        true,
	// Transaction data fields (variable length, can be 64+ hex chars)
	"input": true,
	"data":  true,
}

// SanitizeFields redacts values for field keys that match sensitive patterns.
// The original map is not modified; a new map is returned.
func SanitizeFields(fields map[string]any) map[string]any {
	if fields == nil {
		return nil
	}

	sanitized := make(map[string]any, len(fields))
	for k, v := range fields {
		// L14-039/L15-041 FIX: Sanitize field keys to prevent sensitive data
		// leakage through crafted key names.
		k = SanitizeString(k)
		if isSensitiveFieldKey(k) {
			sanitized[k] = redactedValue
		} else {
			// L9-054 FIX: Skip value-level sanitization for known public hex fields
			// to prevent false-positive redaction of hashes, public keys, and signatures.
			if publicHexFields[k] {
				sanitized[k] = v
			} else if strVal, ok := v.(string); ok {
				// Also sanitize string values in case they contain leaked secrets
				sanitized[k] = SanitizeString(strVal)
			} else {
				sanitized[k] = v
			}
		}
	}
	return sanitized
}

// isSensitiveFieldKey returns true if the field key name suggests
// the value is sensitive and should be redacted.
func isSensitiveFieldKey(key string) bool {
	// Normalize key: replace dots and dashes with underscores for matching
	normalized := strings.ReplaceAll(key, ".", "_")
	normalized = strings.ReplaceAll(normalized, "-", "_")

	for _, pat := range sensitiveFieldPatterns {
		if pat.MatchString(normalized) {
			return true
		}
	}

	// Also check common substrings
	lower := strings.ToLower(key)
	sensitiveSubstrings := []string{
		"private_key",
		"privatekey",
		"secret_key",
		"secretkey",
		"password",
		"passphrase",
		"mnemonic",
		"api_key",
		"apikey",
		"auth_token",
		"accesstoken",
		"refresh_token",
		"refreshtoken",
		"signer_key",
		"signerkey",
	}
	for _, sub := range sensitiveSubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}

	return false
}

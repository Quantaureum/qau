// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestCRYPTO_R12003_DomainLengthPrefixPresent verifies the encoding starts
// with a 4-byte big-endian uint32 equal to len(domain). This is the core
// CRYPTO-R12-003 fix: the encoding must be self-describing.
func TestCRYPTO_R12003_DomainLengthPrefixPresent(t *testing.T) {
	domain := []byte("QUANTAUREUM_VOTE")
	message := []byte("hello world")

	encoded := buildDomainSeparatedMessage(domain, message)

	if len(encoded) < 4 {
		t.Fatalf("encoded too short: %d bytes", len(encoded))
	}

	gotDomainLen := binary.BigEndian.Uint32(encoded[:4])
	if gotDomainLen != uint32(len(domain)) {
		t.Errorf("domain length prefix = %d, want %d", gotDomainLen, len(domain))
	}

	// After the 4-byte length prefix, the next `len(domain)` bytes must
	// equal the domain itself.
	if !bytes.Equal(encoded[4:4+len(domain)], domain) {
		t.Errorf("domain bytes mismatch: got %x, want %x", encoded[4:4+len(domain)], domain)
	}
}

// TestCRYPTO_R12003_MessageLengthPrefixPresent verifies the message
// length prefix immediately follows the domain bytes, and is also a
// 4-byte big-endian uint32. The original encoding already had this
// prefix; the CRYPTO-R12-003 fix adds the symmetric domain length
// prefix without removing the message length prefix.
func TestCRYPTO_R12003_MessageLengthPrefixPresent(t *testing.T) {
	domain := []byte("DOMAIN")
	message := []byte("MESSAGE")

	encoded := buildDomainSeparatedMessage(domain, message)

	// Layout: [4:domainLen][domain][4:msgLen][message]
	domainEnd := 4 + len(domain)
	if len(encoded) < domainEnd+4 {
		t.Fatalf("encoded too short for message length prefix: %d bytes", len(encoded))
	}

	gotMsgLen := binary.BigEndian.Uint32(encoded[domainEnd : domainEnd+4])
	if gotMsgLen != uint32(len(message)) {
		t.Errorf("message length prefix = %d, want %d", gotMsgLen, len(message))
	}

	msgStart := domainEnd + 4
	if !bytes.Equal(encoded[msgStart:msgStart+len(message)], message) {
		t.Errorf("message bytes mismatch: got %x, want %x",
			encoded[msgStart:msgStart+len(message)], message)
	}
}

// TestCRYPTO_R12003_DifferentDomainsProduceDifferentEncodings proves the
// core security property: two different domains over the same message
// produce different encodings. Without this, a signature over one domain
// could be replayed as a signature over another.
func TestCRYPTO_R12003_DifferentDomainsProduceDifferentEncodings(t *testing.T) {
	msg := []byte("common message")

	enc1 := buildDomainSeparatedMessage([]byte("DOMAIN_A"), msg)
	enc2 := buildDomainSeparatedMessage([]byte("DOMAIN_B"), msg)

	if bytes.Equal(enc1, enc2) {
		t.Error("CRYPTO-R12-003 FAILURE: different domains produced identical encodings; cross-domain signature reuse possible")
	}
}

// TestCRYPTO_R12003_DifferentMessagesProduceDifferentEncodings verifies
// the symmetric case: same domain, different messages → different encodings.
func TestCRYPTO_R12003_DifferentMessagesProduceDifferentEncodings(t *testing.T) {
	domain := []byte("DOMAIN")

	enc1 := buildDomainSeparatedMessage(domain, []byte("message_a"))
	enc2 := buildDomainSeparatedMessage(domain, []byte("message_b"))

	if bytes.Equal(enc1, enc2) {
		t.Error("different messages produced identical encodings")
	}
}

// TestCRYPTO_R12003_NoConcatAmbiguity proves the central CRYPTO-R12-003
// property: there are no two (domain, message) pairs whose encodings are
// byte-equal. We construct a specific adversarial pair that the OLD
// encoding (domain || len(message) || message) could not distinguish
// from a different pair, and prove the NEW encoding distinguishes them.
//
// Adversarial example for the OLD encoding:
//
//	pair1: domain="AB", message="CD"        → "AB\x00\x00\x00\x02CD"
//	pair2: domain="ABCD", message=""        → "ABCD\x00\x00\x00\x00"
//
// These differ in bytes, but consider:
//
//	pair3: domain="AB\x00\x00\x00\x02CD", message="" → "AB\x00\x00\x00\x02CD\x00\x00\x00\x00"
//	pair4: domain="AB", message="\x00\x00\x00\x02CD" → "AB\x00\x00\x00\x06\x00\x00\x00\x02CD"
//
// These also differ in the OLD encoding. The real ambiguity is the lack
// of self-description: a decoder without out-of-band domain length
// knowledge can misparse. The NEW encoding is self-describing: we prove
// this by parsing the encoded bytes back into (domain, message) and
// confirming the result matches the input.
func TestCRYPTO_R12003_NoConcatAmbiguity(t *testing.T) {
	cases := []struct {
		name    string
		domain  []byte
		message []byte
	}{
		{"empty_domain", []byte(""), []byte("msg")},
		{"empty_message", []byte("domain"), []byte("")},
		{"both_empty", []byte(""), []byte("")},
		{"domain_has_length_bytes", []byte("\x00\x00\x00\x05fake"), []byte("real")},
		{"message_has_length_bytes", []byte("domain"), []byte("\x00\x00\x00\x05fake")},
		{"domain_equals_message", []byte("XYZ"), []byte("XYZ")},
		{"long_pair", bytes.Repeat([]byte("A"), 100), bytes.Repeat([]byte("B"), 100)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := buildDomainSeparatedMessage(tc.domain, tc.message)

			// Parse it back: 4-byte domain len, domain, 4-byte msg len, msg.
			if len(encoded) < 4 {
				t.Fatalf("encoded too short: %d", len(encoded))
			}
			domainLen := binary.BigEndian.Uint32(encoded[:4])
			if int(domainLen) != len(tc.domain) {
				t.Errorf("parsed domain length = %d, want %d", domainLen, len(tc.domain))
				return
			}
			domainEnd := 4 + int(domainLen)
			if len(encoded) < domainEnd+4 {
				t.Fatalf("encoded truncated after domain: %d bytes", len(encoded))
			}
			parsedDomain := encoded[4:domainEnd]
			if !bytes.Equal(parsedDomain, tc.domain) {
				t.Errorf("parsed domain = %x, want %x", parsedDomain, tc.domain)
			}
			msgLen := binary.BigEndian.Uint32(encoded[domainEnd : domainEnd+4])
			if int(msgLen) != len(tc.message) {
				t.Errorf("parsed message length = %d, want %d", msgLen, len(tc.message))
				return
			}
			msgStart := domainEnd + 4
			if len(encoded) < msgStart+int(msgLen) {
				t.Fatalf("encoded truncated after message length: %d bytes", len(encoded))
			}
			parsedMsg := encoded[msgStart : msgStart+int(msgLen)]
			if !bytes.Equal(parsedMsg, tc.message) {
				t.Errorf("parsed message = %x, want %x", parsedMsg, tc.message)
			}
			// Ensure no trailing bytes.
			if len(encoded) != msgStart+int(msgLen) {
				t.Errorf("encoded has %d trailing bytes", len(encoded)-(msgStart+int(msgLen)))
			}
		})
	}
}

// TestCRYPTO_R12003_SignVerifyWithDomainRoundTrip verifies that a signature
// created with SignWithDomain verifies correctly with VerifyWithDomain.
// This is the end-to-end regression guard: any encoding mismatch between
// Sign and Verify would silently invalidate every domain-separated signature.
func TestCRYPTO_R12003_SignVerifyWithDomainRoundTrip(t *testing.T) {
	// Generate a real Dilithium3 key pair for this test.
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	priv := kp.Private

	domain := []byte("QUANTAUREUM_TEST_DOMAIN")
	message := []byte("the quick brown fox jumps over the lazy dog")

	sig, err := SignWithDomain(priv, domain, message)
	if err != nil {
		t.Fatalf("SignWithDomain failed: %v", err)
	}
	if len(sig) != Dilithium3SignatureSize {
		t.Errorf("signature size = %d, want %d", len(sig), Dilithium3SignatureSize)
	}

	pub := priv.PublicKey()
	if !VerifyWithDomain(pub, domain, message, sig) {
		t.Error("VerifyWithDomain returned false for valid signature")
	}

	// Different domain → must fail.
	if VerifyWithDomain(pub, []byte("WRONG_DOMAIN"), message, sig) {
		t.Error("VerifyWithDomain returned true for wrong domain (cross-domain replay possible)")
	}

	// Different message → must fail.
	if VerifyWithDomain(pub, domain, []byte("wrong message"), sig) {
		t.Error("VerifyWithDomain returned true for wrong message")
	}

	// Tampered signature → must fail.
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 0xFF
	if VerifyWithDomain(pub, domain, message, tampered) {
		t.Error("VerifyWithDomain returned true for tampered signature")
	}
}

// TestCRYPTO_R12003_EmptyInputsAreSafe verifies the encoding handles
// empty domain and empty message without crashing or producing
// ambiguous output. The CRYPTO-R12-003 fix must not regress on edge cases.
func TestCRYPTO_R12003_EmptyInputsAreSafe(t *testing.T) {
	enc := buildDomainSeparatedMessage(nil, nil)
	if len(enc) != 8 {
		t.Errorf("nil+nil encoding = %d bytes, want 8 (two zero length prefixes)", len(enc))
	}
	if !bytes.Equal(enc, []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("nil+nil encoding = %x, want 8 zero bytes", enc)
	}

	// Empty domain, non-empty message.
	enc2 := buildDomainSeparatedMessage(nil, []byte("X"))
	if len(enc2) != 9 {
		t.Errorf("empty domain encoding = %d bytes, want 9", len(enc2))
	}

	// Non-empty domain, empty message.
	enc3 := buildDomainSeparatedMessage([]byte("X"), nil)
	if len(enc3) != 9 {
		t.Errorf("empty message encoding = %d bytes, want 9", len(enc3))
	}

	// The two encodings above must differ (different field positions).
	if bytes.Equal(enc2, enc3) {
		t.Error("empty domain + 'X' message collides with 'X' domain + empty message")
	}
}

// TestCRYPTO_R12003_TotalLengthMatchesPrefixSum verifies the encoded
// total length equals 4 + len(domain) + 4 + len(message). This catches
// any off-by-one in the buffer sizing.
func TestCRYPTO_R12003_TotalLengthMatchesPrefixSum(t *testing.T) {
	domain := []byte("DOMAIN")
	message := []byte("MESSAGE")
	encoded := buildDomainSeparatedMessage(domain, message)

	expectedLen := 4 + len(domain) + 4 + len(message)
	if len(encoded) != expectedLen {
		t.Errorf("encoded length = %d, want %d", len(encoded), expectedLen)
	}
}

// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"
)

// signCAOperation produces a low-s ECDSA signature over the CA operation
// payload, matching the production signing format. Used by R19 tests.
func signCAOperation(t *testing.T, priv *ecdsa.PrivateKey, domain []byte, timestamp int64, target string) []byte {
	t.Helper()
	payload := caOperationPayload(domain, timestamp, target)
	hash := sha3.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign failed: %v", err)
	}
	// Force low-s
	curveParams := priv.Curve.Params()
	halfN := new(big.Int).Rsh(curveParams.N, 1)
	if s.Cmp(halfN) > 0 {
		s.Sub(curveParams.N, s)
	}
	sig, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		t.Fatalf("asn1.Marshal failed: %v", err)
	}
	return sig
}

// signCAOperationHighS produces a HIGH-s signature (non-normalized) for
// testing that ecdsaVerifyLowS correctly rejects it.
func signCAOperationHighS(t *testing.T, priv *ecdsa.PrivateKey, domain []byte, timestamp int64, target string) []byte {
	t.Helper()
	payload := caOperationPayload(domain, timestamp, target)
	hash := sha3.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign failed: %v", err)
	}
	// Force HIGH-s (opposite of low-s normalization)
	curveParams := priv.Curve.Params()
	halfN := new(big.Int).Rsh(curveParams.N, 1)
	if s.Cmp(halfN) <= 0 {
		s.Sub(curveParams.N, s)
	}
	sig, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		t.Fatalf("asn1.Marshal failed: %v", err)
	}
	return sig
}

// setupNCMWithCAs creates a NodeCertificateManager with both Root and
// Intermediate CAs for testing CA signature verification paths.
func setupNCMWithCAs(t *testing.T) (*NodeCertificateManager, *ecdsa.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()
	nodeID, err := NewPeerID()
	if err != nil {
		t.Fatalf("NewPeerID: %v", err)
	}
	rootCA, err := GenerateRootCA()
	if err != nil {
		t.Fatalf("GenerateRootCA: %v", err)
	}
	intermediateCA, err := GenerateIntermediateCA(rootCA)
	if err != nil {
		t.Fatalf("GenerateIntermediateCA: %v", err)
	}
	ncm, err := NewNodeCertificateManager("", "", nodeID, intermediateCA, rootCA.CertPEM)
	if err != nil {
		t.Fatalf("NewNodeCertificateManager: %v", err)
	}
	return ncm, rootCA.PrivateKey, intermediateCA.PrivateKey
}

// TestCRYPTO_R19_CRIT01_Revoke_FreshnessWindow verifies that the ±5-minute
// freshness check rejects signatures with timestamps outside the window.
func TestCRYPTO_R19_CRIT01_Revoke_FreshnessWindow(t *testing.T) {
	ncm, _, intermediateKey := setupNCMWithCAs(t)
	// DO NOT call SkipCASignatureForTesting — we want the production path.

	// Case 1: Valid timestamp (now) → should succeed.
	now := time.Now().Unix()
	sig := signCAOperation(t, intermediateKey, caRevokeDomainSeparator, now, "serial-123")
	if err := ncm.RevokeCertificate("serial-123", now, sig); err != nil {
		t.Errorf("valid timestamp should succeed: %v", err)
	}

	// Case 2: Timestamp too old (10 minutes ago) → should fail.
	old := now - 600
	sigOld := signCAOperation(t, intermediateKey, caRevokeDomainSeparator, old, "serial-456")
	if err := ncm.RevokeCertificate("serial-456", old, sigOld); err == nil {
		t.Error("expired timestamp should be rejected")
	}

	// Case 3: Timestamp too far in the future (10 minutes ahead) → should fail.
	future := now + 600
	sigFuture := signCAOperation(t, intermediateKey, caRevokeDomainSeparator, future, "serial-789")
	if err := ncm.RevokeCertificate("serial-789", future, sigFuture); err == nil {
		t.Error("future timestamp should be rejected")
	}
}

// TestCRYPTO_R19_CRIT01_Unpin_FreshnessWindow verifies freshness on Unpin.
func TestCRYPTO_R19_CRIT01_Unpin_FreshnessWindow(t *testing.T) {
	ncm, _, intermediateKey := setupNCMWithCAs(t)

	now := time.Now().Unix()
	peerID := PeerID("test-peer-id")

	// Valid timestamp → should succeed (signature verified, pin removed).
	sig := signCAOperation(t, intermediateKey, caUnpinDomainSeparator, now, string(peerID))
	if err := ncm.UnpinPeerPublicKey(peerID, now, sig); err != nil {
		t.Errorf("valid timestamp should succeed: %v", err)
	}

	// Expired timestamp → should fail.
	old := now - 600
	sigOld := signCAOperation(t, intermediateKey, caUnpinDomainSeparator, old, string(peerID))
	if err := ncm.UnpinPeerPublicKey(peerID, old, sigOld); err == nil {
		t.Error("expired timestamp should be rejected")
	}
}

// TestCRYPTO_R19_CRIT01_Revoke_ReplayPrevention verifies that a valid
// signature cannot be replayed after the freshness window expires.
func TestCRYPTO_R19_CRIT01_Revoke_ReplayPrevention(t *testing.T) {
	ncm, _, intermediateKey := setupNCMWithCAs(t)

	// Sign at time T.
	t1 := time.Now().Unix()
	sig := signCAOperation(t, intermediateKey, caRevokeDomainSeparator, t1, "serial-replay")

	// First use at T → succeeds.
	if err := ncm.RevokeCertificate("serial-replay", t1, sig); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}

	// Replay at T+600 (outside window) → must fail.
	if err := ncm.RevokeCertificate("serial-replay2", t1, sig); err == nil {
		t.Error("replay with old timestamp should be rejected")
	}
}

// TestCRYPTO_R19_CRIT01_CrossDomainReplay verifies that a Revoke signature
// cannot be replayed as an Unpin operation (domain separation).
func TestCRYPTO_R19_CRIT01_CrossDomainReplay(t *testing.T) {
	ncm, _, intermediateKey := setupNCMWithCAs(t)

	now := time.Now().Unix()
	// Sign a Revoke payload.
	revokeSig := signCAOperation(t, intermediateKey, caRevokeDomainSeparator, now, "serial-x")
	// Try to use it as an Unpin signature → must fail (different domain).
	if err := ncm.UnpinPeerPublicKey(PeerID("serial-x"), now, revokeSig); err == nil {
		t.Error("Revoke signature must not be valid for Unpin (domain separation)")
	}
}

// TestCRYPTO_R19_CRIT03_LowS_Enforcement verifies that high-s signatures
// are rejected by ecdsaVerifyLowS.
func TestCRYPTO_R19_CRIT03_LowS_Enforcement(t *testing.T) {
	ncm, _, intermediateKey := setupNCMWithCAs(t)

	now := time.Now().Unix()

	// Low-s signature → should succeed.
	sigLow := signCAOperation(t, intermediateKey, caRevokeDomainSeparator, now, "serial-lows")
	if err := ncm.RevokeCertificate("serial-lows", now, sigLow); err != nil {
		t.Errorf("low-s signature should succeed: %v", err)
	}

	// High-s signature → must be rejected.
	sigHigh := signCAOperationHighS(t, intermediateKey, caRevokeDomainSeparator, now, "serial-highs")
	if err := ncm.RevokeCertificate("serial-highs", now, sigHigh); err == nil {
		t.Error("high-s signature must be rejected (CRYPTO-R19-CRIT-03)")
	}
}

// TestCRYPTO_R19_M01_RootCA_Rejected verifies that Root CA signatures are
// rejected for daily Revoke/Unpin operations (only Intermediate CA allowed).
func TestCRYPTO_R19_M01_RootCA_Rejected(t *testing.T) {
	ncm, rootKey, _ := setupNCMWithCAs(t)

	now := time.Now().Unix()

	// Root CA signature on Revoke → must be rejected.
	sigRoot := signCAOperation(t, rootKey, caRevokeDomainSeparator, now, "serial-root")
	if err := ncm.RevokeCertificate("serial-root", now, sigRoot); err == nil {
		t.Error("Root CA signature must be rejected for Revoke (CRYPTO-R19-M01)")
	}

	// Root CA signature on Unpin → must be rejected.
	sigRootUnpin := signCAOperation(t, rootKey, caUnpinDomainSeparator, now, "peer-root")
	if err := ncm.UnpinPeerPublicKey(PeerID("peer-root"), now, sigRootUnpin); err == nil {
		t.Error("Root CA signature must be rejected for Unpin (CRYPTO-R19-M01)")
	}
}

// TestCRYPTO_R19_CRIT03_ecdsaVerifyLowS_RejectsHighS directly tests the
// helper function with a known high-s signature.
func TestCRYPTO_R19_CRIT03_ecdsaVerifyLowS_RejectsHighS(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("test message")
	hash := sha3.Sum256(msg)

	// Produce high-s signature.
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	halfN := new(big.Int).Rsh(priv.Curve.Params().N, 1)
	if s.Cmp(halfN) <= 0 {
		s.Sub(priv.Curve.Params().N, s)
	}
	highSig, _ := asn1.Marshal(ecdsaSignature{r, s})

	if ecdsaVerifyLowS(&priv.PublicKey, hash[:], highSig) {
		t.Error("ecdsaVerifyLowS must reject high-s signature")
	}

	// Produce low-s signature.
	r2, s2, _ := ecdsa.Sign(rand.Reader, priv, hash[:])
	if s2.Cmp(halfN) > 0 {
		s2.Sub(priv.Curve.Params().N, s2)
	}
	lowSig, _ := asn1.Marshal(ecdsaSignature{r2, s2})

	if !ecdsaVerifyLowS(&priv.PublicKey, hash[:], lowSig) {
		t.Error("ecdsaVerifyLowS must accept low-s signature")
	}
}

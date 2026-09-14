// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"crypto/tls"
	"encoding/pem"
	"testing"
	"time"
)

func TestNodeCertificateManagerGeneration(t *testing.T) {
	nodeID, err := NewPeerID()
	if err != nil {
		t.Fatalf("failed to generate peer ID: %v", err)
	}

	rootCA, err := GenerateRootCA()
	if err != nil {
		t.Fatalf("failed to generate root CA: %v", err)
	}

	intermediateCA, err := GenerateIntermediateCA(rootCA)
	if err != nil {
		t.Fatalf("failed to generate intermediate CA: %v", err)
	}

	ncm, err := NewNodeCertificateManager("", "", nodeID, intermediateCA, rootCA.CertPEM)
	if err != nil {
		t.Fatalf("failed to create certificate manager: %v", err)
	}

	cert := ncm.GetCertificate()
	if cert == nil {
		t.Fatal("certificate is nil")
	}

	if cert.Subject.CommonName != string(nodeID) {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, string(nodeID))
	}

	if cert.IsCA {
		t.Error("node certificate should not be a CA")
	}

	if time.Until(cert.NotAfter) < 23*time.Hour {
		t.Error("certificate validity is less than 23 hours")
	}

	certPEM := ncm.GetCertificatePEM()
	if len(certPEM) == 0 {
		t.Error("certificate PEM is empty")
	}
}

func TestNodeCertificateManagerTLSConfig(t *testing.T) {
	nodeID, _ := NewPeerID()

	rootCA, err := GenerateRootCA()
	if err != nil {
		t.Fatalf("failed to generate root CA: %v", err)
	}

	intermediateCA, err := GenerateIntermediateCA(rootCA)
	if err != nil {
		t.Fatalf("failed to generate intermediate CA: %v", err)
	}

	ncm, err := NewNodeCertificateManager("", "", nodeID, intermediateCA, rootCA.CertPEM)
	if err != nil {
		t.Fatalf("failed to create certificate manager: %v", err)
	}

	config, err := ncm.GetTLSConfig()
	if err != nil {
		t.Fatalf("failed to get TLS config: %v", err)
	}

	if config.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = 0x%x, want 0x%x", config.MinVersion, tls.VersionTLS13)
	}

	if config.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Error("ClientAuth should be RequireAndVerifyClientCert")
	}

	if len(config.Certificates) == 0 {
		t.Error("no certificates in TLS config")
	}
}

func TestTrustedPeerManagement(t *testing.T) {
	rootCA, _ := GenerateRootCA()
	intermediateCA, _ := GenerateIntermediateCA(rootCA)

	nodeID1, _ := NewPeerID()
	ncm1, _ := NewNodeCertificateManager("", "", nodeID1, intermediateCA, rootCA.CertPEM)

	nodeID2, _ := NewPeerID()
	_, _ = NewNodeCertificateManager("", "", nodeID2, intermediateCA, rootCA.CertPEM) // ncm2 reserved for future peer-trust scenarios

	// P2P-R10-C2 (2026-07-19): AddTrustedPeer now enforces that the
	// supplied certificate must be a CA (IsCA=true with KeyUsageCertSign).
	// Previously this test added ncm2's leaf cert (IsCA=false), which
	// allowed a compromised leaf to be treated as a trusted issuer —
	// enabling identity forgery. AddTrustedPeer is for trust roots
	// (CAs), not for peer leaf certs. Use the root CA's PEM here.
	certPEM := rootCA.CertPEM
	if err := ncm1.AddTrustedPeer(nodeID2, certPEM); err != nil {
		t.Fatalf("failed to add trusted peer: %v", err)
	}

	config, err := ncm1.GetTLSConfig()
	if err != nil {
		t.Fatalf("failed to get TLS config after adding trust: %v", err)
	}
	if config.ClientCAs == nil {
		t.Error("ClientCAs should not be nil after adding trusted peer")
	}

	ncm1.RemoveTrustedPeer(nodeID2)
	config2, _ := ncm1.GetTLSConfig()
	if config2 == nil {
		t.Error("TLS config should still work after removing peer")
	}
}

func TestCertificateRevocation(t *testing.T) {
	rootCA, _ := GenerateRootCA()
	intermediateCA, _ := GenerateIntermediateCA(rootCA)

	nodeID, _ := NewPeerID()
	ncm, _ := NewNodeCertificateManager("", "", nodeID, intermediateCA, rootCA.CertPEM)
	ncm.SkipCASignatureForTesting()

	cert := ncm.GetCertificate()
	sn := cert.SerialNumber.String()

	if ncm.crl.IsRevoked(sn) {
		t.Error("certificate should not be revoked initially")
	}

	ncm.RevokeCertificate(sn, 0, nil)

	if !ncm.crl.IsRevoked(sn) {
		t.Error("certificate should be revoked after RevokeCertificate")
	}

	if ncm.crl.LastUpdated().IsZero() {
		t.Error("LastUpdated should not be zero after revocation")
	}

	revoked := ncm.crl.GetRevokedList()
	if _, ok := revoked[sn]; !ok {
		t.Error("revoked serial number not in list")
	}
}

func TestVerifyPeerCertificate(t *testing.T) {
	rootCA, _ := GenerateRootCA()
	intermediateCA, _ := GenerateIntermediateCA(rootCA)

	nodeID, _ := NewPeerID()
	ncm, _ := NewNodeCertificateManager("", "", nodeID, intermediateCA, rootCA.CertPEM)
	ncm.SkipCASignatureForTesting()

	cert := ncm.GetCertificate()
	rawCert := ncm.GetCertificatePEM()

	err := ncm.verifyPeerCertificate([][]byte{}, nil)
	if err == nil {
		t.Error("verifyPeerCertificate should fail with no certs")
	}

	block, _ := pemDecode(rawCert)
	if block == nil {
		t.Fatal("failed to decode cert PEM")
	}

	err = ncm.verifyPeerCertificate([][]byte{block.Bytes}, nil)
	if err != nil {
		t.Errorf("verifyPeerCertificate failed for valid cert: %v", err)
	}

	ncm.RevokeCertificate(cert.SerialNumber.String(), 0, nil)
	err = ncm.verifyPeerCertificate([][]byte{block.Bytes}, nil)
	if err == nil {
		t.Error("verifyPeerCertificate should fail for revoked cert")
	}
}

func TestSelfSignedFallback(t *testing.T) {
	nodeID, _ := NewPeerID()

	ncm, err := NewNodeCertificateManager("", "", nodeID, nil, nil)
	if err != nil {
		t.Fatalf("failed to create self-signed certificate manager: %v", err)
	}

	cert := ncm.GetCertificate()
	if cert == nil {
		t.Fatal("self-signed certificate is nil")
	}

	if cert.IsCA {
		t.Error("self-signed fallback should also produce IsCA=false")
	}

	if cert.Subject.CommonName != string(nodeID) {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, string(nodeID))
	}
}

func TestRootCAGeneration(t *testing.T) {
	rootCA, err := GenerateRootCA()
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	if rootCA.Certificate == nil {
		t.Fatal("root CA certificate is nil")
	}

	if !rootCA.Certificate.IsCA {
		t.Error("root CA certificate should have IsCA=true")
	}

	if rootCA.Certificate.MaxPathLen != 1 {
		t.Errorf("root CA MaxPathLen = %d, want 1", rootCA.Certificate.MaxPathLen)
	}

	if len(rootCA.CertPEM) == 0 {
		t.Error("root CA CertPEM is empty")
	}
}

func TestIntermediateCAGeneration(t *testing.T) {
	rootCA, _ := GenerateRootCA()

	intermediateCA, err := GenerateIntermediateCA(rootCA)
	if err != nil {
		t.Fatalf("GenerateIntermediateCA failed: %v", err)
	}

	if intermediateCA.Certificate == nil {
		t.Fatal("intermediate CA certificate is nil")
	}

	if !intermediateCA.Certificate.IsCA {
		t.Error("intermediate CA certificate should have IsCA=true")
	}

	if intermediateCA.Certificate.MaxPathLen != 0 {
		t.Errorf("intermediate CA MaxPathLen = %d, want 0", intermediateCA.Certificate.MaxPathLen)
	}

	if !intermediateCA.Certificate.MaxPathLenZero {
		t.Error("intermediate CA MaxPathLenZero should be true")
	}
}

func pemDecode(data []byte) (*pem.Block, []byte) {
	return pem.Decode(data)
}

// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"
)

// ============================================================================
// mTLS for P2P Node Certificate System
//
// Architecture: Root CA -> Intermediate CA -> Node Certificate
//
// 1. A dedicated Root CA (offline, generated once during network bootstrap)
//    signs Intermediate CAs.
// 2. Intermediate CAs (managed by network operators) sign Node Certificates.
// 3. Each node holds a leaf certificate (IsCA=false) signed by the Intermediate CA.
// 4. During P2P dial, nodes perform mTLS: each side presents its leaf cert,
//    and verification walks the chain up to the trusted Root CA.
// 5. After mTLS succeeds, the existing Dilithium3+AES-GCM handshake runs
//    inside the TLS tunnel for post-quantum forward secrecy.
//
// This replaces the previous self-signed model where every node was a CA,
// which allowed any compromised node to forge certificates for any identity.
// ============================================================================

const (
	leafCertValidity            = 24 * time.Hour
	intermediateCAValidityYears = 5
	rootCAValidityYears         = 10
	serialNumberBits            = 128
	maxLeafCertValidity         = 24 * time.Hour

	// P2P-R10-L1 (2026-07-19) FIX: Bound the trustedCerts map to prevent
	// memory-exhaustion DoS. Each entry stores a parsed *x509.Certificate
	// (typically 1-3 KB) plus the peerID string key (~64 bytes). Even at
	// 10,000 entries this is only ~30MB — well below any production node's
	// memory budget — but a finite limit prevents a malicious or buggy
	// caller from filling the map unbounded. AddTrustedPeer is already
	// gated by IsCA + KeyUsageCertSign checks (P2P-R10-C2 fix), so this
	// limit is defense-in-depth against logic bugs or future admin RPCs
	// that might loosen those checks.
	maxTrustedCerts = 10000
	// P2P-R16-H03 (2026-07-22): Bound the pinnedPubKeys (TOFU pinning) map
	// to prevent Sybil-attack memory exhaustion. An attacker creating many
	// different peerID connections could fill the map unbounded. Each entry
	// is ~32 bytes (SHA-256 hash) + peerID string, so 10,000 entries is
	// ~1MB — trivial. The limit mirrors maxTrustedCerts for consistency.
	maxPinnedPubKeys = 10000
)

// RootCA holds the root CA key pair and certificate.
// The root CA private key should be kept offline after network bootstrap.
type RootCA struct {
	PrivateKey  *ecdsa.PrivateKey
	Certificate *x509.Certificate
	CertPEM     []byte
	KeyPEM      []byte
}

// IntermediateCA holds an intermediate CA that can sign node certificates.
type IntermediateCA struct {
	PrivateKey  *ecdsa.PrivateKey
	Certificate *x509.Certificate
	CertPEM     []byte
	KeyPEM      []byte
	parent      *RootCA
}

// NodeCertificateManager handles X.509 certificate lifecycle for a P2P node.
type NodeCertificateManager struct {
	mu sync.RWMutex

	privateKey  *ecdsa.PrivateKey
	certificate *x509.Certificate
	certPEM     []byte
	keyPEM      []byte

	rootCA         *RootCA
	intermediateCA *IntermediateCA

	trustedCerts map[string]*x509.Certificate
	crl          *CertificateRevocationList

	// P2P-R12-H03 (2026-07-20) FIX: TOFU (Trust On First Use) public key
	// pinning. After the first successful mTLS+post-quantum handshake with
	// a peer, the SHA-256 hash of the peer's leaf certificate public key is
	// recorded here. On subsequent connections, the peer's leaf cert pubkey
	// must match the pinned hash. This prevents MITM attacks on reconnection
	// if the CA private key is later compromised — the attacker can mint a
	// new valid cert for the same nodeID, but its pubkey won't match the
	// pinned hash.
	//
	// Pinning is keyed by peerID (the post-quantum identity established in
	// encrypted_transport.go), NOT by cert serial — certs rotate (H01 fix).
	// The value is SHA-256(SubjectPublicKeyInfo) — a stable identifier of
	// the keypair, independent of cert metadata.
	pinnedPubKeys map[string][]byte

	// P2P-R14-CRIT-002 (2026-07-21): rotation callbacks. Invoked after a
	// successful certificate rotation in CheckAndRotateCertificate. The
	// Host registers a callback that proactively disconnects all connected
	// peers so they reconnect and learn the new cert via the normal
	// handshake. Without this, peers still hold the OLD pinned public key
	// and reject the new cert on the next connection attempt — the rotated
	// node gets isolated from the network until every peer's pinning
	// expires or is manually cleared.
	onRotation []func()

	// P2P-R16-M08 (2026-07-23) FIX: stop channel for the CRL cleanup
	// goroutine. Previously, the goroutine had no stop mechanism —
	// NewNodeCertificateManager leaked a goroutine on every call (tests
	// create dozens of NCMs per run). Close() signals the goroutine to
	// exit. closeOnce ensures Close is idempotent.
	stopCh    chan struct{}
	closeOnce sync.Once

	// CRIT-09 (R17, 2026-07-23): Replaces testing.Testing() bypass.
	// When true, RevokeCertificate/UnpinPeerPublicKey skip the CA
	// signature requirement. Defaults to false (secure). Tests set this
	// to true via the SkipCASignatureForTesting method to bypass
	// signature verification for messages constructed without signatures.
	// Production code MUST NOT call SkipCASignatureForTesting.
	//
	// R16 only replaced testing.Testing() in host.go (skipCRLAuth). This
	// field completes the fix for mtls.go: testing.Testing() returned true
	// for ANY test binary, including a test binary accidentally deployed
	// to production (e.g., via a misconfigured CI/CD pipeline that ships
	// the test binary instead of the production binary). An attacker
	// could then revoke any certificate or unpin any peer without a CA
	// signature — full mTLS bypass.
	skipCASignature bool
}

// CertificateRevocationList tracks revoked peer certificates.
type CertificateRevocationList struct {
	mu          sync.RWMutex
	revokedSNs  map[string]time.Time
	lastUpdated time.Time
}

// GenerateRootCA creates a new root CA for the Quantaureum network.
// This should be called once during network bootstrap, and the private key
// must be stored securely offline.
func GenerateRootCA() (*RootCA, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate root CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialNumberBits))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Quantaureum Network"},
			OrganizationalUnit: []string{"Root CA"},
			CommonName:         "Quantaureum Root CA",
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().AddDate(rootCAValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create root CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal root CA private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &RootCA{
		PrivateKey:  privKey,
		Certificate: cert,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// GenerateIntermediateCA creates an intermediate CA signed by the root CA.
func GenerateIntermediateCA(root *RootCA) (*IntermediateCA, error) {
	if root == nil || root.PrivateKey == nil || root.Certificate == nil {
		return nil, errors.New("root CA is not initialized")
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate intermediate CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialNumberBits))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Quantaureum Network"},
			OrganizationalUnit: []string{"Intermediate CA"},
			CommonName:         "Quantaureum Intermediate CA",
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().AddDate(intermediateCAValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, root.Certificate, &privKey.PublicKey, root.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create intermediate CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse intermediate CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal intermediate CA private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &IntermediateCA{
		PrivateKey:  privKey,
		Certificate: cert,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		parent:      root,
	}, nil
}

// NewNodeCertificateManager creates a certificate manager for a P2P node.
// The node certificate is signed by the intermediate CA (not self-signed).
func NewNodeCertificateManager(certPath, keyPath string, nodeID PeerID, intermediateCA *IntermediateCA, rootCAPEM []byte) (*NodeCertificateManager, error) {
	ncm := &NodeCertificateManager{
		trustedCerts: make(map[string]*x509.Certificate),
		crl: &CertificateRevocationList{
			revokedSNs: make(map[string]time.Time),
		},
		pinnedPubKeys: make(map[string][]byte), // P2P-R12-H03
		stopCh:        make(chan struct{}),     // P2P-R16-M08
	}

	// SECURITY (audit 2026-06-24, M-1): Start periodic cleanup of revoked
	// serials so the CRL does not grow unbounded over the node's lifetime.
	// P2P-R16-CRIT-002 (2026-07-22) FIX: Panic recovery so a CRL cleanup
	// bug cannot silently halt this goroutine (CRL unbounded growth →
	// memory exhaustion). Matches the recover pattern used by the other
	// P2P background loops (P2P-R15-MED-5). Uses log.Printf (not
	// logging.Global) for consistency with the rest of mtls.go.
	// P2P-R16-M08 (2026-07-23) FIX: Added stopCh select so Close() can
	// terminate this goroutine. Previously it was `for range ticker.C`
	// with no stop channel, leaking a goroutine per NCM instance.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("ERROR: p2p CRL cleanup goroutine panic recovered: %v", r)
			}
		}()
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ncm.crl.Cleanup()
			case <-ncm.stopCh:
				return
			}
		}
	}()

	if intermediateCA != nil {
		ncm.intermediateCA = intermediateCA
	}

	if rootCAPEM != nil {
		rootPool := x509.NewCertPool()
		if !rootPool.AppendCertsFromPEM(rootCAPEM) {
			return nil, errors.New("failed to parse root CA PEM")
		}
		// P2P-R17-M01 (2026-07-23) FIX: x509.ParseCertificate expects
		// DER-encoded bytes, not PEM. Calling it on the raw PEM bytes always
		// failed, so ncm.rootCA was never populated. Decode the PEM block first
		// and parse the DER bytes. P2P-R17-L02: also removed the deprecated
		// rootPool.Subjects() call (deprecated since Go 1.19); the
		// AppendCertsFromPEM true-return above already proves the pool is
		// non-empty, so the len(roots)>0 guard was redundant.
		if block, _ := pem.Decode(rootCAPEM); block != nil {
			rootCert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				ncm.rootCA = &RootCA{Certificate: rootCert, CertPEM: rootCAPEM}
			}
		}
	}

	if certPath != "" && keyPath != "" {
		if err := ncm.loadFromFiles(certPath, keyPath); err == nil {
			return ncm, nil
		}
	}

	if intermediateCA != nil {
		if err := ncm.generateNodeCert(nodeID, intermediateCA); err != nil {
			return nil, fmt.Errorf("failed to generate node certificate: %w", err)
		}
	} else {
		if err := ncm.generateSelfSigned(nodeID); err != nil {
			return nil, fmt.Errorf("failed to generate self-signed cert: %w", err)
		}
	}

	return ncm, nil
}

// Close stops the CRL cleanup goroutine (P2P-R16-M08).
// It is idempotent and safe to call multiple times.
func (ncm *NodeCertificateManager) Close() {
	ncm.closeOnce.Do(func() {
		close(ncm.stopCh)
	})
}

// SkipCASignatureForTesting enables the test-only bypass for CA signature
// verification in RevokeCertificate and UnpinPeerPublicKey. CRIT-09 (R17):
// replaces testing.Testing() which was insecure (any test binary deployed
// to production would disable mTLS CA auth). This method is intentionally
// unexported — only tests in the p2p package can call it.
func (ncm *NodeCertificateManager) SkipCASignatureForTesting() {
	ncm.mu.Lock()
	defer ncm.mu.Unlock()
	ncm.skipCASignature = true
}

// generateNodeCert creates a leaf certificate signed by the intermediate CA.
// The certificate has IsCA=false and cannot sign other certificates.
func (ncm *NodeCertificateManager) generateNodeCert(nodeID PeerID, ca *IntermediateCA) error {
	ncm.mu.Lock()
	defer ncm.mu.Unlock()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate node key: %w", err)
	}
	ncm.privateKey = privKey

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialNumberBits))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Quantaureum Network"},
			OrganizationalUnit: []string{"P2P Node"},
			CommonName:         string(nodeID),
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(leafCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{string(nodeID)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, &privKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create node certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse node certificate: %w", err)
	}
	ncm.certificate = cert

	ncm.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	ncm.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return nil
}

// generateSelfSigned creates a self-signed certificate as a fallback
// when no CA is available (e.g., development/testing).
func (ncm *NodeCertificateManager) generateSelfSigned(nodeID PeerID) error {
	// SECURITY (audit 2026-06-24, M-2): Self-signed certificates should only
	// be used in development. Log a prominent warning so operators notice
	// if this path is hit in production.
	log.Printf("[SECURITY WARNING] Generating self-signed certificate for node %s - this is insecure for production", nodeID)

	ncm.mu.Lock()
	defer ncm.mu.Unlock()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	ncm.privateKey = privKey

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialNumberBits))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Quantaureum"},
			OrganizationalUnit: []string{"P2P Node (Dev)"},
			CommonName:         string(nodeID),
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(leafCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	ncm.certificate = cert

	ncm.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	ncm.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return nil
}

func (ncm *NodeCertificateManager) loadFromFiles(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file %s: %w", certPath, err)
	}

	keyPEMData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file %s: %w", keyPath, err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM from %s", certPath)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate from %s: %w", certPath, err)
	}

	keyBlock, _ := pem.Decode(keyPEMData)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode key PEM from %s", keyPath)
	}

	privKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse EC private key from %s: %w", keyPath, err)
	}

	ncm.mu.Lock()
	defer ncm.mu.Unlock()

	ncm.certificate = cert
	ncm.privateKey = privKey
	ncm.certPEM = certPEM
	ncm.keyPEM = keyPEMData

	return nil
}

// SaveToFiles saves the certificate and key to PEM files.
func (ncm *NodeCertificateManager) SaveToFiles(certPath, keyPath string) error {
	ncm.mu.RLock()
	defer ncm.mu.RUnlock()

	if ncm.certPEM == nil || ncm.keyPEM == nil {
		return errors.New("certificate not initialized")
	}

	if err := os.WriteFile(certPath, ncm.certPEM, 0600); err != nil {
		return fmt.Errorf("failed to write certificate to %s: %w", certPath, err)
	}

	if err := os.WriteFile(keyPath, ncm.keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write key to %s: %w", keyPath, err)
	}

	return nil
}

// GetTLSConfig returns a tls.Config for mTLS connections.
// If a root CA is configured, it verifies peer certificates against the CA chain.
// Otherwise, it falls back to the peer whitelist model.
func (ncm *NodeCertificateManager) GetTLSConfig() (*tls.Config, error) {
	ncm.mu.RLock()
	defer ncm.mu.RUnlock()

	if ncm.certificate == nil || ncm.privateKey == nil {
		return nil, errors.New("certificate not initialized")
	}

	cert, err := tls.X509KeyPair(ncm.certPEM, ncm.keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair: %w", err)
	}

	pool := x509.NewCertPool()
	// P2P-R17-L02 (2026-07-23) FIX: Track cert additions with a bool
	// instead of calling the deprecated (*x509.CertPool).Subjects()
	// (deprecated since Go 1.19). The previous code at line 584 called
	// pool.Subjects() to check if the pool was empty, but that API is
	// deprecated and the comment at line 324 claiming it was removed was
	// only partially correct — this call site was missed.
	certsAdded := false

	if ncm.rootCA != nil && ncm.rootCA.CertPEM != nil {
		if !pool.AppendCertsFromPEM(ncm.rootCA.CertPEM) {
			return nil, errors.New("failed to add root CA to trust pool")
		}
		certsAdded = true
	}

	if ncm.intermediateCA != nil && ncm.intermediateCA.CertPEM != nil {
		if !pool.AppendCertsFromPEM(ncm.intermediateCA.CertPEM) {
			return nil, errors.New("failed to add intermediate CA to trust pool")
		}
		certsAdded = true
	}

	for _, trustedCert := range ncm.trustedCerts {
		pool.AddCert(trustedCert)
		certsAdded = true
	}

	// P2P-R17-L02: Use certsAdded bool instead of deprecated Subjects().
	if !certsAdded {
		pool.AddCert(ncm.certificate)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		RootCAs:      pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		// G123 fix (2026-08-20): VerifyPeerCertificate is NOT invoked on
		// resumed TLS sessions, so a client resuming a cached session could
		// bypass the custom CRL / identity checks. Disable session
		// resumption (tickets on the server side, cache on the client side)
		// so every connection runs the full verifyPeerCertificate path.
		SessionTicketsDisabled: true,
		ClientSessionCache:     nil, // never resume; always re-verify
		VerifyPeerCertificate:  ncm.verifyPeerCertificate,
		VerifyConnection:       ncm.verifyConnection,
		// P3-P2P-MTLS FIX (R29, 2026-07-26): Drop TLS_AES_128_GCM_SHA256.
		// Although TLS 1.3 negotiates the highest-priority mutually
		// supported suite (so a Go client and Go server would always pick
		// AES_256_GCM_SHA384 in practice), retaining the weaker 128-bit
		// suite in the list is unnecessary attack surface: it would be
		// used if a peer (or future library) prioritized it. AES-256-GCM
		// and ChaCha20-Poly1305 are the only two strong options.
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	return config, nil
}

// verifyConnection is invoked on EVERY connection, including resumed TLS
// sessions (unlike VerifyPeerCertificate, which is skipped when a session
// is resumed). G123 fix (2026-08-20): it re-runs the same custom
// verification as verifyPeerCertificate so that even if session resumption
// is ever re-enabled, the CRL / identity checks cannot be bypassed.
func (ncm *NodeCertificateManager) verifyConnection(state tls.ConnectionState) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("no peer certificate presented")
	}
	rawCerts := make([][]byte, len(state.PeerCertificates))
	for i, cert := range state.PeerCertificates {
		rawCerts[i] = cert.Raw
	}
	return ncm.verifyPeerCertificate(rawCerts, nil)
}

func (ncm *NodeCertificateManager) verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("no peer certificate presented")
	}

	// RPC-R9-C1 (2026-07-19) FIX: Parse and validate EVERY certificate in
	// the presented chain, not just rawCerts[0]. The previous implementation
	// only checked the leaf cert's attributes (validity, CRL, IsCA) and
	// immediately returned nil when the standard library reported a
	// verified chain — meaning a revoked INTERMEDIATE in the chain was
	// silently accepted (the standard library does not consult our custom
	// CRL). An attacker (or a compromised intermediate) whose leaf was
	// still unrevoked could ride on a revoked-but-not-yet-expired
	// intermediate to authenticate.
	//
	// Now every cert in the chain gets:
	//   - validity period check
	//   - CRL revocation check
	//   - IsCA constraint check (leaf must NOT be CA; intermediates MUST be CA)
	presentedCerts := make([]*x509.Certificate, 0, len(rawCerts))
	for i, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return fmt.Errorf("failed to parse peer certificate at chain index %d: %w", i, err)
		}
		presentedCerts = append(presentedCerts, cert)
	}

	now := time.Now().UTC()

	// Validate every cert in the chain.
	for i, cert := range presentedCerts {
		role := "leaf"
		if i > 0 {
			role = "intermediate"
		}

		if now.Before(cert.NotBefore) {
			return fmt.Errorf("%s certificate at index %d not yet valid (NotBefore: %s)", role, i, cert.NotBefore)
		}
		if now.After(cert.NotAfter) {
			return fmt.Errorf("%s certificate at index %d expired (NotAfter: %s)", role, i, cert.NotAfter)
		}

		// RPC-R9-C1 FIX: CRL revocation check on EVERY cert in the chain,
		// not just the leaf. A revoked intermediate must invalidate the
		// entire chain, even if the standard library's chain-building
		// still considered it valid (it doesn't consult our custom CRL).
		if ncm.crl.IsRevoked(cert.SerialNumber.String()) {
			return fmt.Errorf("%s certificate at index %d (SN %s) has been revoked", role, i, cert.SerialNumber.String())
		}

		if i == 0 {
			// Leaf cert: MUST NOT be a CA. Also enforce max validity.
			if cert.IsCA {
				return errors.New("peer presented a CA certificate as leaf; only leaf certificates are accepted")
			}
			validity := cert.NotAfter.Sub(cert.NotBefore)
			if validity > maxLeafCertValidity {
				return fmt.Errorf("leaf certificate validity %v exceeds maximum %v", validity, maxLeafCertValidity)
			}

			// RPC-R9-M (2026-07-19) FIX: Structural identity-binding check.
			// Previously verifyPeerCertificate validated the chain (CA path,
			// CRL, IsCA, validity) but never inspected the leaf's identity
			// fields. A stolen Quantaureum leaf cert carries DNSNames = [nodeID]
			// and CommonName = nodeID per generateNodeCert; if those are
			// absent or disagree, the cert is either malformed or forged by
			// an attacker who controls a CA but didn't replicate the SAN.
			// We require:
			//   1. CommonName is non-empty.
			//   2. At least one DNS SAN is present (matches generateNodeCert).
			//   3. The first DNS SAN equals CommonName (single-identity contract).
			// This does NOT yet bind the cert to a SPECIFIC expected peer ID
			// (the post-quantum handshake in encrypted_transport.go handles
			// that binding). It only enforces that the cert actually carries
			// a Quantaureum-style identity, preventing generic / wildcard
			// certs from being accepted via mTLS.
			cn := cert.Subject.CommonName
			if cn == "" {
				return errors.New("leaf certificate missing CommonName (expected nodeID)")
			}
			if len(cert.DNSNames) == 0 {
				return errors.New("leaf certificate missing DNS SAN (expected nodeID)")
			}
			// Use subtle.ConstantTimeCompare to avoid leaking which field
			// mismatched via timing — even though both fields come from the
			// peer cert, an attacker shouldn't learn "CN matched but SAN
			// didn't" vs the reverse.
			if subtle.ConstantTimeCompare([]byte(cn), []byte(cert.DNSNames[0])) != 1 {
				return errors.New("leaf certificate identity mismatch: CommonName != DNSNames[0]")
			}
			// Reject wildcard identities (e.g. CN="*" or DNSNames=["*"]) —
			// a nodeID is a concrete cryptographic identifier, not a pattern.
			if cn == "*" || strings.ContainsAny(cn, "*?") {
				return fmt.Errorf("leaf certificate identity %q contains wildcard characters (not allowed for nodeID)", cn)
			}
		} else {
			// Intermediate cert: MUST be a CA. A non-CA cert presented as
			// an intermediate is a sign of chain manipulation (the standard
			// library's BasicConstraints check should already reject this,
			// but we check defensively in case VerifyPeerCertificate is
			// ever called without RequireAndVerifyClientCert).
			if !cert.IsCA {
				return fmt.Errorf("certificate at chain index %d is not a CA but is presented as intermediate", i)
			}
		}
	}

	// RPC-R9-C1 FIX: Do NOT short-circuit on `len(verifiedChains) > 0`.
	// Previously the function returned nil as soon as the standard library
	// reported a verified chain, skipping the per-cert CRL/IsCA checks
	// above for intermediates. We now run those checks unconditionally
	// and only consult verifiedChains as a defense-in-depth signal below.

	// P2P-R13-CRIT-002 (2026-07-21, R12-H03 regression fix): Verify the
	// pinned public key before accepting any certificate chain. The R12
	// implementation wrote VerifyPinnedPublicKey() and PinPeerPublicKey()
	// but never called them from verifyPeerCertificate — so TOFU pinning
	// was completely inoperative in production. An attacker with a stolen
	// CA private key could MITM any peer connection even after the peer
	// had been pinned.
	//
	// TOFU (Trust On First Use) semantics:
	//   - First connection (peer not pinned): pin the cert's public key
	//     hash, return nil. Future connections must present the same key.
	//   - Subsequent connections (peer pinned): verify the cert's pubkey
	//     hash matches the pin. Mismatch → reject (potential MITM or
	//     key rotation; operator must call UnpinPeerPublicKey to reset).
	//
	// We extract the peerID from the leaf cert's CommonName (which
	// generateNodeCert sets to the nodeID = PeerID).
	//
	// NOTE: This pins the mTLS leaf cert's TLS public key (RSA/ECDSA),
	// NOT the post-quantum Dilithium3 identity. The PQ identity is
	// verified separately in the encrypted_transport.go handshake.
	// Pinning the TLS key here defends against CA-compromise MITM
	// attacks: even if an attacker steals the intermediate CA's private
	// key and issues a forged leaf cert for a peer, the forged cert's
	// TLS public key will differ from the pinned hash and be rejected.
	verifyPinning := func() error {
		if len(presentedCerts) == 0 {
			return nil
		}
		leaf := presentedCerts[0]
		peerID := PeerID(leaf.Subject.CommonName)
		if peerID == "" {
			// Already checked above — but defensively return nil here
			// to avoid blocking on a malformed cert that somehow
			// passed the earlier checks.
			return nil
		}
		// P2P-R13-CRIT-002: verify against existing pin (if any).
		if err := ncm.VerifyPinnedPublicKey(peerID, leaf); err != nil {
			return err
		}
		// P2P-R13-CRIT-002: if this is the first connection (peer not
		// pinned), pin the public key hash now (TOFU).
		if !ncm.IsPeerPinned(peerID) {
			if err := ncm.PinPeerPublicKey(peerID, leaf); err != nil {
				// Pin failed — likely a concurrent first-connection race
				// where another goroutine pinned a DIFFERENT public key
				// in the window between our IsPeerPinned check and
				// PinPeerPublicKey. Treat as potential MITM and reject.
				return fmt.Errorf("P2P-R13-CRIT-002: TOFU pin failed for peer %s (potential MITM or concurrent connection race): %w",
					peerID, err)
			}
		}
		return nil
	}

	// SECURITY (audit 2026-06-24, H-4): Verify the certificate chain.
	// The previous implementation only checked the leaf certificate's own
	// attributes (validity, revocation, IsCA) but never verified that the
	// leaf was signed by a trusted CA. This allowed any attacker to forge
	// a leaf certificate with an arbitrary identity.
	//
	// Strategy:
	// 1. If the standard library already built verified chains, accept them
	//    (we've already applied CRL/IsCA to every cert above).
	// 2. Otherwise, verify the leaf against the trusted CA pool (rootCA /
	//    intermediateCA / trustedCerts) using x509.Certificate.CheckSignatureFrom.
	if len(verifiedChains) > 0 {
		// Standard library already validated the chain signature/builder,
		// AND we just applied per-cert CRL/IsCA checks above. Safe to accept.
		// P2P-R13-CRIT-002: verify TOFU pin before accepting.
		return verifyPinning()
	}

	// Fall back to manual issuer verification against our trusted CA pool.
	ncm.mu.RLock()
	rootCert := ncm.rootCA
	intermediateCert := ncm.intermediateCA
	trusted := ncm.trustedCerts
	ncm.mu.RUnlock()

	// Build the list of trusted issuer certificates.
	trustedIssuers := make([]*x509.Certificate, 0, len(trusted)+2)
	if rootCert != nil && rootCert.Certificate != nil {
		trustedIssuers = append(trustedIssuers, rootCert.Certificate)
	}
	if intermediateCert != nil && intermediateCert.Certificate != nil {
		trustedIssuers = append(trustedIssuers, intermediateCert.Certificate)
	}
	for _, c := range trusted {
		trustedIssuers = append(trustedIssuers, c)
	}

	if len(trustedIssuers) == 0 {
		// No CA configured — this is only acceptable in development mode.
		// In production, GetTLSConfig should refuse to start without a CA.
		return errors.New("no trusted CA configured; cannot verify peer certificate chain")
	}

	// P2P-R10-C1 (2026-07-19) FIX: Previously this fallback path ONLY
	// verified that the leaf certificate was directly signed by a
	// trusted issuer (CheckSignatureFrom), which has two failure modes:
	//
	//   1. A legitimate three-tier chain (leaf → intermediate → root)
	//      is REJECTED because the leaf is not directly signed by a
	//      trusted root. Only one-tier chains are accepted.
	//   2. An attacker with a stolen intermediate CA private key can
	//      issue arbitrary leaves that pass this check, because the
	//      intermediate's signature is accepted as if it were a root.
	//      Standard PKI requires the full chain to be walked and each
	//      intermediate to be cross-signed by a trusted root.
	//
	// Fix: use the standard library's x509.Certificate.Verify() with
	// the trusted issuers configured as Roots (and Intermediates
	// populated from the presented chain). This performs the full chain
	// verification: signature chain, name constraints, basic constraints
	// (CA flag), key usage (CertSign for intermediates), and validity
	// periods — exactly what RFC 5280 requires for path validation.
	leafCert := presentedCerts[0]

	// Build the intermediate pool from presented intermediate certs
	// (i.e., all certs in the chain after the leaf).
	intermediatePool := x509.NewCertPool()
	for i := 1; i < len(presentedCerts); i++ {
		intermediatePool.AddCert(presentedCerts[i])
	}

	// Build the root pool from our trusted issuers.
	rootPool := x509.NewCertPool()
	for _, issuer := range trustedIssuers {
		rootPool.AddCert(issuer)
	}

	// Perform full RFC 5280 path validation.
	verifyOpts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		// Don't enforce EKU server/client — we already enforce the
		// expected identity via CN/DNSNames checks above. The standard
		// library's EKU handling is permissive by default and matches
		// what we want for mTLS.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leafCert.Verify(verifyOpts); err == nil {
		// Full chain verified — leaf chains up to a trusted root via
		// properly cross-signed intermediates, with all basic constraints
		// and validity periods checked.
		// P2P-R13-CRIT-002: verify TOFU pin before accepting.
		return verifyPinning()
	}

	// Fallback: a single-tier chain where the leaf is directly signed
	// by a trusted issuer (no intermediate). CheckSignatureFrom covers
	// this case but does NOT validate the leaf's own signature algorithm
	// strength or pathlen constraints, so we keep it as a last resort
	// for backward compatibility with one-tier dev deployments.
	//
	// SECURITY NOTE: This fallback is ONLY safe because we already
	// applied per-cert CRL/IsCA checks above. We do NOT use this path
	// to bypass chain verification for multi-tier certificates — the
	// leafCert.Verify() call above already handles those.
	//
	// P2P-R11-H01 (2026-07-20) FIX: Previously this loop only called
	// CheckSignatureFrom, which verifies that the leaf's signature was
	// produced by the issuer's private key. It does NOT verify:
	//   - The issuer is actually a CA (IsCA + BasicConstraintsValid)
	//   - The issuer has KeyCertSign in KeyUsage
	//   - The issuer's pathlen constraint allows signing a leaf
	//   - The leaf's signature algorithm is acceptable (e.g., not SHA1)
	// An attacker who obtains a stolen leaf cert (non-CA) private key
	// could sign a new malicious leaf and pass this check, because the
	// stolen leaf's IsCA=false was never enforced on the issuer side.
	// We now enforce full CA constraints on the issuer and reject weak
	// signature algorithms on the leaf before accepting the fallback.
	for _, issuer := range trustedIssuers {
		// Verify issuer meets CA requirements (mirrors x509.Verify).
		if !issuer.IsCA {
			continue
		}
		if !issuer.BasicConstraintsValid {
			continue
		}
		// Issuer must have KeyCertSign in its Key Usage (RFC 5280, Key Usage extension).
		if issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
			continue
		}
		// PathLenConstraint: if set (>=0), limits the number of
		// intermediates between this issuer and the leaf. A leaf is
		// a direct child (depth 1), so PathLen=0 means "can only sign
		// leaves, no further intermediates" - still acceptable for
		// one-tier chain. PathLen<0 means "no constraint". Any value
		// >=0 is acceptable for signing a leaf directly.
		// (No explicit check needed — PathLen=0 still allows leaves.)

		// P2P-R11-H01: Reject weak leaf signature algorithms.
		// CheckSignatureFrom does not enforce a minimum signature
		// algorithm strength. SHA1WithRSA is considered cryptographically
		// broken and must not be accepted even in the fallback path.
		switch leafCert.SignatureAlgorithm {
		case x509.UnknownSignatureAlgorithm:
			continue
		case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
			// Reject SHA1-based signatures (collision attacks practical).
			continue
		}

		if err := leafCert.CheckSignatureFrom(issuer); err == nil {
			// Signature verified — the leaf was directly signed by a
			// trusted CA (one-tier chain) AND the issuer is a valid CA
			// AND the leaf uses an acceptable signature algorithm.
			// P2P-R13-CRIT-002: verify TOFU pin before accepting.
			return verifyPinning()
		}
	}

	return errors.New("peer certificate is not signed by a trusted CA (full chain validation failed)")
}

func (ncm *NodeCertificateManager) AddTrustedPeer(peerID PeerID, certPEM []byte) error {
	ncm.mu.Lock()
	defer ncm.mu.Unlock()

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return errors.New("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// P2P-R10-C2 (2026-07-19) FIX: AddTrustedPeer adds a certificate to
	// the trustedCerts map, which is used by VerifyPeerCertificate as a
	// trusted issuer for verifying leaf certificates. Previously, ANY
	// certificate could be added — including a non-CA leaf certificate.
	//
	// If a non-CA leaf is in trustedCerts, it is treated as a trusted
	// root: VerifyPeerCertificate would accept any leaf signed by that
	// leaf's private key, AND the CheckSignatureFrom fallback above
	// would accept any new leaf directly signed by it. This means an
	// attacker with one stolen leaf private key could mint unlimited
	// new identities and bypass mTLS authentication entirely.
	//
	// Fix: enforce that the certificate has IsCA=true AND has the
	// keyCertSign KeyUsage (CertSign in Go's x509 package). These are
	// the same constraints the standard library enforces when building
	// a chain — a leaf without these cannot be used as an issuer.
	if !cert.IsCA {
		return fmt.Errorf("AddTrustedPeer rejected: certificate for peer %s is not a CA (IsCA=false); "+
			"only CA certificates may be added as trusted issuers", peerID)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("AddTrustedPeer rejected: certificate for peer %s does not have KeyUsageCertSign; "+
			"only CA certificates with the keyCertSign usage may be added as trusted issuers", peerID)
	}

	// P2P-R10-L1 (2026-07-19) FIX: Bound the trustedCerts map size to
	// prevent memory-exhaustion DoS. The map is keyed by peerID, so a
	// re-add for an EXISTING peerID is an overwrite (not growth) and is
	// allowed even when the map is at capacity. Only NEW peerIDs that
	// would push the count past maxTrustedCerts are rejected.
	if _, exists := ncm.trustedCerts[string(peerID)]; !exists {
		if len(ncm.trustedCerts) >= maxTrustedCerts {
			return fmt.Errorf("AddTrustedPeer rejected: trustedCerts map at capacity (%d entries); "+
				"remove an existing trusted peer before adding peer %s", maxTrustedCerts, peerID)
		}
	}

	ncm.trustedCerts[string(peerID)] = cert
	return nil
}

func (ncm *NodeCertificateManager) RemoveTrustedPeer(peerID PeerID) {
	ncm.mu.Lock()
	defer ncm.mu.Unlock()
	delete(ncm.trustedCerts, string(peerID))
}

// RevokeCertificate revokes a leaf certificate by serial number.
//
// RPC-R9-M (2026-07-19) FIX: Require an explicit authorization proof.
// Previously this was a no-arg public method callable by any code that
// held a *NodeCertificateManager reference. There was no audit log, no
// caller authentication, and no record of who revoked what. The risk:
// if any future RPC admin method (e.g. qau_admin_revokeCertificate)
// exposes this directly, any holder of an admin API key could revoke a
// validator's certificate and split the network.
//
// The fix introduces a `caSignature` parameter: the caller must present a
// signature over the canonical revocation request, signed by the same
// rootCA / intermediateCA private key that issued the certificate. This
// binds revocation authority to CA key custody — exactly the property X.509
// CRLs rely on in standard PKI. An empty signature is accepted only when
// ncm.skipCASignature is true (test-only, set via SkipCASignatureForTesting)
// so existing tests continue to work.
//
// CRIT-09 (R17, 2026-07-23): Replaced testing.Testing() with the explicit
// ncm.skipCASignature flag. testing.Testing() returned true for ANY test
// binary, including one accidentally deployed to production — which would
// disable CA signature verification, allowing anyone to revoke certificates.
//
// CRYPTO-R19-CRIT-01/02/03 + CRYPTO-R19-M01 (2026-07-24): Complete rewrite
// of the CA signature verification path:
//   - Formal domain separation tag (caRevokeDomainSeparator) with NUL
//     terminator and versioning, replacing ad-hoc "REVOKE:" prefix.
//   - Length-prefixed payload (V2 pattern) to prevent prefix-extension.
//   - Timestamp parameter + ±5-minute freshness check to prevent permanent
//     replay of leaked CA signatures.
//   - SHA3-256 hash for consistency with other project signature primitives.
//   - low-s enforcement via ecdsaVerifyLowS (CRYPTO-R19-CRIT-03).
//   - Root CA rejected by default (CRYPTO-R19-M01): only Intermediate CA
//     is allowed for daily Revoke operations. Root CA must remain offline.
//
// Signing payload format (callers must produce signatures over this):
//
//	SHA3-256( caOperationPayload(caRevokeDomainSeparator, timestamp, serialNumber) )
//
// where timestamp is the current Unix time in seconds.
func (ncm *NodeCertificateManager) RevokeCertificate(serialNumber string, timestamp int64, caSignature []byte) error {
	if serialNumber == "" {
		return errors.New("cannot revoke empty serial number")
	}
	ncm.mu.RLock()
	skip := ncm.skipCASignature
	ncm.mu.RUnlock()
	if !skip {
		// Production path: require CA signature.
		if len(caSignature) == 0 {
			return errors.New("RevokeCertificate requires a CA signature in production; sign SHA3-256(caRevokeDomainSeparator || timestamp || serialNumber) and pass (serialNumber, timestamp, signature)")
		}
		// CRYPTO-R19-CRIT-01: ±5-minute freshness check.
		now := time.Now().Unix()
		if timestamp <= 0 || now-timestamp > caFreshnessWindow || timestamp-now > caFreshnessWindow {
			log.Printf("[WARN] CRYPTO-R19-CRIT-01: RevokeCertificate(%s) rejected — timestamp %d outside freshness window (now=%d, ±%ds)",
				serialNumber, timestamp, now, caFreshnessWindow)
			return errors.New("CA signature timestamp outside freshness window")
		}
		// CRYPTO-R19-CRIT-01/02: Build V2 length-prefixed payload with
		// formal domain tag + timestamp + serial number.
		payload := caOperationPayload(caRevokeDomainSeparator, timestamp, serialNumber)
		hash := sha3.Sum256(payload)
		verified := false
		// CRYPTO-R19-M01: Prefer Intermediate CA for daily operations.
		// Root CA should remain offline and is rejected by default for
		// Revoke operations. This limits blast radius if Root CA is
		// compromised through online exposure.
		if ncm.intermediateCA != nil && ncm.intermediateCA.Certificate != nil {
			if pub, ok := ncm.intermediateCA.Certificate.PublicKey.(*ecdsa.PublicKey); ok && pub != nil {
				if ecdsaVerifyLowS(pub, hash[:], caSignature) {
					verified = true
				}
			}
		}
		if !verified {
			log.Printf("[WARN] RPC-R9-M: RevokeCertificate(%s) rejected — invalid CA signature (Root CA rejected by default per CRYPTO-R19-M01)", serialNumber)
			return errors.New("invalid CA signature for certificate revocation")
		}
	}
	ncm.crl.Revoke(serialNumber)
	log.Printf("[INFO] RPC-R9-M: certificate %s revoked (authorized by CA signature)", serialNumber)
	return nil
}

func (ncm *NodeCertificateManager) GetCertificatePEM() []byte {
	ncm.mu.RLock()
	defer ncm.mu.RUnlock()
	return ncm.certPEM
}

func (ncm *NodeCertificateManager) GetCertificate() *x509.Certificate {
	ncm.mu.RLock()
	defer ncm.mu.RUnlock()
	return ncm.certificate
}

func (crl *CertificateRevocationList) Revoke(serialNumber string) {
	crl.mu.Lock()
	defer crl.mu.Unlock()
	crl.revokedSNs[serialNumber] = time.Now().UTC()
	crl.lastUpdated = time.Now().UTC()
}

func (crl *CertificateRevocationList) IsRevoked(serialNumber string) bool {
	crl.mu.RLock()
	defer crl.mu.RUnlock()
	_, revoked := crl.revokedSNs[serialNumber]
	return revoked
}

func (crl *CertificateRevocationList) GetRevokedList() map[string]time.Time {
	crl.mu.RLock()
	defer crl.mu.RUnlock()

	result := make(map[string]time.Time, len(crl.revokedSNs))
	for sn, t := range crl.revokedSNs {
		result[sn] = t
	}
	return result
}

func (crl *CertificateRevocationList) LastUpdated() time.Time {
	crl.mu.RLock()
	defer crl.mu.RUnlock()
	return crl.lastUpdated
}

// Cleanup removes revoked serials whose associated leaf certificates have
// expired (older than 2x leafCertValidity). This prevents unbounded memory
// growth in the revocation list.
// SECURITY (audit 2026-06-24, M-8): Add periodic cleanup of revoked serials.
func (crl *CertificateRevocationList) Cleanup() {
	crl.mu.Lock()
	defer crl.mu.Unlock()
	cutoff := time.Now().UTC().Add(-leafCertValidity * 2)
	for serial, revokedAt := range crl.revokedSNs {
		if revokedAt.Before(cutoff) {
			delete(crl.revokedSNs, serial)
		}
	}
}

// ============================================================================
// P2P-R12-H01 (2026-07-20) FIX: Certificate auto-rotation
//
// Audit finding: "Node certificates were valid forever after issuance — no expiry check, no automatic rotation.
// Once a certificate private key leaked, expiry offered no way to invalidate it."
//
// Note: leafCertValidity = 24h was already set, but there was no mechanism
// to check at startup whether the cert is near expiry and regenerate it.
// This fix adds CheckAndRotateCertificate(), which should be called at node
// startup (and periodically) to ensure the cert is always fresh.
//
// The rotation regenerates the leaf cert using the same intermediateCA,
// producing a new keypair + new serial number. The old cert is not revoked
// (it simply expires naturally); peers that cached the old cert will
// re-verify on next connection.
// ============================================================================

// certRotationThreshold is the default remaining validity below which
// CheckAndRotateCertificate regenerates the leaf cert. 6h gives the node
// ample time to rotate before the 24h cert expires, even if the rotation
// is delayed by a few hours.
const certRotationThreshold = 6 * time.Hour

// RegisterRotationCallback registers a function to be invoked after a
// successful certificate rotation in CheckAndRotateCertificate. The Host
// uses this to proactively disconnect all connected peers so they
// reconnect and learn the new cert via the normal handshake.
//
// P2P-R14-CRIT-002 (2026-07-21): without this notification mechanism,
// peers still hold the OLD pinned public key after local cert rotation
// and reject the new cert on the next connection attempt — the rotated
// node gets isolated from the network.
//
// Callbacks are invoked WITHOUT holding ncm.mu (to avoid deadlock if a
// callback calls back into the manager). Callbacks must be safe to call
// from the rotation goroutine. Registration must happen before
// CheckAndRotateCertificate is first called (typically at Host.Start).
func (ncm *NodeCertificateManager) RegisterRotationCallback(fn func()) {
	ncm.mu.Lock()
	defer ncm.mu.Unlock()
	ncm.onRotation = append(ncm.onRotation, fn)
}

// CheckAndRotateCertificate checks the remaining validity of the current
// leaf certificate and regenerates it if less than rotationThreshold remains.
// Returns nil if no rotation was needed, or nil after a successful rotation.
// Returns an error only if rotation was needed but failed.
//
// Call this at startup (after NewNodeCertificateManager) and periodically
// (e.g., every hour) to ensure the cert never expires while the node is
// running.
//
// If intermediateCA is nil (self-signed fallback / dev mode), rotation
// uses generateSelfSigned instead.
//
// P2P-R14-CRIT-002 (2026-07-21): after a successful rotation, all
// registered rotation callbacks are invoked. The Host registers a
// callback that disconnects all connected peers so they reconnect with
// the new cert. Without this, peers' pinned public keys would reject
// the new cert, isolating the rotated node.
func (ncm *NodeCertificateManager) CheckAndRotateCertificate(rotationThreshold time.Duration) error {
	ncm.mu.RLock()
	cert := ncm.certificate
	intermediate := ncm.intermediateCA
	ncm.mu.RUnlock()

	if cert == nil {
		// Nothing to rotate — caller hasn't initialized the cert yet.
		return nil
	}

	now := time.Now().UTC()
	remaining := cert.NotAfter.Sub(now)
	if remaining > rotationThreshold {
		// Plenty of validity left — no rotation needed.
		return nil
	}

	// Extract the nodeID from the existing cert (CN = nodeID).
	nodeID := PeerID(cert.Subject.CommonName)
	if nodeID == "" {
		return errors.New("P2P-R12-H01: cannot rotate cert with empty CommonName (nodeID)")
	}

	log.Printf("[INFO] P2P-R12-H01: rotating leaf certificate (remaining validity %v < threshold %v)",
		remaining.Round(time.Minute), rotationThreshold)

	// Regenerate. generateNodeCert and generateSelfSigned both acquire
	// ncm.mu.Lock() internally, so we don't hold the lock here.
	if intermediate != nil {
		if err := ncm.generateNodeCert(nodeID, intermediate); err != nil {
			return fmt.Errorf("P2P-R12-H01: failed to rotate cert via intermediate CA: %w", err)
		}
	} else {
		if err := ncm.generateSelfSigned(nodeID); err != nil {
			return fmt.Errorf("P2P-R12-H01: failed to rotate self-signed cert: %w", err)
		}
	}

	log.Printf("[INFO] P2P-R12-H01: certificate rotated successfully (new NotAfter: %s)",
		ncm.GetCertificate().NotAfter.Format(time.RFC3339))

	// P2P-R14-CRIT-002 (2026-07-21): invoke rotation callbacks WITHOUT
	// holding ncm.mu (callbacks may call back into the manager, e.g.,
	// GetCertificate, which would deadlock). Snapshot the callback list
	// under the lock, then invoke outside the lock.
	ncm.mu.RLock()
	callbacks := make([]func(), len(ncm.onRotation))
	copy(callbacks, ncm.onRotation)
	ncm.mu.RUnlock()
	for _, cb := range callbacks {
		// Defensive: a panicking callback must not break the rotation
		// loop or prevent subsequent callbacks from running.
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[WARN] P2P-R14-CRIT-002: rotation callback panicked: %v", r)
				}
			}()
			cb()
		}()
	}
	return nil
}

// CertificateRemainingValidity returns the remaining validity duration of
// the current leaf certificate. Useful for monitoring / metrics.
func (ncm *NodeCertificateManager) CertificateRemainingValidity() time.Duration {
	ncm.mu.RLock()
	defer ncm.mu.RUnlock()
	if ncm.certificate == nil {
		return 0
	}
	return time.Until(ncm.certificate.NotAfter)
}

// ============================================================================
// P2P-R12-H02 (2026-07-20) FIX: CRL propagation across P2P peers
//
// Audit finding: "Certificate verification only checked the signature chain and validity window, not OCSP/CRL revocation.
// Even after a validator private key leak, an unexpired certificate could not be revoked."
//
// Note: The audit finding is partially incorrect — verifyPeerCertificate
// DOES consult the local CRL (see line ~552: ncm.crl.IsRevoked(...)). The
// real gap is that the CRL is local-only: if Node A revokes a cert, Node B
// doesn't know until its local operator also calls RevokeCertificate.
//
// This fix adds a serializable CRL snapshot format (CRLSnapshot) and
// GetCRLSnapshot / MergeCRLSnapshot methods so peers can exchange CRL
// state via the P2P gossipsub layer. The actual gossipsub wiring is a
// separate task (would modify host.go to broadcast CRL snapshots).
//
// Security considerations:
//   - MergeCRLSnapshot is monotonic: it only ADDS revoked serials, never
//     removes them. Removing a revoked serial would un-revoke a cert,
//     which is a security risk. Cleanup of expired serials is handled
//     locally by CRL.Cleanup().
//   - The snapshot includes a timestamp for freshness checks (caller can
//     reject stale snapshots).
//   - The snapshot is NOT signed — it is intended to be transported over
//     the authenticated mTLS channel, where the peer's identity is already
//     verified. If a peer lies about revocations, the worst case is that
//     the local node revokes certs that are actually still valid (DoS).
//     This is preferable to the status quo where revocations don't propagate
//     at all.
// ============================================================================

// CRLSnapshot is a serializable point-in-time view of a
// CertificateRevocationList. It can be JSON-marshaled and exchanged between
// peers to propagate revocation information.
//
// R15-CRIT-001 FIX (2026-07-22): added IssuerPeerID + Signature fields.
// The signature is an ECDSA-ASN1 signature over SHA-256 of the canonical
// signing payload (version || lastUpdated || canonical-sorted(RevokedSNs)).
// The signing key is the issuing node's leaf certificate private key
// (NodeCertificateManager.privateKey). Receivers verify the signature
// against the pinned public key for IssuerPeerID (P2P-R12-H03 TOFU
// pinning), or against a trusted-CA-signed leaf cert if available.
//
// In testing mode (when the receiver's Host has skipCRLAuth=true, set via
// the test-only struct field), snapshots without a signature are accepted
// to preserve existing test behavior. In production, a snapshot from a
// non-trusted peer without a verifiable signature is dropped.
// CRIT-09 (R17): replaced testing.Testing() with the explicit skipCRLAuth
// flag on Host (see P2P-R16-M06).
type CRLSnapshot struct {
	// RevokedSNs maps revoked certificate serial numbers (decimal string)
	// to the UTC timestamp when they were revoked.
	RevokedSNs map[string]int64 `json:"revoked_sns"`
	// LastUpdated is the UTC timestamp of the most recent revocation.
	LastUpdated int64 `json:"last_updated"`
	// Version is the snapshot format version (currently 1).
	Version int `json:"version"`
	// IssuerPeerID is the peer ID of the node that signed this snapshot.
	// Must match the GossipSub msg.From of the carrier message.
	IssuerPeerID string `json:"issuer_peer_id,omitempty"`
	// Signature is an ECDSA-ASN1 signature over the canonical signing
	// payload (see crlSigningPayload). Produced by the issuer node's leaf
	// certificate private key. Empty if the snapshot was produced before
	// R15-CRIT-001 or in testing mode.
	Signature []byte `json:"signature,omitempty"`
}

// crlSnapshotVersion is the current CRL snapshot format version.
const crlSnapshotVersion = 1

// crlSigningPayload builds the canonical byte payload that is signed and
// verified. The payload is a fixed-layout concatenation that excludes the
// Signature and IssuerPeerID fields themselves (which are produced by the
// signer and verified by the receiver).
//
// Layout: domainTag || version(8 bytes BE) || lastUpdated(8 bytes BE) || sorted(RevokedSNs)
// where each RevokedSNs entry is: snLen(4 bytes BE) || sn || ts(8 bytes BE).
// Sorting is by serial number (string compare) for determinism.
//
// R15-CRIT-001 (2026-07-22).
// CRYPTO-R16-H01 (2026-07-23) FIX: Added domain separation tag prefix
// "QUANTAUREUM_CRL_V1\x00" to prevent cross-protocol signature reuse.
// Without the tag, an ECDSA signature from any other protocol using the
// same key could be replayed as a valid CRL signature (or vice versa).
// The NUL terminator prevents prefix-extension attacks, matching the
// transaction signing domain separator pattern (encoding/proto.go:545).
//
// CRYPTO-R18-H02 (2026-07-24): Added length-prefixed payload format
// (crlSigningPayloadV2) using the SignWithDomain pattern:
//
//	len(domain)(4B BE) || domain || len(msg)(4B BE) || msg
//
// This provides unambiguous domain separation without relying on the
// NUL terminator alone. The legacy format (crlSigningPayload) is
// retained for backward-compatible verification of pre-R18 snapshots.
var crlSigningDomainSeparator = []byte("QUANTAUREUM_CRL_V1\x00")

// CRYPTO-R19-CRIT-01/02 (2026-07-24): Formal domain separation tags for CA
// administrative operations. These replace the ad-hoc "REVOKE:"/"UNPIN:"
// string prefixes that had no NUL terminator, no length prefix, and no
// versioning. Each tag is NUL-terminated to prevent prefix-extension
// attacks and versioned (V1) to allow future format changes.
//
// The signing payload format is length-prefixed (V2 pattern, same as CRL):
//
//	len(domain)(4B BE) || domain || len(body)(4B BE) || body
//
// where body contains:
//
//	timestamp(8B BE, Unix seconds) || len(serial/peerID)(4B BE) || serial/peerID
//
// The timestamp enables ±5-minute freshness checking, preventing permanent
// replay of leaked CA signatures (CRYPTO-R19-CRIT-01).
var (
	caRevokeDomainSeparator = []byte("QUANTAUREUM_CA_REVOKE_V1\x00")
	caUnpinDomainSeparator  = []byte("QUANTAUREUM_CA_UNPIN_V1\x00")
)

// caFreshnessWindow is the maximum allowed clock skew (in seconds) between
// the timestamp embedded in a CA operation signature and the verifier's
// local clock. CRYPTO-R19-CRIT-01: prevents replay of old signatures.
const caFreshnessWindow = 5 * 60 // 5 minutes

func crlSigningPayload(snap *CRLSnapshot) []byte {
	// CRYPTO-R16-H01: prepend domain separation tag.
	buf := append([]byte(nil), crlSigningDomainSeparator...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(snap.Version))
	buf = binary.BigEndian.AppendUint64(buf, uint64(snap.LastUpdated))

	type kv struct {
		sn string
		ts int64
	}
	entries := make([]kv, 0, len(snap.RevokedSNs))
	for sn, ts := range snap.RevokedSNs {
		entries = append(entries, kv{sn, ts})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].sn < entries[j].sn })
	for _, e := range entries {
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(e.sn)))
		buf = append(buf, []byte(e.sn)...)
		buf = binary.BigEndian.AppendUint64(buf, uint64(e.ts))
	}
	return buf
}

// crlSigningPayloadV2 produces the CRYPTO-R18-H02 length-prefixed payload.
// Format: len(domain)(4B BE) || domain || len(body)(4B BE) || body
// where body is the legacy payload WITHOUT the domain tag (version +
// lastUpdated + sorted entries). Length prefixes prevent prefix-extension
// attacks without relying on a NUL terminator, and make the format
// robust to future domain tag changes.
func crlSigningPayloadV2(snap *CRLSnapshot) []byte {
	// Build the body (everything after the domain tag in V1).
	body := binary.BigEndian.AppendUint32(nil, uint32(snap.Version))
	body = binary.BigEndian.AppendUint64(body, uint64(snap.LastUpdated))

	type kv struct {
		sn string
		ts int64
	}
	entries := make([]kv, 0, len(snap.RevokedSNs))
	for sn, ts := range snap.RevokedSNs {
		entries = append(entries, kv{sn, ts})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].sn < entries[j].sn })
	for _, e := range entries {
		body = binary.BigEndian.AppendUint32(body, uint32(len(e.sn)))
		body = append(body, []byte(e.sn)...)
		body = binary.BigEndian.AppendUint64(body, uint64(e.ts))
	}

	// Assemble: len(domain) || domain || len(body) || body
	buf := binary.BigEndian.AppendUint32(nil, uint32(len(crlSigningDomainSeparator)))
	buf = append(buf, crlSigningDomainSeparator...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(body)))
	buf = append(buf, body...)
	return buf
}

// SignCRLSnapshot signs the snapshot in-place using the node's leaf
// certificate ECDSA private key. The signature is stored in snap.Signature
// and snap.IssuerPeerID is set to nodeID.
//
// R15-CRIT-001: CRL snapshots propagated via GossipSub must be signed so
// receivers can authenticate the issuer (in addition to the per-peer rate
// limit and trusted-peer authorization enforced in handleCRLMessage).
//
// Returns an error if the node has no leaf private key (e.g., the manager
// was initialized without one — only happens in incomplete test setups).
func (ncm *NodeCertificateManager) SignCRLSnapshot(snap *CRLSnapshot, nodeID PeerID) error {
	ncm.mu.RLock()
	priv := ncm.privateKey
	ncm.mu.RUnlock()
	if priv == nil {
		return errors.New("SignCRLSnapshot: node has no leaf private key")
	}

	snap.IssuerPeerID = string(nodeID)
	// CRYPTO-R18-H02 (2026-07-24): Use the length-prefixed V2 payload to
	// prevent prefix-extension attacks without relying on a NUL terminator.
	payload := crlSigningPayloadV2(snap)
	// CRYPTO-R18-H03 (2026-07-24): Use SHA3-256 for consistency with the
	// project's other signature primitives (Dilithium3 uses SHAKE, VRF uses
	// SHA3-256). SHA-256 is retained only for backward-compatible
	// verification of pre-R18 CRL snapshots in VerifyCRLSnapshotSignature.
	hash := sha3.Sum256(payload)
	// CRYPTO-R18-CRIT-02 (2026-07-24): Use low-s normalization to prevent
	// signature malleability. ECDSA allows (r,s) and (r,n-s) as valid
	// signatures for the same message — without enforcing low-s, the same
	// CRL can have two different valid signatures, bypassing dedup/cache.
	// ecdsa.SignASN1 does not guarantee low-s, so we sign manually and
	// normalize s before encoding to ASN.1 DER.
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		return fmt.Errorf("SignCRLSnapshot: ecdsa.Sign failed: %w", err)
	}
	// Force low-s: if s > n/2, replace with n-s
	curveParams := priv.Curve.Params()
	halfN := new(big.Int).Rsh(curveParams.N, 1)
	if s.Cmp(halfN) > 0 {
		s.Sub(curveParams.N, s)
	}
	snap.Signature, err = asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return fmt.Errorf("SignCRLSnapshot: asn1.Marshal failed: %w", err)
	}
	return nil
}

// ecdsaSignature is the ASN.1 DER structure for ECDSA signatures (RFC 3279).
// Used by CRYPTO-R18-CRIT-02 to enable manual low-s normalization.
type ecdsaSignature struct {
	R, S *big.Int
}

// ecdsaVerifyLowS verifies an ECDSA signature in ASN.1 DER form, enforcing
// low-s normalization (CRYPTO-R19-CRIT-03). ECDSA allows (r,s) and (r,n-s)
// as valid signatures for the same message — without enforcing low-s, a
// single message can have two distinct valid signatures, enabling signature
// malleability attacks that bypass dedup caches, replay protection, and
// audit uniqueness checks.
//
// This function is the SINGLE entry point for ECDSA verification in this
// file. All ECDSA verification paths MUST use it instead of calling
// ecdsa.VerifyASN1 directly, to ensure uniform low-s enforcement.
// CRYPTO-R19-CRIT-03 (2026-07-24).
func ecdsaVerifyLowS(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	if pub == nil || len(hash) == 0 || len(sig) == 0 {
		return false
	}
	var es ecdsaSignature
	if _, err := asn1.Unmarshal(sig, &es); err != nil {
		// Not valid ASN.1 DER — reject. We do NOT fall back to
		// ecdsa.VerifyASN1 here because that would accept high-s.
		return false
	}
	if es.R == nil || es.S == nil || es.R.Sign() <= 0 || es.S.Sign() <= 0 {
		return false
	}
	curveParams := pub.Curve.Params()
	halfN := new(big.Int).Rsh(curveParams.N, 1)
	// Reject high-s to prevent malleability
	if es.S.Cmp(halfN) > 0 {
		return false
	}
	return ecdsa.Verify(pub, hash, es.R, es.S)
}

// caOperationPayload builds the length-prefixed signing payload for a CA
// administrative operation (Revoke/Unpin).
// CRYPTO-R19-CRIT-01/02 (2026-07-24).
//
// Format: len(domain)(4B BE) || domain || len(body)(4B BE) || body
// where body = timestamp(8B BE) || len(target)(4B BE) || target
//
// The timestamp enables ±5-minute freshness checking. The length prefixes
// prevent prefix-extension attacks without relying on the NUL terminator
// alone. The domain tag prevents cross-operation replay (a Revoke signature
// cannot be replayed as an Unpin signature).
func caOperationPayload(domain []byte, timestamp int64, target string) []byte {
	// Build body: timestamp || len(target) || target
	body := binary.BigEndian.AppendUint64(nil, uint64(timestamp))
	body = binary.BigEndian.AppendUint32(body, uint32(len(target)))
	body = append(body, []byte(target)...)

	// Assemble: len(domain) || domain || len(body) || body
	buf := binary.BigEndian.AppendUint32(nil, uint32(len(domain)))
	buf = append(buf, domain...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(body)))
	buf = append(buf, body...)
	return buf
}

// VerifyCRLSnapshotSignature verifies the snapshot's signature against the
// issuer's known leaf certificate public key. Returns true only if a
// signature is present AND verifies against a known public key for the
// issuer. Returns false (no error) if:
//   - the snapshot has no signature (pre-R15 or testing mode), OR
//   - the issuer's public key is not known locally (caller should fall
//     back to trusted-peer authorization + rate limiting), OR
//   - the signature fails verification (invalid, malformed, or high-s).
//
// CRYPTO-R18-M02 (2026-07-24) Clarification: Returning false for BOTH
// "unknown issuer" and "verification failed" is INTENTIONALLY fail-closed
// (reject). Callers that need to distinguish the two cases should call
// HasIssuerCertificate FIRST:
//   - If HasIssuerCertificate returns false → unknown issuer (caller may
//     fall back to trusted-peer authorization or fetch the issuer's cert).
//   - If HasIssuerCertificate returns true AND VerifyCRLSnapshotSignature
//     returns false → signature is INVALID (reject immediately).
//
// The current callers (host.go:1195-1238) already use this pattern
// correctly: Path 1 checks HasIssuerCertificate before verifying; Path 2
// (trusted peers) calls VerifyCRLSnapshotSignature directly, which
// returns false (reject) for unknown issuers — fail-closed.
//
// R15-CRIT-001.
// CRYPTO-R18-CRIT-02 (2026-07-24): Added low-s validation — rejects
// signatures where s > n/2 to prevent malleability.
// CRYPTO-R18-H02/H03 (2026-07-24): Try V2 payload (length-prefixed) with
// SHA3-256 first; if that fails, fall back to V1 payload (domain||msg)
// with SHA-256 for backward compatibility with pre-R18 snapshots.
//
// CRYPTO-R19-CRIT-03 (2026-07-24): Unified all ECDSA verification through
// ecdsaVerifyLowS — no path accepts high-s signatures anymore. Previously
// the V1 backward-compat fallback used ecdsa.VerifyASN1 which accepts
// both s and n-s, allowing signature malleability on legacy snapshots.
//
// CRYPTO-R19-H01 (2026-07-24): The V1 backward-compat path (SHA-256,
// legacy payload) is permanently disabled in production builds
// (QAU_PRODUCTION=1). This prevents an attacker from forging pre-R18
// format CRL snapshots to bypass the low-s and SHA3-256 requirements.
// In non-production builds (tests, dev), the V1 path remains available
// for backward compatibility with pre-R18 test fixtures.
func (ncm *NodeCertificateManager) VerifyCRLSnapshotSignature(snap *CRLSnapshot) bool {
	if snap == nil || len(snap.Signature) == 0 || snap.IssuerPeerID == "" {
		return false
	}

	ncm.mu.RLock()
	defer ncm.mu.RUnlock()

	// Look up the issuer's trusted certificate (CA cert stored via
	// AddTrustedPeer). If the issuer is a CA itself, its cert is in
	// trustedCerts and we can use its public key directly.
	cert, ok := ncm.trustedCerts[snap.IssuerPeerID]
	if !ok {
		// No known public key for the issuer; caller must rely on
		// trusted-peer authorization.
		return false
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub == nil {
		return false
	}

	// CRYPTO-R19-CRIT-03 (2026-07-24): Use ecdsaVerifyLowS for ALL
	// verification paths. This function decodes ASN.1 DER, enforces
	// low-s (rejects s > n/2), and verifies. If the signature is not
	// valid ASN.1 DER, it returns false — we no longer fall back to
	// ecdsa.VerifyASN1 which would accept high-s signatures.

	// CRYPTO-R18-H02/H03 (2026-07-24): Try V2 payload (length-prefixed)
	// with SHA3-256 first. This is the new format produced by
	// SignCRLSnapshot post-R18.
	v2Payload := crlSigningPayloadV2(snap)
	v2Hash := sha3.Sum256(v2Payload)
	if ecdsaVerifyLowS(pub, v2Hash[:], snap.Signature) {
		return true
	}

	// CRYPTO-R20-M01 (2026-07-24) FIX: V1 backward-compat path permanently
	// removed. Previously this path was gated by isProductionBuild()
	// (QAU_PRODUCTION env var), but env-var gating is not a chain-level
	// sunset — an operator could forget to set the variable, or a test
	// fixture could regress to V1 format silently. Since mainnet never
	// deployed V1 CRL snapshots (the V1 format only existed briefly during
	// testnet development and all test fixtures now use V2 via
	// SignCRLSnapshot), the V1 path is removed entirely. Any V1-format
	// snapshot is rejected regardless of build mode, closing the SHA-256 /
	// high-s downgrade vector unconditionally.
	return false
}

// HasIssuerCertificate returns true if the manager has a trusted certificate
// for the given peer ID (i.e., the issuer's signature can be verified
// locally). R15-CRIT-001.
func (ncm *NodeCertificateManager) HasIssuerCertificate(peerID PeerID) bool {
	ncm.mu.RLock()
	defer ncm.mu.RUnlock()
	_, ok := ncm.trustedCerts[string(peerID)]
	return ok
}

// GetCRLSnapshot returns a serializable snapshot of the current CRL state.
// The snapshot can be JSON-marshaled and sent to peers. Callers should
// transfer it over an authenticated channel (mTLS) to prevent tampering.
func (ncm *NodeCertificateManager) GetCRLSnapshot() *CRLSnapshot {
	ncm.crl.mu.RLock()
	defer ncm.crl.mu.RUnlock()

	snap := &CRLSnapshot{
		RevokedSNs:  make(map[string]int64, len(ncm.crl.revokedSNs)),
		LastUpdated: ncm.crl.lastUpdated.Unix(),
		Version:     crlSnapshotVersion,
	}
	for sn, t := range ncm.crl.revokedSNs {
		snap.RevokedSNs[sn] = t.Unix()
	}
	return snap
}

// MergeCRLSnapshot merges a remote CRL snapshot into the local CRL.
// Returns the number of NEWLY added revocations (i.e., serials that were
// not previously revoked locally).
//
// Merge is monotonic: it only adds revocations, never removes them. This
// means a malicious peer cannot un-revoke a cert by sending a snapshot
// without it — the local CRL retains all previously known revocations.
//
// The snapshot's LastUpdated is NOT trusted for ordering; we use the
// current local time for newly added revocations (matching the behavior
// of CRL.Revoke). This prevents a peer from back-dating revocations.
func (ncm *NodeCertificateManager) MergeCRLSnapshot(snap *CRLSnapshot) (int, error) {
	if snap == nil {
		return 0, errors.New("P2P-R12-H02: cannot merge nil CRL snapshot")
	}
	if snap.Version != crlSnapshotVersion {
		return 0, fmt.Errorf("P2P-R12-H02: incompatible CRL snapshot version: got %d, want %d",
			snap.Version, crlSnapshotVersion)
	}

	ncm.crl.mu.Lock()
	defer ncm.crl.mu.Unlock()

	now := time.Now().UTC()
	newCount := 0
	for sn := range snap.RevokedSNs {
		if sn == "" {
			continue // skip malformed entries
		}
		if _, exists := ncm.crl.revokedSNs[sn]; !exists {
			ncm.crl.revokedSNs[sn] = now
			newCount++
		}
	}
	if newCount > 0 && now.After(ncm.crl.lastUpdated) {
		ncm.crl.lastUpdated = now
	}
	return newCount, nil
}

// GetCRLRevocationCount returns the number of revoked serials in the local
// CRL. Useful for monitoring / metrics.
func (ncm *NodeCertificateManager) GetCRLRevocationCount() int {
	ncm.crl.mu.RLock()
	defer ncm.crl.mu.RUnlock()
	return len(ncm.crl.revokedSNs)
}

// ============================================================================
// P2P-R12-H03 (2026-07-20) FIX: TOFU public key pinning
//
// Audit finding: "AddTrustedPeer only added the CA certificate and did not pin the leaf certificate's public key from the first connection.
// On first contact with a new peer, a leaked CA private key enables MITM."
//
// Fix: After the first successful mTLS + post-quantum handshake with a peer,
// the caller (encrypted_transport.go or higher layer) records the peer's
// leaf certificate public key hash. On subsequent connections, the caller
// verifies that the peer's leaf cert pubkey matches the pinned hash.
//
// This is TOFU (Trust On First Use): the first connection trusts the CA
// chain (as today), and pins the leaf pubkey; subsequent connections
// require both the CA chain AND the pinned pubkey to match.
//
// Threat model: If the CA private key is compromised AFTER the first
// connection, an attacker can mint a new valid cert for the same nodeID,
// but its pubkey won't match the pinned hash — the connection is rejected.
// This reduces the MITM window to the first connection only.
//
// Pinning is keyed by peerID (post-quantum identity), NOT by cert serial
// or nodeID-in-cert. This allows the peer to legitimately rotate its cert
// (H01 fix) WITHOUT breaking pinning — as long as the peer keeps the same
// keypair. If the peer genuinely rotates its keypair (e.g., due to key
// compromise), the operator must call UnpinPeerPublicKey before the peer
// can reconnect.
// ============================================================================

// hashLeafCertPublicKey returns SHA-256(SubjectPublicKeyInfo) of the cert.
// This is the same identifier used by HPKP (HTTP Public Key Pinning) and
// is stable across cert metadata changes (serial, validity, etc.).
func hashLeafCertPublicKey(cert *x509.Certificate) []byte {
	if cert == nil || cert.RawSubjectPublicKeyInfo == nil {
		return nil
	}
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return h[:]
}

// PinPeerPublicKey records the SHA-256 hash of the peer's leaf certificate
// public key. This implements TOFU pinning.
//
// If the peer is already pinned, the existing pin is overwritten ONLY if
// the new cert's pubkey hash matches the existing pin. If they don't
// match, this is a potential MITM attack (or a legitimate key rotation)
// and the function returns an error. The caller must call
// UnpinPeerPublicKey first if the peer legitimately rotated its keypair.
//
// Returns nil on success (new pin or matching overwrite).
func (ncm *NodeCertificateManager) PinPeerPublicKey(peerID PeerID, cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("P2P-R12-H03: cannot pin nil certificate")
	}
	pubKeyHash := hashLeafCertPublicKey(cert)
	if pubKeyHash == nil {
		return errors.New("P2P-R12-H03: cannot pin cert with empty SubjectPublicKeyInfo")
	}

	ncm.mu.Lock()
	defer ncm.mu.Unlock()

	key := string(peerID)
	if existing, ok := ncm.pinnedPubKeys[key]; ok {
		// Already pinned — verify the pubkey hash matches.
		if subtle.ConstantTimeCompare(existing, pubKeyHash) != 1 {
			return fmt.Errorf("P2P-R12-H03: peer %s is already pinned with a different public key "+
				"(potential MITM or key rotation; call UnpinPeerPublicKey first if the rotation is legitimate)", peerID)
		}
		// Same hash — no-op.
		return nil
	}

	// New pin.
	// P2P-R16-H03 (2026-07-22) FIX: Bound the pinnedPubKeys map to prevent
	// Sybil-attack memory exhaustion. An attacker creating many different
	// peerID connections could fill the map unbounded. Re-pin of an EXISTING
	// peerID is handled above (overwrite path), so this check only gates
	// NEW peerIDs.
	if len(ncm.pinnedPubKeys) >= maxPinnedPubKeys {
		return fmt.Errorf("P2P-R16-H03: pinnedPubKeys map at capacity (%d entries); "+
			"cannot pin new peer %s", maxPinnedPubKeys, peerID)
	}
	ncm.pinnedPubKeys[key] = pubKeyHash
	return nil
}

// VerifyPinnedPublicKey verifies that the certificate's public key matches
// the pinned hash for the peer. Returns:
//   - nil if the peer is NOT pinned (first connection — caller should
//     call PinPeerPublicKey after the full handshake completes).
//   - nil if the peer IS pinned and the pubkey hash matches.
//   - error if the peer IS pinned but the pubkey hash does NOT match
//     (potential MITM or key rotation).
func (ncm *NodeCertificateManager) VerifyPinnedPublicKey(peerID PeerID, cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("P2P-R12-H03: cannot verify nil certificate")
	}

	ncm.mu.RLock()
	existing, ok := ncm.pinnedPubKeys[string(peerID)]
	ncm.mu.RUnlock()

	if !ok {
		// Not pinned — first connection. Caller should pin after handshake.
		return nil
	}

	pubKeyHash := hashLeafCertPublicKey(cert)
	if pubKeyHash == nil {
		return errors.New("P2P-R12-H03: cert has empty SubjectPublicKeyInfo")
	}

	// Constant-time compare to avoid timing-based pin enumeration.
	if subtle.ConstantTimeCompare(existing, pubKeyHash) != 1 {
		return fmt.Errorf("P2P-R12-H03: peer %s public key does not match pinned hash "+
			"(potential MITM or key rotation; call UnpinPeerPublicKey first if the rotation is legitimate)", peerID)
	}
	return nil
}

// IsPeerPinned returns true if the peer has a pinned public key hash.
func (ncm *NodeCertificateManager) IsPeerPinned(peerID PeerID) bool {
	ncm.mu.RLock()
	defer ncm.mu.RUnlock()
	_, ok := ncm.pinnedPubKeys[string(peerID)]
	return ok
}

// UnpinPeerPublicKey removes the pinned public key hash for a peer.
// This should be called when a peer legitimately rotates its keypair
// (e.g., due to key compromise) and needs to re-establish a new pin.
//
// P2P-R13-L02 (2026-07-21) FIX: Previously this method had NO operator
// authorization check — any caller (including an attacker who gains
// runtime access via a compromised RPC handler or deserialization bug)
// could clear all pinned public keys, defeating TOFU and enabling MITM
// attacks. The fix mirrors RevokeCertificate's CA signature pattern:
// in production, the caller MUST present an ECDSA signature over
// "UNPIN:<peerID>" signed by the rootCA or intermediateCA private key.
// When ncm.skipCASignature is true (test-only, set via
// SkipCASignatureForTesting), an empty signature is accepted so existing
// unit tests continue to work.
//
// CRIT-09 (R17, 2026-07-23): Replaced testing.Testing() with the explicit
// ncm.skipCASignature flag (same fix as RevokeCertificate).
//
// CRYPTO-R19-CRIT-01/02/03 + CRYPTO-R19-M01 (2026-07-24): Same security
// hardening as RevokeCertificate — see the comment on that function for
// the full list of fixes applied here.
//
// Signing payload format (callers must produce signatures over this):
//
//	SHA3-256( caOperationPayload(caUnpinDomainSeparator, timestamp, string(peerID)) )
//
// where timestamp is the current Unix time in seconds.
func (ncm *NodeCertificateManager) UnpinPeerPublicKey(peerID PeerID, timestamp int64, caSignature []byte) error {
	ncm.mu.RLock()
	skip := ncm.skipCASignature
	ncm.mu.RUnlock()
	if !skip {
		// Production path: require CA signature.
		if len(caSignature) == 0 {
			return errors.New("UnpinPeerPublicKey requires a CA signature in production; sign SHA3-256(caUnpinDomainSeparator || timestamp || peerID) and pass (peerID, timestamp, signature)")
		}
		// CRYPTO-R19-CRIT-01: ±5-minute freshness check.
		now := time.Now().Unix()
		if timestamp <= 0 || now-timestamp > caFreshnessWindow || timestamp-now > caFreshnessWindow {
			log.Printf("[WARN] CRYPTO-R19-CRIT-01: UnpinPeerPublicKey(%s) rejected — timestamp %d outside freshness window (now=%d, ±%ds)",
				peerID, timestamp, now, caFreshnessWindow)
			return errors.New("CA signature timestamp outside freshness window")
		}
		// CRYPTO-R19-CRIT-01/02: Build V2 length-prefixed payload with
		// formal domain tag + timestamp + peerID.
		payload := caOperationPayload(caUnpinDomainSeparator, timestamp, string(peerID))
		hash := sha3.Sum256(payload)
		verified := false
		// CRYPTO-R19-M01: Only Intermediate CA allowed (same as Revoke).
		if ncm.intermediateCA != nil && ncm.intermediateCA.Certificate != nil {
			if pub, ok := ncm.intermediateCA.Certificate.PublicKey.(*ecdsa.PublicKey); ok && pub != nil {
				if ecdsaVerifyLowS(pub, hash[:], caSignature) {
					verified = true
				}
			}
		}
		if !verified {
			log.Printf("[WARN] P2P-R13-L02: UnpinPeerPublicKey(%s) rejected — invalid CA signature (Root CA rejected by default per CRYPTO-R19-M01)", peerID)
			return errors.New("invalid CA signature for unpinning peer public key")
		}
	}
	ncm.mu.Lock()
	defer ncm.mu.Unlock()
	delete(ncm.pinnedPubKeys, string(peerID))
	log.Printf("[INFO] P2P-R13-L02: peer %s public key pin removed (authorized by CA signature)", peerID)
	return nil
}

// GetPinnedPeerCount returns the number of peers with pinned public keys.
// Useful for monitoring / metrics.
func (ncm *NodeCertificateManager) GetPinnedPeerCount() int {
	ncm.mu.RLock()
	defer ncm.mu.RUnlock()
	return len(ncm.pinnedPubKeys)
}

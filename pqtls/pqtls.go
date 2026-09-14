// Quantaureum Node source, version 1.0.0.
package pqtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"

	logging "github.com/quantaureum/qau/log"
)

var (
	ErrPQTLSCertRequired    = errors.New("pqtls: post-quantum certificate required")
	ErrPQTLSHandshakeFailed = errors.New("pqtls: post-quantum handshake failed")
	ErrPQTLSNotSupported    = errors.New("pqtls: post-quantum TLS not supported by peer")
	// audit fix (H-2): RequirePQ is a no-op because custom PQCurveIDs
	// are not recognized by the standard Go crypto/tls. Setting RequirePQ=true
	// gives a false sense of post-quantum security while the actual key exchange
	// falls back to classical X25519. Callers that set RequirePQ=true will now
	// receive this error from ToTLSConfig to force them to acknowledge the gap.
	ErrPQTLSNotImplemented = errors.New("pqtls: RequirePQ=true but post-quantum TLS is not actually implemented; custom PQCurveIDs are ignored by standard Go crypto/tls. Set RequirePQ=false or integrate a real PQ-TLS library")
)

// SECURITY NOTE H-2: the following PQCurveID constants use
// custom IDs (0xFE01-0xFE03) in the private-use range. The standard Go crypto/tls
// package does NOT recognize these custom CurveIDs — it only supports standard
// curves like X25519, P-256, etc. Setting them in tls.Config.CurvePreferences
// will NOT enable actual post-quantum key exchange; the standard library will
// simply ignore unknown curve IDs (or fall back to a standard curve).
//
// Real post-quantum TLS (e.g., Kyber-based key exchange) requires either:
//  1. A forked/patched crypto/tls that implements the post-quantum key share
//     extension (e.g., draft-ietf-tls-hybrid-design), OR
//  2. A custom TLS extension negotiated via a custom ClientHello/ServerHello
//     handler, OR
//  3. A dedicated post-quantum TLS library (e.g., oqs-provider for OpenSSL).
//
// Until one of the above is integrated, the PQCurveID_* values below serve
// only as configuration markers and do NOT provide post-quantum security.
const (
	PQCurveID_Dilithium3 = 0xFE01
	PQCurveID_Kyber      = 0xFE02
	PQCurveID_Hybrid     = 0xFE03
)

type PQTLSConfig struct {
	MinVersion           uint16
	MaxVersion           uint16
	RequirePQ            bool
	PreferPQ             bool
	AllowedCipherSuites  []uint16
	EnableHybridExchange bool
	Certificates         []tls.Certificate
	RootCAs              *x509.CertPool
	ClientAuth           tls.ClientAuthType
	ServerName           string
}

func DefaultServerConfig() *PQTLSConfig {
	// audit fix (H-2): RequirePQ defaults to false because the custom
	// PQCurveIDs are not recognized by standard Go crypto/tls. Setting
	// RequirePQ=true previously gave a false sense of post-quantum security
	// while the actual key exchange used classical X25519. Callers that need
	// real PQ-TLS must integrate a dedicated library and set RequirePQ=true
	// only after verifying the integration works.
	return &PQTLSConfig{
		MinVersion:           tls.VersionTLS13,
		MaxVersion:           tls.VersionTLS13,
		RequirePQ:            false,
		PreferPQ:             false,
		EnableHybridExchange: false,
		ClientAuth:           tls.RequireAndVerifyClientCert,
	}
}

func DefaultClientConfig() *PQTLSConfig {
	// audit fix (H-2): same rationale as DefaultServerConfig —
	// PreferPQ/EnableHybridExchange are no-ops without a real PQ-TLS library.
	return &PQTLSConfig{
		MinVersion:           tls.VersionTLS13,
		MaxVersion:           tls.VersionTLS13,
		RequirePQ:            false,
		PreferPQ:             false,
		EnableHybridExchange: false,
	}
}

func (c *PQTLSConfig) ToTLSConfig() (*tls.Config, error) {
	// audit fix (H-2): fail-closed when RequirePQ=true is set but the
	// standard library cannot honor it. Previously this silently fell back to
	// classical X25519, giving a false sense of post-quantum security.
	if c.RequirePQ {
		return nil, ErrPQTLSNotImplemented
	}

	// AUDIT (2026) ZK-NN-6 FIX: Warn when PreferPQ is set, since it is a
	// silent no-op — ToTLSConfig never consults it. This prevents operators
	// from believing they have PQ-TLS preference enabled when they don't.
	if c.PreferPQ {
		logging.Warn("pqtls: PreferPQ is set but is a silent no-op — post-quantum TLS is not actually enabled. ToTLSConfig does not consult this flag.",
			map[string]any{
				"module":    "pqtls",
				"prefer_pq": true,
			})
	}

	tlsCfg := &tls.Config{
		MinVersion:   c.MinVersion,
		MaxVersion:   c.MaxVersion,
		Certificates: c.Certificates,
		RootCAs:      c.RootCAs,
		ClientAuth:   c.ClientAuth,
		ServerName:   c.ServerName,
	}

	// PQTLS-01 FIX (deep-audit 2026-07-12): for server-side mutual TLS, Go
	// verifies client certificates against ClientCAs, NOT RootCAs. Without this,
	// a config with ClientAuth=RequireAndVerifyClientCert and a non-system node
	// CA leaves ClientCAs nil, so Go falls back to the host system root pool and
	// the configured CA never authenticates peers (auth against the wrong trust
	// anchor). Use the same CA pool to verify inbound client certs.
	if c.ClientAuth >= tls.VerifyClientCertIfGiven {
		tlsCfg.ClientCAs = c.RootCAs
	}

	if c.EnableHybridExchange {
		// SECURITY FIX H-2: warn that custom PQCurveIDs are
		// not recognized by the standard Go crypto/tls package. Setting them in
		// CurvePreferences does NOT enable actual post-quantum key exchange — the
		// standard library ignores unknown curve IDs. Real post-quantum TLS
		// requires a custom TLS extension or a patched crypto/tls. See the
		// PQCurveID constant comments above for details.
		logging.Warn("pqtls: post-quantum TLS may not be actually enabled - custom PQCurveIDs are not recognized by standard Go crypto/tls",
			map[string]any{
				"module":          "pqtls",
				"hybrid_exchange": true,
				"require_pq":      c.RequirePQ,
			})
		tlsCfg.CurvePreferences = []tls.CurveID{
			tls.CurveID(PQCurveID_Hybrid),
			tls.CurveID(PQCurveID_Kyber),
			tls.X25519,
		}
	}

	return tlsCfg, nil
}

func isPostQuantumCert(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.4.1.54392.5.1400" {
			return true
		}
	}
	return false
}

type PQTLSManager struct {
	mu       sync.RWMutex
	config   *PQTLSConfig
	tlsCfg   *tls.Config
	certPool *x509.CertPool
}

func NewPQTLSManager(config *PQTLSConfig) (*PQTLSManager, error) {
	tlsCfg, err := config.ToTLSConfig()
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if config.RootCAs != nil {
		pool = config.RootCAs
	}

	return &PQTLSManager{
		config:   config,
		tlsCfg:   tlsCfg,
		certPool: pool,
	}, nil
}

func (m *PQTLSManager) TLSConfig() *tls.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tlsCfg.Clone()
}

func (m *PQTLSManager) UpdateCertificates(certs []tls.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.config.Certificates = certs
	tlsCfg, err := m.config.ToTLSConfig()
	if err != nil {
		return err
	}
	m.tlsCfg = tlsCfg
	return nil
}

func (m *PQTLSManager) AddRootCA(cert *x509.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certPool.AddCert(cert)
	m.config.RootCAs = m.certPool
	// PQTLS-02 FIX (deep-audit 2026-07-12): rebuild the cached tls.Config so the
	// newly trusted CA takes effect. Previously only config.RootCAs was updated,
	// but TLSConfig() returns a clone of m.tlsCfg, which kept the stale (possibly
	// nil) RootCAs/ClientCAs — the added anchor was silently ignored.
	if tlsCfg, err := m.config.ToTLSConfig(); err == nil {
		m.tlsCfg = tlsCfg
	}
}

// IsPostQuantumEnabled reports whether post-quantum TLS is ACTUALLY in effect.
//
// AUDIT (2026) ZK-NN-6 FIX: Previously returned RequirePQ || PreferPQ,
// which misreported PQ-TLS as enabled when it was not. RequirePQ=true causes
// ToTLSConfig to fail (no TLS config produced), and PreferPQ is a silent
// no-op. EnableHybridExchange sets custom curve IDs that Go's crypto/tls
// ignores, falling back to classical X25519. None of these flags result in
// actual post-quantum key exchange. This method now always returns false
// until a real PQ-TLS library is integrated.
func (m *PQTLSManager) IsPostQuantumEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Post-quantum TLS is NOT implemented. All config flags (RequirePQ,
	// PreferPQ, EnableHybridExchange) fail to produce actual PQ key exchange.
	// Return false to avoid giving callers a false sense of PQ security.
	return false
}

func (m *PQTLSManager) GetStats() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]any{
		"require_pq":           m.config.RequirePQ,
		"prefer_pq":            m.config.PreferPQ,
		"hybrid_exchange":      m.config.EnableHybridExchange,
		"min_version":          m.config.MinVersion,
		"max_version":          m.config.MaxVersion,
		"certificate_count":    len(m.config.Certificates),
		"root_ca_count":        len(m.certPool.Subjects()),
		"client_auth_required": m.config.ClientAuth >= tls.RequireAndVerifyClientCert,
	}
}

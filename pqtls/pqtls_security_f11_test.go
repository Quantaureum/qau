// Quantaureum Node source, version 1.0.0.
package pqtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

// newTestCertificate creates a self-signed ECDSA certificate usable for both
// server and client authentication, together with a pool trusting it.
func newTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pqtls-f11-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, pool
}

func TestPQTLS_MutualTLS13Handshake(t *testing.T) {
	cert, pool := newTestCertificate(t)

	serverCfg := DefaultServerConfig()
	serverCfg.Certificates = []tls.Certificate{cert}
	serverCfg.RootCAs = pool
	serverTLS, err := serverCfg.ToTLSConfig()
	if err != nil {
		t.Fatalf("server ToTLSConfig: %v", err)
	}

	clientCfg := DefaultClientConfig()
	clientCfg.Certificates = []tls.Certificate{cert}
	clientCfg.RootCAs = pool
	clientCfg.ServerName = "localhost"
	clientTLS, err := clientCfg.ToTLSConfig()
	if err != nil {
		t.Fatalf("client ToTLSConfig: %v", err)
	}

	if serverTLS.MinVersion != tls.VersionTLS13 || clientTLS.MinVersion != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3 minimum, server=%#x client=%#x", serverTLS.MinVersion, clientTLS.MinVersion)
	}
	if clientTLS.ClientCAs != nil {
		t.Fatal("client config must not set ClientCAs")
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	deadline := time.Now().Add(10 * time.Second)
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set server deadline: %v", err)
	}
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	serverErr := make(chan error, 1)
	var serverState tls.ConnectionState
	go func() {
		conn := tls.Server(serverConn, serverTLS)
		if err := conn.Handshake(); err != nil {
			serverErr <- err
			return
		}
		serverState = conn.ConnectionState()
		serverErr <- nil
	}()

	client := tls.Client(clientConn, clientTLS)
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	clientState := client.ConnectionState()

	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	if clientState.Version != tls.VersionTLS13 {
		t.Fatalf("client negotiated version %#x, want TLS 1.3", clientState.Version)
	}
	if serverState.Version != tls.VersionTLS13 {
		t.Fatalf("server negotiated version %#x, want TLS 1.3", serverState.Version)
	}
	if len(clientState.PeerCertificates) == 0 {
		t.Fatal("client did not receive the server certificate")
	}
	if len(serverState.PeerCertificates) == 0 {
		t.Fatal("server did not receive the client certificate")
	}
}

func TestPQTLS_MutualTLSRejectsMissingClientCert(t *testing.T) {
	cert, pool := newTestCertificate(t)

	serverCfg := DefaultServerConfig()
	serverCfg.Certificates = []tls.Certificate{cert}
	serverCfg.RootCAs = pool
	serverTLS, err := serverCfg.ToTLSConfig()
	if err != nil {
		t.Fatalf("server ToTLSConfig: %v", err)
	}

	clientCfg := DefaultClientConfig()
	clientCfg.RootCAs = pool
	clientCfg.ServerName = "localhost"
	clientTLS, err := clientCfg.ToTLSConfig()
	if err != nil {
		t.Fatalf("client ToTLSConfig: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	deadline := time.Now().Add(10 * time.Second)
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set server deadline: %v", err)
	}
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- tls.Server(serverConn, serverTLS).Handshake()
	}()

	client := tls.Client(clientConn, clientTLS)
	_ = client.Handshake()

	// A TLS 1.3 client can finish before the server validates its certificate;
	// drain the connection so the server's rejection alert is delivered.
	buf := make([]byte, 1)
	if _, readErr := client.Read(buf); readErr == nil {
		t.Fatal("expected the server rejection to surface as a read error")
	}

	if err := <-serverErr; err == nil {
		t.Fatal("server accepted a client without a certificate")
	}
}

func TestToTLSConfig_RequirePQFailsClosed(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.RequirePQ = true

	tlsCfg, err := cfg.ToTLSConfig()
	if !errors.Is(err, ErrPQTLSNotImplemented) {
		t.Fatalf("ToTLSConfig error = %v, want ErrPQTLSNotImplemented", err)
	}
	if tlsCfg != nil {
		t.Fatal("ToTLSConfig must not return a config when RequirePQ=true")
	}

	if _, err := NewPQTLSManager(cfg); !errors.Is(err, ErrPQTLSNotImplemented) {
		t.Fatalf("NewPQTLSManager error = %v, want ErrPQTLSNotImplemented", err)
	}
}

func TestToTLSConfig_ClientCASTrustAnchorBoundary(t *testing.T) {
	_, pool := newTestCertificate(t)

	cfg := DefaultServerConfig()
	cfg.RootCAs = pool
	tlsCfg, err := cfg.ToTLSConfig()
	if err != nil {
		t.Fatalf("ToTLSConfig: %v", err)
	}
	if tlsCfg.ClientCAs != pool {
		t.Fatal("ClientCAs must mirror RootCAs when client certs are verified")
	}

	cfg.ClientAuth = tls.VerifyClientCertIfGiven
	tlsCfg, err = cfg.ToTLSConfig()
	if err != nil {
		t.Fatalf("ToTLSConfig: %v", err)
	}
	if tlsCfg.ClientCAs != pool {
		t.Fatal("ClientCAs must be set for VerifyClientCertIfGiven")
	}

	cfg.ClientAuth = tls.RequireAnyClientCert
	tlsCfg, err = cfg.ToTLSConfig()
	if err != nil {
		t.Fatalf("ToTLSConfig: %v", err)
	}
	if tlsCfg.ClientCAs != nil {
		t.Fatal("ClientCAs must stay nil when certificates are not verified")
	}
}

func TestPQTLSManager_RootCAAndCertUpdatesTakeEffect(t *testing.T) {
	mgr, err := NewPQTLSManager(DefaultClientConfig())
	if err != nil {
		t.Fatalf("NewPQTLSManager: %v", err)
	}
	if mgr.GetStats()["root_ca_count"] != 0 {
		t.Fatal("new manager must start without root CAs")
	}

	cert, _ := newTestCertificate(t)
	mgr.AddRootCA(cert.Leaf)

	tlsCfg := mgr.TLSConfig()
	if tlsCfg.RootCAs == nil {
		t.Fatal("TLSConfig must expose the added root CA")
	}
	if got := mgr.GetStats()["root_ca_count"]; got != 1 {
		t.Fatalf("root_ca_count = %v, want 1", got)
	}

	if err := mgr.UpdateCertificates([]tls.Certificate{cert}); err != nil {
		t.Fatalf("UpdateCertificates: %v", err)
	}
	if got := len(mgr.TLSConfig().Certificates); got != 1 {
		t.Fatalf("certificate count = %d, want 1", got)
	}
	if got := mgr.GetStats()["certificate_count"]; got != 1 {
		t.Fatalf("certificate_count = %v, want 1", got)
	}
}

func TestPQTLSManager_IsPostQuantumEnabledReportsReality(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.PreferPQ = true
	cfg.EnableHybridExchange = true

	mgr, err := NewPQTLSManager(cfg)
	if err != nil {
		t.Fatalf("NewPQTLSManager: %v", err)
	}
	if mgr.IsPostQuantumEnabled() {
		t.Fatal("IsPostQuantumEnabled must report false: standard crypto/tls ignores custom PQ curve IDs")
	}

	curves := mgr.TLSConfig().CurvePreferences
	if len(curves) == 0 || curves[0] != tls.CurveID(PQCurveID_Hybrid) {
		t.Fatalf("hybrid config must mark the hybrid PQ curve first, got %v", curves)
	}

	stats := mgr.GetStats()
	if stats["require_pq"] != false || stats["prefer_pq"] != true || stats["hybrid_exchange"] != true {
		t.Fatalf("unexpected stats: %v", stats)
	}
	if stats["client_auth_required"] != false {
		t.Fatalf("client_auth_required = %v, want false", stats["client_auth_required"])
	}
}

// Quantaureum Node source, version 1.0.0.
package enode

import (
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/quantaureum/qau/crypto"
)

// buildSignedENR constructs a signed ENR record with the given IP for use in
// P2P-H03 tests. The URL node ID is derived from the Dilithium3 public key
// (matching the DeriveID check in ParseV4).
func buildSignedENR(t *testing.T, ip net.IP, tcp, udp int) (urlID string, enrB64 string) {
	t.Helper()

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pubBytes := kp.Public.Bytes()
	if len(pubBytes) != 1952 {
		t.Fatalf("Dilithium3 public key size = %d, want 1952", len(pubBytes))
	}

	r := NewRecord()
	r.SetSeq(1)
	r.SetID("v4")
	r.SetPublicKey(pubBytes)
	r.SetIP(ip)
	r.SetTCP(tcp)
	r.SetUDP(udp)

	signedData := r.EncodeSignedData()
	sig, err := crypto.Sign(kp.Private, signedData)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	r.SetSignature(sig)

	encoded, err := r.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// base64url encoding (URL-safe base64 without padding, as in ParseV4).
	s := base64.URLEncoding.EncodeToString(encoded)
	s = strings.TrimRight(s, "=")
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")

	urlID = DeriveID(pubBytes).Hex()
	enrB64 = s
	return urlID, enrB64
}

// TestP2P_H03_ENR_Ipv4_Unroutable verifies that an ENR containing a loopback
// IPv4 address is rejected by ParseV4 even when the URL host is a routable IP.
// This is the core P2P-H03 fix: ENR-provided IPs must pass isUnroutableIP.
func TestP2P_H03_ENR_Ipv4_Unroutable(t *testing.T) {
	urlID, enrB64 := buildSignedENR(t, net.ParseIP("127.0.0.1"), 9000, 9000)

	// URL uses a routable IP; ENR carries the unroutable 127.0.0.1.
	url := "enode://" + urlID + "@203.0.113.10:9000?enr=" + enrB64
	_, err := ParseV4(url)
	if err == nil {
		t.Fatal("ParseV4 accepted ENR with unroutable IPv4 127.0.0.1 (P2P-H03 regression)")
	}
	if !strings.Contains(err.Error(), "ENR IPv4") || !strings.Contains(err.Error(), "unroutable") {
		t.Errorf("unexpected error %q, want ENR IPv4 unroutable rejection", err.Error())
	}
}

// TestP2P_H03_ENR_Ipv4_PrivateRejected verifies that an ENR carrying a private
// IPv4 (10.x) is rejected.
func TestP2P_H03_ENR_Ipv4_PrivateRejected(t *testing.T) {
	urlID, enrB64 := buildSignedENR(t, net.ParseIP("10.0.0.1"), 9000, 9000)

	url := "enode://" + urlID + "@203.0.113.10:9000?enr=" + enrB64
	_, err := ParseV4(url)
	if err == nil {
		t.Fatal("ParseV4 accepted ENR with private IPv4 10.0.0.1 (P2P-H03 regression)")
	}
	if !strings.Contains(err.Error(), "ENR IPv4") || !strings.Contains(err.Error(), "unroutable") {
		t.Errorf("unexpected error %q, want ENR IPv4 unroutable rejection", err.Error())
	}
}

// TestP2P_H03_ENR_Ipv6_LoopbackRejected verifies that an ENR carrying an IPv6
// loopback (::1) is rejected.
func TestP2P_H03_ENR_Ipv6_LoopbackRejected(t *testing.T) {
	urlID, enrB64 := buildSignedENR(t, net.ParseIP("::1"), 9000, 9000)

	url := "enode://" + urlID + "@203.0.113.10:9000?enr=" + enrB64
	_, err := ParseV4(url)
	if err == nil {
		t.Fatal("ParseV4 accepted ENR with IPv6 loopback ::1 (P2P-H03 regression)")
	}
	if !strings.Contains(err.Error(), "ENR IPv6") || !strings.Contains(err.Error(), "unroutable") {
		t.Errorf("unexpected error %q, want ENR IPv6 unroutable rejection", err.Error())
	}
}

// TestP2P_H03_ENR_Routable_Accepted verifies that an ENR carrying a routable
// public IP is accepted (negative test — ensures the fix does not over-block).
func TestP2P_H03_ENR_Routable_Accepted(t *testing.T) {
	urlID, enrB64 := buildSignedENR(t, net.ParseIP("203.0.113.42"), 9000, 9000)

	url := "enode://" + urlID + "@203.0.113.10:9000?enr=" + enrB64
	node, err := ParseV4(url)
	if err != nil {
		t.Fatalf("ParseV4 rejected valid routable ENR: %v", err)
	}
	if !node.IP().Equal(net.ParseIP("203.0.113.42")) {
		t.Errorf("node.IP = %v, want 203.0.113.42 (ENR IP should take precedence)", node.IP())
	}
}

// TestR31_P2_ToNode_RejectsUnroutableIP verifies that ToNode() rejects ENR
// records containing unroutable IPs (loopback, private, etc.). This is the
// defense-in-depth check added in R31-P2: even if a caller obtains a Record
// through a path that bypasses ParseV4's IP validation, ToNode() itself
// refuses to produce a Node with an unusable IP.
// R31-P2 FIX (2026-07-28).
func TestR31_P2_ToNode_RejectsUnroutableIP(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pubBytes := kp.Public.Bytes()
	r := NewRecord()
	r.SetSeq(1)
	r.SetID("v4")
	r.SetPublicKey(pubBytes)
	r.SetIP(net.ParseIP("127.0.0.1"))
	r.SetTCP(9000)
	r.SetUDP(9000)

	sig, err := crypto.Sign(kp.Private, r.EncodeSignedData())
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	r.SetSignature(sig)

	_, err = r.ToNode()
	if err == nil {
		t.Fatal("ToNode accepted ENR with unroutable IPv4 127.0.0.1")
	}
	if !strings.Contains(err.Error(), "unroutable") {
		t.Errorf("unexpected error %q, want 'unroutable'", err.Error())
	}
}

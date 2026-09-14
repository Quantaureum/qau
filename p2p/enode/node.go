// Quantaureum Node source, version 1.0.0.
// Package enode implements the Ethereum Node Record (ENR) and node identification.
package enode

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"
)

const (
	// IDLength is the length of a node ID in bytes (32 bytes = 256 bits)
	IDLength = 32
)

var (
	// ErrInvalidURL is returned when the enode URL is invalid
	ErrInvalidURL = errors.New("invalid enode URL")

	// ErrInvalidID is returned when the node ID is invalid
	ErrInvalidID = errors.New("invalid node ID")

	// ErrInvalidIP is returned when the IP address is invalid
	ErrInvalidIP = errors.New("invalid IP address")

	// ErrInvalidPort is returned when the port is invalid
	ErrInvalidPort = errors.New("invalid port")
)

// ID represents a unique node identifier (32 bytes)
type ID [IDLength]byte

// Bytes returns the ID as a byte slice
func (id ID) Bytes() []byte {
	return id[:]
}

// Hex returns the hex representation of the ID
func (id ID) Hex() string {
	return hex.EncodeToString(id[:])
}

// String returns the hex representation of the ID
func (id ID) String() string {
	return id.Hex()
}

// IsEmpty returns true if the ID is all zeros
func (id ID) IsEmpty() bool {
	for _, b := range id {
		if b != 0 {
			return false
		}
	}
	return true
}

// HexToID converts a hex string to ID
func HexToID(s string) (ID, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")

	b, err := hex.DecodeString(s)
	if err != nil {
		return ID{}, fmt.Errorf("%w: %v", ErrInvalidID, err)
	}

	if len(b) != IDLength {
		return ID{}, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidID, IDLength, len(b))
	}

	var id ID
	copy(id[:], b)
	return id, nil
}

// BytesToID converts bytes to ID
func BytesToID(b []byte) (ID, error) {
	if len(b) != IDLength {
		return ID{}, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidID, IDLength, len(b))
	}
	var id ID
	copy(id[:], b)
	return id, nil
}

// GenerateID generates a random node ID
func GenerateID() (ID, error) {
	var id ID
	_, err := rand.Read(id[:])
	if err != nil {
		return ID{}, fmt.Errorf("failed to generate random ID: %w", err)
	}
	return id, nil
}

// DeriveID derives a node ID from a Dilithium3 public key.
// SECURITY (audit R3-P2P-01): This is the single canonical derivation used across
// the codebase. It uses SHA3-256(pubkey) to produce a uniformly distributed
// 32-byte ID, preventing collision attacks possible with pubkey[:32] (where
// an attacker could craft a key whose first 32 bytes match a target).
//
// Previously, two incompatible ID spaces coexisted:
//   - host.go / encrypted_transport.go used SHA3-256(pubkey) for PeerID/PoW
//   - enode.DeriveID used pubkey[:32] (this function)
//
// This caused discovery to fail (PoW nonces computed in one space failed
// verification in the other) and created "phantom" duplicate node identities
// in the routing table. Unifying on SHA3-256 fixes both issues.
func DeriveID(pubkey []byte) ID {
	h := sha3.New256()
	h.Write(pubkey)
	var id ID
	copy(id[:], h.Sum(nil))
	return id
}

// Node represents a network node with its identity and network information
type Node struct {
	id  ID
	ip  net.IP
	tcp int
	udp int
	seq uint64  // sequence number for ENR
	r   *Record // ENR record (defined in enr.go)
}

// NewNode creates a new node with the given ID and network information
func NewNode(id ID, ip net.IP, tcp, udp int) *Node {
	return &Node{
		id:  id,
		ip:  ip,
		tcp: tcp,
		udp: udp,
	}
}

// ID returns the node's identifier
func (n *Node) ID() ID {
	return n.id
}

// IP returns the node's IP address
func (n *Node) IP() net.IP {
	return n.ip
}

// TCP returns the node's TCP port
func (n *Node) TCP() int {
	return n.tcp
}

// UDP returns the node's UDP port
func (n *Node) UDP() int {
	return n.udp
}

// Seq returns the node's sequence number
func (n *Node) Seq() uint64 {
	return n.seq
}

// SetSeq sets the node's sequence number
func (n *Node) SetSeq(seq uint64) {
	n.seq = seq
}

// Record returns the node's ENR record
func (n *Node) Record() *Record {
	return n.r
}

// HasENR returns whether this node carries a signed ENR record.
// P2P-C03 FIX (R30, 2026-07-26): Traditional discv4 NEIGHBORS responses
// carry only (IP, Port, ID) with no ENR. The previous ValidateNodeID
// required every node to have an ENR, which rejected all discv4-discovered
// peers and partitioned the network — only bootstrap nodes (configured
// with ENR) could connect. Callers must now branch on HasENR:
//   - true  → full ENR-based validation (signature, pubkey binding, PoW)
//   - false → basic validation only (ID format, IP routability) and the
//     node is scheduled for lazy ENR fetch via ENRRequest.
func (n *Node) HasENR() bool {
	return n.r != nil
}

// SetRecord sets the node's ENR record
func (n *Node) SetRecord(r *Record) {
	n.r = r
}

// isUnroutableIP returns true if the IP address is private, loopback, link-local,
// multicast, or otherwise unsuitable for public P2P networking.
// audit-fix P2P-DNS-1: prevents DNS rebinding attacks that resolve to internal addresses.
func isUnroutableIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	return false
}

// IsUnroutableIP is the exported form of isUnroutableIP for cross-package use
// (e.g. discovery's ValidateNodeID needs to validate IPs of discv4-only nodes
// that have no ENR record to lean on). P2P-C03 FIX (R30, 2026-07-26).
func IsUnroutableIP(ip net.IP) bool {
	return isUnroutableIP(ip)
}

// String returns the enode URL representation
func (n *Node) String() string {
	return n.URLv4()
}

// URLv4 returns the enode URL in v4 format
// Format: enode://<node-id>@<ip>:<tcp-port>?discport=<udp-port>
func (n *Node) URLv4() string {
	addr := fmt.Sprintf("%s:%d", n.ip.String(), n.tcp)
	if n.udp != n.tcp && n.udp != 0 {
		return fmt.Sprintf("enode://%s@%s?discport=%d", n.id.Hex(), addr, n.udp)
	}
	return fmt.Sprintf("enode://%s@%s", n.id.Hex(), addr)
}

// ParseV4 parses an enode URL in v4 format
// Format: enode://<node-id>@<ip>:<tcp-port>?discport=<udp-port>&enr=<base64>
// CRITICAL SECURITY FIX: Parse and verify ENR signature when 'enr' parameter is present
func ParseV4(rawurl string) (*Node, error) {
	// Parse the URL
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}

	// Check scheme
	if u.Scheme != "enode" {
		return nil, fmt.Errorf("%w: expected 'enode' scheme, got '%s'", ErrInvalidURL, u.Scheme)
	}

	// Parse node ID from user info
	if u.User == nil {
		return nil, fmt.Errorf("%w: missing node ID", ErrInvalidURL)
	}
	idHex := u.User.Username()
	id, err := HexToID(idHex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid node ID: %v", ErrInvalidURL, err)
	}

	// Parse host and port
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid host:port: %v", ErrInvalidURL, err)
	}

	// Parse IP
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("%w: cannot resolve host '%s'", ErrInvalidIP, host)
		}
		for _, resolved := range ips {
			if !isUnroutableIP(resolved) {
				ip = resolved
				break
			}
		}
		if ip == nil {
			return nil, fmt.Errorf("%w: host '%s' resolves only to private/internal addresses", ErrInvalidIP, host)
		}
	}
	if isUnroutableIP(ip) {
		return nil, fmt.Errorf("%w: host '%s' resolves to non-routable address %s", ErrInvalidIP, host, ip.String())
	}

	// Parse TCP port
	tcp, err := strconv.Atoi(portStr)
	if err != nil || tcp < 0 || tcp > 65535 {
		return nil, fmt.Errorf("%w: invalid TCP port '%s'", ErrInvalidPort, portStr)
	}

	// Parse UDP port from query (discport parameter)
	udp := tcp // default to same as TCP
	if discport := u.Query().Get("discport"); discport != "" {
		udp, err = strconv.Atoi(discport)
		if err != nil || udp < 0 || udp > 65535 {
			return nil, fmt.Errorf("%w: invalid UDP port '%s'", ErrInvalidPort, discport)
		}
	}

	node := NewNode(id, ip, tcp, udp)

	// CRITICAL SECURITY FIX: Parse and verify ENR signature if present
	// ENR parameter contains base64url-encoded QNR record
	if enrParam := u.Query().Get("enr"); enrParam != "" {
		// Decode base64url (URL-safe base64)
		// Standard base64 uses + and /, URL-safe uses - and _
		enrBase64 := strings.ReplaceAll(enrParam, "-", "+")
		enrBase64 = strings.ReplaceAll(enrBase64, "_", "/")

		// Add padding if necessary
		if len(enrBase64)%4 != 0 {
			enrBase64 += strings.Repeat("=", 4-len(enrBase64)%4)
		}

		enrBytes, err := base64.StdEncoding.DecodeString(enrBase64)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decode ENR base64: %v", ErrInvalidURL, err)
		}

		// Parse ENR record
		record, err := DecodeRecord(enrBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse ENR record: %v", ErrInvalidURL, err)
		}

		// CRITICAL SECURITY FIX: Verify ENR signature to prevent MITM attacks
		// An attacker could modify the ENR record after signing (IP, ports, etc.)
		// without signature verification
		if err := record.VerifySignature(); err != nil {
			return nil, fmt.Errorf("ENR signature verification failed: %w", err)
		}

		// SECURITY (audit P2P-11): Bind the URL node ID to the ENR public key.
		// Without this check, an attacker can present a valid ENR signed with
		// their own Dilithium3 key but claim a different node ID in the URL,
		// enabling identity spoofing and routing table poisoning. The URL ID
		// must match the ID cryptographically derived from the ENR public key.
		enrPubkey := record.PublicKey()
		if enrPubkey != nil {
			enrID := DeriveID(enrPubkey)
			if enrID != id {
				return nil, fmt.Errorf("%w: URL node ID does not match ENR public key", ErrInvalidID)
			}
		}

		// Use ENR data to populate node (ENR takes precedence over URL params)
		// P2P-H03 FIX (R29, audit 2026-07-25): ENR-provided IPs must pass
		// isUnroutableIP, same as URL-provided IPs. Without this, a malicious
		// node can publish an ENR pointing to an internal/private IP (e.g.
		// 127.0.0.1, 10.x, 192.168.x) and trick other nodes into connecting
		// to it — an SSRF auxiliary vector. Reject the ENR if its IP is
		// unroutable; do NOT silently fall back to the URL IP, because a
		// signed ENR with a bad IP is itself suspicious.
		if enrIP := record.IP(); enrIP != nil {
			if isUnroutableIP(enrIP) {
				return nil, fmt.Errorf("%w: ENR IPv4 %s is unroutable (private/loopback/link-local)", ErrInvalidIP, enrIP.String())
			}
			ip = enrIP
		}
		if enrIP6 := record.IP6(); enrIP6 != nil {
			if isUnroutableIP(enrIP6) {
				return nil, fmt.Errorf("%w: ENR IPv6 %s is unroutable (private/loopback/link-local)", ErrInvalidIP, enrIP6.String())
			}
			ip = enrIP6
		}
		if enrTCP := record.TCP(); enrTCP > 0 {
			tcp = enrTCP
		}
		if enrUDP := record.UDP(); enrUDP > 0 {
			udp = enrUDP
		}

		// Reconstruct node with ENR-derived values
		node = NewNode(id, ip, tcp, udp)
		node.seq = record.Seq()
		node.r = record
	}

	return node, nil
}

// ParseV4WithDefault parses an enode URL and returns error on failure
func ParseV4WithDefault(rawurl string) (*Node, error) {
	return ParseV4(rawurl)
}

// Equal returns true if two nodes have the same ID
func (n *Node) Equal(other *Node) bool {
	if n == nil || other == nil {
		return n == other
	}
	return n.id == other.id
}

// Addr returns the TCP address of the node
func (n *Node) Addr() *net.TCPAddr {
	return &net.TCPAddr{
		IP:   n.ip,
		Port: n.tcp,
	}
}

// UDPAddr returns the UDP address of the node
func (n *Node) UDPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   n.ip,
		Port: n.udp,
	}
}

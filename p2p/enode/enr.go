// Quantaureum Node source, version 1.0.0.
// Package enode implements the Quantaureum Node Record (QNR) format.
// QNR is based on EIP-778 ENR but uses Dilithium3 quantum-resistant keys.
package enode

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"

	"github.com/quantaureum/qau/crypto"
)

const (
	// MaxRecordSize is the maximum size of a QNR record in bytes
	// Increased from ENR's 300 to accommodate larger Dilithium3 keys
	MaxRecordSize = 8000

	// QNR key names
	keyID        = "id"
	keyDilithium = "dilithium3"
	keyIP        = "ip"
	keyIP6       = "ip6"
	keyTCP       = "tcp"
	keyUDP       = "udp"
	keyTCP6      = "tcp6"
	keyUDP6      = "udp6"
	keyPoWNonce  = "pow" // PoW nonce for Sybil resistance
)

var (
	// ErrRecordTooLarge is returned when the record exceeds MaxRecordSize
	ErrRecordTooLarge = errors.New("QNR record too large")

	// ErrInvalidRecord is returned when the record format is invalid
	ErrInvalidRecord = errors.New("invalid QNR record")

	// ErrInvalidSignature is returned when the signature is invalid
	ErrInvalidSignature = errors.New("invalid QNR signature")

	// ErrMissingKey is returned when a required key is missing
	ErrMissingKey = errors.New("missing required key")
)

// pair represents a key-value pair in an ENR record
type pair struct {
	key   string
	value []byte
}

// Record represents an Ethereum Node Record (ENR)
type Record struct {
	seq       uint64
	signature []byte
	pairs     []pair
}

// NewRecord creates a new empty ENR record
func NewRecord() *Record {
	return &Record{
		seq:   0,
		pairs: make([]pair, 0),
	}
}

// Seq returns the sequence number of the record
func (r *Record) Seq() uint64 {
	return r.seq
}

// SetSeq sets the sequence number of the record
func (r *Record) SetSeq(seq uint64) {
	r.seq = seq
}

// Signature returns the signature of the record
func (r *Record) Signature() []byte {
	return r.signature
}

// SetSignature sets the signature of the record
func (r *Record) SetSignature(sig []byte) {
	r.signature = sig
}

// VerifySignature verifies the record's signature using the embedded public key.
// Returns nil if signature is valid, error otherwise.
// audit-fix CRITICAL: ENR signature was never verified in ToNode()
func (r *Record) VerifySignature() error {
	if len(r.signature) == 0 {
		return ErrInvalidSignature
	}

	pubkey := r.PublicKey()
	if pubkey == nil {
		return ErrMissingKey
	}

	// Reconstruct the signed data: seq + pairs (without signature)
	// The signature is over the record content without the signature field itself
	signedData := r.encodeSignedData()

	// Verify using Dilithium3
	pubKey, err := crypto.PublicKeyFromBytes(pubkey)
	if err != nil {
		return fmt.Errorf("%w: failed to parse public key: %v", ErrInvalidSignature, err)
	}

	if !pubKey.Verify(signedData, r.signature) {
		return ErrInvalidSignature
	}

	return nil
}

// EncodeSignedData encodes the record data that was signed (seq + pairs)
func (r *Record) EncodeSignedData() []byte {
	return r.encodeSignedData()
}

// encodeSignedData encodes the record data that was signed (seq + pairs)
func (r *Record) encodeSignedData() []byte {
	var buf bytes.Buffer

	// Write sequence number
	seqBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBuf, r.seq)
	buf.Write(seqBuf)

	// Write pairs in sorted order for deterministic signing
	sortedPairs := make([]pair, len(r.pairs))
	copy(sortedPairs, r.pairs)
	sort.Slice(sortedPairs, func(i, j int) bool {
		return sortedPairs[i].key < sortedPairs[j].key
	})

	// Write number of pairs
	pairCountBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(pairCountBuf, uint16(len(sortedPairs))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	buf.Write(pairCountBuf)

	// Write pairs
	for _, p := range sortedPairs {
		writeVarString(&buf, p.key)  // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		writeVarBytes(&buf, p.value) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	}

	return buf.Bytes()
}

// Set sets a key-value pair in the record
func (r *Record) Set(key string, value []byte) {
	// Remove existing key if present
	for i, p := range r.pairs {
		if p.key == key {
			r.pairs = append(r.pairs[:i], r.pairs[i+1:]...)
			break
		}
	}
	// Add new pair
	r.pairs = append(r.pairs, pair{key: key, value: value})
	// Sort pairs by key
	sort.Slice(r.pairs, func(i, j int) bool {
		return r.pairs[i].key < r.pairs[j].key
	})
}

// Get retrieves a value by key from the record
func (r *Record) Get(key string) ([]byte, bool) {
	for _, p := range r.pairs {
		if p.key == key {
			return p.value, true
		}
	}
	return nil, false
}

// SetIP sets the IP address in the record.
//
// R31-P2 FIX (2026-07-28): Defense-in-depth for unroutable IPs lives in
// ToNode() and ParseV4 (the consumer boundaries), NOT here. SetIP is a
// low-level setter used by both production code and tests — including tests
// that intentionally construct ENR records with unroutable IPs (loopback,
// private) to verify ParseV4/ToNode reject them. Silently skipping unroutable
// IPs in SetIP would break those tests and violate the setter contract
// (caller sets X, expects X stored). The validation belongs at the point
// where an ENR record (possibly from an untrusted source) is converted to
// a Node — see ToNode() and ParseV4.
func (r *Record) SetIP(ip net.IP) {
	if ip == nil {
		return
	}
	if ip4 := ip.To4(); ip4 != nil {
		r.Set(keyIP, ip4)
	} else if ip6 := ip.To16(); ip6 != nil {
		r.Set(keyIP6, ip6)
	}
}

// IP returns the IPv4 address from the record
func (r *Record) IP() net.IP {
	if v, ok := r.Get(keyIP); ok {
		return net.IP(v)
	}
	return nil
}

// IP6 returns the IPv6 address from the record
func (r *Record) IP6() net.IP {
	if v, ok := r.Get(keyIP6); ok {
		return net.IP(v)
	}
	return nil
}

// SetTCP sets the TCP port in the record
func (r *Record) SetTCP(port int) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(port)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	r.Set(keyTCP, buf)
}

// TCP returns the TCP port from the record
func (r *Record) TCP() int {
	if v, ok := r.Get(keyTCP); ok && len(v) >= 2 {
		return int(binary.BigEndian.Uint16(v))
	}
	return 0
}

// SetUDP sets the UDP port in the record
func (r *Record) SetUDP(port int) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(port)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	r.Set(keyUDP, buf)
}

// UDP returns the UDP port from the record
func (r *Record) UDP() int {
	if v, ok := r.Get(keyUDP); ok && len(v) >= 2 {
		return int(binary.BigEndian.Uint16(v))
	}
	return 0
}

// SetID sets the identity scheme in the record
func (r *Record) SetID(scheme string) {
	r.Set(keyID, []byte(scheme))
}

// ID returns the identity scheme from the record
func (r *Record) ID() string {
	if v, ok := r.Get(keyID); ok {
		return string(v)
	}
	return ""
}

// SetPublicKey sets the Dilithium3 public key in the record (1952 bytes)
func (r *Record) SetPublicKey(pubkey []byte) {
	r.Set(keyDilithium, pubkey)
}

// PublicKey returns the Dilithium3 public key from the record
func (r *Record) PublicKey() []byte {
	if v, ok := r.Get(keyDilithium); ok {
		return v
	}
	return nil
}

// SetPoWNonce sets the proof-of-work nonce in the record (8 bytes)
func (r *Record) SetPoWNonce(nonce uint64) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, nonce)
	r.Set(keyPoWNonce, buf)
}

// GetPoWNonce returns the proof-of-work nonce from the record
// Returns false if the nonce is not present
func (r *Record) GetPoWNonce() (uint64, bool) {
	if v, ok := r.Get(keyPoWNonce); ok && len(v) == 8 {
		return binary.BigEndian.Uint64(v), true
	}
	return 0, false
}

// Pairs returns all key-value pairs in the record
func (r *Record) Pairs() []pair {
	return r.pairs
}

// Encode serializes the record to bytes
// Format: signature + seq (8 bytes) + pairs (key-length + key + value-length + value)
func (r *Record) Encode() ([]byte, error) {
	var buf bytes.Buffer

	// Write signature length and signature
	if err := writeVarBytes(&buf, r.signature); err != nil {
		return nil, err
	}

	// Write sequence number
	seqBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBuf, r.seq)
	// audit-fix STATIC-ERR: check buf.Write error
	if _, err := buf.Write(seqBuf); err != nil {
		return nil, err
	}

	// Write number of pairs
	pairCountBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(pairCountBuf, uint16(len(r.pairs))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	// audit-fix STATIC-ERR: check buf.Write error
	if _, err := buf.Write(pairCountBuf); err != nil {
		return nil, err
	}

	// Write pairs
	for _, p := range r.pairs {
		// Write key
		if err := writeVarString(&buf, p.key); err != nil {
			return nil, err
		}
		// Write value
		if err := writeVarBytes(&buf, p.value); err != nil {
			return nil, err
		}
	}

	if buf.Len() > MaxRecordSize {
		return nil, ErrRecordTooLarge
	}

	return buf.Bytes(), nil
}

// Decode deserializes a record from bytes
func (r *Record) Decode(data []byte) error {
	if len(data) > MaxRecordSize {
		return ErrRecordTooLarge
	}

	buf := bytes.NewReader(data)

	// Read signature
	sig, err := readVarBytes(buf)
	if err != nil {
		return fmt.Errorf("%w: failed to read signature: %v", ErrInvalidRecord, err)
	}
	r.signature = sig

	// Read sequence number
	seqBuf := make([]byte, 8)
	if _, err := io.ReadFull(buf, seqBuf); err != nil {
		return fmt.Errorf("%w: failed to read sequence: %v", ErrInvalidRecord, err)
	}
	r.seq = binary.BigEndian.Uint64(seqBuf)

	// Read number of pairs
	pairCountBuf := make([]byte, 2)
	if _, err := io.ReadFull(buf, pairCountBuf); err != nil {
		return fmt.Errorf("%w: failed to read pair count: %v", ErrInvalidRecord, err)
	}
	pairCount := binary.BigEndian.Uint16(pairCountBuf)

	// AUDIT (2026) P2P-07: Cap the pre-allocated capacity to a sane
	// bound derived from MaxRecordSize. A malicious 16-bit pairCount of
	// 65535 would cause `make([]pair, 0, 65535)` to pre-allocate ~2.6MB
	// for a record that is at most 8KB. Since each pair has at least a
	// 1-byte key length prefix + 1 byte key + 1-byte value length prefix,
	// a valid 8KB record can have at most ~2700 pairs. Cap at 4096 to
	// leave headroom while keeping the allocation modest (~160KB worst
	// case, vs. 2.6MB before). Records exceeding this cap are rejected.
	const maxPairsCap = 4096
	if int(pairCount) > maxPairsCap {
		return fmt.Errorf("%w: pair count %d exceeds maximum %d", ErrInvalidRecord, pairCount, maxPairsCap)
	}
	r.pairs = make([]pair, 0, pairCount)
	for i := uint16(0); i < pairCount; i++ {
		// Read key
		key, err := readVarString(buf)
		if err != nil {
			return fmt.Errorf("%w: failed to read key: %v", ErrInvalidRecord, err)
		}
		// Read value
		value, err := readVarBytes(buf)
		if err != nil {
			return fmt.Errorf("%w: failed to read value: %v", ErrInvalidRecord, err)
		}
		r.pairs = append(r.pairs, pair{key: key, value: value})
	}

	return nil
}

// DecodeRecord decodes a record from bytes
func DecodeRecord(data []byte) (*Record, error) {
	r := NewRecord()
	if err := r.Decode(data); err != nil {
		return nil, err
	}
	return r, nil
}

// Clone creates a deep copy of the record
func (r *Record) Clone() *Record {
	clone := NewRecord()
	clone.seq = r.seq
	clone.signature = make([]byte, len(r.signature))
	copy(clone.signature, r.signature)
	clone.pairs = make([]pair, len(r.pairs))
	for i, p := range r.pairs {
		clone.pairs[i] = pair{
			key:   p.key,
			value: make([]byte, len(p.value)),
		}
		copy(clone.pairs[i].value, p.value)
	}
	return clone
}

// Equal returns true if two records are equal
func (r *Record) Equal(other *Record) bool {
	if r == nil || other == nil {
		return r == other
	}
	if r.seq != other.seq {
		return false
	}
	if !bytes.Equal(r.signature, other.signature) {
		return false
	}
	if len(r.pairs) != len(other.pairs) {
		return false
	}
	for i, p := range r.pairs {
		if p.key != other.pairs[i].key {
			return false
		}
		if !bytes.Equal(p.value, other.pairs[i].value) {
			return false
		}
	}
	return true
}

// Helper functions for variable-length encoding

func writeVarBytes(w io.Writer, data []byte) error {
	// Write length as 2 bytes
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(data))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	// Write data
	if _, err := w.Write(data); err != nil {
		return err
	}
	return nil
}

func readVarBytes(r io.Reader) ([]byte, error) {
	// Read length
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenBuf)
	// R70-ENR-LEN [LOW] FIX: Enforce per-value size limit in readVarBytes.
	// The Decode() function checks len(data) > MaxRecordSize after assembling
	// the full record, but individual field reads via readVarBytes can produce
	// values up to 65535 bytes (2-byte length prefix). An oversized field
	// within a valid-length record could bypass the MaxRecordSize check,
	// so we enforce the limit here at the field level.
	if length > MaxRecordSize {
		return nil, fmt.Errorf("record field too large: %d bytes (max %d)", length, MaxRecordSize)
	}
	// Read data
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}

func writeVarString(w io.Writer, s string) error {
	return writeVarBytes(w, []byte(s))
}

func readVarString(r io.Reader) (string, error) {
	data, err := readVarBytes(r)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ToNode converts a QNR record to a Node
func (r *Record) ToNode() (*Node, error) {
	pubkey := r.PublicKey()
	if pubkey == nil {
		return nil, fmt.Errorf("%w: dilithium3 public key", ErrMissingKey)
	}

	// audit-fix CRITICAL: Verify ENR signature to prevent MITM attacks
	// An attacker could modify the ENR record after signing (IP, ports, etc.)
	// without signature verification, the node would accept the modified record
	if err := r.VerifySignature(); err != nil {
		return nil, fmt.Errorf("ENR signature verification failed: %w", err)
	}

	var id ID
	id = DeriveID(pubkey)

	// Get IP address
	ip := r.IP()
	if ip == nil {
		ip = r.IP6()
	}
	if ip == nil {
		return nil, fmt.Errorf("%w: IP address", ErrMissingKey)
	}

	// R31-P2 FIX (2026-07-28): Defense-in-depth — reject unroutable IPs at
	// the ToNode boundary. All discovery-layer entry points already filter
	// unroutable IPs, but ToNode is a public API that any caller can use.
	// Without this check, a record containing 0.0.0.0, 127.0.0.1, or a
	// multicast/broadcast address would silently produce a Node with an
	// unusable IP, potentially polluting routing tables or causing subtle
	// connection failures. Reject early with a clear error.
	if isUnroutableIP(ip) {
		return nil, fmt.Errorf("ENR contains unroutable IP: %s", ip.String())
	}

	// Get ports
	tcp := r.TCP()
	udp := r.UDP()
	if udp == 0 {
		udp = tcp
	}

	node := NewNode(id, ip, tcp, udp)
	node.seq = r.seq
	node.r = r

	return node, nil
}

// FromNode creates an ENR record from a Node
func FromNode(n *Node) *Record {
	r := NewRecord()
	r.seq = n.seq
	r.SetID("v4")
	r.SetIP(n.ip)
	r.SetTCP(n.tcp)
	r.SetUDP(n.udp)
	return r
}

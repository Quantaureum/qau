// Quantaureum Node source, version 1.0.0.
package enode

import (
	"net"
	"testing"
)

func TestIDBytes(t *testing.T) {
	var id ID
	for i := range id {
		id[i] = byte(i)
	}

	bytes := id.Bytes()
	if len(bytes) != IDLength {
		t.Errorf("len(Bytes()) = %d, want %d", len(bytes), IDLength)
	}
}

func TestIDHex(t *testing.T) {
	var id ID
	id[0] = 0xAB
	id[1] = 0xCD

	hex := id.Hex()
	if len(hex) != IDLength*2 {
		t.Errorf("len(Hex()) = %d, want %d", len(hex), IDLength*2)
	}
	if hex[:4] != "abcd" {
		t.Errorf("Hex() prefix = %q, want %q", hex[:4], "abcd")
	}
}

func TestIDString(t *testing.T) {
	var id ID
	id[0] = 0xFF
	s := id.String()
	if s != id.Hex() {
		t.Errorf("String() != Hex()")
	}
}

func TestIDIsEmpty(t *testing.T) {
	var zeroID ID
	if !zeroID.IsEmpty() {
		t.Error("zero ID should be empty")
	}

	var nonZeroID ID
	nonZeroID[0] = 1
	if nonZeroID.IsEmpty() {
		t.Error("non-zero ID should not be empty")
	}
}

func TestHexToID(t *testing.T) {
	var expected ID
	for i := range expected {
		expected[i] = byte(i)
	}

	hex := expected.Hex()
	id, err := HexToID(hex)
	if err != nil {
		t.Fatalf("HexToID failed: %v", err)
	}
	if id != expected {
		t.Error("ID mismatch")
	}
}

func TestHexToIDWithPrefix(t *testing.T) {
	var expected ID
	expected[0] = 0xFF

	hex := "0x" + expected.Hex()
	id, err := HexToID(hex)
	if err != nil {
		t.Fatalf("HexToID with 0x prefix failed: %v", err)
	}
	if id != expected {
		t.Error("ID mismatch")
	}
}

func TestHexToIDInvalid(t *testing.T) {
	_, err := HexToID("not-valid-hex")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestHexToIDWrongLength(t *testing.T) {
	_, err := HexToID("abcd")
	if err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestBytesToID(t *testing.T) {
	var expected ID
	for i := range expected {
		expected[i] = byte(i)
	}

	id, err := BytesToID(expected[:])
	if err != nil {
		t.Fatalf("BytesToID failed: %v", err)
	}
	if id != expected {
		t.Error("ID mismatch")
	}
}

func TestBytesToIDWrongLength(t *testing.T) {
	_, err := BytesToID([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestGenerateID(t *testing.T) {
	id1, err := GenerateID()
	if err != nil {
		t.Fatalf("GenerateID failed: %v", err)
	}
	if id1.IsEmpty() {
		t.Error("generated ID should not be empty")
	}

	id2, err := GenerateID()
	if err != nil {
		t.Fatalf("GenerateID failed: %v", err)
	}
	if id1 == id2 {
		t.Error("two generated IDs should be different")
	}
}

func TestNewNode(t *testing.T) {
	id, _ := GenerateID()
	ip := net.ParseIP("198.51.100.10")
	node := NewNode(id, ip, 9000, 9001)

	if node == nil {
		t.Fatal("NewNode returned nil")
	}
	if node.ID() != id {
		t.Error("ID mismatch")
	}
	if !node.IP().Equal(ip) {
		t.Errorf("IP = %v, want %v", node.IP(), ip)
	}
	if node.TCP() != 9000 {
		t.Errorf("TCP = %d, want 9000", node.TCP())
	}
	if node.UDP() != 9001 {
		t.Errorf("UDP = %d, want 9001", node.UDP())
	}
}

func TestNodeSeq(t *testing.T) {
	id, _ := GenerateID()
	node := NewNode(id, net.ParseIP("198.51.100.10"), 9000, 9001)

	if node.Seq() != 0 {
		t.Errorf("initial Seq = %d, want 0", node.Seq())
	}

	node.SetSeq(42)
	if node.Seq() != 42 {
		t.Errorf("Seq = %d, want 42", node.Seq())
	}
}

func TestNodeRecord(t *testing.T) {
	id, _ := GenerateID()
	node := NewNode(id, net.ParseIP("198.51.100.10"), 9000, 9001)

	if node.Record() != nil {
		t.Error("initial Record should be nil")
	}

	r := NewRecord()
	node.SetRecord(r)
	if node.Record() != r {
		t.Error("Record mismatch after SetRecord")
	}
}

func TestNodeEqual(t *testing.T) {
	id1, _ := GenerateID()
	id2, _ := GenerateID()

	node1 := NewNode(id1, net.ParseIP("198.51.100.10"), 9000, 9001)
	node2 := NewNode(id1, net.ParseIP("198.51.100.30"), 8000, 8001) // same ID
	node3 := NewNode(id2, net.ParseIP("198.51.100.10"), 9000, 9001) // different ID

	if !node1.Equal(node2) {
		t.Error("nodes with same ID should be equal")
	}
	if node1.Equal(node3) {
		t.Error("nodes with different ID should not be equal")
	}
}

func TestNodeEqualNil(t *testing.T) {
	id, _ := GenerateID()
	node := NewNode(id, net.ParseIP("198.51.100.10"), 9000, 9001)

	if node.Equal(nil) {
		t.Error("non-nil node should not equal nil")
	}

	var nilNode *Node
	if nilNode.Equal(node) {
		t.Error("nil node should not equal non-nil")
	}
	if !nilNode.Equal(nil) {
		t.Error("nil nodes should be equal")
	}
}

func TestNodeString(t *testing.T) {
	id, _ := GenerateID()
	node := NewNode(id, net.ParseIP("198.51.100.10"), 9000, 9001)

	s := node.String()
	if s == "" {
		t.Error("String should not be empty")
	}
}

func TestNodeURLv4(t *testing.T) {
	id, _ := GenerateID()
	node := NewNode(id, net.ParseIP("198.51.100.10"), 9000, 9001)

	url := node.URLv4()
	if url == "" {
		t.Error("URLv4 should not be empty")
	}
}

func TestNodeURLv4WithDifferentPorts(t *testing.T) {
	id, _ := GenerateID()
	node := NewNode(id, net.ParseIP("198.51.100.10"), 9000, 9001)

	url := node.URLv4()
	if url == "" {
		t.Error("URLv4 should not be empty")
	}
	// Should contain discport since UDP != TCP
}

func TestNodeAddr(t *testing.T) {
	id, _ := GenerateID()
	ip := net.ParseIP("198.51.100.10")
	node := NewNode(id, ip, 9000, 9001)

	addr := node.Addr()
	if addr.Port != 9000 {
		t.Errorf("Addr.Port = %d, want 9000", addr.Port)
	}
}

func TestNodeUDPAddr(t *testing.T) {
	id, _ := GenerateID()
	ip := net.ParseIP("198.51.100.10")
	node := NewNode(id, ip, 9000, 9001)

	addr := node.UDPAddr()
	if addr.Port != 9001 {
		t.Errorf("UDPAddr.Port = %d, want 9001", addr.Port)
	}
}

func TestParseV4InvalidScheme(t *testing.T) {
	_, err := ParseV4("http://abcd@198.51.100.10:9000")
	if err == nil {
		t.Error("expected error for invalid scheme")
	}
}

func TestParseV4MissingNodeID(t *testing.T) {
	_, err := ParseV4("enode://198.51.100.10:9000")
	if err == nil {
		t.Error("expected error for missing node ID")
	}
}

func TestParseV4InvalidHostPort(t *testing.T) {
	id, _ := GenerateID()
	_, err := ParseV4("enode://" + id.Hex() + "@invalid")
	if err == nil {
		t.Error("expected error for invalid host:port")
	}
}

func TestParseV4InvalidPort(t *testing.T) {
	id, _ := GenerateID()
	_, err := ParseV4("enode://" + id.Hex() + "@198.51.100.10:invalid")
	if err == nil {
		t.Error("expected error for invalid port")
	}
}

func TestParseV4WithDiscport(t *testing.T) {
	id, _ := GenerateID()
	url := "enode://" + id.Hex() + "@203.0.113.1:9000?discport=9001"
	node, err := ParseV4(url)
	if err != nil {
		t.Fatalf("ParseV4 failed: %v", err)
	}
	if node.TCP() != 9000 {
		t.Errorf("TCP = %d, want 9000", node.TCP())
	}
	if node.UDP() != 9001 {
		t.Errorf("UDP = %d, want 9001", node.UDP())
	}
}

func TestParseV4WithDefaultDiscport(t *testing.T) {
	id, _ := GenerateID()
	url := "enode://" + id.Hex() + "@203.0.113.1:9000"
	node, err := ParseV4(url)
	if err != nil {
		t.Fatalf("ParseV4 failed: %v", err)
	}
	if node.UDP() != 9000 {
		t.Errorf("UDP should default to TCP port, got %d", node.UDP())
	}
}

func TestIsUnroutableIP(t *testing.T) {
	routable := net.ParseIP("198.51.100.10")
	if isUnroutableIP(routable) {
		t.Error("198.51.100.10 should be routable")
	}

	loopback := net.ParseIP("127.0.0.1")
	if !isUnroutableIP(loopback) {
		t.Error("127.0.0.1 should be unroutable")
	}

	private := net.ParseIP("192.168.1.1")
	if !isUnroutableIP(private) {
		t.Error("192.168.1.1 should be unroutable")
	}

	unspecified := net.ParseIP("0.0.0.0")
	if !isUnroutableIP(unspecified) {
		t.Error("0.0.0.0 should be unroutable")
	}
}

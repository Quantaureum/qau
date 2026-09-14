// Quantaureum Node source, version 1.0.0.
package types

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// mockQuantumSigner implements QuantumSigner without importing the crypto
// package, avoiding a circular dependency (crypto imports types).
type mockQuantumSigner struct {
	priv []byte
	pub  []byte
}

func (m *mockQuantumSigner) Sign(message []byte) ([]byte, error) {
	// Return a deterministic placeholder signature of the correct size.
	sig := make([]byte, QuantumSignatureSize)
	for i := range sig {
		sig[i] = byte(i) ^ message[i%len(message)]
	}
	return sig, nil
}

func (m *mockQuantumSigner) PublicKeyBytes() []byte {
	return m.pub
}

func TestAddressConstants(t *testing.T) {
	if AddressLength != 20 {
		t.Errorf("expected 20, got %d", AddressLength)
	}
	if AddressPrefix != "QAU" {
		t.Errorf("expected QAU, got %s", AddressPrefix)
	}
	if HashLength != 32 {
		t.Errorf("expected 32, got %d", HashLength)
	}
}

func TestBytesToAddress(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03}
	addr := BytesToAddress(b)
	if addr.IsEmpty() {
		t.Fatal("expected non-empty address")
	}
	raw := addr.Bytes()
	if len(raw) != AddressLength {
		t.Errorf("expected %d bytes, got %d", AddressLength, len(raw))
	}
}

func TestBytesToAddress_Empty(t *testing.T) {
	addr := BytesToAddress([]byte{})
	if !addr.IsEmpty() {
		t.Error("expected empty address from empty bytes")
	}
}

func TestBytesToAddress_Truncate(t *testing.T) {
	b := make([]byte, 25)
	for i := range b {
		b[i] = byte(i + 1)
	}
	addr := BytesToAddress(b)
	if addr[0] != 6 {
		t.Errorf("expected 6 at position 0 (last 20 bytes), got %d", addr[0])
	}
}

func TestAddress_IsEmpty(t *testing.T) {
	var addr Address
	if !addr.IsEmpty() {
		t.Error("zero address should be empty")
	}

	addr[0] = 0x01
	if addr.IsEmpty() {
		t.Error("non-zero address should not be empty")
	}
}

func TestAddress_IsValid(t *testing.T) {
	var addr Address
	if addr.IsValid() {
		t.Error("zero address should be invalid")
	}

	addr[0] = 0x01
	if !addr.IsValid() {
		t.Error("non-zero address should be valid")
	}
}

func TestAddress_Equal(t *testing.T) {
	a1 := BytesToAddress([]byte{0x01})
	a2 := BytesToAddress([]byte{0x01})
	a3 := BytesToAddress([]byte{0x02})

	if !a1.Equal(a2) {
		t.Error("same addresses should be equal")
	}
	if a1.Equal(a3) {
		t.Error("different addresses should not be equal")
	}
}

func TestAddress_ConstantTimeEqual(t *testing.T) {
	a1 := BytesToAddress([]byte{0x01})
	a2 := BytesToAddress([]byte{0x01})
	a3 := BytesToAddress([]byte{0x02})

	if !a1.ConstantTimeEqual(a2) {
		t.Error("same addresses should be constant-time equal")
	}
	if a1.ConstantTimeEqual(a3) {
		t.Error("different addresses should not be constant-time equal")
	}
}

func TestAddress_String(t *testing.T) {
	var addr Address
	copy(addr[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14})
	s := addr.String()
	if len(s) == 0 {
		t.Error("expected non-empty string")
	}
	if s[:3] != AddressPrefix {
		t.Errorf("expected prefix %s, got %s", AddressPrefix, s[:3])
	}
}

func TestAddress_ShortString(t *testing.T) {
	var addr Address
	addr[0] = 0x01
	s := addr.ShortString()
	if len(s) == 0 {
		t.Error("expected non-empty short string")
	}
}

func TestAddress_ToHexAddress(t *testing.T) {
	var addr Address
	addr[0] = 0xab
	hex := addr.ToHexAddress()
	if len(hex) != 42 {
		t.Errorf("expected 42 chars (0x + 40 hex), got %d: %s", len(hex), hex)
	}
	if hex[:2] != "0x" {
		t.Errorf("expected 0x prefix, got %s", hex[:2])
	}
}

func TestParseAddress(t *testing.T) {
	var addr Address
	addr[0] = 0x01
	s := addr.String()

	parsed, err := ParseAddress(s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.Equal(addr) {
		t.Error("parsed address should equal original")
	}
}

func TestParseAddress_Empty(t *testing.T) {
	_, err := ParseAddress("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestParseAddress_InvalidPrefix(t *testing.T) {
	_, err := ParseAddress("ETH..." + "A")
	if err == nil {
		t.Error("expected error for invalid prefix")
	}
}

func TestParseAddress_NoData(t *testing.T) {
	_, err := ParseAddress("QAU")
	if err == nil {
		t.Error("expected error for prefix-only address")
	}
}

func TestParseHexAddress(t *testing.T) {
	hex := "0x" + "0000000000000000000000000000000000000001"
	addr, err := ParseHexAddress(hex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.IsEmpty() {
		t.Error("expected non-empty address")
	}
}

func TestParseHexAddress_NoPrefix(t *testing.T) {
	hex := "0000000000000000000000000000000000000001"
	addr, err := ParseHexAddress(hex)
	if err != nil {
		t.Fatalf("unexpected error without prefix: %v", err)
	}
	if addr.IsEmpty() {
		t.Error("expected non-empty address")
	}
}

func TestParseHexAddress_Empty(t *testing.T) {
	_, err := ParseHexAddress("")
	if err == nil {
		t.Error("expected error for empty hex")
	}
}

func TestParseHexAddress_InvalidLength(t *testing.T) {
	_, err := ParseHexAddress("0x123")
	if err == nil {
		t.Error("expected error for invalid length")
	}
}

func TestParseAddressWithFallback_QAU(t *testing.T) {
	var addr Address
	addr[0] = 0x01
	s := addr.String()

	parsed, err := ParseAddressWithFallback(s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.Equal(addr) {
		t.Error("parsed should equal original")
	}
}

func TestParseAddressWithFallback_Hex(t *testing.T) {
	hex := "0x0000000000000000000000000000000000000001"
	addr, err := ParseAddressWithFallback(hex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.IsEmpty() {
		t.Error("expected non-empty address")
	}
}

func TestParseAddressWithFallback_Invalid(t *testing.T) {
	_, err := ParseAddressWithFallback("invalid_address_format")
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestAddressFromPublicKey_InvalidSize(t *testing.T) {
	addr := AddressFromPublicKey([]byte{0x01})
	if !addr.IsEmpty() {
		t.Error("expected empty address for invalid pub key size")
	}
}

func TestAddressFromPublicKey_ValidSize(t *testing.T) {
	pubKey := make([]byte, QuantumPublicKeySize)
	for i := range pubKey {
		pubKey[i] = byte(i % 256)
	}
	addr := AddressFromPublicKey(pubKey)
	if addr.IsEmpty() {
		t.Error("expected non-empty address for valid pub key")
	}
}

func TestBytesToHash(t *testing.T) {
	b := []byte{0x01, 0x02}
	h := BytesToHash(b)
	if h.IsEmpty() {
		t.Fatal("expected non-empty hash")
	}
	raw := h.Bytes()
	if len(raw) != HashLength {
		t.Errorf("expected %d bytes, got %d", HashLength, len(raw))
	}
}

func TestHash_IsEmpty(t *testing.T) {
	var h Hash
	if !h.IsEmpty() {
		t.Error("zero hash should be empty")
	}

	h[0] = 0x01
	if h.IsEmpty() {
		t.Error("non-zero hash should not be empty")
	}
}

func TestHash_String(t *testing.T) {
	var h Hash
	h[0] = 0xab
	s := h.String()
	if len(s) == 0 {
		t.Error("expected non-empty string")
	}
}

func TestKeccak256Hash(t *testing.T) {
	h := Keccak256Hash([]byte("test"))
	if h.IsEmpty() {
		t.Error("expected non-empty hash from keccak256")
	}
}

func TestKeccak256Hash_Empty(t *testing.T) {
	h := Keccak256Hash([]byte{})
	if h.IsEmpty() {
		t.Error("keccak256 of empty should not be zero")
	}
}

func TestQuantumPublicKeySize(t *testing.T) {
	if QuantumPublicKeySize != 1952 {
		t.Errorf("expected 1952, got %d", QuantumPublicKeySize)
	}
}

func TestQuantumSignatureSize(t *testing.T) {
	if QuantumSignatureSize != 3293 {
		t.Errorf("expected 3293, got %d", QuantumSignatureSize)
	}
}

func TestNewQuantumTransfer_ZeroChainID(t *testing.T) {
	_, err := NewQuantumTransfer(0, 0, Address{}, nil)
	if err == nil {
		t.Error("expected error for zero chainID")
	}
}

func TestNewQuantumTransfer_Success(t *testing.T) {
	var to Address
	to[0] = 0x01
	tx, err := NewQuantumTransfer(0, 1, to, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tx.Type != TransferType {
		t.Errorf("expected transfer type, got %d", tx.Type)
	}
	if tx.GasLimit != 21000 {
		t.Errorf("expected 21000 gas, got %d", tx.GasLimit)
	}
}

func TestQuantumTransaction_IsSigned_Unsigned(t *testing.T) {
	tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
	if tx.IsSigned() {
		t.Error("unsigned tx should not report signed")
	}
}

func TestQuantumTransaction_Sender_EmptyPubKey(t *testing.T) {
	tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
	sender := tx.Sender()
	if !sender.IsEmpty() {
		t.Error("expected empty sender for empty pub key")
	}
}

func TestQuantumTransaction_Verify_Unsigned(t *testing.T) {
	tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
	if tx.Verify() {
		t.Error("unsigned tx should not verify")
	}
}

func TestQuantumTransaction_Verify_ZeroChainID(t *testing.T) {
	tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
	tx.ChainID = 0
	if tx.Verify() {
		t.Error("zero chainID tx should not verify")
	}
}

// R37-P0-03 (2026-07-30): an all-zero Dilithium3 public key (t1=0)
// degenerates the verification equation and allows keyless signature
// forgery. The tx-level Verify must reject it even when every other check
// (size, chainID, sender match) passes.
func TestQuantumTransaction_Verify_ZeroPublicKey(t *testing.T) {
	tx, _ := NewQuantumTransfer(1, 1, Address{}, nil)
	tx.PublicKey = make([]byte, QuantumPublicKeySize)
	tx.Signature = make([]byte, QuantumSignatureSize)
	tx.From = tx.Sender() // sender derived from the zero key, so addr check passes
	if tx.Verify() {
		t.Error("tx with all-zero public key must not verify (keyless forgery vector)")
	}
}

func TestQuantumTransaction_Hash(t *testing.T) {
	tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
	h := tx.Hash()
	_ = h
}

func TestQuantumTransaction_Size(t *testing.T) {
	tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
	sz := tx.Size()
	if sz <= 0 {
		t.Errorf("expected positive size, got %d", sz)
	}
}

func TestQuantumTransaction_Serialize(t *testing.T) {
	tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
	data, err := tx.Serialize()
	if err != nil {
		t.Fatalf("unexpected serialize error: %v", err)
	}
	if len(data) <= 0 {
		t.Error("expected non-empty serialized data")
	}
}

func TestDeserializeQuantumTransaction(t *testing.T) {
	tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
	tx.PublicKey = make([]byte, QuantumPublicKeySize)
	for i := range tx.PublicKey {
		tx.PublicKey[i] = byte(i % 256)
	}
	tx.From = AddressFromPublicKey(tx.PublicKey)
	tx.Signature = make([]byte, QuantumSignatureSize)
	for i := range tx.Signature {
		tx.Signature[i] = byte((i + 1) % 256)
	}
	data, _ := tx.Serialize()

	deserialized, err := DeserializeQuantumTransaction(data)
	if err != nil {
		t.Fatalf("unexpected deserialize error: %v", err)
	}
	if deserialized.Type != tx.Type {
		t.Errorf("type mismatch: %d != %d", deserialized.Type, tx.Type)
	}
	if deserialized.Nonce != tx.Nonce {
		t.Errorf("nonce mismatch: %d != %d", deserialized.Nonce, tx.Nonce)
	}
}

func TestDeserializeQuantumTransaction_TooShort(t *testing.T) {
	_, err := DeserializeQuantumTransaction([]byte{0x01})
	if err == nil {
		t.Error("expected error for too-short data")
	}
}

func TestQuantumTransaction_Copy(t *testing.T) {
	tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
	tx.Data = []byte{0x01, 0x02}

	cpy := tx.Copy()
	if cpy.Type != tx.Type {
		t.Error("type mismatch in copy")
	}
	cpy.Data[0] = 0xff
	if tx.Data[0] == 0xff {
		t.Error("copy should be deep - modifying copy affected original")
	}
}

func TestQuantumTransaction_EncodeRLP(t *testing.T) {
	tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
	var buf []byte
	_ = tx.EncodeRLP(nil)
	_ = buf
}

func TestQuantumTransaction_MarshalJSON(t *testing.T) {
	tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
	data, err := tx.MarshalJSON()
	if err != nil {
		t.Errorf("unexpected marshal error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}

	// R9-H2 (2026-07-19) FIX: Verify publicKey field is present and correctly
	// formatted in the JSON output. H-05 (R8) added the publicKey field but
	// no test verified its presence — meaning a regression that drops the
	// field would silently pass. Clients rely on publicKey to independently
	// verify signatures and derive the sender address; omitting it makes
	// the RPC payload untrustworthy.
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse marshal output: %v", err)
	}

	// 1. publicKey field must be present
	pubKeyRaw, ok := parsed["publicKey"]
	if !ok {
		t.Fatal("R9-H2: publicKey field missing from MarshalJSON output")
	}
	pubKeyStr, ok := pubKeyRaw.(string)
	if !ok {
		t.Fatalf("R9-H2: publicKey field is not a string, got %T", pubKeyRaw)
	}

	// 2. publicKey must be 0x-prefixed hex
	if !strings.HasPrefix(pubKeyStr, "0x") {
		t.Errorf("R9-H2: publicKey must be 0x-prefixed, got %q", pubKeyStr)
	}

	// 3. For unsigned tx (no publicKey set), it should be "0x" (empty hex)
	if pubKeyStr != "0x" {
		t.Errorf("R9-H2: unsigned tx publicKey should be '0x', got %q", pubKeyStr)
	}

	// 4. For a signed tx, publicKey must be the hex-encoded Dilithium3 public key (1952 bytes -> 3904 hex chars + 2 prefix = 3906)
	pubKey := make([]byte, QuantumPublicKeySize)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	signer := &mockQuantumSigner{pub: pubKey}
	if err := tx.Sign(signer); err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}
	data, err = tx.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal signed tx: %v", err)
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse signed marshal output: %v", err)
	}
	pubKeyStr, ok = parsed["publicKey"].(string)
	if !ok {
		t.Fatal("R9-H2: publicKey field missing or wrong type in signed tx output")
	}
	expected := "0x" + hex.EncodeToString(pubKey)
	if pubKeyStr != expected {
		t.Errorf("R9-H2: signed tx publicKey mismatch\n  got:    %s (len=%d)\n  expect: %s (len=%d)",
			pubKeyStr, len(pubKeyStr), expected, len(expected))
	}
}

func TestNewQuantumContractCall_ZeroChainID(t *testing.T) {
	_, err := NewQuantumContractCall(0, 0, Address{}, nil, nil, 100000, nil)
	if err == nil {
		t.Error("expected error for zero chainID")
	}
}

func TestNewQuantumContractCreation_ZeroChainID(t *testing.T) {
	_, err := NewQuantumContractCreation(0, 0, nil, nil, 100000, nil)
	if err == nil {
		t.Error("expected error for zero chainID")
	}
}

func TestNewQuantumStake(t *testing.T) {
	var validator Address
	validator[0] = 0x01
	tx, err := NewQuantumStake(1, 1, validator, nil, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tx.Type != StakeType {
		t.Errorf("expected stake type, got %d", tx.Type)
	}
}

func TestAddress_EmptyBoundary(t *testing.T) {
	addr := Address{}
	if !addr.IsEmpty() {
		t.Error("zero address should be empty")
	}
	addr[19] = 0x01
	if addr.IsEmpty() {
		t.Error("last-byte non-zero address should not be empty")
	}
}

func TestHash_EmptyBoundary(t *testing.T) {
	h := Hash{}
	if !h.IsEmpty() {
		t.Error("zero hash should be empty")
	}
	h[31] = 0x01
	if h.IsEmpty() {
		t.Error("last-byte non-zero hash should not be empty")
	}
}

// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestEncodeDecodeSnapStateRequest(t *testing.T) {
	req := &SnapStateRequest{
		BlockHeight: 100,
		Limit:       500,
	}
	copy(req.StartHash[:], []byte("start_hash_0001_0001_0001_0001_00"))

	encoded := EncodeSnapStateRequest(req)
	decoded, err := DecodeSnapStateRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeSnapStateRequest failed: %v", err)
	}

	if decoded.BlockHeight != req.BlockHeight {
		t.Errorf("BlockHeight = %d, want %d", decoded.BlockHeight, req.BlockHeight)
	}
	if decoded.Limit != req.Limit {
		t.Errorf("Limit = %d, want %d", decoded.Limit, req.Limit)
	}
	if decoded.StartHash != req.StartHash {
		t.Error("StartHash mismatch")
	}
}

func TestDecodeSnapStateRequestTooShort(t *testing.T) {
	_, err := DecodeSnapStateRequest([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for too short data")
	}
}

func TestEncodeDecodeSnapStateResponse(t *testing.T) {
	var addr types.Address
	copy(addr[:], []byte("test_address_0001_0001_0001_0001"))

	resp := &SnapStateResponse{
		BlockHeight: 200,
		Accounts: []SnapAccountData{
			{Address: addr, Account: []byte("account-data-1")},
		},
		MoreComing: true,
	}

	encoded := EncodeSnapStateResponse(resp)
	decoded, err := DecodeSnapStateResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeSnapStateResponse failed: %v", err)
	}

	if decoded.BlockHeight != resp.BlockHeight {
		t.Errorf("BlockHeight = %d, want %d", decoded.BlockHeight, resp.BlockHeight)
	}
	if decoded.MoreComing != resp.MoreComing {
		t.Errorf("MoreComing = %v, want %v", decoded.MoreComing, resp.MoreComing)
	}
	if len(decoded.Accounts) != 1 {
		t.Fatalf("len(Accounts) = %d, want 1", len(decoded.Accounts))
	}
}

func TestDecodeSnapStateResponseTooShort(t *testing.T) {
	_, err := DecodeSnapStateResponse([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for too short data")
	}
}

func TestDecodeSnapStateResponseTruncated(t *testing.T) {
	// Header says 1 account but no account data follows
	data := make([]byte, 13)
	data[8] = 0 // MoreComing = false
	// count = 1
	data[9] = 0
	data[10] = 0
	data[11] = 0
	data[12] = 1

	_, err := DecodeSnapStateResponse(data)
	if err == nil {
		t.Error("expected error for truncated response")
	}
}

func TestEncodeDecodeSnapStateResponseEmpty(t *testing.T) {
	resp := &SnapStateResponse{
		BlockHeight: 100,
		Accounts:    []SnapAccountData{},
		MoreComing:  false,
	}

	encoded := EncodeSnapStateResponse(resp)
	decoded, err := DecodeSnapStateResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeSnapStateResponse failed: %v", err)
	}

	if len(decoded.Accounts) != 0 {
		t.Errorf("len(Accounts) = %d, want 0", len(decoded.Accounts))
	}
}

func TestEncodeDecodeSnapStorageRequest(t *testing.T) {
	req := &SnapStorageRequest{
		BlockHeight: 100,
		Limit:       1000,
	}
	copy(req.AccountHash[:], []byte("account_hash_0001_0001_0001_0001_"))
	copy(req.StartKey[:], []byte("start_key_0001_0001_0001_0001_000"))

	encoded := EncodeSnapStorageRequest(req)
	decoded, err := DecodeSnapStorageRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeSnapStorageRequest failed: %v", err)
	}

	if decoded.BlockHeight != req.BlockHeight {
		t.Errorf("BlockHeight = %d, want %d", decoded.BlockHeight, req.BlockHeight)
	}
	if decoded.Limit != req.Limit {
		t.Errorf("Limit = %d, want %d", decoded.Limit, req.Limit)
	}
	if decoded.AccountHash != req.AccountHash {
		t.Error("AccountHash mismatch")
	}
}

func TestDecodeSnapStorageRequestTooShort(t *testing.T) {
	_, err := DecodeSnapStorageRequest([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for too short data")
	}
}

func TestEncodeDecodeSnapStorageResponse(t *testing.T) {
	var key, value types.Hash
	copy(key[:], []byte("storage_key_0001_0001_0001_0001_00"))
	copy(value[:], []byte("storage_value_0001_0001_0001_0001"))

	resp := &SnapStorageResponse{
		BlockHeight: 200,
		Entries: []SnapStorageEntry{
			{Key: key, Value: value},
		},
		MoreComing: false,
	}
	copy(resp.AccountHash[:], []byte("account_hash_0001_0001_0001_0001_"))

	encoded := EncodeSnapStorageResponse(resp)
	decoded, err := DecodeSnapStorageResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeSnapStorageResponse failed: %v", err)
	}

	if decoded.BlockHeight != resp.BlockHeight {
		t.Errorf("BlockHeight = %d, want %d", decoded.BlockHeight, resp.BlockHeight)
	}
	if len(decoded.Entries) != 1 {
		t.Fatalf("len(Entries) = %d, want 1", len(decoded.Entries))
	}
	if decoded.Entries[0].Key != key {
		t.Error("Key mismatch")
	}
	if decoded.Entries[0].Value != value {
		t.Error("Value mismatch")
	}
}

func TestDecodeSnapStorageResponseTooShort(t *testing.T) {
	_, err := DecodeSnapStorageResponse([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for too short data")
	}
}

func TestDecodeSnapStorageResponseTruncated(t *testing.T) {
	// Header says 1 entry but no entry data follows
	data := make([]byte, 45)
	data[40] = 0 // MoreComing = false
	// count = 1
	data[41] = 0
	data[42] = 0
	data[43] = 0
	data[44] = 1

	_, err := DecodeSnapStorageResponse(data)
	if err == nil {
		t.Error("expected error for truncated response")
	}
}

func TestEncodeDecodeSnapBytecodeRequest(t *testing.T) {
	var hash1, hash2 types.Hash
	copy(hash1[:], []byte("bytecode_hash_0001_0001_0001_0001_"))
	copy(hash2[:], []byte("bytecode_hash_0002_0002_0002_0002_"))

	req := &SnapBytecodeRequest{
		BlockHeight: 100,
		Hashes:      []types.Hash{hash1, hash2},
		Limit:       50,
	}

	encoded := EncodeSnapBytecodeRequest(req)
	decoded, err := DecodeSnapBytecodeRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeSnapBytecodeRequest failed: %v", err)
	}

	if decoded.BlockHeight != req.BlockHeight {
		t.Errorf("BlockHeight = %d, want %d", decoded.BlockHeight, req.BlockHeight)
	}
	if decoded.Limit != req.Limit {
		t.Errorf("Limit = %d, want %d", decoded.Limit, req.Limit)
	}
	if len(decoded.Hashes) != 2 {
		t.Fatalf("len(Hashes) = %d, want 2", len(decoded.Hashes))
	}
	if decoded.Hashes[0] != hash1 {
		t.Error("Hash[0] mismatch")
	}
}

func TestDecodeSnapBytecodeRequestTooShort(t *testing.T) {
	_, err := DecodeSnapBytecodeRequest([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for too short data")
	}
}

func TestDecodeSnapBytecodeRequestTruncated(t *testing.T) {
	// Header says 1 hash but no hash data follows
	data := make([]byte, 16)
	// count = 1
	data[8] = 0
	data[9] = 0
	data[10] = 0
	data[11] = 1

	_, err := DecodeSnapBytecodeRequest(data)
	if err == nil {
		t.Error("expected error for truncated request")
	}
}

func TestEncodeDecodeSnapBytecodeResponse(t *testing.T) {
	var hash types.Hash
	copy(hash[:], []byte("bytecode_hash_0001_0001_0001_0001_"))

	resp := &SnapBytecodeResponse{
		BlockHeight: 200,
		Entries: []SnapBytecodeEntry{
			{Hash: hash, Code: []byte("bytecode-data-here")},
		},
		MoreComing: true,
	}

	encoded := EncodeSnapBytecodeResponse(resp)
	decoded, err := DecodeSnapBytecodeResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeSnapBytecodeResponse failed: %v", err)
	}

	if decoded.BlockHeight != resp.BlockHeight {
		t.Errorf("BlockHeight = %d, want %d", decoded.BlockHeight, resp.BlockHeight)
	}
	if decoded.MoreComing != resp.MoreComing {
		t.Errorf("MoreComing = %v, want %v", decoded.MoreComing, resp.MoreComing)
	}
	if len(decoded.Entries) != 1 {
		t.Fatalf("len(Entries) = %d, want 1", len(decoded.Entries))
	}
	if decoded.Entries[0].Hash != hash {
		t.Error("Hash mismatch")
	}
	if string(decoded.Entries[0].Code) != "bytecode-data-here" {
		t.Errorf("Code = %q, want %q", string(decoded.Entries[0].Code), "bytecode-data-here")
	}
}

func TestDecodeSnapBytecodeResponseTooShort(t *testing.T) {
	_, err := DecodeSnapBytecodeResponse([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for too short data")
	}
}

func TestDecodeSnapBytecodeResponseTruncated(t *testing.T) {
	// Header says 1 entry but no entry data follows
	data := make([]byte, 13)
	data[8] = 0 // MoreComing = false
	// count = 1
	data[9] = 0
	data[10] = 0
	data[11] = 0
	data[12] = 1

	_, err := DecodeSnapBytecodeResponse(data)
	if err == nil {
		t.Error("expected error for truncated response")
	}
}

func TestEncodeDecodeSnapBytecodeResponseEmpty(t *testing.T) {
	resp := &SnapBytecodeResponse{
		BlockHeight: 100,
		Entries:     []SnapBytecodeEntry{},
		MoreComing:  false,
	}

	encoded := EncodeSnapBytecodeResponse(resp)
	decoded, err := DecodeSnapBytecodeResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeSnapBytecodeResponse failed: %v", err)
	}

	if len(decoded.Entries) != 0 {
		t.Errorf("len(Entries) = %d, want 0", len(decoded.Entries))
	}
}

func TestSnapStateResponseMaxAccountsExceeded(t *testing.T) {
	// Create a response header claiming more than MaxSnapAccountsPerResponse accounts
	data := make([]byte, 13)
	data[8] = 0
	// count = MaxSnapAccountsPerResponse + 1
	count := uint32(MaxSnapAccountsPerResponse + 1)
	data[9] = byte(count >> 24)
	data[10] = byte(count >> 16)
	data[11] = byte(count >> 8)
	data[12] = byte(count)

	_, err := DecodeSnapStateResponse(data)
	if err == nil {
		t.Error("expected error for exceeding max accounts")
	}
}

func TestSnapStorageResponseMaxEntriesExceeded(t *testing.T) {
	data := make([]byte, 45)
	data[40] = 0
	count := uint32(MaxSnapStoragePerResponse + 1)
	data[41] = byte(count >> 24)
	data[42] = byte(count >> 16)
	data[43] = byte(count >> 8)
	data[44] = byte(count)

	_, err := DecodeSnapStorageResponse(data)
	if err == nil {
		t.Error("expected error for exceeding max entries")
	}
}

func TestSnapBytecodeResponseMaxEntriesExceeded(t *testing.T) {
	data := make([]byte, 13)
	data[8] = 0
	count := uint32(MaxSnapBytecodePerResponse + 1)
	data[9] = byte(count >> 24)
	data[10] = byte(count >> 16)
	data[11] = byte(count >> 8)
	data[12] = byte(count)

	_, err := DecodeSnapBytecodeResponse(data)
	if err == nil {
		t.Error("expected error for exceeding max entries")
	}
}

func TestSnapBytecodeRequestMaxHashesExceeded(t *testing.T) {
	data := make([]byte, 16)
	count := uint32(MaxSnapBytecodePerResponse + 1)
	data[8] = byte(count >> 24)
	data[9] = byte(count >> 16)
	data[10] = byte(count >> 8)
	data[11] = byte(count)

	_, err := DecodeSnapBytecodeRequest(data)
	if err == nil {
		t.Error("expected error for exceeding max hashes")
	}
}

func TestSnapStateResponseLargeAddressExceeded(t *testing.T) {
	// Create a response with an address that's too large
	data := make([]byte, 13+2+4) // header + addrLen(2) + accLen(4)
	data[8] = 0
	// count = 1
	data[12] = 1
	// addrLen = MaxSnapAddressSize + 1 (too large)
	addrLen := uint16(MaxSnapAddressSize + 1)
	data[13] = byte(addrLen >> 8)
	data[14] = byte(addrLen)

	_, err := DecodeSnapStateResponse(data)
	if err == nil {
		t.Error("expected error for address size exceeding max")
	}
}

func TestSnapBytecodeResponseLargeCodeExceeded(t *testing.T) {
	// Create a response with code that's too large
	data := make([]byte, 13+32+4) // header + hash(32) + codeLen(4)
	data[8] = 0
	// count = 1
	data[12] = 1
	// codeLen = MaxSnapBytecodeSize + 1 (too large)
	codeLen := uint32(MaxSnapBytecodeSize + 1)
	data[13+32] = byte(codeLen >> 24)
	data[13+33] = byte(codeLen >> 16)
	data[13+34] = byte(codeLen >> 8)
	data[13+35] = byte(codeLen)

	_, err := DecodeSnapBytecodeResponse(data)
	if err == nil {
		t.Error("expected error for code size exceeding max")
	}
}

func TestSnapBytecodeRequestNoHashes(t *testing.T) {
	req := &SnapBytecodeRequest{
		BlockHeight: 100,
		Hashes:      []types.Hash{},
		Limit:       50,
	}

	encoded := EncodeSnapBytecodeRequest(req)
	decoded, err := DecodeSnapBytecodeRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeSnapBytecodeRequest failed: %v", err)
	}

	if len(decoded.Hashes) != 0 {
		t.Errorf("len(Hashes) = %d, want 0", len(decoded.Hashes))
	}
}

// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"encoding/binary"
	"fmt"

	"github.com/quantaureum/qau/types"
)

const (
	MaxSnapAccountsPerResponse = 1000
	MaxSnapStoragePerResponse  = 5000
	MaxSnapBytecodePerResponse = 100

	MaxSnapAddressSize  = 64
	MaxSnapAccountSize  = 1024 * 1024
	MaxSnapBytecodeSize = 24576

	// LOW-7 FIX: Sanity bounds for BlockHeight in snap sync responses.
	// A malicious peer could send a response with BlockHeight=0 or an
	// absurdly large value to corrupt sync state or trigger downstream
	// integer overflows. We reject heights outside [1, MaxSnapBlockHeight].
	// The upper bound is set conservatively at 2^63-1 to catch garbage
	// values while accommodating any realistic chain length.
	MinSnapBlockHeight = 1
	MaxSnapBlockHeight = (1 << 63) - 1
)

// validateSnapBlockHeight performs a sanity check on a BlockHeight value
// received from a remote peer during snap sync. Returns an error if the
// height is outside the acceptable range.
// LOW-7 FIX: Previously, Decode*Response functions accepted any uint64
// BlockHeight without validation, allowing a malicious peer to inject
// height=0 or height=math.MaxUint64 to corrupt sync state.
func validateSnapBlockHeight(height uint64) error {
	if height < MinSnapBlockHeight {
		return fmt.Errorf("snap sync response has invalid BlockHeight %d: must be >= %d", height, MinSnapBlockHeight)
	}
	if height > MaxSnapBlockHeight {
		return fmt.Errorf("snap sync response has invalid BlockHeight %d: must be <= %d", height, MaxSnapBlockHeight)
	}
	return nil
}

type SnapStateRequest struct {
	BlockHeight uint64
	StartHash   types.Hash
	Limit       uint32
}

func EncodeSnapStateRequest(req *SnapStateRequest) []byte {
	buf := make([]byte, 8+32+4)
	binary.BigEndian.PutUint64(buf[0:8], req.BlockHeight)
	copy(buf[8:40], req.StartHash[:])
	binary.BigEndian.PutUint32(buf[40:44], req.Limit)
	return buf
}

func DecodeSnapStateRequest(data []byte) (*SnapStateRequest, error) {
	if len(data) < 44 {
		return nil, fmt.Errorf("snap state request too short: %d bytes", len(data))
	}
	req := &SnapStateRequest{
		BlockHeight: binary.BigEndian.Uint64(data[0:8]),
		Limit:       binary.BigEndian.Uint32(data[40:44]),
	}
	// R33 P2P-10 FIX (2026-07-28): Validate BlockHeight on requests too,
	// not just responses. A malicious peer could send a request with
	// BlockHeight=0 or math.MaxUint64 to corrupt server-side sync state
	// or trigger expensive lookups for invalid heights.
	if err := validateSnapBlockHeight(req.BlockHeight); err != nil {
		return nil, err
	}
	copy(req.StartHash[:], data[8:40])
	return req, nil
}

type SnapAccountData struct {
	Address types.Address
	Account []byte
}

type SnapStateResponse struct {
	BlockHeight uint64
	Accounts    []SnapAccountData
	MoreComing  bool
	// FIX (2026-08-15): Truncated indicates the server
	// hit its hard export cap (maxSnapServeAccounts) and stopped before
	// the entire account set was streamed. Receivers MUST NOT treat the
	// sync as complete when Truncated is set — the state root all-sync
	// the receiver computed over the partial set would be wrong (the
	// result of running on a snapshot that is, by definition, incomplete).
	Truncated bool
}

func EncodeSnapStateResponse(resp *SnapStateResponse) []byte {
	count := len(resp.Accounts)
	buf := make([]byte, 8+1+4)
	binary.BigEndian.PutUint64(buf[0:8], resp.BlockHeight)
	// FIX (2026-08-15): flags byte is now a bitmask.
	// bit 0 = MoreComing (back-compat: legacy peers read `data[8] == 1`).
	// bit 1 = Truncated (new flag added by  so receivers can
	// distinguish a hard-cap cut from a clean end-of-stream).
	var flags byte
	if resp.MoreComing {
		flags |= 1
	}
	if resp.Truncated {
		flags |= 2
	}
	buf[8] = flags
	binary.BigEndian.PutUint32(buf[9:13], uint32(count))

	for _, acc := range resp.Accounts {
		addrLen := uint32(len(acc.Address))
		accLen := uint32(len(acc.Account))
		entry := make([]byte, 2+addrLen+4+accLen)
		binary.BigEndian.PutUint16(entry[0:2], uint16(addrLen))
		copy(entry[2:2+addrLen], acc.Address[:])
		binary.BigEndian.PutUint32(entry[2+addrLen:6+addrLen], accLen)
		copy(entry[6+addrLen:6+addrLen+accLen], acc.Account)
		buf = append(buf, entry...)
	}
	return buf
}

func DecodeSnapStateResponse(data []byte) (*SnapStateResponse, error) {
	if len(data) < 13 {
		return nil, fmt.Errorf("snap state response too short: %d bytes", len(data))
	}
	// FIX (2026-08-15): flags byte is a bitmask.
	// bit 0 = MoreComing, bit 1 = Truncated. The old decoder read
	// `data[8] == 1`; using `& 1` here means encoded MoreComing-only
	// responses (value 1) decode identically to before, preserving
	// wire-compat with peers on either side of the upgrade boundary.
	resp := &SnapStateResponse{
		BlockHeight: binary.BigEndian.Uint64(data[0:8]),
		MoreComing:  data[8]&1 != 0,
		Truncated:   data[8]&2 != 0,
	}
	// LOW-7 FIX: Validate BlockHeight before trusting the response.
	if err := validateSnapBlockHeight(resp.BlockHeight); err != nil {
		return nil, err
	}
	count := binary.BigEndian.Uint32(data[9:13])
	if count > MaxSnapAccountsPerResponse {
		return nil, fmt.Errorf("snap state response account count %d exceeds max %d", count, MaxSnapAccountsPerResponse)
	}

	resp.Accounts = make([]SnapAccountData, 0, count)
	offset := 13
	for i := uint32(0); i < count; i++ {
		if offset+2 > len(data) {
			return nil, fmt.Errorf("snap state response truncated at account %d", i)
		}
		addrLen := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		if int(addrLen) > MaxSnapAddressSize {
			return nil, fmt.Errorf("snap state response address size %d exceeds max %d at account %d", addrLen, MaxSnapAddressSize, i)
		}
		if offset+int(addrLen)+4 > len(data) {
			return nil, fmt.Errorf("snap state response truncated at account %d address", i)
		}
		var addr types.Address
		copy(addr[:], data[offset:offset+int(addrLen)])
		offset += int(addrLen)

		accLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		if int(accLen) > MaxSnapAccountSize {
			return nil, fmt.Errorf("snap state response account data size %d exceeds max %d at account %d", accLen, MaxSnapAccountSize, i)
		}
		if offset+int(accLen) > len(data) {
			return nil, fmt.Errorf("snap state response truncated at account %d data", i)
		}
		accData := make([]byte, accLen)
		copy(accData, data[offset:offset+int(accLen)])
		offset += int(accLen)

		resp.Accounts = append(resp.Accounts, SnapAccountData{
			Address: addr,
			Account: accData,
		})
	}
	return resp, nil
}

type SnapStorageRequest struct {
	BlockHeight uint64
	AccountHash types.Hash
	StartKey    types.Hash
	Limit       uint32
}

func EncodeSnapStorageRequest(req *SnapStorageRequest) []byte {
	buf := make([]byte, 8+32+32+4)
	binary.BigEndian.PutUint64(buf[0:8], req.BlockHeight)
	copy(buf[8:40], req.AccountHash[:])
	copy(buf[40:72], req.StartKey[:])
	binary.BigEndian.PutUint32(buf[72:76], req.Limit)
	return buf
}

func DecodeSnapStorageRequest(data []byte) (*SnapStorageRequest, error) {
	if len(data) < 76 {
		return nil, fmt.Errorf("snap storage request too short: %d bytes", len(data))
	}
	req := &SnapStorageRequest{
		BlockHeight: binary.BigEndian.Uint64(data[0:8]),
		Limit:       binary.BigEndian.Uint32(data[72:76]),
	}
	// R33 P2P-10 FIX: Validate BlockHeight on requests (same as state).
	if err := validateSnapBlockHeight(req.BlockHeight); err != nil {
		return nil, err
	}
	copy(req.AccountHash[:], data[8:40])
	copy(req.StartKey[:], data[40:72])
	return req, nil
}

type SnapStorageEntry struct {
	Key   types.Hash
	Value types.Hash
}

type SnapStorageResponse struct {
	BlockHeight uint64
	AccountHash types.Hash
	Entries     []SnapStorageEntry
	MoreComing  bool
	// FIX (2026-08-15): Truncated indicates the server
	// hit its hard export cap (maxSnapServeStorage) before the account's
	// full storage was streamed. This is the more dangerous of the two
	// truncation cases: the account-phase state-root check in
	// completeSnapSync happens BEFORE storage is requested, so a storage
	// truncation has NO downstream verification and would silently leave
	// the trie inconsistent. Receivers MUST detect Truncated and abort
	// the snap sync (treat as a failed peer, retry from a different peer).
	Truncated bool
}

func EncodeSnapStorageResponse(resp *SnapStorageResponse) []byte {
	count := len(resp.Entries)
	buf := make([]byte, 8+32+1+4)
	binary.BigEndian.PutUint64(buf[0:8], resp.BlockHeight)
	copy(buf[8:40], resp.AccountHash[:])
	// FIX (2026-08-15): flags byte is a bitmask.
	// bit 0 = MoreComing, bit 1 = Truncated (hard-cap cut). Back-compat
	// with legacy peers is preserved because value 1 still means pure
	// MoreComing, and `data[40] == 1` on the old decode path matches.
	var flags byte
	if resp.MoreComing {
		flags |= 1
	}
	if resp.Truncated {
		flags |= 2
	}
	buf[40] = flags
	binary.BigEndian.PutUint32(buf[41:45], uint32(count))

	for _, entry := range resp.Entries {
		entryBuf := make([]byte, 64)
		copy(entryBuf[0:32], entry.Key[:])
		copy(entryBuf[32:64], entry.Value[:])
		buf = append(buf, entryBuf...)
	}
	return buf
}

func DecodeSnapStorageResponse(data []byte) (*SnapStorageResponse, error) {
	if len(data) < 45 {
		return nil, fmt.Errorf("snap storage response too short: %d bytes", len(data))
	}
	resp := &SnapStorageResponse{
		BlockHeight: binary.BigEndian.Uint64(data[0:8]),
		MoreComing:  data[40]&1 != 0,
		Truncated:   data[40]&2 != 0,
	}
	// LOW-7 FIX: Validate BlockHeight before trusting the response.
	if err := validateSnapBlockHeight(resp.BlockHeight); err != nil {
		return nil, err
	}
	copy(resp.AccountHash[:], data[8:40])
	count := binary.BigEndian.Uint32(data[41:45])
	if count > MaxSnapStoragePerResponse {
		return nil, fmt.Errorf("snap storage response entry count %d exceeds max %d", count, MaxSnapStoragePerResponse)
	}

	resp.Entries = make([]SnapStorageEntry, 0, count)
	offset := 45
	for i := uint32(0); i < count; i++ {
		if offset+64 > len(data) {
			return nil, fmt.Errorf("snap storage response truncated at entry %d", i)
		}
		var key, value types.Hash
		copy(key[:], data[offset:offset+32])
		copy(value[:], data[offset+32:offset+64])
		resp.Entries = append(resp.Entries, SnapStorageEntry{Key: key, Value: value})
		offset += 64
	}
	return resp, nil
}

type SnapBytecodeRequest struct {
	BlockHeight uint64
	Hashes      []types.Hash
	Limit       uint32
}

func EncodeSnapBytecodeRequest(req *SnapBytecodeRequest) []byte {
	count := len(req.Hashes)
	buf := make([]byte, 8+4+4)
	binary.BigEndian.PutUint64(buf[0:8], req.BlockHeight)
	binary.BigEndian.PutUint32(buf[8:12], uint32(count))
	binary.BigEndian.PutUint32(buf[12:16], req.Limit)
	for _, h := range req.Hashes {
		hashBuf := make([]byte, 32)
		copy(hashBuf, h[:])
		buf = append(buf, hashBuf...)
	}
	return buf
}

func DecodeSnapBytecodeRequest(data []byte) (*SnapBytecodeRequest, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("snap bytecode request too short: %d bytes", len(data))
	}
	req := &SnapBytecodeRequest{
		BlockHeight: binary.BigEndian.Uint64(data[0:8]),
		Limit:       binary.BigEndian.Uint32(data[12:16]),
	}
	// R33 P2P-10 FIX: Validate BlockHeight on requests (same as state/storage).
	if err := validateSnapBlockHeight(req.BlockHeight); err != nil {
		return nil, err
	}
	count := binary.BigEndian.Uint32(data[8:12])
	if count > MaxSnapBytecodePerResponse {
		return nil, fmt.Errorf("snap bytecode request hash count %d exceeds max %d", count, MaxSnapBytecodePerResponse)
	}

	req.Hashes = make([]types.Hash, count)
	offset := 16
	for i := uint32(0); i < count; i++ {
		if offset+32 > len(data) {
			return nil, fmt.Errorf("snap bytecode request truncated at hash %d", i)
		}
		copy(req.Hashes[i][:], data[offset:offset+32])
		offset += 32
	}
	return req, nil
}

type SnapBytecodeEntry struct {
	Hash types.Hash
	Code []byte
}

type SnapBytecodeResponse struct {
	BlockHeight uint64
	Entries     []SnapBytecodeEntry
	MoreComing  bool
}

func EncodeSnapBytecodeResponse(resp *SnapBytecodeResponse) []byte {
	count := len(resp.Entries)
	buf := make([]byte, 8+1+4)
	binary.BigEndian.PutUint64(buf[0:8], resp.BlockHeight)
	if resp.MoreComing {
		buf[8] = 1
	}
	binary.BigEndian.PutUint32(buf[9:13], uint32(count))

	for _, entry := range resp.Entries {
		codeLen := uint32(len(entry.Code))
		entryBuf := make([]byte, 32+4+codeLen)
		copy(entryBuf[0:32], entry.Hash[:])
		binary.BigEndian.PutUint32(entryBuf[32:36], codeLen)
		copy(entryBuf[36:36+codeLen], entry.Code)
		buf = append(buf, entryBuf...)
	}
	return buf
}

func DecodeSnapBytecodeResponse(data []byte) (*SnapBytecodeResponse, error) {
	if len(data) < 13 {
		return nil, fmt.Errorf("snap bytecode response too short: %d bytes", len(data))
	}
	resp := &SnapBytecodeResponse{
		BlockHeight: binary.BigEndian.Uint64(data[0:8]),
		MoreComing:  data[8] == 1,
	}
	// LOW-7 FIX: Validate BlockHeight before trusting the response.
	if err := validateSnapBlockHeight(resp.BlockHeight); err != nil {
		return nil, err
	}
	count := binary.BigEndian.Uint32(data[9:13])
	if count > MaxSnapBytecodePerResponse {
		return nil, fmt.Errorf("snap bytecode response entry count %d exceeds max %d", count, MaxSnapBytecodePerResponse)
	}

	resp.Entries = make([]SnapBytecodeEntry, 0, count)
	offset := 13
	for i := uint32(0); i < count; i++ {
		if offset+36 > len(data) {
			return nil, fmt.Errorf("snap bytecode response truncated at entry %d", i)
		}
		var hash types.Hash
		copy(hash[:], data[offset:offset+32])
		codeLen := binary.BigEndian.Uint32(data[offset+32 : offset+36])
		offset += 36
		if int(codeLen) > MaxSnapBytecodeSize {
			return nil, fmt.Errorf("snap bytecode response code size %d exceeds max %d at entry %d", codeLen, MaxSnapBytecodeSize, i)
		}
		if offset+int(codeLen) > len(data) {
			return nil, fmt.Errorf("snap bytecode response truncated at entry %d code", i)
		}
		code := make([]byte, codeLen)
		copy(code, data[offset:offset+int(codeLen)])
		offset += int(codeLen)

		resp.Entries = append(resp.Entries, SnapBytecodeEntry{Hash: hash, Code: code})
	}
	return resp, nil
}

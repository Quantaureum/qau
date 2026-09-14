// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/quantaureum/qau/types"
)

// L1Bridge contract bytecode, assembled from contracts/L1Bridge.qasm.
// W-P1-6 Phase 4 (2026-07-14): On-chain QASM bridge contract that verifies
// 160-depth Sparse Merkle Tree proofs using the SHA-256 precompile.
//
// The contract implements 4 functions:
//   - getLiquidity() → uint256
//   - deposit() → uint256 (accepts CALLVALUE)
//   - recordFinalizedBatch(uint256, bytes32) → uint256 (owner-only)
//   - processWithdrawal(bytes32, uint256, uint256, uint256, bytes32, bytes32, bytes32, bytes32[160]) → uint256
//
// BRDG-FIX (2026-07-16): processWithdrawal now computes the leafHash
// in-contract via SHA256(withdrawer[20] || amount[32] || txIndex[4]) instead
// of trusting a caller-supplied leafHash. The calldata field at [196:228] is
// ignored. This binds the withdrawal amount into the Merkle proof's leaf
// preimage, preventing a malicious relayer from swapping the amount while
// reusing a valid (leafHash, siblings) proof.
//
// Storage layout:
//
//	slot 0:                  owner (deployer)
//	slot 1:                  liquidity (total locked QAU)
//	slot batchIndex+0x1000:  finalized L2 state roots
//	slot dsKey:              processed withdrawal markers
//	  where dsKey = (batchIndex << 160) | withdrawer
const L1BridgeBytecodeHex = "0x731000611101c51100131000791101c5100006761004303511000a02000310007510e04512ffffffff401712f7b6d1e534110045021712a6f2aea334110052021712b4d3d1a034110066021712c5e4f2b83411008802160003161001601000511020100006031610016074201001611001100051102010000603167310006034351101b502100475111000201024751b61100110005110201000060316104475111000206010a47534351101b70210447510a044100475411760100034351101b9021064751101585110247511015451100475110134517c100211014010381000102093351101bf021610047510a051100010c05110a47510e0510310a010c050303511016a02109f10c0501b211710081b23100c2010a0501b471b1710081b241007211b164510014010c05010202210e42075100050171040511b171060511616110137021101440103104050106050104051106051037c1002104010401080102093351101bd021610805010005110c05010012010c0511100e8010310005010e05034351101bb021710011b61161001601024751b301101c1021001601024751b211001617c10047510247510001000100010009017351101c302161001100051102010000603070307030703070307030703070307"

// Function selectors (manually defined per QASM convention, NOT keccak256).
// W-P1-6 Phase 4 (2026-07-14)
const (
	SelectorGetLiquidity         uint32 = 0xf7b6d1e5
	SelectorDeposit              uint32 = 0xa6f2aea3
	SelectorRecordFinalizedBatch uint32 = 0xb4d3d1a0
	SelectorProcessWithdrawal    uint32 = 0xc5e4f2b8
)

// Calldata offsets for processWithdrawal (relative to calldata start).
// W-P1-6 Phase 4 (2026-07-14)
// BRDG- (2026-07-16): pwLeafHashOffset is now IGNORED by the contract —
// the leafHash is computed in-contract from withdrawer/amount/txIndex. The
// field is kept in the calldata for backward-compatible encoding only.
const (
	pwWithdrawerOffset  = 4            // [4:36]   withdrawer (left-padded to 32 bytes)
	pwAmountOffset      = 36           // [36:68]  amount (uint256)
	pwBatchIndexOffset  = 68           // [68:100] batchIndex (uint256)
	pwTxIndexOffset     = 100          // [100:132] txIndex (uint256)
	pwBatchHashOffset   = 132          // [132:164] batchHash (bytes32)
	pwStateRootOffset   = 164          // [164:196] stateRoot (bytes32)
	pwLeafHashOffset    = 196          // [196:228] leafHash (IGNORED — computed in-contract)
	pwSiblingsOffset    = 228          // [228:5348] siblings[160] (160 × 32 bytes)
	pwSiblingsCount     = 160          // must match SparseMerkleTreeDepth
	pwCalldataTotalSize = 228 + 160*32 // 5348 bytes
)

// L1BridgeBytecode returns the deployment bytecode of the L1Bridge contract.
// Use this to deploy the contract via eth_sendTransaction with To=nil.
// W-P1-6 Phase 4 (2026-07-14)
//
// R8-OBS-3 (2026-07-18): Converted from panic to returned error for
// production resilience. The hex constant is validated at package init()
// time — if validation fails there, the process exits with a clear
// log.Fatalf message at startup. The error return here is a defensive
// fallback for the (theoretically impossible) case where init-time
// validation was bypassed (e.g., direct call in a test that skips init).
func L1BridgeBytecode() ([]byte, error) {
	data, err := hex.DecodeString(strings.TrimPrefix(L1BridgeBytecodeHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid L1Bridge bytecode hex: %w", err)
	}
	return data, nil
}

// init validates the L1Bridge bytecode hex constant at package load time.
// If the constant is ever corrupted (e.g., a future edit introduces an
// invalid hex string), the process exits immediately with a clear message
// rather than crashing on the first call to L1BridgeBytecode.
// R8-OBS-3 (2026-07-18)
func init() {
	if _, err := hex.DecodeString(strings.TrimPrefix(L1BridgeBytecodeHex, "0x")); err != nil {
		// Use log.Fatalf via the standard log package to ensure the
		// message is flushed before os.Exit. We import log here (not
		// the project's logger) to avoid circular dependencies during
		// package initialization.
		fmt.Fprintf(os.Stderr, "FATAL (R8-OBS-3): L1Bridge bytecode hex constant is invalid: %v\n", err)
		os.Exit(1)
	}
}

// --- Calldata encoders ---

// EncodeGetLiquidity encodes calldata for getLiquidity() → uint256.
// W-P1-6 Phase 4 (2026-07-14)
func EncodeGetLiquidity() []byte {
	return encodeSelector(SelectorGetLiquidity)
}

// EncodeDeposit encodes calldata for deposit() → uint256.
// The caller must attach CALLVALUE equal to the deposit amount.
// W-P1-6 Phase 4 (2026-07-14)
func EncodeDeposit() []byte {
	return encodeSelector(SelectorDeposit)
}

// EncodeRecordFinalizedBatch encodes calldata for
// recordFinalizedBatch(uint256 batchIndex, bytes32 stateRoot) → uint256.
//
// Only the contract owner (deployer) can call this. The rollup operator
// sends this transaction when a batch's challenge period expires.
// W-P1-6 Phase 4 (2026-07-14)
func EncodeRecordFinalizedBatch(batchIndex uint64, stateRoot types.Hash) []byte {
	data := encodeSelector(SelectorRecordFinalizedBatch)
	// batchIndex (32 bytes, left-padded)
	data = append(data, toWord32(new(big.Int).SetUint64(batchIndex).Bytes())...)
	// stateRoot (32 bytes)
	data = append(data, stateRoot[:]...)
	return data
}

// EncodeProcessWithdrawal encodes calldata for
// processWithdrawal(bytes32 withdrawer, uint256 amount, uint256 batchIndex,
//
//	uint256 txIndex, bytes32 batchHash, bytes32 stateRoot,
//	bytes32 leafHash, bytes32[160] siblings) → uint256.
//
// The caller can be anyone (relayer). The contract verifies the Merkle
// proof and releases funds to the withdrawer. Gas cost is high due to
// 160 SHA-256 STATICCALLs (~160 * 100 gas = ~16000 gas for hashing,
// plus loop overhead).
// W-P1-6 Phase 4 (2026-07-14)
func EncodeProcessWithdrawal(
	withdrawer types.Address,
	amount *big.Int,
	batchIndex uint64,
	txIndex int,
	batchHash types.Hash,
	stateRoot types.Hash,
	leafHash types.Hash,
	siblings []types.Hash,
) ([]byte, error) {
	if len(siblings) != pwSiblingsCount {
		return nil, fmt.Errorf("processWithdrawal requires exactly %d siblings, got %d",
			pwSiblingsCount, len(siblings))
	}
	if amount == nil || amount.Sign() <= 0 {
		return nil, fmt.Errorf("withdrawal amount must be positive")
	}

	data := encodeSelector(SelectorProcessWithdrawal)
	// withdrawer (left-padded to 32 bytes)
	data = append(data, toWord32(withdrawer[:])...)
	// amount (uint256)
	data = append(data, toWord32(amount.Bytes())...)
	// batchIndex (uint256)
	data = append(data, toWord32(new(big.Int).SetUint64(batchIndex).Bytes())...)
	// txIndex (uint256)
	data = append(data, toWord32(new(big.Int).SetInt64(int64(txIndex)).Bytes())...)
	// batchHash (bytes32)
	data = append(data, batchHash[:]...)
	// stateRoot (bytes32)
	data = append(data, stateRoot[:]...)
	// leafHash (bytes32)
	data = append(data, leafHash[:]...)
	// siblings[160] (160 × 32 bytes)
	for i := 0; i < pwSiblingsCount; i++ {
		data = append(data, siblings[i][:]...) // #nosec G602 -- len(siblings)==pwSiblingsCount verified in caller
	}

	if len(data) != pwCalldataTotalSize {
		return nil, fmt.Errorf("internal: calldata size mismatch: got %d, expected %d",
			len(data), pwCalldataTotalSize)
	}
	return data, nil
}

// --- Return value decoders ---

// DecodeUint256Result decodes a 32-byte return value as a big.Int.
// Used for getLiquidity(), deposit(), recordFinalizedBatch(), processWithdrawal()
// which all return uint256 1 on success (or the liquidity value for getLiquidity).
// W-P1-6 Phase 4 (2026-07-14)
func DecodeUint256Result(data []byte) (*big.Int, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("return data too short: got %d bytes, need 32", len(data))
	}
	return new(big.Int).SetBytes(data[:32]), nil
}

// DecodeBoolResult decodes a uint256 return value as a boolean (1=true, 0=false).
// W-P1-6 Phase 4 (2026-07-14)
func DecodeBoolResult(data []byte) (bool, error) {
	val, err := DecodeUint256Result(data)
	if err != nil {
		return false, err
	}
	return val.Sign() != 0, nil
}

// --- Helpers ---

// encodeSelector returns a 4-byte function selector.
func encodeSelector(selector uint32) []byte {
	return []byte{
		byte(selector >> 24),
		byte(selector >> 16),
		byte(selector >> 8),
		byte(selector),
	}
}

// toWord32 left-pads a byte slice to exactly 32 bytes.
func toWord32(b []byte) []byte {
	if len(b) > 32 {
		// Keep only the last 32 bytes (big-endian overflow).
		b = b[len(b)-32:]
	}
	word := make([]byte, 32)
	copy(word[32-len(b):], b)
	return word
}

// BuildProcessWithdrawalCalldata is a convenience wrapper that builds
// the processWithdrawal calldata from a MerkleWithdrawalProof and
// withdrawal parameters. It extracts the leafHash and siblings from
// the proof struct.
//
// AUDIT R4-BRDG-02 (2026-07-15): The stateRoot field in the calldata now
// carries the WithdrawalRoot (root of the dedicated withdrawal tree) instead
// of the L2 state root. The QASM contract (when updated) will use this to
// verify the withdrawal leaf inclusion.
func BuildProcessWithdrawalCalldata(
	withdrawer types.Address,
	amount *big.Int,
	batchIndex uint64,
	txIndex int,
	batchHash types.Hash,
	proof *MerkleWithdrawalProof,
) ([]byte, error) {
	if proof == nil || proof.Proof == nil {
		return nil, fmt.Errorf("nil withdrawal proof")
	}
	return EncodeProcessWithdrawal(
		withdrawer,
		amount,
		batchIndex,
		txIndex,
		batchHash,
		proof.WithdrawalRoot, // calldata field carries the withdrawal tree root
		proof.Proof.LeafHash,
		proof.Proof.Siblings,
	)
}

// L1BridgeContractAddress is a helper that computes the expected storage
// slot for a finalized state root: slot = batchIndex + 0x1000.
// This matches the QASM contract's recordFinalizedBatch storage logic.
// Useful for direct eth_getStorageAt queries without going through eth_call.
// W-P1-6 Phase 4 (2026-07-14)
func L1BridgeFinalizedRootSlot(batchIndex uint64) *big.Int {
	return new(big.Int).Add(big.NewInt(0x1000), new(big.Int).SetUint64(batchIndex))
}

// L1BridgeProcessedSlot computes the storage slot for the double-spend
// marker: slot = (batchIndex << 160) | withdrawer.
// This matches the QASM contract's processWithdrawal double-spend check.
// Useful for checking if a withdrawal has been processed via eth_getStorageAt.
// W-P1-6 Phase 4 (2026-07-14)
func L1BridgeProcessedSlot(batchIndex uint64, withdrawer types.Address) *big.Int {
	batchShifted := new(big.Int).Lsh(new(big.Int).SetUint64(batchIndex), 160)
	withdrawerInt := new(big.Int).SetBytes(withdrawer[:])
	return new(big.Int).Or(batchShifted, withdrawerInt)
}

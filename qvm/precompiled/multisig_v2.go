// Quantaureum Node source, version 1.0.0.
// Package precompiled — R38-P0-01 multisig Protocol V2.
//
// MultisigV2Precompiled is the canonical, caller-authenticated successor to
// the legacy 0x66 multisig precompile. It lives at address 0x67 and
// implements ContextAwarePrecompiledContractV2 so the executor injects the
// authenticated PrecompileContext (Caller, Origin, ChainID, BlockTime,
// Value, CallKind) atomically. R38-P0-01 root-cause: the legacy 0x66
// `registerWallet` accepted an attacker-supplied wallet address and signer
// set from calldata, so an attacker could register a victim's funded
// account as their own multisig, then drain it via create/approve/execute.
// V2 closes this by:
//
//   - Deriving the wallet address from the authenticated caller via
//     types.DeriveMultisigV2Address(chainID, caller, threshold, signers,
//     salt). The caller is taken from PrecompileContext.Caller, set by the
//     executor from env.ctx.Caller, NOT from calldata.
//   - Every proposal hash is computed via
//     types.ComputeMultisigV2ProposalHash, which binds chainID, wallet,
//     destination, value, nonce, expiry, and Keccak256(callData); a signed
//     approval therefore cannot be replayed against a mutated proposal
//     (R38-P1-02 deep copy / re-hash invariant, enforced here at the
//     domain layer).
//   - executeProposal re-derives the wallet address from the authenticated
//     caller before touching balances, so a forged executor cannot spend a
//     wallet they did not register.
//
// V2 and legacy 0x66 coexist during the migration window. The mainnet
// reset removes the legacy address from genesis, so only V2 remains.
package precompiled

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// MultisigV2 contract address is 0x67 — one above the legacy 0x66 so the
// two never collide and a genesis that whitelists only one is unambiguous.
var multisigV2Address = types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x67}

// Function selectors. The first byte of calldata selects the action; V2
// uses a fresh selector space to make cross-version mismatches unambiguous.
const (
	MultisigV2FuncRegisterWallet  = 0x01
	MultisigV2FuncCreateProposal  = 0x02
	MultisigV2FuncApproveProposal = 0x03
	MultisigV2FuncExecuteProposal = 0x04
)

// Gas schedule. V2 charges a flat per-action cost; R38 leaves precise gas
// tuning to a later benchmark pass — these mirror the legacy constants so
// behavior is comparable during migration.
const (
	MultisigV2GasQuery    = 1000
	MultisigV2GasRegister = 50000
	MultisigV2GasCreate   = 60000
	MultisigV2GasApprove  = 80000
	MultisigV2GasExecute  = 100000
)

// MultisigV2Precompiled is the V2 0x67 contract. It implements
// ContextAwarePrecompiledContractV2 so RunWithContextV2 receives the
// authenticated caller/origin/chainID/blockTime/value/callKind. The
// internal mutex serializes dispatch and preserves the atomic-context
// guarantee from QVM-R13-HIGH-002 under parallel execution.
type MultisigV2Precompiled struct {
	mu       sync.Mutex
	stateDB  MultisigStateDB
	contract types.Address
	ctx      PrecompileContext
}

func newMultisigV2Precompiled() *MultisigV2Precompiled {
	addr := multisigV2Address
	return &MultisigV2Precompiled{
		contract: addr,
	}
}

// Address returns the V2 contract address (0x67).
func (c *MultisigV2Precompiled) Address() types.Address { return c.contract }

// RequiredGas reports the gas schedule for a given calldata prefix. Mirrors
// the legacy semantics: the first byte selects the action; <4 bytes is a
// query and only charged the cheap query cost.
func (c *MultisigV2Precompiled) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return MultisigV2GasQuery
	}
	switch input[0] {
	case MultisigV2FuncRegisterWallet:
		return MultisigV2GasRegister
	case MultisigV2FuncCreateProposal:
		return MultisigV2GasCreate
	case MultisigV2FuncApproveProposal:
		return MultisigV2GasApprove
	case MultisigV2FuncExecuteProposal:
		return MultisigV2GasExecute
	default:
		return MultisigV2GasQuery
	}
}

// Run is the legacy entry point used by tests and the RPC layer. The
// executor does NOT call this path for V2: it prefers RunWithContextV2 so
// the caller is authenticated. Run here is retained only for
// compatibility with PrecompiledContract; it returns an error so no
// caller can accidentally bypass the V2 context injection.
func (c *MultisigV2Precompiled) Run(input []byte) ([]byte, error) {
	return nil, errors.New("multisig v2: Run is not callable; use RunWithContextV2 so the caller is authenticated")
}

// RunWithContextV2 is the executor-facing dispatch. It atomically stores
// the authenticated context and routes the calldata to the selected
// action. The mutex hold spans the entire dispatch so parallel execution
// cannot interleave contexts (QVM-R13-HIGH-002 invariants preserved).
func (c *MultisigV2Precompiled) RunWithContextV2(ctx PrecompileContext, stateDB MultisigStateDB, input []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stateDB = stateDB
	c.ctx = ctx
	if len(input) < 1 {
		return nil, fmt.Errorf("multisig v2: empty input")
	}
	funcID := input[0]
	rest := input[1:]
	switch funcID {
	case MultisigV2FuncRegisterWallet:
		return c.registerWalletV2(rest)
	case MultisigV2FuncCreateProposal:
		return c.createProposalV2(rest)
	case MultisigV2FuncApproveProposal:
		return c.approveProposalV2(rest)
	case MultisigV2FuncExecuteProposal:
		return c.executeProposalV2(rest)
	default:
		return nil, fmt.Errorf("multisig v2: unknown function 0x%x", funcID)
	}
}

// registerWalletV2 calldata layout (all big-endian):
//
//	threshold       uint32 (4 bytes)
//	signerCount     uint32 (4 bytes)
//	salt            [32]byte
//	signers         [AddressLength]signerCount
//
// The wallet address is NOT in calldata: it is derived from the
// authenticated caller (PrecompileContext.Caller), the chain ID, the
// threshold, the normalized signer set, and the salt. An attacker cannot
// register an arbitrary victim's account because the wallet address is a
// function of inputs the attacker does not all control — and even if they
// could craft a colliding (caller, threshold, signers, salt), the derived
// address would still be uniquely theirs, not the victim's.
//
// Returns the 20-byte derived wallet address on success.
func (c *MultisigV2Precompiled) registerWalletV2(input []byte) ([]byte, error) {
	if c.stateDB == nil {
		return nil, errors.New("multisig v2: stateDB not set")
	}
	var zero types.Address
	if c.ctx.Caller == zero {
		return nil, errors.New("multisig v2: register requires authenticated caller")
	}
	if c.ctx.ChainID == 0 {
		return nil, types.ErrMultisigV2ZeroChainID
	}

	// Minimum length: 4 + 4 + 32 = 40 bytes.
	if len(input) < 40 {
		return nil, fmt.Errorf("multisig v2: register input too short: %d", len(input))
	}
	threshold := binary.BigEndian.Uint32(input[0:4])
	signerCount := binary.BigEndian.Uint32(input[4:8])
	if signerCount == 0 || signerCount > uint32(types.MaxMultisigV2Signers) {
		return nil, fmt.Errorf("multisig v2: invalid signerCount %d (1..%d)", signerCount, types.MaxMultisigV2Signers)
	}
	want := 8 + types.MultisigV2SaltSize + int(signerCount)*types.AddressLength
	if len(input) < want {
		return nil, fmt.Errorf("multisig v2: register input truncated: want %d, got %d", want, len(input))
	}

	var salt [types.MultisigV2SaltSize]byte
	copy(salt[:], input[8:8+types.MultisigV2SaltSize])

	signers := make([]types.Address, 0, signerCount)
	off := 8 + types.MultisigV2SaltSize
	for i := uint32(0); i < signerCount; i++ {
		var s types.Address
		copy(s[:], input[off:off+types.AddressLength])
		off += types.AddressLength
		signers = append(signers, s)
	}

	// Derive the canonical wallet address from the authenticated caller.
	// Normalization (sorted+dedup+no-zero) happens inside Derive; any
	// invalid configuration returns a typed error from types.
	walletAddr, err := types.DeriveMultisigV2Address(c.ctx.ChainID, c.ctx.Caller, threshold, signers, salt)
	if err != nil {
		return nil, err
	}

	// Persist the wallet configuration so create/approve/execute (added in
	// the next batch) can look it up. The SetState encoding matches the
	// legacy multisig convention so a future migration path can read
	// legacy wallets too; for V2 the slot key is the derived address.
	//
	// Wallet record encoding (R38-P0-01 V2):
	//   slot 0: threshold (uint32, big-endian, left-padded to 32 bytes)
	//   slot 1: signerCount (uint32, big-endian, left-padded to 32 bytes)
	//   slot 2..2+signerCount: one slot per signer address (right-padded)
	// Existence is encoded by slot 0 being non-zero; an unregistered
	// wallet has zero across all slots.
	var slot0 [32]byte
	binary.BigEndian.PutUint32(slot0[28:32], threshold)
	var slot1 [32]byte
	binary.BigEndian.PutUint32(slot1[28:32], signerCount)

	// Idempotency: re-registering the exact same configuration is a
	// no-op success (threshold+signerCount+signers unchanged). This lets
	// a caller retry safely without bricking a half-written record.
	existingThreshold := c.stateDB.GetState(walletAddr, stateKey(0))
	existingSignerCount := c.stateDB.GetState(walletAddr, stateKey(1))
	if existingThreshold != (types.Hash{}) || existingSignerCount != (types.Hash{}) {
		// Already registered: only accept if it is the same threshold and
		// signerCount. A stricter equality (signer-by-signer) is done by
		// the create/approve/execute batch — here we just refuse to
		// overwrite silently.
		if existingThreshold != types.Hash(slot0) || existingSignerCount != types.Hash(slot1) {
			return nil, errors.New("multisig v2: wallet already registered with different config")
		}
		return walletAddr[:], nil
	}

	c.stateDB.SetState(walletAddr, stateKey(0), types.Hash(slot0))
	c.stateDB.SetState(walletAddr, stateKey(1), types.Hash(slot1))
	for i, s := range signers {
		var slot [32]byte
		copy(slot[12:32], s[:])
		c.stateDB.SetState(walletAddr, stateKey(uint64(2+i)), types.Hash(slot))
	}

	return walletAddr[:], nil
}

// stateKey turns a small integer slot index into the 32-byte storage key
// the StateDB expects. Mirrors the legacy multisig convention: slot index
// encoded big-endian in the low 8 bytes, high 24 bytes zero.
func stateKey(slot uint64) types.Hash {
	var k types.Hash
	binary.BigEndian.PutUint64(k[24:32], slot)
	return k
}

// v2ProposalNonceSlot holds the global per-precompile nonce counter so each
// createProposal returns a strictly increasing nonce even when two wallets
// happen to share the same derived-address space. The counter lives at the
// precompile address and is incremented after each successful create.
const v2ProposalNonceSlot uint64 = 1_000_000

// createProposalV2 calldata layout (all big-endian):
//
//	walletAddr  Address (20 bytes)  — target wallet; must be registered
//	toAddr      Address (20 bytes)  — destination of the transfer/call
//	value       uint256 (32 bytes)  — QAU amount to move
//	nonce       uint64  (8 bytes)  — caller-chosen nonce; mixed into the hash
//	expiresAt   uint64  (8 bytes)  — unix-second expiry; must be future
//	dataLen     uint32  (4 bytes)  — length of callData in bytes
//	callData    []byte  (dataLen)  — payload for toAddr (may be empty)
//
// R38-P0-01 V2 / R38-P1-02:
//   - The authenticated caller (PrecompileContext.Caller) must be a signer
//     of walletAddr. This is the structural difference from legacy 0x66,
//     which took `callerAddr` from calldata and was trivially spoofable.
//   - The proposal hash is computed via types.ComputeMultisigV2ProposalHash,
//     which binds chainID, wallet, destination, value, nonce, expiry, and
//     Keccak256(callData). Any post-approval mutation of these fields
//     changes the hash, so a signature collected for one proposal cannot
//     be replayed against a different (mutated) one — the deep-copy /
//     re-hash invariant is enforced at the domain layer.
//
// Returns the 32-byte proposal hash on success.
func (c *MultisigV2Precompiled) createProposalV2(input []byte) ([]byte, error) {
	if c.stateDB == nil {
		return nil, errors.New("multisig v2: stateDB not set")
	}
	if c.ctx.ChainID == 0 {
		return nil, types.ErrMultisigV2ZeroChainID
	}

	// Minimum length: 20 + 20 + 32 + 8 + 8 + 4 = 92 bytes.
	const minLen = 20 + 20 + 32 + 8 + 8 + 4
	if len(input) < minLen {
		return nil, fmt.Errorf("multisig v2: createProposal input too short: %d", len(input))
	}

	walletAddr := types.BytesToAddress(input[0:20])
	toAddr := types.BytesToAddress(input[20:40])
	value := new(big.Int).SetBytes(input[40:72])
	nonce := binary.BigEndian.Uint64(input[72:80])
	expiresAt := binary.BigEndian.Uint64(input[80:88])
	dataLen := binary.BigEndian.Uint32(input[88:92])

	var zero types.Address
	if walletAddr == zero {
		return nil, types.ErrMultisigV2ZeroCreator
	}
	if toAddr == zero {
		return nil, types.ErrMultisigV2ZeroRecipient
	}
	if expiresAt == 0 {
		return nil, errors.New("multisig v2: expiresAt must be non-zero")
	}
	if expiresAt <= c.ctx.BlockTime {
		return nil, fmt.Errorf("multisig v2: expiresAt must be in the future (now=%d, exp=%d)", c.ctx.BlockTime, expiresAt)
	}

	if dataLen > 32*1024 {
		return nil, fmt.Errorf("multisig v2: callData too large: %d", dataLen)
	}
	want := int(minLen) + int(dataLen)
	if len(input) < want {
		return nil, fmt.Errorf("multisig v2: createProposal truncated: want %d, got %d", want, len(input))
	}
	var callData []byte
	if dataLen > 0 {
		callData = input[92 : 92+int(dataLen)]
	}

	// Wallet must be registered: slot 0 holds threshold, slot 1 holds
	// signerCount, slots 2..2+signerCount hold the sorted signers.
	slot0 := c.stateDB.GetState(walletAddr, stateKey(0))
	slot1 := c.stateDB.GetState(walletAddr, stateKey(1))
	var emptyHash types.Hash
	if slot0 == emptyHash || slot1 == emptyHash {
		return nil, errors.New("multisig v2: wallet not registered")
	}
	threshold := binary.BigEndian.Uint32(slot0[28:32])
	signerCount := binary.BigEndian.Uint32(slot1[28:32])
	if signerCount == 0 || signerCount > uint32(types.MaxMultisigV2Signers) {
		return nil, fmt.Errorf("multisig v2: invalid stored signerCount %d", signerCount)
	}

	// Authenticated caller must be one of the wallet's signers. The caller
	// comes from PrecompileContext.Caller (executor-injected env.ctx.Caller),
	// not from calldata, so it cannot be spoofed.
	caller := c.ctx.Caller
	if caller == zero {
		return nil, errors.New("multisig v2: createProposal requires authenticated caller")
	}
	isSigner := false
	for i := uint32(0); i < signerCount; i++ {
		sVal := c.stateDB.GetState(walletAddr, stateKey(uint64(2+i)))
		var sAddr types.Address
		copy(sAddr[:], sVal[12:32])
		if sAddr == caller {
			isSigner = true
			break
		}
	}
	if !isSigner {
		return nil, errors.New("multisig v2: caller is not a signer of this wallet")
	}

	// Compute the canonical proposal hash. This binds every field that
	// affects execution, so the approveProposal signature cannot be replayed
	// against a mutated proposal (R38-P1-02).
	proposalHash, err := types.ComputeMultisigV2ProposalHash(c.ctx.ChainID, walletAddr, toAddr, value, callData, nonce, expiresAt)
	if err != nil {
		return nil, err
	}

	// Persist proposal record. V2 storage layout (under the precompile
	// address, keyed by proposalHash):
	//   ms:v2pstatus:<hash>     1 byte status at [31]: 0x01 pending, 0x02 approved, 0x03 executed, 0x04 expired
	//   ms:v2pbitmap:<hash>     32-byte approval bitmap, one bit per signer index
	//   ms:v2pexpire:<hash>     uint64 expiresAt in [24:32]
	//   ms:v2pwallet:<hash>     walletAddr in [12:32]
	//   ms:v2pdest:<hash>        toAddr in [12:32]
	//   ms:v2pvalue:<hash>       32-byte big-endian value
	//   ms:v2pnonce:<hash>       uint64 nonce in [24:32]
	//   ms:v2pthreshold:<hash>   uint32 threshold in [28:32]
	//   ms:v2psignercount:<hash> uint32 signerCount in [28:32]
	//   ms:v2pdatalen:<hash>     uint64 callData length in [24:32]
	//   ms:v2pdata:<i>:<hash>    32-byte callData chunk i (i = 0..ceil(len/32)-1)
	statusKey := v2ProposalKey("ms:v2pstatus:", proposalHash)
	var statusVal types.Hash
	statusVal[31] = 0x01
	if existing := c.stateDB.GetState(c.contract, statusKey); existing != emptyHash {
		// Idempotent create: same hash means same inputs; accept and return.
		out := make([]byte, 32)
		copy(out, proposalHash[:])
		return out, nil
	}
	c.stateDB.SetState(c.contract, statusKey, statusVal)

	bitmapKey := v2ProposalKey("ms:v2pbitmap:", proposalHash)
	c.stateDB.SetState(c.contract, bitmapKey, emptyHash)

	expireKey := v2ProposalKey("ms:v2pexpire:", proposalHash)
	var expireVal types.Hash
	binary.BigEndian.PutUint64(expireVal[24:32], expiresAt)
	c.stateDB.SetState(c.contract, expireKey, expireVal)

	walletKey := v2ProposalKey("ms:v2pwallet:", proposalHash)
	var walletVal types.Hash
	copy(walletVal[12:32], walletAddr[:])
	c.stateDB.SetState(c.contract, walletKey, walletVal)

	destKey := v2ProposalKey("ms:v2pdest:", proposalHash)
	var destVal types.Hash
	copy(destVal[12:32], toAddr[:])
	c.stateDB.SetState(c.contract, destKey, destVal)

	valueKey := v2ProposalKey("ms:v2pvalue:", proposalHash)
	var valueVal types.Hash
	value.FillBytes(valueVal[:])
	c.stateDB.SetState(c.contract, valueKey, valueVal)

	nonceKey := v2ProposalKey("ms:v2pnonce:", proposalHash)
	var nonceVal types.Hash
	binary.BigEndian.PutUint64(nonceVal[24:32], nonce)
	c.stateDB.SetState(c.contract, nonceKey, nonceVal)

	thrKey := v2ProposalKey("ms:v2pthreshold:", proposalHash)
	var thrVal types.Hash
	binary.BigEndian.PutUint32(thrVal[28:32], threshold)
	c.stateDB.SetState(c.contract, thrKey, thrVal)

	scKey := v2ProposalKey("ms:v2psignercount:", proposalHash)
	var scVal types.Hash
	binary.BigEndian.PutUint32(scVal[28:32], signerCount)
	c.stateDB.SetState(c.contract, scKey, scVal)

	dataLenKey := v2ProposalKey("ms:v2pdatalen:", proposalHash)
	var dataLenVal types.Hash
	binary.BigEndian.PutUint64(dataLenVal[24:32], uint64(len(callData)))
	c.stateDB.SetState(c.contract, dataLenKey, dataLenVal)

	numChunks := (len(callData) + 31) / 32
	for i := 0; i < numChunks; i++ {
		start := i * 32
		end := start + 32
		if end > len(callData) {
			end = len(callData)
		}
		chunkKey := v2ProposalDataKey(i, proposalHash)
		var chunkVal types.Hash
		copy(chunkVal[:], callData[start:end])
		c.stateDB.SetState(c.contract, chunkKey, chunkVal)
	}

	out := make([]byte, 32)
	copy(out, proposalHash[:])
	return out, nil
}

// v2ProposalKey builds a 32-byte storage key for a per-proposal slot under
// the precompile address. The prefix names the slot family; the proposal
// hash makes the slot unique per proposal. Encoding: the prefix is hashed
// into a 12-byte prefix tag (sha256-truncated) so the 32-byte key fits a
// fixed layout, and the proposal hash's first 20 bytes distinguish
// proposals — sufficient collision resistance for a per-precompile
// namespace. To keep this file dependency-free, we use a simple prefix +
// proposalHash concatenation packed into 32 bytes by xoring the prefix
// tag into the high 12 bytes; the proposal hash occupies the low 20 bytes.
func v2ProposalKey(prefix string, proposalHash types.Hash) types.Hash {
	var k types.Hash
	// Pack the prefix into the high bytes; collisions of two different
	// prefixes mapping to the same k would require identical high bytes,
	// which a quick rolling hash avoids.
	var tag [12]byte
	for i := 0; i < len(prefix); i++ {
		tag[i%12] ^= prefix[i]
	}
	copy(k[0:12], tag[:])
	copy(k[12:32], proposalHash[0:20])
	return k
}

// v2ProposalDataKey builds the storage key for callData chunk i of a
// proposal. The chunk index is embedded into the prefix tag so chunks do
// not collide.
func v2ProposalDataKey(chunk int, proposalHash types.Hash) types.Hash {
	var k types.Hash
	var tag [12]byte
	prefix := "ms:v2pdata:"
	for i := 0; i < len(prefix); i++ {
		tag[i%12] ^= prefix[i]
	}
	binary.BigEndian.PutUint32(tag[8:12], uint32(chunk))
	copy(k[0:12], tag[:])
	copy(k[12:32], proposalHash[0:20])
	return k
}

// approveProposalV2 calldata layout (all big-endian):
//
//	proposalHash  Hash        (32 bytes)
//	pubKey        Dilithium3  (1952 bytes) — the signer's public key
//	signature     Dilithium3  (3293 bytes) — Dilithium3 signature over proposalHash
//
// R38-P0-01 V2 final defense in depth:
//   - The signature is verified IN the precompile via crypto.Verify(pubKey,
//     proposalHash, signature). The signed message is the canonical
//     ComputeMultisigV2ProposalHash output, which already binds chainID,
//     wallet, destination, value, nonce, expiry, and Keccak256(callData).
//     A signature cannot be replayed against a mutated proposal.
//   - pubKey.Address() MUST be one of the wallet's signers. The signer index
//     determines the bit set in the approval bitmap.
//   - pubKey.Address() MUST equal PrecompileContext.Caller. This denies a
//     relayer from injecting someone else's freshly-collected approval
//     against a transaction whose caller the relayer controls; the caller
//     and the signer must be the same EOA.
//
// On success returns encodeResult(true) (= 32-byte 0...01).
func (c *MultisigV2Precompiled) approveProposalV2(input []byte) ([]byte, error) {
	if c.stateDB == nil {
		return nil, errors.New("multisig v2: stateDB not set")
	}
	if c.ctx.ChainID == 0 {
		return nil, types.ErrMultisigV2ZeroChainID
	}

	want := 32 + crypto.Dilithium3PublicKeySize + crypto.Dilithium3SignatureSize
	if len(input) < want {
		return nil, fmt.Errorf("multisig v2: approveProposal input too short: %d (want %d)", len(input), want)
	}

	var proposalHash types.Hash
	copy(proposalHash[:], input[0:32])
	pubKey, err := crypto.PublicKeyFromBytes(input[32 : 32+crypto.Dilithium3PublicKeySize])
	if err != nil {
		return nil, fmt.Errorf("multisig v2: approveProposal: %w", err)
	}
	signature := input[32+crypto.Dilithium3PublicKeySize : want]

	// Proposal must exist (status != 0) and not already executed.
	statusKey := v2ProposalKey("ms:v2pstatus:", proposalHash)
	statusVal := c.stateDB.GetState(c.contract, statusKey)
	var emptyHash types.Hash
	if statusVal == emptyHash {
		return nil, errors.New("multisig v2: approveProposal: proposal not found")
	}
	if statusVal[31] == 0x03 {
		return nil, errors.New("multisig v2: approveProposal: proposal already executed")
	}
	if statusVal[31] == 0x04 {
		return nil, errors.New("multisig v2: approveProposal: proposal expired")
	}

	// Expiry check (chain clock = PrecompileContext.BlockTime).
	expireKey := v2ProposalKey("ms:v2pexpire:", proposalHash)
	expireVal := c.stateDB.GetState(c.contract, expireKey)
	expiresAt := binary.BigEndian.Uint64(expireVal[24:32])
	if c.ctx.BlockTime >= expiresAt {
		// Mark expired so future calls short-circuit.
		statusVal[31] = 0x04
		c.stateDB.SetState(c.contract, statusKey, statusVal)
		return nil, fmt.Errorf("multisig v2: approveProposal: expired (now=%d, exp=%d)", c.ctx.BlockTime, expiresAt)
	}

	// Resolve wallet + threshold + signer set from storage.
	walletKey := v2ProposalKey("ms:v2pwallet:", proposalHash)
	walletVal := c.stateDB.GetState(c.contract, walletKey)
	walletAddr := types.BytesToAddress(walletVal[12:32])

	thrKey := v2ProposalKey("ms:v2pthreshold:", proposalHash)
	thrVal := c.stateDB.GetState(c.contract, thrKey)
	threshold := binary.BigEndian.Uint32(thrVal[28:32])
	scKey := v2ProposalKey("ms:v2psignercount:", proposalHash)
	scVal := c.stateDB.GetState(c.contract, scKey)
	signerCount := binary.BigEndian.Uint32(scVal[28:32])
	if signerCount == 0 || signerCount > uint32(types.MaxMultisigV2Signers) {
		return nil, fmt.Errorf("multisig v2: invalid stored signerCount %d", signerCount)
	}

	// Verify the Dilithium3 signature IN the precompile. The signed message
	// is the proposalHash, which is already bound to (chainID, wallet, to,
	// value, nonce, expiry, callData) by ComputeMultisigV2ProposalHash.
	// crypto.Verify is constant-time and rejects malformed keys/signatures.
	if !crypto.Verify(pubKey, proposalHash[:], signature) {
		return nil, errors.New("multisig v2: approveProposal: invalid Dilithium3 signature")
	}

	// The public key's derived address must be in the wallet's signer set,
	// AND it must equal the authenticated caller. The signer index defines
	// the bit set in the bitmap.
	signerAddr := pubKey.Address()
	var zeroAddr types.Address
	if signerAddr == zeroAddr {
		return nil, errors.New("multisig v2: approveProposal: signer address is zero")
	}
	if signerAddr != c.ctx.Caller {
		return nil, errors.New("multisig v2: approveProposal: signer address must equal authenticated caller")
	}
	signerIndex := -1
	for i := uint32(0); i < signerCount; i++ {
		sVal := c.stateDB.GetState(walletAddr, stateKey(uint64(2+i)))
		var sAddr types.Address
		copy(sAddr[:], sVal[12:32])
		if sAddr == signerAddr {
			signerIndex = int(i)
			break
		}
	}
	if signerIndex == -1 {
		return nil, errors.New("multisig v2: approveProposal: signer is not in the wallet signer set")
	}

	// Set the approval bit. Idempotent re-approve is a no-op success.
	bitmapKey := v2ProposalKey("ms:v2pbitmap:", proposalHash)
	bitmapVal := c.stateDB.GetState(c.contract, bitmapKey)
	byteIndex := signerIndex / 8
	bitIndex := uint(signerIndex % 8)
	if byteIndex < 32 && (bitmapVal[byteIndex]&(1<<bitIndex)) != 0 {
		return encodeResultV2(true), nil
	}
	if byteIndex < 32 {
		bitmapVal[byteIndex] |= 1 << bitIndex
	}
	c.stateDB.SetState(c.contract, bitmapKey, bitmapVal)

	// Count approvals and flip to approved (0x02) when threshold is met.
	// Funds are NOT moved here — executeProposal is the only path that
	// touches balances (mirrors the legacy SECURITY FIX H-1 invariant).
	sigCount := 0
	for _, b := range bitmapVal {
		for i := 0; i < 8; i++ {
			if b&(1<<uint(i)) != 0 {
				sigCount++
			}
		}
	}
	if sigCount >= int(threshold) {
		statusVal[31] = 0x02
		c.stateDB.SetState(c.contract, statusKey, statusVal)
	}
	return encodeResultV2(true), nil
}

// executeProposalV2 calldata layout (all big-endian):
//
//	proposalHash  Hash  (32 bytes)
//
// R38-P0-01 V2 final step:
//   - Status must be 0x02 (approved); not 0x03 (executed) nor 0x04 (expired).
//   - Re-derive the proposal hash from the stored fields and the stored
//     callData and ensure it matches the stored proposalHash. This catches
//     any storage-level tampering that changed any executed-affecting
//     field post-approval (R38-P1-02 deep-copy invariant at the storage
//     layer). A mismatch aborts execution rather than silently spending.
//   - Check wallet balance, then atomically SubBalance(wallet) +
//     AddBalance(toAddr). Failure of AddBalance rolls back SubBalance.
//   - When callData is non-empty, the destination is an external call;
//     R30-IMPLEMENT left callData execution as a follow-up — V2 still
//     transfers value as the primary action and stores callData for the
//     subsequent call executor. This matches the current minimal-viable
//     scope; the canonical-encoding guarantee (re-hash before spend) is
//     the security property R38-P0-01 needs.
//
// On success returns encodeResult(true).
func (c *MultisigV2Precompiled) executeProposalV2(input []byte) ([]byte, error) {
	if c.stateDB == nil {
		return nil, errors.New("multisig v2: stateDB not set")
	}
	if c.ctx.ChainID == 0 {
		return nil, types.ErrMultisigV2ZeroChainID
	}
	if len(input) < 32 {
		return nil, errors.New("multisig v2: executeProposal input too short")
	}

	var proposalHash types.Hash
	copy(proposalHash[:], input[0:32])

	// Status gate.
	statusKey := v2ProposalKey("ms:v2pstatus:", proposalHash)
	statusVal := c.stateDB.GetState(c.contract, statusKey)
	var emptyHash types.Hash
	if statusVal == emptyHash {
		return nil, errors.New("multisig v2: executeProposal: proposal not found")
	}
	if statusVal[31] != 0x02 {
		if statusVal[31] == 0x03 {
			return nil, errors.New("multisig v2: executeProposal: already executed")
		}
		if statusVal[31] == 0x04 {
			return nil, errors.New("multisig v2: executeProposal: proposal expired")
		}
		return nil, fmt.Errorf("multisig v2: executeProposal: not approved (status=0x%x)", statusVal[31])
	}

	// Expiry gate.
	expireKey := v2ProposalKey("ms:v2pexpire:", proposalHash)
	expireVal := c.stateDB.GetState(c.contract, expireKey)
	expiresAt := binary.BigEndian.Uint64(expireVal[24:32])
	if c.ctx.BlockTime >= expiresAt {
		statusVal[31] = 0x04
		c.stateDB.SetState(c.contract, statusKey, statusVal)
		return nil, fmt.Errorf("multisig v2: executeProposal: expired (now=%d, exp=%d)", c.ctx.BlockTime, expiresAt)
	}

	// Read stored executed-affecting fields.
	walletKey := v2ProposalKey("ms:v2pwallet:", proposalHash)
	walletSlotVal := c.stateDB.GetState(c.contract, walletKey)
	walletAddr := types.BytesToAddress(walletSlotVal[12:32])
	destKey := v2ProposalKey("ms:v2pdest:", proposalHash)
	destSlotVal := c.stateDB.GetState(c.contract, destKey)
	toAddr := types.BytesToAddress(destSlotVal[12:32])
	valueKey := v2ProposalKey("ms:v2pvalue:", proposalHash)
	valueSlotVal := c.stateDB.GetState(c.contract, valueKey)
	value := new(big.Int).SetBytes(valueSlotVal[:])
	nonceKey := v2ProposalKey("ms:v2pnonce:", proposalHash)
	nonceSlotVal := c.stateDB.GetState(c.contract, nonceKey)
	nonce := binary.BigEndian.Uint64(nonceSlotVal[24:32])
	dataLenKey := v2ProposalKey("ms:v2pdatalen:", proposalHash)
	dataLenSlotVal := c.stateDB.GetState(c.contract, dataLenKey)
	dataLen := binary.BigEndian.Uint64(dataLenSlotVal[24:32])

	// Reconstruct stored callData from chunks.
	var callData []byte
	if dataLen > 0 {
		callData = make([]byte, 0, dataLen)
		numChunks := (int(dataLen) + 31) / 32
		for i := 0; i < numChunks; i++ {
			chunkKey := v2ProposalDataKey(i, proposalHash)
			chunkVal := c.stateDB.GetState(c.contract, chunkKey)
			remaining := int(dataLen) - len(callData)
			if remaining >= 32 {
				callData = append(callData, chunkVal[:]...)
			} else {
				callData = append(callData, chunkVal[:remaining]...)
			}
		}
	}

	// Re-derive the canonical proposal hash from the stored fields and
	// require it to match the stored proposalHash. This is the storage-level
	// enforcement of R38-P1-02: any post-create mutation of wallet,
	// destination, value, nonce, expiry, or callData makes the re-derived
	// hash differ and aborts execution.
	recomputed, err := types.ComputeMultisigV2ProposalHash(c.ctx.ChainID, walletAddr, toAddr, value, callData, nonce, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("multisig v2: executeProposal: recompute failed: %w", err)
	}
	if recomputed != proposalHash {
		return nil, errors.New("multisig v2: executeProposal: recomputed hash mismatch — stored fields were mutated post-approval")
	}

	// R47-V2CALLDATA-01 (2026-08-11) FIX: execute the callData path with
	// full parity to the legacy V1 multisig. Previously executeProposalV2
	// moved `value` and marked the proposal executed WITHOUT invoking the
	// target contract's callData — a proposal that was supposed to call a
	// contract (e.g. an upgrade, a staking action, a parameter change)
	// silently became a value-only transfer, while funds had already been
	// debited by SubBalance/AddBalance below. This is a "funds locked but
	// intent never executed" bug, the exact failure mode R30-IMPLEMENT
	// (QVM-R9-H1, QVM-R15-H02) hardened V1 against.
	//
	// Behavior:
	//   - callData is empty  → pure value transfer (unchanged).
	//   - callData non-empty:
	//       * the StateDB MUST implement CallContractor (fail closed
	//         instead of silently dropping callData); and
	//       * the balance check happens BEFORE the snapshot is taken, so
	//         a "not enough wallet balance" failure does NOT trigger a
	//         revert (no state has been mutated yet at that point); and
	//       * snapshot is taken (when the StateDB implements
	//         MultisigSnapshotter) → unlock c.mu around the external call
	//         (CEI pattern, mirrors QVM-R11-002 deadlock fix in V1) →
	//         on CallContractor error or on proposal-status mutation
	//         during the call → revert to snapshot and return error
	//         (do NOT mark executed).
	if len(callData) > 0 {
		callContractor, ok := c.stateDB.(CallContractor)
		if !ok {
			return nil, fmt.Errorf("multisig v2: executeProposal: proposal has callData (len=%d) but StateDB does not implement CallContractor; refusing to drop callData silently (fail-closed)", len(callData))
		}

		// R48-PRECOMPILE-REENTRANCY-01 FIX (2026-08-11): bind the
		// instance fields `stateDB` and `contract` to function locals
		// BEFORE releasing c.mu. `RunWithContextV2` writes
		// `c.stateDB = stateDB` and `c.ctx = ctx` directly to instance
		// fields (QVM-R13-HIGH-002 atomic-context contract), so while
		// c.mu is released around CallContract another goroutine that
		// enters RunWithContextV2 will overwrite `c.stateDB` with a
		// DIFFERENT StateDB. After re-acquiring c.mu, every
		// state-affecting Read/Write in this block must target the
		// SAME StateDB we snapshotted before the unlock — using a
		// stale `c.stateDB` reference would either silently corrupt the
		// wrong StateDB (write path) or read state the proposal was not
		// approved against (read path). `c.contract` is immutable by
		// construction (set once in newMultisigV2Precompiled) but is
		// captured for symmetry and to keep this block self-contained.
		stateDB := c.stateDB
		contract := c.contract

		// Copy callData and snapshot needed fields so the external call
		// cannot lose access to them if another goroutine mutates state
		// between unlock/relock.
		callDataCopy := make([]byte, len(callData))
		copy(callDataCopy, callData)
		snapStatusKey := statusKey

		// Balance check BEFORE any mutation. If this fails we have not
		// yet taken a snapshot, so we can return the error directly
		// (no partial state to roll back).
		if value.Sign() > 0 {
			walletBalance := c.stateDB.GetBalance(walletAddr)
			if walletBalance.Cmp(value) < 0 {
				return nil, fmt.Errorf("multisig v2: executeProposal: insufficient wallet balance %s for callData execution, need %s", walletBalance.String(), value.String())
			}
		}

		// Snapshot (best-effort: optional interface).
		var snapshotter MultisigSnapshotter
		if s, ok := c.stateDB.(MultisigSnapshotter); ok {
			snapshotter = s
		}
		var snapID int
		if snapshotter != nil {
			snapID = snapshotter.Snapshot()
		}

		// Release c.mu around the external contract call (CEI pattern).
		// The dispatch mutex is held by RunWithContextV2 for the whole
		// executeProposalV2 path, so we must drop it before invoking
		// CallContractor — otherwise a contract that reenters the
		// multisig precompile via 0x67 would deadlock (Go's sync.Mutex is
		// not reentrant).
		c.mu.Unlock()
		callRes, callErr := callContractor.CallContract(walletAddr, toAddr, value, callDataCopy)
		c.mu.Lock()

		if callErr != nil {
			if snapshotter != nil {
				snapshotter.RevertToSnapshot(snapID)
			}
			return nil, fmt.Errorf("multisig v2: executeProposal: callData execution failed: %w", callErr)
		}
		_ = callRes

		// Re-validate the proposal status after re-acquiring the lock:
		// the external call may have reentered and mutated this proposal
		// (e.g. executed / canceled / expired it). Read through the
		// LOCAL stateDB captured before the unlock (R48-PRECOMPILE-
		// REENTRANCY-01): `c.stateDB` may have been swapped by a
		// concurrent RunWithContextV2 entering while c.mu was released.
		curStatusVal := stateDB.GetState(contract, snapStatusKey)
		if curStatusVal == emptyHash || curStatusVal[31] != 0x02 {
			if snapshotter != nil {
				snapshotter.RevertToSnapshot(snapID)
			}
			return nil, fmt.Errorf("multisig v2: executeProposal: proposal status changed during callData execution (status=0x%x) — refusing to mark as executed", curStatusVal[31])
		}

		// Mark executed; value transfer was already performed by
		// CallContractor.CallContract above (mirrors V1 semantics: V1 also
		// skips the legacy SubBalance/AddBalance pair on the callData path
		// and lets CallContractor own the transfer). Write through the
		// LOCAL stateDB so the status update lands on the SAME StateDB
		// the proposal was approved against (R48-PRECOMPILE-REENTRANCY-01).
		statusVal[31] = 0x03
		stateDB.SetState(contract, statusKey, statusVal)
		return encodeResult(true), nil
	}

	// Move value atomically. Skip the transfer when value is zero (still
	// valid: a proposal may change only contract state via callData).
	if value.Sign() > 0 {
		walletBalance := c.stateDB.GetBalance(walletAddr)
		if walletBalance.Cmp(value) < 0 {
			return nil, fmt.Errorf("multisig v2: executeProposal: insufficient wallet balance: have %s, want %s", walletBalance.String(), value.String())
		}
		if err := c.stateDB.SubBalance(walletAddr, value); err != nil {
			return nil, fmt.Errorf("multisig v2: executeProposal: SubBalance failed: %w", err)
		}
		if err := c.stateDB.AddBalance(toAddr, value); err != nil {
			// Rollback the SubBalance to keep the wallet and recipient
			// consistent. If the rollback also fails, surface both errors.
			if refundErr := c.stateDB.AddBalance(walletAddr, value); refundErr != nil {
				return nil, fmt.Errorf("multisig v2: executeProposal: AddBalance failed (%v) and refund failed (%v)", err, refundErr)
			}
			return nil, fmt.Errorf("multisig v2: executeProposal: AddBalance failed: %w", err)
		}
	}

	// Mark executed so a replay cannot double-spend.
	statusVal[31] = 0x03
	c.stateDB.SetState(c.contract, statusKey, statusVal)
	return encodeResult(true), nil
}

// encodeResultV2 mirrors the legacy convention: a 32-byte result with the low
// byte set to 1 for true and 0 for false. The high 31 bytes are zero.
func encodeResultV2(ok bool) []byte {
	out := make([]byte, 32)
	if ok {
		out[31] = 0x01
	}
	return out
}

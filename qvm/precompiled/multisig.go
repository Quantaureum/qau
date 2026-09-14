// Quantaureum Node source, version 1.0.0.
package precompiled

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

const (
	MultisigFuncRegisterWallet        = 0x01
	MultisigFuncCreateProposal        = 0x02
	MultisigFuncApproveProposal       = 0x03
	MultisigFuncExecuteProposal       = 0x04
	MultisigFuncGetWalletConfig       = 0x05
	MultisigFuncGetProposal           = 0x06
	MultisigFuncGetProposalsForSigner = 0x07
	MultisigFuncIsSigner              = 0x08

	maxMultisigSigners = 100

	MultisigGasRegister = 50000
	MultisigGasCreate   = 80000
	MultisigGasApprove  = 30000
	MultisigGasExecute  = 100000
	MultisigGasQuery    = 10000

	storageSlotWalletCount   = uint32(0x1000)
	storageSlotProposalCount = uint32(0x1001)
	storageSlotProposalNonce = uint32(0x1002)
)

type MultisigStateDB interface {
	GetState(addr types.Address, key types.Hash) types.Hash
	SetState(addr types.Address, key, value types.Hash)
	GetBalance(addr types.Address) *big.Int
	SubBalance(addr types.Address, amount *big.Int) error
	AddBalance(addr types.Address, amount *big.Int) error
}

// MultisigSnapshotter is an OPTIONAL capability interface that a
// MultisigStateDB may implement to support atomic state snapshotting and
// rollback.
//
// R30-IMPLEMENT (2026-07-27): QVM-R15-H02 — executeProposal's callData path
// calls CallContractor (an arbitrary contract call) which may partially mutate
// state before failing. Without a snapshot, partial mutations are left in
// place, corrupting retry state. When the StateDB implements
// MultisigSnapshotter, executeProposal takes a snapshot before CallContractor
// and reverts to it on failure (or if the proposal status changed during the
// call). StateDB implementations that do NOT implement this interface
// preserve backward compatibility (no revert possible — partial mutations
// remain, but the proposal is still rejected with an error).
type MultisigSnapshotter interface {
	// Snapshot captures the current state and returns an opaque snapshot ID
	// that can be passed to RevertToSnapshot. Implementations MUST be safe
	// to call from within a SetState / SubBalance / AddBalance / CallContract
	// call chain (the multisig precompile holds its own mutex, but the
	// StateDB implementation must handle its own locking).
	Snapshot() int
	// RevertToSnapshot rolls back state to the snapshot identified by `id`.
	// Implementations MUST be idempotent: reverting to an unknown or
	// already-reverted snapshot is a no-op. The snapshot may be discarded
	// after revert (single-use) or retained (reusable) at the implementation's
	// discretion — callers MUST NOT assume either.
	RevertToSnapshot(id int)
}

// CallContractor is an OPTIONAL capability interface that a MultisigStateDB
// may implement to support executing arbitrary contract calls from within
// the multisig precompile.
//
// QVM-R9-H1 (2026-07-19) FIX: Previously, executeProposal only transferred
// QAU value from wallet → toAddr and silently ignored any callData. This
// meant a proposal that was supposed to invoke a contract method (e.g.,
// "transfer NFT", "approve spender") would be marked as "executed" while
// the actual contract call never happened — funds/value could be locked
// in the target contract without the intended action taking place.
//
// CallContractor lets executeProposal invoke the target contract with the
// proposal's callData when the StateDB supports it. StateDB implementations
// that do NOT implement this interface will cause executeProposal to fail
// closed (return error, do not mark as executed) when callData is non-empty.
//
// Call semantics:
//   - caller:   the wallet address (so the called contract sees the wallet
//     as msg.sender, not the precompile itself)
//   - to:       target contract address (proposal.toAddr)
//   - value:    QAU to transfer along with the call (in addition to the
//     balance transfer executeProposal already does)
//   - data:     full callData from the proposal
//   - returns:  output of the called contract, or error if the call failed
type CallContractor interface {
	CallContract(caller, to types.Address, value *big.Int, data []byte) ([]byte, error)
}

type MultisigPrecompiled struct {
	mu       sync.Mutex
	stateDB  MultisigStateDB
	contract types.Address
	// blockTime is the deterministic block timestamp (unix seconds) used for
	// proposal expiry decisions. QVM-MULTISIG-01 FIX (deep-audit 2026-07-12):
	// expiry was previously decided with time.Now(), so two validators executing
	// the same tx whose expiry straddles their (slightly different) wall clocks
	// would take different branches and diverge. Consensus-safe use REQUIRES the
	// caller (executor) to inject the block timestamp via SetBlockTime before
	// each invocation; time.Now() is only a fallback for non-consensus/test use
	// when no block time has been injected.
	blockTime uint64
	// chainID is the current chain identifier used as a domain separator in
	// multisig proposal hashes to prevent cross-chain replay attacks.
	// QVM-R10-C2 (2026-07-19) FIX: Previously computeMultisigProposalHash did
	// NOT include chainId, so a signed proposal approval valid on chain A
	// could be replayed on chain B (e.g. mainnet vs testnet) if the same
	// wallet address and nonce existed on both. Now chainId is mixed into the
	// proposal hash, making signatures chain-specific. Consensus-safe use
	// REQUIRES the caller (executor) to inject the chainId via SetChainID
	// before any createProposal/approveProposal invocation.
	chainID uint64
	// callerAddr is the authenticated caller address injected via the V2
	// context path (RunWithContextV2). R38-P0-01 FIX: registerWallet and
	// other sensitive operations use this field to verify that the actual
	// caller is authorized, instead of trusting attacker-supplied calldata.
	// When empty (legacy V1 path), sensitive operations fail closed.
	callerAddr types.Address
	// originAddr is the outermost EOA (tx sender) injected via the V2
	// context path. Used for logging/auditing; authorization is based on
	// callerAddr.
	originAddr types.Address
}

// newMultisigPrecompiled registers the legacy V1 multisig precompile at
// address 0x...0x66. AUDIT-FULL-ROUND1-2026-08-15 P1 entry-point #8
// (2026-08-15) — deprecation intent:
//
//   - All four mutator entry points (Run / RunWithContext / RunWithContextV2)
//     fail-closed for mutator function IDs (RegisterWallet / CreateProposal /
//     ApproveProposal / ExecuteProposal) via rejectV1Mutators. Funds cannot
//     move through 0x66 — verified by R39-P0-02 regression tests.
//   - Read-only query functions (GetWalletConfig, GetProposal, IsSigner)
//     remain callable on 0x66 for backward compatibility with on-chain
//     observers' historical read paths.
//   - The contract is therefore FUNCTIONALLY deprecated, not yet physically
//     removed. A future hard fork SHOULD remove this Register() call AND
//     migrate any read-only query consumers to the V2 path at 0x67. Until
//     that hard fork, the rejectV1Mutators fail-closed block above is the
//     authoritative defense — it is run for every entry point and is
//     covered by R39-P0-02 regression tests; do NOT remove it before the
//     physical removal.
func newMultisigPrecompiled() *MultisigPrecompiled {
	return &MultisigPrecompiled{
		contract: types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x66},
	}
}

func (c *MultisigPrecompiled) Address() types.Address {
	return c.contract
}

func (c *MultisigPrecompiled) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return MultisigGasQuery
	}
	funcID := input[0]
	switch funcID {
	case MultisigFuncRegisterWallet:
		return MultisigGasRegister
	case MultisigFuncCreateProposal:
		return MultisigGasCreate
	case MultisigFuncApproveProposal:
		return MultisigGasApprove
	case MultisigFuncExecuteProposal:
		return MultisigGasExecute
	default:
		return MultisigGasQuery
	}
}

// Run is DEPRECATED and fails closed for all mutator operations.
// R42-SECURITY-BOUNDARY: The legacy Run method (V1 path, precompile 0x66)
// is completely disabled for mutator functions. Production callers MUST
// use RunWithContextV2 (V2 path, precompile 0x67) which carries the
// authenticated caller/origin from the execution context.
//
// only read-only query functions (GetWalletConfig, GetProposal, etc.)
// are allowed through this path. Mutator functions (RegisterWallet,
// CreateProposal, ApproveProposal, ExecuteProposal) are rejected to
// prevent the caller-from-calldata attack vector.
//
// P3-QV-05 FIX (2026-08-03): the V1 mutator-reject switch was duplicated
// across three entry points (Run, RunWithContext, RunWithContextV2), with
// each site emitting a slightly different error message (for forensic
// disambiguation). The duplication was a maintenance burden — adding a
// new V1 mutator meant touching all three sites, and it was easy for a
// future change to silently desync one site from the others (allowing a
// V1 mutator to slip past one entry point and not the others — silent
// security regression). Extracted to rejectV1Mutators below. The
// entryPoint string parameter preserves the per-site error message
// wording so external log scrapers and forensic follow-up scripts that
// pattern-match on the message wording are unaffected.
func rejectV1Mutators(input []byte, entryPoint string) error {
	if len(input) < 1 {
		return fmt.Errorf("multisig: %s: empty input", entryPoint)
	}
	switch input[0] {
	case MultisigFuncRegisterWallet,
		MultisigFuncCreateProposal,
		MultisigFuncApproveProposal,
		MultisigFuncExecuteProposal:
		return fmt.Errorf("multisig: V1 (0x66) mutator function 0x%02x DISABLED at entry point %s; use the V2 (0x67) RunWithContextV2 path which carries the authenticated caller",
			input[0], entryPoint)
	}
	return nil
}

// V1MutatorRejected is the exported sentinel returned by rejectV1Mutators
// so wrappers / test fixtures can assert on the exact failure-chain entry.
// P3-QV-05 (2026-08-03). nil = NOT rejected (the input is a V1 query
// function which is allowed to proceed).
func V1MutatorRejected(input []byte, entryPoint string) error {
	return rejectV1Mutators(input, entryPoint)
}
func (c *MultisigPrecompiled) Run(input []byte) ([]byte, error) {
	if len(input) < 1 {
		return nil, fmt.Errorf("multisig: empty input")
	}

	// R41-L4QVFIX: Reject all V1 mutator functions at the gate.
	// Only allow read-only queries through the legacy path.
	// P3-QV-05 (2026-08-03): extracted to rejectV1Mutators; entryPoint
	// "Run (V1 0x66)" preserves the per-site forensic-disambiguation
	// wording in the error message.
	if err := rejectV1Mutators(input, "Run (V1 0x66)"); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stateDB == nil {
		return nil, fmt.Errorf("multisig: stateDB not set")
	}

	return c.dispatchLocked(input)
}

// RunWithContext atomically injects the execution context (stateDB, blockTime,
// chainID) AND dispatches the input, all under a SINGLE acquisition of c.mu.
//
// QVM-R13-HIGH-002 (2026-07-21) FIX: Previously, the QVM executor called
// SetStateDB / SetBlockTime / SetChainID as three SEPARATE locked operations,
// then called Run (which acquires the same lock again). In parallel execution
// mode (Block-STM behind a flag), multiple goroutines invoking the same
// precompile instance could interleave context sets between these four lock
// acquisitions — goroutine A's SetStateDB could be followed by goroutine B's
// SetStateDB, then goroutine A's Run would execute against goroutine B's
// stateDB. This TOCTOU race led to:
//   - Precompile executing against the wrong stateDB → wrong balance operations
//   - Cross-transaction state leakage (one tx's storage writes visible to
//     another tx's precompile execution)
//   - State root divergence between validators (parallel mode is non-deterministic)
//
// RunWithContext eliminates the race window by performing Set + dispatch under
// a single lock. The legacy Set methods remain available for sequential
// callers (e.g. the RPC layer that initializes a precompile instance once and
// then uses it single-threaded), but the executor now prefers RunWithContext.
//
// Callers MUST still verify that stateDB is non-nil before invoking; this
// method preserves the "stateDB not set" error for defensive checking.
func (c *MultisigPrecompiled) RunWithContext(stateDB MultisigStateDB, blockTime uint64, chainID uint64, input []byte) ([]byte, error) {
	if len(input) < 1 {
		return nil, fmt.Errorf("multisig: empty input")
	}

	// R41-L4QVM-13 (2026-08-03) defense-in-depth: mirror the V2 outer
	// switch (see RunWithContextV2, lines 287-293, added by R39-P0-02) on
	// the legacy V1 entry. The current production executor dispatches
	// every 0x66 invocation through executePrecompiledAtomicV2 →
	// Registry.RunWithContextV2 → MultisigPrecompiled.RunWithContextV2
	// (lines 184-244 of qvm/executor.go and precompile_context.go), so
	// this RunWithContext path is only reached when a CALLER bypasses the
	// V2 wrapper — e.g. a future test, RPC plumbing regression, or a
	// plugin that re-wires the executor. In all of those scenarios the
	// legacy mutator surface MUST stay fail-closed, because the V1
	// dispatchLocked path reads `callerAddr` from calldata (not from the
	// authenticated execution context), so an attacker controlling the
	// calldata could register a wallet at any address. Rejecting the V1
	// mutators here turns that latent risk into an immediate, loud error.
	// P3-QV-05 (2026-08-03): extracted to rejectV1Mutators; entryPoint
	// "RunWithContext (V1 0x66)" preserves the per-site forensic wording.
	if err := rejectV1Mutators(input, "RunWithContext (V1 0x66)"); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Atomically replace all three context fields under the same lock that
	// guards dispatch. No other goroutine can observe or mutate these fields
	// between the sets and the dispatch.
	c.stateDB = stateDB
	c.blockTime = blockTime
	c.chainID = chainID

	if c.stateDB == nil {
		return nil, fmt.Errorf("multisig: stateDB not set")
	}

	return c.dispatchLocked(input)
}

// RunWithContextV2 implements ContextAwarePrecompiledContractV2 (R38-P0-01).
//
// R38-P0-01 (2026-08-01) FIX: The legacy RunWithContext path did NOT receive
// the authenticated caller/origin — the multisig precompile had no way to
// know WHO was invoking it. This allowed an attacker to call registerWallet
// for ANY unregistered wallet address (including EOA accounts holding funds)
// and set themselves as a signer, then drain the funds via createProposal +
// executeProposal.
//
// The V2 path receives the authenticated caller/origin from the executor
// (which gets them from the EVM execution context, not from calldata) and
// stores them in callerAddr/originAddr. dispatchLockedV2 then enforces:
//   - registerWallet: the caller MUST be one of the signers being registered.
//     This prevents an attacker from registering a wallet they don't control.
//   - createProposal/approveProposal/executeProposal: unchanged (these already
//     verify Dilithium signatures from the wallet's registered signers).
//
// Precompiles that do NOT implement V2 are unaffected and continue to use
// the legacy RunWithContext path.
func (c *MultisigPrecompiled) RunWithContextV2(ctx PrecompileContext, stateDB MultisigStateDB, input []byte) ([]byte, error) {
	if len(input) < 1 {
		return nil, fmt.Errorf("multisig: empty input")
	}

	// R39-P0-02 (2026-08-02) FIX: legacy 0x66 multisig precompile is the
	// QVM-internal CALL target via executePrecompiledAtomicV2 →
	// Registry.RunWithContextV2 → this method. R38-P0-01 only migrated the
	// RPC admission path to V2 (0x67); the 0x66 path was left "half
	// migrated": dispatchLockedV2 routed registerWallet to registerWalletV2
	// (caller ∈ signers check), but the walletAddr field still came from
	// calldata and createProposal/approveProposal/executeProposal still
	// read both walletAddr and a self-reported callerAddr from calldata —
	// not from the authenticated ctx.Caller. This let an attacker:
	//
	//   1. registerWalletV2: register an arbitrary victim EOA as a
	//      threshold=1 wallet with the attacker as the sole signer (the
	//      caller ∈ signers check passes because the attacker is one of
	//      the signers; walletAddr is not bound to ctx.Caller);
	//   2. createProposal/approveProposal/executeProposal: pass
	//      callerAddr=attacker, walletAddr=victim in calldata → drain the
	//      victim's balance (SubBalance(victim) → AddBalance(attacker)).
	//
	// Closure strategy used here (lowest regression surface): the legacy
	// 0x66 mutator surface — registerWallet / createProposal /
	// approveProposal / executeProposal — is fail-closed on the QVM
	// execution path (RunWithContextV2, the only entry the executor uses
	// for V2-aware precompiles). On-chain contracts (QASM or otherwise)
	// that used to CALL 0x66 to mutate wallet state now get an error and
	// the call reverts — no funds can move through 0x66. Read-only queries
	// (getWalletConfig / getProposal / getProposalsForSigner / isSigner)
	// remain available so existing inspection tools keep working. The
	// canonical multisig register/propose/execute surface is the V2 0x67
	// precompile (MultisigV2Precompiled.RunWithContextV2), whose
	// walletAddr is derived from the authenticated caller and cannot be
	// spoofed to a victim's address.
	//
	// Impact on existing tests: the legacy 0x66 unit tests drive the
	// precompile via Run / registerWallet / RunWithContext — they do NOT
	// go through RunWithContextV2 — so they remain green. Only the QVM
	// executor path (production CALL 0x66) is rejected, which is the
	// intended security posture.
	// P3-QV-05 (2026-08-03): extracted to rejectV1Mutators; entryPoint
	// "RunWithContextV2 (V1 0x66)" preserves the per-site forensic wording.
	if err := rejectV1Mutators(input, "RunWithContextV2 (V1 0x66)"); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.stateDB = stateDB
	c.blockTime = ctx.BlockTime
	c.chainID = ctx.ChainID
	c.callerAddr = ctx.Caller
	c.originAddr = ctx.Origin

	if c.stateDB == nil {
		return nil, fmt.Errorf("multisig: stateDB not set")
	}

	return c.dispatchLockedV2(input, ctx)
}

// dispatchLocked executes the function dispatcher. Caller MUST hold c.mu.
func (c *MultisigPrecompiled) dispatchLocked(input []byte) ([]byte, error) {
	funcID := input[0]
	switch funcID {
	case MultisigFuncRegisterWallet:
		return c.registerWallet(input[1:])
	case MultisigFuncCreateProposal:
		return c.createProposal(input[1:])
	case MultisigFuncApproveProposal:
		return c.approveProposal(input[1:])
	case MultisigFuncExecuteProposal:
		return c.executeProposal(input[1:])
	case MultisigFuncGetWalletConfig:
		return c.getWalletConfig(input[1:])
	case MultisigFuncGetProposal:
		return c.getProposal(input[1:])
	case MultisigFuncGetProposalsForSigner:
		return c.getProposalsForSigner(input[1:])
	case MultisigFuncIsSigner:
		return c.isSigner(input[1:])
	default:
		return nil, fmt.Errorf("multisig: unknown function 0x%02x", funcID)
	}
}

// dispatchLockedV2 is the V2 dispatcher that enforces caller authorization
// on sensitive operations. R38-P0-01 FIX.
//
// The key difference from dispatchLocked is that registerWallet is routed
// to registerWalletV2, which verifies that the authenticated caller (from
// the EVM execution context, NOT from calldata) is one of the signers being
// registered. All other operations are delegated to the same internal
// methods as the V1 path, since they already verify Dilithium signatures.
//
// Caller MUST hold c.mu.
func (c *MultisigPrecompiled) dispatchLockedV2(input []byte, ctx PrecompileContext) ([]byte, error) {
	funcID := input[0]
	switch funcID {
	case MultisigFuncRegisterWallet:
		return c.registerWalletV2(input[1:], ctx)
	case MultisigFuncCreateProposal:
		return c.createProposal(input[1:])
	case MultisigFuncApproveProposal:
		return c.approveProposal(input[1:])
	case MultisigFuncExecuteProposal:
		return c.executeProposal(input[1:])
	case MultisigFuncGetWalletConfig:
		return c.getWalletConfig(input[1:])
	case MultisigFuncGetProposal:
		return c.getProposal(input[1:])
	case MultisigFuncGetProposalsForSigner:
		return c.getProposalsForSigner(input[1:])
	case MultisigFuncIsSigner:
		return c.isSigner(input[1:])
	default:
		return nil, fmt.Errorf("multisig: unknown function 0x%02x", funcID)
	}
}

func (c *MultisigPrecompiled) SetStateDB(db MultisigStateDB) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stateDB = db
}

// IsStateful implements StatefulPrecompiledContract.
//
// QVM-R10-H2 (2026-07-19) FIX: The multisig precompile is stateful — it
// creates wallets, creates/approves/executes proposals, and transfers
// balances via stateDB.SetState / SubBalance / AddBalance. STATICCALL
// callers must therefore be rejected at the executor boundary to
// preserve the read-only guarantee that EVM consumers expect from
// STATICCALL.
func (c *MultisigPrecompiled) IsStateful() bool {
	return true
}

// SetBlockTime injects the deterministic block timestamp (unix seconds) used for
// proposal expiry checks. QVM-MULTISIG-01 FIX: the executor must call this with
// the current block's timestamp before invoking the multisig precompile so that
// expiry decisions are identical across all validators. A value of 0 clears the
// injected time and reverts to the (non-consensus) wall-clock fallback.
func (c *MultisigPrecompiled) SetBlockTime(t uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blockTime = t
}

// SetChainID injects the current chain identifier used as a domain separator
// in multisig proposal hashes.
//
// QVM-R10-C2 (2026-07-19) FIX: computeMultisigProposalHash previously did NOT
// bind chainId into the proposal hash. Because walletAddr and nonce alone are
// not sufficient to disambiguate chains, a Dilithium3 approval signature over
// proposalHash computed on chain A would also verify on chain B if the same
// wallet + nonce existed on both. This is a cross-chain replay attack: an
// adversary observing a mainnet approval could replay it on testnet (or any
// sibling chain sharing the same walletAddr/nonce space) to authorize an
// unintended transfer.
//
// After this fix, chainId is mixed into the proposal hash as the FIRST field
// (domain-separation prefix), so the same (walletAddr, toAddr, value, nonce,
// expiresAt) tuple yields different hashes on different chains — making
// approval signatures chain-specific.
//
// The executor MUST call SetChainID with the current chain's identifier
// (e.g. 1668 for mainnet, 1669 for testnet) before invoking any
// expiry-sensitive multisig operation. A value of 0 clears the injected
// chainId; createProposal will then fail closed (ErrChainIDNotSet).
func (c *MultisigPrecompiled) SetChainID(chainID uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chainID = chainID
}

// ErrBlockTimeNotSet is returned when the multisig precompile is invoked for
// an expiry-sensitive operation (create/approve/execute) without a deterministic
// block timestamp having been injected via SetBlockTime.
//
// AUDIT (2026) QVFIX: Previously currentTime() fell back to
// time.Now() when no block time was injected, which is non-deterministic and
// can cause consensus divergence: two validators executing the same
// expiry-sensitive transaction whose expiry straddles their (slightly
// different) wall clocks would take different branches. Now the precompile
// fails closed instead of silently using a non-deterministic timestamp.
var ErrBlockTimeNotSet = fmt.Errorf("multisig: block time not set; executor must inject deterministic timestamp via SetBlockTime before expiry-sensitive operations")

// ErrChainIDNotSet is returned when the multisig precompile is invoked for a
// proposal-creation operation without a chainId having been injected via
// SetChainID.
//
// QVM-R10-C2 (2026-07-19) FIX: Without a chainId, computeMultisigProposalHash
// produces a hash that is not bound to any specific chain — enabling
// cross-chain replay of approval signatures. The precompile fails closed
// (rejects createProposal) until the executor injects a non-zero chainId.
var ErrChainIDNotSet = fmt.Errorf("multisig: chainId not set; executor must inject chainId via SetChainID before proposal-creation operations")

// currentTime returns the deterministic block timestamp to use for expiry
// decisions. Callers already hold c.mu (Run holds it across the whole
// dispatch).
//
// AUDIT (2026) QVFIX: Returns ErrBlockTimeNotSet when no block time
// has been injected, instead of falling back to time.Now(). This forces the
// executor to inject the block timestamp (via SetBlockTime) before any
// expiry-sensitive operation, ensuring all validators make identical expiry
// decisions.
func (c *MultisigPrecompiled) currentTime() (uint64, error) {
	if c.blockTime > 0 {
		return c.blockTime, nil
	}
	return 0, ErrBlockTimeNotSet
}

func (c *MultisigPrecompiled) storageKey(prefix string, data []byte) types.Hash {
	h := sha256.New()
	h.Write([]byte(prefix))
	h.Write(data)
	digest := h.Sum(nil)
	var hash types.Hash
	copy(hash[:], digest[:types.HashLength])
	return hash
}

func (c *MultisigPrecompiled) walletKey(addr types.Address) types.Hash {
	return c.storageKey("ms:wallet:", addr[:])
}

func (c *MultisigPrecompiled) walletSignerKey(addr types.Address, index int) types.Hash {
	idxBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(idxBytes, uint32(index))
	data := append(addr[:], idxBytes...)
	return c.storageKey("ms:wsigner:", data)
}

func (c *MultisigPrecompiled) proposalKey(hash types.Hash) types.Hash {
	return c.storageKey("ms:proposal:", hash[:])
}

func (c *MultisigPrecompiled) proposalSignerKey(hash types.Hash, index int) types.Hash {
	idxBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(idxBytes, uint32(index))
	data := append(hash[:], idxBytes...)
	return c.storageKey("ms:psigner:", data)
}

func (c *MultisigPrecompiled) signerWalletsKey(addr types.Address) types.Hash {
	return c.storageKey("ms:swallets:", addr[:])
}

// signerWalletsCountKey returns the storage key for the count of wallets
// associated with a signer. FIX: Previously only one wallet could be
// stored per signer; now we use a separate counter and indexed entries.
func (c *MultisigPrecompiled) signerWalletsCountKey(addr types.Address) types.Hash {
	return c.storageKey("ms:swcount:", addr[:])
}

// signerWalletsEntryKey returns the storage key for the wallet address at
// the given index for a signer. FIX: Enables storing multiple wallets
// per signer using incrementing indices.
func (c *MultisigPrecompiled) signerWalletsEntryKey(addr types.Address, index int) types.Hash {
	idxBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(idxBytes, uint32(index))
	data := append(addr[:], idxBytes...)
	return c.storageKey("ms:swentry:", data)
}

func (c *MultisigPrecompiled) counterKey(slot uint32) types.Hash {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, slot)
	return c.storageKey("ms:counter:", b)
}

func (c *MultisigPrecompiled) getCounter(slot uint32) uint64 {
	key := c.counterKey(slot)
	val := c.stateDB.GetState(c.contract, key)
	return new(big.Int).SetBytes(val[:]).Uint64()
}

func (c *MultisigPrecompiled) incrementCounter(slot uint32) uint64 {
	key := c.counterKey(slot)
	current := c.getCounter(slot)
	// QVM-Low (R9 2026-07-19) FIX: Guard against uint64 overflow at the
	// max value. Without this, current=math.MaxUint64 would wrap to 0 and
	// silently reset the counter — letting an attacker reuse a nonce slot
	// by submitting 2^64 - 1 proposals first. In practice this requires
	// an attacker to drive the counter to its max value, which is well
	// beyond any realistic deployment lifetime, but the guard is cheap
	// and prevents a silent wraparound that could be exploited by a
	// long-running attacker.
	if current == ^uint64(0) {
		// Counter saturated — refuse to advance rather than wrapping.
		// Callers that need to detect saturation can read getCounter()
		// and observe that it stays at the max value across calls.
		return current
	}
	newVal := new(big.Int).SetUint64(current + 1)
	var valHash types.Hash
	newVal.FillBytes(valHash[:])
	c.stateDB.SetState(c.contract, key, valHash)
	return current + 1
}

func (c *MultisigPrecompiled) registerWallet(input []byte) ([]byte, error) {
	if len(input) < 24 {
		return nil, fmt.Errorf("multisig: registerWallet invalid input length %d", len(input))
	}

	threshold := binary.BigEndian.Uint32(input[0:4])
	signerCount := binary.BigEndian.Uint32(input[4:8])
	walletAddr := types.BytesToAddress(input[8:28])

	if threshold == 0 {
		return nil, fmt.Errorf("multisig: threshold must be positive")
	}
	if signerCount == 0 {
		return nil, fmt.Errorf("multisig: need at least one signer")
	}
	if signerCount > maxMultisigSigners {
		return nil, fmt.Errorf("multisig: signer count %d exceeds maximum %d", signerCount, maxMultisigSigners)
	}
	if threshold > signerCount {
		return nil, fmt.Errorf("multisig: threshold %d exceeds signer count %d", threshold, signerCount)
	}

	expectedLen := 28 + int(signerCount)*20
	if len(input) < expectedLen {
		return nil, fmt.Errorf("multisig: registerWallet input too short, expected %d got %d", expectedLen, len(input))
	}

	wKey := c.walletKey(walletAddr)
	existing := c.stateDB.GetState(c.contract, wKey)
	if !isZeroHash(existing) {
		// R40-P2-04 (2026-08-03): the audit flagged this idempotency check
		// as comparing only the (threshold, signerCount) header — true for
		// every storage slot persisted under wKey, but the previous error
		// message ("wallet already registered") gave callers no way to
		// distinguish "harmless re-broadcast of the identical registration"
		// from "deliberate signer-set rotation attempt". This block now
		// reconstructs the stored full signer set (wallet|threshold|
		// signerCount + per-signer slots walletSignerKey(0..signerCount-1))
		// and:
		//   - returns idempotent SUCCESS if the (threshold, signerCount,
		//     signer1..signerN) tuple is byte-identical to the new input
		//     (no state mutation, behaves as `no-op + encodeResult(true)`),
		//   - rejects with a descriptive error if ANY field differs
		//     (rotation via re-registration is still forbidden; use the
		//     dedicated rotateSignersV2 entrypoint once one exists).
		// Both branches preserve the original security guarantee (no silent
		// config drift) while making the contract self-documenting for
		// integrators who legitimately re-broadcast the same registration
		// during retries / network partitions.
		storedThreshold := binary.BigEndian.Uint32(existing[0:4])
		storedSignerCount := binary.BigEndian.Uint32(existing[4:8])
		if storedThreshold == threshold && storedSignerCount == signerCount {
			signersMatch := true
			for i := uint32(0); i < signerCount; i++ {
				sKey := c.walletSignerKey(walletAddr, int(i))
				sVal := c.stateDB.GetState(c.contract, sKey)
				newSigner := types.BytesToAddress(input[28+int(i)*20 : 48+int(i)*20])
				storedSigner := types.BytesToAddress(sVal[:])
				if storedSigner != newSigner {
					signersMatch = false
					break
				}
			}
			if signersMatch {
				// Byte-identical re-registration — idempotent no-op. Return
				// the same success encoding a fresh registration would
				// produce so integrators can safely retry without worrying
				// about whether the first attempt landed.
				return encodeResult(true), nil
			}
			return nil, fmt.Errorf(
				"multisig: wallet %x already registered with a different signer set — "+
					"use rotateSignersV2 for signer rotation (R40-P2-04)", walletAddr)
		}
		return nil, fmt.Errorf(
			"multisig: wallet %x already registered (stored threshold=%d signers=%d; "+
				"new threshold=%d signers=%d) — use rotateSignersV2 for rotation (R40-P2-04)",
			walletAddr, storedThreshold, storedSignerCount, threshold, signerCount)
	}

	walletData := make([]byte, 64)
	binary.BigEndian.PutUint32(walletData[0:4], threshold)
	binary.BigEndian.PutUint32(walletData[4:8], signerCount)
	copy(walletData[8:28], walletAddr[:])
	var wh types.Hash
	copy(wh[:], walletData[:32])
	c.stateDB.SetState(c.contract, wKey, wh)

	var wh2 types.Hash
	copy(wh2[:], walletData[32:64])
	wKey2 := c.storageKey("ms:wallet2:", walletAddr[:])
	c.stateDB.SetState(c.contract, wKey2, wh2)

	for i := uint32(0); i < signerCount; i++ {
		signerAddr := types.BytesToAddress(input[28+int(i)*20 : 48+int(i)*20])
		sKey := c.walletSignerKey(walletAddr, int(i))
		var sVal types.Hash
		copy(sVal[:], signerAddr[:])
		c.stateDB.SetState(c.contract, sKey, sVal)

		// FIX: Store wallet address in an indexed list so a signer can
		// be associated with multiple wallets. Previously only the first
		// wallet was stored (count < 1 guard), silently dropping subsequent
		// registrations.
		swCountKey := c.signerWalletsCountKey(signerAddr)
		swCountVal := c.stateDB.GetState(c.contract, swCountKey)
		walletCount := uint32(0)
		if !isZeroHash(swCountVal) {
			walletCount = binary.BigEndian.Uint32(swCountVal[28:32])
		}

		// Check for duplicate wallet registration to avoid storing the same
		// wallet address multiple times for the same signer.
		alreadyRegistered := false
		for i := uint32(0); i < walletCount; i++ {
			entryKey := c.signerWalletsEntryKey(signerAddr, int(i))
			entryVal := c.stateDB.GetState(c.contract, entryKey)
			existingAddr := types.BytesToAddress(entryVal[:])
			if existingAddr == walletAddr {
				alreadyRegistered = true
				break
			}
		}

		if !alreadyRegistered {
			// Store the wallet address at the next available index.
			entryKey := c.signerWalletsEntryKey(signerAddr, int(walletCount))
			var entryVal types.Hash
			copy(entryVal[:], walletAddr[:])
			c.stateDB.SetState(c.contract, entryKey, entryVal)

			// Increment and store the updated count.
			newCountVal := make([]byte, 32)
			binary.BigEndian.PutUint32(newCountVal[28:32], walletCount+1)
			var newCountHash types.Hash
			copy(newCountHash[:], newCountVal)
			c.stateDB.SetState(c.contract, swCountKey, newCountHash)
		}
	}

	c.incrementCounter(storageSlotWalletCount)

	return encodeResult(true), nil
}

// registerWalletV2 is the caller-authenticated version of registerWallet.
// R38-P0-01 (2026-08-01) FIX.
//
// The original registerWallet accepted a wallet address and a list of
// signers from calldata WITHOUT verifying that the caller (the EOA or
// contract invoking the precompile) is one of those signers. This allowed
// an attacker to:
//  1. Call registerWallet with victimAddr as the wallet and their own
//     addresses as signers.
//  2. Create a proposal to transfer all of victimAddr's funds.
//  3. Approve and execute the proposal, draining the victim's funds.
//
// registerWalletV2 enforces that the authenticated caller (ctx.Caller,
// which comes from the EVM execution context and CANNOT be forged via
// calldata) is one of the signers being registered. This ensures that
// only someone who controls one of the signer keys can register a wallet.
//
// For wallets that are contracts (not EOAs), the contract itself must
// call registerWallet — which is the expected pattern for a contract
// wallet that wants to use multisig governance.
func (c *MultisigPrecompiled) registerWalletV2(input []byte, ctx PrecompileContext) ([]byte, error) {
	if len(input) < 24 {
		return nil, fmt.Errorf("multisig: registerWallet invalid input length %d", len(input))
	}

	threshold := binary.BigEndian.Uint32(input[0:4])
	signerCount := binary.BigEndian.Uint32(input[4:8])
	walletAddr := types.BytesToAddress(input[8:28])

	if threshold == 0 {
		return nil, fmt.Errorf("multisig: threshold must be positive")
	}
	if signerCount == 0 {
		return nil, fmt.Errorf("multisig: need at least one signer")
	}
	if signerCount > maxMultisigSigners {
		return nil, fmt.Errorf("multisig: signer count %d exceeds maximum %d", signerCount, maxMultisigSigners)
	}
	if threshold > signerCount {
		return nil, fmt.Errorf("multisig: threshold %d exceeds signer count %d", threshold, signerCount)
	}

	expectedLen := 28 + int(signerCount)*20
	if len(input) < expectedLen {
		return nil, fmt.Errorf("multisig: registerWallet input too short, expected %d got %d", expectedLen, len(input))
	}

	// R38-P0-01 FIX: Verify that the authenticated caller is one of the
	// signers being registered. This prevents an attacker from registering
	// a wallet address they don't control.
	callerIsSigner := false
	for i := uint32(0); i < signerCount; i++ {
		signerAddr := types.BytesToAddress(input[28+int(i)*20 : 48+int(i)*20])
		if signerAddr == ctx.Caller {
			callerIsSigner = true
			break
		}
	}
	if !callerIsSigner {
		return nil, fmt.Errorf("multisig: registerWallet caller %x is not among the signers being registered", ctx.Caller)
	}

	// R41-L4QVM-12 (2026-08-03) FIX: bind the registered wallet address to
	// the authenticated caller. R38-P0-01 already verified `caller ∈
	// signers`, but `walletAddr` itself is read from caller-supplied
	// calldata (input[8:28]) and could be ANY 20-byte value — including
	// the address of a VICTIM EOA that the caller is NOT authorized to
	// administer. With only the R38-P0-01 check, an attacker `M` could
	// register a multisig wallet at the victim's address V by:
	//
	//   1. Setting `walletAddr = V` in calldata.
	//   2. Listing `M` (themselves) plus a few unrelated addresses as
	//      the signers.
	//
	// The R38-P0-01 check passes (M ∈ signers), and the wallet is
	// registered at V. Any subsequent multisig proposal that targets
	// assets held by V would then be governed by M's threshold — V's
	// plain EOA assets could be moved by the multisig.
	//
	// The fix is a strict equality: the wallet being registered MUST be
	// the caller's own address. This guarantees that the caller is the
	// administrator of the wallet they are creating (i.e. the wallet belongs
	// to the caller, not to a third party). The caller MAY list other
	// signers (so `caller ∈ signers` continues to make sense), but the
	// wallet itself is anchored to the caller.
	//
	// Trade-off: this disallows the legitimate use case of one EOA
	// registering a multisig wallet that lives at a different address
	// (e.g. a CREATE2-style deterministic address). That pattern is not
	// currently supported anywhere in the multisig V2 surface, and
	// introducing it would require either (a) the walletAddr being a
	// contract that authorizes the caller — needs new state precompiles,
	// or (b) redesigning the registration surface. Both are out of scope
	// for this audit fix; the safe-by-default choice is walletAddr ==
	// ctx.Caller.
	if walletAddr != ctx.Caller {
		return nil, fmt.Errorf("multisig: registerWalletV2 caller %x does not match walletAddr %x (R41-L4QVM-12: wallet being registered must be the caller's own address; use a separate signer-set rotation flow for administering another address)", ctx.Caller, walletAddr)
	}

	wKey := c.walletKey(walletAddr)
	existing := c.stateDB.GetState(c.contract, wKey)
	if !isZeroHash(existing) {
		return nil, fmt.Errorf("multisig: wallet already registered")
	}

	walletData := make([]byte, 64)
	binary.BigEndian.PutUint32(walletData[0:4], threshold)
	binary.BigEndian.PutUint32(walletData[4:8], signerCount)
	copy(walletData[8:28], walletAddr[:])
	var wh types.Hash
	copy(wh[:], walletData[:32])
	c.stateDB.SetState(c.contract, wKey, wh)

	var wh2 types.Hash
	copy(wh2[:], walletData[32:64])
	wKey2 := c.storageKey("ms:wallet2:", walletAddr[:])
	c.stateDB.SetState(c.contract, wKey2, wh2)

	for i := uint32(0); i < signerCount; i++ {
		signerAddr := types.BytesToAddress(input[28+int(i)*20 : 48+int(i)*20])
		sKey := c.walletSignerKey(walletAddr, int(i))
		var sVal types.Hash
		copy(sVal[:], signerAddr[:])
		c.stateDB.SetState(c.contract, sKey, sVal)

		swCountKey := c.signerWalletsCountKey(signerAddr)
		swCountVal := c.stateDB.GetState(c.contract, swCountKey)
		walletCount := uint32(0)
		if !isZeroHash(swCountVal) {
			walletCount = binary.BigEndian.Uint32(swCountVal[28:32])
		}

		alreadyRegistered := false
		for j := uint32(0); j < walletCount; j++ {
			entryKey := c.signerWalletsEntryKey(signerAddr, int(j))
			entryVal := c.stateDB.GetState(c.contract, entryKey)
			existingAddr := types.BytesToAddress(entryVal[:])
			if existingAddr == walletAddr {
				alreadyRegistered = true
				break
			}
		}

		if !alreadyRegistered {
			entryKey := c.signerWalletsEntryKey(signerAddr, int(walletCount))
			var entryVal types.Hash
			copy(entryVal[:], walletAddr[:])
			c.stateDB.SetState(c.contract, entryKey, entryVal)

			newCountVal := make([]byte, 32)
			binary.BigEndian.PutUint32(newCountVal[28:32], walletCount+1)
			var newCountHash types.Hash
			copy(newCountHash[:], newCountVal)
			c.stateDB.SetState(c.contract, swCountKey, newCountHash)
		}
	}

	c.incrementCounter(storageSlotWalletCount)

	return encodeResult(true), nil
}

func (c *MultisigPrecompiled) createProposal(input []byte) ([]byte, error) {
	// FIX: Input now includes a caller address at the beginning so we can
	// verify the caller is an authorized signer of the wallet before creating
	// a proposal. Previously anyone could create proposals for any wallet.
	// FIX: Input now includes expiresAt (8 bytes) so proposals
	// can expire. Previously proposals lived forever, allowing an attacker to
	// execute an approved proposal long after the signers intended.
	// Input format: callerAddr(20) + walletAddr(20) + toAddr(20) + value(32) + expiresAt(8) + dataLen(4) + callData
	const minCreateProposalLen = 20 + 20 + 20 + 32 + 8 + 4
	if len(input) < minCreateProposalLen {
		return nil, fmt.Errorf("multisig: createProposal invalid input length %d", len(input))
	}

	callerAddr := types.BytesToAddress(input[0:20])
	walletAddr := types.BytesToAddress(input[20:40])
	toAddr := types.BytesToAddress(input[40:60])
	valueBytes := input[60:92]
	expiresAt := binary.BigEndian.Uint64(input[92:100])
	dataLen := binary.BigEndian.Uint32(input[100:104])

	// FIX: validate that expiresAt is in the future.
	if expiresAt == 0 {
		return nil, fmt.Errorf("multisig: expiresAt must be non-zero")
	}
	// AUDIT (2026) QVM-04: Fail closed when block time is not set.
	nowT, err := c.currentTime()
	if err != nil {
		return nil, err
	}
	if nowT > expiresAt {
		return nil, fmt.Errorf("multisig: expiresAt must be in the future")
	}

	var callData []byte
	if dataLen > 0 && len(input) >= 104+int(dataLen) {
		callData = input[104 : 104+int(dataLen)]
	}

	wKey := c.walletKey(walletAddr)
	walletData := c.stateDB.GetState(c.contract, wKey)
	if isZeroHash(walletData) {
		return nil, fmt.Errorf("multisig: wallet not registered")
	}
	threshold := binary.BigEndian.Uint32(walletData[0:4])
	signerCount := binary.BigEndian.Uint32(walletData[4:8])
	if err := validateSignerCount(signerCount); err != nil {
		return nil, fmt.Errorf("multisig: createProposal: %w", err)
	}

	// FIX: Verify the caller is an authorized signer of this wallet.
	// Iterate through the wallet's signer list and check if callerAddr matches.
	isAuthorizedSigner := false
	for i := uint32(0); i < signerCount; i++ {
		sKey := c.walletSignerKey(walletAddr, int(i))
		sVal := c.stateDB.GetState(c.contract, sKey)
		sAddr := types.BytesToAddress(sVal[:])
		if sAddr == callerAddr {
			isAuthorizedSigner = true
			break
		}
	}
	if !isAuthorizedSigner {
		return nil, fmt.Errorf("multisig: caller is not an authorized signer of this wallet")
	}

	nonce := c.getCounter(storageSlotProposalNonce)
	c.incrementCounter(storageSlotProposalNonce)

	// QVM-R10-C2 (2026-07-19) FIX: bind chainId into the proposal hash so
	// approval signatures are chain-specific and cannot be replayed across
	// chains. Fail closed if the executor did not inject a chainId.
	if c.chainID == 0 {
		return nil, ErrChainIDNotSet
	}
	proposalHash := computeMultisigProposalHash(c.chainID, walletAddr, toAddr, valueBytes, nonce, expiresAt)

	pKey := c.proposalKey(proposalHash)
	var ph1 types.Hash
	copy(ph1[0:20], walletAddr[:])
	copy(ph1[20:32], toAddr[:12])
	c.stateDB.SetState(c.contract, pKey, ph1)

	pData2Key := c.storageKey("ms:proposal2:", proposalHash[:])
	var ph2 types.Hash
	copy(ph2[0:8], toAddr[12:20])
	// R33 P2-24 FIX (2026-07-28): Previously copy(ph2[8:32], valueBytes)
	// stored 24 bytes of the 32-byte value into ph2[8:32], but then
	// PutUint32(ph2[12:16], threshold) and PutUint32(ph2[16:20],
	// signerCount) overwrote 8 of those bytes, corrupting the value.
	// When executeProposal read ph2[8:32] back as the value, it got a
	// mixture of value + threshold + signerCount — causing silent
	// transfer amount corruption.
	// Fix: Store the full 32-byte value in a dedicated "ms:pvalue:" slot.
	binary.BigEndian.PutUint32(ph2[8:12], threshold)
	binary.BigEndian.PutUint32(ph2[12:16], signerCount)
	c.stateDB.SetState(c.contract, pData2Key, ph2)

	// R33 P2-24 FIX: Store value in a dedicated slot (full 32 bytes, no truncation).
	pValueKey := c.storageKey("ms:pvalue:", proposalHash[:])
	var pValueVal types.Hash
	copy(pValueVal[:], valueBytes)
	c.stateDB.SetState(c.contract, pValueKey, pValueVal)

	// QVM-R9-H2 (2026-07-19) FIX: Store the proposal hash indexed by its
	// proposal index. Previously createProposal only incremented
	// storageSlotProposalCount but never wrote the mapping
	// (proposalIndex → proposalHash). As a result getProposalsForSigner
	// (which iterates proposalIndex 0..count-1 and reads the "ms:phash:"
	// slot) always saw zero hashes and returned an empty list — the
	// precompile's "list pending proposals for my signer" query was
	// completely non-functional.
	//
	// Write the mapping so the query can recover the hash and look up
	// the full proposal data. Mirrors the read-side key construction in
	// getProposalsForSigner exactly.
	proposalIdx := c.getCounter(storageSlotProposalCount)
	pHashIdxKey := c.storageKey("ms:phash:", uint64ToBEBytes(proposalIdx))
	var pHashVal types.Hash
	copy(pHashVal[:], proposalHash[:])
	c.stateDB.SetState(c.contract, pHashIdxKey, pHashVal)

	// FIX: store expiresAt in a dedicated storage slot so
	// executeProposal can reject expired proposals.
	expireKey := c.storageKey("ms:pexpire:", proposalHash[:])
	var expireVal types.Hash
	binary.BigEndian.PutUint64(expireVal[24:32], expiresAt)
	c.stateDB.SetState(c.contract, expireKey, expireVal)

	statusKey := c.storageKey("ms:pstatus:", proposalHash[:])
	var statusVal types.Hash
	statusVal[31] = 0x01
	c.stateDB.SetState(c.contract, statusKey, statusVal)

	bitmapKey := c.storageKey("ms:pbitmap:", proposalHash[:])
	var emptyBitmap types.Hash
	c.stateDB.SetState(c.contract, bitmapKey, emptyBitmap)

	// QVM-R9-H1 (2026-07-19) FIX: Store the FULL callData (not just the
	// first 32 bytes) so executeProposal can replay it against the target
	// contract. Previously only the first 32 bytes were stored, which is
	// insufficient for any realistic contract call (4-byte selector + N×32
	// bytes args). Storage layout:
	//   ms:pdatalen:        32-byte slot holding total callData length (uint64 BE)
	//   ms:pdata:<i>:       32-byte slot holding chunk i (i = 0..ceil(len/32)-1)
	//
	// Chunking is required because StateDB slots are fixed-size (32 bytes).
	// The length slot lets executeProposal know how many chunks to read
	// back, and lets it reject oversized payloads at create time.
	if len(callData) > 0 {
		const maxCallDataSize = 32 * 1024 // 32 KiB cap, defense-in-depth vs. DoS
		if len(callData) > maxCallDataSize {
			return nil, fmt.Errorf("multisig: callData too large: %d > %d", len(callData), maxCallDataSize)
		}
		dataLenKey := c.storageKey("ms:pdatalen:", proposalHash[:])
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
			chunkKey := c.storageKey("ms:pdata:"+fmt.Sprintf("%08x-", i)+":", proposalHash[:])
			var chunkVal types.Hash
			copy(chunkVal[:], callData[start:end])
			c.stateDB.SetState(c.contract, chunkKey, chunkVal)
		}
	}

	c.incrementCounter(storageSlotProposalCount)

	result := make([]byte, 32)
	copy(result, proposalHash[:])
	return result, nil
}

func (c *MultisigPrecompiled) approveProposal(input []byte) ([]byte, error) {
	// audit-fix C-1: Use real Dilithium3 signature verification instead of SHA256 hash.
	// Input format:
	//   proposalHash (32) + signerAddr (20) + publicKey (1952) + signature (3293)
	// Total: 5297 bytes
	// Legacy format (84 bytes) with SHA256 "signature" is rejected for security.
	const (
		pubKeySize = 1952
		sigSize    = 3293
		minInput   = 32 + 20 + pubKeySize + sigSize
	)
	if len(input) < minInput {
		return nil, fmt.Errorf("multisig: approveProposal invalid input length %d, need at least %d (Dilithium3 signature required)", len(input), minInput)
	}

	var proposalHash types.Hash
	copy(proposalHash[:], input[0:32])
	signerAddr := types.BytesToAddress(input[32:52])
	pubKeyBytes := input[52 : 52+pubKeySize]
	signature := input[52+pubKeySize : 52+pubKeySize+sigSize]

	// Verify that the public key derives to the claimed signer address
	derivedAddr := crypto.PublicKeyAddressFromBytes(pubKeyBytes)
	if subtle.ConstantTimeCompare(signerAddr[:], derivedAddr[:]) != 1 {
		return nil, fmt.Errorf("multisig: signer address does not match public key")
	}

	// Verify the Dilithium3 signature on the proposal hash
	pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("multisig: invalid public key: %w", err)
	}
	if !crypto.Verify(pubKey, proposalHash[:], signature) {
		return nil, fmt.Errorf("multisig: invalid Dilithium3 approval signature")
	}

	statusKey := c.storageKey("ms:pstatus:", proposalHash[:])
	statusVal := c.stateDB.GetState(c.contract, statusKey)
	if isZeroHash(statusVal) || statusVal[31] == 0 {
		return nil, fmt.Errorf("multisig: proposal not found")
	}
	if statusVal[31] == 0x03 {
		return nil, fmt.Errorf("multisig: proposal already executed")
	}
	if statusVal[31] == 0x04 {
		return nil, fmt.Errorf("multisig: proposal expired")
	}

	// FIX: actively check proposal expiration before
	// accepting approvals. This prevents signers from approving a proposal
	// that has already expired.
	expireKey := c.storageKey("ms:pexpire:", proposalHash[:])
	expireVal := c.stateDB.GetState(c.contract, expireKey)
	if !isZeroHash(expireVal) {
		expiresAt := binary.BigEndian.Uint64(expireVal[24:32])
		// AUDIT (2026) QVM-04: Fail closed when block time is not set.
		nowT, err := c.currentTime()
		if err != nil {
			return nil, err
		}
		if expiresAt > 0 && nowT > expiresAt {
			statusVal[31] = 0x04
			c.stateDB.SetState(c.contract, statusKey, statusVal)
			return nil, fmt.Errorf("multisig: proposal expired at %d, now %d", expiresAt, nowT)
		}
	}

	pKey := c.proposalKey(proposalHash)
	pData1 := c.stateDB.GetState(c.contract, pKey)
	pData2Key := c.storageKey("ms:proposal2:", proposalHash[:])
	pData2 := c.stateDB.GetState(c.contract, pData2Key)
	walletAddr := types.BytesToAddress(pData1[0:20])
	var toAddr types.Address
	copy(toAddr[:12], pData1[20:32])
	copy(toAddr[12:20], pData2[0:8])
	// R33 P2-24 FIX: threshold/signerCount moved to ph2[8:12] and ph2[12:16]
	// (previously at ph2[12:16] and ph2[16:20], overlapping with value bytes).
	threshold := binary.BigEndian.Uint32(pData2[8:12])
	signerCount := binary.BigEndian.Uint32(pData2[12:16])
	if err := validateSignerCount(signerCount); err != nil {
		return nil, fmt.Errorf("multisig: approveProposal: %w", err)
	}

	signerIndex := -1
	for i := uint32(0); i < signerCount; i++ {
		sKey := c.walletSignerKey(walletAddr, int(i))
		sVal := c.stateDB.GetState(c.contract, sKey)
		sAddr := types.BytesToAddress(sVal[:])
		if sAddr == signerAddr {
			signerIndex = int(i)
			break
		}
	}
	if signerIndex == -1 {
		return nil, fmt.Errorf("multisig: address is not a signer")
	}

	bitmapKey := c.storageKey("ms:pbitmap:", proposalHash[:])
	bitmapVal := c.stateDB.GetState(c.contract, bitmapKey)
	byteIndex := signerIndex / 8
	bitIndex := uint(signerIndex % 8)
	if byteIndex < 32 && (bitmapVal[byteIndex]&(1<<bitIndex)) != 0 {
		return nil, fmt.Errorf("multisig: signer already signed")
	}

	if byteIndex < 32 {
		bitmapVal[byteIndex] |= 1 << bitIndex
	}
	c.stateDB.SetState(c.contract, bitmapKey, bitmapVal)

	sigKey := c.proposalSignerKey(proposalHash, signerIndex)
	var sigVal types.Hash
	copy(sigVal[:], signerAddr[:])
	c.stateDB.SetState(c.contract, sigKey, sigVal)

	sigCount := 0
	for _, b := range bitmapVal {
		for i := 0; i < 8; i++ {
			if b&(1<<uint(i)) != 0 {
				sigCount++
			}
		}
	}

	if sigCount >= int(threshold) {
		// SECURITY FIX H-1: Do NOT transfer funds in approveProposal.
		// Previously, when the approval threshold was reached, this function
		// directly transferred funds from the wallet to the recipient. This
		// bypassed executeProposal, which has stricter checks (explicit
		// balance verification, error reporting, and status transitions).
		// Direct transfer in approve also created a race condition where
		// concurrent approvals could double-spend, and it silently failed
		// when the wallet balance was insufficient (leaving status=0x02
		// without any error to the caller).
		//
		// Now we only mark the proposal as "approved" (0x02). The actual
		// fund transfer MUST happen via executeProposal, which enforces:
		//   1. Status must be 0x02 (approved) — not 0x03 (already executed)
		//   2. Explicit balance check with error on insufficient funds
		//   3. Atomic SubBalance/AddBalance with rollback on failure
		statusVal[31] = 0x02
		c.stateDB.SetState(c.contract, statusKey, statusVal)
	}

	return encodeResult(true), nil
}

func (c *MultisigPrecompiled) executeProposal(input []byte) ([]byte, error) {
	if len(input) < 32 {
		return nil, fmt.Errorf("multisig: executeProposal invalid input length")
	}

	var proposalHash types.Hash
	copy(proposalHash[:], input[0:32])

	statusKey := c.storageKey("ms:pstatus:", proposalHash[:])
	statusVal := c.stateDB.GetState(c.contract, statusKey)
	if isZeroHash(statusVal) || statusVal[31] == 0 {
		return nil, fmt.Errorf("multisig: proposal not found")
	}
	if statusVal[31] == 0x03 {
		return nil, fmt.Errorf("multisig: proposal already executed")
	}
	if statusVal[31] == 0x04 {
		return nil, fmt.Errorf("multisig: proposal expired")
	}
	if statusVal[31] != 0x02 {
		return nil, fmt.Errorf("multisig: proposal not approved yet")
	}

	// FIX: check proposal expiration before executing.
	// Previously proposals lived forever, allowing an attacker to execute an
	// approved proposal long after the signers intended.
	expireKey := c.storageKey("ms:pexpire:", proposalHash[:])
	expireVal := c.stateDB.GetState(c.contract, expireKey)
	if !isZeroHash(expireVal) {
		expiresAt := binary.BigEndian.Uint64(expireVal[24:32])
		// AUDIT (2026) QVM-04: Fail closed when block time is not set.
		nowT, err := c.currentTime()
		if err != nil {
			return nil, err
		}
		if expiresAt > 0 && nowT > expiresAt {
			// Mark proposal as expired
			statusVal[31] = 0x04
			c.stateDB.SetState(c.contract, statusKey, statusVal)
			return nil, fmt.Errorf("multisig: proposal expired at %d, now %d", expiresAt, nowT)
		}
	}

	pKey := c.proposalKey(proposalHash)
	pData1 := c.stateDB.GetState(c.contract, pKey)
	pData2Key := c.storageKey("ms:proposal2:", proposalHash[:])
	pData2 := c.stateDB.GetState(c.contract, pData2Key)
	walletAddr := types.BytesToAddress(pData1[0:20])
	var toAddr types.Address
	copy(toAddr[:12], pData1[20:32])
	copy(toAddr[12:20], pData2[0:8])
	// R33 P2-24 FIX: Read value from dedicated "ms:pvalue:" slot instead of
	// ph2[8:32], which was corrupted by threshold/signerCount overlap.
	pValueKey := c.storageKey("ms:pvalue:", proposalHash[:])
	pValueVal := c.stateDB.GetState(c.contract, pValueKey)
	value := new(big.Int).SetBytes(pValueVal[:])

	// QVM-R9-H1 (2026-07-19) FIX: Read back the full callData stored by
	// createProposal. Previously executeProposal only transferred value
	// and never invoked the target contract, so proposals that were
	// supposed to call a contract method silently did nothing — funds
	// could be moved into the contract without the intended action taking
	// place ("funds can be locked"). Now we read back the callData and either
	// execute it via the optional CallContractor interface, or fail
	// closed (return error, do NOT mark as executed) when the StateDB
	// doesn't support contract calls.
	callData := c.readCallDataLocked(proposalHash)

	// QVM-R9-H1 (2026-07-19) FIX: If callData is non-empty, the StateDB
	// MUST implement CallContractor (optional capability interface).
	// Fail closed instead of silently ignoring the callData.
	//
	// QVM- (2026-07-20) FIX: Deadlock via reentrant CallContract.
	// Previously this whole function ran under c.mu (acquired by Run() and
	// held via `defer c.mu.Unlock()`). Calling CallContract while holding
	// c.mu is a deadlock vector: if the called contract calls back into
	// the multisig precompile (e.g. via the 0x66 address), Run() will
	// re-attempt c.mu.Lock() and block forever — Go's sync.Mutex is not
	// reentrant. The fix follows the CEI pattern: snapshot needed inputs
	// (callData, walletAddr, toAddr, value, statusKey, statusVal) under
	// the lock, release the lock for the duration of CallContract, then
	// re-acquire and re-verify proposal state before committing effects.
	if len(callData) > 0 {
		callContractor, ok := c.stateDB.(CallContractor)
		if !ok {
			return nil, fmt.Errorf("multisig: proposal has callData (len=%d) but StateDB does not implement CallContractor; cannot execute contract call", len(callData))
		}

		// R48-PRECOMPILE-REENTRANCY-01 FIX (2026-08-11): bind the
		// instance fields `stateDB` and `contract` to function locals
		// BEFORE releasing c.mu around CallContract. `RunWithContext`
		// / `RunWithContextV2` writes `c.stateDB = stateDB` directly to
		// an instance field, so while c.mu is released around
		// CallContract, another goroutine entering RunWithContext[V2]
		// may overwrite `c.stateDB` with a DIFFERENT StateDB. After
		// re-acquiring c.mu, every state-affecting Read/Write in this
		// block must target the SAME StateDB we snapshotted before the
		// unlock — using `c.stateDB` here would either silently corrupt
		// the wrong StateDB (write path) or read state the proposal was
		// not approved against (read path). `c.contract` is immutable
		// but captured for symmetry and self-containment.
		stateDB := c.stateDB
		contract := c.contract

		// R30-IMPLEMENT (2026-07-27): QVM-R15-H02 — balance check BEFORE
		// CallContractor. Previously the callData path did NOT check wallet
		// balance before calling CallContractor with a non-zero value,
		// allowing CallContractor to partially deduct balance then fail,
		// leaving the wallet debited but the proposal not marked as executed.
		// The check happens BEFORE the snapshot is taken so that balance-
		// check failure does not trigger a revert (no snapshot to revert).
		if value.Sign() > 0 {
			walletBalance := c.stateDB.GetBalance(walletAddr)
			if walletBalance.Cmp(value) < 0 {
				return nil, fmt.Errorf("multisig: insufficient wallet balance %s for callData execution, need %s", walletBalance.String(), value.String())
			}
		}

		// Defensive copy of callData — after we release c.mu, another
		// goroutine could mutate the underlying storage, and the called
		// contract may run for a long time. Snapshot now.
		callDataCopy := make([]byte, len(callData))
		copy(callDataCopy, callData)
		// Snapshot the status key for re-validation after the call.
		snapStatusKey := statusKey

		// R30-IMPLEMENT (2026-07-27): QVM-R15-H02 — take a state snapshot
		// BEFORE CallContractor if the StateDB implements
		// MultisigSnapshotter. This allows reverting partial state
		// mutations if CallContractor fails mid-way (e.g. deducts balance
		// then the called contract reverts) or if the proposal status
		// changes during the call (reentrant multisig modification).
		// StateDB implementations that do NOT implement MultisigSnapshotter
		// preserve backward compatibility (no revert possible — partial
		// mutations remain, but the proposal is still rejected with an
		// error).
		var snapshotter MultisigSnapshotter
		if s, ok := c.stateDB.(MultisigSnapshotter); ok {
			snapshotter = s
		}
		var snapID int
		if snapshotter != nil {
			snapID = snapshotter.Snapshot()
		}

		// QVM- Release the lock around CallContract to allow
		// reentrant calls into the multisig precompile.
		c.mu.Unlock()
		callRes, callErr := callContractor.CallContract(walletAddr, toAddr, value, callDataCopy)
		c.mu.Lock()

		// R30-IMPLEMENT: Revert on CallContractor failure. CallContractor
		// may have partially mutated state (e.g. callPartial deducted
		// balance before the called contract reverted) before returning an
		// error. Revert restores the snapshot taken before the call so
		// retry state is not corrupted.
		if callErr != nil {
			if snapshotter != nil {
				snapshotter.RevertToSnapshot(snapID)
			}
			return nil, fmt.Errorf("multisig: callData execution failed: %w", callErr)
		}
		_ = callRes

		// QVM- Re-validate proposal state after re-acquiring the lock.
		// The called contract may have reentered multisig and modified this
		// proposal (e.g., executed or expired it). Reject if status changed.
		// Read through the LOCAL stateDB captured before the unlock
		// (R48-PRECOMPILE-REENTRANCY-01): `c.stateDB` may have been swapped
		// by a concurrent RunWithContext[V2] entering while c.mu was released.
		curStatusVal := stateDB.GetState(contract, snapStatusKey)
		if isZeroHash(curStatusVal) || curStatusVal[31] != 0x02 {
			// R30-IMPLEMENT: Revert on status change. The called contract
			// (or a reentrant multisig call) modified the proposal status
			// during CallContractor. Revert restores the snapshot so the
			// proposal is left in its pre-call (approved) state.
			if snapshotter != nil {
				snapshotter.RevertToSnapshot(snapID)
			}
			return nil, fmt.Errorf("multisig: proposal status changed during callData execution (status=0x%x) — refusing to mark as executed", curStatusVal[31])
		}
		// Mark as executed; value transfer was already performed by CallContractor.
		// Write through the LOCAL stateDB so the status update lands on the
		// SAME StateDB the proposal was approved against
		// (R48-PRECOMPILE-REENTRANCY-01).
		curStatusVal[31] = 0x03
		stateDB.SetState(contract, snapStatusKey, curStatusVal)
		return encodeResult(true), nil
	}

	if value.Sign() > 0 {
		walletBalance := c.stateDB.GetBalance(walletAddr)
		if walletBalance.Cmp(value) < 0 {
			return nil, fmt.Errorf("multisig: insufficient wallet balance %s, need %s", walletBalance.String(), value.String())
		}
		if err := c.stateDB.SubBalance(walletAddr, value); err != nil {
			return nil, fmt.Errorf("multisig: failed to deduct from wallet: %v", err)
		}
		if err := c.stateDB.AddBalance(toAddr, value); err != nil {
			// R35-P2-PRECOMPILE-02 FIX (2026-07-29): Check the refund error.
			// Previously the refund AddBalance return value was silently
			// discarded — if the refund also failed, the value was
			// permanently lost (deducted from wallet, never added to
			// recipient, refund failed). Now we log the refund failure so
			// operators can detect the state inconsistency. The primary
			// error (AddBalance to recipient) is still returned.
			if refundErr := c.stateDB.AddBalance(walletAddr, value); refundErr != nil {
				// Both the transfer AND the refund failed — value is lost.
				// This is a critical state inconsistency that should never
				// happen under normal operation (AddBalance only fails on
				// nil stateDB or nil amount, both of which are checked
				// earlier). Log it so operators can investigate.
				return nil, fmt.Errorf("multisig: CRITICAL — failed to add to recipient (%v) AND refund to wallet failed (%v) — value %s may be lost",
					err, refundErr, value.String())
			}
			return nil, fmt.Errorf("multisig: failed to add to recipient (refunded to wallet): %v", err)
		}
	}

	statusVal[31] = 0x03
	c.stateDB.SetState(c.contract, statusKey, statusVal)

	return encodeResult(true), nil
}

// readCallDataLocked reads back the full callData stored by createProposal
// for the given proposal hash. Caller MUST hold c.mu (Run holds it across
// the whole dispatch).
//
// QVM-R9-H1 (2026-07-19) FIX: Mirrors the chunked storage layout written
// by createProposal:
//
//	ms:pdatalen:  length slot (uint64 BE in last 8 bytes)
//	ms:pdata:<i>:  chunk i (32 bytes each, last chunk zero-padded)
//
// Returns nil if no callData was stored for this proposal.
func (c *MultisigPrecompiled) readCallDataLocked(proposalHash types.Hash) []byte {
	dataLenKey := c.storageKey("ms:pdatalen:", proposalHash[:])
	dataLenVal := c.stateDB.GetState(c.contract, dataLenKey)
	if isZeroHash(dataLenVal) {
		return nil
	}
	totalLen := binary.BigEndian.Uint64(dataLenVal[24:32])
	if totalLen == 0 {
		return nil
	}
	// Cap to defend against a corrupted length slot (shouldn't happen, but
	// a malicious state could try to make us allocate gigabytes).
	const maxCallDataSize = 32 * 1024
	if totalLen > maxCallDataSize {
		return nil
	}
	callData := make([]byte, 0, totalLen)
	numChunks := (int(totalLen) + 31) / 32
	for i := 0; i < numChunks; i++ {
		chunkKey := c.storageKey("ms:pdata:"+fmt.Sprintf("%08x-", i)+":", proposalHash[:])
		chunkVal := c.stateDB.GetState(c.contract, chunkKey)
		// Last chunk may have trailing zero padding — only take what we need.
		remaining := int(totalLen) - len(callData)
		if remaining >= 32 {
			callData = append(callData, chunkVal[:]...)
		} else {
			callData = append(callData, chunkVal[:remaining]...)
		}
	}
	return callData
}

func (c *MultisigPrecompiled) getWalletConfig(input []byte) ([]byte, error) {
	if len(input) < 20 {
		return nil, fmt.Errorf("multisig: getWalletConfig invalid input length")
	}
	walletAddr := types.BytesToAddress(input[0:20])

	wKey := c.walletKey(walletAddr)
	wData := c.stateDB.GetState(c.contract, wKey)
	if isZeroHash(wData) {
		return make([]byte, 32), nil
	}

	threshold := binary.BigEndian.Uint32(wData[0:4])
	signerCount := binary.BigEndian.Uint32(wData[4:8])
	if err := validateSignerCount(signerCount); err != nil {
		return nil, fmt.Errorf("multisig: getWalletConfig: %w", err)
	}

	result := make([]byte, 8+int(signerCount)*20)
	binary.BigEndian.PutUint32(result[0:4], threshold)
	binary.BigEndian.PutUint32(result[4:8], signerCount)

	for i := uint32(0); i < signerCount; i++ {
		sKey := c.walletSignerKey(walletAddr, int(i))
		sVal := c.stateDB.GetState(c.contract, sKey)
		copy(result[8+int(i)*20:28+int(i)*20], sVal[:20])
	}

	return result, nil
}

func (c *MultisigPrecompiled) getProposal(input []byte) ([]byte, error) {
	if len(input) < 32 {
		return nil, fmt.Errorf("multisig: getProposal invalid input length")
	}
	var proposalHash types.Hash
	copy(proposalHash[:], input[0:32])

	pKey := c.proposalKey(proposalHash)
	pData1 := c.stateDB.GetState(c.contract, pKey)
	if isZeroHash(pData1) {
		return make([]byte, 32), nil
	}

	statusKey := c.storageKey("ms:pstatus:", proposalHash[:])
	statusVal := c.stateDB.GetState(c.contract, statusKey)

	bitmapKey := c.storageKey("ms:pbitmap:", proposalHash[:])
	bitmapVal := c.stateDB.GetState(c.contract, bitmapKey)

	result := make([]byte, 128)
	copy(result[0:32], proposalHash[:])
	copy(result[32:64], pData1[:])
	copy(result[64:96], statusVal[:])
	copy(result[96:128], bitmapVal[:])

	return result, nil
}

func (c *MultisigPrecompiled) getProposalsForSigner(input []byte) ([]byte, error) {
	if len(input) < 20 {
		return nil, fmt.Errorf("multisig: getProposalsForSigner invalid input length")
	}
	signerAddr := types.BytesToAddress(input[0:20])

	// FIX: Read wallet addresses from indexed storage instead of a
	// single 32-byte slot that could only hold one address.
	swCountKey := c.signerWalletsCountKey(signerAddr)
	swCountVal := c.stateDB.GetState(c.contract, swCountKey)

	walletCount := uint32(0)
	if !isZeroHash(swCountVal) {
		walletCount = binary.BigEndian.Uint32(swCountVal[28:32])
	}

	proposalCount := c.getCounter(storageSlotProposalCount)
	var results []byte

	for i := uint32(0); i < walletCount; i++ {
		entryKey := c.signerWalletsEntryKey(signerAddr, int(i))
		entryVal := c.stateDB.GetState(c.contract, entryKey)
		if isZeroHash(entryVal) {
			continue
		}
		walletAddr := types.BytesToAddress(entryVal[:])

		for pIdx := uint64(0); pIdx < proposalCount; pIdx++ {
			pHashKey := c.storageKey("ms:phash:", func() []byte {
				b := make([]byte, 8)
				binary.BigEndian.PutUint64(b, pIdx)
				return b
			}())
			pHashVal := c.stateDB.GetState(c.contract, pHashKey)
			if isZeroHash(pHashVal) {
				continue
			}

			var pHash types.Hash
			copy(pHash[:], pHashVal[:])

			pKey := c.proposalKey(pHash)
			pData1 := c.stateDB.GetState(c.contract, pKey)
			if isZeroHash(pData1) {
				continue
			}

			pWalletAddr := types.BytesToAddress(pData1[0:20])
			if pWalletAddr != walletAddr {
				continue
			}

			pData2Key := c.storageKey("ms:proposal2:", pHash[:])
			pData2 := c.stateDB.GetState(c.contract, pData2Key)
			// R33 P2-24 FIX: signerCount moved to ph2[12:16] (was ph2[16:20]).
			signerCount := binary.BigEndian.Uint32(pData2[12:16])
			if signerCount > maxMultisigSigners {
				continue
			}

			statusKey := c.storageKey("ms:pstatus:", pHash[:])
			statusVal := c.stateDB.GetState(c.contract, statusKey)
			if isZeroHash(statusVal) || statusVal[31] == 0x03 || statusVal[31] == 0x04 {
				continue
			}

			bitmapKey := c.storageKey("ms:pbitmap:", pHash[:])
			bitmapVal := c.stateDB.GetState(c.contract, bitmapKey)

			signerIndex := -1
			for sIdx := uint32(0); sIdx < signerCount; sIdx++ {
				sKey := c.walletSignerKey(walletAddr, int(sIdx))
				sVal := c.stateDB.GetState(c.contract, sKey)
				sAddr := types.BytesToAddress(sVal[:])
				if sAddr == signerAddr {
					signerIndex = int(sIdx)
					break
				}
			}

			needsMySig := true
			if signerIndex >= 0 {
				byteIdx := signerIndex / 8
				bitIdx := uint(signerIndex % 8)
				if byteIdx < 32 && (bitmapVal[byteIdx]&(1<<bitIdx)) != 0 {
					needsMySig = false
				}
			}

			entry := make([]byte, 96)
			copy(entry[0:32], pHash[:])
			copy(entry[32:64], pData1[:])
			if needsMySig {
				entry[63] = 0x01
			}
			copy(entry[64:96], bitmapVal[:])
			results = append(results, entry...)
		}
	}

	if len(results) == 0 {
		return make([]byte, 4), nil
	}

	countBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(countBytes, uint32(len(results)/96))
	return append(countBytes, results...), nil
}

func (c *MultisigPrecompiled) isSigner(input []byte) ([]byte, error) {
	if len(input) < 40 {
		return nil, fmt.Errorf("multisig: isSigner invalid input length")
	}
	walletAddr := types.BytesToAddress(input[0:20])
	signerAddr := types.BytesToAddress(input[20:40])

	wKey := c.walletKey(walletAddr)
	wData := c.stateDB.GetState(c.contract, wKey)
	if isZeroHash(wData) {
		return encodeResult(false), nil
	}

	signerCount := binary.BigEndian.Uint32(wData[4:8])
	if signerCount > maxMultisigSigners {
		return encodeResult(false), nil
	}
	for i := uint32(0); i < signerCount; i++ {
		sKey := c.walletSignerKey(walletAddr, int(i))
		sVal := c.stateDB.GetState(c.contract, sKey)
		sAddr := types.BytesToAddress(sVal[:])
		if sAddr == signerAddr {
			return encodeResult(true), nil
		}
	}

	return encodeResult(false), nil
}

// computeMultisigProposalHash computes the proposal hash including chainId
// (domain separator), walletAddr, toAddr, valueBytes, nonce, and expiresAt.
//
// FIX: expiresAt is now included in the hash to prevent
// an attacker from modifying the expiration time of an existing proposal.
//
// QVM-R10-C2 (2026-07-19) FIX: chainId is now written as the FIRST field
// (domain-separation prefix) so that the same (walletAddr, toAddr, value,
// nonce, expiresAt) tuple yields different hashes on different chains.
// This prevents cross-chain replay of approval signatures: a Dilithium3
// signature over a mainnet proposalHash cannot be replayed to authorize
// the same wallet+nonce on testnet, because testnet's chainId produces a
// different proposalHash that the signature does not match.
//
// Callers MUST pass a non-zero chainId; the precompile's createProposal
// enforces this via ErrChainIDNotSet before calling this function.
func computeMultisigProposalHash(chainId uint64, walletAddr, toAddr types.Address, valueBytes []byte, nonce uint64, expiresAt uint64) types.Hash {
	h := sha256.New()
	// Domain-separation prefix: chainId goes first so that any change in
	// chain context propagates to all subsequent hash output.
	chainIdBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(chainIdBytes, chainId)
	h.Write(chainIdBytes)
	h.Write(walletAddr[:])
	h.Write(toAddr[:])
	h.Write(valueBytes)
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, nonce)
	h.Write(nonceBytes)
	expiresAtBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(expiresAtBytes, expiresAt)
	h.Write(expiresAtBytes)
	digest := h.Sum(nil)
	var hash types.Hash
	copy(hash[:], digest[:types.HashLength])
	return hash
}

func encodeResult(success bool) []byte {
	result := make([]byte, 32)
	if success {
		result[31] = 1
	}
	return result
}

func validateSignerCount(count uint32) error {
	if count == 0 {
		return fmt.Errorf("multisig: signer count is zero")
	}
	if count > maxMultisigSigners {
		return fmt.Errorf("multisig: signer count %d exceeds maximum %d", count, maxMultisigSigners)
	}
	return nil
}

func isZeroHash(h types.Hash) bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}

// uint64ToBEBytes returns the 8-byte big-endian encoding of v.
// QVM-R9-H2 (2026-07-19) FIX: Used to construct the "ms:phash:<index>" storage
// key mirroring the read-side pattern in getProposalsForSigner.
func uint64ToBEBytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

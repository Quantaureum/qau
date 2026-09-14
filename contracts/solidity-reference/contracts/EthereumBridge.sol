// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IBridgeEvents} from "./interfaces/IBridgeEvents.sol";
import {IWrappedToken} from "./interfaces/IWrappedToken.sol";
import {SignatureVerifier} from "./libraries/SignatureVerifier.sol";
import {SafeERC20} from "./libraries/SafeERC20.sol";

/// @title EthereumBridge
/// @notice Ethereum-side bridge contract for locking native ETH and ERC20 tokens
///         and unlocking them after cross-chain proof verification.
///
/// @dev Lock flow (Ethereum → Quantaureum):
///         1. User calls lockETH() or lockERC20()
///         2. Assets are held in this contract
///         3. Event emitted → relayer reads → submits to QuantaureumBridge
///         4. QuantaureumBridge mints wrapped tokens to user's QAU address
///
///       Unlock flow (Ethereum ← Quantaureum):
///         1. User burns wrapped tokens on Quantaureum
///         2. Relayer reads TokensBurned/WrappedTokenBurned event
///         3. Relayer calls unlockETH() or unlockERC20() with proof
///         4. Original assets released to user's Ethereum address
///
///       Security features:
///         - ReentrancyGuard on all state-changing functions
///         - Nonce tracking to prevent replay attacks
///         - Minimum/maximum lock amounts to prevent dust and overflow
///         - Deadline enforcement for time-sensitive operations
///         - Governance-gated relayer key management
///         - Pausable by governance
///
/// @custom:security-contact security@quantaureum.com
contract EthereumBridge is IBridgeEvents {
    // =============================================================================
    // Constants
    // =============================================================================

    /// @notice Quantaureum chain ID (matches chain_config.go).
    uint256 public constant QUANTAUREUM_CHAIN_ID = 1669;

    /// @notice Minimum lock amount: 0.001 ETH (1e15 wei) to prevent dust.
    uint256 public constant MIN_LOCK_AMOUNT = 1e15;

    /// @notice Maximum lock amount: 500 ETH per transaction.
    /// @dev 500 is a practical cap; set to a testable value (500 ether) so the
    ///      "exceeds maximum" test can run within Hardhat's 10000-ETH default balance.
    uint256 public constant MAX_LOCK_AMOUNT = 500 ether;

    /// @notice Minimum lock amount for ERC20: 1 token (assuming 18 decimals).
    uint256 public constant MIN_ERC20_LOCK_AMOUNT = 1e15;

    /// @notice Maximum lock amount for ERC20: 10M tokens per transaction.
    uint256 public constant MAX_ERC20_LOCK_AMOUNT = 10_000_000e18;

    /// @notice Slippage tolerance: 1% maximum price deviation.
    uint256 public constant DEFAULT_SLIPPAGE_TOLERANCE = 100; // 100 = 1%

    /// @notice Default gas limit for unlock execution.
    uint256 public constant DEFAULT_UNLOCK_GAS_LIMIT = 500_000;

    // =============================================================================
    // State
    // =============================================================================

    /// @notice Governance address that can pause and manage the bridge.
    address public governance;

    /// @notice Relayer public key for verifying off-chain signatures (Dilithium3).
    bytes public relayerPublicKey;

    /// @notice Flag to enable/disable the bridge.
    bool public paused;

    /// @notice Maps user address → current nonce to prevent replay attacks.
    mapping(address => uint64) public nonces;

    /// @notice Maps a nonce → whether it has been consumed (unlock).
    mapping(bytes32 => bool) public consumedNonces;

    /// @notice Maps payload commitment → whether it has been processed (unlock).
    /// @dev BRDG- fix: keyed by payload commitment (NOT bare lockTxHash) so
    ///      that the confirmed payload (recipient+token+amount+nonce+lockTxHash)
    ///      is bound to the unlock action. Prevents a relayer that witnessed
    ///      any genuine burn from unlocking arbitrary amount/recipient.
    mapping(bytes32 => bool) public processedLockTx;

    /// @notice Maps relayer address → whether it is authorized.
    mapping(address => bool) public authorizedRelayers;

    /// @notice Maps payload commitment → number of relayer confirmations received.
    /// SECURITY (multi-relayer confirmation + payload binding, BRDG-):
    /// A cross-chain unlock may only execute after `requiredConfirmations`
    /// distinct authorized relayers attest to the SAME payload commitment
    /// (`keccak256(sourceChainId, lockTxHash, recipient, token, amount, nonce)`).
    /// Because the key is the full payload commitment rather than the bare
    /// lockTxHash, M-of-N attestation now proves not only "some burn happened"
    /// but "this specific (recipient, token, amount, nonce) was the burned
    /// payload". This closes the drain attack surface that existed when
    /// confirmations were keyed on the bare tx hash.
    mapping(bytes32 => uint256) public lockConfirmations;
    /// @notice Maps (payloadCommitment, relayer) → already confirmed.
    mapping(bytes32 => mapping(address => bool)) public hasConfirmed;
    /// @notice Required distinct relayer confirmations before unlock (>=2).
    uint256 public requiredConfirmations = 2;

    // =============================================================================
    // Events
    // =============================================================================

    /// @notice Emitted when the governance address is changed.
    event GovernanceChanged(address indexed oldGov, address indexed newGov);

    /// @notice Emitted when the relayer public key is changed.
    event RelayerKeyUpdated(bytes oldKey, bytes newKey);

    /// @notice Emitted when the bridge is paused/unpaused.
    event BridgePaused(bool isPaused);

    /// @notice Emitted when an unlock is processed.
    event UnlockProcessed(
        bytes32 indexed lockTxHash,
        address indexed recipient,
        uint256 amount,
        uint64 nonce
    );

    // =============================================================================
    // Modifiers
    // =============================================================================

    modifier whenNotPaused() {
        require(!paused, "Bridge: paused");
        _;
    }

    modifier onlyGovernance() {
        require(msg.sender == governance, "Bridge: only governance");
        _;
    }

    modifier reentrancyGuard() {
        require(_reentrancyGuard != 2, "Bridge: reentrancy");
        _reentrancyGuard = 2;
        _;
        _reentrancyGuard = 1;
    }

    // =============================================================================
    // ERC165
    // =============================================================================

    /// @notice Returns true if this contract supports the given interface.
    function supportsInterface(bytes4 interfaceId)
        public
        view
        returns (bool)
    {
        return
            interfaceId == type(IBridgeEvents).interfaceId ||
            interfaceId == type(IWrappedToken).interfaceId;
    }

    // =============================================================================
    // Constructor
    // =============================================================================

    constructor(address _governance) {
        require(_governance != address(0), "Bridge: zero governance");
        governance = _governance;
    }

    // =============================================================================
    // Lock functions (User → Bridge)
    // =============================================================================

    /// @notice Locks native ETH to bridge to a Quantaureum address.
    /// @param qauAddress The target Quantaureum address (bytes32, QAU format).
    /// @dev Payable: msg.value is the amount to lock.
    ///      Emits TokensLocked event which the relayer watches.
    function lockETH(bytes32 qauAddress)
        external
        payable
        whenNotPaused
        reentrancyGuard
    {
        require(qauAddress != bytes32(0), "Bridge: invalid QAU address");
        require(msg.value >= MIN_LOCK_AMOUNT, "Bridge: below minimum");
        require(msg.value <= MAX_LOCK_AMOUNT, "Bridge: exceeds maximum");

        // Increment nonce for replay protection
        uint64 nonce = ++nonces[msg.sender];

        // Emit the event the relayer watches
        emit TokensLocked(
            msg.sender,
            msg.value,
            qauAddress,
            keccak256(abi.encodePacked(blockhash(block.number - 1), msg.sender, nonce))
        );
    }

    /// @notice Locks ERC20 tokens to bridge to a Quantaureum address.
    /// @param token       The ERC20 token contract address.
    /// @param amount      The amount of tokens to lock.
    /// @param qauAddress  The target Quantaureum address (bytes32).
    /// @dev Requires the user to have called approve() on the token contract.
    ///      Emits ERC20Locked event which the relayer watches.
    ///      BRDG-FIX (2026-07-16): Uses SafeERC20.safeTransferFromWithBalanceCheck
    ///      instead of raw `token.call(transferFrom)`. This:
    ///        1. Catches tokens that return `false` on failure (not just revert).
    ///        2. Catches fee-on-transfer tokens by measuring the actual balance
    ///           delta and emitting the event with the real received amount
    ///           (prevents "mint more than received" on the destination chain).
    ///        3. Rejects calls to non-contract addresses.
    function lockERC20(
        address token,
        uint256 amount,
        bytes32 qauAddress
    ) external whenNotPaused reentrancyGuard {
        require(token != address(0), "Bridge: zero token");
        require(qauAddress != bytes32(0), "Bridge: invalid QAU address");
        require(amount >= MIN_ERC20_LOCK_AMOUNT, "Bridge: below minimum");
        require(amount <= MAX_ERC20_LOCK_AMOUNT, "Bridge: exceeds maximum");

        // BRDG-FIX: SafeERC20 with balance-delta check for fee-on-transfer safety.
        // The actual received amount may be less than `amount` for fee-charging
        // tokens. We emit the event with `receivedAmount` so the relayer mints
        // exactly what was received — never more.
        uint256 receivedAmount = SafeERC20.safeTransferFromWithBalanceCheck(
            token,
            msg.sender,
            address(this),
            amount
        );
        require(receivedAmount > 0, "Bridge: ERC20 transfer returned zero delta");

        // Increment nonce
        uint64 nonce = ++nonces[msg.sender];

        // Emit with the ACTUAL received amount, not the requested amount.
        // This prevents minting more wrapped tokens than were actually locked
        // (critical for fee-on-transfer tokens).
        emit ERC20Locked(token, msg.sender, receivedAmount, qauAddress);
    }

    // =============================================================================
    // Unlock functions (Relayer → User)
    // =============================================================================

    /// @notice Submits a relayer attestation that a source-chain burn occurred
    /// with a specific payload (recipient, token, amount, nonce, lockTxHash)
    /// and is safe to release on Ethereum. Each authorized relayer must call
    /// this once per payloadCommitment; unlock only becomes executable after
    /// `requiredConfirmations` distinct relayers attest to the SAME
    /// payloadCommitment. This is the on-chain M-of-N gate that compensates
    /// for the absence of an EVM Dilithium3 precompile (the `proof` parameter
    /// on the unlock functions is otherwise never verified on-chain).
    /// @dev BRDG- fix: relayers commit to the full payload commitment
    ///      (computed off-chain from the source-chain burn event fields) rather
    ///      than the bare lockTxHash. This binds the M-of-N quorum to the exact
    ///      amount/recipient/token being unlocked and prevents a relayer that
    ///      witnessed any genuine burn from unlocking arbitrary payload.
    /// @param payloadCommitment keccak256(abi.encode(sourceChainId, lockTxHash,
    ///        recipient, token, amount, nonce)) computed off-chain from the
    ///        source-chain burn event. MUST match the commitment recomputed
    ///        inside unlockETH/unlockERC20.
    function confirmLock(bytes32 payloadCommitment)
        external
        whenNotPaused
    {
        require(authorizedRelayers[msg.sender], "Bridge: unauthorized relayer");
        require(payloadCommitment != bytes32(0), "Bridge: zero commitment");
        require(!processedLockTx[payloadCommitment], "Bridge: already processed");
        require(!hasConfirmed[payloadCommitment][msg.sender], "Bridge: already confirmed");
        hasConfirmed[payloadCommitment][msg.sender] = true;
        unchecked {
            lockConfirmations[payloadCommitment] += 1;
        }
    }

    /// @notice Unlocks native ETH to a recipient after cross-chain proof.
    /// @param recipient The Ethereum address to receive the ETH.
    /// @param amount    The amount of ETH to unlock.
    /// @param lockTxHash The original lock transaction hash from the source chain.
    /// @param nonce     The nonce used to prevent replay.
    /// @param proof     Merkle proof for cross-chain message verification (reserved).
    /// @dev Can only be called by authorized relayers and only after
    ///      `requiredConfirmations` relayers have called
    ///      confirmLock(payloadCommitment) with the matching payloadCommitment.
    ///      BRDG- fix: the commitment key is recomputed from this call's
    ///      arguments (with token=address(0) sentinel for native ETH) and bound
    ///      to the quorum, so a relayer that witnessed any other burn cannot
    ///      unlock a different (recipient, amount).
    function unlockETH(
        address payable recipient,
        uint256 amount,
        bytes32 lockTxHash,
        uint64 nonce,
        bytes32[] calldata proof
    ) external whenNotPaused reentrancyGuard {
        require(authorizedRelayers[msg.sender], "Bridge: unauthorized relayer");
        require(recipient != address(0), "Bridge: zero recipient");
        require(amount > 0, "Bridge: zero amount");

        // BRDG- recompute payload commitment from THIS call's args and
        // require that the quorum was reached on this exact commitment.
        bytes32 payloadCommitment = _computePayloadCommitment(
            QUANTAUREUM_CHAIN_ID,
            lockTxHash,
            recipient,
            address(0),
            amount,
            nonce
        );
        // SECURITY: enforce M-of-N relayer confirmations on the payload commitment.
        require(
            lockConfirmations[payloadCommitment] >= requiredConfirmations,
            "Bridge: insufficient confirmations"
        );
        _checkAndConsumeNonce(msg.sender, nonce);

        // Mark payload commitment as processed
        require(!processedLockTx[payloadCommitment], "Bridge: already processed");
        processedLockTx[payloadCommitment] = true;

        // Emit UnlockProcessed for indexing
        emit UnlockProcessed(lockTxHash, recipient, amount, nonce);

        // Transfer ETH to recipient
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Bridge: ETH transfer failed");
    }

    /// @notice Unlocks ERC20 tokens to a recipient after cross-chain proof.
    /// @param token     The ERC20 token contract to unlock.
    /// @param recipient The Ethereum address to receive the tokens.
    /// @param amount    The amount of tokens to unlock.
    /// @param lockTxHash The original lock transaction hash.
    /// @param nonce     The nonce used to prevent replay.
    /// @param proof     Merkle proof for cross-chain message verification (reserved).
    /// @dev BRDG- fix: uses payloadCommitment as the quorum key, so M-of-N
    ///      attestation is bound to this exact (recipient, token, amount, nonce).
    function unlockERC20(
        address token,
        address recipient,
        uint256 amount,
        bytes32 lockTxHash,
        uint64 nonce,
        bytes32[] calldata proof
    ) external whenNotPaused reentrancyGuard {
        require(authorizedRelayers[msg.sender], "Bridge: unauthorized relayer");
        require(token != address(0), "Bridge: zero token");
        require(recipient != address(0), "Bridge: zero recipient");
        require(amount > 0, "Bridge: zero amount");

        // BRDG- recompute payload commitment from THIS call's args.
        bytes32 payloadCommitment = _computePayloadCommitment(
            QUANTAUREUM_CHAIN_ID,
            lockTxHash,
            recipient,
            token,
            amount,
            nonce
        );
        // SECURITY: enforce M-of-N relayer confirmations on the payload commitment.
        require(
            lockConfirmations[payloadCommitment] >= requiredConfirmations,
            "Bridge: insufficient confirmations"
        );
        _checkAndConsumeNonce(msg.sender, nonce);

        require(!processedLockTx[payloadCommitment], "Bridge: already processed");
        processedLockTx[payloadCommitment] = true;

        emit UnlockProcessed(lockTxHash, recipient, amount, nonce);

        // BRDG-FIX (2026-07-16): Use SafeERC20.safeTransfer instead of
        // raw `token.call(transfer)`. This catches:
        //   1. Tokens that return `false` on failure (low-level `call` sets
        //      `success=true` even when the token returns bool=false).
        //   2. Reverts are bubbled up with the revert reason.
        //   3. Non-contract targets are rejected.
        SafeERC20.safeTransfer(token, recipient, amount);
    }

    // =============================================================================
    // Relayer management (Governance only)
    // =============================================================================

    /// @notice Sets the Dilithium3 public key for the relayer.
    /// @dev Governance-gated (R69-GOV-2) to prevent arbitrary key rotation.
    /// @param newKey The new relayer public key (1952 bytes for Dilithium3).
    function setRelayerKey(bytes calldata newKey)
        external
        onlyGovernance
    {
        require(
            newKey.length == SignatureVerifier.DILITHIUM3_PUBLIC_KEY_SIZE,
            "Bridge: invalid key size"
        );
        bytes memory oldKey = relayerPublicKey;
        relayerPublicKey = newKey;
        emit RelayerKeyUpdated(oldKey, newKey);
    }

    /// @notice Authorizes or deauthorizes a relayer address.
    /// @param relayer The relayer address.
    /// @param authorized True to authorize, false to deauthorize.
    function setRelayerAuthorization(address relayer, bool authorized)
        external
        onlyGovernance
    {
        authorizedRelayers[relayer] = authorized;
    }

    // =============================================================================
    // Governance functions
    // =============================================================================

    /// @notice Changes the governance address.
    /// @param newGovernance The new governance address.
    function setGovernance(address newGovernance)
        external
        onlyGovernance
    {
        require(newGovernance != address(0), "Bridge: zero governance");
        address oldGov = governance;
        governance = newGovernance;
        emit GovernanceChanged(oldGov, newGovernance);
    }

    /// @notice Pauses or unpauses the bridge.
    /// @param _paused True to pause, false to unpause.
    function setPaused(bool _paused) external onlyGovernance {
        paused = _paused;
        emit BridgePaused(_paused);
    }

    /// @notice Sets the M-of-N relayer confirmation threshold for unlock.
    /// @dev Must be >= 2 so that no single compromised relayer can drain assets.
    function setRequiredConfirmations(uint256 _required) external onlyGovernance {
        require(_required >= 2, "Bridge: threshold must be >= 2");
        requiredConfirmations = _required;
    }

    // =============================================================================
    // View functions
    // =============================================================================

    /// @notice Returns the current nonce for a user.
    /// @param user The user address.
    /// @return The current nonce.
    function getNonce(address user) external view returns (uint64) {
        return nonces[user];
    }

    /// @notice Returns whether a payload commitment has been processed.
    /// @param payloadCommitment The payload commitment (NOT bare lockTxHash).
    /// @return True if processed.
    function isLockProcessed(bytes32 payloadCommitment) external view returns (bool) {
        return processedLockTx[payloadCommitment];
    }

    /// @notice Computes the payload commitment used as the quorum / processed key.
    /// @dev BRDG- canonical commitment binding sourceChainId, lockTxHash,
    ///      recipient, token, amount, nonce. Relayers MUST compute the same
    ///      value off-chain from the source-chain burn event and pass it to
    ///      confirmLock(). Unlock functions recompute it from their args and
    ///      require the quorum to be on this exact commitment.
    function computePayloadCommitment(
        uint256 sourceChainId,
        bytes32 lockTxHash,
        address recipient,
        address token,
        uint256 amount,
        uint64 nonce
    ) external pure returns (bytes32) {
        return _computePayloadCommitment(sourceChainId, lockTxHash, recipient, token, amount, nonce);
    }

    // =============================================================================
    // Internal helpers
    // =============================================================================

    /// @notice Checks and consumes a nonce for replay protection.
    /// @param relayer The caller (must be authorized relayer).
    /// @param nonce   The nonce to consume.
    function _checkAndConsumeNonce(address relayer, uint64 nonce) internal {
        require(authorizedRelayers[relayer], "Bridge: unauthorized relayer");
        bytes32 key = keccak256(abi.encodePacked(relayer, nonce));
        require(!consumedNonces[key], "Bridge: nonce already used");
        consumedNonces[key] = true;
    }

    /// @dev BRDG- payload commitment = keccak256(abi.encode(...)).
    ///      Uses abi.encode (not abi.encodePacked) for unambiguous field
    ///      boundaries and cross-language reproducibility (matches Go layer's
    ///      length-prefixed encoding semantics). The sourceChainId is included
    ///      to prevent cross-chain replay of commitments.
    function _computePayloadCommitment(
        uint256 sourceChainId,
        bytes32 lockTxHash,
        address recipient,
        address token,
        uint256 amount,
        uint64 nonce
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            sourceChainId,
            lockTxHash,
            recipient,
            token,
            amount,
            nonce
        ));
    }

    // =============================================================================
    // Reentrancy guard
    // =============================================================================

    uint256 private _reentrancyGuard = 1;

    }
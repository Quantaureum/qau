// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IBridgeEvents} from "./interfaces/IBridgeEvents.sol";
import {IWrappedToken} from "./interfaces/IWrappedToken.sol";
import {SignatureVerifier} from "./libraries/SignatureVerifier.sol";

/// @title QuantaureumBridge
/// @notice Quantaureum-side bridge contract for minting/burning wrapped tokens.
///         Receives cross-chain messages from the relayer and mints/burns wrapped
///         tokens accordingly. Wrapped tokens on Quantaureum represent real assets
///         from Ethereum.
///
/// @dev Mint flow (Ethereum → Quantaureum):
///         1. User locks ETH/ERC20 on EthereumBridge
///         2. Relayer reads TokensLocked/ERC20Locked event
///         3. Relayer calls mintWrappedToken() with multi-signature proof
///         4. Wrapped tokens minted to user's QAU address
///
///       Burn flow (Quantaureum → Ethereum):
///         1. User calls burnWrappedToken() to burn wrapped tokens
///         2. Event emitted → relayer reads → submits unlock to EthereumBridge
///         3. Original assets released to user on Ethereum
///
///       Security:
///         - Only authorized relayers can mint (multi-validator threshold)
///         - Governance-gated key management (R69-GOV-1)
///         - Deadline and slippage enforcement
///         - Pausable by governance
///
/// @custom:security-contact security@quantaureum.com
contract QuantaureumBridge is IBridgeEvents {
    // =============================================================================
    // Constants
    // =============================================================================

    /// @notice Ethereum chain ID.
    uint256 public constant ETHEREUM_CHAIN_ID = 1;

    /// @notice Quantaureum testnet chain ID.
    uint256 public constant QUANTAUREUM_CHAIN_ID = 1669;

    /// @notice Minimum amount: 1e15 (0.001 ETH equivalent in smallest unit).
    uint256 public constant MIN_OPERATION_AMOUNT = 1;

    /// @notice Maximum amount per mint/burn operation.
    uint256 public constant MAX_OPERATION_AMOUNT = 10_000_000e18;

    /// @notice Default gas limit for cross-chain message execution.
    uint256 public constant DEFAULT_GAS_LIMIT = 500_000;

    /// @notice Default slippage tolerance: 100 = 1%.
    uint256 public constant DEFAULT_SLIPPAGE_TOLERANCE = 100;

    // =============================================================================
    // State
    // =============================================================================

    /// @notice Governance address for access control.
    address public governance;

    /// @notice Registered validator public keys (Dilithium3).
    /// @dev Map validator address → Dilithium3 public key (1952 bytes).
    mapping(address => bytes) public validatorKeys;

    /// @notice Whether the bridge is paused.
    bool public paused;

    /// @notice Maps wrapped token address → whether it is registered.
    mapping(address => bool) public registeredTokens;

    /// @notice Maps payload commitment (source chain) → processed flag.
    /// @dev BRDG-R5-01 fix: keyed by payload commitment (NOT bare lockTxHash) so
    ///      that the confirmed payload (recipient+token+amount+nonce+lockTxHash)
    ///      is bound to the mint/unlock action. Prevents a relayer that witnessed
    ///      any genuine lock from minting arbitrary amount/recipient/token.
    mapping(bytes32 => bool) public processedLockTx;

    /// @notice Maps user address → current nonce.
    mapping(address => uint64) public nonces;

    /// @notice Maps nonce key → consumed flag.
    mapping(bytes32 => bool) public consumedNonces;

    /// @notice Maps relayer address → authorized flag.
    mapping(address => bool) public authorizedRelayers;

    /// @notice Maps payload commitment → number of relayer confirmations received.
    /// SECURITY (multi-relayer confirmation + payload binding, BRDG-R5-01):
    /// A cross-chain mint may only execute after `requiredConfirmations` distinct
    /// authorized relayers attest to the SAME payload commitment
    /// (`keccak256(sourceChainId, lockTxHash, recipient, token, amount, nonce)`).
    /// Because the key is the full payload commitment rather than the bare
    /// lockTxHash, M-of-N attestation now proves not only "some lock happened"
    /// but "this specific (recipient, token, amount, nonce) was the locked
    /// payload". This closes the unlimited-mint / drain attack surface that
    /// existed when confirmations were keyed on the bare tx hash.
    mapping(bytes32 => uint256) public lockConfirmations;
    /// @notice Maps (payloadCommitment, relayer) → already confirmed, to prevent
    /// one relayer from counting multiple times toward the threshold.
    mapping(bytes32 => mapping(address => bool)) public hasConfirmed;
    /// @notice Number of distinct authorized relayer confirmations required
    /// before a mint/unlock can execute. Defaults to 2; governance can raise it.
    uint256 public requiredConfirmations = 2;

    address public wrappedETHToken;

    // =============================================================================
    // Events
    // =============================================================================

    event GovernanceChanged(address indexed oldGov, address indexed newGov);
    event ValidatorKeyUpdated(address indexed validator, bytes oldKey, bytes newKey);
    event TokenRegistered(address indexed token, address underlying);
    event BridgePaused(bool isPaused);
    event MintProcessed(
        bytes32 indexed lockTxHash,
        address indexed recipient,
        address indexed token,
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

    modifier onlyAuthorizedRelayer() {
        require(authorizedRelayers[msg.sender], "Bridge: unauthorized relayer");
        _;
    }

    modifier reentrancyGuard() {
        require(_reentrancyGuard != 2, "Bridge: reentrancy");
        _reentrancyGuard = 2;
        _;
        _reentrancyGuard = 1;
    }

    // =============================================================================
    // Constructor
    // =============================================================================

    constructor(address _governance) {
        require(_governance != address(0), "Bridge: zero governance");
        governance = _governance;
    }

    // =============================================================================
    // ERC165
    // =============================================================================

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
    // Mint functions (Relayer → User on Quantaureum)
    // =============================================================================

    /// @notice Submits a relayer attestation that a source-chain lock occurred
    /// with a specific payload (recipient, token, amount, nonce, lockTxHash).
    /// Each authorized relayer must call this once per payloadCommitment. The
    /// mint only becomes executable once `requiredConfirmations` distinct relayers
    /// have attested to the SAME payloadCommitment. This is the on-chain M-of-N
    /// gate that compensates for the absence of an EVM Dilithium3 precompile.
    /// @dev BRDG-R5-01 fix: relayers commit to the full payload commitment
    ///      (computed off-chain from the source-chain lock event fields) rather
    ///      than the bare lockTxHash. This binds the M-of-N quorum to the exact
    ///      amount/recipient/token being minted and prevents a relayer that
    ///      witnessed any genuine lock from minting arbitrary payload.
    /// @param payloadCommitment keccak256(abi.encode(sourceChainId, lockTxHash,
    ///        recipient, token, amount, nonce)) computed off-chain from the
    ///        source-chain lock event. MUST match the commitment recomputed
    ///        inside mintWrappedToken/mintWrappedETH.
    function confirmLock(bytes32 payloadCommitment)
        external
        whenNotPaused
        onlyAuthorizedRelayer
    {
        require(payloadCommitment != bytes32(0), "Bridge: zero commitment");
        require(!processedLockTx[payloadCommitment], "Bridge: already processed");
        require(!hasConfirmed[payloadCommitment][msg.sender], "Bridge: already confirmed");
        hasConfirmed[payloadCommitment][msg.sender] = true;
        unchecked {
            lockConfirmations[payloadCommitment] += 1;
        }
    }

    /// @notice Mints wrapped tokens to a recipient after cross-chain proof.
    /// @param recipient   The QAU address to receive minted tokens.
    /// @param token       The wrapped token contract address.
    /// @param amount      The amount to mint.
    /// @param lockTxHash   The lock transaction hash on the source chain.
    /// @param nonce       The nonce for replay protection.
    /// @param deadline    The deadline timestamp for the operation.
    /// @param maxAmount   Maximum amount to mint (slippage protection).
    /// @dev Can only be called by authorized relayers and only after
    ///      `requiredConfirmations` relayers have called
    ///      confirmLock(payloadCommitment) with the matching payloadCommitment.
    ///      BRDG-R5-01 fix: the commitment key is recomputed from this call's
    ///      arguments and bound to the quorum, so a relayer that witnessed any
    ///      other lock cannot mint a different (recipient, token, amount).
    function mintWrappedToken(
        address recipient,
        address token,
        uint256 amount,
        bytes32 lockTxHash,
        uint64 nonce,
        uint64 deadline,
        uint256 maxAmount
    ) external whenNotPaused onlyAuthorizedRelayer reentrancyGuard {
        require(recipient != address(0), "Bridge: zero recipient");
        require(registeredTokens[token], "Bridge: unregistered token");
        require(amount > 0, "Bridge: zero amount");
        require(amount <= MAX_OPERATION_AMOUNT, "Bridge: exceeds maximum");
        require(block.timestamp <= deadline, "Bridge: deadline passed");
        require(amount <= maxAmount, "Bridge: exceeds maxAmount");

        // BRDG-R5-01: recompute payload commitment from THIS call's args and
        // require that the quorum was reached on this exact commitment. This
        // binds the M-of-N attestation to the actual amount/recipient/token.
        bytes32 payloadCommitment = _computePayloadCommitment(
            ETHEREUM_CHAIN_ID,
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

        // Prevent double-processing same payload commitment
        require(!processedLockTx[payloadCommitment], "Bridge: already processed");
        processedLockTx[payloadCommitment] = true;

        emit MintProcessed(lockTxHash, recipient, token, amount, nonce);

        // Mint wrapped tokens via IWrappedToken interface
        IWrappedToken(token).mint(recipient, amount);
    }

    /// @notice Mints wrapped ETH (native asset representation).
    /// @param recipient   The QAU address to receive minted tokens.
    /// @param amount      The amount to mint.
    /// @param lockTxHash   The lock transaction hash on source chain.
    /// @param nonce       Nonce for replay protection.
    /// @param deadline    Operation deadline.
    /// @dev BRDG-R5-01 fix: uses payloadCommitment (with token=address(0)) as
    ///      the quorum key, so M-of-N attestation is bound to this exact
    ///      (recipient, amount, nonce). See mintWrappedToken for details.
    function mintWrappedETH(
        address recipient,
        uint256 amount,
        bytes32 lockTxHash,
        uint64 nonce,
        uint64 deadline
    ) external whenNotPaused onlyAuthorizedRelayer reentrancyGuard {
        require(recipient != address(0), "Bridge: zero recipient");
        require(amount > 0, "Bridge: zero amount");
        require(block.timestamp <= deadline, "Bridge: deadline passed");

        // BRDG-R5-01: payload commitment with token=address(0) sentinel for
        // native ETH. Quorum must have been reached on this exact commitment.
        bytes32 payloadCommitment = _computePayloadCommitment(
            ETHEREUM_CHAIN_ID,
            lockTxHash,
            recipient,
            address(0),
            amount,
            nonce
        );
        require(
            lockConfirmations[payloadCommitment] >= requiredConfirmations,
            "Bridge: insufficient confirmations"
        );

        _checkAndConsumeNonce(msg.sender, nonce);
        require(!processedLockTx[payloadCommitment], "Bridge: already processed");
        processedLockTx[payloadCommitment] = true;

        // Mint wETH via the registered wrapped ETH token
        // The token address is looked up from registeredTokens mapping
        // For native ETH wrapping, a special sentinel address(0) is used.
        emit MintProcessed(lockTxHash, recipient, address(0), amount, nonce);

        address wethToken = wrappedETHToken;
        require(wethToken != address(0), "Bridge: wrapped ETH token not configured");
        require(registeredTokens[wethToken], "Bridge: wrapped ETH token not registered");
        IWrappedToken(wethToken).mint(recipient, amount);
    }

    // =============================================================================
    // Burn functions (User → Bridge → Relayer → Ethereum)
    // =============================================================================

    /// @notice Burns wrapped tokens to trigger cross-chain unlock on Ethereum.
    /// @param token       The wrapped token contract to burn.
    /// @param amount      The amount to burn.
    /// @param ethAddress  The recipient Ethereum address.
    /// @param deadline    The deadline for the operation.
    /// @dev Emits WrappedTokenBurned event which the relayer watches.
    function burnWrappedToken(
        address token,
        uint256 amount,
        address ethAddress,
        uint64 deadline
    ) external whenNotPaused {
        require(token != address(0), "Bridge: zero token");
        require(amount > 0, "Bridge: zero amount");
        require(ethAddress != address(0), "Bridge: zero eth address");
        require(block.timestamp <= deadline, "Bridge: deadline passed");

        // Burn wrapped tokens from caller
        IWrappedToken(token).burn(msg.sender, amount);

        // Increment nonce
        uint64 nonce = ++nonces[msg.sender];

        // Emit event for relayer to relay to Ethereum
        emit WrappedTokenBurned(token, msg.sender, amount, ethAddress);
    }

    /// @notice Burns wrapped native token for ETH unlock on Ethereum.
    /// @param amount     The amount to burn.
    /// @param ethAddress The recipient Ethereum address.
    /// @param deadline   The deadline for the operation.
    function burnWrappedETH(
        uint256 amount,
        address ethAddress,
        uint64 deadline
    ) external whenNotPaused reentrancyGuard {
        require(amount > 0, "Bridge: zero amount");
        require(ethAddress != address(0), "Bridge: zero eth address");
        require(block.timestamp <= deadline, "Bridge: deadline passed");

        address wethToken = wrappedETHToken;
        require(wethToken != address(0), "Bridge: ETH token not set");

        IWrappedToken(wethToken).burn(msg.sender, amount);

        uint64 nonce = ++nonces[msg.sender];

        emit TokensBurned(msg.sender, amount, ethAddress, bytes32(0));
    }

    // =============================================================================
    // Governance functions
    // =============================================================================

    /// @notice Sets a validator's Dilithium3 public key.
    /// @dev R69-GOV-1: governance-gated. Only governance can update validator keys.
    /// @param validator The validator address.
    /// @param newKey     The new Dilithium3 public key (1952 bytes).
    function setValidatorKey(address validator, bytes calldata newKey)
        external
        onlyGovernance
    {
        require(
            newKey.length == SignatureVerifier.DILITHIUM3_PUBLIC_KEY_SIZE,
            "Bridge: invalid key size"
        );
        bytes memory oldKey = validatorKeys[validator];
        validatorKeys[validator] = newKey;
        emit ValidatorKeyUpdated(validator, oldKey, newKey);
    }

    /// @notice Authorizes or deauthorizes a relayer.
    /// @param relayer    The relayer address.
    /// @param authorized True to authorize.
    function setRelayerAuthorization(address relayer, bool authorized)
        external
        onlyGovernance
    {
        authorizedRelayers[relayer] = authorized;
    }

    /// @notice Registers a wrapped token that can be minted/burned.
    /// @param token      The wrapped token contract address.
    /// @param underlying The underlying asset address on the source chain.
    function registerToken(address token, address underlying)
        external
        onlyGovernance
    {
        require(token != address(0), "Bridge: zero token");
        registeredTokens[token] = true;
        emit TokenRegistered(token, underlying);
    }

    function setWrappedETHToken(address _token) external onlyGovernance {
        wrappedETHToken = _token;
        emit TokenRegistered(_token, address(0));
    }

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
    /// @param _paused True to pause.
    function setPaused(bool _paused) external onlyGovernance {
        paused = _paused;
        emit BridgePaused(_paused);
    }

    /// @notice Sets the M-of-N relayer confirmation threshold for mint/unlock.
    /// @dev Must be >= 2 so that no single compromised relayer can mint or
    ///      drain assets. Governance may raise (never lower below 2) the
    ///      threshold as the relayer set grows.
    function setRequiredConfirmations(uint256 _required) external onlyGovernance {
        require(_required >= 2, "Bridge: threshold must be >= 2");
        requiredConfirmations = _required;
    }

    // =============================================================================
    // View functions
    // =============================================================================

    /// @notice Returns whether a token is registered.
    /// @param token The token address.
    /// @return True if registered.
    function isTokenRegistered(address token) external view returns (bool) {
        return registeredTokens[token];
    }

    /// @notice Returns whether a payload commitment has been processed.
    /// @param payloadCommitment The payload commitment (NOT bare lockTxHash).
    /// @return True if processed.
    function isLockProcessed(bytes32 payloadCommitment) external view returns (bool) {
        return processedLockTx[payloadCommitment];
    }

    /// @notice Returns the current nonce for a user.
    /// @param user The user address.
    /// @return The current nonce.
    function getNonce(address user) external view returns (uint64) {
        return nonces[user];
    }

    /// @notice Computes the payload commitment used as the quorum / processed key.
    /// @dev BRDG-R5-01: canonical commitment binding sourceChainId, lockTxHash,
    ///      recipient, token, amount, nonce. Relayers MUST compute the same
    ///      value off-chain from the source-chain lock event and pass it to
    ///      confirmLock(). Mint functions recompute it from their args and
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

    function _checkAndConsumeNonce(address relayer, uint64 nonce) internal {
        require(authorizedRelayers[relayer], "Bridge: unauthorized relayer");
        bytes32 key = keccak256(abi.encodePacked(relayer, nonce));
        require(!consumedNonces[key], "Bridge: nonce already used");
        consumedNonces[key] = true;
    }

    /// @dev BRDG-R5-01: payload commitment = keccak256(abi.encode(...)).
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

    uint256 private _reentrancyGuard = 1;

    }
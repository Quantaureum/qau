// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IWrappedToken} from "./interfaces/IWrappedToken.sol";

/// @title WrappedToken
/// @notice ERC20-wrapped token for cross-chain bridge operations.
///         Minted when assets arrive from the source chain,
///         burned when assets leave for the source chain.
///
/// @dev Security features:
///         - Only the bridge contract can mint/burn
///         - Pausable by governance
///         - Reentrancy guard on all state-changing functions
///
/// @custom:security-contact security@quantaureum.com
contract WrappedToken is IWrappedToken {
    // =============================================================================
    // Constants
    // =============================================================================

    /// @notice Decimals matches ETH (18).
    uint8 public constant decimals = 18;

    // =============================================================================
    // State
    // =============================================================================

    /// @notice The bridge address authorized to mint and burn.
    address public immutable bridgeAddr;

    /// @notice The underlying asset address on the source chain.
    address public immutable underlyingAsset_;

    /// @notice Token metadata.
    string public name_;
    string public symbol_;

    /// @notice ERC20 balances.
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// @notice Total supply of wrapped tokens.
    uint256 public totalSupply;

    /// @notice Whether the token is paused.
    bool public paused;

    /// @notice Governance address for pause control.
    address public governance;

    // =============================================================================
    // Events (ERC20 + bridge-specific)
    // =============================================================================

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event GovernanceChanged(address indexed oldGov, address indexed newGov);
    event TokenPaused(bool isPaused);

    // =============================================================================
    // Modifiers
    // =============================================================================

    modifier onlyBridge() {
        require(msg.sender == bridgeAddr, "WrappedToken: caller is not the bridge");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "WrappedToken: token is paused");
        _;
    }

    modifier onlyGovernance() {
        require(msg.sender == governance, "WrappedToken: caller is not governance");
        _;
    }

    modifier reentrancyGuard() {
        require(_reentrancyGuard != 2, "WrappedToken: reentrancy");
        _reentrancyGuard = 2;
        _;
        _reentrancyGuard = 1;
    }

    // =============================================================================
    // Constructor
    // =============================================================================

    constructor(
        string memory _name,
        string memory _symbol,
        address _bridge,
        address _underlying
    ) {
        require(_bridge != address(0), "WrappedToken: zero bridge");
        require(_underlying != address(0), "WrappedToken: zero underlying");
        name_ = _name;
        symbol_ = _symbol;
        bridgeAddr = _bridge;
        underlyingAsset_ = _underlying;
        governance = msg.sender;
    }

    // =============================================================================
    // IWrappedToken implementation
    // =============================================================================

    /// @notice Returns the bridge address that can mint/burn this token.
    function bridge() external view override returns (address) {
        return bridgeAddr;
    }

    /// @notice Returns the underlying (original chain) asset address.
    function underlyingAsset() external view override returns (address) {
return underlyingAsset_;
    }

    /// @notice Returns the token name.
    function name() external view override returns (string memory) {
        return name_;
    }

    /// @notice Returns the token symbol.
    function symbol() external view override returns (string memory) {
        return symbol_;
    }

    /// @notice Returns the token decimals.
    /// @dev Provided by the public constant.

    /// @notice Mints wrapped tokens to a recipient.
    /// @dev Only callable by the bridge contract.
    /// @param to     Recipient address.
    /// @param amount Amount to mint.
    function mint(address to, uint256 amount)
        external
        override
        onlyBridge
        reentrancyGuard
    {
        require(to != address(0), "WrappedToken: mint to zero");
        require(amount > 0, "WrappedToken: zero amount");

        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    /// @notice Burns wrapped tokens from a holder.
    /// @dev Only callable by the bridge contract.
    /// @param from   Holder address.
    /// @param amount Amount to burn.
    function burn(address from, uint256 amount)
        external
        override
        onlyBridge
        reentrancyGuard
    {
        require(from != address(0), "WrappedToken: burn from zero");
        require(amount > 0, "WrappedToken: zero amount");
        require(balanceOf[from] >= amount, "WrappedToken: insufficient balance");

        totalSupply -= amount;
        balanceOf[from] -= amount;
        emit Transfer(from, address(0), amount);
    }

    // =============================================================================
    // ERC20 functions
    // =============================================================================

    /// @notice Transfers tokens to a recipient.
    /// @param to    Recipient address.
    /// @param amount Amount to transfer.
    /// @return True if successful.
    function transfer(address to, uint256 amount)
        external
        override
        whenNotPaused
        reentrancyGuard
        returns (bool)
    {
        _transfer(msg.sender, to, amount);
        return true;
    }

    /// @notice Approves a spender to spend tokens on behalf of the caller.
    /// @param spender Spender address.
    /// @param amount  Amount to approve.
    /// @return True if successful.
    function approve(address spender, uint256 amount)
        external
        override
        whenNotPaused
        returns (bool)
    {
        require(spender != address(0), "WrappedToken: approve to zero");
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /// @notice Transfers tokens from one address to another.
    /// @param from  Source address.
    /// @param to    Recipient address.
    /// @param amount Amount to transfer.
    /// @return True if successful.
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external override whenNotPaused reentrancyGuard returns (bool) {
        require(from != address(0), "WrappedToken: transfer from zero");
        require(to != address(0), "WrappedToken: transfer to zero");

        uint256 allowed = allowance[from][msg.sender];
        if (msg.sender != bridgeAddr) {
            require(allowed >= amount, "WrappedToken: insufficient allowance");
            allowance[from][msg.sender] = allowed - amount;
        }

        _transfer(from, to, amount);
        return true;
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
        require(newGovernance != address(0), "WrappedToken: zero governance");
        address oldGov = governance;
        governance = newGovernance;
        emit GovernanceChanged(oldGov, newGovernance);
    }

    /// @notice Pauses or unpauses all token transfers.
    /// @param _paused True to pause.
    function setPaused(bool _paused) external onlyGovernance {
        paused = _paused;
        emit TokenPaused(_paused);
    }

    // =============================================================================
    // Internal helpers
    // =============================================================================

    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal {
        require(balanceOf[from] >= amount, "WrappedToken: insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }

    uint256 private _reentrancyGuard = 1;
}

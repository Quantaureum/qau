// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IWrappedToken
/// @notice Interface for ERC20-wrapped tokens deployed by the bridge.
/// Wrapped tokens are minted when assets arrive from the source chain
/// and burned when assets leave for the source chain.
interface IWrappedToken {
    /// @notice Mints wrapped tokens to a recipient.
    /// @dev Only callable by the bridge contract.
    /// @param to     Recipient address.
    /// @param amount Amount to mint.
    function mint(address to, uint256 amount) external;

    /// @notice Burns wrapped tokens from a holder.
    /// @dev Only callable by the bridge contract.
    /// @param from   Holder address.
    /// @param amount Amount to burn.
    function burn(address from, uint256 amount) external;

    /// @notice Returns the bridge address that can mint/burn this token.
    function bridge() external view returns (address);

    /// @notice Returns the underlying (original chain) asset address.
    function underlyingAsset() external view returns (address);

    /// @notice Returns token metadata.
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IBridgeEvents
/// @notice Interface defining all cross-chain bridge event signatures.
/// Event signatures MUST be registered in the BridgeAdapter's allowlist
/// before the relayer will process events. Signatures are keccak256 hashes
/// of the canonical event ABI definitions below.
///
/// @dev Two categories of events:
///   - LOCK events: emitted on source chain when assets are deposited into bridge
///   - BURN events: emitted on target chain when wrapped assets are burned
///
/// Relayer flow:
///   Source chain LOCK event → relayer reads → relayer submits to target chain
///   Target chain BURN event → relayer reads → relayer submits to source chain
interface IBridgeEvents {
    // =============================================================================
    // Source chain events (Ethereum side → Quantaureum)
    // =============================================================================

    /// @notice Emitted when a user locks native ETH for bridging to Quantaureum.
    /// @param user        The user's Ethereum address that locked the ETH.
    /// @param amount      Amount of ETH (in wei) locked.
    /// @param qauAddress  The target Quantaureum address (bytes32) for the bridged assets.
    /// @param txHash      The transaction hash of the lock transaction.
    event TokensLocked(
        address indexed user,
        uint256 amount,
        bytes32 qauAddress,
        bytes32 txHash
    );

    /// @notice Emitted when a user locks ERC20 tokens for bridging to Quantaureum.
    /// @param token     The ERC20 token contract address.
    /// @param user      The user's Ethereum address that locked the tokens.
    /// @param amount    Amount of tokens locked.
    /// @param qauAddress The target Quantaureum address (bytes32).
    event ERC20Locked(
        address indexed token,
        address indexed user,
        uint256 amount,
        bytes32 qauAddress
    );

    // =============================================================================
    // Target chain events (Quantaureum side → Ethereum)
    // =============================================================================

    /// @notice Emitted when a user burns wrapped ETH on Quantaureum to unlock on Ethereum.
    /// @param user     The user's Quantaureum address that burned wrapped ETH.
    /// @param amount   Amount of wrapped ETH burned.
    /// @param ethAddress The recipient Ethereum address.
    /// @param txHash   The transaction hash of the burn transaction.
    event TokensBurned(
        address indexed user,
        uint256 amount,
        address ethAddress,
        bytes32 txHash
    );

    /// @notice Emitted when a user burns wrapped ERC20 tokens on Quantaureum.
    /// @param token       The wrapped token contract address on Quantaureum.
    /// @param user        The user's Quantaureum address that burned tokens.
    /// @param amount      Amount of tokens burned.
    /// @param ethAddress  The recipient Ethereum address for the original tokens.
    event WrappedTokenBurned(
        address indexed token,
        address indexed user,
        uint256 amount,
        address ethAddress
    );
}

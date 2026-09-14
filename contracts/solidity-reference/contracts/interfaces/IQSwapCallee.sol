// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

/// @title IQSwapCallee — Flash-swap callback interface
/// @dev Implement on any contract that wants to receive a flash swap from a QSwapPair.
interface IQSwapCallee {
    function qswapCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

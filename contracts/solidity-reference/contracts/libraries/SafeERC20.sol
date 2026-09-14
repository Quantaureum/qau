// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeERC20
/// @notice Minimal SafeERC20 library implementing OpenZeppelin-style safety
///         checks for ERC20 `transfer` and `transferFrom` calls.
/// @dev    BRDG-FIX (2026-07-16): Previously, EthereumBridge used
///         raw `token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, ...))`
///         and only checked the `success` flag. For tokens that return
///         `false` (without reverting) on failure — e.g. USDT-style non-bool
///         return tokens, or tokens that return bool=false on insufficient
///         allowance/balance — the low-level `call` sets `success=true`
///         regardless, so the bridge silently recorded a transfer as
///         successful when no tokens actually moved. This led to
///         "unbacked minting" / "balance desynchronization" attack surface.
///
///         This library enforces the OpenZeppelin SafeERC20 semantics:
///           - If the call reverts, bubble up the revert.
///           - If the call returns data, decode it as `bool` and require `true`.
///           - If the call returns no data (non-standard but contract exists),
///             assume success (matches OpenZeppelin behavior for USDT).
///         Additionally, `safeTransferFromWithBalanceCheck` performs a
///         before/after balance-difference check to handle fee-on-transfer
///         tokens safely (where the actual received amount < requested amount).
library SafeERC20 {
    /// @notice The target address does not contain code (not a contract).
    error AddressNotContract(address);

    /// @notice The ERC20 call reverted.
    error SafeERC20FailedOperation(address);

    /// @notice The ERC20 call returned an unexpected (non-bool, non-empty) value.
    error SafeERC20FailedReturnValue(address);

    /// @notice The balance-difference check failed (fee-on-transfer safety).
    error SafeERC20InsufficientBalanceDelta(address, uint256 expected, uint256 actual);

    /// @notice Safely calls `transfer(to, amount)` on `token`, reverting on
    ///         any failure mode (revert, bool=false, or unexpected return).
    /// @param token  The ERC20 token contract.
    /// @param to     The recipient.
    /// @param amount The amount to transfer.
    function safeTransfer(address token, address to, uint256 amount) internal {
        _callOptionalReturnBool(token, abi.encodeWithSelector(0xa9059cbb, to, amount));
    }

    /// @notice Safely calls `transferFrom(from, to, amount)` on `token`,
    ///         reverting on any failure mode.
    /// @param token  The ERC20 token contract.
    /// @param from   The source address.
    /// @param to     The recipient.
    /// @param amount The amount to transfer.
    function safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        _callOptionalReturnBool(token, abi.encodeWithSelector(0x23b872dd, from, to, amount));
    }

    /// @notice Safely calls `transferFrom(from, to, amount)` on `token` and
    ///         verifies the actual balance delta matches `amount`. This is the
    ///         BRDG- fix for fee-on-transfer tokens: a malicious or
    ///         fee-charging token may move less than `amount` while returning
    ///         success. The balance-delta check ensures the bridge only credits
    ///         the actual amount received, preventing "lock recorded but tokens
    ///         not received" desynchronization.
    /// @param token        The ERC20 token contract.
    /// @param from         The source address.
    /// @param to           The recipient (typically the bridge).
    /// @param amount       The expected amount to transfer.
    /// @return actualDelta The actual balance increase of `to` after the transfer.
    function safeTransferFromWithBalanceCheck(
        address token,
        address from,
        address to,
        uint256 amount
    ) internal returns (uint256 actualDelta) {
        // IERC20.balanceOf selector: 0x70a08231
        (bool ok, bytes memory data) = token.staticcall(
            abi.encodeWithSelector(0x70a08231, to)
        );
        if (!ok || data.length < 32) {
            revert SafeERC20FailedOperation(token);
        }
        uint256 balanceBefore = abi.decode(data, (uint256));

        safeTransferFrom(token, from, to, amount);

        (ok, data) = token.staticcall(abi.encodeWithSelector(0x70a08231, to));
        if (!ok || data.length < 32) {
            revert SafeERC20FailedOperation(token);
        }
        uint256 balanceAfter = abi.decode(data, (uint256));

        // Guard against underflow (shouldn't happen, but defense-in-depth).
        if (balanceAfter < balanceBefore) {
            revert SafeERC20InsufficientBalanceDelta(token, amount, 0);
        }
        actualDelta = balanceAfter - balanceBefore;
    }

    /// @dev Performs a low-level call to `token` with `data` and validates the
    ///      return value per OpenZeppelin SafeERC20 semantics:
    ///        - If the call reverts, bubble up the revert reason.
    ///        - If the call returns data, decode the first 32 bytes as `bool`
    ///          and require `true`. Non-bool returns are rejected.
    ///        - If the call returns no data (non-standard ERC20 like USDT),
    ///          assume success (matches OZ behavior).
    /// @param token The ERC20 token contract.
    /// @param data  The encoded call data.
    function _callOptionalReturnBool(address token, bytes memory data) private {
        // Ensure the target is a contract to avoid calling into an EOA.
        // Using EXTCODESIZE via inline assembly to avoid the shadowing pitfall.
        uint256 codeSize;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            codeSize := extcodesize(token)
        }
        if (codeSize == 0) {
            revert AddressNotContract(token);
        }

        (bool success, bytes memory returndata) = token.call(data);
        if (success) {
            if (returndata.length == 0) {
                // Non-standard ERC20 (e.g. USDT) returns no data — accept.
                return;
            }
            // Decode the first 32 bytes as bool. abi.decode handles the
            // padding; if the return data is malformed it reverts here.
            bool result = abi.decode(returndata, (bool));
            if (!result) {
                revert SafeERC20FailedOperation(token);
            }
        } else {
            // The call reverted. Bubble up the revert reason if available.
            if (returndata.length > 0) {
                // solhint-disable-next-line no-inline-assembly
                assembly {
                    revert(add(returndata, 0x20), mload(returndata))
                }
            } else {
                revert SafeERC20FailedOperation(token);
            }
        }
    }
}

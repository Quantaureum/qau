// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SignatureVerifier
/// @notice Library for verifying Dilithium3 post-quantum signatures on-chain.
///
/// @dev Dilithium3 is not natively supported by the EVM. This library provides
/// two verification strategies:
///
///   1. OFF-CHAIN (recommended): The relayer verifies Dilithium3 signatures
///      off-chain using the Go SDK (cloudflare/circl), then submits the
///      verified message to the contract. The contract trusts registered
///      relayers via access control.
///
///   2. PRECOMPILE (future): If a precompile is deployed at a fixed address
///      (e.g., 0x0000000000000000000000000000000000010001), this library
///      can be updated to call it. Precompile address to be determined
///      after Quantaureum EVM hardfork coordination.
///
/// Dilithium3 parameters (matching cloudflare/circl mode3):
///   - Public key size:  1952 bytes
///   - Signature size:   3293 bytes
///   - Algorithm:        ML-DSA-65 (recommended security level)
library SignatureVerifier {
    /// @notice Precompile address for Dilithium3 verification (TBD via hardfork).
    /// @dev Set to zero address until precompile is deployed.
    address constant PRECOMPILE_DILITHIUM3 = address(0);

    /// @notice Dilithium3 signature sizes.
    uint256 constant DILITHIUM3_PUBLIC_KEY_SIZE = 1952;
    uint256 constant DILITHIUM3_SIGNATURE_SIZE = 3293;

    /// @notice Verifies a Dilithium3 signature against a message hash.
    /// @dev This is a stub. When the precompile is deployed, this function
    ///      will call into the precompile for on-chain verification.
    ///      Until then, off-chain verification via the relayer is required.
    /// @param pubKey    The Dilithium3 public key (1952 bytes).
    /// @param signature The Dilithium3 signature (3293 bytes).
    /// @param msgHash   The SHA-256 hash of the message being verified.
    /// @return True if the signature is valid, false otherwise.
    function verifyDilithium3(
        bytes calldata pubKey,
        bytes calldata signature,
        bytes32 msgHash
    ) internal view returns (bool) {
        // Stub: Always revert until precompile is available.
        // Off-chain verification by the relayer is mandatory.
        revert("Dilithium3: precompile not yet deployed");
    }

    /// @notice Validates the size of Dilithium3 public key and signature.
    /// @dev Use this for input validation before calling verifyDilithium3.
    /// @param pubKey    The public key bytes.
    /// @param signature  The signature bytes.
    /// @return True if sizes match Dilithium3 mode3 parameters.
    function validateDilithium3Sizes(
        bytes calldata pubKey,
        bytes calldata signature
    ) internal pure returns (bool) {
        return
            pubKey.length == DILITHIUM3_PUBLIC_KEY_SIZE &&
            signature.length == DILITHIUM3_SIGNATURE_SIZE;
    }
}

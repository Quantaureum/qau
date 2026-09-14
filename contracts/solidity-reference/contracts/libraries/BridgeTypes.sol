// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BridgeTypes
/// @notice Library defining cross-chain bridge message types and hashes.
/// The message hash computation MUST match the Go bridge library's
/// computeMessageHash() function in bridge/ethereum_adapter.go:
///   SHA-256("QAU-BRIDGE-MSG-V1" || length-prefixed fields...)
/// Uses SHA-256 (not SHA-3/Keccak) to match Go implementation.
library BridgeTypes {
    /// @notice Domain separator for bridge message hashing.
    bytes32 constant DOMAIN_BRIDGE_MSG = sha256("QAU-BRIDGE-MSG-V1");

    /// @notice Domain separator for Merkle proof hashing.
    bytes32 constant DOMAIN_BRIDGE_MERKLE = sha256("QAU-BRIDGE-MERKLE-V1");

    /// @notice Asset type identifiers.
    bytes32 constant ASSET_TYPE_ETH = sha256("ETH");
    bytes32 constant ASSET_TYPE_ERC20 = sha256("ERC20");
    bytes32 constant ASSET_TYPE_NFT = sha256("NFT");

    /// @notice Chain ID constants (matching config values).
    uint256 constant CHAIN_ETHEREUM_MAINNET = 1;
    uint256 constant CHAIN_ETHEREUM_SEPOLIA = 11155111;
    uint256 constant CHAIN_QUANTAUREUM_MAINNET = 1668;
    uint256 constant CHAIN_QUANTAUREUM_TESTNET = 1669;
    uint256 constant CHAIN_QUANTAUREUM_DEVNET = 1333;

    /// @notice Bridge message structure.
    struct BridgeMessage {
        bytes32 id;
        bytes32 sourceChain;
        bytes32 targetChain;
        bytes32 sourceAddress;
        bytes32 targetAddress;
        bytes32 assetType;
        bytes32 assetId;
        string amount;
        bytes32 tokenId;
        bytes data;
        uint64 nonce;
        uint64 timestamp;
    }

    /// @notice Merkle proof structure.
    struct MerkleProof {
        bytes32 root;
        bytes32[] proof;
        uint256 leafIndex;
    }

    /// @notice Computes the SHA-256 hash of a bridge message.
/// @param m The bridge message to hash (extended with signature/txHash/blockHash).
/// @return hash The 32-byte SHA-256 digest.
    function computeMessageHash(BridgeMessageExt memory m)
        internal
        pure
        returns (bytes32 hash)
    {
        bytes32 domain = DOMAIN_BRIDGE_MSG;
        return sha256(abi.encodePacked(
            domain,
            _lp(m.id),
            _lp(m.sourceChain),
            _lp(m.targetChain),
            _lp(m.sourceAddress),
            _lp(m.targetAddress),
            _lp(m.assetType),
            _lp(m.assetId),
            // amount is string; hash to get fixed-size bytes32 for _lp
            _lp(sha256(abi.encode(m.amount))),
            _lp(m.tokenId),
            // data is bytes; hash to get fixed-size bytes32 for _lp
            _lp(sha256(m.data)),
            m.nonce,
            m.timestamp,
            m.signature,
            m.txHash,
            m.blockHash
        ));
    }

    /// @notice Length-prefixed encoding for a bytes32 field.
    function _lp(bytes32 b) internal pure returns (bytes memory) {
        return abi.encodePacked(uint32(32), b);
    }
}

// Extend BridgeTypes with signature field for message hashing.
// solhint-disable-next-line library-visibility
struct BridgeMessageExt {
    bytes32 id;
    bytes32 sourceChain;
    bytes32 targetChain;
    bytes32 sourceAddress;
    bytes32 targetAddress;
    bytes32 assetType;
    bytes32 assetId;
    string amount;
    bytes32 tokenId;
    bytes data;
    uint64 nonce;
    uint64 timestamp;
    bytes signature;
    bytes32 txHash;
    bytes32 blockHash;
}

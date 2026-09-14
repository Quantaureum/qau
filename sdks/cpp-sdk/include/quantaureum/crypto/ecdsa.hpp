// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <array>
#include <vector>
#include <cstdint>
#include <memory>

namespace quantaureum {
namespace crypto {

/**
 * @brief ECDSA signature operations using secp256k1 curve
 *
 * This class provides cryptographically secure ECDSA operations using
 * the libsecp256k1 library (Bitcoin Core's implementation).
 *
 * Security features:
 * - RFC 6979 deterministic signatures (no nonce reuse)
 * - Signature malleability protection (low-s enforcement)
 * - Public key recovery for Ethereum compatibility
 * - Constant-time operations to prevent timing attacks
 */
class ECDSA {
public:
    /**
     * @brief Initialize the ECDSA context (must be called before use)
     * @return true if initialization succeeded
     */
    static bool initialize();

    /**
     * @brief Cleanup the ECDSA context
     */
    static void cleanup();

    /**
     * @brief Derive public key from private key using secp256k1
     * @param privateKey 32-byte private key
     * @return 64-byte uncompressed public key (without 0x04 prefix)
     * @throws std::runtime_error if derivation fails
     */
    static std::array<uint8_t, 64> derivePublicKey(const std::array<uint8_t, 32>& privateKey);

    /**
     * @brief Sign a 32-byte hash using ECDSA
     * @param hash 32-byte message hash
     * @param privateKey 32-byte private key
     * @return Signature with r, s, and recovery id (v)
     * @throws std::runtime_error if signing fails
     *
     * Uses RFC 6979 deterministic nonce generation for security.
     * Enforces low-s values to prevent signature malleability.
     */
    static std::tuple<std::array<uint8_t, 32>, std::array<uint8_t, 32>, uint8_t>
        sign(const std::array<uint8_t, 32>& hash, const std::array<uint8_t, 32>& privateKey);

    /**
     * @brief Verify an ECDSA signature
     * @param hash 32-byte message hash
     * @param r 32-byte r component
     * @param s 32-byte s component
     * @param publicKey 64-byte uncompressed public key
     * @return true if signature is valid
     */
    static bool verify(
        const std::array<uint8_t, 32>& hash,
        const std::array<uint8_t, 32>& r,
        const std::array<uint8_t, 32>& s,
        const std::array<uint8_t, 64>& publicKey
    );

    /**
     * @brief Recover public key from signature (Ethereum-style)
     * @param hash 32-byte message hash
     * @param r 32-byte r component
     * @param s 32-byte s component
     * @param recoveryId Recovery id (0-3)
     * @return 64-byte uncompressed public key
     * @throws std::runtime_error if recovery fails
     */
    static std::array<uint8_t, 64> recoverPublicKey(
        const std::array<uint8_t, 32>& hash,
        const std::array<uint8_t, 32>& r,
        const std::array<uint8_t, 32>& s,
        uint8_t recoveryId
    );

    /**
     * @brief Validate a private key
     * @param privateKey 32-byte private key
     * @return true if private key is valid (in range [1, n-1])
     */
    static bool validatePrivateKey(const std::array<uint8_t, 32>& privateKey);

    /**
     * @brief Validate a public key
     * @param publicKey 64-byte uncompressed public key
     * @return true if public key is valid (on the curve)
     */
    static bool validatePublicKey(const std::array<uint8_t, 64>& publicKey);

    /**
     * @brief Get the secp256k1 context (for internal use by BIP32)
     * @return Opaque pointer to secp256k1_context
     */
    static void* getContext() { return context_; }

private:
    ECDSA() = delete;

    // Opaque pointer to secp256k1_context
    static void* context_;
};

} // namespace crypto
} // namespace quantaureum

// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <string>
#include <vector>
#include <array>
#include <cstdint>

namespace quantaureum {
namespace crypto {

/**
 * @brief BIP-32 Hierarchical Deterministic (HD) wallet implementation
 *
 * Implements Bitcoin Improvement Proposal 32 for deriving child keys
 * from a master seed.
 *
 * Features:
 * - Master key derivation from seed
 * - Child key derivation (normal and hardened)
 * - Path parsing (e.g., "m/44'/60'/0'/0/0")
 * - Extended key serialization (xprv/xpub)
 *
 * Reference: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */
class BIP32 {
public:
    /**
     * @brief Extended key (contains private or public key + chain code)
     */
    struct ExtendedKey {
        std::array<uint8_t, 32> key;        // Private or public key
        std::array<uint8_t, 32> chainCode;  // Chain code for derivation
        uint32_t depth;                      // Depth in tree (0 for master)
        uint32_t childNumber;                // Child number (0 for master)
        std::array<uint8_t, 4> fingerprint;  // Parent key fingerprint
        bool isPrivate;                      // true if private key

        ExtendedKey() : depth(0), childNumber(0), isPrivate(true) {
            key.fill(0);
            chainCode.fill(0);
            fingerprint.fill(0);
        }
    };

    /**
     * @brief Derive master key from seed
     * @param seed 64-byte seed (typically from BIP-39)
     * @return Master extended private key
     * @throws std::runtime_error if derivation fails
     */
    static ExtendedKey deriveMasterKey(const std::array<uint8_t, 64>& seed);

    /**
     * @brief Derive child key from parent
     * @param parent Parent extended key
     * @param index Child index (use 0x80000000 + i for hardened)
     * @return Child extended key
     * @throws std::runtime_error if derivation fails
     *
     * Hardened derivation: index >= 0x80000000 (2^31)
     * Normal derivation: index < 0x80000000
     */
    static ExtendedKey deriveChild(const ExtendedKey& parent, uint32_t index);

    /**
     * @brief Derive key from path
     * @param master Master extended key
     * @param path Derivation path (e.g., "m/44'/60'/0'/0/0")
     * @return Derived extended key
     * @throws std::invalid_argument if path is invalid
     *
     * Path format:
     * - "m" = master key
     * - Numbers = child indices
     * - "'" or "h" suffix = hardened derivation
     * - Example: "m/44'/60'/0'/0/0" (Ethereum default)
     */
    static ExtendedKey derivePath(const ExtendedKey& master, const std::string& path);

    /**
     * @brief Get public key from extended key
     * @param extKey Extended key (private or public)
     * @return 64-byte uncompressed public key
     * @throws std::runtime_error if key is invalid
     */
    static std::array<uint8_t, 64> getPublicKey(const ExtendedKey& extKey);

    /**
     * @brief Get private key from extended key
     * @param extKey Extended private key
     * @return 32-byte private key
     * @throws std::runtime_error if key is not private
     */
    static std::array<uint8_t, 32> getPrivateKey(const ExtendedKey& extKey);

    /**
     * @brief Serialize extended key to base58 (xprv/xpub format)
     * @param extKey Extended key
     * @return Base58-encoded extended key string
     */
    static std::string serializeKey(const ExtendedKey& extKey);

    /**
     * @brief Deserialize extended key from base58
     * @param serialized Base58-encoded extended key string
     * @return Extended key
     * @throws std::invalid_argument if format is invalid
     */
    static ExtendedKey deserializeKey(const std::string& serialized);

    /**
     * @brief Parse derivation path
     * @param path Derivation path string
     * @return Vector of child indices
     * @throws std::invalid_argument if path is invalid
     */
    static std::vector<uint32_t> parsePath(const std::string& path);

    // Constants
    static constexpr uint32_t HARDENED_OFFSET = 0x80000000;

private:
    BIP32() = delete;

    // HMAC-SHA512 for key derivation
    static std::array<uint8_t, 64> hmacSha512(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data
    );
};

} // namespace crypto
} // namespace quantaureum

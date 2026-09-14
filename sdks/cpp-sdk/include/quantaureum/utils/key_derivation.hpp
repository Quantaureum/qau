// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <array>
#include <vector>
#include <string>
#include <cstdint>

namespace quantaureum {
namespace utils {

/**
 * @brief Key derivation functions (HKDF and PBKDF2)
 *
 * Implements cryptographic key derivation using HMAC-SHA256
 */
class KeyDerivation {
public:
    /**
     * @brief HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
     *
     * RFC 5869 implementation using HMAC-SHA256
     *
     * @param ikm Input keying material
     * @param salt Optional salt value (can be empty)
     * @param info Optional context and application specific information
     * @param length Desired output length in bytes (max 8160 bytes)
     * @return Derived key material
     */
    static std::vector<uint8_t> hkdf(
        const std::vector<uint8_t>& ikm,
        const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& info,
        size_t length
    );

    /**
     * @brief Password-Based Key Derivation Function 2 (PBKDF2)
     *
     * RFC 2898 implementation using HMAC-SHA256
     *
     * @param password Password to derive key from
     * @param salt Salt value (should be at least 16 bytes)
     * @param iterations Number of iterations (recommended: 100000+)
     * @param length Desired output length in bytes
     * @return Derived key
     */
    static std::vector<uint8_t> pbkdf2(
        const std::string& password,
        const std::vector<uint8_t>& salt,
        uint32_t iterations,
        size_t length
    );

    /**
     * @brief PBKDF2 with byte array password
     */
    static std::vector<uint8_t> pbkdf2(
        const std::vector<uint8_t>& password,
        const std::vector<uint8_t>& salt,
        uint32_t iterations,
        size_t length
    );

    /**
     * @brief HMAC-SHA256
     *
     * @param key HMAC key
     * @param data Data to authenticate
     * @return 32-byte HMAC output
     */
    static std::array<uint8_t, 32> hmacSha256(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data
    );

private:
    KeyDerivation() = delete;

    // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    static std::array<uint8_t, 32> hkdfExtract(
        const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& ikm
    );

    // HKDF-Expand: OKM = HMAC-Hash(PRK, info || counter)
    static std::vector<uint8_t> hkdfExpand(
        const std::array<uint8_t, 32>& prk,
        const std::vector<uint8_t>& info,
        size_t length
    );
};

} // namespace utils
} // namespace quantaureum

// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <array>
#include <vector>
#include <cstdint>

namespace quantaureum {
namespace utils {

/**
 * @brief SHA-256 cryptographic hash function
 *
 * Pure C++ implementation of SHA-256 (FIPS 180-4)
 * No external dependencies required.
 */
class SHA256 {
public:
    /**
     * @brief Compute SHA-256 hash of data
     * @param data Input data to hash
     * @return 32-byte SHA-256 hash
     */
    static std::array<uint8_t, 32> hash(const std::vector<uint8_t>& data);

private:
    SHA256() = delete;
};

} // namespace utils
} // namespace quantaureum

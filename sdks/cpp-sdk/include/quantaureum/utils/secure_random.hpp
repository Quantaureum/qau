// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <array>
#include <vector>
#include <cstdint>
#include <stdexcept>

namespace quantaureum {
namespace utils {

/**
 * @brief Cryptographically secure random number generator
 *
 * Uses platform-specific CSPRNG:
 * - Windows: BCryptGenRandom
 * - Linux/Unix: getrandom() or /dev/urandom
 */
class SecureRandom {
public:
    /**
     * @brief Generate cryptographically secure random bytes
     * @param buffer Output buffer
     * @param size Number of bytes to generate
     * @throws std::runtime_error if random generation fails
     */
    static void generateBytes(uint8_t* buffer, size_t size);

    /**
     * @brief Generate random bytes into a vector
     * @param size Number of bytes to generate
     * @return Vector of random bytes
     */
    static std::vector<uint8_t> generateBytes(size_t size);

    /**
     * @brief Generate random bytes into a fixed-size array
     * @tparam N Array size
     * @return Array of random bytes
     */
    template<size_t N>
    static std::array<uint8_t, N> generateBytes() {
        std::array<uint8_t, N> result;
        generateBytes(result.data(), N);
        return result;
    }

    /**
     * @brief Generate a random 32-bit unsigned integer
     */
    static uint32_t generateUInt32();

    /**
     * @brief Generate a random 64-bit unsigned integer
     */
    static uint64_t generateUInt64();

private:
    SecureRandom() = delete;
};

} // namespace utils
} // namespace quantaureum

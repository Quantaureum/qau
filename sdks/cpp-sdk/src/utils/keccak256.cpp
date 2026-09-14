// Quantaureum C++ SDK source, version 1.0.0.
#include "quantaureum/utils/keccak256.hpp"
#include "quantaureum/utils/hex.hpp"
#include <cstring>

namespace quantaureum {

// Keccak-256 round constants
static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rotation offsets
static const int R[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

// Pi permutation
static const int PI[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

void Keccak256::keccakF(uint64_t state[25]) {
    for (int round = 0; round < 24; ++round) {
        // Theta
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; ++x) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (int x = 0; x < 5; ++x) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                state[x + 5 * y] ^= D[x];
            }
        }

        // Rho and Pi
        uint64_t current = state[1];
        for (int i = 0; i < 24; ++i) {
            int j = PI[i];
            uint64_t temp = state[j];
            state[j] = rotl64(current, R[i]);
            current = temp;
        }

        // Chi
        for (int y = 0; y < 5; ++y) {
            uint64_t temp[5];
            for (int x = 0; x < 5; ++x) {
                temp[x] = state[x + 5 * y];
            }
            for (int x = 0; x < 5; ++x) {
                state[x + 5 * y] = temp[x] ^ ((~temp[(x + 1) % 5]) & temp[(x + 2) % 5]);
            }
        }

        // Iota
        state[0] ^= RC[round];
    }
}


Hash Keccak256::hash(const std::vector<uint8_t>& data) {
    return hash(data.data(), data.size());
}

Hash Keccak256::hash(const std::string& data) {
    return hash(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

Hash Keccak256::hash(const uint8_t* data, size_t len) {
    uint64_t state[25] = {0};

    // Absorb phase
    size_t blockSize = BLOCK_SIZE;
    size_t offset = 0;

    while (offset + blockSize <= len) {
        for (size_t i = 0; i < blockSize / 8; ++i) {
            uint64_t lane = 0;
            for (size_t j = 0; j < 8; ++j) {
                lane |= static_cast<uint64_t>(data[offset + i * 8 + j]) << (8 * j);
            }
            state[i] ^= lane;
        }
        keccakF(state);
        offset += blockSize;
    }

    // Padding
    uint8_t padded[BLOCK_SIZE] = {0};
    size_t remaining = len - offset;
    std::memcpy(padded, data + offset, remaining);
    padded[remaining] = 0x01;  // Keccak padding (not SHA-3)
    padded[blockSize - 1] |= 0x80;

    for (size_t i = 0; i < blockSize / 8; ++i) {
        uint64_t lane = 0;
        for (size_t j = 0; j < 8; ++j) {
            lane |= static_cast<uint64_t>(padded[i * 8 + j]) << (8 * j);
        }
        state[i] ^= lane;
    }
    keccakF(state);

    // Squeeze phase
    std::array<uint8_t, 32> output;
    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            output[i * 8 + j] = static_cast<uint8_t>(state[i] >> (8 * j));
        }
    }

    return Hash::fromBytes(output);
}

std::string Keccak256::hashToHex(const std::vector<uint8_t>& data) {
    return hash(data).toHex();
}

std::string Keccak256::hashToHex(const std::string& data) {
    return hash(data).toHex();
}

} // namespace quantaureum

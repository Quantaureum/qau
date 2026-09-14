// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include "quantaureum/types/hash.hpp"

namespace quantaureum {

class Keccak256 {
public:
    static Hash hash(const std::vector<uint8_t>& data);
    static Hash hash(const std::string& data);
    static Hash hash(const uint8_t* data, size_t len);

    static std::string hashToHex(const std::vector<uint8_t>& data);
    static std::string hashToHex(const std::string& data);

private:
    static constexpr size_t HASH_SIZE = 32;
    static constexpr size_t BLOCK_SIZE = 136; // 1088 bits for Keccak-256

    static void keccakF(uint64_t state[25]);
    static void absorb(uint64_t state[25], const uint8_t* data, size_t len);
    static void squeeze(uint64_t state[25], uint8_t* output, size_t len);
};

} // namespace quantaureum

// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace quantaureum {

class Hex {
public:
    static std::string toHexString(const std::vector<uint8_t>& bytes);
    static std::string toHexString(const uint8_t* data, size_t len);

    template<size_t N>
    static std::string toHexString(const std::array<uint8_t, N>& bytes) {
        return toHexString(bytes.data(), N);
    }

    static std::vector<uint8_t> toBytes(const std::string& hex);

    static bool has0xPrefix(const std::string& hex);
    static std::string add0xPrefix(const std::string& hex);
    static std::string remove0xPrefix(const std::string& hex);

    static bool isValidHex(const std::string& hex);
};

} // namespace quantaureum

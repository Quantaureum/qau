// Quantaureum C++ SDK source, version 1.0.0.
#include "quantaureum/utils/hex.hpp"
#include <stdexcept>
#include <algorithm>
#include <cctype>

namespace quantaureum {

std::string Hex::toHexString(const std::vector<uint8_t>& bytes) {
    return toHexString(bytes.data(), bytes.size());
}

std::string Hex::toHexString(const uint8_t* data, size_t len) {
    static const char hexChars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2 + 2);
    result = "0x";

    for (size_t i = 0; i < len; ++i) {
        result += hexChars[(data[i] >> 4) & 0x0F];
        result += hexChars[data[i] & 0x0F];
    }

    return result;
}

std::vector<uint8_t> Hex::toBytes(const std::string& hex) {
    std::string cleanHex = remove0xPrefix(hex);

    if (cleanHex.length() % 2 != 0) {
        cleanHex = "0" + cleanHex;
    }

    std::vector<uint8_t> result;
    result.reserve(cleanHex.length() / 2);

    for (size_t i = 0; i < cleanHex.length(); i += 2) {
        char high = cleanHex[i];
        char low = cleanHex[i + 1];

        auto hexCharToInt = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw std::invalid_argument("Invalid hex character");
        };

        result.push_back((hexCharToInt(high) << 4) | hexCharToInt(low));
    }

    return result;
}

bool Hex::has0xPrefix(const std::string& hex) {
    return hex.length() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X');
}

std::string Hex::add0xPrefix(const std::string& hex) {
    if (has0xPrefix(hex)) {
        return hex;
    }
    return "0x" + hex;
}

std::string Hex::remove0xPrefix(const std::string& hex) {
    if (has0xPrefix(hex)) {
        return hex.substr(2);
    }
    return hex;
}

bool Hex::isValidHex(const std::string& hex) {
    std::string cleanHex = remove0xPrefix(hex);
    if (cleanHex.empty()) return false;

    return std::all_of(cleanHex.begin(), cleanHex.end(), [](char c) {
        return std::isxdigit(static_cast<unsigned char>(c));
    });
}

} // namespace quantaureum

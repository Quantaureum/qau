// Quantaureum C++ SDK source, version 1.0.0.
#include "quantaureum/types/hash.hpp"
#include "quantaureum/utils/hex.hpp"
#include <stdexcept>
#include <algorithm>

namespace quantaureum {

Hash::Hash() : bytes_{} {}

Hash Hash::fromBytes(const std::array<uint8_t, SIZE>& bytes) {
    Hash hash;
    hash.bytes_ = bytes;
    return hash;
}

Hash Hash::fromHex(const std::string& hex) {
    std::string cleanHex = Hex::remove0xPrefix(hex);

    if (cleanHex.length() != SIZE * 2) {
        throw std::invalid_argument("Invalid hash length: expected 64 hex characters");
    }

    if (!Hex::isValidHex(cleanHex)) {
        throw std::invalid_argument("Invalid hex characters in hash");
    }

    auto bytes = Hex::toBytes(cleanHex);
    std::array<uint8_t, SIZE> arr;
    std::copy(bytes.begin(), bytes.end(), arr.begin());

    return fromBytes(arr);
}

std::array<uint8_t, Hash::SIZE> Hash::toBytes() const {
    return bytes_;
}

std::string Hash::toHex() const {
    return Hex::toHexString(bytes_);
}

bool Hash::operator==(const Hash& other) const {
    return bytes_ == other.bytes_;
}

bool Hash::operator!=(const Hash& other) const {
    return !(*this == other);
}

bool Hash::operator<(const Hash& other) const {
    return bytes_ < other.bytes_;
}

bool Hash::isZero() const {
    return std::all_of(bytes_.begin(), bytes_.end(), [](uint8_t b) { return b == 0; });
}

} // namespace quantaureum

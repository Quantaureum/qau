// Quantaureum C++ SDK source, version 1.0.0.
#include "quantaureum/types/address.hpp"
#include "quantaureum/utils/hex.hpp"
#include "quantaureum/utils/keccak256.hpp"
#include <stdexcept>
#include <algorithm>

namespace quantaureum {

Address::Address() : bytes_{} {}

Address Address::fromBytes(const std::array<uint8_t, SIZE>& bytes) {
    Address addr;
    addr.bytes_ = bytes;
    return addr;
}

Address Address::fromHex(const std::string& hex) {
    std::string cleanHex = Hex::remove0xPrefix(hex);

    if (cleanHex.length() != SIZE * 2) {
        throw std::invalid_argument("Invalid address length: expected 40 hex characters");
    }

    if (!Hex::isValidHex(cleanHex)) {
        throw std::invalid_argument("Invalid hex characters in address");
    }

    auto bytes = Hex::toBytes(cleanHex);
    std::array<uint8_t, SIZE> arr;
    std::copy(bytes.begin(), bytes.end(), arr.begin());

    return fromBytes(arr);
}

std::array<uint8_t, Address::SIZE> Address::toBytes() const {
    return bytes_;
}

std::string Address::toHex() const {
    return Hex::toHexString(bytes_);
}

std::string Address::toChecksumHex() const {
    std::string hex = Hex::remove0xPrefix(toHex());
    std::string lowerHex;
    lowerHex.reserve(hex.size());
    for (char c : hex) {
        lowerHex += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    // Hash the lowercase hex address
    Hash hash = Keccak256::hash(lowerHex);
    std::string hashHex = Hex::remove0xPrefix(hash.toHex());

    std::string result = "0x";
    for (size_t i = 0; i < lowerHex.size(); ++i) {
        char c = lowerHex[i];
        if (c >= 'a' && c <= 'f') {
            // Get the corresponding nibble from hash
            int hashNibble = (i % 2 == 0)
                ? (hashHex[i / 2] >= 'a' ? hashHex[i / 2] - 'a' + 10 : hashHex[i / 2] - '0') >> 0
                : 0;

            char hashChar = hashHex[i];
            int nibbleValue;
            if (hashChar >= '0' && hashChar <= '9') {
                nibbleValue = hashChar - '0';
            } else {
                nibbleValue = hashChar - 'a' + 10;
            }

            if (nibbleValue >= 8) {
                result += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            } else {
                result += c;
            }
        } else {
            result += c;
        }
    }

    return result;
}

bool Address::isValid(const std::string& hex) {
    std::string cleanHex = Hex::remove0xPrefix(hex);
    if (cleanHex.length() != SIZE * 2) {
        return false;
    }
    return Hex::isValidHex(cleanHex);
}

bool Address::operator==(const Address& other) const {
    return bytes_ == other.bytes_;
}

bool Address::operator!=(const Address& other) const {
    return !(*this == other);
}

bool Address::operator<(const Address& other) const {
    return bytes_ < other.bytes_;
}

bool Address::isZero() const {
    return std::all_of(bytes_.begin(), bytes_.end(), [](uint8_t b) { return b == 0; });
}

} // namespace quantaureum

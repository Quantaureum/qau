// Quantaureum C++ SDK source, version 1.0.0.
#include "quantaureum/types/uint256.hpp"
#include "quantaureum/utils/hex.hpp"
#include <stdexcept>
#include <algorithm>
#include <cstring>

namespace quantaureum {

Uint256::Uint256() : bytes_{} {}

Uint256::Uint256(uint64_t value) : bytes_{} {
    // Store in big-endian format
    for (int i = 0; i < 8; ++i) {
        bytes_[SIZE - 1 - i] = static_cast<uint8_t>(value >> (i * 8));
    }
}

Uint256 Uint256::fromHex(const std::string& hex) {
    std::string cleanHex = Hex::remove0xPrefix(hex);

    // Pad to 64 characters
    while (cleanHex.length() < SIZE * 2) {
        cleanHex = "0" + cleanHex;
    }

    if (cleanHex.length() > SIZE * 2) {
        throw std::invalid_argument("Hex value too large for uint256");
    }

    auto bytes = Hex::toBytes(cleanHex);
    std::array<uint8_t, SIZE> arr;
    std::copy(bytes.begin(), bytes.end(), arr.begin());

    return fromBytes(arr);
}

Uint256 Uint256::fromBytes(const std::vector<uint8_t>& bytes) {
    if (bytes.size() > SIZE) {
        throw std::invalid_argument("Byte array too large for uint256");
    }

    Uint256 result;
    size_t offset = SIZE - bytes.size();
    std::copy(bytes.begin(), bytes.end(), result.bytes_.begin() + offset);

    return result;
}

Uint256 Uint256::fromBytes(const std::array<uint8_t, SIZE>& bytes) {
    Uint256 result;
    result.bytes_ = bytes;
    return result;
}

std::string Uint256::toHex() const {
    // Find first non-zero byte
    size_t start = 0;
    while (start < SIZE - 1 && bytes_[start] == 0) {
        ++start;
    }

    std::string result = "0x";
    static const char hexChars[] = "0123456789abcdef";

    for (size_t i = start; i < SIZE; ++i) {
        result += hexChars[(bytes_[i] >> 4) & 0x0F];
        result += hexChars[bytes_[i] & 0x0F];
    }

    // Remove leading zeros but keep at least one digit
    size_t pos = 2;
    while (pos < result.length() - 1 && result[pos] == '0') {
        ++pos;
    }

    return "0x" + result.substr(pos);
}

std::vector<uint8_t> Uint256::toBytes() const {
    return std::vector<uint8_t>(bytes_.begin(), bytes_.end());
}

std::array<uint8_t, Uint256::SIZE> Uint256::toBytesArray() const {
    return bytes_;
}

uint64_t Uint256::toUint64() const {
    // Check if value fits in uint64
    for (size_t i = 0; i < SIZE - 8; ++i) {
        if (bytes_[i] != 0) {
            throw std::overflow_error("Value too large for uint64");
        }
    }

    uint64_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result = (result << 8) | bytes_[SIZE - 8 + i];
    }
    return result;
}


Uint256 Uint256::operator+(const Uint256& other) const {
    Uint256 result;
    uint16_t carry = 0;

    for (int i = SIZE - 1; i >= 0; --i) {
        uint16_t sum = static_cast<uint16_t>(bytes_[i]) +
                       static_cast<uint16_t>(other.bytes_[i]) + carry;
        result.bytes_[i] = static_cast<uint8_t>(sum & 0xFF);
        carry = sum >> 8;
    }

    return result;
}

Uint256 Uint256::operator-(const Uint256& other) const {
    Uint256 result;
    int16_t borrow = 0;

    for (int i = SIZE - 1; i >= 0; --i) {
        int16_t diff = static_cast<int16_t>(bytes_[i]) -
                       static_cast<int16_t>(other.bytes_[i]) - borrow;
        if (diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        result.bytes_[i] = static_cast<uint8_t>(diff);
    }

    return result;
}

Uint256 Uint256::operator*(const Uint256& other) const {
    Uint256 result;

    for (int i = SIZE - 1; i >= 0; --i) {
        if (bytes_[i] == 0) continue;

        uint16_t carry = 0;
        for (int j = SIZE - 1; j >= 0; --j) {
            int k = i + j - (SIZE - 1);
            if (k < 0) continue;

            uint32_t prod = static_cast<uint32_t>(bytes_[i]) *
                           static_cast<uint32_t>(other.bytes_[j]) +
                           static_cast<uint32_t>(result.bytes_[k]) + carry;
            result.bytes_[k] = static_cast<uint8_t>(prod & 0xFF);
            carry = static_cast<uint16_t>(prod >> 8);
        }
    }

    return result;
}

Uint256 Uint256::operator/(const Uint256& other) const {
    if (other.isZero()) {
        throw std::invalid_argument("Division by zero");
    }

    if (*this < other) {
        return Uint256::zero();
    }

    // Simple long division
    Uint256 quotient;
    Uint256 remainder;

    for (int i = 0; i < SIZE * 8; ++i) {
        // Shift remainder left by 1
        for (int j = 0; j < SIZE - 1; ++j) {
            remainder.bytes_[j] = (remainder.bytes_[j] << 1) | (remainder.bytes_[j + 1] >> 7);
        }
        remainder.bytes_[SIZE - 1] <<= 1;

        // Get bit i from dividend
        int byteIdx = i / 8;
        int bitIdx = 7 - (i % 8);
        if ((bytes_[byteIdx] >> bitIdx) & 1) {
            remainder.bytes_[SIZE - 1] |= 1;
        }

        // If remainder >= divisor, subtract and set quotient bit
        if (!(remainder < other)) {
            remainder = remainder - other;
            quotient.bytes_[byteIdx] |= (1 << bitIdx);
        }
    }

    return quotient;
}

Uint256 Uint256::operator%(const Uint256& other) const {
    if (other.isZero()) {
        throw std::invalid_argument("Division by zero");
    }

    Uint256 quotient = *this / other;
    return *this - (quotient * other);
}

Uint256& Uint256::operator+=(const Uint256& other) {
    *this = *this + other;
    return *this;
}

Uint256& Uint256::operator-=(const Uint256& other) {
    *this = *this - other;
    return *this;
}

bool Uint256::operator<(const Uint256& other) const {
    return bytes_ < other.bytes_;
}

bool Uint256::operator>(const Uint256& other) const {
    return other < *this;
}

bool Uint256::operator<=(const Uint256& other) const {
    return !(other < *this);
}

bool Uint256::operator>=(const Uint256& other) const {
    return !(*this < other);
}

bool Uint256::operator==(const Uint256& other) const {
    return bytes_ == other.bytes_;
}

bool Uint256::operator!=(const Uint256& other) const {
    return !(*this == other);
}

bool Uint256::isZero() const {
    return std::all_of(bytes_.begin(), bytes_.end(), [](uint8_t b) { return b == 0; });
}

Uint256 Uint256::zero() {
    return Uint256();
}

Uint256 Uint256::one() {
    return Uint256(1);
}

} // namespace quantaureum

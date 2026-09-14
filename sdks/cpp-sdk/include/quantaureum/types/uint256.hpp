// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <array>
#include <string>
#include <vector>
#include <cstdint>

namespace quantaureum {

class Uint256 {
public:
    static constexpr size_t SIZE = 32;

    Uint256();
    explicit Uint256(uint64_t value);

    static Uint256 fromHex(const std::string& hex);
    static Uint256 fromBytes(const std::vector<uint8_t>& bytes);
    static Uint256 fromBytes(const std::array<uint8_t, SIZE>& bytes);

    std::string toHex() const;
    std::vector<uint8_t> toBytes() const;
    std::array<uint8_t, SIZE> toBytesArray() const;
    uint64_t toUint64() const;

    // Arithmetic operators
    Uint256 operator+(const Uint256& other) const;
    Uint256 operator-(const Uint256& other) const;
    Uint256 operator*(const Uint256& other) const;
    Uint256 operator/(const Uint256& other) const;
    Uint256 operator%(const Uint256& other) const;

    Uint256& operator+=(const Uint256& other);
    Uint256& operator-=(const Uint256& other);

    // Comparison operators
    bool operator<(const Uint256& other) const;
    bool operator>(const Uint256& other) const;
    bool operator<=(const Uint256& other) const;
    bool operator>=(const Uint256& other) const;
    bool operator==(const Uint256& other) const;
    bool operator!=(const Uint256& other) const;

    bool isZero() const;

    static Uint256 zero();
    static Uint256 one();

private:
    std::array<uint8_t, SIZE> bytes_; // Big-endian
};

} // namespace quantaureum

// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <array>
#include <string>
#include <cstdint>

namespace quantaureum {

class Hash {
public:
    static constexpr size_t SIZE = 32;

    Hash();

    static Hash fromBytes(const std::array<uint8_t, SIZE>& bytes);
    static Hash fromHex(const std::string& hex);

    std::array<uint8_t, SIZE> toBytes() const;
    std::string toHex() const;

    bool operator==(const Hash& other) const;
    bool operator!=(const Hash& other) const;
    bool operator<(const Hash& other) const;

    bool isZero() const;

private:
    std::array<uint8_t, SIZE> bytes_;
};

} // namespace quantaureum

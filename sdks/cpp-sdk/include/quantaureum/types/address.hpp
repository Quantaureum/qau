// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <array>
#include <string>
#include <cstdint>

namespace quantaureum {

class Address {
public:
    static constexpr size_t SIZE = 20;

    Address();

    static Address fromBytes(const std::array<uint8_t, SIZE>& bytes);
    static Address fromHex(const std::string& hex);

    std::array<uint8_t, SIZE> toBytes() const;
    std::string toHex() const;
    std::string toChecksumHex() const;

    static bool isValid(const std::string& hex);

    bool operator==(const Address& other) const;
    bool operator!=(const Address& other) const;
    bool operator<(const Address& other) const;

    bool isZero() const;

private:
    std::array<uint8_t, SIZE> bytes_;
};

} // namespace quantaureum

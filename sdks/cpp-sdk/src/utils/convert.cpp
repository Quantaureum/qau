// Quantaureum C++ SDK source, version 1.0.0.
#include "quantaureum/utils/convert.hpp"
#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace quantaureum {

Uint256 Convert::getUnitMultiplier(Unit unit) {
    switch (unit) {
        case Unit::Wei:    return Uint256(1);
        case Unit::Kwei:   return Uint256(1000ULL);
        case Unit::Mwei:   return Uint256(1000000ULL);
        case Unit::Gwei:   return Uint256(1000000000ULL);
        case Unit::Szabo:  return Uint256(1000000000000ULL);
        case Unit::Finney: return Uint256(1000000000000000ULL);
        case Unit::Ether:  return Uint256(1000000000000000000ULL);
        default:
            throw std::invalid_argument("Unknown unit");
    }
}

Uint256 Convert::toWei(const std::string& value, Unit unit) {
    // Parse the decimal value
    std::string cleanValue = value;

    // Remove leading/trailing whitespace
    cleanValue.erase(0, cleanValue.find_first_not_of(" \t\n\r"));
    cleanValue.erase(cleanValue.find_last_not_of(" \t\n\r") + 1);

    if (cleanValue.empty()) {
        throw std::invalid_argument("Empty value");
    }

    // Find decimal point
    size_t decimalPos = cleanValue.find('.');
    std::string intPart, fracPart;

    if (decimalPos != std::string::npos) {
        intPart = cleanValue.substr(0, decimalPos);
        fracPart = cleanValue.substr(decimalPos + 1);
    } else {
        intPart = cleanValue;
    }

    if (intPart.empty()) {
        intPart = "0";
    }

    // Get decimals for unit
    int decimals = 0;
    switch (unit) {
        case Unit::Wei:    decimals = 0; break;
        case Unit::Kwei:   decimals = 3; break;
        case Unit::Mwei:   decimals = 6; break;
        case Unit::Gwei:   decimals = 9; break;
        case Unit::Szabo:  decimals = 12; break;
        case Unit::Finney: decimals = 15; break;
        case Unit::Ether:  decimals = 18; break;
    }

    // Pad or truncate fractional part
    if (fracPart.length() < static_cast<size_t>(decimals)) {
        fracPart += std::string(decimals - fracPart.length(), '0');
    } else if (fracPart.length() > static_cast<size_t>(decimals)) {
        fracPart = fracPart.substr(0, decimals);
    }

    // Combine integer and fractional parts
    std::string combined = intPart + fracPart;

    // Remove leading zeros
    size_t start = combined.find_first_not_of('0');
    if (start == std::string::npos) {
        return Uint256::zero();
    }
    combined = combined.substr(start);

    // Convert to Uint256
    Uint256 result = Uint256::zero();
    Uint256 ten(10);

    for (char c : combined) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            throw std::invalid_argument("Invalid character in value");
        }
        result = result * ten + Uint256(static_cast<uint64_t>(c - '0'));
    }

    return result;
}


std::string Convert::fromWei(const Uint256& wei, Unit unit) {
    if (wei.isZero()) {
        return "0";
    }

    // Get decimals for unit
    int decimals = 0;
    switch (unit) {
        case Unit::Wei:    decimals = 0; break;
        case Unit::Kwei:   decimals = 3; break;
        case Unit::Mwei:   decimals = 6; break;
        case Unit::Gwei:   decimals = 9; break;
        case Unit::Szabo:  decimals = 12; break;
        case Unit::Finney: decimals = 15; break;
        case Unit::Ether:  decimals = 18; break;
    }

    if (decimals == 0) {
        // Convert to decimal string
        Uint256 value = wei;
        Uint256 ten(10);
        std::string result;

        while (!value.isZero()) {
            Uint256 digit = value % ten;
            result = static_cast<char>('0' + digit.toUint64()) + result;
            value = value / ten;
        }

        return result.empty() ? "0" : result;
    }

    // Convert to decimal string
    Uint256 value = wei;
    Uint256 ten(10);
    std::string digits;

    while (!value.isZero()) {
        Uint256 digit = value % ten;
        digits = static_cast<char>('0' + digit.toUint64()) + digits;
        value = value / ten;
    }

    // Pad with leading zeros if needed
    while (digits.length() <= static_cast<size_t>(decimals)) {
        digits = "0" + digits;
    }

    // Insert decimal point
    size_t intLen = digits.length() - decimals;
    std::string intPart = digits.substr(0, intLen);
    std::string fracPart = digits.substr(intLen);

    // Remove trailing zeros from fractional part
    size_t lastNonZero = fracPart.find_last_not_of('0');
    if (lastNonZero != std::string::npos) {
        fracPart = fracPart.substr(0, lastNonZero + 1);
    } else {
        fracPart.clear();
    }

    if (fracPart.empty()) {
        return intPart;
    }

    return intPart + "." + fracPart;
}

Uint256 Convert::etherToWei(const std::string& ether) {
    return toWei(ether, Unit::Ether);
}

std::string Convert::weiToEther(const Uint256& wei) {
    return fromWei(wei, Unit::Ether);
}

Uint256 Convert::gweiToWei(const std::string& gwei) {
    return toWei(gwei, Unit::Gwei);
}

std::string Convert::weiToGwei(const Uint256& wei) {
    return fromWei(wei, Unit::Gwei);
}

} // namespace quantaureum

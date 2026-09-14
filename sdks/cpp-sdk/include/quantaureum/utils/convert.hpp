// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <string>
#include "quantaureum/types/uint256.hpp"

namespace quantaureum {

enum class Unit {
    Wei,
    Kwei,
    Mwei,
    Gwei,
    Szabo,
    Finney,
    Ether
};

class Convert {
public:
    static Uint256 toWei(const std::string& value, Unit unit);
    static std::string fromWei(const Uint256& wei, Unit unit);

    static Uint256 etherToWei(const std::string& ether);
    static std::string weiToEther(const Uint256& wei);

    static Uint256 gweiToWei(const std::string& gwei);
    static std::string weiToGwei(const Uint256& wei);

private:
    static Uint256 getUnitMultiplier(Unit unit);
};

} // namespace quantaureum

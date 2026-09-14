// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <vector>
#include <optional>
#include "address.hpp"
#include "hash.hpp"
#include "uint256.hpp"

namespace quantaureum {

/**
 * @brief Block information
 */
class Block {
public:
    Uint256 number;
    Hash hash;
    Hash parentHash;
    Uint256 timestamp;
    std::vector<Hash> transactions;
    Uint256 gasLimit;
    Uint256 gasUsed;
    Address miner;
    Uint256 difficulty;
    Uint256 totalDifficulty;
    std::vector<uint8_t> extraData;
    Uint256 size;
    Hash stateRoot;
    Hash transactionsRoot;
    Hash receiptsRoot;
    Hash logsBloom;
    Uint256 nonce;
};

} // namespace quantaureum

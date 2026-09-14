// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <vector>
#include <optional>
#include <string>
#include "address.hpp"
#include "hash.hpp"
#include "uint256.hpp"

namespace quantaureum {

/**
 * @brief Event log entry
 */
class Log {
public:
    Address address;
    std::vector<Hash> topics;
    std::vector<uint8_t> data;
    Uint256 blockNumber;
    Hash transactionHash;
    Uint256 transactionIndex;
    Hash blockHash;
    Uint256 logIndex;
    bool removed = false;
};

/**
 * @brief Transaction receipt
 */
class TransactionReceipt {
public:
    Hash transactionHash;
    Hash blockHash;
    Uint256 blockNumber;
    Uint256 transactionIndex;
    Address from;
    std::optional<Address> to;
    Uint256 gasUsed;
    Uint256 cumulativeGasUsed;
    std::optional<Address> contractAddress;
    std::vector<Log> logs;
    Uint256 status;
    Hash logsBloom;

    /**
     * @brief Check if transaction was successful
     */
    bool isSuccess() const { return status == Uint256(1); }
};

/**
 * @brief Log filter for querying logs
 */
class LogFilter {
public:
    class Builder;

    static Builder builder();

    std::optional<std::string> fromBlock;
    std::optional<std::string> toBlock;
    std::vector<Address> addresses;
    std::vector<std::optional<Hash>> topics;
};

class LogFilter::Builder {
public:
    Builder& fromBlock(const std::string& block);
    Builder& fromBlock(uint64_t block);
    Builder& toBlock(const std::string& block);
    Builder& toBlock(uint64_t block);
    Builder& address(const Address& addr);
    Builder& addresses(const std::vector<Address>& addrs);
    Builder& topic0(const Hash& topic);
    Builder& topic1(const Hash& topic);
    Builder& topic2(const Hash& topic);
    Builder& topic3(const Hash& topic);
    LogFilter build();

private:
    LogFilter filter_;
};

} // namespace quantaureum

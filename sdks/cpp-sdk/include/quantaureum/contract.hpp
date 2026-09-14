// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <string>
#include <vector>
#include <optional>
#include <future>
#include <chrono>
#include "types/address.hpp"
#include "types/hash.hpp"
#include "types/uint256.hpp"
#include "types/log.hpp"
#include "abi.hpp"

namespace quantaureum {

// Forward declarations
class QuantaureumClient;
class Account;

/**
 * @brief Pending transaction awaiting confirmation
 */
class PendingTransaction {
public:
    PendingTransaction(QuantaureumClient* client, const Hash& hash);

    /**
     * @brief Get transaction hash
     */
    Hash getHash() const { return hash_; }

    /**
     * @brief Wait for transaction receipt
     * @param timeout Maximum time to wait
     */
    TransactionReceipt await(std::chrono::milliseconds timeout = std::chrono::minutes(2));

    /**
     * @brief Wait for specific number of confirmations
     * @param confirmations Number of block confirmations
     * @param timeout Maximum time to wait
     */
    TransactionReceipt await(int confirmations,
                            std::chrono::milliseconds timeout = std::chrono::minutes(2));

    /**
     * @brief Async wait for transaction receipt
     */
    std::future<TransactionReceipt> awaitAsync();

private:
    QuantaureumClient* client_;
    Hash hash_;
};

/**
 * @brief Event filter for querying contract events
 */
class EventFilter {
public:
    EventFilter(QuantaureumClient* client, const Address& address,
                const AbiEvent& event);

    EventFilter& fromBlock(const std::string& block);
    EventFilter& fromBlock(uint64_t block);
    EventFilter& toBlock(const std::string& block);
    EventFilter& toBlock(uint64_t block);
    EventFilter& topic(size_t index, const Hash& value);

    /**
     * @brief Get matching logs
     */
    std::vector<Log> getLogs();

    /**
     * @brief Async get matching logs
     */
    std::future<std::vector<Log>> getLogsAsync();

    /**
     * @brief Decode log data using event ABI
     */
    std::vector<AbiValue> decodeLog(const Log& log) const;

private:
    QuantaureumClient* client_;
    Address address_;
    AbiEvent event_;
    std::optional<std::string> fromBlock_;
    std::optional<std::string> toBlock_;
    std::vector<std::optional<Hash>> topics_;
};

/**
 * @brief Smart contract wrapper
 */
class Contract {
public:
    /**
     * @brief Create contract instance
     * @param client RPC client
     * @param address Contract address
     * @param abi Contract ABI
     */
    Contract(QuantaureumClient& client, const Address& address, const Abi& abi);

    /**
     * @brief Connect signer account for transactions
     */
    Contract& connect(const Account& signer);

    /**
     * @brief Set gas limit for transactions
     */
    Contract& setGasLimit(const Uint256& gasLimit);

    /**
     * @brief Set gas price for transactions
     */
    Contract& setGasPrice(const Uint256& gasPrice);

    /**
     * @brief Set value to send with transactions
     */
    Contract& setValue(const Uint256& value);

    /**
     * @brief Get contract address
     */
    Address getAddress() const { return address_; }

    /**
     * @brief Call read-only function
     * @param method Function name
     * @param args Function arguments
     */
    std::vector<AbiValue> call(const std::string& method,
                               const std::vector<AbiValue>& args = {});

    /**
     * @brief Async call read-only function
     */
    std::future<std::vector<AbiValue>> callAsync(const std::string& method,
                                                  const std::vector<AbiValue>& args = {});

    /**
     * @brief Send state-changing transaction
     * @param method Function name
     * @param args Function arguments
     */
    PendingTransaction send(const std::string& method,
                           const std::vector<AbiValue>& args = {});

    /**
     * @brief Send transaction with value
     * @param method Function name
     * @param value Ether value to send
     * @param args Function arguments
     */
    PendingTransaction send(const std::string& method,
                           const Uint256& value,
                           const std::vector<AbiValue>& args = {});

    /**
     * @brief Encode function call data
     */
    std::vector<uint8_t> encodeFunction(const std::string& method,
                                        const std::vector<AbiValue>& args = {});

    /**
     * @brief Create event filter
     */
    EventFilter events(const std::string& eventName);

private:
    QuantaureumClient* client_;
    Address address_;
    Abi abi_;
    const Account* signer_ = nullptr;
    std::optional<Uint256> gasLimit_;
    std::optional<Uint256> gasPrice_;
    std::optional<Uint256> value_;
};

} // namespace quantaureum

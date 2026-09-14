// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <string>
#include <memory>
#include <optional>
#include <future>
#include <chrono>
#include <vector>
#include "types/address.hpp"
#include "types/hash.hpp"
#include "types/uint256.hpp"
#include "types/block.hpp"
#include "types/log.hpp"
#include "types/transaction.hpp"

namespace quantaureum {

/**
 * @brief Client configuration options
 */
struct ClientConfig {
    std::chrono::milliseconds connectTimeout = std::chrono::seconds(30);
    std::chrono::milliseconds readTimeout = std::chrono::seconds(30);
    std::chrono::milliseconds writeTimeout = std::chrono::seconds(30);

    static ClientConfig defaults() {
        return ClientConfig{};
    }
};

/**
 * @brief Quantaureum JSON-RPC client
 */
class QuantaureumClient {
public:
    /**
     * @brief Create client with RPC URL
     * @param url JSON-RPC endpoint URL
     */
    explicit QuantaureumClient(const std::string& url);

    /**
     * @brief Create client with RPC URL and config
     * @param url JSON-RPC endpoint URL
     * @param config Client configuration
     */
    QuantaureumClient(const std::string& url, const ClientConfig& config);

    ~QuantaureumClient();

    // Move only
    QuantaureumClient(QuantaureumClient&&) noexcept;
    QuantaureumClient& operator=(QuantaureumClient&&) noexcept;
    QuantaureumClient(const QuantaureumClient&) = delete;
    QuantaureumClient& operator=(const QuantaureumClient&) = delete;

    // Block methods
    Uint256 getBlockNumber();
    std::future<Uint256> getBlockNumberAsync();
    std::optional<Block> getBlockByNumber(const Uint256& number, bool fullTx = false);
    std::optional<Block> getBlockByHash(const Hash& hash, bool fullTx = false);

    // Transaction methods
    std::optional<TransactionReceipt> getTransactionReceipt(const Hash& hash);
    Hash sendRawTransaction(const std::string& signedTx);
    Hash sendRawTransaction(const std::vector<uint8_t>& signedTx);
    std::future<Hash> sendRawTransactionAsync(const std::string& signedTx);

    // Account methods
    Uint256 getBalance(const Address& address);
    Uint256 getBalance(const Address& address, const Uint256& blockNumber);
    std::future<Uint256> getBalanceAsync(const Address& address);
    uint64_t getNonce(const Address& address);
    uint64_t getPendingNonce(const Address& address);
    std::vector<uint8_t> getCode(const Address& address);

    // Gas methods
    Uint256 getGasPrice();
    Uint256 estimateGas(const CallRequest& request);
    Uint256 estimateGas(const TransactionRequest& request);

    // Call method
    std::vector<uint8_t> call(const CallRequest& request);
    std::vector<uint8_t> call(const CallRequest& request, const Uint256& blockNumber);

    // Logs
    std::vector<Log> getLogs(const LogFilter& filter);
    std::future<std::vector<Log>> getLogsAsync(const LogFilter& filter);

    // Chain info
    uint64_t getChainId();
    std::string getClientVersion();

    // Raw RPC call
    std::string rpcCall(const std::string& method, const std::string& params);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace quantaureum

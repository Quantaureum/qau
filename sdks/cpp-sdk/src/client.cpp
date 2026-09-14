// Quantaureum C++ SDK source, version 1.0.0.
#include "quantaureum/client.hpp"
#include "quantaureum/utils/hex.hpp"
#include "quantaureum/exceptions/rpc_exception.hpp"
#include <nlohmann/json.hpp>
#include <sstream>
#include <atomic>
#include <mutex>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

using json = nlohmann::json;

namespace quantaureum {

// audit-fix CPP-HIGH-2: Maximum response body size to prevent OOM from a
// malicious or misbehaving node. Without this limit, a node could send an
// arbitrarily large response, exhausting client memory (10 MB limit).
static const size_t MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

// Internal RPC client implementation
class RpcClient {
public:
    RpcClient(const std::string& url, const ClientConfig& config)
        : url_(url), config_(config), requestId_(0) {
        parseUrl(url);
#ifdef _WIN32
        initWinHttp();
#endif
    }

    ~RpcClient() {
#ifdef _WIN32
        cleanupWinHttp();
#endif
    }

    json call(const std::string& method, const json& params) {
        json request = {
            {"jsonrpc", "2.0"},
            {"method", method},
            {"params", params},
            {"id", ++requestId_}
        };

        std::string requestBody = request.dump();
        std::string response = httpPost(requestBody);

        json responseJson = json::parse(response);

        if (responseJson.contains("error")) {
            auto& error = responseJson["error"];
            int code = error.value("code", -1);
            std::string message = error.value("message", "Unknown RPC error");
            throw RpcException(code, message);
        }

        return responseJson["result"];
    }

private:
    std::string url_;
    std::string host_;
    std::string path_;
    int port_;
    bool useHttps_;
    ClientConfig config_;
    std::atomic<uint64_t> requestId_;
    std::mutex mutex_;

#ifdef _WIN32
    HINTERNET hSession_ = nullptr;
    HINTERNET hConnect_ = nullptr;

    void initWinHttp() {
        hSession_ = WinHttpOpen(L"Quantaureum-SDK/1.0",
                                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME,
                                WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession_) {
            throw RpcException(-1, "Failed to initialize WinHTTP");
        }

        DWORD timeout = static_cast<DWORD>(config_.connectTimeout.count());
        WinHttpSetTimeouts(hSession_, timeout, timeout, timeout, timeout);

        std::wstring whost(host_.begin(), host_.end());

        hConnect_ = WinHttpConnect(hSession_, whost.c_str(), static_cast<INTERNET_PORT>(port_), 0);
        if (!hConnect_) {
            WinHttpCloseHandle(hSession_);
            throw RpcException(-1, "Failed to connect to server");
        }
    }

    void cleanupWinHttp() {
        if (hConnect_) WinHttpCloseHandle(hConnect_);
        if (hSession_) WinHttpCloseHandle(hSession_);
    }

    std::string httpPost(const std::string& body) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::wstring wpath(path_.begin(), path_.end());

        DWORD flags = useHttps_ ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hRequest = WinHttpOpenRequest(hConnect_, L"POST", wpath.c_str(),
                                                 nullptr, WINHTTP_NO_REFERER,
                                                 WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hRequest) {
            throw RpcException(-1, "Failed to create HTTP request");
        }

        const wchar_t* headers = L"Content-Type: application/json\r\n";
        WinHttpAddRequestHeaders(hRequest, headers, static_cast<DWORD>(-1), WINHTTP_ADDREQ_FLAG_ADD);

        BOOL result = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                          (LPVOID)body.c_str(), static_cast<DWORD>(body.size()),
                                          static_cast<DWORD>(body.size()), 0);
        if (!result) {
            WinHttpCloseHandle(hRequest);
            throw RpcException(-1, "Failed to send HTTP request");
        }

        result = WinHttpReceiveResponse(hRequest, nullptr);
        if (!result) {
            WinHttpCloseHandle(hRequest);
            throw RpcException(-1, "Failed to receive HTTP response");
        }

        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);

        if (statusCode != 200) {
            WinHttpCloseHandle(hRequest);
            throw RpcException(static_cast<int>(statusCode), "HTTP error: " + std::to_string(statusCode));
        }

        std::string response;
        DWORD bytesAvailable = 0;
        do {
            bytesAvailable = 0;
            WinHttpQueryDataAvailable(hRequest, &bytesAvailable);

            if (bytesAvailable > 0) {
                // audit-fix CPP-HIGH-2: Check response size limit before reading
                if (response.size() + bytesAvailable > MAX_RESPONSE_BYTES) {
                    WinHttpCloseHandle(hRequest);
                    throw RpcException(-1, "Response exceeds maximum allowed size (" +
                        std::to_string(MAX_RESPONSE_BYTES) + " bytes)");
                }
                std::vector<char> buffer(bytesAvailable + 1);
                DWORD bytesRead = 0;
                WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead);
                response.append(buffer.data(), bytesRead);
            }
        } while (bytesAvailable > 0);

        WinHttpCloseHandle(hRequest);
        return response;
    }
#else
    void initWinHttp() {}
    void cleanupWinHttp() {}
    std::string httpPost(const std::string&) {
        throw RpcException(-1, "HTTP client not available on this platform");
    }
#endif

    void parseUrl(const std::string& url) {
        size_t schemeEnd = url.find("://");
        if (schemeEnd == std::string::npos) {
            throw std::invalid_argument("Invalid URL: missing scheme");
        }

        std::string scheme = url.substr(0, schemeEnd);
        useHttps_ = (scheme == "https");
        port_ = useHttps_ ? 443 : 80;

        size_t hostStart = schemeEnd + 3;
        size_t pathStart = url.find('/', hostStart);

        std::string hostPort;
        if (pathStart == std::string::npos) {
            hostPort = url.substr(hostStart);
            path_ = "/";
        } else {
            hostPort = url.substr(hostStart, pathStart - hostStart);
            path_ = url.substr(pathStart);
        }

        size_t colonPos = hostPort.find(':');
        if (colonPos != std::string::npos) {
            host_ = hostPort.substr(0, colonPos);
            port_ = std::stoi(hostPort.substr(colonPos + 1));
        } else {
            host_ = hostPort;
        }
    }
};


// QuantaureumClient implementation
class QuantaureumClient::Impl {
public:
    Impl(const std::string& url, const ClientConfig& config)
        : rpc_(url, config) {}

    RpcClient rpc_;
};

QuantaureumClient::QuantaureumClient(const std::string& url)
    : impl_(std::make_unique<Impl>(url, ClientConfig::defaults())) {}

QuantaureumClient::QuantaureumClient(const std::string& url, const ClientConfig& config)
    : impl_(std::make_unique<Impl>(url, config)) {}

QuantaureumClient::~QuantaureumClient() = default;

QuantaureumClient::QuantaureumClient(QuantaureumClient&&) noexcept = default;
QuantaureumClient& QuantaureumClient::operator=(QuantaureumClient&&) noexcept = default;

// Block methods
Uint256 QuantaureumClient::getBlockNumber() {
    json result = impl_->rpc_.call("eth_blockNumber", json::array());
    return Uint256::fromHex(result.get<std::string>());
}

std::future<Uint256> QuantaureumClient::getBlockNumberAsync() {
    return std::async(std::launch::async, [this]() {
        return getBlockNumber();
    });
}

std::optional<Block> QuantaureumClient::getBlockByNumber(const Uint256& number, bool fullTx) {
    std::string blockNum = number.toHex();
    json result = impl_->rpc_.call("eth_getBlockByNumber", {blockNum, fullTx});

    if (result.is_null()) {
        return std::nullopt;
    }

    Block block;
    block.number = Uint256::fromHex(result["number"].get<std::string>());
    block.hash = Hash::fromHex(result["hash"].get<std::string>());
    block.parentHash = Hash::fromHex(result["parentHash"].get<std::string>());
    block.timestamp = Uint256::fromHex(result["timestamp"].get<std::string>());
    block.gasLimit = Uint256::fromHex(result["gasLimit"].get<std::string>());
    block.gasUsed = Uint256::fromHex(result["gasUsed"].get<std::string>());
    block.miner = Address::fromHex(result["miner"].get<std::string>());

    if (result.contains("difficulty") && !result["difficulty"].is_null()) {
        block.difficulty = Uint256::fromHex(result["difficulty"].get<std::string>());
    }

    return block;
}

std::optional<Block> QuantaureumClient::getBlockByHash(const Hash& hash, bool fullTx) {
    json result = impl_->rpc_.call("eth_getBlockByHash", {hash.toHex(), fullTx});

    if (result.is_null()) {
        return std::nullopt;
    }

    Block block;
    block.number = Uint256::fromHex(result["number"].get<std::string>());
    block.hash = Hash::fromHex(result["hash"].get<std::string>());
    block.parentHash = Hash::fromHex(result["parentHash"].get<std::string>());
    block.timestamp = Uint256::fromHex(result["timestamp"].get<std::string>());
    block.gasLimit = Uint256::fromHex(result["gasLimit"].get<std::string>());
    block.gasUsed = Uint256::fromHex(result["gasUsed"].get<std::string>());
    block.miner = Address::fromHex(result["miner"].get<std::string>());

    return block;
}

// Transaction methods
std::optional<TransactionReceipt> QuantaureumClient::getTransactionReceipt(const Hash& hash) {
    json result = impl_->rpc_.call("eth_getTransactionReceipt", {hash.toHex()});

    if (result.is_null()) {
        return std::nullopt;
    }

    TransactionReceipt receipt;
    receipt.transactionHash = Hash::fromHex(result["transactionHash"].get<std::string>());
    receipt.blockHash = Hash::fromHex(result["blockHash"].get<std::string>());
    receipt.blockNumber = Uint256::fromHex(result["blockNumber"].get<std::string>());
    receipt.from = Address::fromHex(result["from"].get<std::string>());
    if (!result["to"].is_null()) {
        receipt.to = Address::fromHex(result["to"].get<std::string>());
    }
    receipt.gasUsed = Uint256::fromHex(result["gasUsed"].get<std::string>());
    receipt.cumulativeGasUsed = Uint256::fromHex(result["cumulativeGasUsed"].get<std::string>());
    receipt.status = Uint256::fromHex(result["status"].get<std::string>());

    // Parse logs
    if (result.contains("logs") && result["logs"].is_array()) {
        for (const auto& logJson : result["logs"]) {
            Log log;
            log.address = Address::fromHex(logJson["address"].get<std::string>());
            log.data = Hex::toBytes(logJson["data"].get<std::string>());
            log.blockNumber = Uint256::fromHex(logJson["blockNumber"].get<std::string>());
            log.transactionHash = Hash::fromHex(logJson["transactionHash"].get<std::string>());
            log.logIndex = Uint256::fromHex(logJson["logIndex"].get<std::string>());

            if (logJson.contains("topics") && logJson["topics"].is_array()) {
                for (const auto& topic : logJson["topics"]) {
                    log.topics.push_back(Hash::fromHex(topic.get<std::string>()));
                }
            }

            receipt.logs.push_back(log);
        }
    }

    return receipt;
}

Hash QuantaureumClient::sendRawTransaction(const std::string& signedTx) {
    json result = impl_->rpc_.call("eth_sendRawTransaction", {signedTx});
    return Hash::fromHex(result.get<std::string>());
}

Hash QuantaureumClient::sendRawTransaction(const std::vector<uint8_t>& signedTx) {
    return sendRawTransaction(Hex::toHexString(signedTx));
}

std::future<Hash> QuantaureumClient::sendRawTransactionAsync(const std::string& signedTx) {
    return std::async(std::launch::async, [this, signedTx]() {
        return sendRawTransaction(signedTx);
    });
}


// Account methods
Uint256 QuantaureumClient::getBalance(const Address& address) {
    json result = impl_->rpc_.call("eth_getBalance", {address.toHex(), "latest"});
    return Uint256::fromHex(result.get<std::string>());
}

Uint256 QuantaureumClient::getBalance(const Address& address, const Uint256& blockNumber) {
    json result = impl_->rpc_.call("eth_getBalance", {address.toHex(), blockNumber.toHex()});
    return Uint256::fromHex(result.get<std::string>());
}

std::future<Uint256> QuantaureumClient::getBalanceAsync(const Address& address) {
    return std::async(std::launch::async, [this, address]() {
        return getBalance(address);
    });
}

uint64_t QuantaureumClient::getNonce(const Address& address) {
    json result = impl_->rpc_.call("eth_getTransactionCount", {address.toHex(), "latest"});
    return Uint256::fromHex(result.get<std::string>()).toUint64();
}

uint64_t QuantaureumClient::getPendingNonce(const Address& address) {
    json result = impl_->rpc_.call("eth_getTransactionCount", {address.toHex(), "pending"});
    return Uint256::fromHex(result.get<std::string>()).toUint64();
}

std::vector<uint8_t> QuantaureumClient::getCode(const Address& address) {
    json result = impl_->rpc_.call("eth_getCode", {address.toHex(), "latest"});
    return Hex::toBytes(result.get<std::string>());
}

// Gas methods
Uint256 QuantaureumClient::getGasPrice() {
    json result = impl_->rpc_.call("eth_gasPrice", json::array());
    return Uint256::fromHex(result.get<std::string>());
}

Uint256 QuantaureumClient::estimateGas(const CallRequest& request) {
    json params = json::object();

    if (request.getFrom()) {
        params["from"] = request.getFrom()->toHex();
    }
    params["to"] = request.getTo().toHex();
    if (request.getData()) {
        params["data"] = Hex::toHexString(*request.getData());
    }
    if (request.getValue()) {
        params["value"] = request.getValue()->toHex();
    }
    if (request.getGas()) {
        params["gas"] = request.getGas()->toHex();
    }

    json result = impl_->rpc_.call("eth_estimateGas", {params});
    return Uint256::fromHex(result.get<std::string>());
}

Uint256 QuantaureumClient::estimateGas(const TransactionRequest& request) {
    json params = json::object();

    if (request.getFrom()) {
        params["from"] = request.getFrom()->toHex();
    }
    if (request.getTo()) {
        params["to"] = request.getTo()->toHex();
    }
    if (request.getData()) {
        params["data"] = Hex::toHexString(*request.getData());
    }
    if (request.getValue()) {
        params["value"] = request.getValue()->toHex();
    }
    if (request.getGas()) {
        params["gas"] = request.getGas()->toHex();
    }

    json result = impl_->rpc_.call("eth_estimateGas", {params});
    return Uint256::fromHex(result.get<std::string>());
}

// Call method
std::vector<uint8_t> QuantaureumClient::call(const CallRequest& request) {
    json params = json::object();

    params["to"] = request.getTo().toHex();
    if (request.getData()) {
        params["data"] = Hex::toHexString(*request.getData());
    }
    if (request.getFrom()) {
        params["from"] = request.getFrom()->toHex();
    }
    if (request.getValue()) {
        params["value"] = request.getValue()->toHex();
    }
    if (request.getGas()) {
        params["gas"] = request.getGas()->toHex();
    }

    json result = impl_->rpc_.call("eth_call", {params, "latest"});
    return Hex::toBytes(result.get<std::string>());
}

std::vector<uint8_t> QuantaureumClient::call(const CallRequest& request, const Uint256& blockNumber) {
    json params = json::object();

    params["to"] = request.getTo().toHex();
    if (request.getData()) {
        params["data"] = Hex::toHexString(*request.getData());
    }
    if (request.getFrom()) {
        params["from"] = request.getFrom()->toHex();
    }
    if (request.getValue()) {
        params["value"] = request.getValue()->toHex();
    }
    if (request.getGas()) {
        params["gas"] = request.getGas()->toHex();
    }

    json result = impl_->rpc_.call("eth_call", {params, blockNumber.toHex()});
    return Hex::toBytes(result.get<std::string>());
}


// Logs
std::vector<Log> QuantaureumClient::getLogs(const LogFilter& filter) {
    json params = json::object();

    if (filter.fromBlock) {
        params["fromBlock"] = *filter.fromBlock;
    }
    if (filter.toBlock) {
        params["toBlock"] = *filter.toBlock;
    }
    if (!filter.addresses.empty()) {
        if (filter.addresses.size() == 1) {
            params["address"] = filter.addresses[0].toHex();
        } else {
            json addrs = json::array();
            for (const auto& addr : filter.addresses) {
                addrs.push_back(addr.toHex());
            }
            params["address"] = addrs;
        }
    }
    if (!filter.topics.empty()) {
        json topicsJson = json::array();
        for (const auto& topic : filter.topics) {
            if (topic) {
                topicsJson.push_back(topic->toHex());
            } else {
                topicsJson.push_back(nullptr);
            }
        }
        params["topics"] = topicsJson;
    }

    json result = impl_->rpc_.call("eth_getLogs", {params});

    std::vector<Log> logs;
    if (result.is_array()) {
        for (const auto& logJson : result) {
            Log log;
            log.address = Address::fromHex(logJson["address"].get<std::string>());
            log.data = Hex::toBytes(logJson["data"].get<std::string>());
            log.blockNumber = Uint256::fromHex(logJson["blockNumber"].get<std::string>());
            log.transactionHash = Hash::fromHex(logJson["transactionHash"].get<std::string>());
            log.logIndex = Uint256::fromHex(logJson["logIndex"].get<std::string>());

            if (logJson.contains("topics") && logJson["topics"].is_array()) {
                for (const auto& topic : logJson["topics"]) {
                    log.topics.push_back(Hash::fromHex(topic.get<std::string>()));
                }
            }

            logs.push_back(log);
        }
    }

    return logs;
}

std::future<std::vector<Log>> QuantaureumClient::getLogsAsync(const LogFilter& filter) {
    return std::async(std::launch::async, [this, filter]() {
        return getLogs(filter);
    });
}

// Chain info
uint64_t QuantaureumClient::getChainId() {
    json result = impl_->rpc_.call("eth_chainId", json::array());
    return Uint256::fromHex(result.get<std::string>()).toUint64();
}

std::string QuantaureumClient::getClientVersion() {
    json result = impl_->rpc_.call("web3_clientVersion", json::array());
    return result.get<std::string>();
}

// Raw RPC call
std::string QuantaureumClient::rpcCall(const std::string& method, const std::string& params) {
    json paramsJson = json::parse(params);
    json result = impl_->rpc_.call(method, paramsJson);
    return result.dump();
}

} // namespace quantaureum

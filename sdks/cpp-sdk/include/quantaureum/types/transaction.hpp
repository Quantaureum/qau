// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <optional>
#include <vector>
#include <string>
#include "address.hpp"
#include "hash.hpp"
#include "uint256.hpp"

namespace quantaureum {

/**
 * @brief Transaction request for building transactions
 */
class TransactionRequest {
public:
    class Builder;

    static Builder builder();

    std::optional<Address> getFrom() const { return from_; }
    std::optional<Address> getTo() const { return to_; }
    std::optional<Uint256> getValue() const { return value_; }
    std::optional<Uint256> getGas() const { return gas_; }
    std::optional<Uint256> getGasPrice() const { return gasPrice_; }
    std::optional<uint64_t> getNonce() const { return nonce_; }
    std::optional<std::vector<uint8_t>> getData() const { return data_; }

private:
    std::optional<Address> from_;
    std::optional<Address> to_;
    std::optional<Uint256> value_;
    std::optional<Uint256> gas_;
    std::optional<Uint256> gasPrice_;
    std::optional<uint64_t> nonce_;
    std::optional<std::vector<uint8_t>> data_;

    friend class Builder;
};

class TransactionRequest::Builder {
public:
    Builder& from(const Address& from);
    Builder& from(const std::string& from);
    Builder& to(const Address& to);
    Builder& to(const std::string& to);
    Builder& value(const Uint256& value);
    Builder& value(uint64_t value);
    Builder& gas(const Uint256& gas);
    Builder& gas(uint64_t gas);
    Builder& gasLimit(const Uint256& gasLimit);
    Builder& gasLimit(uint64_t gasLimit);
    Builder& gasPrice(const Uint256& gasPrice);
    Builder& gasPrice(uint64_t gasPrice);
    Builder& nonce(uint64_t nonce);
    Builder& data(const std::vector<uint8_t>& data);
    Builder& data(const std::string& hexData);
    TransactionRequest build();

private:
    TransactionRequest tx_;
};

/**
 * @brief Signed transaction ready for broadcast
 */
class SignedTransaction {
public:
    /**
     * @brief RLP encode the signed transaction
     */
    std::vector<uint8_t> encode() const;

    /**
     * @brief Get RLP encoded transaction as hex string
     */
    std::string encodeHex() const;

    /**
     * @brief Get transaction hash
     */
    Hash hash() const;

    /**
     * @brief Recover signer address from signed transaction
     */
    static Address recoverSigner(const SignedTransaction& tx);

    // Transaction fields
    uint64_t nonce;
    Uint256 gasPrice;
    Uint256 gasLimit;
    std::optional<Address> to;
    Uint256 value;
    std::vector<uint8_t> data;

    // Signature
    uint8_t v;
    std::array<uint8_t, 32> r;
    std::array<uint8_t, 32> s;

    // Chain ID (for EIP-155)
    uint64_t chainId;
};

/**
 * @brief Call request for eth_call
 */
class CallRequest {
public:
    class Builder;

    static Builder builder();

    std::optional<Address> getFrom() const { return from_; }
    Address getTo() const { return to_; }
    std::optional<Uint256> getValue() const { return value_; }
    std::optional<Uint256> getGas() const { return gas_; }
    std::optional<Uint256> getGasPrice() const { return gasPrice_; }
    std::optional<std::vector<uint8_t>> getData() const { return data_; }

private:
    std::optional<Address> from_;
    Address to_;
    std::optional<Uint256> value_;
    std::optional<Uint256> gas_;
    std::optional<Uint256> gasPrice_;
    std::optional<std::vector<uint8_t>> data_;

    friend class Builder;
};

class CallRequest::Builder {
public:
    Builder& from(const Address& from);
    Builder& from(const std::string& from);
    Builder& to(const Address& to);
    Builder& to(const std::string& to);
    Builder& value(const Uint256& value);
    Builder& gas(const Uint256& gas);
    Builder& gasPrice(const Uint256& gasPrice);
    Builder& data(const std::vector<uint8_t>& data);
    Builder& data(const std::string& hexData);
    CallRequest build();

private:
    CallRequest req_;
};

} // namespace quantaureum

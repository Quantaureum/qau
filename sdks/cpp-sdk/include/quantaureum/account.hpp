// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <array>
#include <string>
#include <optional>
#include <vector>
#include "types/address.hpp"
#include "types/hash.hpp"
#include "utils/secure_memory.hpp"

namespace quantaureum {

// Forward declarations
class TransactionRequest;
class SignedTransaction;

/**
 * @brief ECDSA signature with r, s, v components
 */
class Signature {
public:
    std::array<uint8_t, 32> r;
    std::array<uint8_t, 32> s;
    uint8_t v;

    /**
     * @brief Convert signature to hex string (65 bytes: r + s + v)
     */
    std::string toHex() const;

    /**
     * @brief Parse signature from hex string
     */
    static Signature fromHex(const std::string& hex);

    /**
     * @brief Get signature as 65-byte array
     */
    std::vector<uint8_t> toBytes() const;
};

/**
 * @brief Ethereum-compatible account for signing transactions and messages
 */
class Account {
public:
    /**
     * @brief Create a new random account
     */
    static Account create();

    /**
     * @brief Create account from private key bytes
     * @param privateKey 32-byte private key
     */
    static Account fromPrivateKey(const std::array<uint8_t, 32>& privateKey);

    /**
     * @brief Create account from private key hex string
     * @param hex Private key as hex string (with or without 0x prefix)
     */
    static Account fromPrivateKeyHex(const std::string& hex);

    /**
     * @brief Create account from BIP-39 mnemonic phrase
     * @param mnemonic Space-separated mnemonic words
     * @param path Derivation path (default: m/44'/60'/0'/0/0)
     */
    static Account fromMnemonic(const std::string& mnemonic,
                                const std::string& path = "m/44'/60'/0'/0/0");

    /**
     * @brief Generate a new BIP-39 mnemonic phrase
     * @param words Number of words (12, 15, 18, 21, or 24)
     */
    static std::string generateMnemonic(int words = 12);

    /**
     * @brief Get the account's address
     */
    Address getAddress() const;

    /**
     * @brief Get the private key as bytes
     * @warning This exposes sensitive data - use with caution
     */
    std::array<uint8_t, 32> getPrivateKey() const;

    /**
     * @brief Get the private key as hex string
     * @warning This exposes sensitive data - use with caution
     */
    std::string getPrivateKeyHex() const;

    /**
     * @brief Get the public key as bytes (uncompressed, 64 bytes)
     */
    std::array<uint8_t, 64> getPublicKey() const;

    /**
     * @brief Get the mnemonic if account was created from one
     */
    std::optional<std::string> getMnemonic() const;

    /**
     * @brief Sign a transaction
     * @param tx Transaction request to sign
     * @param chainId Chain ID for EIP-155 replay protection
     */
    SignedTransaction signTransaction(const TransactionRequest& tx, uint64_t chainId) const;

    /**
     * @brief Sign a message (Ethereum signed message format)
     * @param message Message string to sign
     */
    Signature signMessage(const std::string& message) const;

    /**
     * @brief Sign raw message bytes
     * @param message Message bytes to sign
     */
    Signature signMessage(const std::vector<uint8_t>& message) const;

    /**
     * @brief Sign a hash directly (32 bytes)
     * @param hash Hash to sign
     */
    Signature signHash(const Hash& hash) const;

    /**
     * @brief Recover address from signed message
     * @param message Original message
     * @param sig Signature
     */
    static Address recoverAddress(const std::string& message, const Signature& sig);

    /**
     * @brief Recover address from signed hash
     * @param hash Original hash
     * @param sig Signature
     */
    static Address recoverAddressFromHash(const Hash& hash, const Signature& sig);

private:
    Account() = default;

    // Use SecureArray for automatic memory zeroing on destruction
    utils::SecureArray<uint8_t, 32> privateKey_;
    std::array<uint8_t, 64> publicKey_;
    Address address_;
    std::optional<std::string> mnemonic_;

    void derivePublicKeyAndAddress();
};

} // namespace quantaureum

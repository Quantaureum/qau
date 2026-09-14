// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <string>
#include <vector>
#include <array>
#include <cstdint>

namespace quantaureum {
namespace crypto {

/**
 * @brief BIP-39 mnemonic phrase implementation
 *
 * Implements Bitcoin Improvement Proposal 39 for generating deterministic
 * keys from mnemonic phrases.
 *
 * Features:
 * - Standard 2048-word English wordlist
 * - Support for 12, 15, 18, 21, and 24 word mnemonics
 * - Checksum validation
 * - PBKDF2-HMAC-SHA512 for seed derivation
 *
 * Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 */
class BIP39 {
public:
    /**
     * @brief Generate a new BIP-39 mnemonic phrase
     * @param wordCount Number of words (12, 15, 18, 21, or 24)
     * @return Space-separated mnemonic phrase
     * @throws std::invalid_argument if wordCount is invalid
     *
     * Entropy bits: 128, 160, 192, 224, or 256
     * Checksum bits: 4, 5, 6, 7, or 8
     */
    static std::string generateMnemonic(int wordCount = 12);

    /**
     * @brief Validate a BIP-39 mnemonic phrase
     * @param mnemonic Space-separated mnemonic phrase
     * @return true if mnemonic is valid (words exist and checksum matches)
     */
    static bool validateMnemonic(const std::string& mnemonic);

    /**
     * @brief Convert mnemonic to seed using PBKDF2
     * @param mnemonic Space-separated mnemonic phrase
     * @param passphrase Optional passphrase (default: empty)
     * @return 64-byte seed for BIP-32 derivation
     * @throws std::invalid_argument if mnemonic is invalid
     *
     * Uses PBKDF2-HMAC-SHA512 with 2048 iterations.
     * Salt: "mnemonic" + passphrase
     */
    static std::array<uint8_t, 64> mnemonicToSeed(
        const std::string& mnemonic,
        const std::string& passphrase = ""
    );

    /**
     * @brief Convert mnemonic to entropy
     * @param mnemonic Space-separated mnemonic phrase
     * @return Entropy bytes (16, 20, 24, 28, or 32 bytes)
     * @throws std::invalid_argument if mnemonic is invalid
     */
    static std::vector<uint8_t> mnemonicToEntropy(const std::string& mnemonic);

    /**
     * @brief Convert entropy to mnemonic
     * @param entropy Entropy bytes (16, 20, 24, 28, or 32 bytes)
     * @return Space-separated mnemonic phrase
     * @throws std::invalid_argument if entropy size is invalid
     */
    static std::string entropyToMnemonic(const std::vector<uint8_t>& entropy);

    /**
     * @brief Get word from wordlist by index
     * @param index Word index (0-2047)
     * @return Word from BIP-39 English wordlist
     * @throws std::out_of_range if index is invalid
     */
    static std::string getWord(size_t index);

    /**
     * @brief Find word index in wordlist
     * @param word Word to search for
     * @return Word index (0-2047) or -1 if not found
     */
    static int findWord(const std::string& word);

private:
    BIP39() = delete;

    // BIP-39 English wordlist (2048 words)
    static const char* const WORDLIST[2048];

    // Calculate checksum for entropy
    static uint8_t calculateChecksum(const std::vector<uint8_t>& entropy);
};

} // namespace crypto
} // namespace quantaureum

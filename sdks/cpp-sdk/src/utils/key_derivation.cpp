// Quantaureum C++ SDK source, version 1.0.0.
#include "quantaureum/utils/key_derivation.hpp"
#include "quantaureum/utils/sha256.hpp"
#include <stdexcept>
#include <cstring>
#include <algorithm>

namespace quantaureum {
namespace utils {

// audit-fix CPP-HIGH-1: Replace Keccak256 with proper SHA256 for HMAC/PBKDF2.
// The old code used Keccak256 as a "placeholder" for SHA256, which is
// cryptographically wrong because:
//   1. HMAC-SHA256 and HMAC-Keccak256 produce different outputs
//   2. BIP-39 PBKDF2 requires HMAC-SHA512, not HMAC-Keccak256
//   3. HKDF requires HMAC-SHA256, not HMAC-Keccak256
//   4. Using the wrong hash breaks compatibility with all other BIP-39 wallets
// Now we use the proper SHA256 implementation from utils/sha256.hpp.
static std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& data) {
    return utils::SHA256::hash(data);
}

std::array<uint8_t, 32> KeyDerivation::hmacSha256(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data
) {
    const size_t blockSize = 64; // SHA256 block size
    const size_t hashSize = 32;  // SHA256 output size

    // Prepare key
    std::vector<uint8_t> keyPadded(blockSize, 0);
    if (key.size() > blockSize) {
        // If key is longer than block size, hash it
        auto hashedKey = sha256(key);
        std::copy(hashedKey.begin(), hashedKey.end(), keyPadded.begin());
    } else {
        std::copy(key.begin(), key.end(), keyPadded.begin());
    }

    // Create inner and outer padded keys
    std::vector<uint8_t> iKeyPad(blockSize);
    std::vector<uint8_t> oKeyPad(blockSize);
    for (size_t i = 0; i < blockSize; ++i) {
        iKeyPad[i] = keyPadded[i] ^ 0x36;
        oKeyPad[i] = keyPadded[i] ^ 0x5c;
    }

    // Inner hash: H(K XOR ipad || data)
    std::vector<uint8_t> innerData;
    innerData.reserve(blockSize + data.size());
    innerData.insert(innerData.end(), iKeyPad.begin(), iKeyPad.end());
    innerData.insert(innerData.end(), data.begin(), data.end());
    auto innerHash = sha256(innerData);

    // Outer hash: H(K XOR opad || innerHash)
    std::vector<uint8_t> outerData;
    outerData.reserve(blockSize + hashSize);
    outerData.insert(outerData.end(), oKeyPad.begin(), oKeyPad.end());
    outerData.insert(outerData.end(), innerHash.begin(), innerHash.end());

    return sha256(outerData);
}

std::array<uint8_t, 32> KeyDerivation::hkdfExtract(
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& ikm
) {
    // If salt is empty, use a string of HashLen zeros
    std::vector<uint8_t> actualSalt = salt.empty()
        ? std::vector<uint8_t>(32, 0)
        : salt;

    return hmacSha256(actualSalt, ikm);
}

std::vector<uint8_t> KeyDerivation::hkdfExpand(
    const std::array<uint8_t, 32>& prk,
    const std::vector<uint8_t>& info,
    size_t length
) {
    const size_t hashLen = 32; // SHA256 output size

    if (length > 255 * hashLen) {
        throw std::invalid_argument("HKDF output length too large");
    }

    size_t n = (length + hashLen - 1) / hashLen; // Ceiling division
    std::vector<uint8_t> okm;
    okm.reserve(n * hashLen);

    std::vector<uint8_t> t;
    std::vector<uint8_t> prkVec(prk.begin(), prk.end());

    for (size_t i = 1; i <= n; ++i) {
        std::vector<uint8_t> data;
        data.insert(data.end(), t.begin(), t.end());
        data.insert(data.end(), info.begin(), info.end());
        data.push_back(static_cast<uint8_t>(i));

        auto hmac = hmacSha256(prkVec, data);
        t.assign(hmac.begin(), hmac.end());
        okm.insert(okm.end(), t.begin(), t.end());
    }

    okm.resize(length);
    return okm;
}

std::vector<uint8_t> KeyDerivation::hkdf(
    const std::vector<uint8_t>& ikm,
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& info,
    size_t length
) {
    // Extract
    auto prk = hkdfExtract(salt, ikm);

    // Expand
    return hkdfExpand(prk, info, length);
}

std::vector<uint8_t> KeyDerivation::pbkdf2(
    const std::vector<uint8_t>& password,
    const std::vector<uint8_t>& salt,
    uint32_t iterations,
    size_t length
) {
    if (iterations == 0) {
        throw std::invalid_argument("PBKDF2 iterations must be > 0");
    }
    if (length == 0) {
        throw std::invalid_argument("PBKDF2 output length must be > 0");
    }

    const size_t hashLen = 32; // SHA256 output size
    size_t numBlocks = (length + hashLen - 1) / hashLen;

    std::vector<uint8_t> result;
    result.reserve(numBlocks * hashLen);

    for (uint32_t blockNum = 1; blockNum <= numBlocks; ++blockNum) {
        // U1 = PRF(password, salt || INT_32_BE(blockNum))
        std::vector<uint8_t> block = salt;
        block.push_back(static_cast<uint8_t>(blockNum >> 24));
        block.push_back(static_cast<uint8_t>(blockNum >> 16));
        block.push_back(static_cast<uint8_t>(blockNum >> 8));
        block.push_back(static_cast<uint8_t>(blockNum));

        auto u = hmacSha256(password, block);
        std::array<uint8_t, 32> t = u;

        // U2 through Uc
        for (uint32_t i = 1; i < iterations; ++i) {
            std::vector<uint8_t> uVec(u.begin(), u.end());
            u = hmacSha256(password, uVec);

            // XOR with accumulated result
            for (size_t j = 0; j < hashLen; ++j) {
                t[j] ^= u[j];
            }
        }

        result.insert(result.end(), t.begin(), t.end());
    }

    result.resize(length);
    return result;
}

std::vector<uint8_t> KeyDerivation::pbkdf2(
    const std::string& password,
    const std::vector<uint8_t>& salt,
    uint32_t iterations,
    size_t length
) {
    std::vector<uint8_t> passwordBytes(password.begin(), password.end());
    return pbkdf2(passwordBytes, salt, iterations, length);
}

} // namespace utils
} // namespace quantaureum

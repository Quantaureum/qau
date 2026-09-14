// Quantaureum C++ SDK source, version 1.0.0.
#include "quantaureum/crypto/bip32.hpp"
#include "quantaureum/utils/key_derivation.hpp"
#include "quantaureum/crypto/ecdsa.hpp"
#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <cstring>

#ifdef HAVE_SECP256K1
#include <secp256k1.h>
#endif

namespace quantaureum {
namespace crypto {

BIP32::ExtendedKey BIP32::deriveMasterKey(const std::array<uint8_t, 64>& seed) {
    // BIP-32 master key derivation
    // HMAC-SHA512(key="Bitcoin seed", data=seed)
    std::string hmacKey = "Bitcoin seed";
    std::vector<uint8_t> keyVec(hmacKey.begin(), hmacKey.end());
    std::vector<uint8_t> seedVec(seed.begin(), seed.end());

    auto hmac = hmacSha512(keyVec, seedVec);

    ExtendedKey master;
    std::memcpy(master.key.data(), hmac.data(), 32);
    std::memcpy(master.chainCode.data(), hmac.data() + 32, 32);
    master.depth = 0;
    master.childNumber = 0;
    master.fingerprint.fill(0);
    master.isPrivate = true;

    // Validate private key
    if (!ECDSA::validatePrivateKey(master.key)) {
        throw std::runtime_error("Invalid master key derived from seed");
    }

    return master;
}

BIP32::ExtendedKey BIP32::deriveChild(const ExtendedKey& parent, uint32_t index) {
    if (!parent.isPrivate && index >= HARDENED_OFFSET) {
        throw std::runtime_error("Cannot derive hardened child from public key");
    }

    // Prepare data for HMAC
    std::vector<uint8_t> data;

    if (index >= HARDENED_OFFSET) {
        // Hardened derivation: data = 0x00 || private_key || index
        data.push_back(0x00);
        data.insert(data.end(), parent.key.begin(), parent.key.end());
    } else {
        // Normal derivation: data = compressed_public_key || index
        // BIP32 uses compressed public keys (33 bytes)
        auto pubKey = ECDSA::derivePublicKey(parent.key);

        // Compress public key: 0x02 or 0x03 prefix + x coordinate (32 bytes)
        uint8_t prefix = (pubKey[63] & 1) ? 0x03 : 0x02;
        data.push_back(prefix);
        data.insert(data.end(), pubKey.begin(), pubKey.begin() + 32);
    }

    // Append index (big-endian)
    data.push_back((index >> 24) & 0xFF);
    data.push_back((index >> 16) & 0xFF);
    data.push_back((index >> 8) & 0xFF);
    data.push_back(index & 0xFF);

    // HMAC-SHA512(key=parent.chainCode, data=data)
    std::vector<uint8_t> chainCodeVec(parent.chainCode.begin(), parent.chainCode.end());
    auto hmac = hmacSha512(chainCodeVec, data);

    ExtendedKey child;

    // Child key = parse256(IL) + parent_key (mod n)
    // This requires proper elliptic curve point addition
#ifdef HAVE_SECP256K1
    // Proper implementation using secp256k1
    std::array<uint8_t, 32> tweak;
    std::memcpy(tweak.data(), hmac.data(), 32);

    if (parent.isPrivate) {
        // Private key addition: child_priv = (IL + parent_priv) mod n
        child.key = parent.key;
#ifdef HAVE_SECP256K1
        if (!secp256k1_ec_seckey_tweak_add(static_cast<secp256k1_context*>(ECDSA::getContext()), child.key.data(), tweak.data())) {
            throw std::runtime_error("Invalid child key derived - key addition failed");
        }
#else
        // Fallback: simplified approach (not cryptographically correct)
        std::memcpy(child.key.data(), hmac.data(), 32);
#endif
    } else {
        // Public key addition (not implemented for now)
        throw std::runtime_error("Public key derivation not yet implemented");
    }
#else
    // Fallback: simplified (not cryptographically correct)
    // Just use IL as child key
    std::memcpy(child.key.data(), hmac.data(), 32);
#endif

    std::memcpy(child.chainCode.data(), hmac.data() + 32, 32);
    child.depth = parent.depth + 1;
    child.childNumber = index;
    child.isPrivate = parent.isPrivate;

    // Calculate parent fingerprint (first 4 bytes of HASH160(parent_pubkey))
    // Simplified: use first 4 bytes of parent key
    std::memcpy(child.fingerprint.data(), parent.key.data(), 4);

    // Validate child key
    if (child.isPrivate && !ECDSA::validatePrivateKey(child.key)) {
        throw std::runtime_error("Invalid child key derived");
    }

    return child;
}

BIP32::ExtendedKey BIP32::derivePath(const ExtendedKey& master, const std::string& path) {
    auto indices = parsePath(path);

    ExtendedKey current = master;
    for (uint32_t index : indices) {
        current = deriveChild(current, index);
    }

    return current;
}

std::array<uint8_t, 64> BIP32::getPublicKey(const ExtendedKey& extKey) {
    if (extKey.isPrivate) {
        return ECDSA::derivePublicKey(extKey.key);
    } else {
        // Extended key already contains public key
        std::array<uint8_t, 64> pubKey;
        std::memcpy(pubKey.data(), extKey.key.data(), 32);
        // TODO: Decompress public key if needed
        return pubKey;
    }
}

std::array<uint8_t, 32> BIP32::getPrivateKey(const ExtendedKey& extKey) {
    if (!extKey.isPrivate) {
        throw std::runtime_error("Cannot get private key from public extended key");
    }
    return extKey.key;
}

std::string BIP32::serializeKey(const ExtendedKey& extKey) {
    // TODO: Implement Base58Check encoding
    // Format: version(4) || depth(1) || fingerprint(4) || child_number(4) ||
    //         chain_code(32) || key(33)
    throw std::runtime_error("BIP32::serializeKey not implemented");
}

BIP32::ExtendedKey BIP32::deserializeKey(const std::string& serialized) {
    // TODO: Implement Base58Check decoding
    throw std::runtime_error("BIP32::deserializeKey not implemented");
}

std::vector<uint32_t> BIP32::parsePath(const std::string& path) {
    std::vector<uint32_t> indices;

    // Path must start with "m" or "M"
    if (path.empty() || (path[0] != 'm' && path[0] != 'M')) {
        throw std::invalid_argument("Invalid derivation path: must start with 'm'");
    }

    // Parse path components
    std::istringstream iss(path.substr(1)); // Skip 'm'
    std::string component;

    while (std::getline(iss, component, '/')) {
        if (component.empty()) continue;

        bool hardened = false;
        if (component.back() == '\'' || component.back() == 'h') {
            hardened = true;
            component.pop_back();
        }

        // Parse index
        uint32_t index;
        try {
            index = std::stoul(component);
        } catch (...) {
            throw std::invalid_argument("Invalid path component: " + component);
        }

        if (hardened) {
            index += HARDENED_OFFSET;
        }

        indices.push_back(index);
    }

    return indices;
}

std::array<uint8_t, 64> BIP32::hmacSha512(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data
) {
#ifdef HAVE_OPENSSL
    // Use OpenSSL HMAC-SHA512
    #include <openssl/hmac.h>
    std::array<uint8_t, 64> result;
    unsigned int len = 64;
    HMAC(EVP_sha512(), key.data(), key.size(), data.data(), data.size(), result.data(), &len);
    return result;
#else
    // Fallback: Use HMAC-SHA256 twice (not standard but better than nothing)
    auto hmac256 = utils::KeyDerivation::hmacSha256(key, data);

    std::array<uint8_t, 64> result;
    std::memcpy(result.data(), hmac256.data(), 32);

    // Second round for remaining 32 bytes
    std::vector<uint8_t> data2 = data;
    data2.push_back(0x01);
    auto hmac256_2 = utils::KeyDerivation::hmacSha256(key, data2);
    std::memcpy(result.data() + 32, hmac256_2.data(), 32);

    return result;
#endif
}

} // namespace crypto
} // namespace quantaureum

// Quantaureum C++ SDK source, version 1.0.0.
#include "quantaureum/crypto/ecdsa.hpp"
#include "quantaureum/utils/secure_random.hpp"
#include <stdexcept>
#include <cstring>

#ifdef HAVE_SECP256K1
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#endif

namespace quantaureum {
namespace crypto {

void* ECDSA::context_ = nullptr;

bool ECDSA::initialize() {
#ifdef HAVE_SECP256K1
    context_ = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!context_) return false;

    // Add randomization for additional security
    auto seed = utils::SecureRandom::generateBytes(32);
    return secp256k1_context_randomize(static_cast<secp256k1_context*>(context_), seed.data()) == 1;
#else
    return false;
#endif
}

void ECDSA::cleanup() {
#ifdef HAVE_SECP256K1
    if (context_) {
        secp256k1_context_destroy(static_cast<secp256k1_context*>(context_));
        context_ = nullptr;
    }
#endif
}

std::array<uint8_t, 64> ECDSA::derivePublicKey(const std::array<uint8_t, 32>& privateKey) {
#ifdef HAVE_SECP256K1
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(static_cast<secp256k1_context*>(context_), &pubkey, privateKey.data())) {
        throw std::runtime_error("Failed to derive public key");
    }

    uint8_t serialized[65];
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(static_cast<secp256k1_context*>(context_), serialized, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    std::array<uint8_t, 64> result;
    std::memcpy(result.data(), serialized + 1, 64); // Skip 0x04 prefix
    return result;
#else
    throw std::runtime_error("ECDSA::derivePublicKey not implemented - requires libsecp256k1");
#endif
}

std::tuple<std::array<uint8_t, 32>, std::array<uint8_t, 32>, uint8_t>
ECDSA::sign(const std::array<uint8_t, 32>& hash, const std::array<uint8_t, 32>& privateKey) {
#ifdef HAVE_SECP256K1
    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_sign_recoverable(static_cast<secp256k1_context*>(context_), &sig, hash.data(), privateKey.data(), nullptr, nullptr)) {
        throw std::runtime_error("Failed to sign hash");
    }

    uint8_t output[64];
    int recid;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(static_cast<secp256k1_context*>(context_), output, &recid, &sig);

    std::array<uint8_t, 32> r, s;
    std::memcpy(r.data(), output, 32);
    std::memcpy(s.data(), output + 32, 32);

    return {r, s, static_cast<uint8_t>(recid)};
#else
    throw std::runtime_error("ECDSA::sign not implemented - requires libsecp256k1");
#endif
}

bool ECDSA::verify(
    const std::array<uint8_t, 32>& hash,
    const std::array<uint8_t, 32>& r,
    const std::array<uint8_t, 32>& s,
    const std::array<uint8_t, 64>& publicKey
) {
#ifdef HAVE_SECP256K1
    uint8_t serialized[65];
    serialized[0] = 0x04; // Uncompressed prefix
    std::memcpy(serialized + 1, publicKey.data(), 64);

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(static_cast<secp256k1_context*>(context_), &pubkey, serialized, 65)) {
        return false;
    }

    uint8_t sigdata[64];
    std::memcpy(sigdata, r.data(), 32);
    std::memcpy(sigdata + 32, s.data(), 32);

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_compact(static_cast<secp256k1_context*>(context_), &sig, sigdata)) {
        return false;
    }

    return secp256k1_ecdsa_verify(static_cast<secp256k1_context*>(context_), &sig, hash.data(), &pubkey) == 1;
#else
    throw std::runtime_error("ECDSA::verify not implemented - requires libsecp256k1");
#endif
}

std::array<uint8_t, 64> ECDSA::recoverPublicKey(
    const std::array<uint8_t, 32>& hash,
    const std::array<uint8_t, 32>& r,
    const std::array<uint8_t, 32>& s,
    uint8_t recoveryId
) {
#ifdef HAVE_SECP256K1
    uint8_t sigdata[64];
    std::memcpy(sigdata, r.data(), 32);
    std::memcpy(sigdata + 32, s.data(), 32);

    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(static_cast<secp256k1_context*>(context_), &sig, sigdata, recoveryId)) {
        throw std::runtime_error("Failed to parse recoverable signature");
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ecdsa_recover(static_cast<secp256k1_context*>(context_), &pubkey, &sig, hash.data())) {
        throw std::runtime_error("Failed to recover public key");
    }

    uint8_t serialized[65];
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(static_cast<secp256k1_context*>(context_), serialized, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    std::array<uint8_t, 64> result;
    std::memcpy(result.data(), serialized + 1, 64); // Skip 0x04 prefix
    return result;
#else
    throw std::runtime_error("ECDSA::recoverPublicKey not implemented - requires libsecp256k1");
#endif
}

bool ECDSA::validatePrivateKey(const std::array<uint8_t, 32>& privateKey) {
#ifdef HAVE_SECP256K1
    return secp256k1_ec_seckey_verify(static_cast<secp256k1_context*>(context_), privateKey.data()) == 1;
#else
    // Basic check: not all zeros
    bool allZero = true;
    for (uint8_t byte : privateKey) {
        if (byte != 0) {
            allZero = false;
            break;
        }
    }
    return !allZero;
#endif
}

bool ECDSA::validatePublicKey(const std::array<uint8_t, 64>& publicKey) {
#ifdef HAVE_SECP256K1
    uint8_t serialized[65];
    serialized[0] = 0x04; // Uncompressed prefix
    std::memcpy(serialized + 1, publicKey.data(), 64);

    secp256k1_pubkey pubkey;
    return secp256k1_ec_pubkey_parse(static_cast<secp256k1_context*>(context_), &pubkey, serialized, 65) == 1;
#else
    // Basic check: not all zeros
    bool allZero = true;
    for (uint8_t byte : publicKey) {
        if (byte != 0) {
            allZero = false;
            break;
        }
    }
    return !allZero;
#endif
}

} // namespace crypto
} // namespace quantaureum

// Quantaureum C++ SDK source, version 1.0.0.
#include "quantaureum/account.hpp"
#include "quantaureum/utils/hex.hpp"
#include "quantaureum/utils/keccak256.hpp"
#include "quantaureum/utils/secure_random.hpp"
#include "quantaureum/types/transaction.hpp"
#include "quantaureum/crypto/ecdsa.hpp"
#include "quantaureum/crypto/bip39.hpp"
#include "quantaureum/crypto/bip32.hpp"
#include <stdexcept>
#include <cstring>

namespace quantaureum {

// Signature implementation
std::string Signature::toHex() const {
    std::vector<uint8_t> bytes;
    bytes.reserve(65);
    bytes.insert(bytes.end(), r.begin(), r.end());
    bytes.insert(bytes.end(), s.begin(), s.end());
    bytes.push_back(v);
    return Hex::toHexString(bytes);
}

Signature Signature::fromHex(const std::string& hex) {
    auto bytes = Hex::toBytes(hex);
    if (bytes.size() != 65) {
        throw std::invalid_argument("Invalid signature length: expected 65 bytes");
    }

    Signature sig;
    std::copy(bytes.begin(), bytes.begin() + 32, sig.r.begin());
    std::copy(bytes.begin() + 32, bytes.begin() + 64, sig.s.begin());
    sig.v = bytes[64];
    return sig;
}

std::vector<uint8_t> Signature::toBytes() const {
    std::vector<uint8_t> bytes;
    bytes.reserve(65);
    bytes.insert(bytes.end(), r.begin(), r.end());
    bytes.insert(bytes.end(), s.begin(), s.end());
    bytes.push_back(v);
    return bytes;
}

Account Account::create() {
    Account account;

    // Generate cryptographically secure random private key
    auto randomBytes = utils::SecureRandom::generateBytes<32>();
    account.privateKey_.fromArray(randomBytes);

    // Lock memory to prevent swapping to disk
    account.privateKey_.lock();

    account.derivePublicKeyAndAddress();
    return account;
}

Account Account::fromPrivateKey(const std::array<uint8_t, 32>& privateKey) {
    Account account;
    account.privateKey_.fromArray(privateKey);
    account.privateKey_.lock();
    account.derivePublicKeyAndAddress();
    return account;
}

Account Account::fromPrivateKeyHex(const std::string& hex) {
    auto bytes = Hex::toBytes(hex);
    if (bytes.size() != 32) {
        throw std::invalid_argument("Invalid private key length: expected 32 bytes");
    }

    std::array<uint8_t, 32> privateKey;
    std::copy(bytes.begin(), bytes.end(), privateKey.begin());
    return fromPrivateKey(privateKey);
}

Account Account::fromMnemonic(const std::string& mnemonic, const std::string& path) {
    // audit-fix CPP-CRIT-1: Use proper BIP-39/BIP-32 derivation instead of
    // hashing mnemonic+path with Keccak256. The old code produced keys that
    // were completely unrelated to the standard BIP-39 derivation, meaning
    // wallets created with this SDK could NOT be recovered with any other
    // BIP-39-compliant wallet. Now we use BIP39::mnemonicToSeed() followed
    // by BIP32::derivePath() for correct HD key derivation.
    if (!crypto::BIP39::validateMnemonic(mnemonic)) {
        throw std::invalid_argument("Invalid BIP-39 mnemonic phrase");
    }

    auto seed = crypto::BIP39::mnemonicToSeed(mnemonic);
    auto masterKey = crypto::BIP32::deriveMasterKey(seed);
    auto derivedKey = crypto::BIP32::derivePath(masterKey, path);
    auto privateKeyArray = crypto::BIP32::getPrivateKey(derivedKey);

    Account account;
    account.privateKey_.fromArray(privateKeyArray);
    account.privateKey_.lock();
    account.mnemonic_ = mnemonic;
    account.derivePublicKeyAndAddress();
    return account;
}

std::string Account::generateMnemonic(int words) {
    // audit-fix CPP-CRIT-2: Use proper BIP-39 mnemonic generation via
    // crypto::BIP39::generateMnemonic() instead of a 32-word mini-wordlist.
    // The old code used only 32 words (vs BIP-39's 2048), reducing entropy
    // from 128 bits to ~60 bits for 12 words — trivially brute-forceable.
    return crypto::BIP39::generateMnemonic(words);
}

Address Account::getAddress() const {
    return address_;
}

std::array<uint8_t, 32> Account::getPrivateKey() const {
    return privateKey_.toArray();
}

std::string Account::getPrivateKeyHex() const {
    return Hex::toHexString(privateKey_.toArray());
}

std::array<uint8_t, 64> Account::getPublicKey() const {
    return publicKey_;
}

std::optional<std::string> Account::getMnemonic() const {
    return mnemonic_;
}


void Account::derivePublicKeyAndAddress() {
    // audit-fix CPP-CRIT-3: Use real ECDSA public key derivation via
    // crypto::ECDSA::derivePublicKey() instead of hashing the private key.
    // The old code produced a fake "public key" by hashing the private key
    // with Keccak256, which meant:
    //   1. The public key was NOT the real secp256k1 public key
    //   2. The address was NOT the real blockchain address
    //   3. Signature verification could never succeed against any real node
    auto privateKeyArray = privateKey_.toArray();
    publicKey_ = crypto::ECDSA::derivePublicKey(privateKeyArray);

    // Address is last 20 bytes of keccak256(uncompressed_public_key)
    // The uncompressed key is 0x04 || x || y (65 bytes), but we store
    // just the 64-byte x||y in publicKey_, so we prefix 0x04 before hashing.
    std::vector<uint8_t> pubKeyWithPrefix;
    pubKeyWithPrefix.reserve(65);
    pubKeyWithPrefix.push_back(0x04);
    pubKeyWithPrefix.insert(pubKeyWithPrefix.end(), publicKey_.begin(), publicKey_.end());

    Hash addrHash = Keccak256::hash(pubKeyWithPrefix);
    auto addrBytes = addrHash.toBytes();
    std::array<uint8_t, 20> addressBytes;
    std::copy(addrBytes.begin() + 12, addrBytes.end(), addressBytes.begin());
    address_ = Address::fromBytes(addressBytes);
}

Signature Account::signMessage(const std::string& message) const {
    // Quantaureum signed message format (consistent with Go SDK signing.go)
    std::string prefix = "\x19Quantaureum Signed Message:\n" + std::to_string(message.length());
    std::vector<uint8_t> data(prefix.begin(), prefix.end());
    data.insert(data.end(), message.begin(), message.end());

    Hash hash = Keccak256::hash(data);
    return signHash(hash);
}

Signature Account::signMessage(const std::vector<uint8_t>& message) const {
    // Quantaureum signed message format (consistent with Go SDK signing.go)
    std::string prefix = "\x19Quantaureum Signed Message:\n" + std::to_string(message.size());
    std::vector<uint8_t> data(prefix.begin(), prefix.end());
    data.insert(data.end(), message.begin(), message.end());

    Hash hash = Keccak256::hash(data);
    return signHash(hash);
}

Signature Account::signHash(const Hash& hash) const {
    // audit-fix CPP-CRIT-4: Use real ECDSA signing via crypto::ECDSA::sign()
    // instead of hashing hash+privateKey to produce a fake "signature".
    // The old code created a deterministic hash-based signature that:
    //   1. Could NOT be verified by any ECDSA verifier
    //   2. Provided ZERO cryptographic security (anyone who knows the public
    //      key and message could compute the same "signature")
    //   3. Was completely incompatible with the Quantaureum blockchain
    auto hashBytes = hash.toBytes();
    std::array<uint8_t, 32> hashArray;
    std::copy(hashBytes.begin(), hashBytes.end(), hashArray.begin());

    auto privateKeyArray = privateKey_.toArray();
    auto [r, s, v] = crypto::ECDSA::sign(hashArray, privateKeyArray);

    Signature sig;
    std::copy(r.begin(), r.end(), sig.r.begin());
    std::copy(s.begin(), s.end(), sig.s.begin());
    sig.v = v + 27; // Convert recovery ID to Ethereum convention

    return sig;
}

SignedTransaction Account::signTransaction(const TransactionRequest& tx, uint64_t chainId) const {
    SignedTransaction signed_tx;

    signed_tx.nonce = tx.getNonce().value_or(0);
    signed_tx.gasPrice = tx.getGasPrice().value_or(Uint256::zero());
    signed_tx.gasLimit = tx.getGas().value_or(Uint256(21000));
    signed_tx.to = tx.getTo();
    signed_tx.value = tx.getValue().value_or(Uint256::zero());
    signed_tx.data = tx.getData().value_or(std::vector<uint8_t>{});
    signed_tx.chainId = chainId;

    // Create transaction hash for signing (simplified)
    std::vector<uint8_t> txData;
    auto nonceBytes = Uint256(signed_tx.nonce).toBytes();
    txData.insert(txData.end(), nonceBytes.begin(), nonceBytes.end());
    auto gasPriceBytes = signed_tx.gasPrice.toBytes();
    txData.insert(txData.end(), gasPriceBytes.begin(), gasPriceBytes.end());
    auto gasLimitBytes = signed_tx.gasLimit.toBytes();
    txData.insert(txData.end(), gasLimitBytes.begin(), gasLimitBytes.end());

    if (signed_tx.to) {
        auto toBytes = signed_tx.to->toBytes();
        txData.insert(txData.end(), toBytes.begin(), toBytes.end());
    }

    auto valueBytes = signed_tx.value.toBytes();
    txData.insert(txData.end(), valueBytes.begin(), valueBytes.end());
    txData.insert(txData.end(), signed_tx.data.begin(), signed_tx.data.end());

    // EIP-155: include chainId in hash
    auto chainIdBytes = Uint256(chainId).toBytes();
    txData.insert(txData.end(), chainIdBytes.begin(), chainIdBytes.end());

    Hash txHash = Keccak256::hash(txData);
    Signature sig = signHash(txHash);

    signed_tx.r = sig.r;
    signed_tx.s = sig.s;
    signed_tx.v = static_cast<uint8_t>(chainId * 2 + 35 + (sig.v - 27));

    return signed_tx;
}

Address Account::recoverAddress(const std::string& message, const Signature& sig) {
    // Simplified: In production, use ECDSA recovery
    // For now, return a deterministic address based on signature
    std::vector<uint8_t> data;
    data.insert(data.end(), sig.r.begin(), sig.r.end());
    data.insert(data.end(), sig.s.begin(), sig.s.end());
    data.push_back(sig.v);

    Hash hash = Keccak256::hash(data);
    auto hashBytes = hash.toBytes();
    std::array<uint8_t, 20> addressBytes;
    std::copy(hashBytes.begin() + 12, hashBytes.end(), addressBytes.begin());
    return Address::fromBytes(addressBytes);
}

Address Account::recoverAddressFromHash(const Hash& hash, const Signature& sig) {
    // Simplified implementation
    std::vector<uint8_t> data;
    auto hashBytes = hash.toBytes();
    data.insert(data.end(), hashBytes.begin(), hashBytes.end());
    data.insert(data.end(), sig.r.begin(), sig.r.end());
    data.insert(data.end(), sig.s.begin(), sig.s.end());

    Hash recoveryHash = Keccak256::hash(data);
    auto recoveryBytes = recoveryHash.toBytes();
    std::array<uint8_t, 20> addressBytes;
    std::copy(recoveryBytes.begin() + 12, recoveryBytes.end(), addressBytes.begin());
    return Address::fromBytes(addressBytes);
}

} // namespace quantaureum

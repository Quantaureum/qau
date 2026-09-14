// Quantaureum C++ SDK source, version 1.0.0.
#include "quantaureum/types/transaction.hpp"
#include "quantaureum/utils/hex.hpp"
#include "quantaureum/utils/keccak256.hpp"
#include "quantaureum/crypto/ecdsa.hpp"

namespace quantaureum {

// TransactionRequest::Builder implementation
TransactionRequest::Builder& TransactionRequest::Builder::from(const Address& from) {
    tx_.from_ = from;
    return *this;
}

TransactionRequest::Builder& TransactionRequest::Builder::from(const std::string& from) {
    tx_.from_ = Address::fromHex(from);
    return *this;
}

TransactionRequest::Builder& TransactionRequest::Builder::to(const Address& to) {
    tx_.to_ = to;
    return *this;
}

TransactionRequest::Builder& TransactionRequest::Builder::to(const std::string& to) {
    tx_.to_ = Address::fromHex(to);
    return *this;
}

TransactionRequest::Builder& TransactionRequest::Builder::value(const Uint256& value) {
    tx_.value_ = value;
    return *this;
}

TransactionRequest::Builder& TransactionRequest::Builder::value(uint64_t value) {
    tx_.value_ = Uint256(value);
    return *this;
}

TransactionRequest::Builder& TransactionRequest::Builder::gas(const Uint256& gas) {
    tx_.gas_ = gas;
    return *this;
}

TransactionRequest::Builder& TransactionRequest::Builder::gas(uint64_t gas) {
    tx_.gas_ = Uint256(gas);
    return *this;
}

TransactionRequest::Builder& TransactionRequest::Builder::gasLimit(const Uint256& gasLimit) {
    tx_.gas_ = gasLimit;
    return *this;
}

TransactionRequest::Builder& TransactionRequest::Builder::gasLimit(uint64_t gasLimit) {
    tx_.gas_ = Uint256(gasLimit);
    return *this;
}

TransactionRequest::Builder& TransactionRequest::Builder::gasPrice(const Uint256& gasPrice) {
    tx_.gasPrice_ = gasPrice;
    return *this;
}

TransactionRequest::Builder& TransactionRequest::Builder::gasPrice(uint64_t gasPrice) {
    tx_.gasPrice_ = Uint256(gasPrice);
    return *this;
}

TransactionRequest::Builder& TransactionRequest::Builder::nonce(uint64_t nonce) {
    tx_.nonce_ = nonce;
    return *this;
}

TransactionRequest::Builder& TransactionRequest::Builder::data(const std::vector<uint8_t>& data) {
    tx_.data_ = data;
    return *this;
}

TransactionRequest::Builder& TransactionRequest::Builder::data(const std::string& hexData) {
    tx_.data_ = Hex::toBytes(hexData);
    return *this;
}

TransactionRequest TransactionRequest::Builder::build() {
    return tx_;
}

TransactionRequest::Builder TransactionRequest::builder() {
    return Builder();
}

// SignedTransaction implementation
std::vector<uint8_t> SignedTransaction::encode() const {
    // Simplified RLP encoding
    std::vector<uint8_t> result;

    // This is a simplified version - production code should use proper RLP encoding
    auto appendBytes = [&result](const std::vector<uint8_t>& bytes) {
        if (bytes.empty()) {
            result.push_back(0x80);
        } else if (bytes.size() == 1 && bytes[0] < 0x80) {
            result.push_back(bytes[0]);
        } else if (bytes.size() < 56) {
            result.push_back(static_cast<uint8_t>(0x80 + bytes.size()));
            result.insert(result.end(), bytes.begin(), bytes.end());
        } else {
            // Long string encoding
            size_t lenBytes = 0;
            size_t len = bytes.size();
            while (len > 0) {
                lenBytes++;
                len >>= 8;
            }
            result.push_back(static_cast<uint8_t>(0xb7 + lenBytes));
            len = bytes.size();
            for (size_t i = lenBytes; i > 0; --i) {
                result.push_back(static_cast<uint8_t>((len >> ((i - 1) * 8)) & 0xff));
            }
            result.insert(result.end(), bytes.begin(), bytes.end());
        }
    };

    // Encode transaction fields
    appendBytes(Uint256(nonce).toBytes());
    appendBytes(gasPrice.toBytes());
    appendBytes(gasLimit.toBytes());

    if (to) {
        auto toBytes = to->toBytes();
        appendBytes(std::vector<uint8_t>(toBytes.begin(), toBytes.end()));
    } else {
        appendBytes({});
    }

    appendBytes(value.toBytes());
    appendBytes(data);

    // Signature
    result.push_back(v);
    appendBytes(std::vector<uint8_t>(r.begin(), r.end()));
    appendBytes(std::vector<uint8_t>(s.begin(), s.end()));

    // Wrap in list
    std::vector<uint8_t> list;
    if (result.size() < 56) {
        list.push_back(static_cast<uint8_t>(0xc0 + result.size()));
    } else {
        size_t lenBytes = 0;
        size_t len = result.size();
        while (len > 0) {
            lenBytes++;
            len >>= 8;
        }
        list.push_back(static_cast<uint8_t>(0xf7 + lenBytes));
        len = result.size();
        for (size_t i = lenBytes; i > 0; --i) {
            list.push_back(static_cast<uint8_t>((len >> ((i - 1) * 8)) & 0xff));
        }
    }
    list.insert(list.end(), result.begin(), result.end());

    return list;
}

std::string SignedTransaction::encodeHex() const {
    return Hex::toHexString(encode());
}

Hash SignedTransaction::hash() const {
    return Keccak256::hash(encode());
}

Address SignedTransaction::recoverSigner(const SignedTransaction& tx) {
    // audit-fix CPP-HIGH-3: Use real ECDSA public key recovery instead of
    // hashing r+s+v to produce a fake "address". The old code simply hashed
    // the signature bytes to derive an address, which has no cryptographic
    // relationship to the actual signer. Now we use crypto::ECDSA to properly
    // recover the public key from the signature.
    int recId = tx.v >= 27 ? tx.v - 27 : tx.v;
    std::array<uint8_t, 32> rArr, sArr;
    std::copy(tx.r.begin(), tx.r.end(), rArr.begin());
    std::copy(tx.s.begin(), tx.s.end(), sArr.begin());

    // Reconstruct the signing hash (without signature fields)
    // For a proper implementation, we need the original transaction hash
    // that was signed. This requires re-encoding the transaction without
    // the signature and hashing it.
    std::vector<uint8_t> encodeData;
    auto appendBytes = [&encodeData](const std::vector<uint8_t>& bytes) {
        if (bytes.empty()) {
            encodeData.push_back(0x80);
        } else if (bytes.size() == 1 && bytes[0] < 0x80) {
            encodeData.push_back(bytes[0]);
        } else if (bytes.size() < 56) {
            encodeData.push_back(static_cast<uint8_t>(0x80 + bytes.size()));
            encodeData.insert(encodeData.end(), bytes.begin(), bytes.end());
        } else {
            size_t lenBytes = 0;
            size_t len = bytes.size();
            while (len > 0) { lenBytes++; len >>= 8; }
            encodeData.push_back(static_cast<uint8_t>(0xb7 + lenBytes));
            len = bytes.size();
            for (size_t i = lenBytes; i > 0; --i) {
                encodeData.push_back(static_cast<uint8_t>((len >> ((i - 1) * 8)) & 0xff));
            }
            encodeData.insert(encodeData.end(), bytes.begin(), bytes.end());
        }
    };

    appendBytes(Uint256(tx.nonce).toBytes());
    appendBytes(tx.gasPrice.toBytes());
    appendBytes(tx.gasLimit.toBytes());
    if (tx.to) {
        auto toBytes = tx.to->toBytes();
        appendBytes(std::vector<uint8_t>(toBytes.begin(), toBytes.end()));
    } else {
        appendBytes({});
    }
    appendBytes(tx.value.toBytes());
    appendBytes(tx.data);

    // EIP-155: include chain ID in signing data
    uint64_t chainId = static_cast<uint64_t>(tx.v);
    if (chainId > 28) {
        appendBytes(Uint256(chainId).toBytes());
        appendBytes({});
        appendBytes({});
    }

    // Wrap in list
    std::vector<uint8_t> listData;
    if (encodeData.size() < 56) {
        listData.push_back(static_cast<uint8_t>(0xc0 + encodeData.size()));
    } else {
        size_t lenBytes = 0;
        size_t len = encodeData.size();
        while (len > 0) { lenBytes++; len >>= 8; }
        listData.push_back(static_cast<uint8_t>(0xf7 + lenBytes));
        len = encodeData.size();
        for (size_t i = lenBytes; i > 0; --i) {
            listData.push_back(static_cast<uint8_t>((len >> ((i - 1) * 8)) & 0xff));
        }
    }
    listData.insert(listData.end(), encodeData.begin(), encodeData.end());

    Hash signingHash = Keccak256::hash(listData);
    auto hashBytes = signingHash.toBytes();
    std::array<uint8_t, 32> hashArray;
    std::copy(hashBytes.begin(), hashBytes.end(), hashArray.begin());

    auto pubKey = crypto::ECDSA::recoverPublicKey(hashArray, rArr, sArr, static_cast<uint8_t>(recId));

    // Derive address from recovered public key
    std::vector<uint8_t> pubKeyWithPrefix;
    pubKeyWithPrefix.reserve(65);
    pubKeyWithPrefix.push_back(0x04);
    pubKeyWithPrefix.insert(pubKeyWithPrefix.end(), pubKey.begin(), pubKey.end());

    Hash addrHash = Keccak256::hash(pubKeyWithPrefix);
    auto addrBytes = addrHash.toBytes();
    std::array<uint8_t, 20> addressBytes;
    std::copy(addrBytes.begin() + 12, addrBytes.end(), addressBytes.begin());
    return Address::fromBytes(addressBytes);
}

// CallRequest::Builder implementation
CallRequest::Builder& CallRequest::Builder::from(const Address& from) {
    req_.from_ = from;
    return *this;
}

CallRequest::Builder& CallRequest::Builder::from(const std::string& from) {
    req_.from_ = Address::fromHex(from);
    return *this;
}

CallRequest::Builder& CallRequest::Builder::to(const Address& to) {
    req_.to_ = to;
    return *this;
}

CallRequest::Builder& CallRequest::Builder::to(const std::string& to) {
    req_.to_ = Address::fromHex(to);
    return *this;
}

CallRequest::Builder& CallRequest::Builder::value(const Uint256& value) {
    req_.value_ = value;
    return *this;
}

CallRequest::Builder& CallRequest::Builder::gas(const Uint256& gas) {
    req_.gas_ = gas;
    return *this;
}

CallRequest::Builder& CallRequest::Builder::gasPrice(const Uint256& gasPrice) {
    req_.gasPrice_ = gasPrice;
    return *this;
}

CallRequest::Builder& CallRequest::Builder::data(const std::vector<uint8_t>& data) {
    req_.data_ = data;
    return *this;
}

CallRequest::Builder& CallRequest::Builder::data(const std::string& hexData) {
    req_.data_ = Hex::toBytes(hexData);
    return *this;
}

CallRequest CallRequest::Builder::build() {
    return req_;
}

CallRequest::Builder CallRequest::builder() {
    return Builder();
}

} // namespace quantaureum

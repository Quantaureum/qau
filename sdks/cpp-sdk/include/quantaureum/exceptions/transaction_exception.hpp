// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include "exception.hpp"
#include "quantaureum/types/hash.hpp"
#include <optional>
#include <string>

namespace quantaureum {

class TransactionException : public QuantaureumException {
public:
    explicit TransactionException(const std::string& message)
        : QuantaureumException(message) {}

    TransactionException(const Hash& hash, const std::string& reason)
        : QuantaureumException(reason), hash_(hash), reason_(reason) {}

    std::optional<Hash> getTransactionHash() const { return hash_; }
    std::optional<std::string> getRevertReason() const { return reason_; }

private:
    std::optional<Hash> hash_;
    std::optional<std::string> reason_;
};

} // namespace quantaureum

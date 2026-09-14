// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include "exception.hpp"
#include <string>

namespace quantaureum {

class AbiException : public QuantaureumException {
public:
    explicit AbiException(const std::string& message)
        : QuantaureumException(message) {}
};

} // namespace quantaureum

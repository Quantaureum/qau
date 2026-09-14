// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <stdexcept>
#include <string>

namespace quantaureum {

class QuantaureumException : public std::runtime_error {
public:
    explicit QuantaureumException(const std::string& message)
        : std::runtime_error(message) {}
};

} // namespace quantaureum

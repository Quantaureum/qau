// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include "exception.hpp"
#include <string>

namespace quantaureum {

class RpcException : public QuantaureumException {
public:
    RpcException(int code, const std::string& message, const std::string& data = "")
        : QuantaureumException(message), code_(code), data_(data) {}

    int getCode() const { return code_; }
    std::string getData() const { return data_; }

private:
    int code_;
    std::string data_;
};

} // namespace quantaureum

// Quantaureum C++ SDK source, version 1.0.0.
#include "quantaureum/abi.hpp"
#include "quantaureum/utils/hex.hpp"
#include "quantaureum/utils/keccak256.hpp"
#include "quantaureum/exceptions/abi_exception.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cstring>

namespace quantaureum {

// AbiValue implementation
AbiValue AbiValue::uint256(const Uint256& value) {
    AbiValue v;
    v.type_ = Type::Uint256;
    v.value_ = value;
    return v;
}

AbiValue AbiValue::int256(const Uint256& value) {
    AbiValue v;
    v.type_ = Type::Int256;
    v.value_ = value;
    return v;
}

AbiValue AbiValue::address(const Address& value) {
    AbiValue v;
    v.type_ = Type::Address;
    v.value_ = value;
    return v;
}

AbiValue AbiValue::boolean(bool value) {
    AbiValue v;
    v.type_ = Type::Bool;
    v.value_ = value;
    return v;
}

AbiValue AbiValue::bytes(const std::vector<uint8_t>& value) {
    AbiValue v;
    v.type_ = Type::Bytes;
    v.value_ = value;
    return v;
}

AbiValue AbiValue::fixedBytes(const std::vector<uint8_t>& value, size_t size) {
    if (value.size() > size) {
        throw AbiException("Fixed bytes value too large");
    }
    AbiValue v;
    v.type_ = Type::FixedBytes;
    std::vector<uint8_t> padded(size, 0);
    std::copy(value.begin(), value.end(), padded.begin());
    v.value_ = padded;
    return v;
}

AbiValue AbiValue::string(const std::string& value) {
    AbiValue v;
    v.type_ = Type::String;
    v.value_ = value;
    return v;
}

AbiValue AbiValue::array(const std::vector<AbiValue>& values) {
    AbiValue v;
    v.type_ = Type::Array;
    v.value_ = values;
    return v;
}

AbiValue AbiValue::tuple(const std::vector<AbiValue>& values) {
    AbiValue v;
    v.type_ = Type::Tuple;
    v.value_ = values;
    return v;
}

Uint256 AbiValue::asUint256() const {
    if (type_ != Type::Uint256 && type_ != Type::Int256) {
        throw AbiException("Value is not uint256/int256");
    }
    return std::get<Uint256>(value_);
}

Uint256 AbiValue::asInt256() const {
    return asUint256();
}

Address AbiValue::asAddress() const {
    if (type_ != Type::Address) {
        throw AbiException("Value is not address");
    }
    return std::get<Address>(value_);
}

bool AbiValue::asBool() const {
    if (type_ != Type::Bool) {
        throw AbiException("Value is not bool");
    }
    return std::get<bool>(value_);
}

std::vector<uint8_t> AbiValue::asBytes() const {
    if (type_ != Type::Bytes && type_ != Type::FixedBytes) {
        throw AbiException("Value is not bytes");
    }
    return std::get<std::vector<uint8_t>>(value_);
}

std::string AbiValue::asString() const {
    if (type_ != Type::String) {
        throw AbiException("Value is not string");
    }
    return std::get<std::string>(value_);
}

std::vector<AbiValue> AbiValue::asArray() const {
    if (type_ != Type::Array) {
        throw AbiException("Value is not array");
    }
    return std::get<std::vector<AbiValue>>(value_);
}

std::vector<AbiValue> AbiValue::asTuple() const {
    if (type_ != Type::Tuple) {
        throw AbiException("Value is not tuple");
    }
    return std::get<std::vector<AbiValue>>(value_);
}


// Abi implementation
Abi Abi::fromJson(const std::string& json) {
    Abi abi;

    auto parsed = nlohmann::json::parse(json);

    for (const auto& item : parsed) {
        std::string type = item.value("type", "");

        if (type == "function") {
            AbiFunction func;
            func.name = item.value("name", "");

            // Build signature
            std::string sig = func.name + "(";
            bool first = true;

            if (item.contains("inputs")) {
                for (const auto& input : item["inputs"]) {
                    if (!first) sig += ",";
                    first = false;
                    std::string inputType = input.value("type", "");
                    sig += inputType;
                    func.inputTypes.push_back(inputType);
                    func.inputNames.push_back(input.value("name", ""));
                }
            }
            sig += ")";

            func.selector = calculateSelector(sig);

            if (item.contains("outputs")) {
                for (const auto& output : item["outputs"]) {
                    func.outputTypes.push_back(output.value("type", ""));
                    func.outputNames.push_back(output.value("name", ""));
                }
            }

            std::string stateMutability = item.value("stateMutability", "");
            func.isView = (stateMutability == "view");
            func.isPure = (stateMutability == "pure");
            func.isPayable = (stateMutability == "payable");

            abi.functions_.push_back(func);
        }
        else if (type == "event") {
            AbiEvent event;
            event.name = item.value("name", "");

            std::string sig = event.name + "(";
            bool first = true;

            if (item.contains("inputs")) {
                for (const auto& input : item["inputs"]) {
                    if (!first) sig += ",";
                    first = false;
                    std::string inputType = input.value("type", "");
                    sig += inputType;
                    event.inputTypes.push_back(inputType);
                    event.inputNames.push_back(input.value("name", ""));
                    event.indexed.push_back(input.value("indexed", false));
                }
            }
            sig += ")";

            event.topic = calculateTopic(sig);

            abi.events_.push_back(event);
        }
    }

    return abi;
}

std::optional<AbiFunction> Abi::getFunction(const std::string& name) const {
    for (const auto& func : functions_) {
        if (func.name == name) {
            return func;
        }
    }
    return std::nullopt;
}

std::optional<AbiEvent> Abi::getEvent(const std::string& name) const {
    for (const auto& event : events_) {
        if (event.name == name) {
            return event;
        }
    }
    return std::nullopt;
}

std::string Abi::calculateSelector(const std::string& signature) {
    Hash hash = Keccak256::hash(signature);
    std::string hex = hash.toHex();
    return hex.substr(0, 10); // 0x + 8 chars
}

std::string Abi::calculateTopic(const std::string& signature) {
    return Keccak256::hash(signature).toHex();
}

std::vector<uint8_t> Abi::encode(const AbiValue& value) {
    std::vector<uint8_t> result(32, 0);

    switch (value.getType()) {
        case AbiValue::Type::Uint256:
        case AbiValue::Type::Int256: {
            auto bytes = value.asUint256().toBytesArray();
            std::copy(bytes.begin(), bytes.end(), result.begin());
            break;
        }
        case AbiValue::Type::Address: {
            auto bytes = value.asAddress().toBytes();
            std::copy(bytes.begin(), bytes.end(), result.begin() + 12);
            break;
        }
        case AbiValue::Type::Bool: {
            result[31] = value.asBool() ? 1 : 0;
            break;
        }
        case AbiValue::Type::FixedBytes: {
            auto bytes = value.asBytes();
            std::copy(bytes.begin(), bytes.end(), result.begin());
            break;
        }
        case AbiValue::Type::Bytes:
        case AbiValue::Type::String: {
            // Dynamic types need offset + length + data
            // This is simplified - full implementation needs proper offset handling
            std::vector<uint8_t> data;
            if (value.getType() == AbiValue::Type::String) {
                std::string str = value.asString();
                data = std::vector<uint8_t>(str.begin(), str.end());
            } else {
                data = value.asBytes();
            }

            // Length
            result.clear();
            result.resize(32, 0);
            Uint256 len(data.size());
            auto lenBytes = len.toBytesArray();
            std::copy(lenBytes.begin(), lenBytes.end(), result.begin());

            // Data (padded to 32 bytes)
            size_t paddedLen = ((data.size() + 31) / 32) * 32;
            result.resize(32 + paddedLen, 0);
            std::copy(data.begin(), data.end(), result.begin() + 32);
            break;
        }
        default:
            throw AbiException("Unsupported type for encoding");
    }

    return result;
}

std::vector<uint8_t> Abi::encode(const std::vector<AbiValue>& values) {
    std::vector<uint8_t> result;

    // Simplified encoding - doesn't handle dynamic types properly
    for (const auto& value : values) {
        auto encoded = encode(value);
        result.insert(result.end(), encoded.begin(), encoded.end());
    }

    return result;
}

AbiValue Abi::decode(const std::string& type, const std::vector<uint8_t>& data) {
    if (data.size() < 32) {
        throw AbiException("Data too short for decoding");
    }

    if (type == "uint256" || type.substr(0, 4) == "uint") {
        std::array<uint8_t, 32> bytes;
        std::copy(data.begin(), data.begin() + 32, bytes.begin());
        return AbiValue::uint256(Uint256::fromBytes(bytes));
    }
    else if (type == "int256" || type.substr(0, 3) == "int") {
        std::array<uint8_t, 32> bytes;
        std::copy(data.begin(), data.begin() + 32, bytes.begin());
        return AbiValue::int256(Uint256::fromBytes(bytes));
    }
    else if (type == "address") {
        std::array<uint8_t, 20> bytes;
        std::copy(data.begin() + 12, data.begin() + 32, bytes.begin());
        return AbiValue::address(Address::fromBytes(bytes));
    }
    else if (type == "bool") {
        return AbiValue::boolean(data[31] != 0);
    }
    else if (type.substr(0, 5) == "bytes" && type.length() > 5) {
        // Fixed bytes
        size_t size = std::stoul(type.substr(5));
        std::vector<uint8_t> bytes(data.begin(), data.begin() + size);
        return AbiValue::fixedBytes(bytes, size);
    }

    throw AbiException("Unsupported type for decoding: " + type);
}

std::vector<uint8_t> Abi::encodeFunction(const std::string& name,
                                         const std::vector<AbiValue>& args) const {
    auto func = getFunction(name);
    if (!func) {
        throw AbiException("Function not found: " + name);
    }

    // Selector (4 bytes)
    auto selectorBytes = Hex::toBytes(func->selector);

    // Arguments
    auto argsEncoded = encode(args);

    std::vector<uint8_t> result;
    result.insert(result.end(), selectorBytes.begin(), selectorBytes.end());
    result.insert(result.end(), argsEncoded.begin(), argsEncoded.end());

    return result;
}

std::vector<AbiValue> Abi::decodeReturn(const std::string& name,
                                        const std::vector<uint8_t>& data) const {
    auto func = getFunction(name);
    if (!func) {
        throw AbiException("Function not found: " + name);
    }

    std::vector<AbiValue> result;
    size_t offset = 0;

    for (const auto& type : func->outputTypes) {
        if (offset + 32 > data.size()) {
            throw AbiException("Data too short for decoding return values");
        }

        std::vector<uint8_t> chunk(data.begin() + offset, data.begin() + offset + 32);
        result.push_back(decode(type, chunk));
        offset += 32;
    }

    return result;
}

} // namespace quantaureum

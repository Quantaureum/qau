// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <string>
#include <vector>
#include <optional>
#include <variant>
#include <memory>
#include "types/address.hpp"
#include "types/hash.hpp"
#include "types/uint256.hpp"

namespace quantaureum {

/**
 * @brief ABI value types
 */
class AbiValue {
public:
    enum class Type {
        Uint256,
        Int256,
        Address,
        Bool,
        Bytes,
        String,
        FixedBytes,
        Array,
        Tuple
    };

    static AbiValue uint256(const Uint256& value);
    static AbiValue int256(const Uint256& value);
    static AbiValue address(const Address& value);
    static AbiValue boolean(bool value);
    static AbiValue bytes(const std::vector<uint8_t>& value);
    static AbiValue fixedBytes(const std::vector<uint8_t>& value, size_t size);
    static AbiValue string(const std::string& value);
    static AbiValue array(const std::vector<AbiValue>& values);
    static AbiValue tuple(const std::vector<AbiValue>& values);

    Type getType() const { return type_; }

    Uint256 asUint256() const;
    Uint256 asInt256() const;
    Address asAddress() const;
    bool asBool() const;
    std::vector<uint8_t> asBytes() const;
    std::string asString() const;
    std::vector<AbiValue> asArray() const;
    std::vector<AbiValue> asTuple() const;

private:
    Type type_;
    std::variant<
        Uint256,
        Address,
        bool,
        std::vector<uint8_t>,
        std::string,
        std::vector<AbiValue>
    > value_;
};

/**
 * @brief ABI function definition
 */
struct AbiFunction {
    std::string name;
    std::string selector;
    std::vector<std::string> inputTypes;
    std::vector<std::string> inputNames;
    std::vector<std::string> outputTypes;
    std::vector<std::string> outputNames;
    bool isView = false;
    bool isPure = false;
    bool isPayable = false;
};

/**
 * @brief ABI event definition
 */
struct AbiEvent {
    std::string name;
    std::string topic;
    std::vector<std::string> inputTypes;
    std::vector<std::string> inputNames;
    std::vector<bool> indexed;
};

/**
 * @brief ABI parser and encoder/decoder
 */
class Abi {
public:
    /**
     * @brief Parse ABI from JSON string
     */
    static Abi fromJson(const std::string& json);

    /**
     * @brief Get function by name
     */
    std::optional<AbiFunction> getFunction(const std::string& name) const;

    /**
     * @brief Get event by name
     */
    std::optional<AbiEvent> getEvent(const std::string& name) const;

    /**
     * @brief Get all functions
     */
    std::vector<AbiFunction> getFunctions() const { return functions_; }

    /**
     * @brief Get all events
     */
    std::vector<AbiEvent> getEvents() const { return events_; }

    /**
     * @brief Encode function call
     */
    std::vector<uint8_t> encodeFunction(const std::string& name,
                                        const std::vector<AbiValue>& args = {}) const;

    /**
     * @brief Decode function return value
     */
    std::vector<AbiValue> decodeReturn(const std::string& name,
                                       const std::vector<uint8_t>& data) const;

    /**
     * @brief Calculate function selector (first 4 bytes of keccak256)
     */
    static std::string calculateSelector(const std::string& signature);

    /**
     * @brief Calculate event topic (full keccak256 hash)
     */
    static std::string calculateTopic(const std::string& signature);

    /**
     * @brief Encode a single value
     */
    static std::vector<uint8_t> encode(const AbiValue& value);

    /**
     * @brief Encode multiple values
     */
    static std::vector<uint8_t> encode(const std::vector<AbiValue>& values);

    /**
     * @brief Decode a single value
     */
    static AbiValue decode(const std::string& type, const std::vector<uint8_t>& data);

private:
    std::vector<AbiFunction> functions_;
    std::vector<AbiEvent> events_;
};

} // namespace quantaureum

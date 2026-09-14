// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

/**
 * @file quantaureum.hpp
 * @brief Main header file for Quantaureum C++ SDK
 *
 * Include this file to access all Quantaureum SDK functionality.
 *
 * @example
 * ```cpp
 * #include <quantaureum/quantaureum.hpp>
 *
 * using namespace quantaureum;
 *
 * int main() {
 *     // Create address from hex
 *     Address addr = Address::fromHex("0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00");
 *
 *     // Convert ether to wei
 *     Uint256 wei = Convert::etherToWei("1.5");
 *
 *     // Hash data
 *     Hash hash = Keccak256::hash("hello");
 *
 *     return 0;
 * }
 * ```
 */

// Types
#include "types/address.hpp"
#include "types/hash.hpp"
#include "types/uint256.hpp"
#include "types/transaction.hpp"
#include "types/block.hpp"
#include "types/log.hpp"

// Utils
#include "utils/hex.hpp"
#include "utils/keccak256.hpp"
#include "utils/convert.hpp"

// Core
#include "account.hpp"
#include "abi.hpp"
#include "contract.hpp"

// Exceptions
#include "exceptions/exception.hpp"
#include "exceptions/rpc_exception.hpp"
#include "exceptions/transaction_exception.hpp"
#include "exceptions/abi_exception.hpp"

namespace quantaureum {

/**
 * @brief SDK version string
 */
constexpr const char* VERSION = "0.1.0";

/**
 * @brief SDK version major number
 */
constexpr int VERSION_MAJOR = 0;

/**
 * @brief SDK version minor number
 */
constexpr int VERSION_MINOR = 1;

/**
 * @brief SDK version patch number
 */
constexpr int VERSION_PATCH = 0;

} // namespace quantaureum

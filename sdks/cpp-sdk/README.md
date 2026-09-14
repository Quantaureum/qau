# Quantaureum C++ SDK

Version 1.0.0

A modern C++17 SDK for interacting with the Quantaureum network.

## Features

- Account management with private keys and mnemonics
- Transaction signing and submission
- Smart-contract interaction
- ABI encoding and decoding
- Asynchronous API support

## Requirements

- A C++17-compatible compiler
- CMake 3.16 or newer
- libcurl, when using the HTTP client
- OpenSSL, when using system cryptographic primitives

## Build

```bash
cmake -S . -B build
cmake --build build
```

The library target is `quantaureum`. By default, this source release does not
build tests.

## Quick Start

```cpp
#include <quantaureum/quantaureum.hpp>
#include <iostream>

using namespace quantaureum;

int main() {
    Address address = Address::fromHex(
        "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00");
    std::cout << "Address: " << address.toChecksumHex() << std::endl;

    Uint256 wei = Convert::etherToWei("1.5");
    std::cout << "1.5 QAU = " << wei.toHex() << " wei" << std::endl;

    Hash hash = Keccak256::hash("hello");
    std::cout << "Hash: " << hash.toHex() << std::endl;

    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    std::cout << "Hex: " << Hex::toHexString(data) << std::endl;

    return 0;
}
```

## API Overview

### Address

```cpp
Address address = Address::fromHex("0x...");
Address address = Address::fromBytes(bytes);

std::string hex = address.toHex();
std::string checksum = address.toChecksumHex();
auto bytes = address.toBytes();
bool valid = Address::isValid("0x...");
```

### Uint256

```cpp
Uint256 value(12345);
Uint256 value = Uint256::fromHex("0x...");

Uint256 sum = a + b;
Uint256 difference = a - b;
Uint256 product = a * b;
Uint256 quotient = a / b;

bool less = a < b;
bool equal = a == b;
```

### Unit Conversion

```cpp
Uint256 wei = Convert::etherToWei("1.5");
std::string ether = Convert::weiToEther(wei);

Uint256 wei = Convert::gweiToWei("20");
std::string gwei = Convert::weiToGwei(wei);

Uint256 wei = Convert::toWei("1", Unit::Ether);
std::string value = Convert::fromWei(wei, Unit::Gwei);
```

### Hashing and Hex

```cpp
Hash hash = Keccak256::hash("hello");
Hash hash = Keccak256::hash(bytes);
std::string hex = Keccak256::hashToHex("hello");

std::string hex = Hex::toHexString(bytes);
std::vector<uint8_t> bytes = Hex::toBytes("0xabcd");
std::string prefixed = Hex::add0xPrefix("abc");
std::string unprefixed = Hex::remove0xPrefix("0xabc");
```

## License

Apache License 2.0. See the repository [LICENSE](../../LICENSE).

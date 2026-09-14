# Quantaureum Java SDK

Version 1.0.0

Java SDK for interacting with Quantaureum quantum-safe blockchain.

## Requirements

- Java 17 or higher
- Maven 3.6+

## Installation

### Maven

```xml
<dependency>
    <groupId>com.quantaureum</groupId>
    <artifactId>quantaureum-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'com.quantaureum:quantaureum-sdk:1.0.0'
```

## Quick Start

### Create a Client

```java
import com.quantaureum.sdk.QuantaureumSDK;
import com.quantaureum.sdk.client.QuantaureumClient;

// Create a client
try (QuantaureumClient client = QuantaureumSDK.createClient("http://localhost:8545")) {
    // Get block number
    BigInteger blockNumber = client.getBlockNumber();
    System.out.println("Current block: " + blockNumber);
}
```

### Create an Account

```java
import com.quantaureum.sdk.accounts.Account;

// Create a new random account
Account account = Account.create();
System.out.println("Address: " + account.getAddress());

// Create from private key
Account account = Account.fromPrivateKeyHex("0x...");

// Create from mnemonic
Account account = Account.fromMnemonic("word1 word2 word3 ...");

// Generate a new mnemonic
String mnemonic = Account.generateMnemonic();
```

### Send a Transaction

```java
import com.quantaureum.sdk.types.*;

// Build transaction
TransactionRequest tx = TransactionRequest.builder()
    .to(Address.fromHex("0x..."))
    .value(Convert.etherToWei("1.0"))
    .gas(21000)
    .gasPrice(client.getGasPrice())
    .nonce(client.getNonce(account.getAddress()))
    .build();

// Sign and send
SignedTransaction signedTx = account.signTransaction(tx, client.getChainId());
Hash txHash = client.sendTransaction(signedTx);
System.out.println("Transaction hash: " + txHash);

// Wait for receipt
TransactionReceipt receipt = client.getTransactionReceipt(txHash).orElseThrow();
System.out.println("Status: " + (receipt.isSuccess() ? "Success" : "Failed"));
```

### Sign a Message

```java
import com.quantaureum.sdk.accounts.Signature;

// Sign a message
byte[] message = "Hello, Quantaureum!".getBytes();
Signature signature = account.signMessage(message);

// Recover signer
Address signer = signature.recover(message);
assert signer.equals(account.getAddress());
```

### Utility Functions

```java
import com.quantaureum.sdk.utils.*;

// Wei/Ether conversion
BigInteger wei = Convert.etherToWei("1.5");
String ether = Convert.weiToEther(wei);

// Hex conversion
String hex = Hex.toHexString(bytes);
byte[] bytes = Hex.toBytes("0x1234");

// Keccak256 hash
byte[] hash = Keccak256.hash(data);

// Address validation
boolean valid = Address.isValid("0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00");
```

## API Reference

### QuantaureumClient

| Method | Description |
|--------|-------------|
| `getBlockNumber()` | Get current block number |
| `getBlockByNumber(number)` | Get block by number |
| `getBlockByHash(hash)` | Get block by hash |
| `getTransactionByHash(hash)` | Get transaction by hash |
| `getTransactionReceipt(hash)` | Get transaction receipt |
| `getBalance(address)` | Get account balance |
| `getNonce(address)` | Get account nonce |
| `getGasPrice()` | Get current gas price |
| `estimateGas(tx)` | Estimate gas for transaction |
| `sendTransaction(signedTx)` | Send signed transaction |
| `getChainId()` | Get chain ID |

### Account

| Method | Description |
|--------|-------------|
| `create()` | Create new random account |
| `fromPrivateKey(bytes)` | Create from private key bytes |
| `fromPrivateKeyHex(hex)` | Create from hex private key |
| `fromMnemonic(phrase)` | Create from mnemonic |
| `generateMnemonic()` | Generate new mnemonic |
| `getAddress()` | Get account address |
| `signMessage(message)` | Sign a message |
| `signTransaction(tx, chainId)` | Sign a transaction |

### Types

- `Address` - 20-byte blockchain address
- `Hash` - 32-byte hash value
- `TransactionRequest` - Transaction request builder
- `SignedTransaction` - Signed transaction
- `Block` - Block data
- `TransactionReceipt` - Transaction receipt
- `Log` - Event log

## Error Handling

```java
import com.quantaureum.sdk.exceptions.*;

try {
    client.sendTransaction(signedTx);
} catch (RpcException e) {
    if (e.isConnectionError()) {
        System.err.println("Connection failed");
    } else if (e.isRevert()) {
        System.err.println("Transaction reverted: " + e.getRevertReason().orElse("unknown"));
    } else {
        System.err.println("RPC error: " + e.getCode() + " - " + e.getRpcMessage());
    }
} catch (TransactionException e) {
    System.err.println("Transaction failed: " + e.getRevertReason().orElse("unknown"));
}
```

## Building from Source

```bash
# Clone the repository
git clone https://github.com/quantaureum/qau.git
cd qau/sdks/java-sdk

# Build
mvn clean install

# Run tests
mvn test
```

## License

Apache License 2.0. See the repository [LICENSE](../../LICENSE).

## Links

- [Quantaureum Website](https://quantaureum.io)
- [API Documentation](https://docs.quantaureum.io)
- [GitHub Repository](https://github.com/quantaureum/qau/tree/main/sdks/java-sdk)

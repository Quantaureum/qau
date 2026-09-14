# Quantaureum Go SDK

Version 1.0.0

A comprehensive Go SDK for interacting with the Quantaureum quantum-safe blockchain.

## Installation

```bash
go get github.com/quantaureum/qau/sdks/go-sdk
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "math/big"

    "github.com/quantaureum/qau/sdks/go-sdk"
)

func main() {
    // Create a client
    client, err := quantaureum.NewClient("http://localhost:8545")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Create a new account
    account, err := quantaureum.NewAccount()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Address:", account.Address().Hex())

    // Get balance
    ctx := context.Background()
    balance, err := client.BalanceAt(ctx, account.Address(), nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Balance:", quantaureum.WeiToEther(balance), "QAU")
}
```

## Features

- **Client**: Connect to Quantaureum nodes via JSON-RPC
- **Accounts**: Create and manage accounts, sign messages and transactions
- **Contracts**: Interact with smart contracts using ABI encoding/decoding
- **Utilities**: Unit conversion, address validation, hashing functions

## API Reference

### Client

```go
// Create a new client
client, err := quantaureum.NewClient("http://localhost:8545")

// With options
client, err := quantaureum.NewClient("http://localhost:8545",
    quantaureum.WithTimeout(30 * time.Second),
)

// Close the client
client.Close()

// Get block number
blockNum, err := client.BlockNumber(ctx)

// Get block by number
block, err := client.BlockByNumber(ctx, big.NewInt(100))

// Get block by hash
block, err := client.BlockByHash(ctx, hash)

// Get transaction by hash
tx, isPending, err := client.TransactionByHash(ctx, txHash)

// Get transaction receipt
receipt, err := client.TransactionReceipt(ctx, txHash)

// Get account balance
balance, err := client.BalanceAt(ctx, address, nil) // nil = latest block

// Get account nonce
nonce, err := client.NonceAt(ctx, address, nil)

// Get pending nonce
pendingNonce, err := client.PendingNonceAt(ctx, address)

// Get contract code
code, err := client.CodeAt(ctx, contractAddress, nil)

// Suggest gas price
gasPrice, err := client.SuggestGasPrice(ctx)

// Estimate gas
gas, err := client.EstimateGas(ctx, quantaureum.CallMsg{
    From:  fromAddress,
    To:    &toAddress,
    Value: value,
    Data:  data,
})

// Send transaction
err = client.SendTransaction(ctx, signedTx)

// Call contract (read-only)
result, err := client.Call(ctx, quantaureum.CallMsg{
    To:   &contractAddress,
    Data: callData,
}, nil)

// Filter logs
logs, err := client.FilterLogs(ctx, quantaureum.FilterQuery{
    FromBlock: big.NewInt(0),
    ToBlock:   nil, // latest
    Addresses: []quantaureum.Address{contractAddress},
    Topics:    [][]quantaureum.Hash{{eventTopic}},
})
```

### Accounts

```go
// Create a new random account
account, err := quantaureum.NewAccount()

// Create from private key (hex)
account, err := quantaureum.NewAccountFromPrivateKeyHex("0x...")

// Create from private key (bytes)
account, err := quantaureum.NewAccountFromPrivateKeyBytes(keyBytes)

// Create from mnemonic
account, err := quantaureum.NewAccountFromMnemonic("word1 word2 ... word12")

// Create from mnemonic with custom path
account, err := quantaureum.NewAccountFromMnemonicWithPath(mnemonic, "m/44'/60'/0'/0/1")

// Create from mnemonic with password
account, err := quantaureum.NewAccountFromMnemonicWithPassword(mnemonic, "password")

// Generate mnemonic
mnemonic, err := quantaureum.GenerateMnemonic12() // 12 words
mnemonic, err := quantaureum.GenerateMnemonic24() // 24 words

// Validate mnemonic
isValid := quantaureum.ValidateMnemonic(mnemonic)

// Get account info
address := account.Address()
privateKey := account.PrivateKey()
privateKeyHex := account.PrivateKeyHex()
mnemonic := account.Mnemonic() // if created from mnemonic

// Sign message
signature, err := account.SignMessage([]byte("Hello, World!"))

// Verify signature
isValid := quantaureum.VerifySignature(address, message, signature)

// Sign transaction
signedTx, err := account.SignTransaction(tx, chainID)

// Recover signer from transaction
signer, err := quantaureum.RecoverTransactionSigner(signedTx, chainID)
```

### Transactions

```go
// Create a new transaction
tx := quantaureum.NewTransaction(
    nonce,           // uint64
    &toAddress,      // *Address (nil for contract creation)
    value,           // *big.Int (wei)
    gasLimit,        // uint64
    gasPrice,        // *big.Int
    data,            // []byte
)

// Create contract creation transaction
tx := quantaureum.NewContractCreation(nonce, value, gasLimit, gasPrice, bytecode)

// Get transaction hash
hash := tx.Hash()

// Check if signed
isSigned := tx.IsSigned()

// Check if contract creation
isContractCreation := tx.IsContractCreation()
```

### Contracts

```go
// Parse ABI
abi, err := quantaureum.ParseABI([]byte(abiJSON))
// or
abi, err := quantaureum.JSON(abiJSON)

// Create bound contract
contract := quantaureum.NewBoundContract(contractAddress, abi, client)

// Call contract method (read-only)
var results []interface{}
err := contract.Call(&quantaureum.CallOpts{
    Context: ctx,
}, &results, "balanceOf", ownerAddress)

// Send transaction to contract
opts := &quantaureum.TransactOpts{
    From:    account.Address(),
    Signer:  func(addr quantaureum.Address, tx *quantaureum.Transaction) (*quantaureum.Transaction, error) {
        return account.SignTransaction(tx, chainID)
    },
    Context: ctx,
}
tx, err := contract.Transact(opts, "transfer", toAddress, amount)

// Deploy contract
address, tx, contract, err := quantaureum.DeployContract(
    opts,
    abi,
    bytecode,
    client,
    constructorArg1,
    constructorArg2,
)

// Wait for transaction to be mined
receipt, err := quantaureum.WaitMined(ctx, client, txHash)

// Wait for contract deployment
contractAddr, err := quantaureum.WaitDeployed(ctx, client, tx)

// Calculate contract address
contractAddr := quantaureum.CreateAddress(senderAddress, nonce)
```

### Utilities

#### Unit Conversion

```go
// Ether to Wei
wei, err := quantaureum.EtherToWei("1.5")

// Wei to Ether
ether := quantaureum.WeiToEther(wei)

// GWei to Wei
wei, err := quantaureum.GWeiToWei("20")

// Wei to GWei
gwei := quantaureum.WeiToGWei(wei)

// Generic conversion
wei, err := quantaureum.ToWei("1.5", 18)    // 18 decimals
value := quantaureum.FromWei(wei, 18)

// Aliases
wei, err := quantaureum.ParseUnits("1.5", 18)
value := quantaureum.FormatUnits(wei, 18)

// Unit constants
quantaureum.Wei   // 1
quantaureum.GWei  // 10^9
quantaureum.Ether // 10^18
```

#### Hex Conversion

```go
// Bytes to hex
hex := quantaureum.BytesToHex([]byte{0x01, 0x02, 0x03}) // "0x010203"

// Hex to bytes
bytes, err := quantaureum.HexToBytes("0x010203")

// Check prefix
has := quantaureum.Has0xPrefix("0x123") // true

// Add/remove prefix
hex := quantaureum.Add0xPrefix("123")    // "0x123"
hex := quantaureum.Remove0xPrefix("0x123") // "123"

// Validate hex
isValid := quantaureum.IsValidHex("0x123abc") // true
```

#### Address Utilities

```go
// Validate address
isValid := quantaureum.IsValidAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f...")

// Checksum address (EIP-55)
checksummed := quantaureum.ChecksumAddress("0x742d35cc6634c0532925a3b844bc9e7595f...")

// Validate checksum
isValid := quantaureum.IsChecksumAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f...")

// Convert hex to address
addr := quantaureum.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f...")
addr := quantaureum.AddressFromHex("0x742d35Cc6634C0532925a3b844Bc9e7595f...")
```

#### Hashing

```go
// Keccak256 hash
hash := quantaureum.Keccak256(data)           // []byte
hash := quantaureum.Keccak256Hash(data)       // Hash type
hex := quantaureum.Keccak256Hex(data)         // "0x..."

// Multiple inputs
hash := quantaureum.Keccak256(data1, data2, data3)
```

### Types

```go
// Address (20 bytes)
addr := quantaureum.HexToAddress("0x...")
addr := quantaureum.BytesToAddress(bytes)
hex := addr.Hex()
bytes := addr.Bytes()
isEmpty := addr.IsEmpty()

// Hash (32 bytes)
hash := quantaureum.HexToHash("0x...")
hash := quantaureum.BytesToHash(bytes)
hex := hash.Hex()
bytes := hash.Bytes()
isEmpty := hash.IsEmpty()

// Constants
quantaureum.AddressLength // 20
quantaureum.HashLength    // 32
```

### Error Handling

```go
// Check error types
if errors.Is(err, quantaureum.ErrInvalidAddress) {
    // Handle invalid address
}

// Type assertion for detailed errors
if rpcErr, ok := err.(*quantaureum.RPCError); ok {
    fmt.Println("RPC Error:", rpcErr.Code, rpcErr.Message)
}

if txErr, ok := err.(*quantaureum.TransactionError); ok {
    fmt.Println("Revert reason:", txErr.RevertReason)
}

if valErr, ok := err.(*quantaureum.ValidationError); ok {
    fmt.Println("Field:", valErr.Field, "Message:", valErr.Message)
}

// Common errors
quantaureum.ErrInvalidAddress
quantaureum.ErrInvalidPrivateKey
quantaureum.ErrInvalidMnemonic
quantaureum.ErrInvalidHex
quantaureum.ErrNilPointer
quantaureum.ErrInvalidSignature
quantaureum.ErrConnectionFailed
quantaureum.ErrTimeout
quantaureum.ErrInvalidChainID
quantaureum.ErrInsufficientFunds
quantaureum.ErrNonceTooLow
quantaureum.ErrGasTooLow
quantaureum.ErrTransactionAlreadyKnown
quantaureum.ErrReplacementUnderpriced
quantaureum.ErrExecutionReverted
```

## Examples

### Send Transaction

```go
package main

import (
    "context"
    "fmt"
    "log"
    "math/big"

    "github.com/quantaureum/qau/sdks/go-sdk"
)

func main() {
    ctx := context.Background()

    // Connect to node
    client, err := quantaureum.NewClient("http://localhost:8545")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Load account from private key
    account, err := quantaureum.NewAccountFromPrivateKeyHex("0x...")
    if err != nil {
        log.Fatal(err)
    }

    // Get nonce
    nonce, err := client.PendingNonceAt(ctx, account.Address())
    if err != nil {
        log.Fatal(err)
    }

    // Get gas price
    gasPrice, err := client.SuggestGasPrice(ctx)
    if err != nil {
        log.Fatal(err)
    }

    // Create transaction
    toAddress := quantaureum.HexToAddress("0x...")
    value, _ := quantaureum.EtherToWei("0.1")
    tx := quantaureum.NewTransaction(nonce, &toAddress, value, 21000, gasPrice, nil)

    // Sign transaction
    chainID := big.NewInt(1) // Mainnet
    signedTx, err := account.SignTransaction(tx, chainID)
    if err != nil {
        log.Fatal(err)
    }

    // Send transaction
    err = client.SendTransaction(ctx, signedTx)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Transaction sent:", signedTx.Hash().Hex())

    // Wait for receipt
    receipt, err := quantaureum.WaitMined(ctx, client, signedTx.Hash())
    if err != nil {
        log.Fatal(err)
    }

    if receipt.IsSuccess() {
        fmt.Println("Transaction successful!")
    } else {
        fmt.Println("Transaction failed!")
    }
}
```

### Interact with Contract

```go
package main

import (
    "context"
    "fmt"
    "log"
    "math/big"

    "github.com/quantaureum/qau/sdks/go-sdk"
)

const erc20ABI = `[
    {"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"},
    {"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"}
]`

func main() {
    ctx := context.Background()

    client, err := quantaureum.NewClient("http://localhost:8545")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Parse ABI
    abi, err := quantaureum.JSON(erc20ABI)
    if err != nil {
        log.Fatal(err)
    }

    // Create contract instance
    contractAddr := quantaureum.HexToAddress("0x...")
    contract := quantaureum.NewBoundContract(contractAddr, abi, client)

    // Call balanceOf
    var results []interface{}
    ownerAddr := quantaureum.HexToAddress("0x...")
    err = contract.Call(&quantaureum.CallOpts{Context: ctx}, &results, "balanceOf", ownerAddr)
    if err != nil {
        log.Fatal(err)
    }

    balance := results[0].(*big.Int)
    fmt.Println("Balance:", balance)
}
```

## Dependencies

- `github.com/btcsuite/btcd/btcec/v2` - Elliptic curve cryptography
- `github.com/tyler-smith/go-bip39` - BIP-39 mnemonic support
- `golang.org/x/crypto` - Cryptographic functions
- `github.com/leanovate/gopter` - Property-based testing (dev only)

## License

Apache License 2.0. See the repository [LICENSE](../LICENSE).

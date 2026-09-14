// Quantaureum Node source, version 1.0.0.
// Parametric offline transaction signer for the Quantaureum blockchain.
//
// Usage:
//
//	qsign <privkey_file> <nonce> <to_addr_hex|none> <value_wei> <txtype> [data_hex]
//
//	privkey_file : file containing a Dilithium3 private key as 8000 hex chars
//	nonce        : decimal nonce (e.g. 0)
//	to_addr_hex  : recipient address with 0x prefix, or "none" for contract creation
//	value_wei    : value in wei (decimal), e.g. 32000000000000000000000 for 32000 QAU
//	txtype       : 0=transfer, 1=contract, 2=create, 3=stake, 4=unstake
//	data_hex     : optional hex payload (for contract creation: init code)
//
// Outputs the signed protobuf transaction as 0x-prefixed hex on its own line,
// prefixed with "RAWTX:". Also prints the derived sender address and signing details.
package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	ethTypes "github.com/quantaureum/qau/types"
)

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 6 {
		fmt.Fprintln(os.Stderr, "Usage: qsign <privkey_file> <nonce> <to_addr|none> <value_wei> <txtype> [data_hex]")
		fmt.Fprintln(os.Stderr, "  txtype: 0=transfer 1=contract 2=create 3=stake 4=unstake")
		os.Exit(1)
	}

	keyPath := os.Args[1]
	keyText, err := os.ReadFile(keyPath)
	if err != nil {
		die("read key file: %v", err)
	}
	keyHex := strings.TrimSpace(string(keyText))
	keyHex = strings.TrimPrefix(keyHex, "dilithium3:")
	if idx := strings.Index(keyHex, ":"); idx >= 0 {
		keyHex = keyHex[:idx]
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		die("decode key hex: %v", err)
	}
	// audit-fix HIGH: zero key bytes after use to prevent private key material
	// from persisting in heap memory after program exit.
	defer func() {
		for i := range keyBytes {
			keyBytes[i] = 0
		}
	}()
	if len(keyBytes) != mode3.PrivateKeySize {
		die("invalid key size: expected %d, got %d", mode3.PrivateKeySize, len(keyBytes))
	}

	var privKey mode3.PrivateKey
	privKey.Unpack((*[mode3.PrivateKeySize]byte)(keyBytes))
	// audit-fix HIGH: zeroize private key internal state after use to prevent
	// key material from remaining in memory after program exit.
	defer func() {
		var zeroed [mode3.PrivateKeySize]byte
		privKey.Unpack(&zeroed)
		for i := range zeroed {
			zeroed[i] = 0
		}
	}()
	pubKey := privKey.Public().(*mode3.PublicKey)
	pubKeyBytes := pubKey.Bytes()
	fromAddr := crypto.PublicKeyAddressFromBytes(pubKeyBytes)

	// parse nonce
	var nonce uint64
	fmt.Sscanf(os.Args[2], "%d", &nonce)

	// parse 'to'
	var toAddr *ethTypes.Address
	toArg := strings.TrimSpace(os.Args[3])
	if toArg != "none" && toArg != "" {
		h := strings.TrimPrefix(strings.ToLower(toArg), "0x")
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 20 {
			die("invalid to address: %s", toArg)
		}
		var a ethTypes.Address
		copy(a[:], b)
		toAddr = &a
	}

	// parse value
	value := new(big.Int)
	if _, ok := value.SetString(os.Args[4], 10); !ok {
		die("invalid value_wei: %s", os.Args[4])
	}

	// parse txtype
	var ttype int
	fmt.Sscanf(os.Args[5], "%d", &ttype)

	// Auto-set To address for stake/unstake transactions if not provided
	// Staking contract address: 0x0000000000000000000000000000000000001001
	// Unstake contract address: 0x0000000000000000000000000000000000001002
	if ttype == int(encoding.TxTypeStake) && toAddr == nil {
		var stakingAddr ethTypes.Address
		stakingAddr[18] = 0x10
		stakingAddr[19] = 0x01
		toAddr = &stakingAddr
		fmt.Printf("Auto-set To to staking contract: 0x%x\n", stakingAddr[:])
	} else if ttype == int(encoding.TxTypeUnstake) && toAddr == nil {
		var unstakeAddr ethTypes.Address
		unstakeAddr[18] = 0x10
		unstakeAddr[19] = 0x02
		toAddr = &unstakeAddr
		fmt.Printf("Auto-set To to unstake contract: 0x%x\n", unstakeAddr[:])
	}

	// parse optional data
	var dataBytes []byte
	if len(os.Args) >= 7 {
		dh := strings.TrimPrefix(os.Args[6], "0x")
		dataBytes, err = hex.DecodeString(dh)
		if err != nil {
			die("invalid data hex: %v", err)
		}
	}

	gasLimit := uint64(21000)
	// contract creation needs more gas
	if ttype == int(encoding.TxTypeCreate) || ttype == int(encoding.TxTypeContract) || len(dataBytes) > 0 {
		gasLimit = 30_000_000 // 30M, matches prior deploy attempts
	}
	gasPrice := big.NewInt(1_000_000_000) // 1 Gwei
	// ChainID defaults to mainnet (1668); override with QAU_CHAIN_ID env or the
	// 7th positional arg so devnet (1333) / testnet (1669) signing works.
	chainID := uint64(1668)
	if v := os.Getenv("QAU_CHAIN_ID"); v != "" {
		cid, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			die("invalid QAU_CHAIN_ID %q: %v", v, err)
		}
		chainID = cid
	}
	if len(os.Args) >= 8 {
		cid, err := strconv.ParseUint(os.Args[7], 10, 64)
		if err != nil {
			die("invalid chain_id arg %q: %v", os.Args[7], err)
		}
		chainID = cid
	}

	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxType(ttype),
		Nonce:    nonce,
		From:     fromAddr,
		To:       toAddr,
		Value:    value,
		GasLimit: gasLimit,
		GasPrice: gasPrice,
		Data:     dataBytes,
		ChainID:  chainID,
	}

	signingHash, err := tx.SigningHash()
	if err != nil {
		die("failed to compute signing hash: %v", err)
	}

	// sign with Dilithium3
	signature := make([]byte, mode3.SignatureSize)
	mode3.SignTo(&privKey, signingHash[:], signature)
	if !mode3.Verify(pubKey, signingHash[:], signature) {
		die("self-verification FAILED")
	}

	tx.PublicKey = pubKeyBytes
	tx.Signature = signature

	rawBytes, err := encoding.MarshalTransaction(tx)
	if err != nil {
		die("marshal tx: %v", err)
	}

	toStr := "none(create)"
	if toAddr != nil {
		toStr = fmt.Sprintf("0x%x", toAddr[:])
	}
	fmt.Printf("Sender:    0x%x\n", fromAddr[:])
	fmt.Printf("Nonce:     %d\n", nonce)
	fmt.Printf("To:        %s\n", toStr)
	fmt.Printf("Value:     %s wei\n", value.String())
	fmt.Printf("TxType:    %d (%s)\n", ttype, encoding.TxType(ttype))
	fmt.Printf("GasLimit:  %d\n", gasLimit)
	fmt.Printf("DataLen:   %d\n", len(dataBytes))
	fmt.Printf("ChainID:   %d\n", chainID)
	fmt.Printf("SignHash:  0x%x\n", signingHash[:])
	fmt.Printf("SelfVerify: PASSED\n")
	fmt.Printf("RAWTX:0x%x\n", rawBytes)
}

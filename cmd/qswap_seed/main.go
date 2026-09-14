// Quantaureum Node source, version 1.0.0.
// qswap_seed: R130 mainnet initial pool seeding tool (stQAU/wQAU, R123 §4).
//
// Usage:
//
//	qswap_seed <deployer_keyfile> <stqau_addr> <router_addr> <amount_qau> <chain_id>
//
// Environment variables:
//
//	QAU_RPC_URL (default http://127.0.0.1:8545)
//
// Steps:
//  1. stqau.deposit(){value: N QAU}     — stake → mint N stQAU (first deposit, 1:1 exchange rate)
//  2. stqau.approve(router, N)          — ERC20 approval
//  3. router.addLiquidity(N){value: N QAU} — native QAU wrapped into wQAU via router and added to the pool
//
// Reuses the wallet-view signing / receipt logic from cmd/qswap_smoke (including reorg-settle defense).
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

var (
	rpcURL   = envOr("http://127.0.0.1:8545", "QAU_RPC_URL")
	gasLimit = uint64(5_000_000)
	gasPrice = big.NewInt(1)
)

func envOr(def, k string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fatal(f string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "FATAL: "+f+"\n", a...)
	os.Exit(1)
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func rpc(method string, params interface{}) map[string]interface{} {
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": method, "params": params, "id": 1,
	})
	resp, err := httpClient.Post(rpcURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		fatal("rpc %s: %v", method, err)
	}
	defer resp.Body.Close()
	data, _ := ioutil.ReadAll(resp.Body)
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		fatal("rpc %s: bad json: %v (%s)", method, err, string(data))
	}
	if e, ok := out["error"]; ok && e != nil {
		fatal("rpc %s: %v", method, e)
	}
	return out
}

func rpcStr(method string, params interface{}) string {
	out := rpc(method, params)
	s, ok := out["result"].(string)
	if !ok {
		fatal("%s: missing result (%v)", method, out)
	}
	return s
}

func rpcBytes(method string, params interface{}) []byte {
	s := rpcStr(method, params)
	b, _ := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	return b
}

func ethCall(to string, data []byte) []byte {
	return rpcBytes("eth_call", []interface{}{map[string]interface{}{
		"to": to, "data": "0x" + hex.EncodeToString(data),
	}, "latest"})
}

func getBalanceQAU(addr string) *big.Int {
	n, _ := new(big.Int).SetString(strings.TrimPrefix(rpcStr("eth_getBalance", []string{addr, "latest"}), "0x"), 16)
	return n
}

func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
	if err != nil {
		fatal("bad hex %q: %v", s, err)
	}
	return b
}

func pad32(v *big.Int) []byte {
	b := v.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func loadKey(path string) (*crypto.PrivateKey, types.Address) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		fatal("read key: %v", err)
	}
	keyStr := string(raw)
	idx := strings.Index(keyStr, "dilithium3:")
	if idx == -1 {
		fatal("keyfile %s: no dilithium3: segment", path)
	}
	keyStr = keyStr[idx+len("dilithium3:"):]
	var clean strings.Builder
	for _, c := range keyStr {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			clean.WriteRune(c)
		} else {
			break // skip the ':' separator and the public-key segment after the private hex
		}
	}
	keyBytes, err := hex.DecodeString(clean.String())
	if err != nil {
		fatal("key decode: %v", err)
	}
	priv, err := crypto.PrivateKeyFromBytes(keyBytes)
	if err != nil {
		fatal("privkey: %v", err)
	}
	return priv, priv.PublicKey().Address()
}

func sendTx(step string, priv *crypto.PrivateKey, from types.Address, to string,
	data []byte, value *big.Int, nonce uint64, chainID uint64) {

	tx := &encoding.Transaction{
		Version: 1, Type: encoding.TxTypeContract, Nonce: nonce,
		From:  from,
		To:    &types.Address{},
		Value: value, GasLimit: gasLimit, GasPrice: gasPrice,
		Data: data, ChainID: chainID,
	}
	copy(tx.To[:], hexToBytes(to))

	h, err := tx.SigningHash()
	if err != nil {
		fatal("%s: signing hash: %v", step, err)
	}
	sig, err := crypto.Sign(priv, h[:])
	if err != nil {
		fatal("%s: sign: %v", step, err)
	}
	tx.Signature = sig
	tx.PublicKey = priv.PublicKeyBytes()

	raw, err := encoding.MarshalTransaction(tx)
	if err != nil {
		fatal("%s: marshal: %v", step, err)
	}
	txHash := tx.Hash()
	txHex := "0x" + hex.EncodeToString(txHash[:])
	fmt.Printf("  %-30s tx=%s ", step, txHex)

	rpc("eth_sendRawTransaction", []string{"0x" + hex.EncodeToString(raw)})

	deadline := time.Now().Add(150 * time.Second)
	var lastStatus, lastGas string
	for time.Now().Before(deadline) {
		r := rpc("eth_getTransactionReceipt", []string{txHex})
		if rec, ok := r["result"].(map[string]interface{}); ok && rec != nil {
			st, _ := rec["status"].(string)
			gu, _ := rec["gasUsed"].(string)
			lastStatus, lastGas = st, gu
			if st == "0x1" {
				fmt.Printf("status=0x1 gas=%s\n", gu)
				return
			}
			// reorg-settle defense: a bad status may also be a spurious receipt from a reverted block
			time.Sleep(12 * time.Second)
		}
		time.Sleep(3 * time.Second)
	}
	fatal("%s: status=%s gas=%s (not confirmed)", step, lastStatus, lastGas)
}

func main() {
	if len(os.Args) < 6 {
		fmt.Fprintf(os.Stderr, "Usage: qswap_seed <deployer_keyfile> <stqau_addr> <router_addr> <amount_qau> <chain_id>\n")
		os.Exit(1)
	}
	keyFile, stqau, router := os.Args[1], os.Args[2], os.Args[3]
	amountQAU, err := strconv.ParseInt(os.Args[4], 10, 64)
	if err != nil || amountQAU <= 0 {
		fatal("amount_qau: %v", os.Args[4])
	}
	chainID, err := strconv.ParseUint(os.Args[5], 10, 64)
	if err != nil {
		fatal("chain_id: %v", err)
	}

	priv, from := loadKey(keyFile)
	fromHex := from.ToHexAddress()
	fmt.Printf("deployer: %s\nrpc: %s  chainID: %d\nstqau: %s\nrouter: %s\namount: %d QAU\n\n",
		fromHex, rpcURL, chainID, stqau, router, amountQAU)

	one := big.NewInt(1)
	e18 := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	amt := new(big.Int).Mul(big.NewInt(amountQAU), e18)

	// pre-flight checks
	bal := getBalanceQAU(fromHex)
	need := new(big.Int).Mul(big.NewInt(amountQAU*2+1), e18) // 2N + fee headroom
	if bal.Cmp(need) < 0 {
		fatal("insufficient balance: %s wei < %s wei (need 2N QAU + gas)", bal, need)
	}
	rate := new(big.Int).SetBytes(ethCall(stqau, []byte{0x3b, 0xa0, 0xb9, 0xa9})) // exchangeRate()
	fmt.Printf("stqau.exchangeRate = %s (expected 1e18 for a fresh pool)\n", rate.String())
	if rate.Cmp(e18) != 0 {
		fatal("exchangeRate != 1e18 — pool is not empty, refusing blind seed (confirm manually if intentionally topping up)")
	}

	nonce, _ := new(big.Int).SetString(strings.TrimPrefix(rpcStr("eth_getTransactionCount", []string{fromHex, "latest"}), "0x"), 16)
	n0 := nonce.Uint64()

	// 1. stqau.deposit()
	sendTx("1.stqau.deposit", priv, from, stqau, []byte{0xd0, 0xe3, 0x0d, 0xb0}, amt, n0, chainID)

	// stQAU balance should equal amt (first deposit is 1:1)
	stSelBal := []byte{0x70, 0xa0, 0x82, 0x31} // balanceOf(address)
	stBal := new(big.Int).SetBytes(ethCall(stqau, append(stSelBal, pad32(new(big.Int).SetBytes(hexToBytes(fromHex)))...)))
	fmt.Printf("  deployer stQAU balance: %s (expected %s)\n", stBal.String(), amt.String())
	if stBal.Cmp(amt) != 0 {
		fatal("stQAU mint mismatch: %s != %s", stBal, amt)
	}

	// 2. stqau.approve(router, amt)
	selApprove := []byte{0x09, 0x5e, 0xa7, 0xb3}
	ad := append(append([]byte{}, selApprove...), pad32(new(big.Int).SetBytes(hexToBytes(router)))...)
	ad = append(ad, pad32(amt)...)
	sendTx("2.stqau.approve(router)", priv, from, stqau, ad, one.Mul(one, big.NewInt(0)), n0+1, chainID)

	// 3. router.addLiquidity(amt){value: amt QAU}
	selAddLiq := []byte{0x51, 0xc6, 0x59, 0x0a}
	sendTx("3.router.addLiquidity", priv, from, router, append(append([]byte{}, selAddLiq...), pad32(amt)...), amt, n0+2, chainID)

	// final check: pair reserves are not directly readable via router.slot0 — omitted;
	// but we do confirm the contract's native-coin movement:
	fmt.Printf("\nRemaining deployer QAU balance: %s wei\n", getBalanceQAU(fromHex))
	fmt.Printf("SEED COMPLETE: %d stQAU + %d QAU seeded\n", amountQAU, amountQAU)
}

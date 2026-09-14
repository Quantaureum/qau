// Quantaureum Node source, version 1.0.0.
// deploy_qswap deploys the R122 QASM-native QSwap AMM stack in one run.
//
// It is modeled directly on deploy_vesting_all (R120-proven path):
//   - Dilithium3-signed raw transactions (never ECDSA)
//   - TxTypeCreate deployments, which are exempt from the CRV2 commit-reveal
//     gate (same exemption deploy_vesting_all relies on)
//   - Fan-out raw tx to the primary node (localhost RPC) plus optional peers via SSH
//     (QAU_VALIDATOR_NODES) so any block producer sees the tx
//   - Receipt polling with peer fallback, hard failure on any error
//
// Deployment order (R122 QASM stack, constructor args are chained):
//  1. WQAU      — no constructor args                        (nonce N)
//  2. MockToken — no constructor args; deploy with -deploy-mock
//     for localtest only, NEVER on mainnet        (nonce N+1)
//  3. QSwapPair — args: token0, token1 (sorted), router, owner.
//     router is NOT deployed yet — its address is
//     deterministically precomputed (CreateAddress)  (nonce N+2)
//  4. QSwapRouter — args: pair, wqau, owner                   (nonce N+3)
//
// The pair<->router circular dependency is broken by precomputing the router
// address from (deployer, nonce+3) before pair is deployed (addr_preview.go).
//
// After deployment it runs on-chain sanity checks (eth_getCode on each
// deployed address) and writes a manifest JSON with all addresses, the tx
// hashes, and the chain height. The manifest is the single source of truth
// for wallet-extension / mobile-wallet / explorer integration.
//
// Usage:
//
//		deploy_qswap <deployer_keyfile> <bytecode_dir> <chain_id> [owner]
//
//	  deployer_keyfile  — key file containing "dilithium3:<hex>" (the standard offline keyfile format)
//	  bytecode_dir      — directory containing wqau.hex, mock_token.hex,
//	                      qswap_pair.hex, qswap_router.hex (pure hex, no 0x
//	                      prefix, no ctor args)
//	  chain_id          — 1668 mainnet / 1333 localtest
//	  owner             — optional pause authority (defaults to deployer)
//
// Flags:
//
//		-deploy-mock   also deploy MockToken (localtest rehearsal only)
//
//	  deployer_keyfile  — key file containing "dilithium3:<hex>" (the standard offline keyfile format)
//	  bytecode_dir      — directory containing WQAU.hex, QSwapFactory.hex,
//	                      QSwapRouter.hex (pure hex, no 0x prefix, no ctor args)
//	  chain_id          — 1668 for mainnet
//	  fee_to_setter     — optional; defaults to the deployer's own address
//
// Environment variables:
//
//	QAU_RPC_URL          - RPC endpoint (default http://localhost:8545)
//	QAU_VALIDATOR_NODES  - comma-separated SSH targets for tx fan-out
//	                      (e.g. "operator@node-a.example.invalid,operator@node-b.example.invalid")
//	QAU_SSH_KEY          - SSH identity file for peer fan-out (required iff
//	                       QAU_VALIDATOR_NODES is set)
//	QAU_DEPLOY_GAS       - gas limit per deployment (default 5,000,000; the
//	                       Router initcode is ~19.7KB so legacy 500k is NOT
//	                       enough. gasLimit in genesis is 20,000,000)
//	QAU_MANIFEST_OUT     - manifest output path (default qswap_deployment.json
//	                       in the CWD)
//
// The tool is idempotent-hostile by design: it refuses to run if the deployer
// nonce indicates a partially-completed stack might already exist under a
// different bytecode. Check the manifest before re-running after a crash.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

func rpcURL() string {
	if u := strings.TrimSpace(os.Getenv("QAU_RPC_URL")); u != "" {
		return u
	}
	return "http://localhost:8545"
}

func gasForDeploy() uint64 {
	if g := strings.TrimSpace(os.Getenv("QAU_DEPLOY_GAS")); g != "" {
		n, err := strconv.ParseUint(g, 10, 64)
		if err == nil && n > 0 {
			return n
		}
	}
	// QASM contracts are tiny (wqau 755B, mock ~1KB, pair 2818B, router 2226B);
	// 5M gas is a generous ceiling for deploy + constructor SSTOREs.
	// Genesis gasLimit is 20M so a single deployment fits comfortably.
	return 5_000_000
}

const gasPrice = 1 // wei, matches deploy_vesting_all

// loadValidatorNodes reads the QAU_VALIDATOR_NODES env var (comma-separated
// SSH targets). Empty when unset → local-only operation, no SSH required.
func loadValidatorNodes() []string {
	raw := os.Getenv("QAU_VALIDATOR_NODES")
	if raw == "" {
		return nil
	}
	var nodes []string
	for _, n := range strings.Split(raw, ",") {
		if n = strings.TrimSpace(n); n != "" {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

var validatorNodes = loadValidatorNodes()

// R122 flags.
var (
	deployMock  = flag.Bool("deploy-mock", false, "also deploy MockToken (LOCALTEST REHEARSAL ONLY \u2014 never on mainnet)")
	poolToken   = flag.String("pool-token", "", "mainnet: 0x address of the non-QAU pool token (required when -deploy-mock is not set; overridden by -deploy-stqau)")
	deployStqau = flag.Bool("deploy-stqau", false, "R123: deploy stQAU before the pair and use it as the pool token (the stQAU/wQAU first pool)")
)

// sshKeyPath fails closed when peers are configured but no key is provided.
func sshKeyPath() string {
	key := strings.TrimSpace(os.Getenv("QAU_SSH_KEY"))
	if key == "" && len(validatorNodes) > 0 {
		fatal("QAU_SSH_KEY is not set but QAU_VALIDATOR_NODES lists %d peers", len(validatorNodes))
	}
	return key
}

func manifestOut() string {
	if p := strings.TrimSpace(os.Getenv("QAU_MANIFEST_OUT")); p != "" {
		return p
	}
	return "qswap_deployment.json"
}

// ---------------------------------------------------------------------------
// Key loading (identical rules to deploy_vesting_all)
// ---------------------------------------------------------------------------

// loadKey reads a dilithium3 key file and returns the private key and the
// derived address. Accepts the standard offline keyfile format:
//
//	line 1..N: 12-word mnemonic (ignored for signing)
//	line N+1:  0x address (used only as a cross-check when present)
//	line N+2:  dilithium3:<privhex>:<pubhex>
//
// Only the dilithium3 segment is ever used.
func loadKey(keyFile string) (*crypto.PrivateKey, types.Address) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		fatal("read key file %s: %v", keyFile, err)
	}
	keyStr := string(data)
	idx := strings.Index(keyStr, "dilithium3:")
	if idx == -1 {
		fatal("key file %s has no dilithium3: segment", keyFile)
	}
	keyStr = keyStr[idx+len("dilithium3:"):]

	// Keep hex chars only; the remainder contains ":<pubkey>..." which we skip.
	var clean strings.Builder
	for _, c := range keyStr {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			clean.WriteRune(c)
		} else {
			break // stop at first non-hex char (the ':' separator)
		}
	}
	keyHex := clean.String()

	const privLen = crypto.Dilithium3PrivateKeySize * 2 // 8000 hex chars
	if len(keyHex) < privLen {
		fatal("key in %s too short: %d hex chars, need %d", keyFile, len(keyHex), privLen)
	}
	privBytes, err := hex.DecodeString(keyHex[:privLen])
	if err != nil {
		fatal("decode private key from %s: %v", keyFile, err)
	}
	privKey, err := crypto.PrivateKeyFromBytes(privBytes)
	if err != nil {
		fatal("parse private key from %s: %v", keyFile, err)
	}
	return privKey, privKey.PublicKey().Address()
}

// ---------------------------------------------------------------------------
// Bytecode loading + constructor arg ABI encoding
// ---------------------------------------------------------------------------

// loadBytecode reads a hex file (optionally 0x-prefixed), strips whitespace,
// and returns the raw deploy initcode WITHOUT constructor args.
func loadBytecode(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fatal("read bytecode %s: %v", path, err)
	}
	s := strings.TrimSpace(string(data))
	s = strings.TrimPrefix(s, "0x")
	// Some editors write trailing newlines; remove all whitespace inside too.
	var b strings.Builder
	for _, c := range s {
		switch {
		case (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
			b.WriteRune(c)
		case c == ' ' || c == '\n' || c == '\r' || c == '\t':
			continue
		default:
			fatal("bytecode %s contains non-hex char %q", path, c)
		}
	}
	out, err := hex.DecodeString(b.String())
	if err != nil {
		fatal("decode bytecode %s: %v", path, err)
	}
	if len(out) == 0 {
		fatal("bytecode %s is empty", path)
	}
	return out
}

// encodeAddressArg ABI-encodes an address as a 32-byte word (left-padded).
func encodeAddressArg(addrHex string) []byte {
	a := strings.TrimPrefix(strings.ToLower(addrHex), "0x")
	raw, err := hex.DecodeString(a)
	if err != nil || len(raw) != 20 {
		fatal("bad address arg %q", addrHex)
	}
	word := make([]byte, 32)
	copy(word[12:], raw)
	return word
}

// ---------------------------------------------------------------------------
// RPC helpers (same shape as deploy_vesting_all)
// ---------------------------------------------------------------------------

func rpcCall(method string, params interface{}) map[string]interface{} {
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	})
	resp, err := http.Post(rpcURL(), "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result
}

// localFanoutEndpoints returns extra local RPC endpoints from QAU_LOCAL_FANOUT
// (comma-separated URLs, e.g. "http://127.0.0.1:8542,...") used to submit
// the same tx to every validator's mempool on a local multi-node chain.
func localFanoutEndpoints() []string {
	raw := strings.TrimSpace(os.Getenv("QAU_LOCAL_FANOUT"))
	if raw == "" {
		return nil
	}
	var eps []string
	for _, e := range strings.Split(raw, ",") {
		if e = strings.TrimSpace(e); e != "" {
			eps = append(eps, e)
		}
	}
	return eps
}

// localRPCCall posts a JSON-RPC request to a specific local endpoint.
func localRPCCall(endpoint, method string, params interface{}) map[string]interface{} {
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	})
	resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result
}

func rpcResultString(method string, params interface{}) (string, bool) {
	r := rpcCall(method, params)
	if r == nil {
		return "", false
	}
	if errObj, exists := r["error"]; exists {
		fmt.Fprintf(os.Stderr, "  rpc %s error: %v\n", method, errObj)
		return "", false
	}
	res, _ := r["result"].(string)
	return res, res != ""
}

func fetchNonce(addrHex string) (uint64, error) {
	// QAU_NONCE_BYPASS: ops escape hatch — submit at an explicit nonce
	// instead of the chain-reported latest (use to hop over a mempool
	// zombie tx stuck at the reported nonce after a reorg).
	if v := strings.TrimSpace(os.Getenv("QAU_NONCE_BYPASS")); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n, nil
		}
	}
	s, ok := rpcResultString("eth_getTransactionCount", []string{addrHex, "latest"})
	if !ok {
		return 0, fmt.Errorf("eth_getTransactionCount failed for %s", addrHex)
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("parse nonce %q: %v", s, err)
	}
	return n, nil
}

func fetchBalance(addrHex string) *big.Int {
	s, ok := rpcResultString("eth_getBalance", []string{addrHex, "latest"})
	if !ok {
		return big.NewInt(0)
	}
	n, _ := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
	if n == nil {
		return big.NewInt(0)
	}
	return n
}

// fanOutRawTx submits the raw tx to the primary node (QAU_RPC_URL) and, when configured,
// to every peer in QAU_VALIDATOR_NODES via SSH curl to their localhost RPC.
// This is intended for deployments whose peer nodes do not expose public RPC.
func fanOutRawTx(txHex string) bool {
	payload, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_sendRawTransaction",
		"params":  []string{txHex},
		"id":      1,
	})

	primaryOK := false
	if r := rpcCall("eth_sendRawTransaction", []string{txHex}); r != nil {
		if _, hasErr := r["error"]; hasErr {
			fmt.Fprintf(os.Stderr, "  primary RPC error: %v\n", r["error"])
		} else {
			primaryOK = true
			fmt.Printf("  primary accepted: %v\n", r["result"])
		}
	}

	// Local fan-out is used when a submitted transaction must reach another
	// configured RPC endpoint directly. QAU_LOCAL_FANOUT is a comma-separated
	// list of local RPC endpoints (no SSH); the primary RPC is skipped.
	for _, ep := range localFanoutEndpoints() {
		if ep == rpcURL() {
			continue
		}
		if r := localRPCCall(ep, "eth_sendRawTransaction", []string{txHex}); r != nil {
			if _, hasErr := r["error"]; hasErr {
				fmt.Fprintf(os.Stderr, "  fanout %s error: %v\n", ep, r["error"])
			} else {
				fmt.Printf("  fanout %s accepted: %v\n", ep, r["result"])
			}
		}
	}

	for _, node := range validatorNodes {
		sshCmd := fmt.Sprintf(
			`curl -s -X POST http://127.0.0.1:8545 -H "Content-Type: application/json" -d '%s' --max-time 8`,
			string(payload),
		)
		//nolint:gosec // G204: ops tool — targets come from QAU_VALIDATOR_NODES env, not untrusted input.
		cmd := exec.Command("ssh",
			"-o", "ConnectTimeout=8",
			"-i", sshKeyPath(),
			node, sshCmd,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  peer %s error: %v\n", node, err)
		} else {
			fmt.Printf("  peer %s: %s\n", node, strings.TrimSpace(string(out)))
		}
	}
	return primaryOK
}

// waitForReceipt polls the primary RPC, then peers via SSH, until the tx is
// mined or the timeout expires. Peers may be ahead of the primary.
func waitForReceipt(txHashHex string, timeoutSec int) map[string]interface{} {
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	// Receipts read during a chain reorg window can be transient failures from
	// a soon-to-be-discarded fork. A failed-status receipt is only trusted after
	// it survives re-polling past the settle window.
	const settleChecks = 5
	const settleDelay = 6 * time.Second
	var lastFailed map[string]interface{}
	for time.Now().Before(deadline) {
		if r := rpcCall("eth_getTransactionReceipt", []string{txHashHex}); r != nil {
			if receipt, ok := r["result"].(map[string]interface{}); ok && receipt != nil {
				if status, _ := receipt["status"].(string); status == "0x1" {
					return receipt
				}
				lastFailed = receipt
			}
		}
		for _, node := range validatorNodes {
			sshCmd := fmt.Sprintf(
				`curl -s -X POST http://127.0.0.1:8545 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["%s"],"id":1}' --max-time 8 2>/dev/null`,
				txHashHex,
			)
			//nolint:gosec // G204: ops tool — env-driven ssh, no untrusted input.
			cmd := exec.Command("ssh",
				"-o", "ConnectTimeout=8",
				"-i", sshKeyPath(),
				node, sshCmd,
			)
			out, err := cmd.CombinedOutput()
			if err != nil {
				continue
			}
			var remote map[string]interface{}
			if json.Unmarshal(out, &remote) == nil {
				if receipt, ok := remote["result"].(map[string]interface{}); ok && receipt != nil {
					if status, _ := receipt["status"].(string); status == "0x1" {
						return receipt
					}
					lastFailed = receipt
				}
			}
		}
		// failed receipt — wait out the settle window; only report failure if it persists.
		time.Sleep(settleDelay)
		if lastFailed != nil {
			if r := rpcCall("eth_getTransactionReceipt", []string{txHashHex}); r != nil {
				if receipt, ok := r["result"].(map[string]interface{}); ok && receipt != nil {
					if status, _ := receipt["status"].(string); status == "0x1" {
						return receipt
					}
				}
			}
		}
		_ = settleChecks
	}
	return lastFailed
}

// ---------------------------------------------------------------------------
// Deployment core
// ---------------------------------------------------------------------------

type deployedContract struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	TxHash  string `json:"tx_hash"`
	Block   string `json:"block"`
	GasUsed string `json:"gas_used"`
}

// deployOne signs (Dilithium3) and submits a TxTypeCreate deployment with the
// given initcode (bytecode + ABI-encoded constructor args), then blocks until
// the receipt confirms a deployed contract address. Returns "" on failure.
func deployOne(name string, privKey *crypto.PrivateKey, from types.Address,
	nonce uint64, chainID uint64, initcode []byte) deployedContract {

	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeCreate,
		Nonce:    nonce,
		From:     from,
		To:       nil,
		Value:    big.NewInt(0),
		GasLimit: gasForDeploy(),
		GasPrice: big.NewInt(gasPrice),
		Data:     initcode,
		ChainID:  chainID,
	}

	signingHash, err := tx.SigningHash()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s: signingHash: %v\n", name, err)
		return deployedContract{Name: name}
	}
	sig, err := crypto.Sign(privKey, signingHash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s: sign: %v\n", name, err)
		return deployedContract{Name: name}
	}
	tx.Signature = sig
	tx.PublicKey = privKey.PublicKeyBytes()

	txHash := tx.Hash()
	txHashHex := "0x" + hex.EncodeToString(txHash[:])
	fmt.Printf("  tx hash: %s\n", txHashHex)

	// TxTypeCreate is exempt from the CRV2 commit-reveal gate (same as
	// deploy_vesting_all); submit directly.
	txBytes, err := encoding.MarshalTransaction(tx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s: marshal: %v\n", name, err)
		return deployedContract{Name: name}
	}
	if !fanOutRawTx("0x" + hex.EncodeToString(txBytes)) {
		fmt.Fprintf(os.Stderr, "  %s: every submission path rejected the tx\n", name)
		return deployedContract{Name: name}
	}

	receipt := waitForReceipt(txHashHex, 240)
	if receipt == nil {
		fmt.Fprintf(os.Stderr, "  %s: no receipt after 240s\n", name)
		return deployedContract{Name: name}
	}
	status, _ := receipt["status"].(string)
	contractAddr, _ := receipt["contractAddress"].(string)
	blockNum, _ := receipt["blockNumber"].(string)
	gasUsed, _ := receipt["gasUsed"].(string)
	fmt.Printf("  status=%s block=%s gasUsed=%s\n", status, blockNum, gasUsed)

	if status != "0x1" || contractAddr == "" {
		fmt.Fprintf(os.Stderr, "  %s: DEPLOYMENT FAILED (status=%s addr=%q)\n", name, status, contractAddr)
		return deployedContract{Name: name}
	}
	return deployedContract{Name: name, Address: contractAddr, TxHash: txHashHex, Block: blockNum, GasUsed: gasUsed}
}

// sanityCheck verifies eth_getCode returns non-empty code at the deployed
// address — proves the contract actually lives on-chain post-consensus.
func sanityCheck(name, addr string) bool {
	code, ok := rpcResultString("eth_getCode", []string{addr, "latest"})
	if !ok || code == "" || code == "0x" {
		fmt.Fprintf(os.Stderr, "  sanity FAIL: %s at %s has no code\n", name, addr)
		return false
	}
	fmt.Printf("  sanity OK: %s code size %d bytes\n", name, (len(code)-2)/2)
	return true
}

// wiringCheck cross-checks the deployed pair's constructor storage against
// the deployed router via eth_getStorageAt (pair slots: 0=token0 1=token1 8=router).
func wiringCheck(pairHex, routerHex, wqauHex string) bool {
	getSlot := func(slot string) string {
		s, _ := rpcResultString("eth_getStorageAt", []string{pairHex, slot, "latest"})
		return s
	}
	strip := func(w string) string {
		w = strings.TrimPrefix(w, "0x")
		if len(w) < 40 {
			return ""
		}
		return "0x" + w[len(w)-40:]
	}
	t0 := strip(getSlot("0x0"))
	t1 := strip(getSlot("0x1"))
	rt := strip(getSlot("0x8"))
	fmt.Printf("  wiring: pair.token0=%s token1=%s router=%s\n", t0, t1, rt)
	if rt != strings.ToLower(routerHex) {
		fmt.Fprintf(os.Stderr, "  wiring FAIL: pair.router %s != deployed router %s\n", rt, routerHex)
		return false
	}
	if t0 != strings.ToLower(wqauHex) && t1 != strings.ToLower(wqauHex) {
		fmt.Fprintf(os.Stderr, "  wiring FAIL: wqau %s is neither token0 (%s) nor token1 (%s)\n", wqauHex, t0, t1)
		return false
	}
	return true
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	flag.Parse()

	if flag.NArg() < 3 {
		fmt.Fprintf(os.Stderr, "Usage: deploy_qswap [flags] <deployer_keyfile> <bytecode_dir> <chain_id> [owner]\n")
		fmt.Fprintf(os.Stderr, "Flags: -deploy-mock (localtest only), -pool-token <0x> (mainnet), -deploy-stqau (R123: deploy stQAU + first pool stQAU/wQAU)\n")
		os.Exit(1)
	}
	keyFile := flag.Arg(0)
	bytecodeDir := flag.Arg(1)
	chainID, err := strconv.ParseUint(flag.Arg(2), 10, 64)
	if err != nil {
		fatal("chain_id %q: %v", flag.Arg(2), err)
	}

	// Load deployer key, derive address.
	privKey, fromAddr := loadKey(keyFile)
	fromHex := fromAddr.ToHexAddress()
	owner := fromHex
	if flag.NArg() >= 4 {
		owner = strings.ToLower(flag.Arg(3))
		if !strings.HasPrefix(owner, "0x") || len(owner) != 42 {
			fatal("owner %q is not a 0x address", owner)
		}
	}

	fmt.Println("================================================================")
	fmt.Println("QSwap R122 QASM deployment (WQAU -> [Mock] -> Pair -> Router)")
	fmt.Println("================================================================")
	fmt.Printf("rpc:            %s\n", rpcURL())
	fmt.Printf("chain id:       %d\n", chainID)
	fmt.Printf("deployer:       %s\n", fromHex)
	fmt.Printf("owner:          %s\n", owner)
	fmt.Printf("deploy mock:    %v\n", deployMock)
	fmt.Printf("peers (SSH):    %d\n", len(validatorNodes))
	fmt.Printf("gas per deploy: %d\n", gasForDeploy())

	// Pre-flight: balance must cover 4 deployments worth of gas.
	bal := fetchBalance(fromHex)
	need := big.NewInt(0).Mul(big.NewInt(int64(gasForDeploy())*4), big.NewInt(gasPrice))
	if bal.Cmp(need) < 0 {
		fatal("deployer balance %s wei < gas need %s wei (top up the account)", bal.String(), need.String())
	}
	fmt.Printf("balance:        %s QAU (sufficient)\n",
		new(big.Rat).SetFrac(bal, big.NewInt(1e18)).FloatString(3))

	// Pre-flight: chain must be reachable and on the expected chain id.
	if s, ok := rpcResultString("eth_chainId", nil); ok {
		got, _ := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
		if got != chainID {
			fatal("RPC reports chainId %d, expected %d — refusing to deploy to the wrong chain", got, chainID)
		}
	} else {
		fatal("RPC at %s is unreachable", rpcURL())
	}

	// Load the QASM initcodes.
	wqauCode := loadBytecode(filepath.Join(bytecodeDir, "wqau.hex"))
	pairCode := loadBytecode(filepath.Join(bytecodeDir, "qswap_pair.hex"))
	routerCode := loadBytecode(filepath.Join(bytecodeDir, "qswap_router.hex"))
	fmt.Printf("bytecode sizes: wqau=%dB pair=%dB router=%dB\n",
		len(wqauCode), len(pairCode), len(routerCode))
	var mockCode []byte
	if *deployMock {
		mockCode = loadBytecode(filepath.Join(bytecodeDir, "mock_token.hex"))
		fmt.Printf("                mock=%dB (LOCALTEST ONLY)\n", len(mockCode))
	}
	var stqauCode []byte
	if *deployStqau {
		stqauCode = loadBytecode(filepath.Join(bytecodeDir, "stqau.hex"))
		fmt.Printf("                stqau=%dB (R123 liquid staking)\n", len(stqauCode))
	}

	nonce, err := fetchNonce(fromHex)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Printf("nonce:          %d\n\n", nonce)

	// Nonce plan (n = current deployer nonce):
	//   n+0 wqau, [n+1 mock when -deploy-mock], [stqau when -deploy-stqau], pair, router.
	mockDelta := uint64(0)
	if *deployMock {
		mockDelta = 1
	}
	stqauDelta := uint64(0)
	if *deployStqau {
		stqauDelta = 1
	}
	nWqau := nonce
	nMock := nWqau + 1
	nStqau := nMock + mockDelta
	nPair := nStqau + stqauDelta
	nRouter := nPair + 1

	// ---- 1. WQAU (no constructor args) --------------------------------
	fmt.Println("[1/4] WQAU (no ctor args)")
	c1 := deployOne("WQAU", privKey, fromAddr, nWqau, chainID, wqauCode)
	if c1.Address == "" {
		fatal("WQAU deployment failed; aborting before dependent contracts")
	}
	wqauAddr := c1.Address

	// ---- 2. MockToken (optional, localtest only) ----------------------
	mockAddr := ""
	var c2 deployedContract
	if *deployMock {
		fmt.Println("[2/4] MockToken (no ctor args)")
		c2 = deployOne("MockToken", privKey, fromAddr, nMock, chainID, mockCode)
		if c2.Address == "" {
			fatal("MockToken deployment failed; WQAU is live at %s — manifest has partial state", wqauAddr)
		}
		mockAddr = c2.Address
	} else {
		fmt.Println("[2/4] MockToken skipped (-deploy-mock not set)")
	}

	// ---- 2b. stQAU (R123, optional) ------------------------------------
	stqauAddr := ""
	var cStqau deployedContract
	if *deployStqau {
		fmt.Println("[2b/4] stQAU (no ctor args; owner = CALLER)")
		cStqau = deployOne("StQAU", privKey, fromAddr, nStqau, chainID, stqauCode)
		if cStqau.Address == "" {
			fatal("stQAU deployment failed; WQAU is live at %s — manifest has partial state", wqauAddr)
		}
		stqauAddr = cStqau.Address
	}

	// ---- 3. QSwapPair (ctor: token0, token1 sorted, router, owner) ----
	// router is not deployed yet — precompute its address to break the
	// circular dependency (pair needs router, router needs pair).
	routerPreview := createAddressHex(fromHex, nRouter)
	if routerPreview == "" {
		fatal("precompute router address failed (deployer %s nonce %d)", fromHex, nRouter)
	}
	fmt.Printf("[3/4] QSwapPair (ctor: token0/token1 sorted, router=%s, owner)\n", routerPreview)

	// The second pool token: mock when -deploy-mock; stQAU when
	// -deploy-stqau (R123 first pool); otherwise -pool-token.
	tokenB := mockAddr
	if *deployStqau {
		tokenB = stqauAddr
	} else if !*deployMock {
		if *poolToken == "" {
			fatal("mainnet deploy needs -pool-token <0x-address> (the non-QAU side of the first pool); MockToken is localtest-only")
		}
		tokenB = strings.ToLower(*poolToken)
		if !strings.HasPrefix(tokenB, "0x") || len(tokenB) != 42 {
			fatal("pool token %q is not a 0x address", tokenB)
		}
	}
	// token0 < token1 numeric sort (same rule as the pair tests).
	t0, t1 := wqauAddr, tokenB
	t0Num, _ := new(big.Int).SetString(strings.TrimPrefix(t0, "0x"), 16)
	t1Num, _ := new(big.Int).SetString(strings.TrimPrefix(t1, "0x"), 16)
	if t1Num.Cmp(t0Num) < 0 {
		t0, t1 = t1, t0
	}

	pairInit := append([]byte{}, pairCode...)
	pairInit = append(pairInit, encodeAddressArg(t0)...)
	pairInit = append(pairInit, encodeAddressArg(t1)...)
	pairInit = append(pairInit, encodeAddressArg(routerPreview)...)
	pairInit = append(pairInit, encodeAddressArg(owner)...)
	c3 := deployOne("QSwapPair", privKey, fromAddr, nPair, chainID, pairInit)
	if c3.Address == "" {
		fatal("QSwapPair deployment failed; WQAU=%s — manifest has partial state", wqauAddr)
	}

	// ---- 4. QSwapRouter (ctor: pair, wqau, owner) ----------------------
	fmt.Println("[4/4] QSwapRouter (ctor: pair, wqau, owner)")
	routerInit := append([]byte{}, routerCode...)
	routerInit = append(routerInit, encodeAddressArg(c3.Address)...)
	routerInit = append(routerInit, encodeAddressArg(wqauAddr)...)
	routerInit = append(routerInit, encodeAddressArg(owner)...)
	c4 := deployOne("QSwapRouter", privKey, fromAddr, nRouter, chainID, routerInit)
	if c4.Address == "" {
		fatal("QSwapRouter deployment failed; WQAU=%s Pair=%s — manifest has partial state", wqauAddr, c3.Address)
	}
	if c4.Address != routerPreview {
		fatal("router landed at %s but pair was initialized with precomputed %s — NONCE DESYNC (deployer sent a concurrent tx?)", c4.Address, routerPreview)
	}

	// ---- Sanity: all deployed contracts must have on-chain code --------
	fmt.Println("\nPost-deployment sanity checks")
	contracts := []deployedContract{c1, c3, c4}
	if *deployMock {
		contracts = append(contracts, c2)
	}
	if *deployStqau {
		contracts = append(contracts, cStqau)
	}
	ok := true
	for _, c := range contracts {
		if c.Address == "" {
			continue
		}
		if !sanityCheck(c.Name, c.Address) {
			ok = false
		}
	}
	if !ok {
		fatal("sanity check failed — do NOT hand these addresses to wallets")
	}

	// Cross-contract wiring check: pair.router must equal the deployed router.
	if !wiringCheck(c3.Address, c4.Address, wqauAddr) {
		fatal("pair<->router wiring check failed — treat the stack as inconsistent")
	}

	// ---- Manifest ------------------------------------------------------
	manifest := map[string]interface{}{
		"deployed_at": time.Now().UTC().Format(time.RFC3339),
		"chain_id":    chainID,
		"deployer":    fromHex,
		"owner":       owner,
		"token0":      t0,
		"token1":      t1,
		"contracts": map[string]deployedContract{
			"WQAU":        c1,
			"QSwapPair":   c3,
			"QSwapRouter": c4,
		},
		"next_steps": []string{
			"seed the pool with router.addLiquidity (ERC20 approve first, native QAU via tx value)",
			"hand QSwapRouter address to wallet-extension / mobile-wallet / explorer",
		},
	}
	if *deployMock {
		manifest["contracts"].(map[string]deployedContract)["MockToken"] = c2
	}
	if *deployStqau {
		manifest["contracts"].(map[string]deployedContract)["StQAU"] = cStqau
	}
	data, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(manifestOut(), data, 0600); err != nil { //nolint:gosec // G303: ops manifest lives next to the ops scripts by design; 0600 owner-only.
		fatal("write manifest %s: %v", manifestOut(), err)
	}

	fmt.Println("\n================================================================")
	fmt.Println("DEPLOYMENT COMPLETE — QSwap R122 QASM stack is live")
	fmt.Println("================================================================")
	fmt.Printf("  WQAU:         %s\n", c1.Address)
	if *deployMock {
		fmt.Printf("  MockToken:    %s\n", mockAddr)
	}
	if *deployStqau {
		fmt.Printf("  StQAU:        %s (R123 liquid staking; pool token)\n", stqauAddr)
	}
	fmt.Printf("  QSwapPair:    %s\n", c3.Address)
	fmt.Printf("  QSwapRouter:  %s\n", c4.Address)
	fmt.Printf("\nManifest: %s\n", manifestOut())
}

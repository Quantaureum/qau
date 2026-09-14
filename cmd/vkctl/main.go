// Quantaureum Node source, version 1.0.0.
// Command vkctl builds, signs and (optionally) broadcasts R131 validator
// key-control transactions (TxTypeValidatorKey) targeting the
// ValidatorKeyRegistryAddress system sink.
//
// Flows (all work with an encrypted KeyFile v2 identity/master key):
//
//	vkctl bind-master --identity-key id.json --password-file pw.txt \
//	      --validator YAU... --master YAU... [--rpc http://127.0.0.1:8545]
//	vkctl rotate      --identity-key id.json --password-file pw.txt \
//	      --validator YAU... --session-pubkey-hex 0x... --activation-epoch N
//	vkctl revoke      --master-key master.json --password-file pw.txt \
//	      --validator YAU...
//
// All subcommands print the signed tx hex; with --rpc they POST it via
// qau_sendRawTransaction. Default does NOT broadcast (air-gap friendly).
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/economics"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

var defaultChainID = uint64(1668) // R130

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "rotate":
		doRotate(os.Args[2:])
	case "bind-master":
		doBindMaster(os.Args[2:])
	case "revoke":
		doRevoke(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: vkctl <rotate|bind-master|revoke> [flags]

Builds and signs TxTypeValidatorKey ops (R131). Default output is the signed
raw transaction hex (no broadcast). Add --rpc to send via qau_sendRawTransaction.`)
}

type commonFlags struct {
	chainID      *uint64
	identityKey  *string
	masterKey    *string
	passwordFile *string
	rpc          *string
	nonce        *int64
}

func newCommonFS(name string) (*flag.FlagSet, *commonFlags) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	cf := &commonFlags{
		chainID:      fs.Uint64("chain-id", defaultChainID, "chain id"),
		identityKey:  fs.String("identity-key", "", "encrypted validator identity keyfile (v2 json)"),
		masterKey:    fs.String("master-key", "", "encrypted master keyfile (v2 json)"),
		passwordFile: fs.String("password-file", "", "password file for the signer keyfile"),
		rpc:          fs.String("rpc", "", "JSON-RPC endpoint; empty = do not broadcast"),
		nonce:        fs.Int64("nonce", -1, "tx nonce (-1 = fetch from RPC when --rpc given, else 0)"),
	}
	return fs, cf
}

func doRotate(args []string) {
	fs, cf := newCommonFS("rotate")
	val := fs.String("validator", "", "validator address (QAU base32 or 0x hex)")
	sessHex := fs.String("session-pubkey-hex", "", "Dilithium3 session public key in hex")
	act := fs.Uint64("activation-epoch", 0, "epoch at which session key activates (must be > current epoch)")
	fs.Parse(args)
	if *cf.identityKey == "" || *val == "" || *sessHex == "" || *act == 0 || *cf.passwordFile == "" {
		fmt.Fprintln(os.Stderr, "required: --identity-key --password-file --validator --session-pubkey-hex --activation-epoch")
		os.Exit(2)
	}
	target, err := parseAddr(*val)
	must(err)
	sessPK, err := hex.DecodeString(strings.TrimPrefix(*sessHex, "0x"))
	must(err)
	data := consensus.EncodeVKRotateSession(target, *act, sessPK)
	buildSignAndMaybeSend(cf, *cf.identityKey, data)
}

func doBindMaster(args []string) {
	fs, cf := newCommonFS("bind-master")
	val := fs.String("validator", "", "validator address")
	master := fs.String("master", "", "master (cold) address to bind")
	fs.Parse(args)
	if *cf.identityKey == "" || *val == "" || *master == "" || *cf.passwordFile == "" {
		fmt.Fprintln(os.Stderr, "required: --identity-key --password-file --validator --master")
		os.Exit(2)
	}
	target, err := parseAddr(*val)
	must(err)
	m, err := parseAddr(*master)
	must(err)
	buildSignAndMaybeSend(cf, *cf.identityKey, consensus.EncodeVKBindMaster(target, m))
}

func doRevoke(args []string) {
	fs, cf := newCommonFS("revoke")
	val := fs.String("validator", "", "validator address")
	fs.Parse(args)
	if *cf.masterKey == "" || *val == "" || *cf.passwordFile == "" {
		fmt.Fprintln(os.Stderr, "required: --master-key --password-file --validator")
		os.Exit(2)
	}
	target, err := parseAddr(*val)
	must(err)
	buildSignAndMaybeSend(cf, *cf.masterKey, consensus.EncodeVKRevoke(target))
}

// buildSignAndMaybeSend assembles the tx, signs it with the decrypted signer
// key, prints the hex and conditionally broadcasts.
func buildSignAndMaybeSend(cf *commonFlags, signerKeyPath string, data []byte) {
	kp := mustLoadKey(signerKeyPath, *cf.passwordFile)

	var nonce uint64
	switch {
	case *cf.rpc != "":
		nonce = fetchNonce(*cf.rpc, kp.Public.Address())
	default:
		if *cf.nonce >= 0 {
			nonce = uint64(*cf.nonce)
		}
	}

	signerAddr := make([]byte, 20)
	addrArr := kp.Public.Address()
	copy(signerAddr, addrArr[:])
	registry := economics.ValidatorKeyRegistryAddress

	tx := &encoding.Transaction{
		From:     addrArr,
		To:       (*types.Address)(&registry),
		Type:     encoding.TxTypeValidatorKey,
		Nonce:    nonce,
		Value:    nil, // zero
		GasPrice: nil,
		Data:     data,
		ChainID:  *cf.chainID,
	}
	sig, err := mustSignTx(tx, kp.Private)
	must(err)
	tx.Signature = sig

	raw, err := json.Marshal(tx)
	must(err)
	fmt.Println(string(raw))

	if *cf.rpc == "" {
		fmt.Fprintln(os.Stderr, "not broadcast (no --rpc). POST this JSON to qau_sendRawTransaction to submit.")
		return
	}
	// Send as hex of JSON for qau_sendRawTransaction (go-ethereum style 0x blob).
	rawHex := "0x" + hex.EncodeToString(raw)
	res, err := rpcCall(*cf.rpc, "qau_sendRawTransaction", []any{rawHex})
	must(err)
	fmt.Fprintf(os.Stderr, "broadcast result: %s\n", string(res))
}

func mustLoadKey(path, pwFile string) *crypto.KeyPair {
	pwRaw, err := os.ReadFile(pwFile)
	must(err)
	pw := bytes.TrimRight(pwRaw, "\r\n")
	data, err := os.ReadFile(path)
	must(err)
	kf, err := crypto.KeyFileFromJSON(data)
	must(err)
	priv, err := crypto.DecryptKeyBytes(kf, []byte(pw))
	must(err)
	pub := priv.PublicKey()
	return &crypto.KeyPair{Private: priv, Public: pub}
}

func mustSignTx(tx *encoding.Transaction, priv *crypto.PrivateKey) ([]byte, error) {
	hash, err := tx.SigningHash()
	if err != nil {
		return nil, err
	}
	return crypto.Sign(priv, hash[:])
}

func fetchNonce(rpcURL string, addr types.Address) uint64 {
	res, err := rpcCall(rpcURL, "qau_getTransactionCount", []any{addr.String(), "latest"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: nonce fetch failed (%v), using 0\n", err)
		return 0
	}
	var s string
	if json.Unmarshal(res, &s) == nil {
		var n uint64
		fmt.Sscanf(s, "%v", &n)
		if strings.HasPrefix(s, "0x") {
			fmt.Sscanf(s, "0x%x", &n)
		}
		return n
	}
	var n uint64
	_ = json.Unmarshal(res, &n)
	return n
}

func rpcCall(url, method string, params []any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "method": method, "params": params, "id": 1,
	})
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &rpcResp); err != nil {
		return nil, err
	}
	if len(rpcResp.Error) > 0 {
		return nil, fmt.Errorf("rpc error: %s", string(rpcResp.Error))
	}
	return rpcResp.Result, nil
}

func parseAddr(s string) (types.Address, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") {
		b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
		if err != nil {
			return types.Address{}, err
		}
		if len(b) != 20 {
			return types.Address{}, fmt.Errorf("hex address must be 20 bytes")
		}
		var a types.Address
		copy(a[:], b)
		return a, nil
	}
	return types.ParseAddress(s)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// keep bufio referenced (useful for future interactive confirmation)
var _ = bufio.NewReader

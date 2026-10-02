// Quantaureum Node source, version 1.0.0.
// vdf-shadow follows a running Quantaureum node over RPC and evaluates the
// beacon VDF against each epoch's randomness (proxied by the epoch-boundary
// block hash — the VDF cost is input-independent, so this yields exact
// calibration data for the production seed source).
//
// Modes:
//
//	vdf-shadow -calibrate            run a T sweep once, print JSON rows
//	vdf-shadow -T 43776 -poll 10     follow the chain, evaluate every new epoch
//
// This tool is read-only over RPC and runs entirely off-chain (shadow mode,
// stage-2 spec direction 1): it never modifies node state.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto/vdf"
)

func rpcPost(rpc string, method string, params []interface{}) (json.RawMessage, error) {
	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(rpc, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	if envelope.Error != nil {
		return nil, fmt.Errorf("rpc error: %s", envelope.Error.Message)
	}
	return envelope.Result, nil
}

func fetchHeight(rpc string) (uint64, error) {
	res, err := rpcPost(rpc, "eth_blockNumber", []interface{}{})
	if err != nil {
		return 0, err
	}
	var r string
	if err := json.Unmarshal(res, &r); err != nil {
		return 0, err
	}
	return strconv.ParseUint(trim0x(r), 16, 64)
}

func fetchBlockHash(rpc string, height uint64) ([32]byte, error) {
	var out [32]byte
	res, err := rpcPost(rpc, "eth_getBlockByNumber", []interface{}{toHexQty(height), false})
	if err != nil {
		return out, err
	}
	var r struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(res, &r); err != nil {
		return out, err
	}
	b, err := hex.DecodeString(trim0x(r.Hash))
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("unexpected block hash %q (raw=%s)", r.Hash, string(res))
	}
	copy(out[:], b)
	return out, nil
}

func toHexQty(n uint64) string { return "0x" + strconv.FormatUint(n, 16) }

func trim0x(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

// runEval evaluates the production derivation path end to end on a given
// seed input: SHAKE256 input expansion, CRS derivation, parallel light eval.
func runEval(seedInput [32]byte, epoch uint64, t int, q uint64, workers int, crsSeed [32]byte) (vdf.StateVector, [32]byte, error) {
	y := consensus.DeriveVDFInput(seedInput, epoch, q)
	a := consensus.DeriveCRSMatrix(crsSeed, q)
	return vdf.ExecuteVDFLight(y, a, t, q, workers)
}

func imageBytes(image vdf.StateVector) []byte {
	out := make([]byte, 0, len(image)*64)
	for _, e := range image {
		for _, c := range e {
			var buf [8]byte
			v := c
			for k := 0; k < 8; k++ {
				buf[k] = byte(v >> (8 * uint(k)))
				v >>= 8
			}
			out = append(out, buf[:]...)
		}
	}
	return out
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, digits[x>>4], digits[x&0xf])
	}
	return string(out)
}

// runCalibrate sweeps T over the configured values and prints one JSON row
// per point: the production resource curve (time / allocations vs T).
func runCalibrate(rpc string, crsSeed [32]byte, workers int) {
	q := vdf.QBC
	height, err := fetchHeight(rpc)
	if err != nil {
		fail("fetch height: %v", err)
	}
	seedInput, err := fetchBlockHash(rpc, height)
	if err != nil {
		fail("fetch block hash: %v", err)
	}
	fmt.Println("[vdf-shadow] calibration sweep (input = current chain tip hash)")
	for _, t := range []int{1024, 4096, 16384, 43776} {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		image, whash, err := runEval(seedInput, uint64(height)/uint64(t)+1, t, q, workers, crsSeed)
		wall := time.Since(start)
		runtime.ReadMemStats(&after)
		if err != nil {
			fail("eval T=%d: %v", t, err)
		}
		row, _ := json.Marshal(map[string]interface{}{
			"T":             t,
			"wall_ms":       wall.Milliseconds(),
			"ms_per_step":   float64(wall.Microseconds()) / float64(t) / 1000.0,
			"alloc_mb":      float64(after.TotalAlloc-before.TotalAlloc) / (1 << 20),
			"heap_inuse_mb": float64(after.HeapInuse) / (1 << 20),
			"workers":       workers,
			"witness_hash":  hexEncode(whash[:]),
			"output_prefix": hexEncode(imageBytes(image))[:32],
		})
		fmt.Println(string(row))
	}
}

// runFollow evaluates the configured T once per detected epoch change.
func runFollow(rpc string, crsSeed [32]byte, tSteps, epochLen, poll, workers int) {
	q := vdf.QBC
	fmt.Println("[vdf-shadow] follow mode: evaluating the VDF for every new epoch")
	lastEpoch := int64(-1)
	for {
		height, err := fetchHeight(rpc)
		if err != nil {
			time.Sleep(time.Duration(poll) * time.Second)
			continue
		}
		epoch := int64(height / uint64(epochLen))
		if lastEpoch == -1 {
			lastEpoch = epoch
		}
		if epoch > lastEpoch {
			for e := lastEpoch + 1; e <= epoch; e++ {
				bh, err := fetchBlockHash(rpc, uint64(e) * uint64(epochLen))
				if err != nil {
					continue
				}
				start := time.Now()
				image, whash, err := runEval(bh, uint64(e), tSteps, q, workers, crsSeed)
				wall := time.Since(start)
				if err != nil {
					fmt.Printf("{\"epoch\":%d,\"error\":\"%v\"}\n", e, err)
					continue
				}
				seed := consensus.EpochSeed(image)
				row, _ := json.Marshal(map[string]interface{}{
					"epoch":        e,
					"T":            tSteps,
					"wall_ms":      wall.Milliseconds(),
					"seed_hex":     hexEncode(seed[:]),
					"witness_hash": hexEncode(whash[:]),
				})
				fmt.Println(string(row))
			}
			lastEpoch = epoch
		}
		time.Sleep(time.Duration(poll) * time.Second)
	}
}

func fail(f string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "vdf-shadow: "+f+"\n", a...)
	os.Exit(1)
}

func main() {
	rpc := flag.String("rpc", "http://127.0.0.1:8541", "node JSON-RPC endpoint")
	tSteps := flag.Int("T", 16384, "VDF sequential length for follow mode")
	epochLen := flag.Int("epoch-len", 32, "slots per epoch")
	poll := flag.Int("poll", 10, "poll interval in seconds")
	workers := flag.Int("workers", 0, "parallel workers (0 = NumCPU)")
	calibrate := flag.Bool("calibrate", false, "run a T sweep once and exit")
	crsHex := flag.String("crs-seed", "00", "hex CRS seed (must match node config)")
	flag.Parse()

	if *workers <= 0 {
		*workers = runtime.NumCPU()
	}
	if *workers > vdf.ModuleSize {
		*workers = vdf.ModuleSize
	}

	var crsSeed [32]byte
	if b, err := hex.DecodeString(*crsHex); err == nil && len(b) <= 32 {
		copy(crsSeed[len(crsSeed)-len(b):], b)
	}

	if *calibrate {
		runCalibrate(*rpc, crsSeed, *workers)
		return
	}
	runFollow(*rpc, crsSeed, *tSteps, *epochLen, *poll, *workers)
}

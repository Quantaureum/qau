// Quantaureum Node source, version 1.0.0.
// localnet generates all files needed for a local 6-node test network.
// It creates: genesis.json, 6 validator key files, 6 node configs.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/quantaureum/qau/crypto"
)

type validator struct {
	Address   string `json:"address"`
	Stake     string `json:"stake"`
	PublicKey string `json:"publicKey"`
}

type genesisConfig struct {
	ChainID    int                     `json:"chainId"`
	NetworkID  int                     `json:"networkId"`
	Timestamp  int64                   `json:"timestamp"`
	GasLimit   int                     `json:"gasLimit"`
	ExtraData  string                  `json:"extraData"`
	Alloc      map[string]genesisAlloc `json:"alloc"`
	Validators []validator             `json:"validators"`
}

type genesisAlloc struct {
	Balance string `json:"balance"`
	Nonce   int    `json:"nonce"`
}

type nodeConfig struct {
	Name             string   `json:"name"`
	NodeID           string   `json:"nodeId"`
	DataDir          string   `json:"dataDir"`
	Network          string   `json:"network"`
	NetworkID        uint64   `json:"networkId"`
	ListenAddr       string   `json:"listenAddr"`
	BootstrapPeers   []string `json:"bootstrapPeers"`
	MaxPeers         int      `json:"maxPeers"`
	EnableDHT        bool     `json:"enableDHT"`
	RPCEnabled       bool     `json:"rpcEnabled"`
	RPCAddr          string   `json:"rpcAddr"`
	WSEnabled        bool     `json:"wsEnabled"`
	WSAddr           string   `json:"wsAddr"`
	HealthEnabled    bool     `json:"healthEnabled"`
	HealthAddr       string   `json:"healthAddr"`
	FrontendEnabled  bool     `json:"frontendEnabled"`
	FrontendAddr     string   `json:"frontendAddr"`
	MetricsEnabled   bool     `json:"metricsEnabled"`
	MetricsAddr      string   `json:"metricsAddr"`
	ValidatorEnabled bool     `json:"validatorEnabled"`
	ValidatorKey     string   `json:"validatorKey"`
	BlockProducer    bool     `json:"blockProducer"`
	SyncOnlyMode     bool     `json:"syncOnlyMode"`
	DevMode          bool     `json:"devMode"`
	BlockInterval    int      `json:"blockInterval"`
	GenesisFile      string   `json:"genesisFile"`
}

func main() {
	outDir := "localtest"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		panic(err)
	}

	// Generate 6 validator key pairs
	type valInfo struct {
		Address    string
		PublicKey  string
		PrivateKey string
	}
	var vals [6]valInfo

	for i := 0; i < 6; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			panic(fmt.Sprintf("generate key %d: %v", i, err))
		}
		addr := crypto.PublicKeyAddressFromBytes(kp.Public.Bytes())
		vals[i] = valInfo{
			Address:    addr.ToHexAddress(),
			PublicKey:  hex.EncodeToString(kp.Public.Bytes()),
			PrivateKey: hex.EncodeToString(kp.Private.Bytes()),
		}
		fmt.Printf("[V%d] %s\n", i+1, vals[i].Address)
	}

	// Write validator key files (dilithium3:privhex+pubhex format)
	for i, v := range vals {
		keyFile := filepath.Join(outDir, fmt.Sprintf("validator-%d.key", i+1))
		content := fmt.Sprintf("dilithium3:%s%s", v.PrivateKey, v.PublicKey)
		if err := os.WriteFile(keyFile, []byte(content), 0600); err != nil {
			panic(err)
		}
	}

	// Create genesis.json
	alloc := make(map[string]genesisAlloc)
	for _, v := range vals {
		alloc[v.Address] = genesisAlloc{
			Balance: "100000000000000000000", // 100 QAU
			Nonce:   0,
		}
	}

	// P3-LOCALNET FIX (2026-08-07): Use genesisTime = now (current time).
	// Block timestamps are slot-derived: genesisTime + slot*12.
	// If genesisTime is in the future, block timestamps for later slots
	// (when blocks are sparse due to validator rotation) will be far in
	// the future, exceeding the validator's 15s future-bound →
	// "block timestamp in future" → block rejected → chain fork.
	// Setting genesisTime = now ensures all block timestamps are near
	// the current wall-clock time, always within the future-bound.
	// Nodes that start late (after PoW) compute the same slot from the
	// same genesisTime, so all agree on the proposer for each slot.
	gen := genesisConfig{
		ChainID:   1333,
		NetworkID: 1333,
		Timestamp: time.Now().Unix(),
		GasLimit:  20000000,
		ExtraData: "Quantaureum Local Testnet - 6 Node Network",
		Alloc:     alloc,
	}

	for _, v := range vals {
		gen.Validators = append(gen.Validators, validator{
			Address:   v.Address,
			Stake:     "33000000000000000000", // 33 QAU (above 32 QAU min)
			PublicKey: v.PublicKey,
		})
	}

	genFile := filepath.Join(outDir, "genesis.json")
	genData, _ := json.MarshalIndent(gen, "", "  ")
	if err := os.WriteFile(genFile, genData, 0600); err != nil { // G306: genesis config data, owner-only
		panic(err)
	}
	fmt.Printf("Genesis written to %s\n", genFile)

	// Create 6 node configs
	ports := []struct{ p2p, rpc, ws, health, frontend, metrics int }{
		{9001, 8541, 8551, 8081, 8091, 9091},
		{9002, 8542, 8552, 8082, 8092, 9092},
		{9003, 8543, 8553, 8083, 8093, 9093},
		{9004, 8544, 8554, 8084, 8094, 9094},
		{9005, 8545, 8555, 8085, 8095, 9095},
		{9006, 8546, 8556, 8086, 8096, 9096},
	}

	// Node1 is the bootstrap node (all others connect to it)
	for i, p := range ports {
		cfg := nodeConfig{
			Name:             fmt.Sprintf("local-node-%d", i+1),
			NodeID:           fmt.Sprintf("node-%d", i+1),
			DataDir:          filepath.Join(outDir, fmt.Sprintf("node%d", i+1), "data"),
			NetworkID:        1333,
			ListenAddr:       fmt.Sprintf("127.0.0.1:%d", p.p2p),
			MaxPeers:         50,
			EnableDHT:        true,
			RPCEnabled:       true,
			RPCAddr:          fmt.Sprintf("127.0.0.1:%d", p.rpc),
			WSEnabled:        false,
			HealthEnabled:    true,
			HealthAddr:       fmt.Sprintf("127.0.0.1:%d", p.health),
			FrontendEnabled:  false,
			MetricsEnabled:   false,
			ValidatorEnabled: true,
			ValidatorKey:     filepath.Join(outDir, fmt.Sprintf("validator-%d.key", i+1)),
			BlockProducer:    true,  // P3-LOCALNET FIX: all nodes run produceLoop so they participate in attestation. QPOS election ensures only the elected proposer produces blocks; non-elected nodes still send attestations → chain can finalize → epoch rewards are distributed.
			SyncOnlyMode:     false, // P3-LOCALNET FIX: all nodes create genesis from the same genesis.json (identical hash). SyncOnlyMode left genesisBlock=nil → peers reported genesisHash=0 → sync stalled.
			DevMode:          false,
			BlockInterval:    12,
			GenesisFile:      filepath.Join(outDir, "genesis.json"),
		}

		// All nodes except node1 bootstrap to node1
		if i > 0 {
			cfg.BootstrapPeers = []string{"127.0.0.1:9001"}
		}

		// Create data dir
		os.MkdirAll(cfg.DataDir, 0755)

		cfgFile := filepath.Join(outDir, fmt.Sprintf("config-node%d.json", i+1))
		cfgData, _ := json.MarshalIndent(cfg, "", "  ")
		//nolint:gosec // G306: local-dev node config (no secrets; local test only).
		if err := os.WriteFile(cfgFile, cfgData, 0644); err != nil {
			panic(err)
		}
		fmt.Printf("Config written to %s\n", cfgFile)
	}

	// Write a startup script
	script := `#!/bin/bash
# Start 6 local nodes for testing
# Usage: bash localtest/start.sh

echo "Starting 6 local nodes..."

for i in 1 2 3 4 5 6; do
    echo "Starting node $i..."
    ./qaud -config localtest/config-node$i.json &
    echo "Node $i PID: $!"
    sleep 2
done

echo ""
echo "All 6 nodes started."
echo "Node 1 RPC: http://127.0.0.1:8541"
echo "Node 2 RPC: http://127.0.0.1:8542"
echo "Node 3 RPC: http://127.0.0.1:8543"
echo "Node 4 RPC: http://127.0.0.1:8544"
echo "Node 5 RPC: http://127.0.0.1:8545"
echo "Node 6 RPC: http://127.0.0.1:8546"
echo ""
echo "Wait ~30s then check: python localtest/check.py"
`
	scriptFile := filepath.Join(outDir, "start.sh")
	//nolint:gosec // G306: shell startup script is a user-run tool, NOT sensitive
	// data; 0755 is required so `./start.sh` is executable without chmod.
	os.WriteFile(scriptFile, []byte(script), 0755)

	// Also write a PowerShell startup script
	psScript := `# Start 6 local nodes for testing
Write-Host "Starting 6 local nodes..."

for ($i=1; $i -le 6; $i++) {
    Write-Host "Starting node $i..."
    Start-Process -FilePath ".\qaud.exe" -ArgumentList "-config","localtest\config-node$i.json" -WindowStyle Minimized
    Start-Sleep -Seconds 2
}

Write-Host ""
Write-Host "All 6 nodes started."
Write-Host "Node 1 RPC: http://127.0.0.1:8541"
Write-Host "Node 2 RPC: http://127.0.0.1:8542"
Write-Host "Node 3 RPC: http://127.0.0.1:8543"
Write-Host "Node 4 RPC: http://127.0.0.1:8544"
Write-Host "Node 5 RPC: http://127.0.0.1:8545"
Write-Host "Node 6 RPC: http://127.0.0.1:8546"
`
	psFile := filepath.Join(outDir, "start.ps1")
	//nolint:gosec // G306: local-dev helper script; non-sensitive.
	os.WriteFile(psFile, []byte(psScript), 0644)

	// Write a Python check script
	checkScript := `#!/usr/bin/env python3
"""Check all 6 local nodes for convergence."""
import json, urllib.request, sys, time

ports = [8541, 8542, 8543, 8544, 8545, 8546]
for i, port in enumerate(ports, 1):
    try:
        # Get block number
        req = urllib.request.Request(f"http://127.0.0.1:{port}",
            data=json.dumps({"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}).encode(),
            headers={"Content-Type":"application/json"})
        resp = json.loads(urllib.request.urlopen(req, timeout=5).read())
        h = resp.get("result","0x0")
        hi = int(h, 16)
        # Get block hash
        req2 = urllib.request.Request(f"http://127.0.0.1:{port}",
            data=json.dumps({"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":[h,False],"id":1}).encode(),
            headers={"Content-Type":"application/json"})
        resp2 = json.loads(urllib.request.urlopen(req2, timeout=5).read())
        blk = resp2.get("result",{})
        bh = blk.get("hash","?")[:20] if isinstance(blk,dict) else "?"
        # Sync status
        req3 = urllib.request.Request(f"http://127.0.0.1:{port}",
            data=json.dumps({"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":1}).encode(),
            headers={"Content-Type":"application/json"})
        resp3 = json.loads(urllib.request.urlopen(req3, timeout=5).read())
        sync = resp3.get("result", False)
        print(f"Node{i} (:{port}): h={hi} hash={bh}... sync={sync}")
    except Exception as e:
        print(f"Node{i} (:{port}): ERR {e}")
`
	checkFile := filepath.Join(outDir, "check.py")
	//nolint:gosec // G306: local-dev helper script; non-sensitive.
	os.WriteFile(checkFile, []byte(checkScript), 0644)

	fmt.Println("\n✅ All files generated in localtest/")
	fmt.Println("   Genesis: localtest/genesis.json")
	fmt.Println("   Configs: localtest/config-node{1-6}.json")
	fmt.Println("   Keys: localtest/validator-{1-6}.key")
	fmt.Println("   Start: PowerShell localtest/start.ps1")
	fmt.Println("   Check: python localtest/check.py")
}

// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the qauctl management tool.
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// BlockInfo represents block information from RPC response
type BlockInfo struct {
	Number           string `json:"number"`
	Hash             string `json:"hash"`
	ParentHash       string `json:"parentHash"`
	Timestamp        string `json:"timestamp"`
	Miner            string `json:"miner"`
	GasUsed          string `json:"gasUsed"`
	GasLimit         string `json:"gasLimit"`
	TransactionCount string `json:"transactionCount"`
	Transactions     []any  `json:"transactions"`
}

func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Query node status and information",
		Long:  "Query various status information from a running Quantaureum node.",
	}

	cmd.AddCommand(newStatusNodeCmd())
	cmd.AddCommand(newStatusPeersCmd())
	cmd.AddCommand(newStatusBlockCmd())
	cmd.AddCommand(newStatusSyncCmd())
	cmd.AddCommand(newStatusMetricsCmd())

	return cmd
}

func newStatusNodeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "node",
		Short: "Show node status",
		Long:  "Display the current status of the connected node.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return queryNodeStatus()
		},
	}
}

func newStatusPeersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "peers",
		Short: "List connected peers",
		Long:  "Display information about all connected peers.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return queryPeers()
		},
	}
}

func newStatusBlockCmd() *cobra.Command {
	var height int64
	cmd := &cobra.Command{
		Use:   "block [height]",
		Short: "Show block information",
		Long:  "Display information about a specific block or the latest block.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return queryBlock(height)
		},
	}
	cmd.Flags().Int64VarP(&height, "height", "n", -1, "Block height (-1 for latest)")
	return cmd
}

func newStatusSyncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Show sync status",
		Long:  "Display the current synchronization status.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return querySyncStatus()
		},
	}
}

func newStatusMetricsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "metrics",
		Short: "Show consensus metrics",
		Long:  "Display consensus and performance metrics from the node.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return queryMetrics()
		},
	}
}

// rpcCall makes a JSON-RPC call to the node
func rpcCall(method string, params any) (json.RawMessage, error) {
	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(rpcAddr, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to node: %w", err)
	}
	defer resp.Body.Close()

	// Limit response size to prevent OOM from malicious servers
	const maxResponseBytes = 10 * 1024 * 1024 // 10MB limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", result.Error.Code, result.Error.Message)
	}

	return result.Result, nil
}

// parseHexOrDecimal parses a string as hex (0x prefix) or decimal number
func parseHexOrDecimal(s string) (int, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		val, err := strconv.ParseInt(s[2:], 16, 64)
		return int(val), err
	}
	val, err := strconv.Atoi(s)
	return val, err
}

func queryNodeStatus() error {
	// web3_clientVersion
	verResult, err := rpcCall("web3_clientVersion", nil)
	if err != nil {
		return fmt.Errorf("failed to get client version: %w", err)
	}
	var verStr string
	if err := json.Unmarshal(verResult, &verStr); err != nil {
		verStr = "unknown"
	}

	// eth_networkId
	netResult, err := rpcCall("eth_networkId", nil)
	if err != nil {
		return fmt.Errorf("failed to get network ID: %w", err)
	}
	var netIDStr string
	if err := json.Unmarshal(netResult, &netIDStr); err != nil {
		netIDStr = "0"
	}
	netID, _ := parseHexOrDecimal(netIDStr)

	// eth_blockNumber
	bnResult, err := rpcCall("eth_blockNumber", nil)
	if err != nil {
		return fmt.Errorf("failed to get block number: %w", err)
	}
	var bnStr string
	if err := json.Unmarshal(bnResult, &bnStr); err != nil {
		bnStr = "0x0"
	}
	blockHeight, _ := parseHexOrDecimal(bnStr)

	// net_peerCount
	peerResult, err := rpcCall("net_peerCount", nil)
	if err != nil {
		peerResult = nil
	}
	var peerStr string
	peerCount := 0
	if peerResult != nil {
		if err := json.Unmarshal(peerResult, &peerStr); err == nil {
			peerCount, _ = parseHexOrDecimal(peerStr)
		}
	}

	// eth_syncing
	syncResult, err := rpcCall("eth_syncing", nil)
	isSyncing := false
	if err == nil && syncResult != nil {
		var syncVal any
		if err := json.Unmarshal(syncResult, &syncVal); err == nil {
			if b, ok := syncVal.(bool); ok {
				isSyncing = b
			} else if m, ok := syncVal.(map[string]any); ok {
				// If it returns an object, it means syncing is in progress
				if _, hasField := m["currentBlock"]; hasField {
					isSyncing = true
				}
			}
		}
	}

	// txpool_status
	var txPending, txQueued int
	txResult, err := rpcCall("txpool_status", nil)
	if err == nil && txResult != nil {
		var txStatus struct {
			Pending string `json:"pending"`
			Queued  string `json:"queued"`
		}
		if err := json.Unmarshal(txResult, &txStatus); err == nil {
			txPending, _ = parseHexOrDecimal(txStatus.Pending)
			txQueued, _ = parseHexOrDecimal(txStatus.Queued)
		}
	}

	fmt.Println("Node Status:")
	fmt.Println("============")
	fmt.Printf("  Version:        %s\n", verStr)
	fmt.Printf("  Network ID:     %d\n", netID)
	fmt.Printf("  Block Height:   %d\n", blockHeight)
	fmt.Printf("  Peers:          %d\n", peerCount)
	fmt.Printf("  Syncing:        %v\n", isSyncing)
	fmt.Printf("  TxPool Pending: %d\n", txPending)
	fmt.Printf("  TxPool Queued:  %d\n", txQueued)

	return nil
}

func queryPeers() error {
	result, err := rpcCall("admin_peers", nil)
	if err != nil {
		return err
	}

	// admin_peers returns an array of peer objects
	var peers []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Enode   string `json:"enode"`
		Network struct {
			LocalAddress  string `json:"localAddress"`
			RemoteAddress string `json:"remoteAddress"`
		} `json:"network"`
	}
	if err := json.Unmarshal(result, &peers); err != nil {
		return fmt.Errorf("failed to parse peers: %w", err)
	}

	fmt.Printf("Connected Peers (%d):\n", len(peers))
	fmt.Println("=====================")
	for i, peer := range peers {
		idDisplay := peer.ID
		if len(idDisplay) > 16 {
			idDisplay = idDisplay[:16] + "..."
		}
		enodeDisplay := peer.Enode
		if len(enodeDisplay) > 50 {
			enodeDisplay = enodeDisplay[:50] + "..."
		}
		fmt.Printf("\n[%d] %s\n", i+1, idDisplay)
		fmt.Printf("    Name:    %s\n", peer.Name)
		fmt.Printf("    Enode:   %s\n", enodeDisplay)
		fmt.Printf("    Local:   %s\n", peer.Network.LocalAddress)
		fmt.Printf("    Remote:  %s\n", peer.Network.RemoteAddress)
	}

	return nil
}

func queryBlock(height int64) error {
	var blockTag string
	if height >= 0 {
		blockTag = fmt.Sprintf("0x%x", height)
	} else {
		blockTag = "latest"
	}

	params := []any{blockTag, false}
	result, err := rpcCall("eth_getBlockByNumber", params)
	if err != nil {
		return err
	}

	var block BlockInfo
	if err := json.Unmarshal(result, &block); err != nil {
		return fmt.Errorf("failed to parse block: %w", err)
	}

	blockNum, _ := parseHexOrDecimal(block.Number)
	ts, _ := parseHexOrDecimal(block.Timestamp)
	gasUsed, _ := parseHexOrDecimal(block.GasUsed)
	gasLimit, _ := parseHexOrDecimal(block.GasLimit)
	txCount := len(block.Transactions)

	fmt.Println("Block Information:")
	fmt.Println("==================")
	fmt.Printf("  Number:        %d\n", blockNum)
	fmt.Printf("  Hash:          %s\n", block.Hash)
	fmt.Printf("  Parent Hash:   %s\n", block.ParentHash)
	fmt.Printf("  Timestamp:     %s\n", time.Unix(int64(ts), 0).Format(time.RFC3339))
	fmt.Printf("  Miner:         %s\n", block.Miner)
	fmt.Printf("  Gas Used:      %d\n", gasUsed)
	fmt.Printf("  Gas Limit:     %d\n", gasLimit)
	fmt.Printf("  Transactions:  %d\n", txCount)

	return nil
}

func querySyncStatus() error {
	result, err := rpcCall("eth_syncing", nil)
	if err != nil {
		return err
	}

	// eth_syncing returns false when synced, or an object when syncing
	var syncVal any
	if err := json.Unmarshal(result, &syncVal); err != nil {
		return fmt.Errorf("failed to parse sync status: %w", err)
	}

	fmt.Println("Sync Status:")
	fmt.Println("============")

	switch v := syncVal.(type) {
	case bool:
		if v {
			fmt.Println("  Status: Syncing...")
		} else {
			fmt.Println("  Status: Synced")
		}
	case map[string]any:
		fmt.Println("  Status: Syncing...")
		if cb, ok := v["currentBlock"]; ok {
			fmt.Printf("  Current Block:  %v\n", cb)
		}
		if hb, ok := v["highestBlock"]; ok {
			fmt.Printf("  Highest Block:  %v\n", hb)
		}
		if sb, ok := v["startingBlock"]; ok {
			fmt.Printf("  Starting Block: %v\n", sb)
		}
	default:
		fmt.Printf("  Status: %v\n", v)
	}

	return nil
}

func queryMetrics() error {
	result, err := rpcCall("qau_qposStatus", nil)
	if err != nil {
		return err
	}

	var metrics map[string]any
	if err := json.Unmarshal(result, &metrics); err != nil {
		return fmt.Errorf("failed to parse metrics: %w", err)
	}

	fmt.Println("Consensus Metrics:")
	fmt.Println("===================")
	// Print key metrics in order
	keyOrder := []string{"height", "proposer", "validators", "epoch", "round", "step"}
	for _, k := range keyOrder {
		if val, ok := metrics[k]; ok {
			fmt.Printf("  %s: %v\n", strings.Title(k), val)
		}
	}
	// Print all other fields
	for k, v := range metrics {
		found := false
		for _, ko := range keyOrder {
			if k == ko {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("  %s: %v\n", k, v)
		}
	}

	return nil
}

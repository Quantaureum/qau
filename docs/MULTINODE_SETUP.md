# Quantaureum Multi-Node Deployment Guide

## Overview

This document explains how to deploy and run a Quantaureum multi-node blockchain network.

## Architecture

```
+---------------------------------------------------------------+
|                    Quantaureum Network                          |
+---------------------------------------------------------------+
|                                                                 |
|  +-------------+    +-------------+    +-------------+         |
|  |   Node 1    |<-->|   Node 2    |<-->|   Node 3    |         |
|  |  (Master)   |    | (Validator) |    |  (Sync)     |         |
|  | :9000 P2P   |    | :9001 P2P   |    | :9002 P2P   |         |
|  | :8545 RPC   |    | :8555 RPC   |    | :8565 RPC   |         |
|  +-------------+    +-------------+    +-------------+         |
|                                                                 |
+---------------------------------------------------------------+
```

## Configuration Files

### Node Configuration

| Node | Config File | Data Directory | Role |
|------|----------|----------|------|
| Node1 | `configs/config.json` | `./data` | Master node, produces blocks |
| Node2 | `configs/config.node2.json` | `./data2` | Validator node |
| Node3 | `configs/config.node3.json` | `./data3` | Sync node, SyncOnly mode |

### Genesis Configuration

All nodes must use the same `configs/genesis.json` file to ensure the genesis block is identical:

```json
{
  "chainId": 1668,
  "networkId": 1668,
  "timestamp": 1735300000,
  "gasLimit": 30000000,
  "extraData": "Quantaureum Genesis Block - Mainnet"
}
```

**Important**: `timestamp` must be a fixed value; otherwise each node generates a different genesis block hash, preventing synchronization.

## Quick Start

### Manual Startup

Build the binaries first (see [INSTALL.md](INSTALL.md)):

```powershell
go build -o build\qaud.exe .\cmd\qaud
```

#### 1. Start Node1 (Master)

```powershell
.uild\qaud.exe -config configs/config.json
```

#### 2. Start Node2 (Validator)

```powershell
.uild\qaud.exe -config configs/config.node2.json
```

#### 3. Start Node3 (Sync - SyncOnly)

```powershell
.uild\qaud.exe -config configs/config.node3.json
```

**Note**: Node3 has `"syncOnlyMode": true` configured, so it does not produce blocks and only syncs from other nodes.

## Ports

### Blockchain Node Ports

| Port | Purpose | Node |
|------|------|------|
| 8545 | RPC API | Node1 |
| 8555 | RPC API | Node2 |
| 8565 | RPC API | Node3 |
| 9000 | P2P communication | Node1 |
| 9001 | P2P communication | Node2 |
| 9002 | P2P communication | Node3 |

## Node Modes

### Normal Mode (Node1, Node2)

- `"syncOnlyMode": false`
- Can produce new blocks
- Participates in consensus

### SyncOnly Mode (Node3)

- `"syncOnlyMode": true`
- Only syncs blocks, does not produce new blocks
- Does not create a local genesis at startup; syncs from peers
- Suitable for read-only nodes or newly joined nodes

## Troubleshooting

### Node Fails to Sync

1. Check that all nodes use the same `genesis.json`
2. Confirm the `bootstrapPeers` configuration is correct
3. Check whether the firewall is blocking P2P ports

### Cleaning Data and Restarting

```powershell
# Stop all node processes (Ctrl+C in each terminal, or Stop-Process by name)
Get-Process qaud -ErrorAction SilentlyContinue | Stop-Process

# Clean up the data directories
Remove-Item -Recurse -Force .\data\*, .\data2\*, .\data3\*

# Restart each node with the commands above
```

### Checking Block Height

```powershell
# Check via RPC
$body = '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
Invoke-RestMethod -Uri "http://localhost:8545" -Method Post -ContentType "application/json" -Body $body
```

## Log Files

| File | Content |
|------|------|
When started manually from a terminal, each node logs to its own console. To persist logs, redirect at startup, e.g.:

```powershell
Start-Process -FilePath .uild\qaud.exe -ArgumentList '-config','configs/config.json'   -RedirectStandardOutput logs/node1_output.log -RedirectStandardError logs/node1_error.log
```
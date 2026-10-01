# Quantaureum Data Persistence Guide

## Overview

All Quantaureum blockchain data is persisted to disk, ensuring that state is not lost after a restart.

## Data Storage Locations

```
data/
|-- blocks/              # Blockchain data
|-- state/               # State database
|-- checkpoints/         # State checkpoints
`-- keystore/            # Keystore
```

## Automatic Persistence

### 1. Block Data
- **Trigger**: Automatically saved after each new block is confirmed
- **Content**: Block headers, transactions, receipts
- **Recovery**: Automatically loaded at startup

### 2. State Data
- **Trigger**: Automatically saved after a block is executed
- **Content**: Account state, contract storage
- **Recovery**: Automatically loaded at startup

### 3. Checkpoints
- **Trigger**: Automatically saved every 100 blocks
- **Content**: Full state snapshot
- **Recovery**: The latest checkpoint is automatically loaded at startup

## Manual Backup

### Backing Up All Data
```powershell
# Stop the node
# Copy the entire data directory
Copy-Item -Recurse ./data ./backup_$(Get-Date -Format "yyyyMMdd")
```

### Restoring Data
```powershell
# Stop the node
# Restore the data directory
Remove-Item -Recurse ./data
Copy-Item -Recurse ./backup_20241224 ./data
# Start the node
```

## Key Code Locations

| Feature | File |
|------|------|
| Block storage | `internal/storage/block/` |
| State storage | `internal/storage/state/` |
| Checkpoint management | `internal/storage/checkpoint/` |
| Node shutdown save | `internal/node/node.go` |

## Data Migration

### Preserving Data When Upgrading
1. Back up the `data/` directory
2. Update the code and recompile
3. Start the new version; data is loaded automatically

### Multi-node Data Synchronization
- Blockchain data is synchronized over the P2P network
- State data is computed and verified locally

## Failure Recovery

### Corrupt Checkpoint
If a checkpoint is corrupted, the system automatically reconstructs state from the blockchain:
```
- No valid checkpoint found, will reconstruct from blockchain
- Reconstructing state from blockchain...
- Replayed X blocks
```

### Corrupt State Data
Delete the corrupted state directory; the system will rebuild it from the blockchain:
```powershell
Remove-Item -Recurse ./data/state
# Restart the node; the state will be rebuilt automatically
```

## Best Practices

1. **Regular backups**: back up the `data/` directory daily
2. **Graceful shutdown**: stop the node with Ctrl+C to ensure data is saved
3. **Monitor disk**: ensure there is enough disk space
4. **Version control**: record the data state before every upgrade
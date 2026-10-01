# Quantaureum Validator Onboarding Guide

> **Version**: v1.0 | **Updated**: 2026-06-08 | **Network**: Mainnet ChainID 1668 / Testnet ChainID 1669

---

## 1. Overview

### What is a Validator

Validators are core participants in the Quantaureum network, responsible for proposing new blocks, attesting to block validity, and applying threshold signatures to final blocks. By staking QAU tokens, validators earn the right to participate in consensus while also earning block rewards and transaction fees.

### Stardust Consensus Three-Chamber Architecture

Quantaureum adopts **Stardust Consensus**, an innovative consensus mechanism that combines QPOS (Quantum Proof of Stake) with QTD (Quantum Threshold Dilithium), inspired by the ancient Chinese Three Departments and Six Ministries system:

| Chamber | Role | Members | Responsibilities |
|------|------|------|------|
| **Secretariat** | Proposer | Rotating | Selected by staking weight; bundles transactions and proposes new blocks |
| **Chancellery** | Attestation | 128 people | Attestation votes on proposed blocks to confirm validity |
| **Department of State Affairs** | QTD Sealer | 3 people | Applies a final seal to blocks using QTD threshold signatures, ensuring immutability |

**In simple terms**: the Secretariat drafts the proposal, the Chancellery reviews it, and the Department of State Affairs seals it into effect. The three work together to ensure blocks are both efficient and secure.

### Why Become a Validator

- **Earn rewards**: block rewards + transaction fees per block production cycle
- **Participate in governance**: validators hold voting rights over network governance
- **Quantum security**: uses Dilithium3 post-quantum cryptography to withstand future quantum computing attacks
- **Ecosystem building**: as an early validator, help build the world's first post-quantum blockchain

---

## 2. Hardware Requirements

### Minimum Configuration

| Item | Requirement |
|------|------|
| CPU | 4 cores (ARM64 or x86_64) |
| Memory | 8 GB |
| Storage | 500 GB SSD |
| Bandwidth | 100 Mbps |
| Operating System | Linux (Ubuntu 22.04+ recommended) |

### Recommended Configuration

| Item | Requirement |
|------|------|
| CPU | 8 cores (ARM64 or x86_64) |
| Memory | 16 GB |
| Storage | 1 TB NVMe SSD |
| Bandwidth | 1 Gbps |
| Operating System | Linux (Ubuntu 22.04+ recommended) |

### Network Requirements

| Port | Protocol | Purpose | Exposure |
|------|------|------|---------|
| 9000 | TCP | P2P node communication | Public |
| 8080 | TCP | Health check | Public |
| 8545 | HTTP | JSON-RPC | Local only (127.0.0.1) |
| 8546 | WebSocket | WS-RPC | Local only (127.0.0.1) |

> **Security note**: Never expose the RPC ports (8545/8546) to the public internet, as this could lead to node abuse. For remote access, use an SSH tunnel or reverse proxy.

### Storage Requirements

- Block data grows at roughly **1-2 GB/day**; make sure to reserve sufficient space
- SSDs are recommended; mechanical hard drives severely impact sync speed and block production performance
- Consider configuring disk usage monitoring alerts (80% threshold)

---

## 3. Staking Requirements

### Core Parameters

| Parameter | Value |
|------|-----|
| Minimum stake | **32 QAU** |
| Maximum number of validators | **100** |
| Unbonding period | **21 days** |
| Commission range | **1% - 50%** |
| Slot time | **12 seconds** |

### Risk Notes

1. **Slashing risk**: if a validator double-signs (double vote) or performs a surround vote, it will be slashed
2. **Jail risk**: prolonged downtime or misbehavior results in being jailed, during which no rewards are earned
3. **Lock-up risk**: staked QAU cannot be transferred during the unbonding period (21 days); make sure you keep enough liquidity
4. **Key loss risk**: a lost Dilithium3 key cannot be recovered, **always back it up**
5. **Hardware failure risk**: no rewards are earned while the node is offline; consider redundancy and monitoring

---

## 4. Quick Start (Go Live in 5 Steps)

The following is the shortest path to becoming a validator; detailed steps are in Section 5.

```
Step 1: Generate a Dilithium3 key pair
  |
  v
Step 2: Stake 32 QAU
  |
  v
Step 3: Deploy the validator node
  |
  v
Step 4: Start and sync
  |
  v
Step 5: Verify block production
```

### 4.1 Generate a Dilithium3 Key Pair

```bash
# Use qauctl to generate a post-quantum key
qauctl validator generate --output ./my-validator.key

# View the address for the key (private key not shown)
qauctl validator info ./my-validator.key
```

> **Extremely important**: back up the key file to multiple secure locations! Losing the key = your staked funds are permanently locked.

### 4.2 Stake 32 QAU

```bash
# Import the account to the node
qauctl account-remote import ./my-validator.key http://YOUR_NODE_IP:8545 --password "your_password"

# Unlock the account
qauctl account-remote unlock 0xyour_address http://YOUR_NODE_IP:8545 --password "your_password"

# Stake 32 QAU
curl -X POST http://YOUR_NODE_IP:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_stake","params":["0xyour_address","0x1BC16D674EC80000"],"id":1}'
```

### 4.3 Deploy the Validator Node

```bash
# Deploy the validator key to the server
qauctl validator deploy ./my-validator.key YOUR_SERVER_IP --ssh-key ~/.ssh/id_rsa --restart
```

### 4.4 Start and Sync

```bash
# Start the node service
systemctl start quantaureum

# Check sync status
qauctl status sync --rpc http://YOUR_NODE_IP:8545
```

### 4.5 Verify Block Production

```bash
# Check validator status
qauctl validator check YOUR_SERVER_IP --ssh-key ~/.ssh/id_rsa

# View the current block height
qauctl status block --rpc http://YOUR_NODE_IP:8545
```

When `isProposer=true` appears in the logs or the block height keeps increasing, congratulations - your validator is successfully online!

---

## 5. Detailed Steps

### 5.1 Environment Preparation

#### Install Go 1.26+

```bash
# Download and install Go 1.26+
wget https://go.dev/dl/go1.26.0.linux-arm64.tar.gz
sudo tar -C /usr/local -xzf go1.26.0.linux-arm64.tar.gz

# Configure environment variables
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc

# Verify the installation
go version
# Output: go version go1.26.0 linux/arm64
```

#### Build qaud (Node Daemon)

```bash
# Clone the repository
git clone https://github.com/quantaureum/quantaureum.git
cd quantaureum

# Build
make qaud

# Install to a system path
sudo cp build/bin/qaud /usr/local/bin/qaud

# Verify
qaud version
```

#### Build qauctl (Management Tool)

```bash
# In the same repository directory
make qauctl

# Install to a system path
sudo cp build/bin/qauctl /usr/local/bin/qauctl

# Verify
qauctl version
```

### 5.2 Key Generation

#### Generate a Dilithium3 Key Pair

Quantaureum uses the post-quantum cryptographic algorithm Dilithium3 instead of traditional ECDSA; the key sizes are much larger than those of traditional blockchains:

| Item | Dilithium3 | ECDSA (secp256k1) |
|------|-----------|-------------------|
| Private key length | 4000 bytes (8000 hex) | 32 bytes (64 hex) |
| Public key length | 1952 bytes (3904 hex) | 64 bytes (128 hex) |
| Quantum-resistant | Yes | No |

```bash
# Generate a key pair
qauctl validator generate --output ./my-validator.key

# View the address for the key
qauctl validator info ./my-validator.key
# Output similar to:
# Address: 0x1111111111111111111111111111111111111111
# Algorithm: Dilithium3
```

#### Back Up the Key File (Extremely Important!)

```bash
# Key file format: dilithium3:private_key_hex+public_key_hex
# Example: dilithium3:a3f2b8... (about 11905 hex characters)

# Back up to multiple secure locations
cp ./my-validator.key /secure/backup/location1/validator.key
cp ./my-validator.key /secure/backup/location2/validator.key

# Optional: encrypt the backup
gpg --symmetric --cipher-algo AES256 ./my-validator.key
# This generates an encrypted my-validator.key.gpg file
```

> **Warning**: the key file contains the private key. If leaked, an attacker can impersonate your validator. You must:
> - Store it on offline media (e.g., an encrypted USB drive)
> - Do not upload it to the cloud or a code repository
> - Keep at least two independent backups

### 5.3 Staking Operations

#### Import the Account to the Node

```bash
# Import the key to the remote node (the private key is read from the file and not shown in the output)
qauctl account-remote import "./my-validator.key" http://YOUR_NODE_IP:8545 --password "your_password"

# Can also be imported directly via RPC
curl -X POST http://YOUR_NODE_IP:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"personal_importRawKey","params":["dilithium3:your_hex_key","your_password"],"id":1}'
```

> **Note**: the key format for `personal_importRawKey` is `dilithium3:private_key_hex+public_key_hex`; do not omit the `dilithium3:` prefix.

#### Unlock the Account

```bash
# Unlock using qauctl
qauctl account-remote unlock 0xyour_address http://YOUR_NODE_IP:8545 --password "your_password"

# Unlock via RPC (unlock for 3600 seconds)
curl -X POST http://YOUR_NODE_IP:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"personal_unlockAccount","params":["0xyour_address","your_password",3600],"id":1}'
```

> **Important**: the import password and unlock password must match! A mismatch will cause the unlock to fail.

#### Stake via qau_stake

```bash
# Stake 32 QAU
# 32 QAU = 32 * 10^18 = 0x1BC16D674EC80000 (in wei)
curl -X POST http://YOUR_NODE_IP:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "qau_stake",
    "params": ["0xyour_address", "0x1BC16D674EC80000"],
    "id": 1
  }'
```

#### Verify the Stake

```bash
# Query staking information
curl -X POST http://YOUR_NODE_IP:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_getStake","params":["0xyour_address"],"id":1}'

# Query staking statistics
curl -X POST http://YOUR_NODE_IP:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_getStakingStats","params":[],"id":1}'

# Query pending rewards
curl -X POST http://YOUR_NODE_IP:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_getPendingRewards","params":["0xyour_address"],"id":1}'
```

### 5.4 Node Deployment

#### System Configuration

```bash
# Increase the file descriptor limit
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Disable swap (recommended)
sudo swapoff -a
sudo sed -i '/swap/d' /etc/fstab

# Configure kernel parameters
sudo sysctl -w vm.swappiness=1
sudo sysctl -w vm.dirty_ratio=15
sudo sysctl -w vm.dirty_background_ratio=5
```

#### Genesis File Configuration

```bash
# Create the configuration directory
sudo mkdir -p /etc/quantaureum
sudo mkdir -p /var/lib/quantaureum

# Download the genesis file (from the official source)
sudo curl -o /etc/quantaureum/genesis.json https://genesis.quantaureum.com/mainnet.json

# Verify the genesis file
cat /etc/quantaureum/genesis.json | python3 -m json.tool
```

#### Validator Key Deployment

```bash
# Use qauctl to deploy the validator key to the server
qauctl validator deploy "./my-validator.key" YOUR_SERVER_IP \
  --ssh-key ~/.ssh/id_rsa \
  --restart

# Or deploy manually
sudo cp ./my-validator.key /var/lib/quantaureum/validator.key
sudo chmod 600 /var/lib/quantaureum/validator.key
sudo chown quantaureum:quantaureum /var/lib/quantaureum/validator.key
```

> **Critical**: the validator key file `/var/lib/quantaureum/validator.key` uses the format `dilithium3:hex...`. If the node auto-generates a new key at startup, the address will not match the genesis configuration, resulting in `isProposer=false` and the node cannot produce blocks. Make sure the key file is correct.

#### Systemd Service Configuration

Create `/etc/systemd/system/quantaureum.service`:

```ini
[Unit]
Description=Quantaureum Node
After=network.target

[Service]
Type=simple
User=quantaureum
Group=quantaureum
Environment=QAU_VALIDATOR_KEY_PASSWORD=your_key_password
ExecStart=/usr/local/bin/qaud \
  --datadir /var/lib/quantaureum \
  --config /etc/quantaureum/config.json \
  --validator-key /var/lib/quantaureum/validator.key \
  --port 9000 \
  --http \
  --http.addr 127.0.0.1 \
  --http.port 8545 \
  --ws \
  --ws.addr 127.0.0.1 \
  --ws.port 8546 \
  --http.api qau,personal,txpool,net,web3,qpos
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
# Create the service user
sudo useradd -r -s /bin/false quantaureum
sudo chown -R quantaureum:quantaureum /var/lib/quantaureum

# Reload and enable the service
sudo systemctl daemon-reload
sudo systemctl enable quantaureum
```

#### Start the Node

```bash
# Initialize the node (first time)
qaud init /etc/quantaureum/genesis.json --datadir /var/lib/quantaureum

# Start the service
sudo systemctl start quantaureum

# View the startup logs
sudo journalctl -u quantaureum -f
```

### 5.5 Verify Operation

#### Check Sync Status

```bash
# Using qauctl
qauctl status sync --rpc http://127.0.0.1:8545

# Via RPC
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":1}'

# A return of false means syncing is complete
```

#### Check Validator Status

```bash
# Using qauctl
qauctl validator check YOUR_SERVER_IP --ssh-key ~/.ssh/id_rsa

# View consensus status
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_qposStatus","params":[],"id":1}'

# View detailed consensus information
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_qposStatus","params":[],"id":1}'
```

#### Check Block Production

```bash
# View the current block height
qauctl status block --rpc http://127.0.0.1:8545

# Continuously monitor block growth
watch -n 12 'curl -s -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}" | python3 -c "import sys,json; print(int(json.load(sys.stdin)[\"result\"],16))"'
```

**Success indicators**:
- `isProposer=true` appears in the logs (when it is your turn to produce a block)
- The block height keeps increasing
- Your address appears in the validator list in `qau_qposStatus`

---

## 6. Node Operations

### 6.1 Daily Monitoring

#### Health Check Endpoint

```bash
# Public health check (port 8080)
curl http://YOUR_SERVER_IP:8080/health

# A return of OK means the node is running normally
```

#### Key RPC Commands

```bash
# Node status overview
qauctl status node --rpc http://127.0.0.1:8545

# Current block height
qauctl status block --rpc http://127.0.0.1:8545

# Sync status
qauctl status sync --rpc http://127.0.0.1:8545

# Consensus status
curl -s -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_qposStatus","params":[],"id":1}'

# Transaction pool status
curl -s -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"txpool_status","params":[],"id":1}'

# Number of network peers
curl -s -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}'
```

#### Viewing Logs

```bash
# View logs in real time
sudo journalctl -u quantaureum -f

# View the last 100 lines
sudo journalctl -u quantaureum -n 100

# View error logs
sudo journalctl -u quantaureum -p err

# View a specific time period
sudo journalctl -u quantaureum --since "1 hour ago"
```

### 6.2 Upgrade the Node

#### Zero-downtime Upgrade with qau-visor

```bash
# qau-visor supports zero-downtime upgrades of validator nodes
qau-visor upgrade --version v1.x.x
```

#### Manual Upgrade Steps

```bash
# 1. Build the new version
cd quantaureum && git pull && make qaud

# 2. Stop the service
sudo systemctl stop quantaureum

# 3. Replace the binary (note: do not overwrite a running binary directly)
sudo cp build/bin/qaud /usr/local/bin/qaud

# 4. Restart the service
sudo systemctl start quantaureum

# 5. Verify the version
qaud version
```

> **Note**: directly `cp`-overwriting a running binary will raise a "Text file busy" error. You must stop the process first, then replace the file.

### 6.3 Troubleshooting

#### Node Not Syncing

```bash
# 1. Check network connectivity
curl -s -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}'

# 2. Check sync status
qauctl status sync --rpc http://127.0.0.1:8545

# 3. Check disk space
df -h /var/lib/quantaureum

# 4. Restart the node
sudo systemctl restart quantaureum

# 5. If it still does not sync, check the genesis file and configuration
diff /etc/quantaureum/genesis.json <(curl -s https://genesis.quantaureum.com/mainnet.json)
```

#### Being Jailed

A validator is jailed for the following behaviors:

| Violation type | Jail duration | Description |
|---------|----------|------|
| `double_vote` | 1 hour | Signing two different blocks at the same height |
| `surround_vote` | 1 hour | Surround vote (LMD GHOST attack) |
| `downtime` | 1 hour | Prolonged offline period without participating in consensus |

```bash
# Check whether jailed
curl -s -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_getStake","params":["0xyour_address"],"id":1}'

# Manually unjail after the jail period expires
curl -s -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_unjail","params":["0xyour_address"],"id":1}'
```

#### Handling Operational Mistakes

**Accidentally deleted validator.key**:
1. Restore the key file from backup to `/var/lib/quantaureum/validator.key`
2. Make sure the file format is `dilithium3:hex...`
3. Restart the node: `sudo systemctl restart quantaureum`
4. Verify that `myAddr` in the logs matches the genesis validator address

**Node cannot produce blocks after a chain reset**:
1. After a chain reset, the node automatically generates a new `validator.key`
2. The new key's address does not match the genesis configuration, resulting in `isProposer=false`
3. You must replace `/var/lib/quantaureum/validator.key` with the genesis validator's private key
4. After restarting the node, verify that `myAddr` matches

---

## 7. Security Best Practices

### Key Security

- **Cold storage**: backups of the validator key should be stored on offline media (encrypted USB drives, hardware security modules)
- **Multiple backups**: keep at least 3 independent backups stored in different physical locations
- **Encryption protection**: encrypt backup files using GPG or other tools
- **Access control**: set the `validator.key` file permissions to `600`, readable only by the quantaureum user
- **Never share**: do not upload the key file to the cloud, a code repository, or send it to anyone

```bash
# Set correct file permissions
sudo chmod 600 /var/lib/quantaureum/validator.key
sudo chown quantaureum:quantaureum /var/lib/quantaureum/validator.key

# Encrypt the backup
gpg --symmetric --cipher-algo AES256 /var/lib/quantaureum/validator.key
```

### Server Security

```bash
# 1. Configure SSH key login and disable password login
sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# 2. Configure the firewall (only open necessary ports)
sudo ufw default deny incoming
sudo ufw allow 9000/tcp    # P2P
sudo ufw allow 8080/tcp    # health check
sudo ufw allow ssh         # SSH
sudo ufw enable

# 3. Disable root remote login
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# 4. Install fail2ban to prevent brute-force attacks
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
```

### Monitoring and Alerts

It is recommended to configure the following monitoring items:

| Monitoring item | Alert threshold | Description |
|--------|---------|------|
| Node health check | 3 consecutive failures | The node may be down |
| Block height | No growth for more than 60 seconds | The node may not be syncing |
| Disk usage | > 80% | Need to expand or clean up |
| Memory usage | > 90% | Possible OOM |
| CPU usage | Sustained > 80% | Performance bottleneck |
| Jail status | Jailed | Check the cause and unjail |

### Dilithium3 Key vs Traditional ECDSA Key

| Feature | Dilithium3 | ECDSA (secp256k1) |
|------|-----------|-------------------|
| Quantum-resistant | Yes | No |
| Private key size | 4000 bytes | 32 bytes |
| Public key size | 1952 bytes | 64 bytes |
| Signature size | ~3.3 KB | 64 bytes |
| Key file size | ~12 KB | ~0.5 KB |
| Backup time | Slightly longer (larger file) | Very fast |

> **Key difference**: Dilithium3 key files are much larger than ECDSA keys. When backing up, make sure the entire file is copied and not truncated. The key file is about 11905 hex characters.

---

## 8. Frequently Asked Questions (FAQ)

### Q1: What is the minimum stake?

**32 QAU**. Below this amount you cannot become a validator. You can choose to delegate your QAU to an existing validator (delegation is coming soon).

### Q2: How soon after staking can I start producing blocks?

After the staking transaction is confirmed, the validator is usually added to the active validator set within **1-2 epochs** (from a few minutes to over ten minutes) and begins participating in consensus.

### Q3: Why is the unbonding period 21 days?

The 21-day unbonding period is a security design that prevents validators from transferring funds immediately after misbehaving. It gives the network enough time to detect and punish malicious behavior.

### Q4: What is the key file format?

The key file uses the format `dilithium3:private_key_hex+public_key_hex`, totaling about 11905 hex characters. The private key portion is 8000 hex characters (4000 bytes) and the public key portion is 3904 hex characters (1952 bytes).

### Q5: Can I use an ECDSA key?

**No**. Quantaureum uses post-quantum cryptography and only supports Dilithium3 keys. ECDSA keys cannot participate in Quantaureum consensus.

### Q6: Will my node be punished if it goes offline?

Short downtime (a few minutes) usually does not incur severe penalties, but you will miss rewards during that period. Prolonged downtime results in being jailed (1 hour), during which you earn no rewards. Frequent downtime may affect your reputation.

### Q7: How do I change validator servers?

1. Deploy a node on the new server and sync it to the latest block
2. Copy `validator.key` to the new server
3. Stop the old server node
4. Start the new server node
5. Verify the new node is producing blocks normally

> Note: do not run two nodes using the same key at the same time, as this causes double-signing (double vote) and will result in being jailed.

### Q8: Why do RPC methods use the `qau_` prefix instead of `eth_`?

Quantaureum is an independent quantum blockchain, not a fork of Ethereum. All RPC methods use the `qau_` prefix to distinguish clearly. For example: `eth_blockNumber`, `eth_getBalance`, `eth_sendRawTransaction`. Using `eth_*` method names returns a "method not found" error.

### Q9: How do I view my validator rewards?

```bash
# Query pending rewards
curl -s -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_getPendingRewards","params":["0xyour_address"],"id":1}'
```

### Q10: What is the difference between testnet and mainnet?

| Item | Mainnet | Testnet |
|------|------|--------|
| ChainID | 1668 | 1669 |
| Token | QAU (has real value) | tQAU (test token, no value) |
| Purpose | Production | Development and testing |
| Staking | Real QAU | Test QAU |

It is recommended to validate all operations on the testnet first before executing them on the mainnet.

---

## 9. Glossary

| Term | English | Explanation |
|------|------|------|
| **QPOS** | Quantum Proof of Stake | Quantum Proof of Stake consensus mechanism that selects block proposers based on staking weight |
| **QTD** | Quantum Threshold Dilithium | Quantum threshold signature scheme based on Dilithium3; any 2 of the 3 sealers can complete the final signature |
| **Dilithium3** | - | NIST-standardized post-quantum digital signature algorithm, resistant to quantum computing attacks |
| **Kyber** | - | NIST-standardized post-quantum key encapsulation mechanism used for encrypted communication |
| **Secretariat** | Proposer Chamber | The proposal layer in Stardust Consensus, responsible for bundling transactions and proposing new blocks |
| **Chancellery** | Attestation Chamber | The attestation layer in Stardust Consensus, where 128 people vote to attest blocks |
| **Department of State Affairs** | Sealer Chamber | The finalization layer in Stardust Consensus, where 3 people seal blocks using QTD threshold signatures |
| **Jailing** | - | Temporarily excluding a misbehaving validator from consensus, during which no rewards are earned |
| **Slashing** | - | Confiscating part of a severely misbehaving validator's staked tokens |
| **Unbonding** | - | The waiting period (21 days) for unstaking, during which funds are locked and cannot be transferred |
| **Slot** | - | The block production time unit; each Slot is 12 seconds in Quantaureum |
| **Epoch** | - | A period consisting of a set of Slots, used for validator set updates |
| **qaud** | Quantaureum Daemon | The Quantaureum node daemon |
| **qauctl** | Quantaureum Control | The Quantaureum unified management tool |

---

## 10. Resource Links

| Resource | Link |
|------|------|
| GitHub repository | https://github.com/quantaureum/quantaureum |
| Official documentation | https://docs.quantaureum.com |
| Block explorer | https://explorer.quantaureum.com |
| Discord community | https://discord.gg/MSctkBT5j |
| Telegram group | https://t.me/quantaureum |
| Genesis file (mainnet) | https://genesis.quantaureum.com/mainnet.json |
| Genesis file (testnet) | https://genesis.quantaureum.com/testnet.json |
| Status page | https://status.quantaureum.com |
| Security vulnerability reporting | security@quantaureum.com |

---

> **Disclaimer**: becoming a validator involves financial risk. Please fully understand the staking mechanism and slashing rules before operating. This document is for technical reference only and does not constitute investment advice.

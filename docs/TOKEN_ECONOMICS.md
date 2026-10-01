# QAU Token Economics

## Core Positioning

QAU is the **native utility token** of the Quantaureum quantum-safe blockchain. It is used to pay for network security services, participate in consensus through staking, and engage in protocol governance.

**On the name "Quantaureum":** Derived from Ancient Greek, meaning "quantum gold." The name reflects our design philosophy - creating a digital asset with gold-like scarcity and cryptographic unforgeability. Where gold derives its value from physical scarcity in nature, QAU derives its scarcity from post-quantum cryptographic guarantees and protocol-governed issuance. This is a narrative parallel, not a legal peg.

**QAU is not a payment currency, not a stablecoin, and is not pegged to any fiat currency or commodity.** Its value is derived from network usage demand and the security services it enables.

## 1. Token Basics

| Parameter | Value |
|-----------|-------|
| Token Name | Quantaureum |
| Token Symbol | QAU |
| Token Type | Native Utility Token |
| Initial Supply | 20,000,000 QAU |
| Ongoing Issuance | Protocol-governed staking rewards only (no manual minting) |
| Decimals | 18 |
| Blockchain | Quantaureum Native Blockchain |
| Consensus | Quantum Proof of Stake (QPOS) |
| Cryptography | Dilithium3 + Kyber-768 post-quantum |

## 2. Token Utility

QAU serves exactly three purposes within the Quantaureum network:

### 2.1 Network Transaction Fees (Gas)

- All on-chain operations (transfers, contract calls, deployments) require QAU as gas
- EIP-1559 fee model: base fee burned + priority fee to validators
- Base fee burning creates deflationary pressure

### 2.2 Staking for Consensus Participation

- Validators stake QAU to participate in QPOS consensus
- Delegators can delegate QAU to validators and share rewards
- Staking rewards are issued exclusively by protocol, not by any individual or entity

### 2.3 Protocol Governance

- QAU holders participate in network governance voting
- Includes protocol upgrades, parameter adjustments, and community decisions

## 3. Token Allocation

### 3.1 Genesis Allocation (20,000,000 QAU)

| Category | Amount | Share | Vesting |
|----------|--------|-------|---------|
| Community Contribution | 4,961,600 QAU | 24.81% | Free circulation |
| Team | 4,000,000 QAU | 20% | 4-year linear, 1-year cliff |
| Staking Incentive Pool | 4,000,000 QAU | 20% | 5-year linear |
| Development Fund | 2,000,000 QAU | 10% | 4-year linear, 1-year cliff |
| Ecosystem Fund | 2,000,000 QAU | 10% | 4-year linear |
| Foundation Reserve | 2,000,000 QAU | 10% | 4-year linear, 1-year cliff |
| Security & Compliance | 1,000,000 QAU | 5% | 3-year linear |
| 6 Validators | 38,400 QAU | 0.19% | 6 × 6,000 QAU staked in consensus, 6 × 400 QAU account balance |
| **Total** | **20,000,000 QAU** | **100%** | |

### 3.2 Release Rules

- All locked tokens managed via smart contracts, verifiable on-chain
- Team, Development Fund, and Foundation Reserve include 1-year cliff, linear monthly release thereafter
- Foundation reserve releases require community governance approval

## 4. Staking Economics

### 4.1 Validator Requirements

| Parameter | Value |
|-----------|-------|
| Minimum Stake | 32 QAU |
| Key Type | Dilithium3 (mandatory, quantum-safe) |

### 4.2 Staking Rewards

- Issued by the protocol automatically, not controlled by any entity
- Formula (Ethereum Altair-aligned): each validator's per-epoch base reward is
  `stake x 31 / sqrt(total_staked)`, computed in gwei. Attesters receive 87.5%
  of issuance; the block proposer pool receives 12.5%
- **Yield is a function of total stake, not of a participation ratio.** Because
  issuance scales with `sqrt(total_staked)` while yield divides by stake, APY
  falls as `1/sqrt(total_staked)` — early stakers are not locked into a
  permanently high rate, and no manual adjustment or governance vote is involved

| Total staked (QAU) | Validators | Annual issuance (QAU) | Staking APY |
|---|---|---|---|
| 36,000 (genesis) | 6 | 15,275 | 42.43% |
| 600,000 | 100 | 62,361 | 10.39% |
| 3,996,000 | 666 | 160,935 | 4.03% |
| 19,998,000 | 3,333 | 360,023 | 1.80% |

- The high genesis-stage APY is a deliberate bootstrap premium. Its absolute
  cost is small: 15,275 QAU/year is 0.076% of supply, and it decays
  automatically as stake grows
- No supply cap; no manual minting; no admin-adjustable rate
- Reproduce any row with `go run ./cmd/econsim table -preset live`

### 4.3 Slashing

| Violation | Penalty |
|-----------|---------|
| Double signing | 100% slash + removal from validator set |
| Extended downtime | Progressive penalty proportional to offline duration |
| Malicious behavior | 10-100% based on severity |

### 4.4 Delegation

- Minimum delegation: 1 QAU (no minimum, encourages broad participation)
- Delegation fee: 0-15% of rewards, set by validator
- 7-day unbonding period
- Delegators share slashing risk proportionally

## 5. Economic Security

### 5.1 Deflationary Mechanism

- EIP-1559 base fee is burned (removed from supply, credited to no account);
  the priority fee goes to the block proposer
- Net issuance = staking rewards - base fee burned
- Net deflation occurs under sustained high network usage

> **Current scope of burning.** Base-fee burning applies to EIP-1559
> dynamic-fee transactions. Legacy transaction types currently pay their entire
> fee to the block proposer with no burn. Wallets that submit EIP-1559
> transactions (the default in the Quantaureum wallet) contribute to burning;
> legacy submissions do not. Extending burning to all transaction types is
> tracked as an open item and is not yet in effect.

### 5.2 Supply Dynamics

- No fixed supply cap (similar to Ethereum)
- No manual minting capability (no gold-backed or admin minting mechanism)
- Total supply grows only through protocol-governed staking rewards
- Fee burning provides deflationary counterbalance

## 6. Governance

### 6.1 Governance Model

Quantaureum uses community-driven governance through the QIP (Quantaureum Improvement Proposal) process:

1. Community Discussion -> 2. QIP Draft -> 3. Technical Review -> 4. Testnet Implementation -> 5. Community Vote -> 6. Mainnet Activation

### 6.2 Foundation Role

- The Foundation is the legal entity responsible for protocol maintenance and compliance
- Treasury funds managed by the Foundation under community oversight
- Parameter changes require QIP process
- Foundation gradually transfers governance authority to community DAO

## 7. Comparative Positioning

| Feature | Bitcoin | Ethereum | QAU |
|---------|---------|----------|-----|
| Type | Store of value | Smart contract platform fuel | **Quantum-safe network fuel** |
| Signature | ECDSA | ECDSA | **Dilithium3 (post-quantum)** |
| Key Exchange | None | ECIES | **Kyber-768 (post-quantum)** |
| Consensus | PoW | PoS | QPOS |
| Issuance | Mining | Staking | Staking (protocol-governed) |
| Quantum Resistance | None | None | Yes (native) |

## 8. Disclaimer

QAU is the utility token of the Quantaureum network, used to pay for network services and participate in consensus security. QAU is not a security, not a payment currency, not a stablecoin, and is not pegged to any fiat currency or commodity. This document does not constitute investment advice or a solicitation. Consult local laws and regulations before participating in the network.
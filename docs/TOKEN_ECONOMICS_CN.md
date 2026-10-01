# QAU Token Economics

## Core Positioning

QAU is the **Native Utility Token** of the Quantaureum quantum-secure blockchain, used to pay network security fees, stake for consensus participation, and for protocol governance.

**About the meaning of "Quantum Gold":** Quantaureum derives from ancient Greek and means "quantum gold." The name represents our design philosophy - creating in the digital age a value carrier that is as scarce, secure, and non-counterfeitable as gold. Gold is a naturally scarce asset; QAU is a cryptographically-backed scarce digital asset. This is a narrative resonance, not a legal anchor.

QAU is not a payment currency, not a stablecoin, and not pegged to any fiat currency or commodity. Its value derives from network usage demand and security services.


## 1. Token Basic Information

| Parameter | Value |
|------|-----|
| Token Name | Quantaureum |
| Token Symbol | QAU |
| Token Type | Native Utility Token |
| Genesis Supply | 20,000,000 QAU |
| Subsequent Issuance | Issued only through the staking reward protocol (no manual minting) |
| Decimals | 18 |
| Blockchain | Quantaureum native blockchain |
| Consensus Mechanism | Quantum Proof of Stake (QPOS) |
| Cryptography | Dilithium3 + Kyber-768 post-quantum cryptography suite |


## 2. Token Use Cases

QAU's sole purpose is to run and maintain the Quantaureum network:

### 2.1 Network Transaction Fees (Gas)

- All on-chain operations (transfers, contract calls, deployments) require paying QAU as Gas fees
- Uses the EIP-1559 fee model: base fee burned + priority fee to validators
- Base fee burning produces a deflationary effect

### 2.2 Staking for Consensus Participation

- Validators stake QAU to participate in QPOS consensus and receive protocol-issued staking rewards
- Delegators can delegate QAU to validators and share rewards
- Staking rewards come from automatic protocol issuance, not from any individual or entity

### 2.3 Protocol Governance

- QAU holders participate in network governance voting
- Includes community decisions such as protocol upgrades and parameter adjustments


## 3. Token Allocation

### 3.1 Genesis Allocation (20,000,000 QAU)

| Category | Amount | Share | Vesting |
|------|------|------|----------|
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

- All locked tokens are managed through smart contracts and are verifiable on-chain
- Team, Development Fund, and Foundation Reserve include a 1-year cliff period, followed by monthly linear release
- Each release from the Foundation Reserve requires community vote approval


## 4. Staking Economics

### 4.1 Validator Requirements

| Parameter | Value |
|------|-----|
| Minimum Stake | 32 QAU |
| Key Type | Dilithium3 (mandatory, quantum-secure) |

### 4.2 Staking Rewards

- Issued automatically by the protocol, not human-controlled
- Formula (Ethereum Altair-aligned): each validator's per-epoch base reward is
  `stake x 31 / sqrt(total_staked)`, computed in gwei. Attesters receive 87.5%
  of issuance; the block proposer pool receives 12.5%
- **Yield is a function of total stake, not of a participation ratio.** APY
  falls as `1/sqrt(total_staked)`, so early stakers are not locked into a
  permanently high rate and no manual adjustment or governance vote is involved

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

### 4.3 Slashing Mechanism

| Violation Type | Penalty |
|----------|------|
| Double signing | 100% slashed + removed from the validator set |
| Persistent offline | Gradual penalty proportional to offline time |
| Malicious behavior | 10-100% depending on severity |

### 4.4 Delegation Mechanism

- Minimum delegation of 1 QAU, no need to become a validator to participate
- Delegation fee is set by the validator (0-15%)
- 7-day unbonding period
- Delegators bear slashing risk proportionally


## 5. Economic Security

### 5.1 Deflationary Mechanism

- EIP-1559 base fee is burned (removed from supply, credited to no account);
  the priority fee goes to the block proposer
- Net issuance = staking reward issuance - base fee burn
- Net deflation achieved under sustained high network usage

> **Current scope of burning.** Base-fee burning applies to EIP-1559
> dynamic-fee transactions. Legacy transaction types currently pay their entire
> fee to the block proposer with no burn. Wallets that submit EIP-1559
> transactions (the default in the Quantaureum wallet) contribute to burning;
> legacy submissions do not. Extending burning to all transaction types is
> tracked as an open item and is not yet in effect.

### 5.2 Supply Dynamics

- No fixed total supply cap (similar to Ethereum)
- No manual minting capability (no gold-backed minting mechanism)
- Total supply grows only automatically through the staking reward protocol
- The burn mechanism provides a deflationary balance


## 6. Governance

### 6.1 Governance Model

Quantaureum adopts community-driven governance, making decisions through the QIP (Quantaureum Improvement Proposal) process:

1. Community discussion -> 2. QIP draft -> 3. Technical review -> 4. Testnet implementation -> 5. Community vote -> 6. Mainnet activation

### 6.2 Foundation Role

- The Foundation is a legal entity responsible for the day-to-day maintenance and compliance of the protocol
- Treasury funds are managed by the Foundation, and usage requires community oversight
- Key parameter changes must go through the QIP process
- The Foundation gradually transfers governance rights to the community DAO


## 7. Comparison with Other Tokens

| Feature | Bitcoin | Ethereum | QAU |
|------|---------|----------|-----|
| Type | Store of value | Smart contract platform fuel | **Quantum-secure network fuel** |
| Signature algorithm | ECDSA | ECDSA | **Dilithium3 (post-quantum)** |
| Key exchange | None | ECIES | **Kyber-768 (post-quantum)** |
| Consensus | PoW | PoS | QPOS |
| Issuance method | Mining | Staking | Staking (automatic protocol) |
| Quantum resistance | None | None | Yes (native support) |


## 8. Disclaimer

QAU is a utility token of the Quantaureum network, used to pay for network service fees and participate in consensus security. QAU is not a security, not a payment currency, not a stablecoin, and is not pegged to any fiat currency or commodity. This document does not constitute investment advice or an offer. Please consult local laws and regulations before participating in the network.
# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. Please **do not** open a public GitHub issue for security vulnerabilities.

### How to Report

1. Email security@quantaureum.com with a description of the vulnerability
2. Include steps to reproduce if possible
3. We will acknowledge receipt within 48 hours

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix or Mitigation**: Depends on severity (Critical: 24h, High: 72h, Medium: 7d, Low: 30d)

### Disclosure Policy

- We follow responsible disclosure
- We will credit reporters in release notes (unless they prefer to remain anonymous)
- Please do not disclose the vulnerability publicly until a fix is released

## Bug Bounty

Modeled on the Ethereum Foundation's early bounty program — which allocated a **fixed, capped pool** of 25,000 ETH for security researchers — Quantaureum allocates a **fixed bug-bounty fund of 25,000 QAU** (0.125% of the 20,000,000 QAU supply), drawn from the on-chain **Ecosystem Fund**. The pool is capped: each reward draws down the balance and payouts stop once it is exhausted. Funds are never taken from user balances.

| Severity | Examples | Reward (QAU) |
|----------|----------|--------------|
| Critical | Consensus compromise, direct theft of funds, remote code execution | Up to 5,000 |
| High | Broad loss of funds, stake/protocol integrity compromise | Up to 2,500 |
| Medium | Limited impact, information disclosure, denial of service | Up to 1,000 |
| Low | Low-impact issues, missing best practices | 200 |

Eligibility: issues must be previously undisclosed, reproducible, and not already known to the team. Rewards are the upper bounds above, assessed case-by-case and paid in QAU from the capped bounty fund.

## Security Features

### Post-Quantum Cryptography

Quantaureum uses NIST-standardized post-quantum cryptography:

- **Dilithium3** (FIPS 204) — Digital signatures replacing ECDSA
- **Kyber768** (FIPS 203) — Key encapsulation for encrypted P2P channels
- **GM-QTD** — Gaussian-masked threshold distance signing for distributed key shares

### Threshold Signatures (TSS)

- Private key shares are never stored in a single location
- ScShare (private key material) is transmitted only via encrypted P2P channels
- Kyber768 + AES-256-GCM encryption for all private TSS communications

### Wallet Security

- Network-locked: Only ChainID 1668/1669/1333 are allowed
- Custom network addition is disabled
- ECDSA signatures are disabled; only quantum signatures are accepted

## Security Considerations for Developers

- **Never** commit private keys, mnemonics, or keystore files
- **Always** use `qauctl` for key management (never handle raw private keys in code)
- **Review** all changes to `crypto/`, `consensus/`, and `qvm/` with extra scrutiny
- **Test** with `go test -race` before submitting changes to concurrent code paths

// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Dilithium3 size + identity types for the Quantaureum SDK.
 *
 * Matches the node's crypto.Dilithium3*Size constants (crypto/generate.go) and
 * the project rules (Dilithium3: 1952 B pubkey, 4000 B privkey, 3293 B sig).
 */

export interface QuantumKeyPair {
  publicKey: Uint8Array; // 1952 bytes
  privateKey: Uint8Array; // 4000 bytes
  address: string; // 0x + 40 hex chars (20 bytes), NIST SHA3-256(pubkey)[12:32]
}

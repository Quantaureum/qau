// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Dilithium3 / Kyber768 WASM interface types — SDK-portable subset.
 * @module signers/quantum-crypto/wasm-types
 *
 * R40-P0-02: lifted from the Quantaureum extension wallet's quantum-crypto
 * module and stripped to the Dilithium3-only surface the SDK needs (no Kyber
 * hybrid for now — that is transport-level encryption and out of scope for a
 * signing SDK).
 */

export const DILITHIUM3_PARAMS = {
  PUBLICKEYBYTES: 1952,
  SECRETKEYBYTES: 4000,
  SIGNATUREBYTES: 3293,
  CRYPTO_BYTES: 3293,
  SEEDBYTES: 32,
} as const;

export interface DilithiumKeyPair {
  publicKey: Uint8Array; // 1952 bytes
  secretKey: Uint8Array; // 4000 bytes
}

export interface QuantumCryptoModule {
  dilithium3_keypair: () => DilithiumKeyPair;
  dilithium3_keypair_from_seed: (seed: Uint8Array) => DilithiumKeyPair;
  dilithium3_sign: (message: Uint8Array, secretKey: Uint8Array) => Uint8Array;
  dilithium3_verify: (
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
  ) => boolean;
  randomBytes: (length: number) => Uint8Array;
}

export type WasmModuleStatus = 'unloaded' | 'loading' | 'loaded' | 'error';

export interface WasmModuleState {
  status: WasmModuleStatus;
  module: QuantumCryptoModule | null;
  error: Error | null;
}

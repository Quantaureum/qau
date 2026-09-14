// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Quantaureum SDK quantum cryptography barrel.
 *
 * R40-P0-02 (2026-08-03): public surface = Dilithium3, DILITHIUM3_PARAMS,
 * DEFAULT_QUANTUM_HD_PATH, buildProtobufTransaction, computeSigningHash.
 * Consumers (Wallet.ts and SDK users) should rely on these exports, not on
 * the loader internals.
 */

export { Dilithium3, DEFAULT_QUANTUM_HD_PATH } from './dilithium3';
export { DILITHIUM3_PARAMS } from './wasm-loader';
export type { QuantumKeyPair } from './types';
export type { QuantumCryptoModule, DilithiumKeyPair } from './wasm-types';
export {
  buildProtobufTransaction,
  computeSigningHash,
} from './protobuf-tx';
export type { SdkTxParams } from './protobuf-tx';

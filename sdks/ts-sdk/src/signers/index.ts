// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Signers module exports
 * @module signers
 */

export { type Signer, isSigner } from './Signer';
export { Wallet, verifyMessage, DEFAULT_PATH } from './Wallet';

// Re-export Provider type from providers module for convenience
export type { Provider } from '../providers/Provider';

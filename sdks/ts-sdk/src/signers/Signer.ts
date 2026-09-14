// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Signer interface for Quantaureum SDK
 * @module signers/Signer
 */

import type { TransactionRequest, TransactionResponse } from '../types/transaction';
import type { Provider } from '../providers/Provider';

/**
 * Abstract Signer interface
 * Defines the contract for all signer implementations
 */
export interface Signer {
  /**
   * The address of this signer
   */
  readonly address: string;

  /**
   * The provider this signer is connected to (if any)
   */
  readonly provider: Provider | null;

  /**
   * Get the address of this signer
   * @returns The address as a checksummed hex string
   */
  getAddress(): Promise<string>;

  /**
   * Sign a message
   * @param message - The message to sign (string or bytes)
   * @returns The signature as a hex string
   */
  signMessage(message: string | Uint8Array): Promise<string>;

  /**
   * Sign a transaction
   * @param transaction - The transaction to sign
   * @returns The signed transaction as a hex string
   */
  signTransaction(transaction: TransactionRequest): Promise<string>;

  /**
   * Connect this signer to a provider
   * @param provider - The provider to connect to
   * @returns A new signer instance connected to the provider
   */
  connect(provider: Provider): Signer;

  /**
   * Send a transaction (requires provider)
   * @param transaction - The transaction to send
   * @returns The transaction response
   */
  sendTransaction(transaction: TransactionRequest): Promise<TransactionResponse>;
}

/**
 * Type guard to check if an object is a Signer
 */
export function isSigner(value: unknown): value is Signer {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  const obj = value as Signer;
  return (
    typeof obj.address === 'string' &&
    typeof obj.getAddress === 'function' &&
    typeof obj.signMessage === 'function' &&
    typeof obj.signTransaction === 'function' &&
    typeof obj.connect === 'function'
  );
}

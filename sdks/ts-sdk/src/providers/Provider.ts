// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Provider interface for Quantaureum SDK
 * @module providers/Provider
 */

import type {
  Block,
  BlockWithTransactions,
  BlockTag,
  TransactionRequest,
  TransactionResponse,
  TransactionReceipt,
  Log,
  Network,
  EventFilter,
  ProviderEvent,
} from '../types';

/**
 * Abstract Provider interface
 * Defines the contract for all provider implementations
 */
export interface Provider {
  /**
   * Get the connected network information
   * @returns Network name and chain ID
   */
  getNetwork(): Promise<Network>;

  /**
   * Get the current block number
   * @returns The latest block number
   */
  getBlockNumber(): Promise<number>;

  /**
   * Get the current gas price
   * @returns Gas price in wei
   */
  getGasPrice(): Promise<bigint>;

  /**
   * Get a block by number or hash
   * @param blockHashOrNumber - Block hash or number
   * @returns Block details or null if not found
   */
  getBlock(blockHashOrNumber: string | number): Promise<Block | null>;

  /**
   * Get a block with full transaction objects
   * @param blockHashOrNumber - Block hash or number
   * @returns Block with transactions or null if not found
   */
  getBlockWithTransactions(blockHashOrNumber: string | number): Promise<BlockWithTransactions | null>;

  /**
   * Get a transaction by hash
   * @param hash - Transaction hash
   * @returns Transaction details or null if not found
   */
  getTransaction(hash: string): Promise<TransactionResponse | null>;

  /**
   * Get a transaction receipt
   * @param hash - Transaction hash
   * @returns Transaction receipt or null if not found/pending
   */
  getTransactionReceipt(hash: string): Promise<TransactionReceipt | null>;

  /**
   * Get the balance of an address
   * @param address - Account address
   * @param blockTag - Block tag (default: 'latest')
   * @returns Balance in wei
   */
  getBalance(address: string, blockTag?: BlockTag): Promise<bigint>;

  /**
   * Get the code at an address
   * @param address - Contract address
   * @param blockTag - Block tag (default: 'latest')
   * @returns Contract bytecode or '0x' if not a contract
   */
  getCode(address: string, blockTag?: BlockTag): Promise<string>;

  /**
   * Get the transaction count (nonce) for an address
   * @param address - Account address
   * @param blockTag - Block tag (default: 'latest')
   * @returns Transaction count
   */
  getTransactionCount(address: string, blockTag?: BlockTag): Promise<number>;

  /**
   * Send a signed transaction
   * @param signedTransaction - Signed transaction hex string
   * @returns Transaction response
   */
  sendTransaction(signedTransaction: string): Promise<TransactionResponse>;

  /**
   * Execute a call without sending a transaction
   * @param transaction - Transaction request
   * @param blockTag - Block tag (default: 'latest')
   * @returns Call result data
   */
  call(transaction: TransactionRequest, blockTag?: BlockTag): Promise<string>;

  /**
   * Estimate gas for a transaction
   * @param transaction - Transaction request
   * @returns Estimated gas amount
   */
  estimateGas(transaction: TransactionRequest): Promise<bigint>;

  /**
   * Get logs matching a filter
   * @param filter - Event filter
   * @returns Array of matching logs
   */
  getLogs(filter: EventFilter): Promise<Log[]>;

  /**
   * Subscribe to an event
   * @param event - Event type or filter
   * @param listener - Event listener callback
   */
  on(event: ProviderEvent, listener: (...args: unknown[]) => void): void;

  /**
   * Unsubscribe from an event
   * @param event - Event type or filter
   * @param listener - Event listener callback
   */
  off(event: ProviderEvent, listener: (...args: unknown[]) => void): void;

  /**
   * Subscribe to an event (once)
   * @param event - Event type or filter
   * @param listener - Event listener callback
   */
  once(event: ProviderEvent, listener: (...args: unknown[]) => void): void;

  /**
   * Remove all listeners for an event
   * @param event - Event type or filter (optional, removes all if not specified)
   */
  removeAllListeners(event?: ProviderEvent): void;

  /**
   * Wait for a transaction to be mined
   * @param hash - Transaction hash
   * @param confirmations - Number of confirmations to wait for
   * @param timeout - Timeout in milliseconds
   * @returns Transaction receipt
   */
  waitForTransaction(
    hash: string,
    confirmations?: number,
    timeout?: number
  ): Promise<TransactionReceipt>;
}

/**
 * Type guard to check if an object is a Provider
 */
export function isProvider(value: unknown): value is Provider {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  const obj = value as Provider;
  return (
    typeof obj.getNetwork === 'function' &&
    typeof obj.getBlockNumber === 'function' &&
    typeof obj.getBalance === 'function' &&
    typeof obj.sendTransaction === 'function' &&
    typeof obj.call === 'function'
  );
}

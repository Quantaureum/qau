// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Block types for Quantaureum blockchain
 */

import type { TransactionResponse } from './transaction';

/**
 * Block tag for specifying block reference
 */
export type BlockTag = 'latest' | 'earliest' | 'pending' | number | string;

/**
 * Block structure returned from the blockchain
 */
export interface Block {
  /** Block number (height) */
  number: number;
  /** Block hash */
  hash: string;
  /** Parent block hash */
  parentHash: string;
  /** Block timestamp (Unix seconds) */
  timestamp: number;
  /** Block nonce */
  nonce: string;
  /** Block difficulty */
  difficulty: bigint;
  /** Gas limit for the block */
  gasLimit: bigint;
  /** Gas used in the block */
  gasUsed: bigint;
  /** Miner/validator address */
  miner: string;
  /** Extra data field */
  extraData: string;
  /** Transaction hashes in the block */
  transactions: string[];
}

/**
 * Block with full transaction objects
 */
export interface BlockWithTransactions extends Omit<Block, 'transactions'> {
  /** Full transaction objects */
  transactions: TransactionResponse[];
}

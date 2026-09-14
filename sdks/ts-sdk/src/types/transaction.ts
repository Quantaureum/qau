// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Transaction types for Quantaureum blockchain
 */

/**
 * Transaction request for sending transactions
 */
export interface TransactionRequest {
  /** Recipient address */
  to?: string;
  /** Sender address (optional, derived from signer) */
  from?: string;
  /** Transaction nonce */
  nonce?: number;
  /** Gas limit */
  gasLimit?: bigint;
  /** Gas price in wei */
  gasPrice?: bigint;
  /** Transaction data (hex string) */
  data?: string;
  /** Value to send in wei */
  value?: bigint;
  /** Chain ID */
  chainId?: number;
}

/**
 * Transaction response from the blockchain
 */
export interface TransactionResponse {
  /** Transaction hash */
  hash: string;
  /** Block number (null if pending) */
  blockNumber: number | null;
  /** Block hash (null if pending) */
  blockHash: string | null;
  /** Block timestamp (null if pending) */
  timestamp: number | null;
  /** Sender address */
  from: string;
  /** Recipient address (null for contract creation) */
  to: string | null;
  /** Value transferred in wei */
  value: bigint;
  /** Transaction nonce */
  nonce: number;
  /** Gas limit */
  gasLimit: bigint;
  /** Gas price in wei */
  gasPrice: bigint;
  /** Transaction data */
  data: string;
  /** Chain ID */
  chainId: number;

  /**
   * Wait for transaction confirmation
   * @param confirmations Number of confirmations to wait for
   * @returns Transaction receipt
   */
  wait(confirmations?: number): Promise<TransactionReceipt>;
}

/**
 * Log entry in a transaction receipt
 */
export interface Log {
  /** Block number */
  blockNumber: number;
  /** Block hash */
  blockHash: string;
  /** Transaction hash */
  transactionHash: string;
  /** Transaction index in block */
  transactionIndex: number;
  /** Log index in block */
  logIndex: number;
  /** Contract address that emitted the log */
  address: string;
  /** Log topics */
  topics: string[];
  /** Log data */
  data: string;
  /** Whether the log was removed (due to reorg) */
  removed: boolean;
}

/**
 * Transaction receipt after confirmation
 */
export interface TransactionReceipt {
  /** Transaction hash */
  transactionHash: string;
  /** Transaction index in block */
  transactionIndex: number;
  /** Block number */
  blockNumber: number;
  /** Block hash */
  blockHash: string;
  /** Sender address */
  from: string;
  /** Recipient address (null for contract creation) */
  to: string | null;
  /** Contract address (if contract creation) */
  contractAddress: string | null;
  /** Gas used by this transaction */
  gasUsed: bigint;
  /** Cumulative gas used in block up to this transaction */
  cumulativeGasUsed: bigint;
  /** Transaction status (1 = success, 0 = failure) */
  status: number;
  /** Logs emitted by the transaction */
  logs: Log[];
  /** Logs bloom filter */
  logsBloom: string;
  /** Effective gas price */
  effectiveGasPrice: bigint;
}

/**
 * Pending transaction (not yet mined)
 */
export interface PendingTransaction extends Omit<TransactionResponse, 'blockNumber' | 'blockHash' | 'timestamp'> {
  blockNumber: null;
  blockHash: null;
  timestamp: null;
}

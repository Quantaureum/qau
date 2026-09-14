// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Network types for Quantaureum blockchain
 */

/**
 * Network information
 */
export interface Network {
  /** Network name */
  name: string;
  /** Chain ID */
  chainId: number;
}

/**
 * Known Quantaureum networks
 */
export const Networks: Record<string, Network> = {
  mainnet: {
    name: 'mainnet',
    chainId: 1,
  },
  testnet: {
    name: 'testnet',
    chainId: 5,
  },
  devnet: {
    name: 'devnet',
    chainId: 31337,
  },
} as const;

/**
 * RPC request structure
 */
export interface JsonRpcRequest {
  /** JSON-RPC version */
  jsonrpc: '2.0';
  /** Request ID */
  id: number;
  /** Method name */
  method: string;
  /** Method parameters */
  params: unknown[];
}

/**
 * RPC response structure
 */
export interface JsonRpcResponse<T = unknown> {
  /** JSON-RPC version */
  jsonrpc: '2.0';
  /** Request ID */
  id: number;
  /** Result (if successful) */
  result?: T;
  /** Error (if failed) */
  error?: JsonRpcError;
}

/**
 * RPC error structure
 */
export interface JsonRpcError {
  /** Error code */
  code: number;
  /** Error message */
  message: string;
  /** Additional error data */
  data?: unknown;
}

/**
 * Event filter for querying logs
 */
export interface EventFilter {
  /** Contract address(es) to filter */
  address?: string | string[];
  /** Topics to filter */
  topics?: (string | string[] | null)[];
  /** Start block */
  fromBlock?: number | string;
  /** End block */
  toBlock?: number | string;
}

/**
 * Provider event types
 */
export type ProviderEvent =
  | 'block'
  | 'pending'
  | 'error'
  | 'network'
  | EventFilter
  | string;

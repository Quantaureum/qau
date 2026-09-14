// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * JSON-RPC Provider implementation for Quantaureum SDK
 * @module providers/JsonRpcProvider
 */

import type { Provider } from './Provider';
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
  JsonRpcRequest,
  JsonRpcResponse,
} from '../types';
import {
  NetworkError,
  RpcError,
  ValidationError,
  ErrorCode,
  QuantaureumError,
  parseRpcError,
} from '../errors';
import { getAddress } from '../utils/address';
import { toHex, isHexString } from '../utils/hex';
import {
  assertNonEmptyString,
  assertAddress,
  assertTransactionHash,
  assertHexString,
  validateTransactionRequest,
  validateEventFilter,
} from '../utils/validation';

/**
 * Options for JsonRpcProvider
 */
export interface JsonRpcProviderOptions {
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Network information (auto-detected if not provided) */
  network?: Network;
  /** Polling interval for events in milliseconds (default: 4000) */
  pollingInterval?: number;
  /** Number of retry attempts for failed requests (default: 3) */
  retries?: number;
  /** Initial delay between retries in milliseconds (default: 1000) */
  retryDelay?: number;
}

/**
 * JSON-RPC Provider for connecting to Quantaureum nodes
 */
export class JsonRpcProvider implements Provider {
  /** RPC endpoint URL */
  readonly url: string;

  /** Request timeout in milliseconds */
  readonly timeout: number;

  /** Polling interval for events */
  readonly pollingInterval: number;

  /** Number of retry attempts */
  readonly retries: number;

  /** Initial delay between retries */
  readonly retryDelay: number;

  /** Request ID counter */
  #requestId = 0;

  /** Cached network information */
  #network: Network | null = null;

  /** Event listeners */
  #listeners: Map<string, Set<(...args: unknown[]) => void>> = new Map();

  /** Polling timer */
  #pollingTimer: ReturnType<typeof setInterval> | null = null;

  /** Last seen block number */
  #lastBlockNumber = -1;

  /**
   * Create a new JsonRpcProvider
   * @param url - RPC endpoint URL
   * @param options - Provider options
   */
  constructor(url: string, options: JsonRpcProviderOptions = {}) {
    assertNonEmptyString(url, 'url');

    // Validate URL format
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch {
      throw new ValidationError(
        'Invalid RPC URL format',
        'url',
        url,
        ErrorCode.INVALID_ARGUMENT,
        'valid URL string'
      );
    }

    // Enforce HTTPS or HTTP protocol
    if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
      throw new ValidationError(
        'RPC URL must use https:// or http:// protocol',
        'url',
        url,
        ErrorCode.INVALID_ARGUMENT,
        'https:// or http:// URL'
      );
    }

    // Warn about insecure HTTP connections (except localhost)
    if (
      parsedUrl.protocol === 'http:' &&
      !parsedUrl.hostname.includes('localhost') &&
      !parsedUrl.hostname.includes('127.0.0.1')
    ) {
      // HIGH-10 FIX: Throw error in production builds instead of just warning
      if (process.env['NODE_ENV'] === 'production') {
        throw new ValidationError(
          'Insecure HTTP connection is not allowed in production. Use HTTPS to prevent man-in-the-middle attacks.',
          'url',
          url,
          ErrorCode.INVALID_ARGUMENT,
          'https:// URL'
        );
      }
      console.warn(
        'Warning: Using insecure HTTP connection. ' +
        'Use HTTPS in production to prevent man-in-the-middle attacks.'
      );
    }

    this.url = url;
    this.timeout = options.timeout ?? 30000;
    this.pollingInterval = options.pollingInterval ?? 4000;
    this.retries = options.retries ?? 3;
    this.retryDelay = options.retryDelay ?? 1000;

    if (options.network) {
      this.#network = options.network;
    }
  }

  /**
   * Send a JSON-RPC request with automatic retry
   * @param method - RPC method name
   * @param params - Method parameters
   * @returns RPC result
   */
  async send<T = unknown>(method: string, params: unknown[] = []): Promise<T> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= this.retries; attempt++) {
      try {
        const id = ++this.#requestId;

        const request: JsonRpcRequest = {
          jsonrpc: '2.0',
          id,
          method,
          params,
        };

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
          const response = await fetch(this.url, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(request),
            signal: controller.signal,
          });

          clearTimeout(timeoutId);

          if (!response.ok) {
            throw new NetworkError(
              `HTTP error: ${response.status} ${response.statusText}`,
              this.url,
              ErrorCode.NETWORK_ERROR,
              response.status
            );
          }

          const json: JsonRpcResponse<T> = await response.json();

          if (json.error) {
            throw parseRpcError(json.error, { method, params });
          }

          return json.result as T;
        } catch (error) {
          clearTimeout(timeoutId);
          throw error;
        }
      } catch (error) {
        lastError = error as Error;

        // Don't retry for RPC errors or validation errors
        if (error instanceof RpcError || error instanceof ValidationError) {
          throw error;
        }

        // Last attempt - throw the error
        if (attempt === this.retries) {
          break;
        }

        // Exponential backoff with max delay of 10 seconds
        const delay = Math.min(
          this.retryDelay * Math.pow(2, attempt),
          10000
        );
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    // Handle the last error
    if (lastError instanceof NetworkError) {
      throw lastError;
    }

    if (lastError instanceof Error) {
      if (lastError.name === 'AbortError') {
        throw new NetworkError(
          `Request timeout after ${this.timeout}ms`,
          this.url,
          ErrorCode.TIMEOUT
        );
      }

      throw new NetworkError(
        `Network error: ${lastError.message}`,
        this.url,
        ErrorCode.NETWORK_ERROR
      );
    }

    throw new NetworkError(
      'Unknown network error',
      this.url,
      ErrorCode.NETWORK_ERROR
    );
  }


  /**
   * Get the connected network information
   */
  async getNetwork(): Promise<Network> {
    if (this.#network) {
      return this.#network;
    }

    const chainIdHex = await this.send<string>('eth_chainId');
    const chainId = parseInt(chainIdHex, 16);

    // Determine network name based on chain ID
    let name: string;
    switch (chainId) {
      case 1:
        name = 'mainnet';
        break;
      case 5:
        name = 'testnet';
        break;
      case 31337:
        name = 'devnet';
        break;
      default:
        name = `unknown-${chainId}`;
    }

    this.#network = { name, chainId };
    return this.#network;
  }

  /**
   * Get the current block number
   */
  async getBlockNumber(): Promise<number> {
    const result = await this.send<string>('eth_blockNumber');
    return parseInt(result, 16);
  }

  /**
   * Get the current gas price
   */
  async getGasPrice(): Promise<bigint> {
    const result = await this.send<string>('eth_gasPrice');
    return BigInt(result);
  }

  /**
   * Format a block tag for RPC calls
   */
  private formatBlockTag(blockTag: BlockTag | undefined): string {
    if (blockTag === undefined || blockTag === 'latest') {
      return 'latest';
    }
    if (blockTag === 'earliest') {
      return 'earliest';
    }
    if (blockTag === 'pending') {
      return 'pending';
    }
    if (typeof blockTag === 'number') {
      return toHex(blockTag);
    }
    return blockTag;
  }

  /**
   * Parse a raw block from RPC response
   */
  private parseBlock(raw: RawBlock | null): Block | null {
    if (!raw) return null;

    return {
      number: parseInt(raw.number, 16),
      hash: raw.hash,
      parentHash: raw.parentHash,
      timestamp: parseInt(raw.timestamp, 16),
      nonce: raw.nonce,
      difficulty: BigInt(raw.difficulty ?? '0x0'),
      gasLimit: BigInt(raw.gasLimit),
      gasUsed: BigInt(raw.gasUsed),
      miner: raw.miner,
      extraData: raw.extraData,
      transactions: raw.transactions as string[],
    };
  }

  /**
   * Parse a raw block with transactions from RPC response
   */
  private parseBlockWithTransactions(raw: RawBlock | null): BlockWithTransactions | null {
    if (!raw) return null;

    return {
      number: parseInt(raw.number, 16),
      hash: raw.hash,
      parentHash: raw.parentHash,
      timestamp: parseInt(raw.timestamp, 16),
      nonce: raw.nonce,
      difficulty: BigInt(raw.difficulty ?? '0x0'),
      gasLimit: BigInt(raw.gasLimit),
      gasUsed: BigInt(raw.gasUsed),
      miner: raw.miner,
      extraData: raw.extraData,
      transactions: (raw.transactions as RawTransaction[]).map((tx) =>
        this.parseTransaction(tx)!
      ),
    };
  }

  /**
   * Parse a raw transaction from RPC response
   */
  private parseTransaction(raw: RawTransaction | null): TransactionResponse | null {
    if (!raw) return null;

    return {
      hash: raw.hash,
      blockNumber: raw.blockNumber ? parseInt(raw.blockNumber, 16) : null,
      blockHash: raw.blockHash,
      timestamp: null, // Not available in transaction response
      from: raw.from,
      to: raw.to,
      value: BigInt(raw.value),
      nonce: parseInt(raw.nonce, 16),
      gasLimit: BigInt(raw.gas),
      gasPrice: BigInt(raw.gasPrice),
      data: raw.input,
      chainId: raw.chainId ? parseInt(raw.chainId, 16) : 1,
      wait: async (confirmations = 1): Promise<TransactionReceipt> => {
        return this.waitForTransaction(raw.hash, confirmations);
      },
    };
  }

  /**
   * Parse a raw transaction receipt from RPC response
   */
  private parseTransactionReceipt(raw: RawTransactionReceipt | null): TransactionReceipt | null {
    if (!raw) return null;

    return {
      transactionHash: raw.transactionHash,
      transactionIndex: parseInt(raw.transactionIndex, 16),
      blockNumber: parseInt(raw.blockNumber, 16),
      blockHash: raw.blockHash,
      from: raw.from,
      to: raw.to,
      contractAddress: raw.contractAddress,
      gasUsed: BigInt(raw.gasUsed),
      cumulativeGasUsed: BigInt(raw.cumulativeGasUsed),
      status: parseInt(raw.status, 16),
      logs: raw.logs.map((log) => this.parseLog(log)),
      logsBloom: raw.logsBloom,
      effectiveGasPrice: BigInt(raw.effectiveGasPrice ?? raw.gasUsed),
    };
  }

  /**
   * Parse a raw log from RPC response
   */
  private parseLog(raw: RawLog): Log {
    return {
      blockNumber: parseInt(raw.blockNumber, 16),
      blockHash: raw.blockHash,
      transactionHash: raw.transactionHash,
      transactionIndex: parseInt(raw.transactionIndex, 16),
      logIndex: parseInt(raw.logIndex, 16),
      address: raw.address,
      topics: raw.topics,
      data: raw.data,
      removed: raw.removed ?? false,
    };
  }


  /**
   * Get a block by number or hash
   */
  async getBlock(blockHashOrNumber: string | number): Promise<Block | null> {
    let method: string;
    let params: unknown[];

    if (typeof blockHashOrNumber === 'number') {
      method = 'eth_getBlockByNumber';
      params = [toHex(blockHashOrNumber), false];
    } else if (isHexString(blockHashOrNumber) && blockHashOrNumber.length === 66) {
      // Block hash (32 bytes = 64 hex chars + 0x prefix)
      method = 'eth_getBlockByHash';
      params = [blockHashOrNumber, false];
    } else {
      method = 'eth_getBlockByNumber';
      params = [this.formatBlockTag(blockHashOrNumber as BlockTag), false];
    }

    const raw = await this.send<RawBlock | null>(method, params);
    return this.parseBlock(raw);
  }

  /**
   * Get a block with full transaction objects
   */
  async getBlockWithTransactions(
    blockHashOrNumber: string | number
  ): Promise<BlockWithTransactions | null> {
    let method: string;
    let params: unknown[];

    if (typeof blockHashOrNumber === 'number') {
      method = 'eth_getBlockByNumber';
      params = [toHex(blockHashOrNumber), true];
    } else if (isHexString(blockHashOrNumber) && blockHashOrNumber.length === 66) {
      method = 'eth_getBlockByHash';
      params = [blockHashOrNumber, true];
    } else {
      method = 'eth_getBlockByNumber';
      params = [this.formatBlockTag(blockHashOrNumber as BlockTag), true];
    }

    const raw = await this.send<RawBlock | null>(method, params);
    return this.parseBlockWithTransactions(raw);
  }

  /**
   * Get a transaction by hash
   */
  async getTransaction(hash: string): Promise<TransactionResponse | null> {
    assertTransactionHash(hash, 'hash');

    const raw = await this.send<RawTransaction | null>('eth_getTransactionByHash', [hash]);
    return this.parseTransaction(raw);
  }

  /**
   * Get a transaction receipt
   */
  async getTransactionReceipt(hash: string): Promise<TransactionReceipt | null> {
    assertTransactionHash(hash, 'hash');

    const raw = await this.send<RawTransactionReceipt | null>('eth_getTransactionReceipt', [hash]);
    return this.parseTransactionReceipt(raw);
  }

  /**
   * Get the balance of an address
   */
  async getBalance(address: string, blockTag?: BlockTag): Promise<bigint> {
    assertAddress(address, 'address');

    const result = await this.send<string>('eth_getBalance', [
      getAddress(address),
      this.formatBlockTag(blockTag),
    ]);
    return BigInt(result);
  }

  /**
   * Get the code at an address
   */
  async getCode(address: string, blockTag?: BlockTag): Promise<string> {
    assertAddress(address, 'address');

    const result = await this.send<string>('eth_getCode', [
      getAddress(address),
      this.formatBlockTag(blockTag),
    ]);
    return result;
  }

  /**
   * Get the transaction count (nonce) for an address
   */
  async getTransactionCount(address: string, blockTag?: BlockTag): Promise<number> {
    assertAddress(address, 'address');

    const result = await this.send<string>('eth_getTransactionCount', [
      getAddress(address),
      this.formatBlockTag(blockTag),
    ]);
    return parseInt(result, 16);
  }


  /**
   * Send a signed transaction
   */
  async sendTransaction(signedTransaction: string): Promise<TransactionResponse> {
    assertHexString(signedTransaction, 'signedTransaction');

    const hash = await this.send<string>('eth_sendRawTransaction', [signedTransaction]);

    // Get the transaction details
    const tx = await this.getTransaction(hash);
    if (!tx) {
      throw new QuantaureumError(
        'Transaction sent but not found',
        ErrorCode.UNKNOWN_ERROR
      );
    }

    return tx;
  }

  /**
   * Execute a call without sending a transaction
   */
  async call(transaction: TransactionRequest, blockTag?: BlockTag): Promise<string> {
    validateTransactionRequest(transaction);

    const callObject: Record<string, string> = {};

    if (transaction.from) {
      callObject['from'] = getAddress(transaction.from);
    }

    if (transaction.to) {
      callObject['to'] = getAddress(transaction.to);
    }

    if (transaction.gasLimit !== undefined) {
      callObject['gas'] = toHex(transaction.gasLimit);
    }

    if (transaction.gasPrice !== undefined) {
      callObject['gasPrice'] = toHex(transaction.gasPrice);
    }

    if (transaction.value !== undefined) {
      callObject['value'] = toHex(transaction.value);
    }

    if (transaction.data !== undefined) {
      callObject['data'] = transaction.data;
    }

    const result = await this.send<string>('eth_call', [
      callObject,
      this.formatBlockTag(blockTag),
    ]);
    return result;
  }

  /**
   * Estimate gas for a transaction
   */
  async estimateGas(transaction: TransactionRequest): Promise<bigint> {
    validateTransactionRequest(transaction);

    const callObject: Record<string, string> = {};

    if (transaction.from) {
      callObject['from'] = getAddress(transaction.from);
    }

    if (transaction.to) {
      callObject['to'] = getAddress(transaction.to);
    }

    if (transaction.gasLimit !== undefined) {
      callObject['gas'] = toHex(transaction.gasLimit);
    }

    if (transaction.gasPrice !== undefined) {
      callObject['gasPrice'] = toHex(transaction.gasPrice);
    }

    if (transaction.value !== undefined) {
      callObject['value'] = toHex(transaction.value);
    }

    if (transaction.data !== undefined) {
      callObject['data'] = transaction.data;
    }

    const result = await this.send<string>('eth_estimateGas', [callObject]);
    return BigInt(result);
  }

  /**
   * Get logs matching a filter
   */
  async getLogs(filter: EventFilter): Promise<Log[]> {
    validateEventFilter(filter);

    const filterObject: Record<string, unknown> = {};

    if (filter.address) {
      if (Array.isArray(filter.address)) {
        filterObject['address'] = filter.address.map((addr) => getAddress(addr));
      } else {
        filterObject['address'] = getAddress(filter.address);
      }
    }

    if (filter.topics) {
      filterObject['topics'] = filter.topics;
    }

    if (filter.fromBlock !== undefined) {
      filterObject['fromBlock'] =
        typeof filter.fromBlock === 'number'
          ? toHex(filter.fromBlock)
          : filter.fromBlock;
    }

    if (filter.toBlock !== undefined) {
      filterObject['toBlock'] =
        typeof filter.toBlock === 'number' ? toHex(filter.toBlock) : filter.toBlock;
    }

    const rawLogs = await this.send<RawLog[]>('eth_getLogs', [filterObject]);
    return rawLogs.map((log) => this.parseLog(log));
  }


  /**
   * Wait for a transaction to be mined
   */
  async waitForTransaction(
    hash: string,
    confirmations = 1,
    timeout?: number
  ): Promise<TransactionReceipt> {
    const startTime = Date.now();
    const timeoutMs = timeout ?? 0; // 0 means no timeout

    // eslint-disable-next-line no-constant-condition
    while (true) {
      const receipt = await this.getTransactionReceipt(hash);

      if (receipt) {
        if (confirmations <= 1) {
          return receipt;
        }

        const currentBlock = await this.getBlockNumber();
        const confirmedBlocks = currentBlock - receipt.blockNumber + 1;

        if (confirmedBlocks >= confirmations) {
          return receipt;
        }
      }

      // Check timeout
      if (timeoutMs > 0 && Date.now() - startTime > timeoutMs) {
        throw new QuantaureumError(
          `Transaction ${hash} not mined within ${timeoutMs}ms`,
          ErrorCode.TIMEOUT
        );
      }

      // Wait before polling again
      await new Promise((resolve) => setTimeout(resolve, this.pollingInterval));
    }
  }

  /**
   * Get the event key for listener management
   */
  private getEventKey(event: ProviderEvent): string {
    if (typeof event === 'string') {
      return event;
    }
    return JSON.stringify(event);
  }

  /**
   * Subscribe to an event
   */
  on(event: ProviderEvent, listener: (...args: unknown[]) => void): void {
    const key = this.getEventKey(event);
    let listeners = this.#listeners.get(key);
    if (!listeners) {
      listeners = new Set();
      this.#listeners.set(key, listeners);
    }
    listeners.add(listener);

    // Start polling if this is the first listener
    if (this.#pollingTimer === null && this.#listeners.size > 0) {
      this.startPolling();
    }
  }

  /**
   * Unsubscribe from an event
   */
  off(event: ProviderEvent, listener: (...args: unknown[]) => void): void {
    const key = this.getEventKey(event);
    const listeners = this.#listeners.get(key);
    if (listeners) {
      listeners.delete(listener);
      if (listeners.size === 0) {
        this.#listeners.delete(key);
      }
    }

    // Stop polling if no more listeners
    if (this.#listeners.size === 0) {
      this.stopPolling();
    }
  }

  /**
   * Subscribe to an event (once)
   */
  once(event: ProviderEvent, listener: (...args: unknown[]) => void): void {
    const wrappedListener = (...args: unknown[]): void => {
      this.off(event, wrappedListener);
      listener(...args);
    };
    this.on(event, wrappedListener);
  }

  /**
   * Remove all listeners for an event
   */
  removeAllListeners(event?: ProviderEvent): void {
    if (event === undefined) {
      this.#listeners.clear();
      this.stopPolling();
    } else {
      const key = this.getEventKey(event);
      this.#listeners.delete(key);
      if (this.#listeners.size === 0) {
        this.stopPolling();
      }
    }
  }

  /**
   * Start polling for events
   */
  private startPolling(): void {
    if (this.#pollingTimer !== null) return;

    this.#pollingTimer = setInterval(() => {
      void this.poll().catch(() => {
        // Emit error event
        this.emit('error', new Error('Polling error'));
      });
    }, this.pollingInterval);
  }

  /**
   * Stop polling for events
   */
  private stopPolling(): void {
    if (this.#pollingTimer !== null) {
      clearInterval(this.#pollingTimer);
      this.#pollingTimer = null;
    }
  }

  /**
   * Poll for new blocks and events
   */
  private async poll(): Promise<void> {
    const blockNumber = await this.getBlockNumber();

    if (this.#lastBlockNumber === -1) {
      this.#lastBlockNumber = blockNumber;
      return;
    }

    if (blockNumber > this.#lastBlockNumber) {
      // Emit block events
      for (let i = this.#lastBlockNumber + 1; i <= blockNumber; i++) {
        this.emit('block', i);
      }
      this.#lastBlockNumber = blockNumber;
    }
  }

  /**
   * Emit an event to all listeners
   */
  private emit(event: ProviderEvent, ...args: unknown[]): void {
    const key = this.getEventKey(event);
    const listeners = this.#listeners.get(key);
    if (listeners) {
      for (const listener of listeners) {
        try {
          listener(...args);
        } catch (err) {
          // HIGH-8 FIX: Log errors to a dedicated error handler instead of silently ignoring
          console.error(`Error in event listener for '${key}':`, err);
        }
      }
    }
  }

  /**
   * Destroy the provider and clean up resources
   */
  destroy(): void {
    this.stopPolling();
    this.#listeners.clear();
  }
}

/**
 * Raw block structure from RPC
 */
interface RawBlock {
  number: string;
  hash: string;
  parentHash: string;
  timestamp: string;
  nonce: string;
  difficulty?: string;
  gasLimit: string;
  gasUsed: string;
  miner: string;
  extraData: string;
  transactions: string[] | RawTransaction[];
}

/**
 * Raw transaction structure from RPC
 */
interface RawTransaction {
  hash: string;
  blockNumber: string | null;
  blockHash: string | null;
  from: string;
  to: string | null;
  value: string;
  nonce: string;
  gas: string;
  gasPrice: string;
  input: string;
  chainId?: string;
}

/**
 * Raw transaction receipt structure from RPC
 */
interface RawTransactionReceipt {
  transactionHash: string;
  transactionIndex: string;
  blockNumber: string;
  blockHash: string;
  from: string;
  to: string | null;
  contractAddress: string | null;
  gasUsed: string;
  cumulativeGasUsed: string;
  status: string;
  logs: RawLog[];
  logsBloom: string;
  effectiveGasPrice?: string;
}

/**
 * Raw log structure from RPC
 */
interface RawLog {
  blockNumber: string;
  blockHash: string;
  transactionHash: string;
  transactionIndex: string;
  logIndex: string;
  address: string;
  topics: string[];
  data: string;
  removed?: boolean;
}

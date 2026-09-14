// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Contract class for interacting with smart contracts
 * @module contracts/Contract
 */

import type { Provider } from '../providers/Provider';
import type { Signer } from '../signers/Signer';
import type {
  TransactionRequest,
  TransactionResponse,
  Log,
  EventFilter,
} from '../types';
import type { ABI } from '../utils/abi';
import { Interface, FunctionFragment, EventFragment } from './Interface';
import {
  ValidationError,
  ContractError,
  QuantaureumError,
  ErrorCode,
  extractRevertReason,
} from '../errors';
import { getAddress } from '../utils/address';
import { isProvider } from '../providers/Provider';
import { isSigner } from '../signers/Signer';
import { assertAddress } from '../utils/validation';

/**
 * Contract function type
 */
export type ContractFunction<T = unknown> = (...args: unknown[]) => Promise<T>;

/**
 * Contract method options
 */
export interface ContractMethodOptions {
  /** Gas limit */
  gasLimit?: bigint;
  /** Gas price */
  gasPrice?: bigint;
  /** Value to send */
  value?: bigint;
  /** Nonce */
  nonce?: number;
  /** Block tag for calls */
  blockTag?: string | number;
}

/**
 * Parsed event from a log
 */
export interface ContractEvent {
  /** Event name */
  eventName: string;
  /** Event arguments */
  args: Record<string, unknown>;
  /** Original log */
  log: Log;
  /** Block number */
  blockNumber: number;
  /** Block hash */
  blockHash: string;
  /** Transaction hash */
  transactionHash: string;
  /** Log index */
  logIndex: number;
}


/**
 * Contract class for interacting with smart contracts
 */
export class Contract {
  /** Contract address */
  readonly address: string;

  /** Contract interface */
  readonly interface: Interface;

  /** Connected provider */
  readonly provider: Provider | null;

  /** Connected signer */
  readonly signer: Signer | null;

  /** Event filters */
  readonly filters: Record<string, (...args: unknown[]) => EventFilter>;

  /** Event listeners */
  private eventListeners: Map<string, Set<(...args: unknown[]) => void>>;

  /** Dynamic method index signature */
  [key: string]: unknown;

  /**
   * Create a new Contract instance
   * @param address - Contract address
   * @param abi - Contract ABI
   * @param signerOrProvider - Signer or Provider to connect
   */
  constructor(
    address: string,
    abi: ABI | Interface | string,
    signerOrProvider?: Signer | Provider
  ) {
    // Validate address
    assertAddress(address, 'address');

    this.address = getAddress(address);

    // Parse interface
    if (abi instanceof Interface) {
      this.interface = abi;
    } else {
      this.interface = new Interface(abi as ABI | string);
    }

    // Connect signer or provider
    if (signerOrProvider) {
      if (isSigner(signerOrProvider)) {
        this.signer = signerOrProvider;
        this.provider = signerOrProvider.provider;
      } else if (isProvider(signerOrProvider)) {
        this.signer = null;
        this.provider = signerOrProvider;
      } else {
        throw new ValidationError(
          'Invalid signer or provider',
          'signerOrProvider',
          signerOrProvider,
          ErrorCode.INVALID_ARGUMENT,
          'Signer or Provider'
        );
      }
    } else {
      this.signer = null;
      this.provider = null;
    }

    this.eventListeners = new Map();
    this.filters = {};

    // Generate dynamic methods
    this.generateMethods();
    this.generateFilters();
  }


  /**
   * Generate dynamic methods for all functions in the ABI
   */
  private generateMethods(): void {
    for (const [name, fragment] of this.interface.functions) {
      // Skip constructor, fallback, receive
      if (name === 'constructor' || name === 'fallback' || name === 'receive') {
        continue;
      }

      // Create the method
      const method = this.createMethod(fragment);

      // Attach to contract
      if (!(name in this)) {
        (this as Record<string, unknown>)[name] = method;
      }

      // Also attach with full signature for overloaded functions
      const sigMethod = this.createMethod(fragment);
      (this as Record<string, unknown>)[fragment.signature] = sigMethod;
    }
  }

  /**
   * Create a contract method
   */
  private createMethod(fragment: FunctionFragment): ContractFunction {
    return async (...args: unknown[]): Promise<unknown> => {
      // Check if last argument is options
      let options: ContractMethodOptions = {};
      let methodArgs = args;

      if (args.length > fragment.inputs.length) {
        const lastArg = args[args.length - 1];
        if (lastArg && typeof lastArg === 'object' && !Array.isArray(lastArg)) {
          options = lastArg as ContractMethodOptions;
          methodArgs = args.slice(0, -1);
        }
      }

      // Validate argument count
      if (methodArgs.length !== fragment.inputs.length) {
        throw new ValidationError(
          `Expected ${fragment.inputs.length} arguments, got ${methodArgs.length}`,
          'args',
          methodArgs,
          ErrorCode.INVALID_ARGUMENT,
          `${fragment.inputs.length} arguments`
        );
      }

      // Encode function data
      const data = this.interface.encodeFunctionData(fragment.name, methodArgs);

      // Determine if this is a read or write call
      const isReadOnly =
        fragment.stateMutability === 'view' || fragment.stateMutability === 'pure';

      if (isReadOnly) {
        // Read-only call
        return this.callReadOnly(fragment, data, options);
      } else {
        // State-changing transaction
        return this.sendTransaction(fragment, data, options);
      }
    };
  }


  /**
   * Execute a read-only call
   */
  private async callReadOnly(
    fragment: FunctionFragment,
    data: string,
    options: ContractMethodOptions
  ): Promise<unknown> {
    if (!this.provider) {
      throw new QuantaureumError(
        'Cannot call contract: no provider connected',
        ErrorCode.NO_PROVIDER
      );
    }

    const tx: TransactionRequest = {
      to: this.address,
      data,
    };

    if (options.gasLimit !== undefined) {
      tx.gasLimit = options.gasLimit;
    }

    try {
      const result = await this.provider.call(tx, options.blockTag);

      // Decode result
      if (fragment.outputs.length === 0) {
        return undefined;
      }

      const decoded = this.interface.decodeFunctionResult(fragment.name, result);

      // Return single value directly, or array for multiple outputs
      if (fragment.outputs.length === 1) {
        return decoded[0];
      }
      return decoded;
    } catch (error) {
      throw this.wrapError(error, fragment.name);
    }
  }

  /**
   * Send a state-changing transaction
   */
  private async sendTransaction(
    fragment: FunctionFragment,
    data: string,
    options: ContractMethodOptions
  ): Promise<TransactionResponse> {
    if (!this.signer) {
      throw new QuantaureumError(
        'Cannot send transaction: no signer connected',
        ErrorCode.NO_PROVIDER
      );
    }

    const tx: TransactionRequest = {
      to: this.address,
      data,
    };

    if (options.gasLimit !== undefined) {
      tx.gasLimit = options.gasLimit;
    }
    if (options.gasPrice !== undefined) {
      tx.gasPrice = options.gasPrice;
    }
    if (options.value !== undefined) {
      tx.value = options.value;
    }
    if (options.nonce !== undefined) {
      tx.nonce = options.nonce;
    }

    try {
      return await this.signer.sendTransaction(tx);
    } catch (error) {
      throw this.wrapError(error, fragment.name);
    }
  }

  /**
   * Wrap an error with contract context
   */
  private wrapError(error: unknown, method: string): Error {
    if (error instanceof ContractError) {
      return error;
    }

    const message = error instanceof Error ? error.message : String(error);

    // Try to extract revert reason
    let reason: string | undefined;
    if (error && typeof error === 'object') {
      const errorObj = error as Record<string, unknown>;
      // Check for data field that might contain revert reason
      if (typeof errorObj['data'] === 'string') {
        reason = extractRevertReason(message, errorObj['data']) ?? undefined;
      } else if (errorObj['error'] && typeof errorObj['error'] === 'object') {
        const innerError = errorObj['error'] as Record<string, unknown>;
        if (typeof innerError['data'] === 'string') {
          reason = extractRevertReason(message, innerError['data']) ?? undefined;
        }
      }
    }

    // Also try to extract from message
    if (!reason) {
      reason = extractRevertReason(message) ?? undefined;
    }

    const options: { method?: string; reason?: string } = { method };
    if (reason) options.reason = reason;

    return new ContractError(
      reason ? `Contract call failed: ${reason}` : `Contract call failed: ${message}`,
      this.address,
      ErrorCode.CALL_EXCEPTION,
      options
    );
  }


  /**
   * Generate event filters for all events in the ABI
   */
  private generateFilters(): void {
    for (const [name, fragment] of this.interface.events) {
      this.filters[name] = (...args: unknown[]): EventFilter => {
        return this.createEventFilter(fragment, args);
      };
    }
  }

  /**
   * Create an event filter
   */
  private createEventFilter(
    fragment: EventFragment,
    args: unknown[]
  ): EventFilter {
    const topics = this.interface.encodeFilterTopics(fragment.name, args);

    return {
      address: this.address,
      topics: topics as (string | string[] | null)[],
    };
  }

  /**
   * Connect to a new signer or provider
   * @param signerOrProvider - Signer or Provider to connect
   * @returns New Contract instance
   */
  connect(signerOrProvider: Signer | Provider): Contract {
    return new Contract(this.address, this.interface, signerOrProvider);
  }

  /**
   * Attach to a new address
   * @param address - New contract address
   * @returns New Contract instance
   */
  attach(address: string): Contract {
    return new Contract(
      address,
      this.interface,
      this.signer ?? this.provider ?? undefined
    );
  }

  /**
   * Get the deployed bytecode
   * @returns Contract bytecode
   */
  async getDeployedCode(): Promise<string> {
    if (!this.provider) {
      throw new QuantaureumError(
        'Cannot get code: no provider connected',
        ErrorCode.NO_PROVIDER
      );
    }

    return this.provider.getCode(this.address);
  }

  /**
   * Wait for contract deployment
   * @param timeout - Timeout in milliseconds
   * @returns This contract instance
   */
  async waitForDeployment(timeout?: number): Promise<Contract> {
    if (!this.provider) {
      throw new QuantaureumError(
        'Cannot wait for deployment: no provider connected',
        ErrorCode.NO_PROVIDER
      );
    }

    const startTime = Date.now();
    const timeoutMs = timeout ?? 60000;

    // eslint-disable-next-line no-constant-condition
    while (true) {
      const code = await this.provider.getCode(this.address);
      if (code !== '0x' && code !== '') {
        return this;
      }

      if (Date.now() - startTime > timeoutMs) {
        throw new ContractError(
          'Contract deployment timeout',
          this.address,
          ErrorCode.TIMEOUT
        );
      }

      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }


  /**
   * Query historical events
   * @param event - Event name or filter
   * @param fromBlock - Start block
   * @param toBlock - End block
   * @returns Array of parsed events
   */
  async queryFilter(
    event: string | EventFilter,
    fromBlock?: number | string,
    toBlock?: number | string
  ): Promise<ContractEvent[]> {
    if (!this.provider) {
      throw new QuantaureumError(
        'Cannot query events: no provider connected',
        ErrorCode.NO_PROVIDER
      );
    }

    let filter: EventFilter;

    if (typeof event === 'string') {
      // Get event fragment
      const fragment = this.interface.getEvent(event);
      filter = {
        address: this.address,
        topics: [fragment.topic],
      };
    } else {
      filter = {
        ...event,
        address: event.address ?? this.address,
      };
    }

    if (fromBlock !== undefined) {
      filter.fromBlock = fromBlock;
    }
    if (toBlock !== undefined) {
      filter.toBlock = toBlock;
    }

    const logs = await this.provider.getLogs(filter);
    return this.parseLogs(logs);
  }

  /**
   * Parse logs into contract events
   */
  private parseLogs(logs: Log[]): ContractEvent[] {
    const events: ContractEvent[] = [];

    for (const log of logs) {
      const event = this.parseLog(log);
      if (event) {
        events.push(event);
      }
    }

    return events;
  }

  /**
   * Parse a single log into a contract event
   */
  private parseLog(log: Log): ContractEvent | null {
    if (!log.topics || log.topics.length === 0) {
      return null;
    }

    const topic = log.topics[0];
    if (!topic) {
      return null;
    }

    // Find matching event
    const fragment = this.interface.eventsByTopic.get(topic);
    if (!fragment) {
      return null;
    }

    try {
      const args = this.interface.decodeEventLog(
        fragment.name,
        log.data,
        log.topics
      );

      return {
        eventName: fragment.name,
        args,
        log,
        blockNumber: log.blockNumber,
        blockHash: log.blockHash,
        transactionHash: log.transactionHash,
        logIndex: log.logIndex,
      };
    } catch {
      return null;
    }
  }


  /**
   * Subscribe to contract events
   * @param event - Event name or filter
   * @param listener - Event listener
   */
  on(event: string | EventFilter, listener: (...args: unknown[]) => void): void {
    if (!this.provider) {
      throw new QuantaureumError(
        'Cannot subscribe to events: no provider connected',
        ErrorCode.NO_PROVIDER
      );
    }

    const key = this.getEventKey(event);
    let listeners = this.eventListeners.get(key);
    if (!listeners) {
      listeners = new Set();
      this.eventListeners.set(key, listeners);
    }
    listeners.add(listener);

    // Set up provider listener
    const filter = this.getEventFilter(event);
    const providerListener = (...args: unknown[]): void => {
      const log = args[0] as Log;
      if (log) {
        const parsedEvent = this.parseLog(log);
        if (parsedEvent) {
          listener(parsedEvent);
        }
      }
    };
    this.provider.on(filter, providerListener);
  }

  /**
   * Subscribe to contract events (once)
   * @param event - Event name or filter
   * @param listener - Event listener
   */
  once(event: string | EventFilter, listener: (...args: unknown[]) => void): void {
    const wrappedListener = (...args: unknown[]): void => {
      this.off(event, wrappedListener);
      listener(...args);
    };
    this.on(event, wrappedListener);
  }

  /**
   * Unsubscribe from contract events
   * @param event - Event name or filter
   * @param listener - Event listener
   */
  off(event: string | EventFilter, listener: (...args: unknown[]) => void): void {
    const key = this.getEventKey(event);
    const listeners = this.eventListeners.get(key);
    if (listeners) {
      listeners.delete(listener);
      if (listeners.size === 0) {
        this.eventListeners.delete(key);
      }
    }

    if (this.provider) {
      const filter = this.getEventFilter(event);
      this.provider.off(filter, listener);
    }
  }

  /**
   * Remove all event listeners
   * @param event - Event name or filter (optional)
   */
  removeAllListeners(event?: string | EventFilter): void {
    if (event === undefined) {
      this.eventListeners.clear();
      if (this.provider) {
        this.provider.removeAllListeners();
      }
    } else {
      const key = this.getEventKey(event);
      this.eventListeners.delete(key);
      if (this.provider) {
        const filter = this.getEventFilter(event);
        this.provider.removeAllListeners(filter);
      }
    }
  }

  /**
   * Get event key for listener management
   */
  private getEventKey(event: string | EventFilter): string {
    if (typeof event === 'string') {
      return event;
    }
    return JSON.stringify(event);
  }

  /**
   * Get event filter from event name or filter
   */
  private getEventFilter(event: string | EventFilter): EventFilter {
    if (typeof event === 'string') {
      const fragment = this.interface.getEvent(event);
      return {
        address: this.address,
        topics: [fragment.topic],
      };
    }
    return {
      ...event,
      address: event.address ?? this.address,
    };
  }

  /**
   * Get the number of listeners for an event
   * @param event - Event name or filter
   * @returns Number of listeners
   */
  listenerCount(event?: string | EventFilter): number {
    if (event === undefined) {
      let count = 0;
      for (const listeners of this.eventListeners.values()) {
        count += listeners.size;
      }
      return count;
    }

    const key = this.getEventKey(event);
    const listeners = this.eventListeners.get(key);
    return listeners ? listeners.size : 0;
  }

  /**
   * Get all listeners for an event
   * @param event - Event name or filter
   * @returns Array of listeners
   */
  listeners(event?: string | EventFilter): ((...args: unknown[]) => void)[] {
    if (event === undefined) {
      const allListeners: ((...args: unknown[]) => void)[] = [];
      for (const listeners of this.eventListeners.values()) {
        allListeners.push(...listeners);
      }
      return allListeners;
    }

    const key = this.getEventKey(event);
    const listeners = this.eventListeners.get(key);
    return listeners ? Array.from(listeners) : [];
  }
}

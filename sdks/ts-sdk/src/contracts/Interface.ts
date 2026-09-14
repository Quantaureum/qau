// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Interface class for ABI parsing and method generation
 * @module contracts/Interface
 */

import type {
  ABI,
  ABIFunction,
  ABIEvent,
  ABIError,
  ABIParameter,
} from '../utils/abi';
import {
  encodeAbi,
  decodeAbi,
  encodeFunctionData,
  decodeFunctionResult,
} from '../utils/abi';
import { keccak256 } from '../utils/hash';
import { ValidationError, ErrorCode } from '../errors';

/**
 * Parsed function fragment
 */
export interface FunctionFragment {
  /** Function type */
  type: 'function' | 'constructor' | 'fallback' | 'receive';
  /** Function name */
  name: string;
  /** Function inputs */
  inputs: ABIParameter[];
  /** Function outputs */
  outputs: ABIParameter[];
  /** State mutability */
  stateMutability: 'pure' | 'view' | 'nonpayable' | 'payable';
  /** Function selector (4 bytes) */
  selector: string;
  /** Full function signature */
  signature: string;
}

/**
 * Parsed event fragment
 */
export interface EventFragment {
  /** Event type */
  type: 'event';
  /** Event name */
  name: string;
  /** Event inputs */
  inputs: ABIParameter[];
  /** Whether the event is anonymous */
  anonymous: boolean;
  /** Event topic (keccak256 of signature) */
  topic: string;
  /** Full event signature */
  signature: string;
}

/**
 * Parsed error fragment
 */
export interface ErrorFragment {
  /** Error type */
  type: 'error';
  /** Error name */
  name: string;
  /** Error inputs */
  inputs: ABIParameter[];
  /** Error selector (4 bytes) */
  selector: string;
  /** Full error signature */
  signature: string;
}


/**
 * Interface class for parsing and interacting with contract ABIs
 */
export class Interface {
  /** The raw ABI */
  readonly abi: ABI;

  /** Parsed function fragments by name */
  readonly functions: Map<string, FunctionFragment>;

  /** Parsed event fragments by name */
  readonly events: Map<string, EventFragment>;

  /** Parsed error fragments by name */
  readonly errors: Map<string, ErrorFragment>;

  /** Function fragments by selector */
  readonly functionsBySelector: Map<string, FunctionFragment>;

  /** Event fragments by topic */
  readonly eventsByTopic: Map<string, EventFragment>;

  /** Error fragments by selector */
  readonly errorsBySelector: Map<string, ErrorFragment>;

  /**
   * Create a new Interface instance
   * @param abi - Contract ABI (array or JSON string)
   */
  constructor(abi: ABI | string) {
    // Parse ABI if string
    let parsedAbi: ABI;
    if (typeof abi === 'string') {
      try {
        parsedAbi = JSON.parse(abi) as ABI;
      } catch {
        throw new ValidationError(
          'Invalid ABI: failed to parse JSON',
          'abi',
          abi,
          ErrorCode.INVALID_ABI,
          'valid JSON array'
        );
      }
    } else if (Array.isArray(abi)) {
      parsedAbi = abi;
    } else {
      throw new ValidationError(
        'Invalid ABI: must be an array or JSON string',
        'abi',
        abi,
        ErrorCode.INVALID_ABI,
        'array or JSON string'
      );
    }

    this.abi = parsedAbi;
    this.functions = new Map();
    this.events = new Map();
    this.errors = new Map();
    this.functionsBySelector = new Map();
    this.eventsByTopic = new Map();
    this.errorsBySelector = new Map();

    // Parse all ABI entries
    for (const item of parsedAbi) {
      if (item.type === 'function' || item.type === 'constructor' ||
          item.type === 'fallback' || item.type === 'receive') {
        this.parseFunction(item);
      } else if (item.type === 'event') {
        this.parseEvent(item);
      } else if (item.type === 'error') {
        this.parseError(item);
      }
    }
  }


  /**
   * Parse a function ABI entry
   */
  private parseFunction(item: ABIFunction): void {
    const name = item.name ?? (item.type === 'constructor' ? 'constructor' : item.type);
    const inputs = item.inputs ?? [];
    const outputs = item.outputs ?? [];
    const stateMutability = item.stateMutability ?? 'nonpayable';

    // Build signature
    const inputTypes = inputs.map((input) => this.formatType(input));
    const signature = `${name}(${inputTypes.join(',')})`;

    // Calculate selector (first 4 bytes of keccak256)
    const selector = keccak256(signature).slice(0, 10);

    const fragment: FunctionFragment = {
      type: item.type,
      name,
      inputs,
      outputs,
      stateMutability,
      selector,
      signature,
    };

    this.functions.set(name, fragment);
    this.functionsBySelector.set(selector, fragment);
  }

  /**
   * Parse an event ABI entry
   */
  private parseEvent(item: ABIEvent): void {
    const name = item.name;
    const inputs = item.inputs ?? [];
    const anonymous = item.anonymous ?? false;

    // Build signature
    const inputTypes = inputs.map((input) => this.formatType(input));
    const signature = `${name}(${inputTypes.join(',')})`;

    // Calculate topic (keccak256 of signature)
    const topic = keccak256(signature);

    const fragment: EventFragment = {
      type: 'event',
      name,
      inputs,
      anonymous,
      topic,
      signature,
    };

    this.events.set(name, fragment);
    this.eventsByTopic.set(topic, fragment);
  }

  /**
   * Parse an error ABI entry
   */
  private parseError(item: ABIError): void {
    const name = item.name;
    const inputs = item.inputs || [];

    // Build signature
    const inputTypes = inputs.map((input) => this.formatType(input));
    const signature = `${name}(${inputTypes.join(',')})`;

    // Calculate selector (first 4 bytes of keccak256)
    const selector = keccak256(signature).slice(0, 10);

    const fragment: ErrorFragment = {
      type: 'error',
      name,
      inputs,
      selector,
      signature,
    };

    this.errors.set(name, fragment);
    this.errorsBySelector.set(selector, fragment);
  }

  /**
   * Format a parameter type for signature generation
   */
  private formatType(param: ABIParameter): string {
    if (param.type === 'tuple' && param.components) {
      const componentTypes = param.components.map((c) => this.formatType(c));
      return `(${componentTypes.join(',')})`;
    }
    if (param.type.startsWith('tuple') && param.components) {
      const suffix = param.type.slice(5); // e.g., "[]" or "[3]"
      const componentTypes = param.components.map((c) => this.formatType(c));
      return `(${componentTypes.join(',')})${suffix}`;
    }
    return param.type;
  }


  /**
   * Get a function fragment by name or selector
   * @param nameOrSelector - Function name or selector
   * @returns Function fragment
   */
  getFunction(nameOrSelector: string): FunctionFragment {
    // Try by name first
    let fragment = this.functions.get(nameOrSelector);
    if (fragment) return fragment;

    // Try by selector
    const selector = nameOrSelector.startsWith('0x')
      ? nameOrSelector.slice(0, 10)
      : `0x${nameOrSelector.slice(0, 8)}`;
    fragment = this.functionsBySelector.get(selector);
    if (fragment) return fragment;

    throw new ValidationError(
      `Function "${nameOrSelector}" not found in interface`,
      'nameOrSelector',
      nameOrSelector,
      ErrorCode.INVALID_ARGUMENT,
      'valid function name or selector'
    );
  }

  /**
   * Get an event fragment by name or topic
   * @param nameOrTopic - Event name or topic
   * @returns Event fragment
   */
  getEvent(nameOrTopic: string): EventFragment {
    // Try by name first
    let fragment = this.events.get(nameOrTopic);
    if (fragment) return fragment;

    // Try by topic
    fragment = this.eventsByTopic.get(nameOrTopic);
    if (fragment) return fragment;

    throw new ValidationError(
      `Event "${nameOrTopic}" not found in interface`,
      'nameOrTopic',
      nameOrTopic,
      ErrorCode.INVALID_ARGUMENT,
      'valid event name or topic'
    );
  }

  /**
   * Get an error fragment by name or selector
   * @param nameOrSelector - Error name or selector
   * @returns Error fragment
   */
  getError(nameOrSelector: string): ErrorFragment {
    // Try by name first
    let fragment = this.errors.get(nameOrSelector);
    if (fragment) return fragment;

    // Try by selector
    const selector = nameOrSelector.startsWith('0x')
      ? nameOrSelector.slice(0, 10)
      : `0x${nameOrSelector.slice(0, 8)}`;
    fragment = this.errorsBySelector.get(selector);
    if (fragment) return fragment;

    throw new ValidationError(
      `Error "${nameOrSelector}" not found in interface`,
      'nameOrSelector',
      nameOrSelector,
      ErrorCode.INVALID_ARGUMENT,
      'valid error name or selector'
    );
  }

  /**
   * Encode function call data
   * @param functionName - Function name
   * @param args - Function arguments
   * @returns Encoded call data
   */
  encodeFunctionData(functionName: string, args: unknown[] = []): string {
    return encodeFunctionData(this.abi, functionName, args);
  }

  /**
   * Decode function result data
   * @param functionName - Function name
   * @param data - Encoded result data
   * @returns Decoded result values
   */
  decodeFunctionResult(functionName: string, data: string): unknown[] {
    return decodeFunctionResult(this.abi, functionName, data);
  }


  /**
   * Encode event filter topics
   * @param eventName - Event name
   * @param args - Indexed argument values (use null for wildcards)
   * @returns Array of topics for filtering
   */
  encodeFilterTopics(eventName: string, args: (unknown | null)[] = []): (string | null)[] {
    const fragment = this.getEvent(eventName);
    const topics: (string | null)[] = [];

    // First topic is the event signature (unless anonymous)
    if (!fragment.anonymous) {
      topics.push(fragment.topic);
    }

    // Add indexed parameter topics
    const indexedInputs = fragment.inputs.filter((input) => input.indexed);
    for (let i = 0; i < indexedInputs.length; i++) {
      const input = indexedInputs[i];
      const arg = args[i];

      if (arg === null || arg === undefined) {
        topics.push(null);
      } else if (input) {
        // Encode the indexed value
        const encoded = encodeAbi([input.type], [arg]);
        topics.push(encoded);
      }
    }

    return topics;
  }

  /**
   * Decode event log data
   * @param eventName - Event name
   * @param data - Log data
   * @param topics - Log topics
   * @returns Decoded event arguments
   */
  decodeEventLog(
    eventName: string,
    data: string,
    topics: string[]
  ): Record<string, unknown> {
    const fragment = this.getEvent(eventName);
    const result: Record<string, unknown> = {};

    // Separate indexed and non-indexed inputs
    const indexedInputs = fragment.inputs.filter((input) => input.indexed);
    const nonIndexedInputs = fragment.inputs.filter((input) => !input.indexed);

    // Decode indexed parameters from topics
    let topicIndex = fragment.anonymous ? 0 : 1; // Skip event signature topic
    for (const input of indexedInputs) {
      const topic = topics[topicIndex];
      if (topic) {
        // For dynamic types (string, bytes, arrays), the topic is the hash
        if (this.isDynamicType(input.type)) {
          result[input.name] = topic;
        } else {
          const decoded = decodeAbi([input.type], topic);
          result[input.name] = decoded[0];
        }
      }
      topicIndex++;
    }

    // Decode non-indexed parameters from data
    if (nonIndexedInputs.length > 0 && data !== '0x') {
      const types = nonIndexedInputs.map((input) => input.type);
      const decoded = decodeAbi(types, data);
      for (let i = 0; i < nonIndexedInputs.length; i++) {
        const input = nonIndexedInputs[i];
        if (input) {
          result[input.name] = decoded[i];
        }
      }
    }

    return result;
  }

  /**
   * Check if a type is dynamic (variable length)
   */
  private isDynamicType(type: string): boolean {
    return (
      type === 'string' ||
      type === 'bytes' ||
      type.endsWith('[]') ||
      type.startsWith('tuple')
    );
  }

  /**
   * Parse error data from a revert
   * @param data - Error data from revert
   * @returns Parsed error or null if not recognized
   */
  parseRevertError(data: string): { name: string; args: Record<string, unknown> } | null {
    if (!data || data === '0x' || data.length < 10) {
      return null;
    }

    const selector = data.slice(0, 10);
    const fragment = this.errorsBySelector.get(selector);

    if (!fragment) {
      return null;
    }

    const types = fragment.inputs.map((input) => input.type);
    const decoded = decodeAbi(types, '0x' + data.slice(10));

    const args: Record<string, unknown> = {};
    for (let i = 0; i < fragment.inputs.length; i++) {
      const input = fragment.inputs[i];
      if (input) {
        args[input.name] = decoded[i];
      }
    }

    return { name: fragment.name, args };
  }

  /**
   * Get all function names
   */
  getFunctionNames(): string[] {
    return Array.from(this.functions.keys());
  }

  /**
   * Get all event names
   */
  getEventNames(): string[] {
    return Array.from(this.events.keys());
  }

  /**
   * Get all error names
   */
  getErrorNames(): string[] {
    return Array.from(this.errors.keys());
  }

  /**
   * Format a function fragment for display
   */
  formatFunction(nameOrSelector: string): string {
    const fragment = this.getFunction(nameOrSelector);
    const inputs = fragment.inputs
      .map((input) => `${input.type}${input.name ? ' ' + input.name : ''}`)
      .join(', ');
    const outputs = fragment.outputs
      .map((output) => `${output.type}${output.name ? ' ' + output.name : ''}`)
      .join(', ');
    return `function ${fragment.name}(${inputs})${outputs ? ` returns (${outputs})` : ''}`;
  }

  /**
   * Format an event fragment for display
   */
  formatEvent(nameOrTopic: string): string {
    const fragment = this.getEvent(nameOrTopic);
    const inputs = fragment.inputs
      .map((input) => {
        const indexed = input.indexed ? 'indexed ' : '';
        return `${input.type} ${indexed}${input.name}`;
      })
      .join(', ');
    return `event ${fragment.name}(${inputs})`;
  }
}

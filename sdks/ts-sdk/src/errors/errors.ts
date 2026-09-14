// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Custom error classes for Quantaureum SDK
 */

import type { TransactionReceipt } from '../types/transaction';

/**
 * Error codes used throughout the SDK
 */
export enum ErrorCode {
  // Network errors
  NETWORK_ERROR = 'NETWORK_ERROR',
  TIMEOUT = 'TIMEOUT',
  CONNECTION_REFUSED = 'CONNECTION_REFUSED',

  // RPC errors
  RPC_ERROR = 'RPC_ERROR',
  INVALID_RESPONSE = 'INVALID_RESPONSE',
  SERVER_ERROR = 'SERVER_ERROR',

  // Transaction errors
  TRANSACTION_FAILED = 'TRANSACTION_FAILED',
  TRANSACTION_REVERTED = 'TRANSACTION_REVERTED',
  INSUFFICIENT_FUNDS = 'INSUFFICIENT_FUNDS',
  NONCE_TOO_LOW = 'NONCE_TOO_LOW',
  NONCE_TOO_HIGH = 'NONCE_TOO_HIGH',
  GAS_TOO_LOW = 'GAS_TOO_LOW',
  REPLACEMENT_UNDERPRICED = 'REPLACEMENT_UNDERPRICED',

  // Validation errors
  INVALID_ARGUMENT = 'INVALID_ARGUMENT',
  INVALID_ADDRESS = 'INVALID_ADDRESS',
  INVALID_PRIVATE_KEY = 'INVALID_PRIVATE_KEY',
  INVALID_PUBLIC_KEY = 'INVALID_PUBLIC_KEY',
  INVALID_MNEMONIC = 'INVALID_MNEMONIC',
  INVALID_HEX = 'INVALID_HEX',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',

  // Contract errors
  CALL_EXCEPTION = 'CALL_EXCEPTION',
  UNPREDICTABLE_GAS_LIMIT = 'UNPREDICTABLE_GAS_LIMIT',
  CONTRACT_NOT_DEPLOYED = 'CONTRACT_NOT_DEPLOYED',
  INVALID_ABI = 'INVALID_ABI',

  // Signer errors
  NO_PROVIDER = 'NO_PROVIDER',
  SIGNING_DENIED = 'SIGNING_DENIED',

  // Unknown
  UNKNOWN_ERROR = 'UNKNOWN_ERROR',
}

/**
 * Base error class for all Quantaureum SDK errors
 */
export class QuantaureumError extends Error {
  /** Error code for programmatic handling */
  readonly code: ErrorCode;
  /** Additional context about the error */
  readonly context: Record<string, unknown> | undefined;

  constructor(message: string, code: ErrorCode, context?: Record<string, unknown>) {
    super(message);
    this.name = 'QuantaureumError';
    this.code = code;
    this.context = context;

    // Maintains proper stack trace for where error was thrown
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, QuantaureumError);
    }
  }

  /**
   * Create a formatted error message with code
   */
  override toString(): string {
    return `[${this.code}] ${this.message}`;
  }

  /**
   * Convert error to JSON for logging
   */
  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      context: this.context,
    };
  }
}

/**
 * Error for RPC-related failures
 */
export class RpcError extends QuantaureumError {
  /** RPC error code from the server */
  readonly rpcCode: number;
  /** RPC error message from the server */
  readonly rpcMessage: string;
  /** Additional RPC error data */
  readonly rpcData: unknown;

  constructor(
    message: string,
    rpcCode: number,
    rpcMessage: string,
    rpcData?: unknown,
    context?: Record<string, unknown>
  ) {
    super(message, ErrorCode.RPC_ERROR, context);
    this.name = 'RpcError';
    this.rpcCode = rpcCode;
    this.rpcMessage = rpcMessage;
    this.rpcData = rpcData;
  }

  override toJSON(): Record<string, unknown> {
    return {
      ...super.toJSON(),
      rpcCode: this.rpcCode,
      rpcMessage: this.rpcMessage,
      rpcData: this.rpcData,
    };
  }
}

/**
 * Error for transaction-related failures
 */
export class TransactionError extends QuantaureumError {
  /** Transaction hash (if available) */
  readonly transactionHash: string | undefined;
  /** Transaction receipt (if available) */
  readonly receipt: TransactionReceipt | undefined;
  /** Revert reason (if available) */
  readonly reason: string | undefined;

  constructor(
    message: string,
    code: ErrorCode = ErrorCode.TRANSACTION_FAILED,
    options?: {
      transactionHash?: string;
      receipt?: TransactionReceipt;
      reason?: string;
      context?: Record<string, unknown>;
    }
  ) {
    super(message, code, options?.context);
    this.name = 'TransactionError';
    this.transactionHash = options?.transactionHash;
    this.receipt = options?.receipt;
    this.reason = options?.reason;
  }

  override toJSON(): Record<string, unknown> {
    return {
      ...super.toJSON(),
      transactionHash: this.transactionHash,
      receipt: this.receipt,
      reason: this.reason,
    };
  }
}

/**
 * Error for input validation failures
 */
export class ValidationError extends QuantaureumError {
  /** Name of the invalid field/parameter */
  readonly field: string;
  /** The invalid value that was provided */
  readonly value: unknown;
  /** Expected type or format */
  readonly expected: string | undefined;

  constructor(
    message: string,
    field: string,
    value: unknown,
    code: ErrorCode = ErrorCode.INVALID_ARGUMENT,
    expected?: string,
    context?: Record<string, unknown>
  ) {
    super(message, code, context);
    this.name = 'ValidationError';
    this.field = field;
    this.value = value;
    this.expected = expected;
  }

  override toJSON(): Record<string, unknown> {
    return {
      ...super.toJSON(),
      field: this.field,
      value: this.value,
      expected: this.expected,
    };
  }
}

/**
 * Error for network-related failures
 */
export class NetworkError extends QuantaureumError {
  /** URL that failed */
  readonly url: string;
  /** HTTP status code (if applicable) */
  readonly statusCode: number | undefined;

  constructor(
    message: string,
    url: string,
    code: ErrorCode = ErrorCode.NETWORK_ERROR,
    statusCode?: number,
    context?: Record<string, unknown>
  ) {
    super(message, code, context);
    this.name = 'NetworkError';
    this.url = url;
    this.statusCode = statusCode;
  }

  override toJSON(): Record<string, unknown> {
    return {
      ...super.toJSON(),
      url: this.url,
      statusCode: this.statusCode,
    };
  }
}

/**
 * Error for contract call failures
 */
export class ContractError extends QuantaureumError {
  /** Contract address */
  readonly contractAddress: string;
  /** Method that failed */
  readonly method: string | undefined;
  /** Revert reason */
  readonly reason: string | undefined;
  /** Error data from the contract */
  readonly errorData: string | undefined;

  constructor(
    message: string,
    contractAddress: string,
    code: ErrorCode = ErrorCode.CALL_EXCEPTION,
    options?: {
      method?: string;
      reason?: string;
      errorData?: string;
      context?: Record<string, unknown>;
    }
  ) {
    super(message, code, options?.context);
    this.name = 'ContractError';
    this.contractAddress = contractAddress;
    this.method = options?.method;
    this.reason = options?.reason;
    this.errorData = options?.errorData;
  }

  override toJSON(): Record<string, unknown> {
    return {
      ...super.toJSON(),
      contractAddress: this.contractAddress,
      method: this.method,
      reason: this.reason,
      errorData: this.errorData,
    };
  }
}

/**
 * Type guard to check if an error is a QuantaureumError
 */
export function isQuantaureumError(error: unknown): error is QuantaureumError {
  return error instanceof QuantaureumError;
}

/**
 * Type guard to check if an error is an RpcError
 */
export function isRpcError(error: unknown): error is RpcError {
  return error instanceof RpcError;
}

/**
 * Type guard to check if an error is a TransactionError
 */
export function isTransactionError(error: unknown): error is TransactionError {
  return error instanceof TransactionError;
}

/**
 * Type guard to check if an error is a ValidationError
 */
export function isValidationError(error: unknown): error is ValidationError {
  return error instanceof ValidationError;
}

/**
 * Type guard to check if an error is a NetworkError
 */
export function isNetworkError(error: unknown): error is NetworkError {
  return error instanceof NetworkError;
}

/**
 * Type guard to check if an error is a ContractError
 */
export function isContractError(error: unknown): error is ContractError {
  return error instanceof ContractError;
}

/**
 * Standard RPC error codes
 */
export const RPC_ERROR_CODES = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  SERVER_ERROR_START: -32099,
  SERVER_ERROR_END: -32000,
  // Ethereum-specific error codes
  EXECUTION_REVERTED: 3,
  RESOURCE_NOT_FOUND: -32001,
  RESOURCE_UNAVAILABLE: -32002,
  TRANSACTION_REJECTED: -32003,
  METHOD_NOT_SUPPORTED: -32004,
  LIMIT_EXCEEDED: -32005,
  JSON_RPC_VERSION_NOT_SUPPORTED: -32006,
} as const;

/**
 * Parse an RPC error response and create appropriate error
 * @param rpcError - RPC error object from response
 * @param context - Additional context about the request
 * @returns Appropriate error instance
 */
export function parseRpcError(
  rpcError: { code: number; message: string; data?: unknown },
  context?: { method?: string; params?: unknown[] }
): RpcError | TransactionError {
  const { code, message, data } = rpcError;

  // Check for execution reverted (transaction revert)
  if (code === RPC_ERROR_CODES.EXECUTION_REVERTED ||
      message.toLowerCase().includes('revert') ||
      message.toLowerCase().includes('execution reverted')) {
    const reason = extractRevertReason(message, data);
    const options: { reason?: string; context?: Record<string, unknown> } = {};
    if (reason) options.reason = reason;
    if (context) options.context = context;
    return new TransactionError(
      reason ? `Transaction reverted: ${reason}` : 'Transaction reverted',
      ErrorCode.TRANSACTION_REVERTED,
      options
    );
  }

  // Check for insufficient funds
  if (message.toLowerCase().includes('insufficient funds') ||
      message.toLowerCase().includes('insufficient balance')) {
    return new TransactionError(
      'Insufficient funds for transaction',
      ErrorCode.INSUFFICIENT_FUNDS,
      context ? { context } : undefined
    );
  }

  // Check for nonce errors
  if (message.toLowerCase().includes('nonce too low')) {
    return new TransactionError(
      'Nonce too low',
      ErrorCode.NONCE_TOO_LOW,
      context ? { context } : undefined
    );
  }

  if (message.toLowerCase().includes('nonce too high')) {
    return new TransactionError(
      'Nonce too high',
      ErrorCode.NONCE_TOO_HIGH,
      context ? { context } : undefined
    );
  }

  // Check for gas errors
  if (message.toLowerCase().includes('gas too low') ||
      message.toLowerCase().includes('intrinsic gas too low')) {
    return new TransactionError(
      'Gas limit too low',
      ErrorCode.GAS_TOO_LOW,
      context ? { context } : undefined
    );
  }

  // Check for replacement transaction errors
  if (message.toLowerCase().includes('replacement transaction underpriced')) {
    return new TransactionError(
      'Replacement transaction underpriced',
      ErrorCode.REPLACEMENT_UNDERPRICED,
      context ? { context } : undefined
    );
  }

  // Default to RpcError
  return new RpcError(
    message || 'RPC error',
    code,
    message,
    data,
    context
  );
}

/**
 * Extract revert reason from error message or data
 * @param message - Error message
 * @param data - Error data (may contain encoded revert reason)
 * @returns Extracted revert reason or null
 */
export function extractRevertReason(
  message: string,
  data?: unknown
): string | null {
  // Try to extract from message first
  // Common patterns: "execution reverted: reason", "revert: reason", "reverted with reason string 'reason'"
  const messagePatterns = [
    /execution reverted:\s*(.+)/i,
    /revert:\s*(.+)/i,
    /reverted with reason string\s*['"](.+)['"]/i,
    /reverted:\s*(.+)/i,
    /VM Exception while processing transaction: revert\s*(.+)/i,
  ];

  for (const pattern of messagePatterns) {
    const match = message.match(pattern);
    if (match?.[1]) {
      return match[1].trim();
    }
  }

  // Try to decode from data if it's a hex string
  if (typeof data === 'string' && data.startsWith('0x')) {
    const decoded = decodeRevertData(data);
    if (decoded) {
      return decoded;
    }
  }

  // Check if data is an object with a message field
  if (data && typeof data === 'object' && 'message' in data) {
    const dataMessage = (data as { message: string }).message;
    if (typeof dataMessage === 'string') {
      return dataMessage;
    }
  }

  return null;
}

/**
 * Decode revert data to extract the reason string
 * @param data - Hex-encoded revert data
 * @returns Decoded reason string or null
 */
export function decodeRevertData(data: string): string | null {
  if (!data || data === '0x' || data.length < 10) {
    return null;
  }

  // Error(string) selector: 0x08c379a0
  const ERROR_SELECTOR = '0x08c379a0';
  // Panic(uint256) selector: 0x4e487b71
  const PANIC_SELECTOR = '0x4e487b71';

  const selector = data.slice(0, 10).toLowerCase();

  if (selector === ERROR_SELECTOR) {
    // Decode Error(string)
    try {
      // Skip selector (4 bytes = 8 hex chars + 0x)
      const encodedData = data.slice(10);

      // First 32 bytes is the offset to the string data
      // Next 32 bytes is the string length
      // Then the string data
      if (encodedData.length < 128) {
        return null;
      }

      const lengthHex = encodedData.slice(64, 128);
      const length = parseInt(lengthHex, 16);

      if (length === 0 || length > 1000) {
        return null;
      }

      const stringDataHex = encodedData.slice(128, 128 + length * 2);
      const bytes = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        bytes[i] = parseInt(stringDataHex.slice(i * 2, i * 2 + 2), 16);
      }

      return new TextDecoder().decode(bytes);
    } catch {
      return null;
    }
  }

  if (selector === PANIC_SELECTOR) {
    // Decode Panic(uint256)
    try {
      const panicCodeHex = data.slice(10, 74);
      const panicCode = parseInt(panicCodeHex, 16);
      return getPanicReason(panicCode);
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Get human-readable panic reason from panic code
 * @param code - Panic code
 * @returns Human-readable reason
 */
function getPanicReason(code: number): string {
  const panicReasons: Record<number, string> = {
    0x00: 'Generic compiler panic',
    0x01: 'Assertion failed',
    0x11: 'Arithmetic overflow/underflow',
    0x12: 'Division or modulo by zero',
    0x21: 'Invalid enum value',
    0x22: 'Storage byte array encoding error',
    0x31: 'Pop on empty array',
    0x32: 'Array index out of bounds',
    0x41: 'Memory allocation overflow',
    0x51: 'Zero-initialized function pointer call',
  };

  return panicReasons[code] || `Panic code: 0x${code.toString(16)}`;
}

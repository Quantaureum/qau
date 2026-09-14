// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Input validation utilities for Quantaureum SDK
 * @module utils/validation
 */

import { ValidationError, ErrorCode } from '../errors';
import { isAddress } from './address';
import { isHexString } from './hex';

/**
 * Validate that a value is defined (not null or undefined)
 * @param value - Value to validate
 * @param field - Field name for error message
 * @param expected - Expected type description
 * @throws ValidationError if value is null or undefined
 */
export function assertDefined<T>(
  value: T | null | undefined,
  field: string,
  expected: string
): asserts value is T {
  if (value === null || value === undefined) {
    throw new ValidationError(
      `${field} is required`,
      field,
      value,
      ErrorCode.INVALID_ARGUMENT,
      expected
    );
  }
}

/**
 * Validate that a value is a string
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a string
 */
export function assertString(
  value: unknown,
  field: string
): asserts value is string {
  if (typeof value !== 'string') {
    throw new ValidationError(
      `${field} must be a string`,
      field,
      value,
      ErrorCode.INVALID_ARGUMENT,
      'string'
    );
  }
}

/**
 * Validate that a value is a non-empty string
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a non-empty string
 */
export function assertNonEmptyString(
  value: unknown,
  field: string
): asserts value is string {
  assertString(value, field);
  if (value.trim().length === 0) {
    throw new ValidationError(
      `${field} cannot be empty`,
      field,
      value,
      ErrorCode.INVALID_ARGUMENT,
      'non-empty string'
    );
  }
}


/**
 * Validate that a value is a number
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a number
 */
export function assertNumber(
  value: unknown,
  field: string
): asserts value is number {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    throw new ValidationError(
      `${field} must be a number`,
      field,
      value,
      ErrorCode.INVALID_ARGUMENT,
      'number'
    );
  }
}

/**
 * Validate that a value is a non-negative integer
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a non-negative integer
 */
export function assertNonNegativeInteger(
  value: unknown,
  field: string
): asserts value is number {
  assertNumber(value, field);
  if (!Number.isInteger(value) || value < 0) {
    throw new ValidationError(
      `${field} must be a non-negative integer`,
      field,
      value,
      ErrorCode.INVALID_ARGUMENT,
      'non-negative integer'
    );
  }
}

/**
 * Validate that a value is a positive integer
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a positive integer
 */
export function assertPositiveInteger(
  value: unknown,
  field: string
): asserts value is number {
  assertNumber(value, field);
  if (!Number.isInteger(value) || value <= 0) {
    throw new ValidationError(
      `${field} must be a positive integer`,
      field,
      value,
      ErrorCode.INVALID_ARGUMENT,
      'positive integer'
    );
  }
}

/**
 * Validate that a value is a bigint
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a bigint
 */
export function assertBigInt(
  value: unknown,
  field: string
): asserts value is bigint {
  if (typeof value !== 'bigint') {
    throw new ValidationError(
      `${field} must be a bigint`,
      field,
      value,
      ErrorCode.INVALID_ARGUMENT,
      'bigint'
    );
  }
}

/**
 * Validate that a value is a non-negative bigint
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a non-negative bigint
 */
export function assertNonNegativeBigInt(
  value: unknown,
  field: string
): asserts value is bigint {
  assertBigInt(value, field);
  if (value < 0n) {
    throw new ValidationError(
      `${field} must be non-negative`,
      field,
      value,
      ErrorCode.INVALID_ARGUMENT,
      'non-negative bigint'
    );
  }
}

/**
 * Validate that a value is a boolean
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a boolean
 */
export function assertBoolean(
  value: unknown,
  field: string
): asserts value is boolean {
  if (typeof value !== 'boolean') {
    throw new ValidationError(
      `${field} must be a boolean`,
      field,
      value,
      ErrorCode.INVALID_ARGUMENT,
      'boolean'
    );
  }
}

/**
 * Validate that a value is a Uint8Array
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a Uint8Array
 */
export function assertUint8Array(
  value: unknown,
  field: string
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new ValidationError(
      `${field} must be a Uint8Array`,
      field,
      value,
      ErrorCode.INVALID_ARGUMENT,
      'Uint8Array'
    );
  }
}


/**
 * Validate that a value is a valid hex string
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a valid hex string
 */
export function assertHexString(
  value: unknown,
  field: string
): asserts value is string {
  assertString(value, field);
  if (!isHexString(value)) {
    throw new ValidationError(
      `${field} must be a valid hex string`,
      field,
      value,
      ErrorCode.INVALID_HEX,
      'hex string (0x-prefixed)'
    );
  }
}

/**
 * Validate that a value is a valid hex string with specific byte length
 * @param value - Value to validate
 * @param field - Field name for error message
 * @param byteLength - Expected byte length
 * @throws ValidationError if value is not a valid hex string with correct length
 */
export function assertHexStringWithLength(
  value: unknown,
  field: string,
  byteLength: number
): asserts value is string {
  assertHexString(value, field);
  const expectedLength = byteLength * 2 + 2; // 2 hex chars per byte + '0x'
  if (value.length !== expectedLength) {
    throw new ValidationError(
      `${field} must be ${byteLength} bytes (${expectedLength} characters including 0x prefix)`,
      field,
      value,
      ErrorCode.INVALID_HEX,
      `${byteLength}-byte hex string`
    );
  }
}

/**
 * Validate that a value is a valid Ethereum-style address
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a valid address
 */
export function assertAddress(
  value: unknown,
  field: string
): asserts value is string {
  if (!isAddress(value)) {
    throw new ValidationError(
      `${field} must be a valid address`,
      field,
      value,
      ErrorCode.INVALID_ADDRESS,
      '0x-prefixed 40 character hex string'
    );
  }
}

/**
 * Validate that a value is a valid transaction hash (32 bytes)
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a valid transaction hash
 */
export function assertTransactionHash(
  value: unknown,
  field: string
): asserts value is string {
  assertHexStringWithLength(value, field, 32);
}

/**
 * Validate that a value is a valid block hash (32 bytes)
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a valid block hash
 */
export function assertBlockHash(
  value: unknown,
  field: string
): asserts value is string {
  assertHexStringWithLength(value, field, 32);
}

/**
 * Validate that a value is a valid private key (32 bytes)
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a valid private key format
 */
export function assertPrivateKey(
  value: unknown,
  field: string
): asserts value is string | Uint8Array {
  if (typeof value === 'string') {
    assertHexString(value, field);
    const cleanHex = value.startsWith('0x') ? value.slice(2) : value;
    if (cleanHex.length !== 64) {
      throw new ValidationError(
        `${field} must be 32 bytes`,
        field,
        '[REDACTED]',
        ErrorCode.INVALID_PRIVATE_KEY,
        '32-byte hex string'
      );
    }
  } else if (value instanceof Uint8Array) {
    if (value.length !== 32) {
      throw new ValidationError(
        `${field} must be 32 bytes`,
        field,
        '[REDACTED]',
        ErrorCode.INVALID_PRIVATE_KEY,
        '32-byte Uint8Array'
      );
    }
  } else {
    throw new ValidationError(
      `${field} must be a hex string or Uint8Array`,
      field,
      '[REDACTED]',
      ErrorCode.INVALID_PRIVATE_KEY,
      'string or Uint8Array'
    );
  }
}


/**
 * Validate that a value is an array
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not an array
 */
export function assertArray(
  value: unknown,
  field: string
): asserts value is unknown[] {
  if (!Array.isArray(value)) {
    throw new ValidationError(
      `${field} must be an array`,
      field,
      value,
      ErrorCode.INVALID_ARGUMENT,
      'array'
    );
  }
}

/**
 * Validate that a value is an object (not null, not array)
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not an object
 */
export function assertObject(
  value: unknown,
  field: string
): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ValidationError(
      `${field} must be an object`,
      field,
      value,
      ErrorCode.INVALID_ARGUMENT,
      'object'
    );
  }
}

/**
 * Validate that a value is a function
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a function
 */
export function assertFunction(
  value: unknown,
  field: string
): asserts value is (...args: unknown[]) => unknown {
  if (typeof value !== 'function') {
    throw new ValidationError(
      `${field} must be a function`,
      field,
      value,
      ErrorCode.INVALID_ARGUMENT,
      'function'
    );
  }
}

/**
 * Validate that a value is a valid URL string
 * @param value - Value to validate
 * @param field - Field name for error message
 * @throws ValidationError if value is not a valid URL
 */
export function assertUrl(
  value: unknown,
  field: string
): asserts value is string {
  assertNonEmptyString(value, field);
  try {
    new URL(value);
  } catch {
    throw new ValidationError(
      `${field} must be a valid URL`,
      field,
      value,
      ErrorCode.INVALID_ARGUMENT,
      'valid URL string'
    );
  }
}

/**
 * Validate that a value is one of the allowed values
 * @param value - Value to validate
 * @param field - Field name for error message
 * @param allowedValues - Array of allowed values
 * @throws ValidationError if value is not in allowed values
 */
export function assertOneOf<T>(
  value: unknown,
  field: string,
  allowedValues: readonly T[]
): asserts value is T {
  if (!allowedValues.includes(value as T)) {
    throw new ValidationError(
      `${field} must be one of: ${allowedValues.join(', ')}`,
      field,
      value,
      ErrorCode.INVALID_ARGUMENT,
      `one of: ${allowedValues.join(', ')}`
    );
  }
}

/**
 * Validate a transaction request object
 * @param tx - Transaction request to validate
 * @throws ValidationError if any field is invalid
 */
export function validateTransactionRequest(tx: unknown): void {
  assertObject(tx, 'transaction');

  const transaction = tx;

  // Validate 'to' address if present
  if (transaction['to'] !== undefined && transaction['to'] !== null) {
    assertAddress(transaction['to'], 'transaction.to');
  }

  // Validate 'from' address if present
  if (transaction['from'] !== undefined && transaction['from'] !== null) {
    assertAddress(transaction['from'], 'transaction.from');
  }

  // Validate nonce if present
  if (transaction['nonce'] !== undefined && transaction['nonce'] !== null) {
    assertNonNegativeInteger(transaction['nonce'], 'transaction.nonce');
  }

  // Validate gasLimit if present
  if (transaction['gasLimit'] !== undefined && transaction['gasLimit'] !== null) {
    assertNonNegativeBigInt(transaction['gasLimit'], 'transaction.gasLimit');
  }

  // Validate gasPrice if present
  if (transaction['gasPrice'] !== undefined && transaction['gasPrice'] !== null) {
    assertNonNegativeBigInt(transaction['gasPrice'], 'transaction.gasPrice');
  }

  // Validate value if present
  if (transaction['value'] !== undefined && transaction['value'] !== null) {
    assertNonNegativeBigInt(transaction['value'], 'transaction.value');
  }

  // Validate data if present
  if (transaction['data'] !== undefined && transaction['data'] !== null) {
    assertHexString(transaction['data'], 'transaction.data');
  }

  // Validate chainId if present
  if (transaction['chainId'] !== undefined && transaction['chainId'] !== null) {
    assertPositiveInteger(transaction['chainId'], 'transaction.chainId');
  }
}

/**
 * Validate an event filter object
 * @param filter - Event filter to validate
 * @throws ValidationError if any field is invalid
 */
export function validateEventFilter(filter: unknown): void {
  assertObject(filter, 'filter');

  const f = filter;

  // Validate address if present
  if (f['address'] !== undefined && f['address'] !== null) {
    if (Array.isArray(f['address'])) {
      for (let i = 0; i < f['address'].length; i++) {
        assertAddress(f['address'][i], `filter.address[${i}]`);
      }
    } else {
      assertAddress(f['address'], 'filter.address');
    }
  }

  // Validate topics if present
  if (f['topics'] !== undefined && f['topics'] !== null) {
    assertArray(f['topics'], 'filter.topics');
  }

  // Validate fromBlock if present
  if (f['fromBlock'] !== undefined && f['fromBlock'] !== null) {
    if (typeof f['fromBlock'] !== 'number' && typeof f['fromBlock'] !== 'string') {
      throw new ValidationError(
        'filter.fromBlock must be a number or string',
        'filter.fromBlock',
        f['fromBlock'],
        ErrorCode.INVALID_ARGUMENT,
        'number or string'
      );
    }
  }

  // Validate toBlock if present
  if (f['toBlock'] !== undefined && f['toBlock'] !== null) {
    if (typeof f['toBlock'] !== 'number' && typeof f['toBlock'] !== 'string') {
      throw new ValidationError(
        'filter.toBlock must be a number or string',
        'filter.toBlock',
        f['toBlock'],
        ErrorCode.INVALID_ARGUMENT,
        'number or string'
      );
    }
  }
}

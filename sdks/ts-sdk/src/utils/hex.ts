// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Hex conversion utilities for Quantaureum SDK
 * @module utils/hex
 */

import { ValidationError, ErrorCode } from '../errors';

/**
 * Convert a value to a hex string with 0x prefix
 * @param value - Number, bigint, or Uint8Array to convert
 * @returns Hex string with 0x prefix
 */
export function toHex(value: number | bigint | Uint8Array): string {
  if (value instanceof Uint8Array) {
    return hexlify(value);
  }

  if (typeof value === 'bigint') {
    if (value < 0n) {
      throw new ValidationError(
        'Cannot convert negative bigint to hex',
        'value',
        value,
        ErrorCode.INVALID_ARGUMENT,
        'non-negative bigint'
      );
    }
    const hex = value.toString(16);
    return '0x' + hex;
  }

  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0) {
      throw new ValidationError(
        'Cannot convert non-integer or negative number to hex',
        'value',
        value,
        ErrorCode.INVALID_ARGUMENT,
        'non-negative integer'
      );
    }
    return '0x' + value.toString(16);
  }

  throw new ValidationError(
    'Invalid value type for hex conversion',
    'value',
    value,
    ErrorCode.INVALID_ARGUMENT,
    'number, bigint, or Uint8Array'
  );
}

/**
 * Convert a hex string to Uint8Array
 * @param hex - Hex string (with or without 0x prefix)
 * @returns Uint8Array of bytes
 */
export function fromHex(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new ValidationError(
      'Expected hex string',
      'hex',
      hex,
      ErrorCode.INVALID_HEX,
      'string'
    );
  }

  // Remove 0x prefix if present
  let cleanHex = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;

  // Validate hex characters
  if (!/^[0-9a-fA-F]*$/.test(cleanHex)) {
    throw new ValidationError(
      'Invalid hex string: contains non-hex characters',
      'hex',
      hex,
      ErrorCode.INVALID_HEX,
      'valid hex characters (0-9, a-f, A-F)'
    );
  }

  // Pad with leading zero if odd length
  if (cleanHex.length % 2 !== 0) {
    cleanHex = '0' + cleanHex;
  }

  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }

  return bytes;
}

/**
 * Convert Uint8Array to hex string with 0x prefix
 * @param data - Uint8Array to convert
 * @returns Hex string with 0x prefix
 */
export function hexlify(data: Uint8Array): string {
  if (!(data instanceof Uint8Array)) {
    throw new ValidationError(
      'Expected Uint8Array',
      'data',
      data,
      ErrorCode.INVALID_ARGUMENT,
      'Uint8Array'
    );
  }

  let hex = '0x';
  for (let i = 0; i < data.length; i++) {
    const byte = data[i];
    if (byte !== undefined) {
      hex += byte.toString(16).padStart(2, '0');
    }
  }
  return hex;
}

/**
 * Convert hex string to Uint8Array (alias for fromHex)
 * @param hex - Hex string (with or without 0x prefix)
 * @returns Uint8Array of bytes
 */
export function arrayify(hex: string): Uint8Array {
  return fromHex(hex);
}

/**
 * Check if a string is a valid hex string
 * @param value - String to check
 * @returns True if valid hex string
 */
export function isHexString(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }

  const cleanHex = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  return /^[0-9a-fA-F]*$/.test(cleanHex);
}

/**
 * Pad a hex string to a specific byte length
 * @param hex - Hex string to pad
 * @param length - Target byte length
 * @returns Padded hex string with 0x prefix
 */
export function zeroPadHex(hex: string, length: number): string {
  if (!isHexString(hex)) {
    throw new ValidationError(
      'Invalid hex string',
      'hex',
      hex,
      ErrorCode.INVALID_HEX,
      'valid hex string'
    );
  }

  const cleanHex = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  const targetLength = length * 2; // Each byte is 2 hex chars

  if (cleanHex.length > targetLength) {
    throw new ValidationError(
      `Hex string too long: ${cleanHex.length / 2} bytes, max ${length} bytes`,
      'hex',
      hex,
      ErrorCode.INVALID_ARGUMENT,
      `hex string with at most ${length} bytes`
    );
  }

  return '0x' + cleanHex.padStart(targetLength, '0');
}

/**
 * Concatenate multiple hex strings
 * @param hexStrings - Hex strings to concatenate
 * @returns Concatenated hex string with 0x prefix
 */
export function concatHex(...hexStrings: string[]): string {
  let result = '0x';
  for (const hex of hexStrings) {
    if (!isHexString(hex)) {
      throw new ValidationError(
        'Invalid hex string in concatenation',
        'hexStrings',
        hex,
        ErrorCode.INVALID_HEX,
        'valid hex string'
      );
    }
    const cleanHex = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
    result += cleanHex;
  }
  return result;
}

// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Formatting utilities for Quantaureum SDK
 * @module utils/format
 */

import { ValidationError, ErrorCode } from '../errors';

/**
 * Number of decimals for Ether (18)
 */
export const ETHER_DECIMALS = 18;

/**
 * One Ether in wei (10^18)
 */
export const WEI_PER_ETHER = 10n ** 18n;

/**
 * Format wei value to ether string
 * @param wei - Value in wei as bigint
 * @returns Ether value as decimal string
 */
export function formatEther(wei: bigint): string {
  return formatUnits(wei, ETHER_DECIMALS);
}

/**
 * Parse ether string to wei value
 * @param ether - Ether value as decimal string
 * @returns Value in wei as bigint
 */
export function parseEther(ether: string): bigint {
  return parseUnits(ether, ETHER_DECIMALS);
}

/**
 * Format a value with specified decimals to a decimal string
 * @param value - Value as bigint
 * @param decimals - Number of decimal places
 * @returns Formatted decimal string
 */
export function formatUnits(value: bigint, decimals: number): string {
  if (typeof value !== 'bigint') {
    throw new ValidationError(
      'Value must be a bigint',
      'value',
      value,
      ErrorCode.INVALID_ARGUMENT,
      'bigint'
    );
  }

  if (!Number.isInteger(decimals) || decimals < 0) {
    throw new ValidationError(
      'Decimals must be a non-negative integer',
      'decimals',
      decimals,
      ErrorCode.INVALID_ARGUMENT,
      'non-negative integer'
    );
  }

  const negative = value < 0n;
  const absValue = negative ? -value : value;

  const divisor = 10n ** BigInt(decimals);
  const wholePart = absValue / divisor;
  const fractionalPart = absValue % divisor;

  // Format fractional part with leading zeros
  let fractionalStr = fractionalPart.toString().padStart(decimals, '0');

  // Remove trailing zeros
  fractionalStr = fractionalStr.replace(/0+$/, '');

  // Build result
  let result = wholePart.toString();
  if (fractionalStr.length > 0) {
    result += '.' + fractionalStr;
  }

  if (negative) {
    result = '-' + result;
  }

  return result;
}

/**
 * Parse a decimal string to a value with specified decimals
 * @param value - Decimal string
 * @param decimals - Number of decimal places
 * @returns Value as bigint
 */
export function parseUnits(value: string, decimals: number): bigint {
  if (typeof value !== 'string') {
    throw new ValidationError(
      'Value must be a string',
      'value',
      value,
      ErrorCode.INVALID_ARGUMENT,
      'string'
    );
  }

  if (!Number.isInteger(decimals) || decimals < 0) {
    throw new ValidationError(
      'Decimals must be a non-negative integer',
      'decimals',
      decimals,
      ErrorCode.INVALID_ARGUMENT,
      'non-negative integer'
    );
  }

  // Trim whitespace
  value = value.trim();

  // Handle negative values
  const negative = value.startsWith('-');
  if (negative) {
    value = value.slice(1);
  }

  // Validate format
  if (!/^\d*\.?\d*$/.test(value) || value === '' || value === '.') {
    throw new ValidationError(
      `Invalid decimal string: "${value}"`,
      'value',
      value,
      ErrorCode.INVALID_ARGUMENT,
      'valid decimal string'
    );
  }

  // Split into whole and fractional parts
  const parts = value.split('.');
  const wholePart = parts[0] || '0';
  let fractionalPart = parts[1] || '';

  // Check if fractional part has too many decimals
  if (fractionalPart.length > decimals) {
    throw new ValidationError(
      `Too many decimal places: ${fractionalPart.length}, max ${decimals}`,
      'value',
      value,
      ErrorCode.INVALID_ARGUMENT,
      `at most ${decimals} decimal places`
    );
  }

  // Pad fractional part to full decimals
  fractionalPart = fractionalPart.padEnd(decimals, '0');

  // Combine and parse
  const combined = wholePart + fractionalPart;
  let result = BigInt(combined);

  if (negative) {
    result = -result;
  }

  return result;
}

/**
 * Format a bigint value with commas for readability
 * @param value - Value to format
 * @returns Formatted string with commas
 */
export function formatWithCommas(value: bigint): string {
  const str = value.toString();
  const negative = str.startsWith('-');
  const absStr = negative ? str.slice(1) : str;

  // Add commas every 3 digits from the right
  let result = '';
  for (let i = 0; i < absStr.length; i++) {
    if (i > 0 && (absStr.length - i) % 3 === 0) {
      result += ',';
    }
    result += absStr[i];
  }

  return negative ? '-' + result : result;
}

/**
 * Convert a number to bigint safely
 * @param value - Number to convert
 * @returns BigInt value
 */
export function toBigInt(value: number | string | bigint): bigint {
  if (typeof value === 'bigint') {
    return value;
  }

  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new ValidationError(
        'Cannot convert non-integer number to bigint',
        'value',
        value,
        ErrorCode.INVALID_ARGUMENT,
        'integer'
      );
    }
    return BigInt(value);
  }

  if (typeof value === 'string') {
    // Handle hex strings
    if (value.startsWith('0x') || value.startsWith('0X')) {
      return BigInt(value);
    }
    // Handle decimal strings
    return BigInt(value);
  }

  throw new ValidationError(
    'Cannot convert value to bigint',
    'value',
    value,
    ErrorCode.INVALID_ARGUMENT,
    'number, string, or bigint'
  );
}

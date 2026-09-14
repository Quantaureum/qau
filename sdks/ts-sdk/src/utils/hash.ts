// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Hash utilities for Quantaureum SDK
 * @module utils/hash
 */

import { keccak_256 } from '@noble/hashes/sha3';
import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { ValidationError, ErrorCode } from '../errors';
import { hexlify, fromHex, isHexString } from './hex';

/**
 * Compute keccak256 hash of data
 * @param data - String or Uint8Array to hash
 * @returns Hash as hex string with 0x prefix (66 chars total)
 */
export function keccak256(data: string | Uint8Array): string {
  let bytes: Uint8Array;

  if (typeof data === 'string') {
    if (isHexString(data) && data.startsWith('0x')) {
      // Hex string - convert to bytes
      bytes = fromHex(data);
    } else {
      // UTF-8 string - encode to bytes
      bytes = new TextEncoder().encode(data);
    }
  } else if (data instanceof Uint8Array) {
    bytes = data;
  } else {
    throw new ValidationError(
      'Invalid data type for keccak256',
      'data',
      data,
      ErrorCode.INVALID_ARGUMENT,
      'string or Uint8Array'
    );
  }

  const hash = keccak_256(bytes);
  return hexlify(hash);
}

/**
 * Compute SHA256 hash of data
 * @param data - String or Uint8Array to hash
 * @returns Hash as hex string with 0x prefix (66 chars total)
 */
export function sha256(data: string | Uint8Array): string {
  let bytes: Uint8Array;

  if (typeof data === 'string') {
    if (isHexString(data) && data.startsWith('0x')) {
      // Hex string - convert to bytes
      bytes = fromHex(data);
    } else {
      // UTF-8 string - encode to bytes
      bytes = new TextEncoder().encode(data);
    }
  } else if (data instanceof Uint8Array) {
    bytes = data;
  } else {
    throw new ValidationError(
      'Invalid data type for sha256',
      'data',
      data,
      ErrorCode.INVALID_ARGUMENT,
      'string or Uint8Array'
    );
  }

  const hash = nobleSha256(bytes);
  return hexlify(hash);
}

/**
 * Compute keccak256 hash of a UTF-8 string
 * This is commonly used for computing function selectors and event topics
 * @param text - UTF-8 string to hash
 * @returns Hash as hex string with 0x prefix (66 chars total)
 */
export function id(text: string): string {
  if (typeof text !== 'string') {
    throw new ValidationError(
      'Expected string for id()',
      'text',
      text,
      ErrorCode.INVALID_ARGUMENT,
      'string'
    );
  }

  const bytes = new TextEncoder().encode(text);
  const hash = keccak_256(bytes);
  return hexlify(hash);
}

/**
 * Compute the function selector (first 4 bytes of keccak256 hash)
 * @param signature - Function signature (e.g., "transfer(address,uint256)")
 * @returns Function selector as hex string with 0x prefix (10 chars total)
 */
export function functionSelector(signature: string): string {
  const hash = id(signature);
  return hash.slice(0, 10); // 0x + 8 hex chars = 4 bytes
}

/**
 * Compute the event topic (keccak256 hash of event signature)
 * @param signature - Event signature (e.g., "Transfer(address,address,uint256)")
 * @returns Event topic as hex string with 0x prefix (66 chars total)
 */
export function eventTopic(signature: string): string {
  return id(signature);
}

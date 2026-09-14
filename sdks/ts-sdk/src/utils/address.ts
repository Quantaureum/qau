// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Address utilities for Quantaureum SDK
 * @module utils/address
 */

import { keccak_256, sha3_256 } from '@noble/hashes/sha3';
import { ValidationError, ErrorCode } from '../errors';
import { fromHex, hexlify, isHexString } from './hex';

/**
 * Dilithium3 public key size — 1952 bytes (project cryptographic contract).
 * Used to validate computeAddress inputs. Kept as a local constant instead of
 * importing from the quantum-crypto module to keep utils/address decoupled
 * from the WASM loader (which is a much heavier dependency).
 */
const DILITHIUM3_PUBLIC_KEY_SIZE = 1952;

/**
 * Regular expression for validating Ethereum-style addresses
 * 40 hex characters with 0x prefix (42 chars total)
 */
const ADDRESS_REGEX = /^0x[0-9a-fA-F]{40}$/;

/**
 * Check if a string is a valid Ethereum-style address
 * @param address - String to check
 * @returns True if valid address format
 */
export function isAddress(address: unknown): address is string {
  if (typeof address !== 'string') {
    return false;
  }
  return ADDRESS_REGEX.test(address);
}

/**
 * Get the checksum address (EIP-55)
 * @param address - Address to checksum
 * @returns Checksummed address
 * @throws ValidationError if address is invalid
 */
export function getAddress(address: string): string {
  if (typeof address !== 'string') {
    throw new ValidationError(
      'Address must be a string',
      'address',
      address,
      ErrorCode.INVALID_ADDRESS,
      '0x-prefixed 40 character hex string'
    );
  }

  // Normalize to lowercase without 0x prefix
  let addr = address.toLowerCase();
  if (addr.startsWith('0x')) {
    addr = addr.slice(2);
  }

  // Validate length and characters
  if (addr.length !== 40 || !/^[0-9a-f]{40}$/.test(addr)) {
    throw new ValidationError(
      `Invalid address: ${address}`,
      'address',
      address,
      ErrorCode.INVALID_ADDRESS,
      '0x-prefixed 40 character hex string'
    );
  }

  // Compute checksum using keccak256 of lowercase address
  const hash = keccak_256(new TextEncoder().encode(addr));
  const hashHex = hexlify(hash).slice(2); // Remove 0x prefix

  // Apply checksum
  let checksumAddress = '0x';
  for (let i = 0; i < 40; i++) {
    // If the corresponding hash nibble is >= 8, uppercase the character
    const hashChar = hashHex[i];
    const addrChar = addr[i];
    if (hashChar !== undefined && addrChar !== undefined) {
      const hashNibble = parseInt(hashChar, 16);
      if (hashNibble >= 8) {
        checksumAddress += addrChar.toUpperCase();
      } else {
        checksumAddress += addrChar;
      }
    }
  }

  return checksumAddress;
}

/**
 * Compute address from a Dilithium3 public key (1952 bytes).
 *
 * R40-P0-02 (2026-08-03): the SDK now derives addresses the same way the
 * Quantaureum node and the Quantaureum extension wallet do —
 *   `address = '0x' + hexlify(NIST sha3_256(publicKey)[12:32])`
 * Previously this function hashed the secp256k1 public key with
 * Keccak-256 (Ethereum) and took the last 20 bytes, which produced addresses
 * that did NOT match any account on the Quantaureum chain. The fix switches
 * the hash family to NIST SHA3-256 and accepts the Dilithium3 public key
 * length (1952 bytes). The 65-byte / 64-byte ECDSA pubkey paths are removed
 * (no longer relevant after the Dilithium3 migration); EIP-55 checksum
 * encoding is preserved via getAddress() for backwards compatibility with
 * the address-string representation used throughout the SDK.
 *
 * @param publicKey - Dilithium3 public key (1952 bytes), as `Uint8Array` or
 *                    `0x`-prefixed hex string (3904 hex chars).
 * @returns The EIP-55 checksummed Quantaureum address
 * @throws ValidationError if the public key length is not 1952 bytes
 */
export function computeAddress(publicKey: string | Uint8Array): string {
  let pubKeyBytes: Uint8Array;

  if (typeof publicKey === 'string') {
    if (!isHexString(publicKey)) {
      throw new ValidationError(
        'Public key must be a valid hex string',
        'publicKey',
        publicKey,
        ErrorCode.INVALID_ARGUMENT,
        '1952-byte (3904-hex) Dilithium3 public key',
      );
    }
    pubKeyBytes = fromHex(publicKey);
  } else if (publicKey instanceof Uint8Array) {
    pubKeyBytes = publicKey;
  } else {
    throw new ValidationError(
      'Public key must be a string or Uint8Array',
      'publicKey',
      publicKey,
      ErrorCode.INVALID_ARGUMENT,
      'string or Uint8Array',
    );
  }

  if (pubKeyBytes.length !== DILITHIUM3_PUBLIC_KEY_SIZE) {
    throw new ValidationError(
      `Invalid public key length: ${pubKeyBytes.length} bytes (expected ${DILITHIUM3_PUBLIC_KEY_SIZE} for Dilithium3)`,
      'publicKey',
      '[REDACTED]',
      ErrorCode.INVALID_PUBLIC_KEY,
      `exactly ${DILITHIUM3_PUBLIC_KEY_SIZE} bytes`,
    );
  }

  // NIST SHA3-256 of the raw Dilithium3 public key, take bytes [12:32] (the
  // last 20 bytes of the 32-byte digest). Match `types.AddressFromPublicKeyE`
  // and the wallet's `Dilithium3.deriveAddress` byte-for-byte.
  const hash = sha3_256(pubKeyBytes);
  const addressBytes = hash.slice(12, 32);
  const address = hexlify(addressBytes);

  // Return checksummed address (EIP-55 using keccak_256 of the lowercase
  // address string — checksum is orthogonal to address derivation).
  return getAddress(address);
}

/**
 * Check if an address has a valid checksum (EIP-55)
 * @param address - Address to check
 * @returns True if checksum is valid or address is all lowercase/uppercase
 */
export function isChecksumAddress(address: string): boolean {
  if (!isAddress(address)) {
    return false;
  }

  // All lowercase or all uppercase is valid (no checksum)
  const addr = address.slice(2);
  if (addr === addr.toLowerCase() || addr === addr.toUpperCase()) {
    return true;
  }

  // Check if checksum matches
  try {
    return getAddress(address) === address;
  } catch {
    return false;
  }
}

/**
 * Compare two addresses for equality (case-insensitive)
 * @param a - First address
 * @param b - Second address
 * @returns True if addresses are equal
 */
export function addressEquals(a: string, b: string): boolean {
  if (!isAddress(a) || !isAddress(b)) {
    return false;
  }
  return a.toLowerCase() === b.toLowerCase();
}

/**
 * Zero address constant
 */
export const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

/**
 * Check if an address is the zero address
 * @param address - Address to check
 * @returns True if address is the zero address
 */
export function isZeroAddress(address: string): boolean {
  return addressEquals(address, ZERO_ADDRESS);
}

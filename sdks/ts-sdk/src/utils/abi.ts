// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * ABI encoding and decoding utilities for Quantaureum SDK
 * @module utils/abi
 */

import { ValidationError, ErrorCode } from '../errors';
import { fromHex, hexlify, isHexString } from './hex';
import { keccak256 } from './hash';
import { isAddress, getAddress } from './address';

/**
 * ABI type definitions
 */
export type ABIType =
  | 'uint8' | 'uint16' | 'uint32' | 'uint64' | 'uint128' | 'uint256'
  | 'int8' | 'int16' | 'int32' | 'int64' | 'int128' | 'int256'
  | 'address' | 'bool' | 'bytes' | 'string'
  | `bytes${number}` | `uint${number}` | `int${number}`
  | `${string}[]` | `${string}[${number}]`;

/**
 * ABI function/event parameter
 */
export interface ABIParameter {
  name: string;
  type: string;
  indexed?: boolean;
  components?: ABIParameter[];
}

/**
 * ABI function definition
 */
export interface ABIFunction {
  type: 'function' | 'constructor' | 'fallback' | 'receive';
  name?: string;
  inputs: ABIParameter[];
  outputs?: ABIParameter[];
  stateMutability?: 'pure' | 'view' | 'nonpayable' | 'payable';
}

/**
 * ABI event definition
 */
export interface ABIEvent {
  type: 'event';
  name: string;
  inputs: ABIParameter[];
  anonymous?: boolean;
}

/**
 * ABI error definition
 */
export interface ABIError {
  type: 'error';
  name: string;
  inputs: ABIParameter[];
}

/**
 * Full ABI type
 */
export type ABI = (ABIFunction | ABIEvent | ABIError)[];

/**
 * Encode ABI values
 * @param types - Array of ABI types
 * @param values - Array of values to encode
 * @returns Encoded data as hex string
 */
export function encodeAbi(types: string[], values: unknown[]): string {
  if (types.length !== values.length) {
    throw new ValidationError(
      `Types and values length mismatch: ${types.length} types, ${values.length} values`,
      'values',
      values,
      ErrorCode.INVALID_ARGUMENT,
      `${types.length} values`
    );
  }

  const encoded: Uint8Array[] = [];
  const dynamicData: Uint8Array[] = [];
  let dynamicOffset = types.length * 32; // Start of dynamic data

  for (let i = 0; i < types.length; i++) {
    const type = types[i];
    const value = values[i];
    if (type === undefined) continue;
    const { head, tail } = encodeParameter(type, value, dynamicOffset);
    encoded.push(head);
    if (tail) {
      dynamicOffset += tail.length;
      dynamicData.push(tail);
    }
  }

  // Combine head and tail data
  const totalLength = encoded.reduce((sum, arr) => sum + arr.length, 0) +
    dynamicData.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const arr of encoded) {
    result.set(arr, offset);
    offset += arr.length;
  }
  for (const arr of dynamicData) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return hexlify(result);
}

/**
 * Decode ABI values
 * @param types - Array of ABI types
 * @param data - Encoded data as hex string
 * @returns Array of decoded values
 */
export function decodeAbi(types: string[], data: string): unknown[] {
  if (!isHexString(data)) {
    throw new ValidationError(
      'Data must be a valid hex string',
      'data',
      data,
      ErrorCode.INVALID_HEX,
      'hex string'
    );
  }

  const bytes = fromHex(data);
  const results: unknown[] = [];
  let offset = 0;

  for (const type of types) {
    const { value, bytesRead } = decodeParameter(type, bytes, offset);
    results.push(value);
    offset += bytesRead;
  }

  return results;
}

/**
 * Encode function call data
 * @param abi - Contract ABI
 * @param functionName - Name of the function
 * @param args - Function arguments
 * @returns Encoded function call data
 */
export function encodeFunctionData(abi: ABI, functionName: string, args: unknown[]): string {
  const func = abi.find(
    (item): item is ABIFunction =>
      item.type === 'function' && item.name === functionName
  );

  if (!func) {
    throw new ValidationError(
      `Function "${functionName}" not found in ABI`,
      'functionName',
      functionName,
      ErrorCode.INVALID_ARGUMENT,
      'valid function name'
    );
  }

  const types = func.inputs.map(input => input.type);
  const signature = `${functionName}(${types.join(',')})`;
  const selector = keccak256(signature).slice(0, 10); // First 4 bytes

  if (args.length === 0) {
    return selector;
  }

  const encodedArgs = encodeAbi(types, args);
  return selector + encodedArgs.slice(2); // Remove 0x from encoded args
}

/**
 * Decode function result data
 * @param abi - Contract ABI
 * @param functionName - Name of the function
 * @param data - Encoded result data
 * @returns Decoded result values
 */
export function decodeFunctionResult(abi: ABI, functionName: string, data: string): unknown[] {
  const func = abi.find(
    (item): item is ABIFunction =>
      item.type === 'function' && item.name === functionName
  );

  if (!func) {
    throw new ValidationError(
      `Function "${functionName}" not found in ABI`,
      'functionName',
      functionName,
      ErrorCode.INVALID_ARGUMENT,
      'valid function name'
    );
  }

  if (!func.outputs || func.outputs.length === 0) {
    return [];
  }

  const types = func.outputs.map(output => output.type);
  return decodeAbi(types, data);
}

// Helper functions for encoding

function encodeParameter(type: string, value: unknown, dynamicOffset: number): { head: Uint8Array; tail?: Uint8Array } {
  // Handle arrays
  if (type.endsWith('[]')) {
    return encodeDynamicArray(type.slice(0, -2), value as unknown[], dynamicOffset);
  }

  // Handle fixed arrays
  const fixedArrayMatch = type.match(/^(.+)\[(\d+)\]$/);
  if (fixedArrayMatch?.[1] && fixedArrayMatch[2]) {
    return encodeFixedArray(fixedArrayMatch[1], parseInt(fixedArrayMatch[2]), value as unknown[]);
  }

  // Handle basic types
  if (type === 'address') {
    return { head: encodeAddress(value as string) };
  }

  if (type === 'bool') {
    return { head: encodeBool(value as boolean) };
  }

  if (type.startsWith('uint')) {
    const bits = parseInt(type.slice(4)) || 256;
    return { head: encodeUint(value as bigint | number, bits) };
  }

  if (type.startsWith('int')) {
    const bits = parseInt(type.slice(3)) || 256;
    return { head: encodeInt(value as bigint | number, bits) };
  }

  if (type === 'bytes') {
    return encodeDynamicBytes(value as string | Uint8Array, dynamicOffset);
  }

  if (type === 'string') {
    return encodeString(value as string, dynamicOffset);
  }

  if (type.startsWith('bytes')) {
    const size = parseInt(type.slice(5));
    return { head: encodeFixedBytes(value as string | Uint8Array, size) };
  }

  throw new ValidationError(
    `Unsupported ABI type: ${type}`,
    'type',
    type,
    ErrorCode.INVALID_ARGUMENT,
    'supported ABI type'
  );
}

function decodeParameter(type: string, data: Uint8Array, offset: number): { value: unknown; bytesRead: number } {
  // Handle arrays
  if (type.endsWith('[]')) {
    return decodeDynamicArray(type.slice(0, -2), data, offset);
  }

  // Handle fixed arrays
  const fixedArrayMatch = type.match(/^(.+)\[(\d+)\]$/);
  if (fixedArrayMatch?.[1] && fixedArrayMatch[2]) {
    return decodeFixedArray(fixedArrayMatch[1], parseInt(fixedArrayMatch[2]), data, offset);
  }

  // Handle basic types
  if (type === 'address') {
    return { value: decodeAddress(data, offset), bytesRead: 32 };
  }

  if (type === 'bool') {
    return { value: decodeBool(data, offset), bytesRead: 32 };
  }

  if (type.startsWith('uint')) {
    return { value: decodeUint(data, offset), bytesRead: 32 };
  }

  if (type.startsWith('int')) {
    return { value: decodeInt(data, offset), bytesRead: 32 };
  }

  if (type === 'bytes') {
    return decodeDynamicBytes(data, offset);
  }

  if (type === 'string') {
    return decodeString(data, offset);
  }

  if (type.startsWith('bytes')) {
    const size = parseInt(type.slice(5));
    return { value: decodeFixedBytes(data, offset, size), bytesRead: 32 };
  }

  throw new ValidationError(
    `Unsupported ABI type: ${type}`,
    'type',
    type,
    ErrorCode.INVALID_ARGUMENT,
    'supported ABI type'
  );
}

// Encoding helpers

function encodeAddress(value: string): Uint8Array {
  if (!isAddress(value)) {
    throw new ValidationError(
      'Invalid address',
      'value',
      value,
      ErrorCode.INVALID_ADDRESS,
      'valid address'
    );
  }
  const addr = getAddress(value).slice(2).toLowerCase();
  const result = new Uint8Array(32);
  const bytes = fromHex(addr);
  result.set(bytes, 12); // Right-align in 32 bytes
  return result;
}

function encodeBool(value: boolean): Uint8Array {
  const result = new Uint8Array(32);
  result[31] = value ? 1 : 0;
  return result;
}

function encodeUint(value: bigint | number, bits: number): Uint8Array {
  const bigValue = typeof value === 'number' ? BigInt(value) : value;
  if (bigValue < 0n) {
    throw new ValidationError(
      'Uint cannot be negative',
      'value',
      value,
      ErrorCode.INVALID_ARGUMENT,
      'non-negative value'
    );
  }
  const maxValue = (1n << BigInt(bits)) - 1n;
  if (bigValue > maxValue) {
    throw new ValidationError(
      `Value exceeds uint${bits} max`,
      'value',
      value,
      ErrorCode.INVALID_ARGUMENT,
      `value <= ${maxValue}`
    );
  }
  return bigintToBytes32(bigValue);
}

function encodeInt(value: bigint | number, bits: number): Uint8Array {
  const bigValue = typeof value === 'number' ? BigInt(value) : value;
  const maxValue = (1n << BigInt(bits - 1)) - 1n;
  const minValue = -(1n << BigInt(bits - 1));
  if (bigValue > maxValue || bigValue < minValue) {
    throw new ValidationError(
      `Value out of int${bits} range`,
      'value',
      value,
      ErrorCode.INVALID_ARGUMENT,
      `${minValue} <= value <= ${maxValue}`
    );
  }
  // Two's complement for negative values
  const unsigned = bigValue < 0n ? (1n << 256n) + bigValue : bigValue;
  return bigintToBytes32(unsigned);
}

function encodeFixedBytes(value: string | Uint8Array, size: number): Uint8Array {
  let bytes: Uint8Array;
  if (typeof value === 'string') {
    bytes = fromHex(value);
  } else {
    bytes = value;
  }
  if (bytes.length > size) {
    throw new ValidationError(
      `Bytes too long for bytes${size}`,
      'value',
      value,
      ErrorCode.INVALID_ARGUMENT,
      `at most ${size} bytes`
    );
  }
  const result = new Uint8Array(32);
  result.set(bytes, 0); // Left-align
  return result;
}

function encodeDynamicBytes(value: string | Uint8Array, dynamicOffset: number): { head: Uint8Array; tail: Uint8Array } {
  let bytes: Uint8Array;
  if (typeof value === 'string') {
    bytes = fromHex(value);
  } else {
    bytes = value;
  }
  const head = bigintToBytes32(BigInt(dynamicOffset));
  const length = bigintToBytes32(BigInt(bytes.length));
  const paddedLength = Math.ceil(bytes.length / 32) * 32;
  const paddedData = new Uint8Array(paddedLength);
  paddedData.set(bytes, 0);
  const tail = new Uint8Array(32 + paddedLength);
  tail.set(length, 0);
  tail.set(paddedData, 32);
  return { head, tail };
}

function encodeString(value: string, dynamicOffset: number): { head: Uint8Array; tail: Uint8Array } {
  const bytes = new TextEncoder().encode(value);
  const head = bigintToBytes32(BigInt(dynamicOffset));
  const length = bigintToBytes32(BigInt(bytes.length));
  const paddedLength = Math.ceil(bytes.length / 32) * 32;
  const paddedData = new Uint8Array(paddedLength);
  paddedData.set(bytes, 0);
  const tail = new Uint8Array(32 + paddedLength);
  tail.set(length, 0);
  tail.set(paddedData, 32);
  return { head, tail };
}

function encodeDynamicArray(elementType: string, values: unknown[], dynamicOffset: number): { head: Uint8Array; tail: Uint8Array } {
  const head = bigintToBytes32(BigInt(dynamicOffset));
  const length = bigintToBytes32(BigInt(values.length));

  const encodedElements: Uint8Array[] = [];
  for (const value of values) {
    const { head: elemHead } = encodeParameter(elementType, value, 0);
    encodedElements.push(elemHead);
  }

  const tailLength = 32 + encodedElements.reduce((sum, arr) => sum + arr.length, 0);
  const tail = new Uint8Array(tailLength);
  tail.set(length, 0);
  let offset = 32;
  for (const elem of encodedElements) {
    tail.set(elem, offset);
    offset += elem.length;
  }

  return { head, tail };
}

function encodeFixedArray(elementType: string, size: number, values: unknown[]): { head: Uint8Array; tail?: Uint8Array } {
  if (values.length !== size) {
    throw new ValidationError(
      `Array length mismatch: expected ${size}, got ${values.length}`,
      'values',
      values,
      ErrorCode.INVALID_ARGUMENT,
      `array of length ${size}`
    );
  }

  const encodedElements: Uint8Array[] = [];
  for (const value of values) {
    const { head: elemHead } = encodeParameter(elementType, value, 0);
    encodedElements.push(elemHead);
  }

  const totalLength = encodedElements.reduce((sum, arr) => sum + arr.length, 0);
  const head = new Uint8Array(totalLength);
  let offset = 0;
  for (const elem of encodedElements) {
    head.set(elem, offset);
    offset += elem.length;
  }

  return { head };
}

// Decoding helpers

function decodeAddress(data: Uint8Array, offset: number): string {
  const bytes = data.slice(offset + 12, offset + 32);
  return getAddress(hexlify(bytes));
}

function decodeBool(data: Uint8Array, offset: number): boolean {
  return data[offset + 31] !== 0;
}

function decodeUint(data: Uint8Array, offset: number): bigint {
  return bytes32ToBigint(data.slice(offset, offset + 32));
}

function decodeInt(data: Uint8Array, offset: number): bigint {
  const unsigned = bytes32ToBigint(data.slice(offset, offset + 32));
  // Check if negative (high bit set)
  if (unsigned >= (1n << 255n)) {
    return unsigned - (1n << 256n);
  }
  return unsigned;
}

function decodeFixedBytes(data: Uint8Array, offset: number, size: number): string {
  const bytes = data.slice(offset, offset + size);
  return hexlify(bytes);
}

function decodeDynamicBytes(data: Uint8Array, offset: number): { value: string; bytesRead: number } {
  const dataOffset = Number(bytes32ToBigint(data.slice(offset, offset + 32)));
  const length = Number(bytes32ToBigint(data.slice(dataOffset, dataOffset + 32)));
  const bytes = data.slice(dataOffset + 32, dataOffset + 32 + length);
  return { value: hexlify(bytes), bytesRead: 32 };
}

function decodeString(data: Uint8Array, offset: number): { value: string; bytesRead: number } {
  const dataOffset = Number(bytes32ToBigint(data.slice(offset, offset + 32)));
  const length = Number(bytes32ToBigint(data.slice(dataOffset, dataOffset + 32)));
  const bytes = data.slice(dataOffset + 32, dataOffset + 32 + length);
  return { value: new TextDecoder().decode(bytes), bytesRead: 32 };
}

function decodeDynamicArray(elementType: string, data: Uint8Array, offset: number): { value: unknown[]; bytesRead: number } {
  const dataOffset = Number(bytes32ToBigint(data.slice(offset, offset + 32)));
  const length = Number(bytes32ToBigint(data.slice(dataOffset, dataOffset + 32)));

  const values: unknown[] = [];
  let elemOffset = dataOffset + 32;
  for (let i = 0; i < length; i++) {
    const { value, bytesRead } = decodeParameter(elementType, data, elemOffset);
    values.push(value);
    elemOffset += bytesRead;
  }

  return { value: values, bytesRead: 32 };
}

function decodeFixedArray(elementType: string, size: number, data: Uint8Array, offset: number): { value: unknown[]; bytesRead: number } {
  const values: unknown[] = [];
  let currentOffset = offset;
  for (let i = 0; i < size; i++) {
    const { value, bytesRead } = decodeParameter(elementType, data, currentOffset);
    values.push(value);
    currentOffset += bytesRead;
  }
  return { value: values, bytesRead: currentOffset - offset };
}

// Utility functions

function bigintToBytes32(value: bigint): Uint8Array {
  const result = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    result[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return result;
}

function bytes32ToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte !== undefined) {
      result = (result << 8n) | BigInt(byte);
    }
  }
  return result;
}

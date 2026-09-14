// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Quantaureum Protobuf transaction serialization for the SDK.
 * @module signers/quantum-crypto/protobuf-tx
 *
 * R40-P0-02 (2026-08-03): the previous SDK signed EIP-155 RLP transactions
 * (`[nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]` → keccak_256
 * → 65-byte ECDSA signature), but the node's wire format is a Protobuf
 * encoding defined over fields 1..13 (`encoding.Transaction.MarshalTransaction`
 * / `SigningHash`). Every signature the old SDK produced was instantly rejected
 * by the node. This module reproduces the node's signing-hash byte layout
 * exactly (verified to match the wallet's `buildProtobufTransaction`), so an
 * SDK-signed tx and a wallet-signed tx verify under the same node rule.
 *
 * Field map (matches `encoding/transaction.go` + `types/quantum_transaction.go`):
 *   1  version     varint, always 1
 *   2  type        varint (0=transfer, 1=contract, 2=create, 3=stake, 4=unstake, 7=multisig)
 *   3  nonce       varint
 *   4  from        bytes (20)
 *   5  to          bytes (20) — omitted iff nil
 *   6  value       bytes (big-endian) — omitted iff all-zero
 *   7  gas_limit   varint
 *   8  gas_price   bytes (big-endian) — omitted iff all-zero
 *   9  data        bytes
 *  10  signature   bytes — ALWAYS encoded (zero-length on signing-hash path)
 *  11  public_key  bytes — ALWAYS encoded (zero-length on signing-hash path)
 *  13  chain_id    varint — ALWAYS encoded
 *
 * The "ALWAYS encode" rule for fields 10 and 11 is what makes the signing-hash
 * wire layout (signed path / empty) match the verify wire layout (signature +
 * pubkey populated). Without this, any signature would verify against the wrong
 * hash. See `encoding.Transaction.SigningHash()` and the wallet's
 * `buildProtobufTransaction` for the canonical reference.
 */

import { sha3_256 } from '@noble/hashes/sha3';

function isAllZero(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0) return false;
  }
  return true;
}

function encodeVarintInto(buf: number[], value: number | bigint): void {
  let v = BigInt(value);
  if (v < 0n) {
    throw new Error(`encodeVarint: negative value ${value} not supported`);
  }
  while (v >= 0x80n) {
    buf.push(Number(v & 0x7fn) | 0x80);
    v >>= 7n;
  }
  buf.push(Number(v & 0x7fn));
}

function encodeTagInto(buf: number[], fieldNum: number, wireType: number): void {
  encodeVarintInto(buf, (BigInt(fieldNum) << 3n) | BigInt(wireType));
}

function encodeBytesFieldInto(buf: number[], fieldNum: number, data: Uint8Array): void {
  if (data.length > 0) {
    encodeTagInto(buf, fieldNum, 2);
    encodeVarintInto(buf, data.length);
    for (let i = 0; i < data.length; i++) buf.push(data[i]!);
  }
}

function encodeBytesFieldAlwaysInto(buf: number[], fieldNum: number, data: Uint8Array): void {
  encodeTagInto(buf, fieldNum, 2);
  encodeVarintInto(buf, data.length);
  for (let i = 0; i < data.length; i++) buf.push(data[i]!);
}

function encodeUintFieldInto(buf: number[], fieldNum: number, v: number | bigint): void {
  if (v !== 0 && v !== 0n) {
    encodeTagInto(buf, fieldNum, 0);
    encodeVarintInto(buf, v);
  }
}

function hexToBytes(hex: string): Uint8Array {
  let clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length === 0) return new Uint8Array(0);
  // Left-pad odd-length hex with a leading '0' so callers can pass `0x0` /
  // single-nibble values (Wallet.signTransaction emits `0x0` for zero value
  // and gasPrice via its bigIntToHex helper). Mirrors utils/hex.fromHex.
  if (clean.length % 2 !== 0) {
    clean = '0' + clean;
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bigIntToHex(v: bigint | number | string | null | undefined): string {
  if (v === null || v === undefined) return '0x0';
  if (typeof v === 'bigint') return '0x' + v.toString(16);
  if (typeof v === 'number') return '0x' + (v as number).toString(16);
  return v as string;
}

export interface SdkTxParams {
  txType: number;
  nonce: number;
  from: string;
  to: string | null;
  value: string;
  gasLimit: string;
  gasPrice: string;
  data: string;
  chainId: number;
}

export function buildProtobufTransaction(
  txParams: SdkTxParams,
  signature?: Uint8Array,
  publicKey?: Uint8Array,
): Uint8Array {
  const buf: number[] = [];

  encodeUintFieldInto(buf, 1, 1); // version
  encodeUintFieldInto(buf, 2, txParams.txType);
  encodeUintFieldInto(buf, 3, txParams.nonce);

  const fromBytes = hexToBytes(txParams.from);
  if (fromBytes.length !== 20) {
    throw new Error(
      `Invalid 'from' address: expected 20 bytes, got ${fromBytes.length} (${txParams.from})`,
    );
  }
  encodeBytesFieldInto(buf, 4, fromBytes);

  if (txParams.to) {
    const toBytes = hexToBytes(txParams.to);
    if (toBytes.length !== 20) {
      throw new Error(
        `Invalid 'to' address: expected 20 bytes, got ${toBytes.length} (${txParams.to})`,
      );
    }
    encodeBytesFieldInto(buf, 5, toBytes);
  }

  const valueBytes = hexToBytes(bigIntToHex(txParams.value));
  if (valueBytes.length > 0 && !isAllZero(valueBytes)) {
    encodeBytesFieldInto(buf, 6, valueBytes);
  }

  const gasLimitVal = Number(bigIntToHex(txParams.gasLimit));
  encodeUintFieldInto(buf, 7, gasLimitVal);

  const gasPriceBytes = hexToBytes(bigIntToHex(txParams.gasPrice));
  if (gasPriceBytes.length > 0 && !isAllZero(gasPriceBytes)) {
    encodeBytesFieldInto(buf, 8, gasPriceBytes);
  }

  const dataBytes = hexToBytes(bigIntToHex(txParams.data) === '0x' ? '0x' : txParams.data);
  encodeBytesFieldInto(buf, 9, dataBytes);

  // Fields 10 and 11 are ALWAYS encoded (matching node's EncodeBytesFieldAlways).
  const sigBytes = signature ?? new Uint8Array(0);
  encodeBytesFieldAlwaysInto(buf, 10, sigBytes);
  const pubKeyBytes = publicKey ?? new Uint8Array(0);
  encodeBytesFieldAlwaysInto(buf, 11, pubKeyBytes);

  // Field 13: chain_id — ALWAYS encoded (matches node's EncodeUint64FieldAlways).
  encodeTagInto(buf, 13, 0);
  encodeVarintInto(buf, txParams.chainId);

  return new Uint8Array(buf);
}

/**
 * The signing-hash for a transaction is `sha3_256(unsignedTx)` where
 * `unsignedTx` is the Protobuf serialization with fields 10/11 set to
 * zero-length bytes. Matches `encoding.Transaction.SigningHash`.
 */
export function computeSigningHash(txParams: SdkTxParams): Uint8Array {
  const unsignedTx = buildProtobufTransaction(txParams);
  return sha3_256(unsignedTx);
}

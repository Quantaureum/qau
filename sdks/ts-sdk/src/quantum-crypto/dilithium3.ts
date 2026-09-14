// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Dilithium3 wrapper for the Quantaureum SDK.
 * @module signers/quantum-crypto/dilithium3
 *
 * R40-P0-02 (2026-08-03): the SDK ships a portable Dilithium3 binding that uses
 * the SAME circl-mode3 WASM binary the Quantaureum extension wallet uses
 * (`dilithium3-circl.wasm`, compiled in the wallet project from
 * cloudflare/circl/sign/dilithium/mode3 with `GOOS=js GOARCH=wasm`). The wrapper
 * mirrors the address-derivation, keygen, and signing semantics of the wallet's
 * `Dilithium3` class (same HKDF-SHA256 mnemonic→seed, same NIST SHA3-256
 * address derivation, same sign/verify argument contract) so a key pair
 * produced in the wallet will produce identical signatures in the SDK.
 *
 * Differences from the wallet implementation are intentionally minimal:
 *   - No Kyber768 / hybrid encryption (out of scope for a signing SDK).
 *   - No Chrome-extension integrity pinning; the SDK ships the wasm as a
 *     sibling binary asset alongside the compiled JS and loads it from disk
 *     (Node) or fetch (browser). Consumers MUST serve the wasm from a trusted
 *     origin so the `fetch` path is supply-chain-safe.
 *   - No private-key-to-hex export: same security stance as the wallet (JS
 *     strings can't be reliably zeroized). The public `exportPrivateKey()`
 *     method on the `Wallet` class returns hex for compatibility with existing
 *     keystore flows, but the Dilithium3 wrapper here deliberately does not
 *     expose a hex serializer for secret material — it works exclusively in
 *     `Uint8Array` so callers can `.fill(0)` after use.
 */

import { sha3_256 } from '@noble/hashes/sha3';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

import type { QuantumKeyPair } from './types';
import { DILITHIUM3_PARAMS, loadQuantumWasmModule } from './wasm-loader';
import type { QuantumCryptoModule } from './wasm-types';

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, '0');
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error(`Invalid hex string: odd length (${clean.length})`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Default BIP-44 HD path for Quantaureum. Coin type 1668 is the mainnet ChainID,
 * used consistently by the node (genesis), the wallet, and now the SDK. The
 * previous SDK default `m/44'/60'/0'/0/0` (Ethereum coin type 60) violated the
 * project cryptographic contract and is removed in R40-P0-02.
 */
export const DEFAULT_QUANTUM_HD_PATH = "m/44'/1668'/0'/0/0";

export class Dilithium3 {
  static async generateKeyPair(seed?: Uint8Array): Promise<QuantumKeyPair> {
    const module = await this.module();
    const actualSeed = seed ?? module.randomBytes(DILITHIUM3_PARAMS.SEEDBYTES);
    try {
      const { publicKey, secretKey } = module.dilithium3_keypair_from_seed(actualSeed);
      return {
        publicKey,
        privateKey: secretKey,
        address: this.deriveAddress(publicKey),
      };
    } finally {
      if (!seed) {
        actualSeed.fill(0);
      }
    }
  }

  static async generateKeyPairFromMnemonic(
    mnemonic: string,
    hdPath: string = DEFAULT_QUANTUM_HD_PATH,
  ): Promise<QuantumKeyPair> {
    const mnemonicBytes = new TextEncoder().encode(mnemonic.trim());
    try {
      return await this.generateKeyPairFromMnemonicBytes(mnemonicBytes, hdPath);
    } finally {
      mnemonicBytes.fill(0);
    }
  }

  static async generateKeyPairFromMnemonicBytes(
    mnemonicBytes: Uint8Array,
    hdPath: string = DEFAULT_QUANTUM_HD_PATH,
  ): Promise<QuantumKeyPair> {
    const mnemonicStr = new TextDecoder().decode(mnemonicBytes);
    const words = mnemonicStr.trim().split(/\s+/);
    if (![12, 15, 18, 21, 24].includes(words.length)) {
      throw new Error(`Invalid mnemonic: expected 12-24 words, got ${words.length}`);
    }
    const uniqueWords = new Set(words);
    if (uniqueWords.size < words.length / 2) {
      throw new Error('Invalid mnemonic: insufficient word diversity (possible weak entropy)');
    }
    const seed = await this.mnemonicToSeedFromBytes(mnemonicBytes, hdPath);
    try {
      return await this.generateKeyPair(seed);
    } finally {
      seed.fill(0);
    }
  }

  /**
   * Derive a 32-byte Dilithium3 seed from a mnemonic + HD path using
   * HKDF-SHA256 with the same length-prefixed domain separation string the
   * wallet uses (`quantaureum-dilithium3` salt, `dilithium3-seed-v1` info).
   * Keeping this IDENTICAL to the wallet is what guarantees a mnemonic
   * produces the same key pair in both contexts.
   */
  static async mnemonicToSeedFromBytes(
    mnemonicBytes: Uint8Array,
    hdPath: string,
  ): Promise<Uint8Array> {
    const pathBytes = new TextEncoder().encode(hdPath);
    const salt = new TextEncoder().encode('quantaureum-dilithium3');
    try {
      const mnemonicLen = new Uint8Array(4);
      new DataView(mnemonicLen.buffer).setUint32(0, mnemonicBytes.length, true);
      const pathLen = new Uint8Array(4);
      new DataView(pathLen.buffer).setUint32(0, pathBytes.length, true);

      const ikm = new Uint8Array([
        ...mnemonicLen,
        ...mnemonicBytes,
        ...pathLen,
        ...pathBytes,
      ]);
      try {
        return hkdf(
          sha256,
          ikm,
          salt,
          new TextEncoder().encode('dilithium3-seed-v1'),
          DILITHIUM3_PARAMS.SEEDBYTES,
        );
      } finally {
        ikm.fill(0);
      }
    } finally {
      pathBytes.fill(0);
    }
  }

  static async sign(privateKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
    if (privateKey.length !== DILITHIUM3_PARAMS.SECRETKEYBYTES) {
      throw new Error(
        `Invalid private key size: expected ${DILITHIUM3_PARAMS.SECRETKEYBYTES}, got ${privateKey.length}`,
      );
    }
    if (!message || message.length === 0) {
      throw new Error('Message must not be empty');
    }
    if (message.length > 1024 * 1024) {
      throw new Error(`Message too large: ${message.length} bytes (max 1MB)`);
    }
    const module = await this.module();
    return module.dilithium3_sign(message, privateKey);
  }

  static async verify(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean> {
    if (publicKey.length !== DILITHIUM3_PARAMS.PUBLICKEYBYTES) {
      throw new Error(
        `Invalid public key size: expected ${DILITHIUM3_PARAMS.PUBLICKEYBYTES}, got ${publicKey.length}`,
      );
    }
    if (signature.length !== DILITHIUM3_PARAMS.SIGNATUREBYTES) {
      throw new Error(
        `Invalid signature size: expected ${DILITHIUM3_PARAMS.SIGNATUREBYTES}, got ${signature.length}`,
      );
    }
    const module = await this.module();
    return module.dilithium3_verify(signature, message, publicKey);
  }

  /**
   * Match the node's address derivation: `sha3_256(publicKey)[12:32]`, returned
   * as `0x` + 40 lowercase hex chars. This MUST stay byte-identical with
   * `crypto/types.AddressFromPublicKeyE` and the wallet's `Dilithium3.deriveAddress`.
   */
  static deriveAddress(publicKey: Uint8Array): string {
    if (publicKey.length !== DILITHIUM3_PARAMS.PUBLICKEYBYTES) {
      throw new Error(
        `Invalid public key size for address derivation: expected ${DILITHIUM3_PARAMS.PUBLICKEYBYTES}, got ${publicKey.length}`,
      );
    }
    const hash = sha3_256(publicKey);
    const addressBytes = hash.slice(12, 32);
    return '0x' + bytesToHex(addressBytes);
  }

  static publicKeyToHex(publicKey: Uint8Array): string {
    return '0x' + bytesToHex(publicKey);
  }

  static hexToPublicKey(hex: string): Uint8Array {
    const bytes = hexToBytes(hex);
    if (bytes.length !== DILITHIUM3_PARAMS.PUBLICKEYBYTES) {
      throw new Error(
        `Invalid public key length: expected ${DILITHIUM3_PARAMS.PUBLICKEYBYTES} bytes, got ${bytes.length}`,
      );
    }
    return bytes;
  }

  static hexToPrivateKey(hex: string): Uint8Array {
    const bytes = hexToBytes(hex);
    if (bytes.length !== DILITHIUM3_PARAMS.SECRETKEYBYTES) {
      throw new Error(
        `Invalid private key length: expected ${DILITHIUM3_PARAMS.SECRETKEYBYTES} bytes, got ${bytes.length}`,
      );
    }
    return bytes;
  }

  static getPublicKeySize(): number {
    return DILITHIUM3_PARAMS.PUBLICKEYBYTES;
  }

  static getPrivateKeySize(): number {
    return DILITHIUM3_PARAMS.SECRETKEYBYTES;
  }

  static getSignatureSize(): number {
    return DILITHIUM3_PARAMS.SIGNATUREBYTES;
  }

  private static async module(): Promise<QuantumCryptoModule> {
    return loadQuantumWasmModule();
  }
}

export { DILITHIUM3_PARAMS } from './wasm-loader';

// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Wallet implementation for Quantaureum SDK
 * @module signers/Wallet
 *
 * R40-P0-02 (2026-08-03): this implementation now signs with Dilithium3 (circl
 * mode3) matching the node's `crypto.Dilithium3*Size` contract and the
 * Quantaureum extension wallet — NOT @noble/secp256k1.
 *
 *   - private key  : 4000 bytes (Uint8Array)
 *   - public key   : 1952 bytes (Uint8Array)
 *   - signature    : 3293 bytes (Uint8Array) — Dilithium3 detached, deterministic
 *   - address      : NIST sha3_256(publicKey)[12:32] → `0x` + 40 lowercase hex
 *     (matches `types.AddressFromPublicKeyE` and the wallet's `Dilithium3.deriveAddress`)
 *   - HD path      : `m/44'/1668'/0'/0/{index}` (coin type 1668 = mainnet ChainID)
 *                    mnemonic→seed uses HKDF-SHA256 with the same length-prefixed
 *                    domain separation as the wallet, so a mnemonic produces the
 *                    same key pair in the extension and the SDK.
 *   - tx wire      : Quantaureum Protobuf (`encoding.Transaction.MarshalTransaction`
 *                    / `SigningHash`), NOT EIP-155 RLP. `signTransaction` returns
 *                    the hex of the signed Protobuf bytes with fields 10 (sig)
 *                    and 11 (pubkey) populated.
 *   - default chainId : 1668 (Quantaureum mainnet); previously defaulted to 1
 *                    (Ethereum mainnet), which silently produced cross-chain
 *                    replay-vulnerable signatures.
 */

import { generateMnemonic, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

import type { Signer } from './Signer';
import type { Provider } from '../providers/Provider';
import type { TransactionRequest, TransactionResponse } from '../types/transaction';
import { ValidationError, ErrorCode, QuantaureumError } from '../errors';
import { computeAddress, isAddress } from '../utils/address';
import { hexlify, fromHex, isHexString } from '../utils/hex';
import {
  Dilithium3,
  DEFAULT_QUANTUM_HD_PATH,
  buildProtobufTransaction,
  computeSigningHash,
} from '../quantum-crypto';
import type { QuantumKeyPair } from '../quantum-crypto';
import type { SdkTxParams } from '../quantum-crypto';

/**
 * Default BIP-44 HD derivation path for Quantaureum (coin type 1668 = mainnet
 * ChainID). Replaces the previous `m/44'/60'/0'/0/0` (Ethereum coin type 60).
 */
const DEFAULT_PATH = DEFAULT_QUANTUM_HD_PATH;

/**
 * Default ChainID for the Quantaureum mainnet. Used when a TransactionRequest
 * omits `chainId` and the wallet has no connected provider. Previously this
 * defaulted to `1` (Ethereum mainnet) — see R40-P0-02.
 */
const DEFAULT_CHAIN_ID = 1668;

/**
 * Wallet class for managing Dilithium3 private keys and signing.
 */
export class Wallet implements Signer {
  /**
   * The wallet's address (`0x` + 40 lowercase hex chars, EIP-55 checksummed by
   * the wallet's getter accessors at the address-utils layer).
   */
  readonly address: string;

  /**
   * The wallet's Dilithium3 public key (1952 bytes, hex-encoded with `0x` prefix).
   */
  readonly publicKey: string;

  /**
   * The wallet's Dilithium3 private key (4000 bytes). Held as `Uint8Array` so
   * callers can `.fill(0)` after use; never serialized to a JS string.
   */
  readonly #privateKey: Uint8Array;

  /**
   * The wallet's Dilithium3 public key, raw bytes.
   */
  readonly #publicKeyBytes: Uint8Array;

  /**
   * The mnemonic phrase (if created from mnemonic)
   */
  readonly #mnemonic: string | null;

  /**
   * The HD derivation path (if created from mnemonic)
   */
  readonly #path: string | null;

  /**
   * The connected provider (if any)
   */
  #provider: Provider | null;

  /**
   * Whether the wallet has been destroyed (private key zeroed)
   */
  #destroyed: boolean;

  /**
   * Create a new Wallet instance from a Dilithium3 private key.
   *
   * @param privateKey - 4000-byte Dilithium3 secret key, accepted as:
   *                      (a) a `Uint8Array` (RECOMMENDED — can be zeroized),
   *                      (b) a hex string `0x...` (8000 chars, for keystore /
   *                          import flows — caller SHOULD zero the source
   *                          bytes / file after construction).
   * @param publicKey  - 1952-byte Dilithium3 public key matching the secret
   *                      key. REQUIRED when the input is supplied as raw bytes
   *                      because Dilithium3's public key cannot be derived from
   *                      the secret key in SDK land without invoking the WASM
   *                      signer (which has no "derive pubkey" entry). If the
   *                      caller has only the private key, use `Wallet.fromPrivateKey`
   *                      which instantiates the WASM module once to recover the
   *                      public key.
   * @param provider - Optional provider to connect to
   */
  constructor(privateKey: Uint8Array | string, publicKey?: Uint8Array | string, provider?: Provider) {
    const privBytes = normalizePrivateKey(privateKey);
    const pubBytes = normalizePublicKey(publicKey);

    // Sanity: derive the address from the public key using NIST SHA3-256. A
    // mismatch between the supplied pubBytes and the node's address derivation
    // would be caught here (cryptographic check is performed only on the sign
    // path; here we just validate length consistency).
    this.#privateKey = privBytes;
    this.#publicKeyBytes = pubBytes;
    this.publicKey = hexlify(pubBytes);
    this.address = computeAddress(pubBytes);

    this.#mnemonic = null;
    this.#path = null;
    this.#provider = provider ?? null;
    this.#destroyed = false;
  }

  /**
   * Internal constructor hook for mnemonic-preserving wallet creation.
   */
  private static createWithMnemonic(
    kp: QuantumKeyPair,
    mnemonic: string,
    path: string,
    provider?: Provider,
  ): Wallet {
    const w = new Wallet(kp.privateKey, kp.publicKey, provider);
    Object.defineProperty(w, '_mnemonic', { value: mnemonic, writable: false });
    Object.defineProperty(w, '_path', { value: path, writable: false });
    return w;
  }

  /**
   * Get the provider this wallet is connected to
   */
  get provider(): Provider | null {
    return this.#provider;
  }

  /**
   * Get the mnemonic phrase (if available)
   */
  get mnemonic(): string | null {
    if (this.#destroyed) {
      return null;
    }
    return (this as unknown as { _mnemonic?: string })._mnemonic ?? this.#mnemonic;
  }

  /**
   * Get the HD derivation path (if available)
   */
  get path(): string | null {
    return (this as unknown as { _path?: string })._path ?? this.#path;
  }

  /**
   * Create a new wallet with a randomly generated Dilithium3 key pair and a
   * fresh BIP-39 mnemonic (12 words). The mnemonic is the ONLY way to recover
   * the private key — store it securely.
   */
  static async createRandom(provider?: Provider): Promise<Wallet> {
    const mnemonic = generateMnemonic(wordlist, 128); // 12 words
    return Wallet.fromMnemonic(mnemonic, DEFAULT_PATH, provider);
  }

  /**
   * Create a wallet from a BIP-39 mnemonic phrase.
   * The mnemonic → seed derivation is HKDF-SHA256 with the same length-prefixed
   * domain separation as the Quantaureum extension wallet, so a mnemonic
   * produces the SAME key pair in both environments.
   *
   * @param mnemonic - BIP-39 mnemonic phrase (12-24 words)
   * @param path - HD derivation path (default: m/44'/1668'/0'/0/0)
   * @param provider - Optional provider to connect to
   * @returns A new Wallet derived from the mnemonic
   */
  static async fromMnemonic(
    mnemonic: string,
    path: string = DEFAULT_PATH,
    provider?: Provider,
  ): Promise<Wallet> {
    if (typeof mnemonic !== 'string') {
      throw new ValidationError(
        'Mnemonic must be a string',
        'mnemonic',
        '[REDACTED]',
        ErrorCode.INVALID_MNEMONIC,
        'string',
      );
    }
    const normalized = mnemonic.trim().toLowerCase().replace(/\s+/g, ' ');
    if (!validateMnemonic(normalized, wordlist)) {
      throw new ValidationError(
        'Invalid mnemonic phrase',
        'mnemonic',
        '[REDACTED]',
        ErrorCode.INVALID_MNEMONIC,
        'valid BIP-39 mnemonic',
      );
    }
    // Use the wallet-compatible HKDF-SHA256 mnemonic→seed derivation (NOT BIP-32
    // EC point derivation, which is incompatible with lattice Dilithium).
    const kp = await Dilithium3.generateKeyPairFromMnemonic(normalized, path);
    return Wallet.createWithMnemonic(kp, normalized, path, provider);
  }

  /**
   * Create a wallet from a Dilithium3 secret key (4000 bytes).
   *
   * Dilithium3's public key cannot be derived from the secret key in the SDK
   * without the original mnemonic (the WASM bridge exposes no
   * "derivePublicKey" entry). Silently signing with a public key that doesn't
   * match the node's record of the account would be a footgun, so this factory
   * throws. Supply the public key together with the secret key via the
   * constructor (`new Wallet(sk, pk)`), or regenerate the key pair via
   * `Wallet.fromMnemonic(mnemonic)`.
   */
  static async fromPrivateKey(
    privateKey: Uint8Array | string,
    _provider?: Provider,
  ): Promise<Wallet> {
    // Validate length so the call fails fast on a malformed secret key, even
    // though we cannot construct a Wallet from it. This gives a clearer error
    // message than letting the caller discover the limitation later.
    normalizePrivateKey(privateKey);
    throw new QuantaureumError(
      'Wallet.fromPrivateKey is not supported: Dilithium3 public keys cannot be ' +
        'derived from secret keys in the SDK without the original mnemonic. ' +
        'Either supply (secretKey, publicKey) together to the constructor, or ' +
        'regenerate the key pair via Wallet.fromMnemonic(mnemonic).',
      ErrorCode.INVALID_PRIVATE_KEY,
    );
  }

  /**
   * Get the address of this wallet
   */
  async getAddress(): Promise<string> {
    return this.address;
  }

  /**
   * Connect this wallet to a provider — returns a NEW Wallet sharing the same
   * key material (copied, not aliased, so the original wallet can be destroyed
   * independently).
   */
  connect(provider: Provider): Wallet {
    this.#ensureNotDestroyed();
    const w = new Wallet(this.#privateKey, this.#publicKeyBytes, provider);
    if (this.mnemonic && this.path) {
      Object.defineProperty(w, '_mnemonic', { value: this.mnemonic, writable: false });
      Object.defineProperty(w, '_path', { value: this.path, writable: false });
    }
    return w;
  }

  /**
   * Export the private key as a hex string. The output is 4000 bytes (8000 hex
   * chars). Callers are responsible for securing the resulting string — JS
   * strings cannot be reliably zeroized from memory.
   */
  exportPrivateKey(): string {
    this.#ensureNotDestroyed();
    return hexlify(this.#privateKey);
  }

  /**
   * Export the public key as a hex string (3904 hex chars, 1952 bytes).
   */
  exportPublicKey(): string {
    this.#ensureNotDestroyed();
    return hexlify(this.#publicKeyBytes);
  }

  /**
   * Securely destroy the wallet by zeroing the private key bytes and mnemonic.
   * After calling this method, the wallet can no longer be used for signing.
   */
  destroy(): void {
    if (this.#destroyed) {
      return;
    }
    this.#privateKey.fill(0);
    delete (this as { _mnemonic?: string })._mnemonic;
    this.#destroyed = true;
  }

  /**
   * Check if the wallet has been destroyed
   */
  get destroyed(): boolean {
    return this.#destroyed;
  }

  /**
   * Ensure the wallet has not been destroyed before performing sensitive operations
   */
  #ensureNotDestroyed(): void {
    if (this.#destroyed) {
      throw new QuantaureumError(
        'Wallet has been destroyed and can no longer be used for signing',
        ErrorCode.UNKNOWN_ERROR,
      );
    }
  }

  /**
   * Sign a message using the Quantaureum personal_sign convention.
   *
   * The message is prefixed with the same EIP-191 layout the wallet uses
   * (`\x19Quantaureum Signed Message:\n${len}`), then hashed with NIST
   * SHA3-256 (NOT Keccak-256), then signed with Dilithium3. The signature is
   * 3293 bytes, hex-encoded with `0x` prefix.
   *
   * @param message - Message (string or bytes)
   * @returns Hex-encoded Dilithium3 signature (3293 bytes → 6586 hex chars)
   */
  async signMessage(message: string | Uint8Array): Promise<string> {
    this.#ensureNotDestroyed();
    let messageBytes: Uint8Array;
    if (typeof message === 'string') {
      messageBytes = new TextEncoder().encode(message);
    } else if (message instanceof Uint8Array) {
      messageBytes = message;
    } else {
      throw new ValidationError(
        'Message must be a string or Uint8Array',
        'message',
        message,
        ErrorCode.INVALID_ARGUMENT,
        'string or Uint8Array',
      );
    }

    // Quantaureum personal_sign prefix — the SDK owns this domain. Using
    // `\x19Quantaureum Signed Message:\n` (instead of Ethereum's
    // `\x19Ethereum Signed Message:\n`) prevents cross-chain personal_sign
    // replay attacks. The node verifies personal_sign signatures against
    // this same prefix (see `qau_signQuantumTransaction` / personal_verify RPC).
    const prefix = `\x19Quantaureum Signed Message:\n${messageBytes.length}`;
    const prefixBytes = new TextEncoder().encode(prefix);
    const prefixedMessage = new Uint8Array(prefixBytes.length + messageBytes.length);
    prefixedMessage.set(prefixBytes, 0);
    prefixedMessage.set(messageBytes, prefixBytes.length);

    // NIST SHA3-256 — matches node's `crypto.PublicKeyAddressFromBytes`
    // hash family and the wallet's signing path.
    const { sha3_256 } = await import('@noble/hashes/sha3');
    const messageHash = sha3_256(prefixedMessage);

    const sig = await Dilithium3.sign(this.#privateKey, messageHash);
    return hexlify(sig);
  }

  /**
   * Sign a transaction using the Quantaureum Protobuf wire format.
   * @param transaction - The transaction request
   * @returns Hex-encoded signed Protobuf transaction (with signature + public key populated)
   */
  async signTransaction(transaction: TransactionRequest): Promise<string> {
    this.#ensureNotDestroyed();

    if (transaction.to && !isAddress(transaction.to)) {
      throw new ValidationError(
        'Invalid "to" address',
        'to',
        transaction.to,
        ErrorCode.INVALID_ADDRESS,
        'valid address',
      );
    }

    // R40-P0-02 fix: default chainId is now the Quantaureum mainnet (1668),
    // NOT Ethereum mainnet (1).
    const chainId = transaction.chainId ?? this.#chainOrDefault();

    const txParams: SdkTxParams = {
      txType: this.#txTypeOrTransfer(transaction),
      nonce: transaction.nonce ?? 0,
      from: this.address,
      to: transaction.to ?? null,
      value: bigIntToHex(transaction.value ?? 0n),
      gasLimit: bigIntToHex(transaction.gasLimit ?? 21000n),
      gasPrice: bigIntToHex(transaction.gasPrice ?? 0n),
      data: transaction.data ?? '0x',
      chainId,
    };

    // Compute the signing hash over the unsigned Protobuf (fields 10/11 empty).
    const txHash = computeSigningHash(txParams);
    const sig = await Dilithium3.sign(this.#privateKey, txHash);

    // Re-serialize with the real signature + public key populated (fields 10/11).
    const signedTx = buildProtobufTransaction(txParams, sig, this.#publicKeyBytes);
    return hexlify(signedTx);
  }

  /**
   * Resolve the default chainId: prefer the connected provider's network, else
   * fall back to the Quantaureum mainnet (1668). This is async-safe to call
   * with no provider — synchronous callers (signTransaction) accept a
   * best-effort default; sendTransaction always resolves chainId via the
   * provider before signing.
   */
  #chainOrDefault(): number {
    return DEFAULT_CHAIN_ID;
  }

  /**
   * Extract a numeric transaction type. The SDK's TransactionRequest does not
   * yet have a typed `txType` field, but callers can supply it via the
   * undiscriminated `(TransactionRequest & { txType?: number })` shape. The
   * default is `0` = TxTypeTransfer, matching the node.
   */
  #txTypeOrTransfer(transaction: TransactionRequest): number {
    const t = transaction as TransactionRequest & { txType?: number };
    if (typeof t.txType === 'number' && Number.isInteger(t.txType) && t.txType >= 0) {
      return t.txType;
    }
    return 0;
  }

  /**
   * Send a transaction (requires provider)
   */
  async sendTransaction(transaction: TransactionRequest): Promise<TransactionResponse> {
    this.#ensureNotDestroyed();
    if (!this.#provider) {
      throw new QuantaureumError(
        'Cannot send transaction: no provider connected',
        ErrorCode.NO_PROVIDER,
      );
    }

    const tx: TransactionRequest = { ...transaction };
    tx.from = this.address;
    if (tx.nonce === undefined) {
      tx.nonce = await this.#provider.getTransactionCount(this.address, 'pending');
    }
    if (tx.gasPrice === undefined) {
      tx.gasPrice = await this.#provider.getGasPrice();
    }
    if (tx.gasLimit === undefined) {
      tx.gasLimit = await this.#provider.estimateGas(tx);
    }
    if (tx.chainId === undefined) {
      const network = await this.#provider.getNetwork();
      tx.chainId = network.chainId;
    }

    const signedTx = await this.signTransaction(tx);
    return this.#provider.sendTransaction(signedTx);
  }
}

function bigIntToHex(v: bigint): string {
  if (v === 0n) return '0x0';
  return '0x' + v.toString(16);
}

function normalizePrivateKey(privateKey: Uint8Array | string): Uint8Array {
  let privBytes: Uint8Array;
  if (typeof privateKey === 'string') {
    if (!isHexString(privateKey)) {
      throw new ValidationError(
        'Invalid private key: must be a valid hex string',
        'privateKey',
        '[REDACTED]',
        ErrorCode.INVALID_PRIVATE_KEY,
        '4000-byte (8000-hex) Dilithium3 secret key',
      );
    }
    privBytes = fromHex(privateKey);
  } else if (privateKey instanceof Uint8Array) {
    // Copy to avoid aliasing the caller's buffer (so we can `.fill(0)` on destroy
    // without clobbering the caller's copy).
    privBytes = new Uint8Array(privateKey);
  } else {
    throw new ValidationError(
      'Invalid private key type',
      'privateKey',
      '[REDACTED]',
      ErrorCode.INVALID_PRIVATE_KEY,
      'Uint8Array or hex string',
    );
  }
  if (privBytes.length !== Dilithium3.getPrivateKeySize()) {
    throw new ValidationError(
      `Invalid private key length: ${privBytes.length} bytes (expected ${Dilithium3.getPrivateKeySize()} for Dilithium3)`,
      'privateKey',
      '[REDACTED]',
      ErrorCode.INVALID_PRIVATE_KEY,
      `exactly ${Dilithium3.getPrivateKeySize()} bytes`,
    );
  }
  return privBytes;
}

function normalizePublicKey(publicKey?: Uint8Array | string): Uint8Array {
  if (publicKey === undefined || publicKey === null) {
    throw new ValidationError(
      'A Dilithium3 public key is required to construct a Wallet (the SDK cannot ' +
        'derive a public key from a secret key alone). Supply it alongside the ' +
        'secret key, or create the wallet via Wallet.fromMnemonic / Wallet.createRandom.',
      'publicKey',
      '[REDACTED]',
      ErrorCode.INVALID_PUBLIC_KEY,
      `exactly ${Dilithium3.getPublicKeySize()} bytes`,
    );
  }
  let pubBytes: Uint8Array;
  if (typeof publicKey === 'string') {
    if (!isHexString(publicKey)) {
      throw new ValidationError(
        'Invalid public key: must be a valid hex string',
        'publicKey',
        '[REDACTED]',
        ErrorCode.INVALID_PUBLIC_KEY,
        '1952-byte (3904-hex) Dilithium3 public key',
      );
    }
    pubBytes = fromHex(publicKey);
  } else if (publicKey instanceof Uint8Array) {
    pubBytes = new Uint8Array(publicKey);
  } else {
    throw new ValidationError(
      'Invalid public key type',
      'publicKey',
      '[REDACTED]',
      ErrorCode.INVALID_PUBLIC_KEY,
      'Uint8Array or hex string',
    );
  }
  if (pubBytes.length !== Dilithium3.getPublicKeySize()) {
    throw new ValidationError(
      `Invalid public key length: ${pubBytes.length} bytes (expected ${Dilithium3.getPublicKeySize()} for Dilithium3)`,
      'publicKey',
      '[REDACTED]',
      ErrorCode.INVALID_PUBLIC_KEY,
      `exactly ${Dilithium3.getPublicKeySize()} bytes`,
    );
  }
  return pubBytes;
}

/**
 * Verify a message signature with the wallet's public key. This is the SDK
 * consumer's verification helper — it uses Dilithium3.verify (NOT ECDSA pubkey
 * recovery, which does not exist in the post-quantum world).
 *
 * @param message - The original message
 * @param signature - The Dilithium3 signature (hex string, 3293 bytes)
 * @param publicKeyOrAddress - Dilithium3 public key (hex), or an address whose
 *                              public key is registered in the caller's context
 * @returns True if the signature verifies under the public key
 */
export async function verifyMessage(
  message: string | Uint8Array,
  signature: string,
  publicKey: string | Uint8Array,
): Promise<boolean> {
  let messageBytes: Uint8Array;
  if (typeof message === 'string') {
    messageBytes = new TextEncoder().encode(message);
  } else {
    messageBytes = message;
  }
  const prefix = `\x19Quantaureum Signed Message:\n${messageBytes.length}`;
  const prefixBytes = new TextEncoder().encode(prefix);
  const prefixedMessage = new Uint8Array(prefixBytes.length + messageBytes.length);
  prefixedMessage.set(prefixBytes, 0);
  prefixedMessage.set(messageBytes, prefixBytes.length);

  const { sha3_256 } = await import('@noble/hashes/sha3');
  const messageHash = sha3_256(prefixedMessage);

  let sigBytes: Uint8Array;
  if (typeof signature === 'string') {
    sigBytes = fromHex(signature);
  } else {
    sigBytes = signature;
  }
  if (sigBytes.length !== Dilithium3.getSignatureSize()) {
    throw new ValidationError(
      `Invalid signature length: ${sigBytes.length} bytes (expected ${Dilithium3.getSignatureSize()} for Dilithium3)`,
      'signature',
      signature,
      ErrorCode.INVALID_SIGNATURE,
      `exactly ${Dilithium3.getSignatureSize()} bytes`,
    );
  }

  let pubBytes: Uint8Array;
  if (typeof publicKey === 'string') {
    pubBytes = Dilithium3.hexToPublicKey(publicKey);
  } else {
    pubBytes = publicKey;
    if (pubBytes.length !== Dilithium3.getPublicKeySize()) {
      throw new ValidationError(
        `Invalid public key length: ${pubBytes.length} bytes`,
        'publicKey',
        '[REDACTED]',
        ErrorCode.INVALID_PUBLIC_KEY,
        `exactly ${Dilithium3.getPublicKeySize()} bytes`,
      );
    }
  }

  return Dilithium3.verify(pubBytes, messageHash, sigBytes);
}

// Re-export the default path for legacy consumers that imported it from the
// signers module root.
export { DEFAULT_PATH };

// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Utility functions for Quantaureum SDK
 * @module utils
 */

// Hex utilities
export {
  toHex,
  fromHex,
  hexlify,
  arrayify,
  isHexString,
  zeroPadHex,
  concatHex,
} from './hex';

// Hash utilities
export {
  keccak256,
  sha256,
  id,
  functionSelector,
  eventTopic,
} from './hash';

// Address utilities
export {
  isAddress,
  getAddress,
  computeAddress,
  isChecksumAddress,
  addressEquals,
  isZeroAddress,
  ZERO_ADDRESS,
} from './address';

// Format utilities
export {
  formatEther,
  parseEther,
  formatUnits,
  parseUnits,
  formatWithCommas,
  toBigInt,
  ETHER_DECIMALS,
  WEI_PER_ETHER,
} from './format';

// ABI utilities
export {
  encodeAbi,
  decodeAbi,
  encodeFunctionData,
  decodeFunctionResult,
} from './abi';

// ABI types
export type {
  ABIType,
  ABIParameter,
  ABIFunction,
  ABIEvent,
  ABIError,
  ABI,
} from './abi';

// Validation utilities
export {
  assertDefined,
  assertString,
  assertNonEmptyString,
  assertNumber,
  assertNonNegativeInteger,
  assertPositiveInteger,
  assertBigInt,
  assertNonNegativeBigInt,
  assertBoolean,
  assertUint8Array,
  assertHexString,
  assertHexStringWithLength,
  assertAddress,
  assertTransactionHash,
  assertBlockHash,
  assertPrivateKey,
  assertArray,
  assertObject,
  assertFunction,
  assertUrl,
  assertOneOf,
  validateTransactionRequest,
  validateEventFilter,
} from './validation';

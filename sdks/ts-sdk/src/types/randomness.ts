// Quantaureum TypeScript SDK source, version 1.0.0.
// Per-epoch verifiable randomness (qau_randomness* RPC) type definitions.

/**
 * One epoch's verifiable randomness as served by the node's
 * `qau_randomnessGet` / `qau_randomnessLatest` RPC methods.
 *
 * `randomness` is the per-epoch VRF accumulator recorded on the epoch
 * boundary block header — publicly verifiable against block data, NOT a
 * hardware quantum RNG output.
 */
export interface RandomnessRecord {
  /** Epoch the randomness belongs to (decimal number). */
  epoch: number;
  /** The VRF accumulator — the canonical randomness value (0x hex, 32 bytes). */
  randomness: string;
  /** Height of the epoch's boundary (last) block, `epoch*32 + 31` (0x hex). */
  boundaryBlock: string;
  /** Hash of the boundary block (0x hex). */
  blockHash: string;
  /**
   * true only when the epoch is finalized (irreversible). A sealed but
   * not-yet-finalized epoch can still change on a reorg.
   */
  finalized: boolean;
  /** Data source label; always "vrf-accumulator". */
  source: string;
}

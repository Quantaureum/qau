// Quantaureum TypeScript SDK source, version 1.0.0.
// Unit tests for the qau_randomness* provider methods (send is mocked).

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { JsonRpcProvider } from './JsonRpcProvider';
import type { RandomnessRecord } from '../types';

const sample: RandomnessRecord = {
  epoch: 18420,
  randomness: '0xa3f9c1',
  boundaryBlock: '0x8f8bf',
  blockHash: '0x77e5',
  finalized: true,
  source: 'vrf-accumulator',
};

describe('JsonRpcProvider randomness methods', () => {
  let provider: JsonRpcProvider;
  let sendMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    provider = new JsonRpcProvider('http://127.0.0.1:8545');
    sendMock = vi.spyOn(provider, 'send').mockResolvedValue(sample);
  });

  it('getEpochRandomness calls qau_randomnessGet with the epoch param', async () => {
    const rec = await provider.getEpochRandomness(18420);
    expect(sendMock).toHaveBeenCalledWith('qau_randomnessGet', [{ epoch: 18420 }]);
    expect(rec).toEqual(sample);
  });

  it('getEpochRandomness accepts a numeric string epoch', async () => {
    await provider.getEpochRandomness('18420');
    expect(sendMock).toHaveBeenCalledWith('qau_randomnessGet', [{ epoch: '18420' }]);
  });

  it('getLatestRandomness calls qau_randomnessLatest without params', async () => {
    const rec = await provider.getLatestRandomness();
    expect(sendMock).toHaveBeenCalledWith('qau_randomnessLatest', []);
    expect(rec.finalized).toBe(true);
  });

  it('propagates JSON-RPC errors (pre-finality -32000)', async () => {
    sendMock.mockRejectedValue(new Error('no finalized epoch yet'));
    await expect(provider.getLatestRandomness()).rejects.toThrow('no finalized epoch yet');
  });
});

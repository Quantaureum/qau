# 14 - RPC Method Full Table

> Summarizes all JSON-RPC methods exposed by the Quantaureum node. Naming convention:
> standard methods use `eth_*`, specific methods use `qau_*`.
> The wallet whitelist (`QUANTAUREUM_RPC_METHOD_WHITELIST`)must stay in sync with this table.

## 14.1 Blocks

| Method | Description |
|------|------|
| `eth_blockNumber` | latest block number |
| `eth_getBlockByNumber` | get a block by number |
| `eth_getBlockByHash` | get a block by hash |
| `eth_getBlockTransactionCountByNumber` | number of transactions in a block (by number) |
| `eth_getBlockTransactionCountByHash` | number of transactions in a block (by hash) |
| `eth_getTransactionByBlockHashAndIndex` | get a transaction by block hash + index |
| `eth_getTransactionByBlockNumberAndIndex` | get a transaction by block number + index |

## 14.2 Accounts

| Method | Description |
|------|------|
| `eth_getBalance` | balance |
| `eth_getTransactionCount` | nonce |
| `eth_getCode` | contract code |
| `eth_getStorageAt` | storage slot |
| `eth_getProof` | state proof |

## 14.3 Transactions

| Method | Description |
|------|------|
| `eth_sendRawTransaction` | submit a pre-signed transaction |
| `eth_sendTransaction` | node-sign and submit (large amounts require commit-reveal) |
| `eth_getTransactionByHash` | get a transaction by hash |
| `eth_getTransactionReceipt` | transaction receipt |
| `eth_getLogs` | logs |
| `eth_pendingTransactions` | pending transactions |

## 14.4 Gas

| Method | Description |
|------|------|
| `eth_gasPrice` | current gas price |
| `eth_estimateGas` | estimate gas |
| `eth_maxPriorityFeePerGas` | EIP-1559 priority fee |
| `eth_feeHistory` | fee history |
| `eth_createAccessList` | generate access list |

## 14.5 Calls

| Method | Description |
|------|------|
| `eth_call` | read-only call |
| `eth_chainId` | chain ID |
| `eth_protocolVersion` | protocol version |
| `eth_syncing` | sync status |
| `eth_coinbase` / `eth_mining` / `eth_hashrate` | mining-related (compatibility placeholders) |

## 14.6 Filters

| Method | Description |
|------|------|
| `eth_newFilter` / `eth_newBlockFilter` / `eth_newPendingTransactionFilter` | create a filter |
| `eth_uninstallFilter` | remove a filter |
| `eth_getFilterChanges` / `eth_getFilterLogs` | pull filter results |

## 14.7 Subscriptions (WS)

| Method | Description |
|------|------|
| `eth_subscribe` / `eth_unsubscribe` | subscribe/unsubscribe |

## 14.8 Signing (Typed Data / compatibility)

| Method | Description |
|------|------|
| `eth_sign` | sign a message |
| `eth_signTypedData` / `_v1` / `_v3` / `_v4` | structured-data signing |

## 14.9 Account Abstraction (ERC-4337)

| Method | Description |
|------|------|
| `eth_sendUserOperation` | submit a UserOperation |
| `eth_estimateUserOperationGas` | estimate |
| `eth_getUserOperationByHash` / `eth_getUserOperationReceipt` | query |
| `eth_supportedEntryPoints` | list of EntryPoints |
| `qau_sendUserOperation` / `qau_estimateUserOperationGas` / `qau_getUserOperationByHash` / `qau_getUserOperationReceipt` / `qau_supportedEntryPoints` | **qau_ aliases** (backward compatible) |

## 14.10 Staking / Economics (qau_)

| Method | Description |
|------|------|
| `qau_qposStatus` | QPOS status |
| `qau_getStake` | staking information |
| `qau_getStakingPools` / `qau_getStakingStats` | staking pools/stats |
| `qau_getUserStakes` | user stakes |
| `qau_getPendingRewards` | pending rewards |
| `qau_getStakingContracts` | staking contracts |
| `qau_stake` / `qau_unstake` | stake/unstake |
| `qau_claimRewards` / `qau_compoundRewards` | claim/compound |
| `qau_getUnstakeStatus` / `qau_getContractBalance` | unstake status/contract balance |

## 14.11 Multisig (qau_)

| Method | Description |
|------|------|
| `qau_registerMultisigWallet` | register a multisig wallet |
| `qau_createMultisigProposal` | create a proposal |
| `qau_approveMultisigProposal` | approve |
| `qau_executeMultisigProposal` | execute |
| `qau_getMultisigWallet` / `qau_isMultisigWallet` | query |
| `qau_getPendingMultisigProposals` / `qau_getMultisigProposal` / `qau_getAllMultisigProposals` / `qau_getProposalsForSigner` | proposal queries |

## 14.12 DeFi (qau_)

| Method | Description |
|------|------|
| `qau_getLiquidityPools` / `qau_getLiquidityPool` | liquidity pools |
| `qau_getSwapQuote` / `qau_swap` | quote/swap |
| `qau_getUserLPBalance` / `qau_addLiquidity` / `qau_removeLiquidity` | LP operations |
| `qau_getLendingPools` / `qau_getLendingPool` / `qau_getUserLendingPosition` | lending |
| `qau_supply` / `qau_withdraw` / `qau_borrow` / `qau_repay` | lending operations |
| `qau_getYieldFarms` / `qau_getYieldFarm` / `qau_getFarmPendingReward` / `qau_getUserFarmStake` / `qau_stakeFarm` / `qau_unstakeFarm` / `qau_harvestFarm` | yield farms |

## 14.13 TSS / QTD (qau_tss_*)

| Method | Admin | Description |
|------|-------|------|
| `qau_tss_status` | — | threshold status (read-only) |
| `qau_tss_getPublicKey` | — | threshold public key (read-only) |
| `qau_tss_generateKeyShares` | ✔ | generate shares (DKG) |
| `qau_tss_getShare` | ✔ | export shares (only dev network) |
| `qau_tss_signMessage` | ✔ | threshold signing |
| `qau_tss_verifySignature` | ✔ | signature verification |
| `qau_tss_getSealStatus` | — | seal status (read-only) |
| `qau_tss_requestSeal` | ✔ | request a seal (admin) |
| `qau_tss_submitPartialSeal` | ✔ | submit a partial seal (admin) |

## 14.14 Quantum Signing / Privacy (qau_)

| Method | Description |
|------|------|
| `qau_signQuantumTransaction` | node signing (**disabled at compile time by default**; use client-side signing) |
| `qau_verifyQuantumTransaction` | signature verification |
| `qau_sendPrivacyTransaction` / `qau_scanPrivacy` / `qau_getPrivacyBalance` | privacy transactions |
| `qau_generateStealthAddress` | Stealth address |

## 14.15 Front-Running Protection (commit-reveal)

| Method | Description |
|------|------|
| `qau_submitCommitment` | submit a commitment (prerequisite for large transfers) |

## 14.16 Sharding / Rollup / Bridge / DA / Builder / DKG

| Method | Description |
|------|------|
| `qau_shardGetShardCount` / `qau_shardGetActiveShardCount` / `qau_shardGetShard` / `qau_shardGetBlock` / `qau_shardGetCommitment` / `qau_shardGetReceipt` / `qau_shardIsReceiptSpent` | shard queries |
| `qau_shardSubmitCrossShardMessage` | cross-shard messages (admin) |
| `qau_rollupGetStatus` / `qau_rollupGetBatch` / `qau_rollupGetStateRoot` / `qau_rollupSendRawTransaction` / `qau_rollupGetAnchor` | Rollup L2 |
| `qau_l1BridgeGetStatus` / `qau_l1BridgeGetLiquidity` / `qau_l1BridgeGetDeposit` / `qau_l1BridgeGetFinalizedStateRoot` / `qau_l1BridgeGetContractBytecode` / `qau_l1BridgeEncodeRecordFinalizedBatch` | L1↔L2 bridge |
| `qau_getBlobBaseFee` / `qau_getBlobSidecar` / `qau_sendBlobTransaction` | DA blobs |
| `qau_builder_submitBid` / `qau_builder_getSlotInfo` / `qau_builder_getWinningBid` | block auctions |
| `qau_stardust_getDKGStatus` | DKG monitoring (read-only) |

## 14.17 Network / Web3 / Tx Pool / Admin / Local Accounts

| Method | Description |
|------|------|
| `net_version` / `net_peerCount` / `net_listening` | network |
| `web3_clientVersion` / `web3_sha3` | Web3 |
| `txpool_status` / `txpool_content` / `txpool_inspect` | transaction pool |
| `admin_peers` / `admin_nodeInfo` / `admin_mint` | admin (HMAC) |
| `personal_newAccount` / `personal_listAccounts` / `personal_unlockAccount` / `personal_lockAccount` / `personal_sendTransaction` / `personal_sign` / `personal_importRawKey` | local accounts |
| `debug_traceTransaction` / `debug_traceCall` / `debug_traceBlockByNumber` / `debug_traceBlockByHash` | debugging |

## 14.18 New RPC Specification

1. **Standard vs. specific**: standard → `eth_*`; specific → `qau_*`.
2. Implement the method signature: `func (api *X) Method(ctx context.Context, params json.RawMessage) (any, *Error)`.
3. Register: `server.RegisterHandler("method", api.X)`; for admin methods additionally `RegisterAdminMethod`.
4. **Synchronously update the wallet whitelist** (`QUANTAUREUM_RPC_METHOD_WHITELIST` in `network-controller-init.ts`).
5. Update this full table.
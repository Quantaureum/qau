# Quantaureum JSON-RPC API

Reference inventory of the JSON-RPC methods this node serves.

This list is derived from the handler registration call sites in the source tree
(`server.RegisterHandler(...)` and `server.RegisterAdminMethod(...)`), so it tracks
the code rather than a hand-maintained list. If it ever disagrees with a registration
call site, treat this document as the bug and regenerate it.

- Methods registered: **221**
- Methods requiring admin authorization: **48**

Transport, request/response envelope, error codes and the concrete schemas for the
core and light-client subsets: see [openapi.yaml](./openapi.yaml). Specialized
namespaces have their own documents: [bridge-rpc-api.md](./bridge-rpc-api.md),
[shard-rpc-api.md](./shard-rpc-api.md), [rollup-rpc-api.md](./rollup-rpc-api.md).

## Authentication and rate limiting

Public methods need no credentials. The methods marked **Admin** below are on the
server's admin whitelist: each call must additionally pass admin-level authorization
(`ValidateAdminRequest`), enforced on HTTP, WebSocket and batch requests alike. When
an admin method is registered and no auth manager is configured, the request is
rejected instead of being served unauthenticated. Rate limiting is on by default
(1000 requests/s globally, 100 requests/s per IP, burst 50) with stricter per-method
limits for expensive or key-handling methods; see `rpc/ratelimit.go`.

## Namespaces

| Namespace | Methods | Admin-gated |
| --- | --- | --- |
| `admin_` | 2 | 2 |
| `debug_` | 5 | 5 |
| `eth_` | 41 | 3 |
| `evm_` | 2 | 2 |
| `net_` | 3 | 0 |
| `personal_` | 7 | 7 |
| `qau_` | 156 | 27 |
| `txpool_` | 3 | 2 |
| `web3_` | 2 | 0 |

## Method reference

### `admin_` (2 methods)

| Method | Admin | Registered in |
| --- | --- | --- |
| `admin_nodeInfo` | yes | rpc/api.go |
| `admin_peers` | yes | rpc/api.go |

### `debug_` (5 methods)

| Method | Admin | Registered in |
| --- | --- | --- |
| `debug_rollbackChainToHeight` | yes | rpc/api.go |
| `debug_traceBlockByHash` | yes | rpc/debug_api.go |
| `debug_traceBlockByNumber` | yes | rpc/debug_api.go |
| `debug_traceCall` | yes | rpc/debug_api.go |
| `debug_traceTransaction` | yes | rpc/debug_api.go |

### `eth_` (41 methods)

| Method | Admin | Registered in |
| --- | --- | --- |
| `eth_blobBaseFee` |  | rpc/blob_api.go |
| `eth_blockNumber` |  | rpc/api.go |
| `eth_call` |  | rpc/api.go |
| `eth_chainId` |  | rpc/api.go |
| `eth_createAccessList` |  | rpc/access_list_api.go |
| `eth_estimateGas` |  | rpc/api.go |
| `eth_estimateUserOperationGas` |  | rpc/api.go |
| `eth_feeHistory` |  | rpc/fee_api.go |
| `eth_gasPrice` |  | rpc/api.go |
| `eth_getBalance` |  | rpc/api.go |
| `eth_getBlobSidecar` |  | rpc/blob_api.go |
| `eth_getBlockByHash` |  | rpc/api.go |
| `eth_getBlockByNumber` |  | rpc/api.go |
| `eth_getBlockTransactionCountByHash` |  | rpc/api.go |
| `eth_getBlockTransactionCountByNumber` |  | rpc/api.go |
| `eth_getCode` |  | rpc/api.go |
| `eth_getFilterChanges` |  | rpc/api.go |
| `eth_getFilterLogs` |  | rpc/api.go |
| `eth_getLogs` |  | rpc/api.go |
| `eth_getProof` |  | rpc/proof_api.go |
| `eth_getStorageAt` |  | rpc/api.go |
| `eth_getTransactionByBlockHashAndIndex` |  | rpc/api.go |
| `eth_getTransactionByBlockNumberAndIndex` |  | rpc/api.go |
| `eth_getTransactionByHash` |  | rpc/api.go |
| `eth_getTransactionCount` |  | rpc/api.go |
| `eth_getTransactionReceipt` |  | rpc/api.go |
| `eth_getUserOperationByHash` |  | rpc/api.go |
| `eth_getUserOperationReceipt` |  | rpc/api.go |
| `eth_maxPriorityFeePerGas` |  | rpc/fee_api.go |
| `eth_newBlockFilter` |  | rpc/api.go |
| `eth_newFilter` |  | rpc/api.go |
| `eth_newPendingTransactionFilter` |  | rpc/api.go |
| `eth_pendingTransactions` | yes | rpc/api.go |
| `eth_protocolVersion` |  | rpc/api.go |
| `eth_sendBlobTransaction` | yes | rpc/blob_api.go |
| `eth_sendRawTransaction` |  | rpc/api.go |
| `eth_sendTransaction` | yes | rpc/api.go |
| `eth_sendUserOperation` |  | rpc/api.go |
| `eth_supportedEntryPoints` |  | rpc/api.go |
| `eth_syncing` |  | rpc/api.go |
| `eth_uninstallFilter` |  | rpc/api.go |

### `evm_` (2 methods)

| Method | Admin | Registered in |
| --- | --- | --- |
| `evm_revert` | yes | rpc/api.go |
| `evm_snapshot` | yes | rpc/api.go |

### `net_` (3 methods)

| Method | Admin | Registered in |
| --- | --- | --- |
| `net_listening` |  | rpc/api.go |
| `net_peerCount` |  | rpc/api.go |
| `net_version` |  | rpc/api.go |

### `personal_` (7 methods)

| Method | Admin | Registered in |
| --- | --- | --- |
| `personal_importRawKey` | yes | rpc/personal.go |
| `personal_listAccounts` | yes | rpc/personal.go |
| `personal_lockAccount` | yes | rpc/personal.go |
| `personal_newAccount` | yes | rpc/personal.go |
| `personal_sendTransaction` | yes | rpc/personal.go |
| `personal_sign` | yes | rpc/personal.go |
| `personal_unlockAccount` | yes | rpc/personal.go |

### `qau_` (156 methods)

| Method | Admin | Registered in |
| --- | --- | --- |
| `qau_addLiquidity` |  | rpc/defi_api.go |
| `qau_approveMultisigProposal` | yes | rpc/multisig_api.go |
| `qau_borrow` |  | rpc/defi_api.go |
| `qau_bridgeGetPendingTransfers` | yes | rpc/bridge_api.go |
| `qau_bridgeGetStatus` |  | rpc/bridge_api.go |
| `qau_bridgeGetSupportedChains` |  | rpc/bridge_api.go |
| `qau_bridgeRefundFailedLock` | yes | rpc/bridge_api.go |
| `qau_builder_getSlotInfo` |  | rpc/builder_api.go |
| `qau_builder_getWinningBid` |  | rpc/builder_api.go |
| `qau_builder_submitBid` | yes | rpc/builder_api.go |
| `qau_castVote` | yes | rpc/governance_api.go |
| `qau_claimDeFiIncentives` | yes | rpc/economics_api.go |
| `qau_claimRewards` |  | rpc/api.go |
| `qau_compoundRewards` |  | rpc/api.go |
| `qau_createMultisigProposal` | yes | rpc/multisig_api.go |
| `qau_createProposal` | yes | rpc/governance_api.go |
| `qau_estimateUserOperationGas` |  | rpc/api.go |
| `qau_executeMultisigProposal` | yes | rpc/multisig_api.go |
| `qau_executeProposal` | yes | rpc/governance_api.go |
| `qau_finalizeProposal` | yes | rpc/governance_api.go |
| `qau_generateStealthAddress` |  | rpc/api.go |
| `qau_getActiveProposals` |  | rpc/governance_api.go |
| `qau_getAllMultisigProposals` |  | rpc/multisig_api.go |
| `qau_getContractBalance` |  | rpc/api.go |
| `qau_getContractList` |  | rpc/api.go |
| `qau_getDeFiIncentives` |  | rpc/economics_api.go |
| `qau_getExchangeRate` |  | rpc/economics_api.go |
| `qau_getFarmPendingReward` |  | rpc/defi_api.go |
| `qau_getFeeDistribution` |  | rpc/economics_api.go |
| `qau_getGovernanceConfig` |  | rpc/governance_api.go |
| `qau_getGovernanceParameter` |  | rpc/governance_api.go |
| `qau_getGovernanceParameters` |  | rpc/governance_api.go |
| `qau_getIncomingMultisigTransfers` |  | rpc/multisig_api.go |
| `qau_getInflationInfo` |  | rpc/economics_api.go |
| `qau_getLendingPool` |  | rpc/defi_api.go |
| `qau_getLendingPools` |  | rpc/defi_api.go |
| `qau_getLiquidityPool` |  | rpc/defi_api.go |
| `qau_getLiquidityPools` |  | rpc/defi_api.go |
| `qau_getLiquidStakingPosition` |  | rpc/economics_api.go |
| `qau_getMultisigProposal` |  | rpc/multisig_api.go |
| `qau_getMultisigWallet` |  | rpc/multisig_api.go |
| `qau_getPendingMultisigProposals` |  | rpc/multisig_api.go |
| `qau_getPendingRewards` |  | rpc/api.go |
| `qau_getPrivacyBalance` |  | rpc/api.go |
| `qau_getProposal` |  | rpc/governance_api.go |
| `qau_getProposalCount` |  | rpc/governance_api.go |
| `qau_getProposalsForSigner` |  | rpc/multisig_api.go |
| `qau_getRewardPoolStatus` |  | rpc/api.go |
| `qau_getRewardStats` |  | rpc/economics_api.go |
| `qau_getStake` |  | rpc/api.go |
| `qau_getStakingContracts` |  | rpc/api.go |
| `qau_getStakingPools` |  | rpc/api.go |
| `qau_getStakingStats` |  | rpc/api.go |
| `qau_getSupply` |  | rpc/economics_api.go |
| `qau_getSwapQuote` |  | rpc/defi_api.go |
| `qau_getTotalRewardsClaimed` |  | rpc/api.go |
| `qau_getUnstakeStatus` |  | rpc/api.go |
| `qau_getUserFarmStake` |  | rpc/defi_api.go |
| `qau_getUserLendingPosition` |  | rpc/defi_api.go |
| `qau_getUserLPBalance` |  | rpc/defi_api.go |
| `qau_getUserOperationByHash` |  | rpc/api.go |
| `qau_getUserOperationReceipt` |  | rpc/api.go |
| `qau_getUserStakes` |  | rpc/api.go |
| `qau_getVote` |  | rpc/governance_api.go |
| `qau_getYieldFarm` |  | rpc/defi_api.go |
| `qau_getYieldFarms` |  | rpc/defi_api.go |
| `qau_harvestFarm` |  | rpc/defi_api.go |
| `qau_isMultisigWallet` |  | rpc/multisig_api.go |
| `qau_l1BridgeEncodeRecordFinalizedBatch` |  | rpc/rollup_api.go |
| `qau_l1BridgeGetContractBytecode` |  | rpc/rollup_api.go |
| `qau_l1BridgeGetDeposit` |  | rpc/rollup_api.go |
| `qau_l1BridgeGetFinalizedStateRoot` |  | rpc/rollup_api.go |
| `qau_l1BridgeGetLiquidity` |  | rpc/rollup_api.go |
| `qau_l1BridgeGetStatus` |  | rpc/rollup_api.go |
| `qau_light_batchRequest` |  | lightclient/api.go |
| `qau_light_getBalance` |  | lightclient/api.go |
| `qau_light_getBandwidthStats` |  | lightclient/api.go |
| `qau_light_getBlockHeader` |  | lightclient/api.go |
| `qau_light_getBlockHeaders` |  | lightclient/api.go |
| `qau_light_getCheckpoints` |  | lightclient/api.go |
| `qau_light_getCompactProof` |  | lightclient/api.go |
| `qau_light_getCompressedHeaders` |  | lightclient/api.go |
| `qau_light_getDeltaHeaders` |  | lightclient/api.go |
| `qau_light_getLatestHeader` |  | lightclient/api.go |
| `qau_light_getMultiStateProof` |  | lightclient/api.go |
| `qau_light_getMultiTxProof` |  | lightclient/api.go |
| `qau_light_getSerializedStateProof` |  | lightclient/api.go |
| `qau_light_getSerializedTxProof` |  | lightclient/api.go |
| `qau_light_getStateProof` |  | lightclient/api.go |
| `qau_light_getSyncCommittee` |  | lightclient/api.go |
| `qau_light_getSyncStatus` |  | lightclient/api.go |
| `qau_light_getTxProof` |  | lightclient/api.go |
| `qau_light_getTxStatus` |  | lightclient/api.go |
| `qau_light_submitTransaction` |  | lightclient/api.go |
| `qau_light_verifyStateProof` |  | lightclient/api.go |
| `qau_light_verifySyncCommitteeSig` |  | lightclient/api.go |
| `qau_light_verifyTxProof` |  | lightclient/api.go |
| `qau_liquidate` |  | rpc/defi_api.go |
| `qau_liquidStake` | yes | rpc/economics_api.go |
| `qau_liquidUnstake` | yes | rpc/economics_api.go |
| `qau_qposStatus` |  | rpc/api.go |
| `qau_qrngGetRandom` | yes | rpc/quantum_api.go |
| `qau_quantumGetKeyRotationStatus` |  | rpc/quantum_api.go |
| `qau_quantumGetMPCStatus` |  | rpc/quantum_api.go |
| `qau_quantumVerifyZKP` |  | rpc/quantum_api.go |
| `qau_registerMultisigWallet` | yes | rpc/multisig_api.go |
| `qau_removeLiquidity` |  | rpc/defi_api.go |
| `qau_repay` |  | rpc/defi_api.go |
| `qau_rollupGetAnchor` |  | rpc/rollup_api.go |
| `qau_rollupGetBatch` |  | rpc/rollup_api.go |
| `qau_rollupGetStateRoot` |  | rpc/rollup_api.go |
| `qau_rollupGetStatus` |  | rpc/rollup_api.go |
| `qau_rollupSendRawTransaction` | yes | rpc/rollup_api.go |
| `qau_rollupSubmitFraudProof` | yes | rpc/rollup_api.go |
| `qau_scanPrivacy` |  | rpc/api.go |
| `qau_sendBlobTransaction` | yes | rpc/blob_api.go |
| `qau_sendPrivacyTransaction` | yes | rpc/api.go |
| `qau_sendUserOperation` |  | rpc/api.go |
| `qau_shardGetActiveShardCount` |  | rpc/shard_api.go |
| `qau_shardGetBlock` |  | rpc/shard_api.go |
| `qau_shardGetCommitment` |  | rpc/shard_api.go |
| `qau_shardGetReceipt` |  | rpc/shard_api.go |
| `qau_shardGetShard` |  | rpc/shard_api.go |
| `qau_shardGetShardCount` |  | rpc/shard_api.go |
| `qau_shardIsReceiptSpent` |  | rpc/shard_api.go |
| `qau_shardSubmitCrossShardMessage` | yes | rpc/shard_api.go |
| `qau_signQuantumTransaction` | yes | rpc/api.go |
| `qau_stake` |  | rpc/api.go |
| `qau_stakeFarm` |  | rpc/defi_api.go |
| `qau_stardust_getChambers` |  | rpc/stardust_api.go |
| `qau_stardust_getDKGStatus` |  | rpc/stardust_api.go |
| `qau_stardust_getExecutiveChamber` |  | rpc/stardust_api.go |
| `qau_stardust_getFinality` |  | rpc/stardust_api.go |
| `qau_stardust_getMinistryStatus` |  | rpc/stardust_api.go |
| `qau_stardust_getQTDFinalityStatus` |  | rpc/stardust_api.go |
| `qau_stardust_getReviewChamber` |  | rpc/stardust_api.go |
| `qau_stardust_getThreeChambersFlow` |  | rpc/stardust_api.go |
| `qau_stardust_verifyFinality` |  | rpc/stardust_api.go |
| `qau_supply` |  | rpc/defi_api.go |
| `qau_supportedEntryPoints` |  | rpc/api.go |
| `qau_swap` |  | rpc/defi_api.go |
| `qau_tss_generateKeyShares` | yes | rpc/qtd_api.go |
| `qau_tss_getPublicKey` |  | rpc/qtd_api.go |
| `qau_tss_getSealStatus` |  | rpc/stardust_api.go |
| `qau_tss_getShare` | yes | rpc/qtd_api.go |
| `qau_tss_requestSeal` | yes | rpc/stardust_api.go |
| `qau_tss_signMessage` | yes | rpc/qtd_api.go |
| `qau_tss_status` |  | rpc/qtd_api.go |
| `qau_tss_submitPartialSeal` | yes | rpc/stardust_api.go |
| `qau_tss_verifySignature` | yes | rpc/qtd_api.go |
| `qau_unstake` |  | rpc/api.go |
| `qau_unstakeFarm` |  | rpc/defi_api.go |
| `qau_updateCommission` |  | rpc/api.go |
| `qau_validatorKeyStatus` |  | rpc/api.go |
| `qau_verifyQuantumTransaction` |  | rpc/api.go |
| `qau_withdraw` |  | rpc/defi_api.go |

### `txpool_` (3 methods)

| Method | Admin | Registered in |
| --- | --- | --- |
| `txpool_content` | yes | rpc/api.go |
| `txpool_inspect` | yes | rpc/api.go |
| `txpool_status` |  | rpc/api.go |

### `web3_` (2 methods)

| Method | Admin | Registered in |
| --- | --- | --- |
| `web3_clientVersion` |  | rpc/api.go |
| `web3_sha3` |  | rpc/api.go |

## Security-relevant behaviour notes

These are deliberate refusals or honest flags, not bugs to work around; each is
enforced in code and pinned by tests.

- **Account Abstraction is not live.** `eth_sendUserOperation`,
  `qau_sendUserOperation`, `eth_estimateUserOperationGas`,
  `qau_estimateUserOperationGas` and the receipt/lookup variants answer with an
  explicit not-live error: no bundler is wired to the chain, so a user operation
  would never be included in a block. The txpool refuses independently
  (`txpool.ErrUserOpsNotLive`).
- **`evm_snapshot` / `evm_revert` refuse.** Block-height state snapshots cannot be
  restored on this node: the stored map is only pruning bookkeeping and
  `RevertToSnapshot` takes a journal position, not a height. Both handlers answer
  with `ErrStateSnapshotNotSupportedRPC`.
- **`eth_getProof` marks what it cannot prove.** Committed storage never reaches the
  Verkle state trie on this node (slots go to the key-value store; every state-trie
  key is an account address), so storage entries can never be state-root-bound. Each
  `storageProof` entry therefore carries `"unverified": true`, the result carries the
  same flag, and `storageHash` is the empty root. Account proofs are verified against
  the trie when the state root can be resolved. A caller that treats these proofs as
  finalized evidence is trusting an assertion the node never made. At most 100 storage
  keys per request.
- **`qau_light_*` state proofs refuse storage keys.** `qau_light_getStateProof`, 
  `qau_light_getMultiStateProof`, `qau_light_getSerializedStateProof` and the compact 
  variant answer a request that names storage slots with an error (`-32603`, message 
  `state proof unavailable`, the `ErrProofNotSupported` reason in `data`), because a 
  storage key has no state-trie path to prove; a malformed slot key is rejected up 
  front with `-32602` instead of being dropped from the requested set. Requests 
  without storage keys are served normally.
- **Serialization of Verkle proofs is versioned.** Proof blobs carry an explicit wire
  version so a decoder cannot silently mis-read a future format.

## Admin whitelist without a handler

None: every method on the admin whitelist also has a registered handler, so the
Admin column above covers the whole gated surface.

## Drift

This document is generated content. Methods are added by registering a handler; the
table then has to be regenerated so the pushed doc cannot drift from the code.

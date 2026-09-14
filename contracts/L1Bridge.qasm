// Quantaureum Node source, version 1.0.0.
// QVM L1Bridge contract (QASM)
// Quantaureum native quantum blockchain — L1↔L2 bridge contract
//
// W-P1-6 Phase 4 (2026-07-14): on-chain bridge contract with on-chain Merkle withdrawal verification
//
// QVM opcode stack semantics (different from EVM!):
//   SUB: pops a(top), b(second), returns a - b
//   LT:  pops a(top), b(second), returns a < b ? 1 : 0
//   GT:  pops a(top), b(second), returns a > b ? 1 : 0
//   DIV: pops a(top), b(second), returns a / b
//   MUL: pops a(top), b(second), returns a * b
//   MOD: pops a(top), b(second), returns a % b
//   ADD: pops a(top), b(second), returns a + b
//   MSTORE: pops offset(top), value(second), writes memory[offset] = value
//   MLOAD:  pops offset(top), returns memory[offset]
//   SSTORE: pops key(top), value(second), writes storage[key] = value
//   SLOAD:  pops key(top), returns storage[key]
//   SHR: pops shift(top), value(second), returns value >> shift
//   SHL: pops shift(top), value(second), returns value << shift
//   BYTE: pops i(top), x(second), returns (x >> (248 - i*8)) & 0xFF
//   EQ:  pops a(top), b(second), returns a == b ? 1 : 0
//   AND: pops a(top), b(second), returns a & b
//   OR:  pops a(top), b(second), returns a | b
//
// Storage:
//   slot 0:                   owner (deployer address)
//   slot 1:                   liquidity (total QAU locked in the bridge)
//   slot batchIndex+0x1000:   finalized L2 state roots (written by recordFinalizedBatch)
//   slot dsKey:               processed-withdrawal markers (dsKey = (batchIndex<<160)|withdrawer)
//
// SHA-256 precompiled contract:
//   address: 0x0000000000000000000000000000000000000002
//   input: bytes of arbitrary length
//   output: 32-byte SHA-256 hash
//   Gas:  60 + 12*ceil(len/32)
//   call: STATICCALL(gas, addr, inOff, inSize, outOff, outSize)
//   WARNING: do NOT use the SHA3/KECCAK256 opcodes! They produce Keccak-256, which mismatches the SMT's SHA-256
//
// Merkle verification:
//   SMT depth = 160 (matching the account address bit width)
//   one SHA-256 call per level, 160 in total
//   verification: currentHash starts at leafHash and hashes with the sibling level by level
//   left child (bit=0): SHA256(currentHash || sibling)
//   right child (bit=1): SHA256(sibling || currentHash)
//   the final result must equal stateRoot
//
// function selectors (manually defined, not keccak256):
//   0xf7b6d1e5 = getLiquidity()
//   0xa6f2aea3 = deposit()
//   0xb4d3d1a0 = recordFinalizedBatch(uint256 batchIndex, bytes32 stateRoot)
//   0xc5e4f2b8 = processWithdrawal(bytes32, uint256, uint256, uint256, bytes32, bytes32, bytes32, bytes32[160])

// ===== Constructor =====
.INIT
    // store owner = CALLER
    CALLER
    PUSH1 0x00
    SSTORE

    // return runtime code
    PUSH2 @code_end-@code_start
    PUSH2 @code_start
    PUSH1 0x00
    CODECOPY
    PUSH2 @code_end-@code_start
    PUSH1 0x00
    RETURN

// ===== Runtime code =====
.CODE
code_start:
    // ===== function dispatcher =====
    CALLDATASIZE
    PUSH1 0x04
    LT
    ISZERO
    JUMPI @dispatch
    STOP

dispatch:
    JUMPDEST
    PUSH1 0x00
    CALLDATALOAD
    PUSH1 0xe0
    SHR
    PUSH4 0xffffffff
    AND

    DUP1
    PUSH4 0xf7b6d1e5
    EQ
    JUMPI @fn_getLiquidity

    DUP1
    PUSH4 0xa6f2aea3
    EQ
    JUMPI @fn_deposit

    DUP1
    PUSH4 0xb4d3d1a0
    EQ
    JUMPI @fn_recordFinalizedBatch

    DUP1
    PUSH4 0xc5e4f2b8
    EQ
    JUMPI @fn_processWithdrawal

    POP
    STOP

    // ===== getLiquidity() =====
    //   returns: uint256 liquidity
fn_getLiquidity:
    JUMPDEST
    POP
    PUSH1 0x01
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

    // ===== deposit() =====
    //   the caller sends QAU (CALLVALUE), adding bridge liquidity
    // returns: uint256 1 (success)
fn_deposit:
    JUMPDEST
    POP
    // newLiquidity = liquidity + CALLVALUE
    PUSH1 0x01
    SLOAD                   // [liquidity]
    CALLVALUE               // [liquidity, callvalue]
    ADD                     // ADD(a=callvalue, b=liquidity) = callvalue + liquidity
    PUSH1 0x01              // [newLiquidity, 1]
    SSTORE                  // SSTORE(key=1, value=newLiquidity)
    //   return 1
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

    // ===== recordFinalizedBatch(uint256 batchIndex, bytes32 stateRoot) =====
    //   owner only. Records a finalized L2 state root.
    // Calldata: [4:36]=batchIndex, [36:68]=stateRoot
    // returns: uint256 1 (success)
fn_recordFinalizedBatch:
    JUMPDEST
    POP
    //   permission check: CALLER == owner
    CALLER                  // [caller]
    PUSH1 0x00
    SLOAD                   // [caller, owner]
    EQ                      // EQ(a=owner, b=caller) = owner == caller
    ISZERO                  // not owner?
    JUMPI @not_owner

    // Storage: SSTORE(batchIndex + 0x1000, stateRoot)
    PUSH1 0x04              // [offset=4]
    CALLDATALOAD            // [batchIndex]
    PUSH2 0x1000            // [batchIndex, 0x1000]
    ADD                     // ADD(a=0x1000, b=batchIndex) = batchIndex + 0x1000
    // Stack: [storageKey]
    PUSH1 0x24              // [storageKey, offset=36]
    CALLDATALOAD            // [storageKey, stateRoot]
    //   SSTORE needs the key on top: [storageKey, stateRoot] with stateRoot on top
    //   swap needed: [stateRoot, storageKey]
    SWAP1                   // [stateRoot, storageKey]
    SSTORE                  // SSTORE(key=storageKey, value=stateRoot)

    //   return 1
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

    // ===== processWithdrawal(...) =====
    //   verifies a Merkle withdrawal proof and releases locked QAU.
    //
    //   Calldata layout:
    //   [0:4]     selector (0xc5e4f2b8)
    //   [4:36]    withdrawer (left-padded to 32 bytes)
    //   [36:68]   amount (uint256)
    //   [68:100]  batchIndex (uint256)
    //   [100:132] txIndex (uint256)
    //   [132:164] batchHash (bytes32)
    //   [164:196] stateRoot (bytes32) — the finalized L2 state root of the batch
    //   [196:228] leafHash (bytes32) — WARNING: ignored by the contract; the leaf is recomputed on-chain
    //   [228:5348] siblings[160] — 160 sibling hashes, 32 bytes each
    //
    //   Verification flow:
    //   1. check the batch is finalized (stored stateRoot == calldata stateRoot)
    //   2. check no double-spend (dsKey unmarked)
    //   3. compute leafHash on-chain = SHA256(withdrawer[20] || amount[32] || txIndex[4])
    //      (FIX: the amount enters the leaf preimage, forbidding caller-supplied leafHash)
    //   4. Merkle proof verification (160 SHA-256 calls)
    //   5. mark as processed
    //   6. deduct liquidity
    //   7. transfer QAU to the withdrawer
    //
    //   Memory layout:
    //   0x00-0x1f:  currentHash (updated per level; initialized to the on-chain-computed leafHash)
    //   0x40-0x5f:  SHA-256 input left half (32 bytes)
    //   0x60-0x7f:  SHA-256 input right half (32 bytes)
    //   0x80-0x9f:  SHA-256 output (32 bytes)
    //   0xa0-0xbf:  addr_value (left-padded withdrawer address)
    //   0xc0-0xdf:  loop counter i
    //   0xe0-0xff:  stateRoot (for the final comparison)
    //   0x134-0x153: withdrawer word (12 zeros || withdrawer[20]) — building the leafHash input
    //   0x140-0x177: leafHash SHA-256 input (56 bytes: withdrawer[20] || amount[32] || txIndex[4])

fn_processWithdrawal:
    JUMPDEST
    POP

    //   --- step 1: verify the batch is finalized ---
    //   load batchIndex, compute storageKey = batchIndex + 0x1000
    PUSH1 0x44              // [offset=68]
    CALLDATALOAD            // [batchIndex]
    PUSH2 0x1000            // [batchIndex, 0x1000]
    ADD                     // [storageKey]
    SLOAD                   // [storedStateRoot]

    //   load stateRoot from calldata
    PUSH1 0xa4              // [storedStateRoot, offset=164]
    CALLDATALOAD            // [storedStateRoot, stateRoot]

    //   compare: storedStateRoot == stateRoot
    EQ                      // EQ(a=stateRoot, b=storedStateRoot)
    ISZERO                  // not equal?
    JUMPI @batch_not_finalized

    //   --- step 2: check double-spend ---
    // dsKey = (batchIndex << 160) | withdrawer
    //   batchIndex in the high bits (bit 160+), withdrawer in the low 160 bits
    PUSH1 0x44              // [offset=68]
    CALLDATALOAD            // [batchIndex]
    PUSH1 0xa0              // [batchIndex, 160]
    SHL                     // SHL(shift=160, value=batchIndex) = batchIndex << 160
    PUSH1 0x04              // [batchIndex<<160, offset=4]
    CALLDATALOAD            // [batchIndex<<160, withdrawer]
    OR                      // OR(a=withdrawer, b=batchIndex<<160) = dsKey

    //   check whether dsKey is already marked
    DUP1                    // [dsKey, dsKey]
    SLOAD                   // [dsKey, processed]
    PUSH1 0x00              // [dsKey, processed, 0]
    EQ                      // EQ(a=0, b=processed) = (processed == 0)
    ISZERO                  // already processed?
    JUMPI @already_processed
    // Stack: [dsKey]

    //   --- step 3: compute leafHash on-chain and initialize Merkle verification memory ---
    //   FIX (2026-07-16): leafHash is not read from calldata; it is derived on-chain as
    //   SHA256(withdrawer[20] || amount[32 left-padded] || txIndex[4 BE]).
    //   The amount and recipient come from calldata and enter the leaf preimage; tampering with either changes the leaf,
    //   the Merkle root no longer matches, and proof_failed fires — preventing a caller from freely supplying a leafHash
    //   paired with legitimate siblings to withdraw an arbitrary amount.
    //
    //   Fully consistent with the Go-side rollup.ComputeWithdrawalLeafHash (56-byte input).
    //
    //   Memory build (leafHash SHA-256 input, 56 bytes at mem[0x140:0x178]):
    //   mem[0x140:0x154] = withdrawer[20]   (low 20 bytes of calldata[16:36])
    //   mem[0x154:0x174] = amount[32]       (calldata[36:68])
    //   mem[0x174:0x178] = txIndex[4 BE]    (low 4 bytes of calldata[128:132])
    //
    //   Write order (avoiding overlapping 32-byte MSTORE writes):
    //   1. txIndex word  → mem[0x158]  (mem[0x158:0x178] = 28 zeros || txIndex[4])
    //   2. amount word   -> mem[0x154]  (mem[0x154:0x174] = amount[32]; overwrites step-1
    //                                    zeros while keeping mem[0x174:0x178] = txIndex[4])
    //   3. withdrawer word → mem[0x134] (mem[0x134:0x154] = 12 zeros || withdrawer[20];
    //                                    mem[0x140:0x154] = withdrawer[20])

    // 1. txIndex: MSTORE(calldata[100:132], 0x158)
    PUSH1 0x64              // [dsKey, offset=100]
    CALLDATALOAD            // [dsKey, txIndex_word]
    PUSH2 0x0158            // [dsKey, txIndex_word, 0x0158]
    MSTORE                  // mem[0x158:0x178] = txIndex_word (28 zeros || txIndex[4])
    // Stack: [dsKey]

    // 2. amount: MSTORE(calldata[36:68], 0x154)
    PUSH1 0x24              // [dsKey, offset=36]
    CALLDATALOAD            // [dsKey, amount_word]
    PUSH2 0x0154            // [dsKey, amount_word, 0x0154]
    MSTORE                  // mem[0x154:0x174] = amount_word
    // Stack: [dsKey]

    // 3. withdrawer: MSTORE(calldata[4:36], 0x134)
    PUSH1 0x04              // [dsKey, offset=4]
    CALLDATALOAD            // [dsKey, withdrawer_word]
    PUSH2 0x0134            // [dsKey, withdrawer_word, 0x0134]
    MSTORE                  // mem[0x134:0x154] = withdrawer_word (12 zeros || withdrawer[20])
    // mem[0x140:0x154] = withdrawer[20], mem[0x154:0x174] = amount[32], mem[0x174:0x178] = txIndex[4]
    // Stack: [dsKey]

    // 4. SHA-256(withdrawer[20] || amount[32] || txIndex[4]) → mem[0x00]
    //    STATICCALL(gas, addr=0x02, inOff=0x140, inSize=56, outOff=0x00, outSize=32)
    GAS                     // [dsKey, gas]
    PUSH1 0x02              // [dsKey, gas, addr=0x02]
    PUSH2 0x0140            // [dsKey, gas, addr, inOff=0x0140]
    PUSH1 0x38              // [dsKey, gas, addr, inOff, inSize=56]
    PUSH1 0x00              // [dsKey, gas, addr, inOff, inSize, outOff=0x00]
    PUSH1 0x20              // [dsKey, gas, addr, inOff, inSize, outOff, outSize=32]
    STATICCALL              // [dsKey, success]
    ISZERO                  // [dsKey, failed]
    JUMPI @leaf_hash_failed
    POP                     // [dsKey]
    //   mem[0x00:0x20] = leafHash (= initial currentHash, entering the Merkle loop)
    // Stack: [dsKey]

    //   mem[0xa0] = withdrawer address value (loaded from calldata[4:36], used to extract bits in the loop)
    PUSH1 0x04              // [dsKey, offset=4]
    CALLDATALOAD            // [dsKey, addr_value]
    PUSH1 0xa0              // [dsKey, addr_value, 0xa0]
    MSTORE                  // mem[0xa0] = addr_value
    // Stack: [dsKey]

    //   mem[0xc0] = 0 (loop counter)
    PUSH1 0x00              // [dsKey, 0]
    PUSH1 0xc0              // [dsKey, 0, 0xc0]
    MSTORE                  // mem[0xc0] = 0
    // Stack: [dsKey]

    //   mem[0xe0] = stateRoot (loaded from calldata[164:196])
    PUSH1 0xa4              // [dsKey, offset=164]
    CALLDATALOAD            // [dsKey, stateRoot]
    PUSH1 0xe0              // [dsKey, stateRoot, 0xe0]
    MSTORE                  // mem[0xe0] = stateRoot
    // Stack: [dsKey]

    //   --- Merkle verification loop ---
    //   160 iterations, each:
    //   1. extract bit (159-i) from the address
    //   2. load sibling[i] from calldata
    //   3. order the hashes by the bit: left||right
    //   4. call the SHA-256 precompile
    //   5. update currentHash

merkle_loop:
    JUMPDEST
    // Stack: [dsKey]

    //   check i >= 160
    PUSH1 0xa0              // [dsKey, 160]
    PUSH1 0xc0
    MLOAD                   // [dsKey, 160, i]
    LT                      // LT(a=i, b=160) = i < 160
    ISZERO                  // i >= 160?
    JUMPI @merkle_done
    // Stack: [dsKey]

    //   compute bitIndex = 159 - i
    PUSH1 0x9f              // [dsKey, 159]
    PUSH1 0xc0
    MLOAD                   // [dsKey, 159, i]
    SWAP1                   // [dsKey, i, 159]
    SUB                     // SUB(a=159, b=i) = 159 - i
    // Stack: [dsKey, bitIndex]

    //   compute byte32_index = 12 + (bitIndex / 8)
    //   the address is left-padded with 12 zero bytes, so address byte 0 sits at byte 12 of the 32-byte value
    DUP1                    // [dsKey, bitIndex, bitIndex]
    PUSH1 0x08              // [dsKey, bitIndex, bitIndex, 8]
    SWAP1                   // [dsKey, bitIndex, 8, bitIndex]
    DIV                     // DIV(a=bitIndex, b=8) = bitIndex / 8
    PUSH1 0x0c              // [dsKey, bitIndex, bitIndex/8, 12]
    ADD                     // ADD(a=12, b=bitIndex/8) = 12 + bitIndex/8
    // Stack: [dsKey, bitIndex, byte32_index]

    //   extract the byte: byte = BYTE(byte32_index, addr_value)
    PUSH1 0xa0
    MLOAD                   // [dsKey, bitIndex, byte32_index, addr_value]
    SWAP1                   // [dsKey, bitIndex, addr_value, byte32_index]
    BYTE                    // BYTE(i=byte32_index, x=addr_value) = byte
    // Stack: [dsKey, bitIndex, byte]

    //   compute bitInByte = 7 - (bitIndex % 8)
    SWAP1                   // [dsKey, byte, bitIndex]
    DUP1                    // [dsKey, byte, bitIndex, bitIndex]
    PUSH1 0x08              // [dsKey, byte, bitIndex, bitIndex, 8]
    SWAP1                   // [dsKey, byte, bitIndex, 8, bitIndex]
    MOD                     // MOD(a=bitIndex, b=8) = bitIndex % 8
    PUSH1 0x07              // [dsKey, byte, bitIndex, bitIndex%8, 7]
    SUB                     // SUB(a=7, b=bitIndex%8) = 7 - bitIndex%8
    // Stack: [dsKey, byte, bitIndex, bitInByte]

    //   compute isRight = (byte >> bitInByte) & 1
    SWAP1                   // [dsKey, byte, bitInByte, bitIndex]
    POP                     // [dsKey, byte, bitInByte]
    SHR                     // SHR(shift=bitInByte, value=byte) = byte >> bitInByte
    PUSH1 0x01              // [dsKey, byte>>bitInByte, 1]
    AND                     // AND(a=1, b=byte>>bitInByte) = isRight
    // Stack: [dsKey, isRight]

    //   load sibling[i] from calldata[228 + i*32]
    PUSH1 0xc0
    MLOAD                   // [dsKey, isRight, i]
    PUSH1 0x20              // [dsKey, isRight, i, 32]
    MUL                     // MUL(a=32, b=i) = i * 32
    PUSH1 0xe4              // [dsKey, isRight, i*32, 0xe4]
    ADD                     // ADD(a=0xe4, b=i*32) = 228 + i*32
    CALLDATALOAD            // [dsKey, isRight, sibling]

    //   load currentHash from mem[0x00]
    PUSH1 0x00
    MLOAD                   // [dsKey, isRight, sibling, currentHash]

    //   write the SHA-256 input buffer:
    //   mem[0x40] = currentHash (default left child)
    //   mem[0x60] = sibling (default right child)
    DUP1                    // [dsKey, isRight, sibling, currentHash, currentHash]
    PUSH1 0x40              // [dsKey, isRight, sibling, currentHash, currentHash, 0x40]
    MSTORE                  // mem[0x40] = currentHash
    // Stack: [dsKey, isRight, sibling, currentHash]

    SWAP1                   // [dsKey, isRight, currentHash, sibling]
    DUP1                    // [dsKey, isRight, currentHash, sibling, sibling]
    PUSH1 0x60              // [dsKey, isRight, currentHash, sibling, sibling, 0x60]
    MSTORE                  // mem[0x60] = sibling
    // Stack: [dsKey, isRight, currentHash, sibling]

    //   clean the stack: drop sibling and currentHash (already in memory)
    POP                     // [dsKey, isRight, currentHash]
    POP                     // [dsKey, isRight]

    //   if isRight == 1, swap mem[0x40] and mem[0x60]
    JUMPI @merkle_swap
    //   Stack: [dsKey] (isRight == 0, no swap needed)
    JUMP @merkle_hash

merkle_swap:
    JUMPDEST
    // Stack: [dsKey]
    //   swap: temp = mem[0x40]; mem[0x40] = mem[0x60]; mem[0x60] = temp
    PUSH1 0x40
    MLOAD                   // [dsKey, left]
    PUSH1 0x60
    MLOAD                   // [dsKey, left, right]
    PUSH1 0x40              // [dsKey, left, right, 0x40]
    MSTORE                  // mem[0x40] = right (sibling becomes the left child)
    // Stack: [dsKey, left]
    PUSH1 0x60              // [dsKey, left, 0x60]
    MSTORE                  // mem[0x60] = left (currentHash becomes the right child)
    // Stack: [dsKey]

merkle_hash:
    JUMPDEST
    // Stack: [dsKey]
    //   call the SHA-256 precompile (address 0x02)
    // STATICCALL(gas, addr, inOff, inSize, outOff, outSize)
    //   input: mem[0x40:0x80] (64 bytes = left || right)
    //   output: mem[0x80:0xa0] (32-byte hash)
    GAS                     // [dsKey, gas]
    PUSH1 0x02              // [dsKey, gas, addr=0x02]
    PUSH1 0x40              // [dsKey, gas, addr, inOff=0x40]
    PUSH1 0x40              // [dsKey, gas, addr, inOff, inSize=64]
    PUSH1 0x80              // [dsKey, gas, addr, inOff, inSize, outOff=0x80]
    PUSH1 0x20              // [dsKey, gas, addr, inOff, inSize, outOff, outSize=32]
    STATICCALL              // [dsKey, success]

    //   check whether STATICCALL succeeded
    ISZERO                  // [dsKey, failed]
    JUMPI @hash_failed
    POP                     // [dsKey] (drop success=1)

    //   copy the result to mem[0x00] (the new currentHash)
    PUSH1 0x80
    MLOAD                   // [dsKey, newHash]
    PUSH1 0x00              // [dsKey, newHash, 0x00]
    MSTORE                  // mem[0x00] = newHash
    // Stack: [dsKey]

    //   increment the counter: i++
    PUSH1 0xc0
    MLOAD                   // [dsKey, i]
    PUSH1 0x01              // [dsKey, i, 1]
    ADD                     // [dsKey, i+1]
    PUSH1 0xc0              // [dsKey, i+1, 0xc0]
    MSTORE                  // mem[0xc0] = i+1
    // Stack: [dsKey]

    JUMP @merkle_loop

merkle_done:
    JUMPDEST
    // Stack: [dsKey]
    //   compare currentHash (mem[0x00]) with stateRoot (mem[0xe0])
    PUSH1 0x00
    MLOAD                   // [dsKey, currentHash]
    PUSH1 0xe0
    MLOAD                   // [dsKey, currentHash, stateRoot]
    EQ                      // EQ(a=stateRoot, b=currentHash)
    ISZERO                  // mismatch?
    JUMPI @proof_failed
    // Stack: [dsKey]

    //   --- step 4: mark the withdrawal processed ---
    // SSTORE(dsKey, 1)
    DUP1                    // [dsKey, dsKey]
    PUSH1 0x01              // [dsKey, dsKey, 1]
    SWAP1                   // [dsKey, 1, dsKey]
    SSTORE                  // SSTORE(key=dsKey, value=1)
    // Stack: [dsKey]
    POP                     // []

    //   --- step 5: check and deduct liquidity ---
    //   check liquidity >= amount
    //   (2026-07-17): QVM LT semantics cross-verified against qvm/operations.go:opLt
    //   LT pops a(top), b(second), returning a < b ? 1 : 0
    //   after SWAP1 the top is liquidity and second is amount, so LT returns liquidity < amount
    //   boundary semantics: amount == liquidity -> LT=0 -> no jump -> full-balance withdrawal allowed (legitimate)
    //             amount >  liquidity -> LT=1 -> jump to insufficient_liquidity (rejected)
    //             amount <  liquidity -> LT=0 -> no jump -> withdrawal allowed (legitimate)
    PUSH1 0x01
    SLOAD                   // [liquidity]
    PUSH1 0x24              // [liquidity, offset=36]
    CALLDATALOAD            // [liquidity, amount]
    SWAP1                   // [amount, liquidity]
    LT                      // LT(a=liquidity, b=amount) = liquidity < amount
    JUMPI @insufficient_liquidity
    // Stack: []

    //   deduct: newLiquidity = liquidity - amount
    PUSH1 0x01
    SLOAD                   // [liquidity]
    PUSH1 0x24              // [liquidity, offset=36]
    CALLDATALOAD            // [liquidity, amount]
    //   SUB(a=amount, b=liquidity) = amount - liquidity ... wrong!
    //   we need liquidity - amount, so a=liquidity
    SWAP1                   // [amount, liquidity]
    SUB                     // SUB(a=liquidity, b=amount) = liquidity - amount
    PUSH1 0x01              // [newLiquidity, 1]
    SSTORE                  // SSTORE(key=1, value=newLiquidity)

    //   --- step 6: transfer QAU to the withdrawer ---
    // CALL(gas, addr, value, inOff, inSize, outOff, outSize)
    GAS                     // [gas]
    PUSH1 0x04              // [gas, offset=4]
    CALLDATALOAD            // [gas, addr=withdrawer]
    PUSH1 0x24              // [gas, addr, offset=36]
    CALLDATALOAD            // [gas, addr, value=amount]
    PUSH1 0x00              // [gas, addr, value, inOff=0]
    PUSH1 0x00              // [gas, addr, value, inOff, inSize=0]
    PUSH1 0x00              // [gas, addr, value, inOff, inSize, outOff=0]
    PUSH1 0x00              // [gas, addr, value, inOff, inSize, outOff, outSize=0]
    CALL                    // [success]

    //   check whether CALL succeeded
    DUP1                    // [success, success]
    ISZERO                  // [success, failed]
    JUMPI @transfer_failed
    POP                     // []

    //   return 1 (success)
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

    //   ===== error handling =====

not_owner:
    JUMPDEST
    REVERT

batch_not_finalized:
    JUMPDEST
    REVERT

already_processed:
    JUMPDEST
    REVERT

proof_failed:
    JUMPDEST
    REVERT

hash_failed:
    JUMPDEST
    REVERT

leaf_hash_failed:
    JUMPDEST
    REVERT

insufficient_liquidity:
    JUMPDEST
    REVERT

transfer_failed:
    JUMPDEST
    REVERT

code_end:

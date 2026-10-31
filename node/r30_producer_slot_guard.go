package node

// R30 F9 (2026-10-30): the producer could seal a block for a slot that is not
// ahead of its own head.
//
// The head may legitimately sit ahead of the local clock: a peer's block up to
// MaxFutureSlotGap slots in the future is accepted on purpose (R38-P0-03, so a
// node with a lagging clock does not split from the network). Sealing on top of
// such a head was never refused, and both halves of the resulting block are
// illegal for every peer:
//
//   - slot < parent slot is rejected by core.BlockValidator (slotGap < 0);
//   - slot == parent slot can never pass the timestamp rules either, because
//     the producer stamps genesisTime + slot*SlotDuration, which is exactly the
//     parent's own timestamp in that case.
//
// The node does not validate its own block, so it adopted the rejected block as
// its head and built further blocks on it: self-inflicted orphaning until a
// re-sync replaced the head. Waiting for the clock is the only correct action —
// nothing can legally extend that parent yet.
//
// Kept as a free function (not inlined) so the rule is testable without a fully
// wired producer, mirroring shouldSkipForStateTrust.
func canExtendHead(slot, parentSlot uint64) bool {
	return slot > parentSlot
}

// skipSlotForBuildState abandons a slot whose build state could not be isolated.
//
// R30 F12 (2026-10-30): its only caller runs inside tryProduceBlock's Phase 1,
// which acquires node.mu on entry and holds it until the heavy work starts. The
// skip used to return to the caller with the lock still held, so one refused
// copy would wedge every goroutine that needs the head (block import, fork
// choice, RPC reads) for the lifetime of the process. The unlock therefore lives
// here, next to the log line, where it cannot be lost when the branch is edited.
func (bp *BlockProducer) skipSlotForBuildState(slot uint64) {
	bp.node.mu.Unlock()
	bpLog.Error("Cannot isolate build state (R7-01); skipping slot %d", slot)
}

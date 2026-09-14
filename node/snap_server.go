// Quantaureum Node source, version 1.0.0.
// Package node — ETHEREUM-PARITY SYNC (2026-08-13): snap/sync server.
//
// SnapServer is the SERVING side of the extended sync protocol. Before this
// component existed, p2p/host.go routed incoming snap requests into
// snapReqCh but NOTHING consumed that channel — a peer asking for snap state
// never got an answer. SnapServer closes that gap and additionally serves
// the Ethereum-parity message kinds added to qau_snap:
//
//   - MsgTypeSnapStateReq    → account export from the committed state
//   - MsgTypeSnapStorageReq  → per-account storage slot export
//   - MsgTypeSnapBytecodeReq → contract bytecode by code hash
//   - MsgTypeHeaderReq       → header-first (skeleton) sync, hash/height
//     origin with skip + reverse (GetBlockHeaders equivalent)
//   - MsgTypeReceiptReq      → receipts grouped by block hash
//
// Design notes:
//
//   - All serving reads committed/persisted data only (stateDB exports,
//     blockStore). The server never blocks block production.
//   - Requests are processed by a small bounded worker pool so one slow
//     export cannot stall other peers; the P2P layer already applies the
//     lenient sync rate limit per peer per type.
//   - Storage requests identify the account by placing the 20-byte address
//     in the low bytes of the 32-byte AccountHash wire field (see
//     EncodeSnapStorageRequest callers in node/syncer.go) — the wire struct
//     predates this server and could not carry an address otherwise.
package node

import (
	"context"
	"sync"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

// snapServerWorkers bounds concurrent request handling (DoS protection).
const snapServerWorkers = 4

// maxSnapServeAccounts caps the TOTAL number of accounts a single account
// export request may stream. AUDIT-FULL H-7 (2026-08-14): serveAccounts
// previously streamed the entire committed state with no overall bound —
// only the per-response batch was capped — letting a peer keep a worker
// busy and memory churn high indefinitely on a large state.
//
// AUDIT-FULL  (2026-08-15): intentionally a package-private const.
// The cap is a DoS-defense budget, not a tunable: 2M accounts × ~110 B
// per SnapAccountData is ~220 MB peak RAM per request, the ceiling chosen
// to bound worst-case memory on a state-of-the-art mainnet-style chain.
// Making it configurable would let operators WEAKEN the bound (or zero it
// out) under the guide of "my peer really does have a bigger state",
// reopening the H-7 memory-exhaustion vector. Any future mainnet growth
// past 2M committed accounts is the trigger to bump this constant in a
// coordinated release; receivers already handle Truncated=true ()
// by aborting the snap sync instead of silently accepting a partial set.
const maxSnapServeAccounts = 2_000_000

// maxSnapServeStorage caps the total slots served for one storage request
// (same rationale as maxSnapServeAccounts — see audit note there).
const maxSnapServeStorage = 2_000_000

// drainAccounts consumes and discards the remainder of an account export so
// the exporter goroutine can finish cleanly. AUDIT-FULL C-2 (2026-08-14):
// the exporter already aborts after a 1s send timeout, but draining lets it
// exit promptly instead of timing out, and protects against future
// exporter changes that could otherwise leak the goroutine.
//
// AUDIT-FULL  (2026-08-15): the inbound drain loop is a plain
// `for range ch` — there is NO hardcoded outbound timeout in this server.
// The "1s" mentioned in the C-2 comment is the EXPORTER-side send timeout
// baked into `state.ExportAccounts` (the producer closes the channel when
// its send exceeds that window). Once the producer closes the channel,
// `for range ch` returns automatically. Adding a server-side drain
// deadline here is a non-goal: the producer always closes in bounded time
// after H-7 truncation sends `drainNow()`, and the drain goroutine only
// exists to consume leftover items in the channel buffer — bounded by the
// SnapAccountExport channel capacity, not unbounded. A server-side drain
// deadline would race the producer and leak the goroutine again (the C-2
// regression). Treatment here is documentation-only.
func drainAccounts(ch <-chan state.SnapAccountExport) {
	for range ch {
	}
}

// drainStorage is the storage-export counterpart of drainAccounts.
func drainStorage(ch <-chan state.SnapStorageExport) {
	for range ch {
	}
}

// SnapServer serves extended sync protocol requests from peers.
type SnapServer struct {
	host       *p2p.Host
	blockStore *block.BlockStore
	stateDB    *state.StateDB

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewSnapServer creates a snap/sync protocol server.
func NewSnapServer(host *p2p.Host, blockStore *block.BlockStore, stateDB *state.StateDB) *SnapServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &SnapServer{
		host:       host,
		blockStore: blockStore,
		stateDB:    stateDB,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start launches the request dispatch loop.
func (s *SnapServer) Start() {
	s.wg.Add(1)
	go s.loop()
}

// Stop terminates the server and waits for workers to exit.
func (s *SnapServer) Stop() {
	s.cancel()
	s.wg.Wait()
}

func (s *SnapServer) loop() {
	defer s.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			syncLog.Error("SnapServer: dispatch loop panic recovered: %v", r)
		}
	}()

	reqCh := s.host.SubscribeSnapRequests()
	sem := make(chan struct{}, snapServerWorkers)

	for {
		select {
		case <-s.ctx.Done():
			return
		case pm, ok := <-reqCh:
			if !ok {
				return
			}
			select {
			case sem <- struct{}{}:
			case <-s.ctx.Done():
				return
			}
			s.wg.Add(1)
			go func(pm p2p.PeerMessage) {
				defer s.wg.Done()
				defer func() { <-sem }()
				defer func() {
					if r := recover(); r != nil {
						syncLog.Error("SnapServer: worker panic recovered: %v", r)
					}
				}()
				s.dispatch(pm)
			}(pm)
		}
	}
}

func (s *SnapServer) dispatch(pm p2p.PeerMessage) {
	switch pm.Type {
	case p2p.MsgTypeSnapStateReq:
		s.serveAccounts(pm)
	case p2p.MsgTypeSnapStorageReq:
		s.serveStorage(pm)
	case p2p.MsgTypeSnapBytecodeReq:
		s.serveBytecode(pm)
	case p2p.MsgTypeHeaderReq:
		s.serveHeaders(pm)
	case p2p.MsgTypeReceiptReq:
		s.serveReceipts(pm)
	default:
		// Legacy SnapRangeReq and unknown types: silently ignored.
	}
}

// send encodes and unicasts a response to the requester.
func (s *SnapServer) send(to p2p.PeerID, msgType uint8, payload []byte) {
	msg, err := p2p.EncodeMessage(msgType, payload)
	if err != nil {
		syncLog.Error("SnapServer: encode %d failed: %v", msgType, err)
		return
	}
	if err := s.host.SendRaw(to, msg); err != nil {
		syncLog.Warn("SnapServer: send %d to %s failed: %v", msgType, to.String()[:16], err)
	}
}

// serveAccounts streams the committed account set in chunks.
// Ethereum parity: this is the GetAccountRange equivalent. We serve the
// state at the server's LAST COMMITTED height and stamp that height into
// every response so the client can verify the state root against the
// matching block header (R12-NODE-002 pattern).
func (s *SnapServer) serveAccounts(pm p2p.PeerMessage) {
	req, err := p2p.DecodeSnapStateRequest(pm.Payload)
	if err != nil {
		return
	}
	if s.stateDB == nil {
		return
	}

	limit := int(req.Limit)
	if limit <= 0 || limit > p2p.MaxSnapAccountsPerResponse {
		limit = p2p.MaxSnapAccountsPerResponse
	}
	height := s.stateDB.LastCommittedHeight()

	accCh, errCh := s.stateDB.ExportAccounts(limit)
	batch := make([]p2p.SnapAccountData, 0, limit)

	// AUDIT-FULL C-2: on any exit path, drain the export channel so the
	// exporter goroutine terminates promptly instead of blocking on sends.
	drained := false
	drainNow := func() {
		if !drained {
			drained = true
			go drainAccounts(accCh)
		}
	}
	defer drainNow()

	// AUDIT-FULL H-7: total cap on accounts served per request.
	served := 0

	flush := func(moreComing bool, truncated bool) {
		if len(batch) == 0 && moreComing {
			return
		}
		resp := &p2p.SnapStateResponse{
			BlockHeight: height,
			Accounts:    batch,
			MoreComing:  moreComing,
			Truncated:   truncated,
		}
		s.send(pm.From, p2p.MsgTypeSnapStateResp, p2p.EncodeSnapStateResponse(resp))
		batch = make([]p2p.SnapAccountData, 0, limit)
	}

	for {
		select {
		case <-s.ctx.Done():
			return
		case acc, ok := <-accCh:
			if !ok {
				flush(false, false) // final chunk, no truncation
				return
			}
			batch = append(batch, p2p.SnapAccountData{Address: acc.Address, Account: acc.Data})
			served++
			if len(batch) >= limit {
				flush(true, false)
			}
			// AUDIT-FULL H-7: stop streaming past the hard cap.
			// FIX (2026-08-15): previously this path sent
			// MoreComing=false, indistinguishable from a clean end-of-stream.
			// Now we set Truncated=true so the receiver can abort the snap
			// sync instead of silently accepting an incomplete account set.
			if served >= maxSnapServeAccounts {
				syncLog.Warn("SnapServer: account export capped at %d accounts for peer %s", served, pm.From.String()[:16])
				drainNow()
				flush(false, true)
				return
			}
		case exportErr := <-errCh:
			if exportErr != nil {
				syncLog.Error("SnapServer: account export failed: %v", exportErr)
				drainNow()
				flush(false, false)
				return
			}
		}
	}
}

// serveStorage streams one account's storage slots.
// The wire AccountHash field carries the 20-byte account address in its low
// bytes (documented in the package comment).
func (s *SnapServer) serveStorage(pm p2p.PeerMessage) {
	req, err := p2p.DecodeSnapStorageRequest(pm.Payload)
	if err != nil {
		return
	}
	if s.stateDB == nil {
		return
	}

	var addr types.Address
	copy(addr[:], req.AccountHash[12:32])

	limit := int(req.Limit)
	if limit <= 0 || limit > p2p.MaxSnapStoragePerResponse {
		limit = p2p.MaxSnapStoragePerResponse
	}
	height := s.stateDB.LastCommittedHeight()

	slotCh, errCh := s.stateDB.ExportStorage(addr, limit)
	batch := make([]p2p.SnapStorageEntry, 0, limit)

	// AUDIT-FULL C-2: drain the export channel on exit (see serveAccounts).
	drained := false
	drainNow := func() {
		if !drained {
			drained = true
			go drainStorage(slotCh)
		}
	}
	defer drainNow()

	// AUDIT-FULL H-7: total cap on slots served per request.
	served := 0

	flush := func(moreComing bool, truncated bool) {
		if len(batch) == 0 && moreComing {
			return
		}
		resp := &p2p.SnapStorageResponse{
			BlockHeight: height,
			AccountHash: req.AccountHash,
			Entries:     batch,
			MoreComing:  moreComing,
			Truncated:   truncated,
		}
		s.send(pm.From, p2p.MsgTypeSnapStorageResp, p2p.EncodeSnapStorageResponse(resp))
		batch = make([]p2p.SnapStorageEntry, 0, limit)
	}

	for {
		select {
		case <-s.ctx.Done():
			return
		case slot, ok := <-slotCh:
			if !ok {
				flush(false, false)
				return
			}
			batch = append(batch, p2p.SnapStorageEntry{Key: slot.Key, Value: slot.Value})
			served++
			if len(batch) >= limit {
				flush(true, false)
			}
			// AUDIT-FULL H-7: stop streaming past the hard cap.
			// FIX (2026-08-15): send Truncated=true so
			// the receiver aborts the snap sync instead of silently
			// accepting an incomplete storage set (storage has NO
			// downstream state-root verification, making this the riskier
			// truncation path).
			if served >= maxSnapServeStorage {
				syncLog.Warn("SnapServer: storage export for %x capped at %d slots", addr[:8], served)
				drainNow()
				flush(false, true)
				return
			}
		case exportErr := <-errCh:
			if exportErr != nil {
				syncLog.Error("SnapServer: storage export for %x failed: %v", addr[:8], exportErr)
				drainNow()
				flush(false, false)
				return
			}
		}
	}
}

// serveBytecode returns contract code for the requested code hashes.
func (s *SnapServer) serveBytecode(pm p2p.PeerMessage) {
	req, err := p2p.DecodeSnapBytecodeRequest(pm.Payload)
	if err != nil {
		return
	}
	if s.stateDB == nil {
		return
	}

	limit := int(req.Limit)
	if limit <= 0 || limit > p2p.MaxSnapBytecodePerResponse {
		limit = p2p.MaxSnapBytecodePerResponse
	}

	entries := make([]p2p.SnapBytecodeEntry, 0, len(req.Hashes))
	for _, h := range req.Hashes {
		if len(entries) >= limit {
			break
		}
		code, cerr := s.stateDB.GetCodeByHash(h)
		if cerr != nil || len(code) == 0 {
			continue // unknown code hash: skip, the client heals via retries
		}
		entries = append(entries, p2p.SnapBytecodeEntry{Hash: h, Code: code})
	}

	resp := &p2p.SnapBytecodeResponse{
		BlockHeight: s.stateDB.LastCommittedHeight(),
		Entries:     entries,
		MoreComing:  false,
	}
	s.send(pm.From, p2p.MsgTypeSnapBytecodeResp, p2p.EncodeSnapBytecodeResponse(resp))
}

// serveHeaders returns block headers for a header-first sync request —
// the GetBlockHeaders equivalent. Supports hash or height origin, skip and
// reverse direction.
func (s *SnapServer) serveHeaders(pm p2p.PeerMessage) {
	req, err := p2p.DecodeHeaderRequest(pm.Payload)
	if err != nil {
		return
	}

	// Resolve the origin to a height.
	var originHeight uint64
	if req.OriginHash != ([32]byte{}) {
		blk, gerr := s.blockStore.GetBlock(types.Hash(req.OriginHash))
		if gerr != nil || blk == nil || blk.Header == nil {
			// Unknown origin: reply empty so the requester tries another peer.
			s.send(pm.From, p2p.MsgTypeHeaderResp, p2p.EncodeHeaderResponse(&p2p.HeaderResponse{RequestID: req.RequestID}))
			return
		}
		originHeight = blk.Header.Height
	} else {
		originHeight = req.OriginHeight
	}

	step := uint64(req.Skip) + 1
	headers := make([][]byte, 0, req.Count)
	for i := uint32(0); i < req.Count; i++ {
		var h uint64
		if req.Reverse {
			if originHeight < uint64(i)*step {
				break // walked past genesis
			}
			h = originHeight - uint64(i)*step
		} else {
			h = originHeight + uint64(i)*step
		}
		blk, gerr := s.blockStore.GetBlockByHeight(h)
		if gerr != nil || blk == nil || blk.Header == nil {
			break // gap or tip reached
		}
		data, merr := encoding.MarshalBlockHeader(blk.Header)
		if merr != nil {
			break
		}
		headers = append(headers, data)
	}

	resp := &p2p.HeaderResponse{RequestID: req.RequestID, Headers: headers}
	s.send(pm.From, p2p.MsgTypeHeaderResp, p2p.EncodeHeaderResponse(resp))
}

// serveReceipts returns all stored receipts of the requested blocks.
func (s *SnapServer) serveReceipts(pm p2p.PeerMessage) {
	req, err := p2p.DecodeReceiptRequest(pm.Payload)
	if err != nil {
		return
	}

	sets := make([]p2p.ReceiptSet, 0, len(req.BlockHashes))
	for _, bh := range req.BlockHashes {
		blk, gerr := s.blockStore.GetBlock(types.Hash(bh))
		if gerr != nil || blk == nil {
			continue
		}
		set := p2p.ReceiptSet{BlockHash: bh}
		for _, tx := range blk.Transactions {
			if tx == nil {
				continue
			}
			receipt, rerr := s.blockStore.GetReceipt(tx.Hash())
			if rerr != nil || receipt == nil {
				continue
			}
			data, merr := encoding.MarshalReceipt(receipt)
			if merr != nil {
				continue
			}
			set.Receipts = append(set.Receipts, data)
		}
		sets = append(sets, set)
	}

	resp := &p2p.ReceiptResponse{RequestID: req.RequestID, Sets: sets}
	s.send(pm.From, p2p.MsgTypeReceiptResp, p2p.EncodeReceiptResponse(resp))
}

// Quantaureum Node source, version 1.0.0.
package node

// Group-key rotation handoff proof (TSS-R3-B-1 Wave F).
//
// The observer side of the v1 rotation lane (consensus/qtd_handoff.go,
// R19-F02 chained adoption) has always demanded the outgoing committee's
// handoff signature over (chainID, epochNew, keyNew, committeeVersion) on any
// boundary anchor that CHANGES the group key — but no production code ever
// produced or embedded one, so every rotation anchor was refused and
// share-less observers structurally failed every group-signed header of the
// rotation epoch (fail-closed, liveness-only). This file closes the producer
// side with three pieces:
//
//  1. PROOF PRODUCTION. At a rotation's activation-exchange convergence — the
//     one point where the NEW key is certified and the OLD share is still the
//     active one on every commit path (fresh-key ceremony park or inline
//     commit, offline-ceremony adoption) — the node runs one ordinary
//     four-signer v1 session (SigningDomainHandoff) over
//     consensus.QTDHandoffMessage with the OUTGOING key's binding, verifies
//     the resulting group signature locally against the outgoing key, and
//     persists it as a per-rotation record beside the activation certificate.
//     A first establishment (no outgoing share) and the R77 same-key reshare
//     (the key does not change) produce no record: their anchors are
//     legitimate without a proof.
//
//  2. PROOF STORAGE. One small record per rotation epoch under the share
//     store's ledger directory (public material — the same bytes ride the
//     public header field). The producer looks a record up by the header's
//     own epoch, so a per-epoch rotation (the experimental runtime-DKG
//     posture rotates every epoch) never confuses two rotations' proofs. A
//     session that failed persists a PENDING record (empty signature): the
//     anchor it would arm is suppressed instead of emitted unprovable.
//
//  3. ANCHOR DISCIPLINE. The producer attaches the record's signature to the
//     header's QTDGroupKeyProof field, and — fail-closed — SUPPRESSES an
//     anchor it cannot prove: a rotation key without a usable proof, and any
//     anchor key that is not the key this node's own ceremony state holds for
//     the header's epoch (the superseded-key quiet rule of the offline
//     re-key, extended from signing to anchoring). A suppressed anchor leaves
//     the un-anchored window open, so the next proven carrier (the same
//     discipline, once the proof exists) seeds the key instead. The
//     first-establishment lane is byte-for-byte unchanged: no predecessor
//     share, no record, plain anchor.
//
// TRUST MODEL. The proof is verified at three points against independent
// inputs: at session completion (against the outgoing active share's key),
// at record load (against the record's own stored outgoing key), and the
// observer repeats the same check under consensus.VerifyAnchoredGroupKeyProof
// with its own custody key — a record that does not verify is never embedded,
// and a header proof that does not verify under the observer's key is refused
// exactly as before this channel existed. No new trust root: the signature is
// produced by the same four-signer session machinery the seals use, under the
// roster-bound share the activation certificate vouches for.

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/quantaureum/qau/consensus"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// tdilithium3HandoffProofMagic prefixes every persisted handoff record.
const tdilithium3HandoffProofMagic = "QTD3HANDOFF"

// tdilithium3HandoffProofVersion is the record encoding version.
const tdilithium3HandoffProofVersion = uint8(1)

// tdilithium3HandoffProofAttempts bounds the handoff session attempts. The
// signer subset rotates with the attempt (the seal round-robin), so a member
// offline for one attempt is excluded from a later one.
const tdilithium3HandoffProofAttempts = 6

// tdilithium3HandoffProofAttemptPause spaces the attempts so members that sat
// an attempt out re-derive the next subset in step. The sessions of distinct
// attempts are independent (session ID binds the attempt nonce), so a loose
// pacing only wastes the budget, never correctness.
const tdilithium3HandoffProofAttemptPause = 2 * time.Second

// tdilithium3HandoffProofKeep bounds how many recent rotation records are
// retained. The producer reads only the header's own epoch (and, for the
// same-key continuation check, the newest record before it), so the last
// three rotations are ample headroom for a restart mid-rotation.
const tdilithium3HandoffProofKeep = 3

// tdilithium3HandoffProofRecord is one rotation's persisted handoff proof.
// An empty Signature marks a PENDING record: the rotation is real (a
// predecessor key existed) but the handoff session did not converge, so the
// rotation's anchors must be suppressed rather than emitted unprovable.
type tdilithium3HandoffProofRecord struct {
	EpochNew         uint64
	CommitteeVersion uint64
	OldKey           []byte
	NewKey           []byte
	Signature        []byte
}

// validate checks the record's shape; it does not verify the signature (the
// callers do that against their own trust inputs).
func (record *tdilithium3HandoffProofRecord) validate() error {
	switch {
	case record == nil:
		return fmt.Errorf("nil handoff proof record")
	case record.EpochNew == 0:
		return fmt.Errorf("handoff proof record has a zero epoch")
	case record.CommitteeVersion == 0:
		return fmt.Errorf("handoff proof record has a zero committee version")
	case len(record.OldKey) != qcrypto.Dilithium3PublicKeySize:
		return fmt.Errorf("handoff proof record outgoing key has %d bytes, want %d", len(record.OldKey), qcrypto.Dilithium3PublicKeySize)
	case len(record.NewKey) != qcrypto.Dilithium3PublicKeySize:
		return fmt.Errorf("handoff proof record incoming key has %d bytes, want %d", len(record.NewKey), qcrypto.Dilithium3PublicKeySize)
	case qcrypto.IsDegeneratePublicKeyBytes(record.OldKey), qcrypto.IsDegeneratePublicKeyBytes(record.NewKey):
		return fmt.Errorf("handoff proof record has a degenerate key")
	case bytes.Equal(record.OldKey, record.NewKey):
		return fmt.Errorf("handoff proof record endorses an unchanged key")
	case len(record.Signature) != 0 && len(record.Signature) != qcrypto.Dilithium3SignatureSize:
		return fmt.Errorf("handoff proof record signature has %d bytes, want %d", len(record.Signature), qcrypto.Dilithium3SignatureSize)
	}
	return nil
}

// encode serializes the record: magic, version, epoch, committee version, the
// two group keys, and the length-prefixed signature (zero length = pending).
func (record *tdilithium3HandoffProofRecord) encode() ([]byte, error) {
	if err := record.validate(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(tdilithium3HandoffProofMagic)+1+8+8+2*qcrypto.Dilithium3PublicKeySize+4+len(record.Signature))
	out = append(out, tdilithium3HandoffProofMagic...)
	out = append(out, tdilithium3HandoffProofVersion)
	out = binary.BigEndian.AppendUint64(out, record.EpochNew)
	out = binary.BigEndian.AppendUint64(out, record.CommitteeVersion)
	out = append(out, record.OldKey...)
	out = append(out, record.NewKey...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(record.Signature)))
	out = append(out, record.Signature...)
	return out, nil
}

// tdilithium3HandoffProofRecordFrom decodes and shape-checks one record.
func tdilithium3HandoffProofRecordFrom(encoded []byte) (*tdilithium3HandoffProofRecord, error) {
	headerLen := len(tdilithium3HandoffProofMagic) + 1 + 8 + 8 + 2*qcrypto.Dilithium3PublicKeySize + 4
	if len(encoded) < headerLen || !bytes.HasPrefix(encoded, []byte(tdilithium3HandoffProofMagic)) {
		return nil, fmt.Errorf("invalid handoff proof record encoding")
	}
	if version := encoded[len(tdilithium3HandoffProofMagic)]; version != tdilithium3HandoffProofVersion {
		return nil, fmt.Errorf("unsupported handoff proof record version %d", version)
	}
	offset := len(tdilithium3HandoffProofMagic) + 1
	record := &tdilithium3HandoffProofRecord{
		EpochNew:         binary.BigEndian.Uint64(encoded[offset:]),
		CommitteeVersion: binary.BigEndian.Uint64(encoded[offset+8:]),
	}
	offset += 16
	record.OldKey = append([]byte(nil), encoded[offset:offset+qcrypto.Dilithium3PublicKeySize]...)
	offset += qcrypto.Dilithium3PublicKeySize
	record.NewKey = append([]byte(nil), encoded[offset:offset+qcrypto.Dilithium3PublicKeySize]...)
	offset += qcrypto.Dilithium3PublicKeySize
	signatureLen := binary.BigEndian.Uint32(encoded[offset:])
	offset += 4
	if signatureLen != uint32(len(encoded)-offset) {
		return nil, fmt.Errorf("handoff proof record signature length mismatch")
	}
	if signatureLen > 0 {
		record.Signature = append([]byte(nil), encoded[offset:]...)
	}
	if err := record.validate(); err != nil {
		return nil, err
	}
	return record, nil
}

// tdilithium3HandoffProofDir returns the directory the rotation records live
// in: beside the activation certificate under the v1 protocol root.
func tdilithium3HandoffProofDir(dataDir string) (string, error) {
	if dataDir == "" {
		return "", fmt.Errorf("handoff proof store requires a data directory")
	}
	paths, err := newThresholdProtocolPaths(dataDir, protocol.ThresholdProtocolDilithium3V1, 1, 1, 1)
	if err != nil {
		return "", err
	}
	return filepath.Join(paths.Root, "ledger", "handoff"), nil
}

// tdilithium3HandoffProofMutex serializes the record directory's writes and
// prunes within this process. Reads are lock-free: every write is atomic
// (temp file + rename), so a reader either sees the previous or the complete
// new record.
var tdilithium3HandoffProofMutex sync.Mutex

// storeTDilithium3HandoffProofRecord persists one rotation record. A record
// for an OLDER epoch than an existing one is refused (rotations move
// forward); a same-epoch rewrite is an idempotent convergence of the same
// session and is accepted when the bytes match, refused otherwise.
func (n *Node) storeTDilithium3HandoffProofRecord(record *tdilithium3HandoffProofRecord) error {
	if n == nil || n.config == nil || record == nil {
		return fmt.Errorf("handoff proof store is not configured")
	}
	if err := record.validate(); err != nil {
		return err
	}
	dir, err := tdilithium3HandoffProofDir(n.config.DataDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	encoded, err := record.encode()
	if err != nil {
		return err
	}
	tdilithium3HandoffProofMutex.Lock()
	defer tdilithium3HandoffProofMutex.Unlock()
	// Monotonic guard: never let a late older rotation overwrite a newer
	// record (a straggler ceremony goroutine must not rewind the store).
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, entry := range entries {
			existingEpoch, ok := tdilithium3HandoffProofEpochFromName(entry.Name())
			if !ok || existingEpoch <= record.EpochNew {
				continue
			}
			return fmt.Errorf("handoff proof record for epoch %d refused: epoch %d already recorded", record.EpochNew, existingEpoch)
		}
	}
	target := filepath.Join(dir, tdilithium3HandoffProofRecordName(record.EpochNew))
	if existing, err := os.ReadFile(target); err == nil {
		if bytes.Equal(existing, encoded) {
			return nil
		}
		// Pending-to-signed upgrade (audit medium): a PENDING record is the
		// strictly weaker state of the SAME rotation — the handoff session
		// ran after the pending write and converged. Accept the rewrite only
		// when the stored record is pending, the rotation identity
		// (epoch, committee version, outgoing key, incoming key) matches the
		// incoming record byte for byte, and the incoming signature verifies
		// under that identity's outgoing key. Every other divergence — an
		// already-signed record with different bytes, or a pending record of
		// a DIFFERENT rotation identity — keeps the refuse guard, so the
		// straggler-rewind and foreign-key protections are unchanged.
		existingRecord, decodeErr := tdilithium3HandoffProofRecordFrom(existing)
		if decodeErr != nil ||
			len(existingRecord.Signature) != 0 ||
			existingRecord.EpochNew != record.EpochNew ||
			existingRecord.CommitteeVersion != record.CommitteeVersion ||
			!bytes.Equal(existingRecord.OldKey, record.OldKey) ||
			!bytes.Equal(existingRecord.NewKey, record.NewKey) ||
			!consensus.VerifyAnchoredGroupKeyProof(record.OldKey, record.NewKey, record.EpochNew, n.config.NetworkID, record.CommitteeVersion, record.Signature) {
			return fmt.Errorf("handoff proof record for epoch %d already exists with different bytes", record.EpochNew)
		}
	}
	if err := atomicWriteThresholdFile(target, encoded); err != nil {
		return err
	}
	n.pruneTDilithium3HandoffProofRecords(dir, record.EpochNew)
	return nil
}

// pruneTDilithium3HandoffProofRecords removes all but the newest
// tdilithium3HandoffProofKeep records at or below the given epoch. Caller
// holds tdilithium3HandoffProofMutex.
func (n *Node) pruneTDilithium3HandoffProofRecords(dir string, epochNew uint64) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	epochs := make([]uint64, 0, len(entries))
	for _, entry := range entries {
		if epoch, ok := tdilithium3HandoffProofEpochFromName(entry.Name()); ok && epoch <= epochNew {
			epochs = append(epochs, epoch)
		}
	}
	slices.Sort(epochs)
	for len(epochs) > tdilithium3HandoffProofKeep {
		_ = os.Remove(filepath.Join(dir, tdilithium3HandoffProofRecordName(epochs[0])))
		epochs = epochs[1:]
	}
}

// tdilithium3HandoffProofRecordName is the per-epoch record file name.
func tdilithium3HandoffProofRecordName(epoch uint64) string {
	return "epoch-" + strconv.FormatUint(epoch, 10) + ".bin"
}

// tdilithium3HandoffProofEpochFromName parses a record file name back to its
// epoch; ok is false for anything else in the directory.
func tdilithium3HandoffProofEpochFromName(name string) (uint64, bool) {
	rest, found := bytes.CutPrefix([]byte(name), []byte("epoch-"))
	if !found {
		return 0, false
	}
	rest, found = bytes.CutSuffix(rest, []byte(".bin"))
	if !found {
		return 0, false
	}
	epoch, err := strconv.ParseUint(string(rest), 10, 64)
	if err != nil || epoch == 0 {
		return 0, false
	}
	return epoch, true
}

// loadTDilithium3HandoffProofRecord reads and fully verifies the record for
// one rotation epoch: shape, key lengths, and the signature itself under the
// record's stored outgoing key. A record that does not verify is reported as
// absent (the anchor decision then fails closed on the rotation-detection
// branch instead of trusting unverified bytes).
func (n *Node) loadTDilithium3HandoffProofRecord(epoch uint64) *tdilithium3HandoffProofRecord {
	if n == nil || n.config == nil || epoch == 0 {
		return nil
	}
	dir, err := tdilithium3HandoffProofDir(n.config.DataDir)
	if err != nil {
		return nil
	}
	encoded, err := os.ReadFile(filepath.Join(dir, tdilithium3HandoffProofRecordName(epoch)))
	if err != nil {
		return nil
	}
	record, err := tdilithium3HandoffProofRecordFrom(encoded)
	if err != nil {
		nodeLog.Warn("Dilithium3 v1 handoff proof record for epoch %d unreadable: %v", epoch, err)
		return nil
	}
	if record.EpochNew != epoch {
		return nil
	}
	if len(record.Signature) == 0 {
		// A pending record is a deliberate state, not corruption: hand it
		// back so the anchor decision can suppress the rotation's anchors.
		return record
	}
	if !consensus.VerifyAnchoredGroupKeyProof(record.OldKey, record.NewKey, record.EpochNew, n.config.NetworkID, record.CommitteeVersion, record.Signature) {
		nodeLog.Warn("Dilithium3 v1 handoff proof record for epoch %d does not verify under its stored outgoing key; ignoring", epoch)
		return nil
	}
	return record
}

// newestTDilithium3HandoffProofRecordBefore returns the verified record of
// the latest rotation strictly before the given epoch, or nil.
func (n *Node) newestTDilithium3HandoffProofRecordBefore(epoch uint64) *tdilithium3HandoffProofRecord {
	if n == nil || n.config == nil || epoch == 0 {
		return nil
	}
	dir, err := tdilithium3HandoffProofDir(n.config.DataDir)
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	newest := uint64(0)
	for _, entry := range entries {
		if recorded, ok := tdilithium3HandoffProofEpochFromName(entry.Name()); ok && recorded < epoch && recorded > newest {
			newest = recorded
		}
	}
	if newest == 0 {
		return nil
	}
	return n.loadTDilithium3HandoffProofRecord(newest)
}

// tdilithium3V1AnchorProofDecision returns the handoff proof an anchor of
// (epoch, key) must carry, and whether the anchor may be embedded at all.
//
// Decision table:
//   - an exact-epoch record endorsing this key: attach its signature, or
//     (pending record) suppress the anchor;
//   - an exact-epoch record endorsing a DIFFERENT key: the header's key is
//     not what the outgoing committee endorsed — suppress;
//   - no exact-epoch record, but a recorded rotation before this epoch whose
//     key differs: a key change without a usable proof — suppress;
//   - otherwise: first establishment or same-key continuation — embed plain.
func (n *Node) tdilithium3V1AnchorProofDecision(epoch uint64, key []byte) (proof []byte, keep bool) {
	if len(key) != qcrypto.Dilithium3PublicKeySize || qcrypto.IsDegeneratePublicKeyBytes(key) {
		return nil, false
	}
	if record := n.loadTDilithium3HandoffProofRecord(epoch); record != nil {
		if !bytes.Equal(record.NewKey, key) {
			return nil, false
		}
		if len(record.Signature) == 0 {
			return nil, false
		}
		return record.Signature, true
	}
	if latest := n.newestTDilithium3HandoffProofRecordBefore(epoch); latest != nil && !bytes.Equal(latest.NewKey, key) {
		return nil, false
	}
	return nil, true
}

// produceTDilithium3HandoffProof runs the rotation handoff for one activation
// exchange convergence. It is called with the candidate share's key BEFORE
// the active share is replaced (park or commit), so the outgoing share is
// still the active one and the ordinary signing binding loads it. A first
// establishment (no outgoing share), an already-active share, and the R77
// same-key reshare (unchanged group key) are quiet no-ops. The outcome is
// always persisted — proof or pending — because the anchor discipline needs
// to distinguish "no rotation" from "rotation whose session failed".
func (n *Node) produceTDilithium3HandoffProof(
	ctx context.Context,
	activationEpoch uint64,
	newKey []byte,
	store *thresholdShareStore,
	password []byte,
) {
	if n == nil || n.config == nil || store == nil || len(password) == 0 || ctx == nil {
		return
	}
	if activationEpoch == 0 || len(newKey) != qcrypto.Dilithium3PublicKeySize || qcrypto.IsDegeneratePublicKeyBytes(newKey) {
		return
	}
	oldEpoch, oldKey, _, err := store.ActiveSharePublicIdentity(password)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			// A probe that failed for any reason other than "no active
			// share" (store lock contention, decryption failure, ledger
			// mismatch) is a real fault, not a rotation shape: log it with
			// the rotation epoch so a missing handoff proof is attributable
			// (audit low). The no-op lane itself is unchanged — fail-closed.
			nodeLog.Warn("Dilithium3 v1 handoff proof probe for epoch %d failed (rotation handoff skipped): %v", activationEpoch, err)
		}
		return
	}
	if oldEpoch == 0 || oldEpoch >= activationEpoch {
		// No outgoing share (first establishment) or an already-active share
		// for this activation: no handoff exists for this rotation shape.
		return
	}
	if bytes.Equal(oldKey, newKey) {
		// The R77 same-key reshare keeps the group key: the observer's
		// chained adoption sees a same-key continuation, no proof required.
		return
	}
	record := &tdilithium3HandoffProofRecord{
		EpochNew:         activationEpoch,
		CommitteeVersion: consensus.QTDAnchorProofCommitteeVersion,
		OldKey:           append([]byte(nil), oldKey...),
		NewKey:           append([]byte(nil), newKey...),
	}
	proof, err := n.runTDilithium3HandoffProofSession(ctx, oldEpoch, activationEpoch, newKey)
	if err != nil {
		// Persist the pending record so the anchor discipline suppresses this
		// rotation's anchors instead of emitting an unprovable one. The
		// rotation itself is unaffected (the shares are committed regardless);
		// only the observer lane degrades, exactly as before this channel.
		nodeLog.Warn("Dilithium3 v1 handoff proof session for epoch %d failed (rotation anchors suppressed): %v", activationEpoch, err)
	} else {
		record.Signature = proof
		nodeLog.Info("Dilithium3 v1 handoff proof recorded for epoch %d (outgoing key prefix %x, incoming key prefix %x)",
			activationEpoch, oldKey[:4], newKey[:4])
	}
	if err := n.storeTDilithium3HandoffProofRecord(record); err != nil {
		nodeLog.Warn("Dilithium3 v1 handoff proof record for epoch %d not persisted: %v", activationEpoch, err)
	}
}

// runTDilithium3HandoffProofSession runs the outgoing committee's handoff
// signing session: one ordinary v1 session over the handoff message for
// (chainID, epochNew, keyNew, committeeVersion), signed by the outgoing key's
// four-signer subset. The inputs are fully public and deterministic, so the
// chosen signers form the session with no announcement round. The result is
// verified locally against the outgoing key before it is returned.
func (n *Node) runTDilithium3HandoffProofSession(
	ctx context.Context,
	oldActivationEpoch, epochNew uint64,
	newKey []byte,
) ([]byte, error) {
	if n == nil || n.config == nil || n.p2pHost == nil || n.blockProducer == nil {
		return nil, fmt.Errorf("Dilithium3 v1 handoff session requires a configured node with a p2p host")
	}
	if oldActivationEpoch == 0 || epochNew == 0 || len(newKey) != qcrypto.Dilithium3PublicKeySize {
		return nil, fmt.Errorf("Dilithium3 v1 handoff session requires a rotation tuple")
	}
	slot := consensus.EpochStartSlot(epochNew)
	message := consensus.QTDHandoffMessage(n.config.NetworkID, epochNew, newKey, consensus.QTDAnchorProofCommitteeVersion)
	// Independent session budget (audit low): the attempts loop is bounded by
	// its OWN deadline — every attempt costs at most one signing slot window
	// (tdilithium3SigningSlotTimeout, the schedule's per-attempt cap) plus the
	// inter-attempt pause, so the budget is the attempts' worst case plus one
	// window of slack. context.WithDeadline propagates the EARLIER of this
	// budget and the caller's own deadline, so the budget only ever CAPS a
	// wider caller (an unbounded or ceremony-length context cannot be eaten
	// by a hung session); it never extends a tighter one. Note the practical
	// consequence, stated plainly: under the fresh-key ceremony's 30-second
	// activation-exchange context the effective attempt count is 1-2, not the
	// nominal six — the park/commit retry cadence of the caller is what
	// recovers a rotation whose session needs more.
	{
		budget := time.Duration(tdilithium3HandoffProofAttempts)*(tdilithium3SigningSlotTimeout+tdilithium3HandoffProofAttemptPause) + tdilithium3SigningSlotTimeout
		budgetContext, cancelBudget := context.WithTimeout(ctx, budget)
		defer cancelBudget()
		ctx = budgetContext
	}
	var lastErr error
	for attempt := uint64(0); attempt < tdilithium3HandoffProofAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		signers, localSigner, err := n.tdilithium3HandoffSigners(oldActivationEpoch, slot, attempt)
		if err != nil {
			lastErr = err
		} else if localSigner {
			signature, err := n.runTDilithium3HandoffProofAttempt(ctx, oldActivationEpoch, signers, epochNew, slot, newKey, message, attempt)
			if err == nil {
				return signature, nil
			}
			lastErr = err
		} else {
			// This member sits the attempt out; a later attempt's subset
			// includes it again (the round-robin covers every pair).
			lastErr = errTDilithium3HandoffNotASigner
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(tdilithium3HandoffProofAttemptPause):
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("handoff session exhausted without an outcome")
	}
	return nil, fmt.Errorf("handoff session failed after %d attempts: %w", tdilithium3HandoffProofAttempts, lastErr)
}

// errTDilithium3HandoffNotASigner reports that this member is not in the
// current attempt's signer subset — a quiet outcome for that attempt.
var errTDilithium3HandoffNotASigner = errors.New("local validator is not one of the handoff signers")

// tdilithium3HandoffSigners resolves the signer subset of one handoff attempt
// over the OUTGOING activation's committee: the same deterministic
// round-robin the seal executor uses, with no stake view (a handoff is not a
// seal; every pair is admissible).
func (n *Node) tdilithium3HandoffSigners(oldActivationEpoch, slot, attempt uint64) ([]uint32, bool, error) {
	rosterEpoch, err := tdilithium3DKGSessionRosterEpoch(oldActivationEpoch)
	if err != nil {
		return nil, false, err
	}
	roster, err := n.capturedEpochValidatorRosterAtOrAfter(rosterEpoch)
	if err != nil {
		return nil, false, err
	}
	committee, _, err := n.tdilithium3DKGCommitteeForRoster(roster)
	if err != nil {
		return nil, false, err
	}
	return tdilithium3SealSigningSignersForRoster(
		roster, committee, n.blockProducer.ValidatorAddr(), slot, attempt,
		tdilithium3SealSigningWeights{},
	)
}

// runTDilithium3HandoffProofAttempt runs one handoff session attempt through
// the ordinary signing binding and schedule, and verifies the resulting group
// signature against the outgoing key before returning it. The binding loads
// the ACTIVE share for the outgoing activation — the caller runs this strictly
// before that share is replaced.
func (n *Node) runTDilithium3HandoffProofAttempt(
	ctx context.Context,
	oldActivationEpoch uint64,
	signers []uint32,
	epochNew, slot uint64,
	newKey, message []byte,
	attempt uint64,
) ([]byte, error) {
	binding, err := n.newTDilithium3SigningBinding(oldActivationEpoch, signers, crand.Reader)
	if err != nil {
		return nil, fmt.Errorf("handoff binding: %w", err)
	}
	defer func() { _ = binding.close() }()
	signature, _, err := n.signWithTDilithium3Signing(
		ctx, binding, epochNew, slot, protocol.SigningDomainHandoff, message, attempt,
	)
	if err != nil {
		return nil, err
	}
	// Verify with the same inputs the observer will use: the outgoing key the
	// binding's share carries (the roster-verified active share of the
	// outgoing activation).
	outgoingKey := binding.Share.Key.PublicKey
	if !consensus.VerifyAnchoredGroupKeyProof(outgoingKey, newKey, epochNew, n.config.NetworkID, consensus.QTDAnchorProofCommitteeVersion, signature) {
		return nil, fmt.Errorf("handoff session signature does not verify under the outgoing key")
	}
	return signature, nil
}

// tdilithium3V1AnchorableKey returns the group key this node's own ceremony
// state holds for the given header epoch — the only key a v1 anchor may
// carry — or nil when nothing anchorable exists. The rule mirrors
// tdilithium3V1HeaderAnchorKey's epoch-membership discipline:
//
//   - experimental runtime-DKG posture: the active share must belong to the
//     header's epoch (a key of an earlier epoch is the outgoing key Wave D
//     refuses to anchor; a key of a later epoch anchors nothing);
//   - offline ceremony posture: the armed ceremony's key — the active share's
//     key while it is usable, otherwise the installed candidate's key. A
//     superseded active share (the re-key quiet rule) never anchors.
func (n *Node) tdilithium3V1AnchorableKey(epoch uint64) []byte {
	if n == nil || n.config == nil {
		return nil
	}
	activation, activeKey, _, identityErr := n.tdilithium3ActiveShareIdentityCached()
	offlineArmed := n.offlineTDilithium3SealingArmed(epoch)
	if offlineArmed {
		armed, armedOK := n.offlineTDilithium3SealingActivation()
		if identityErr == nil && len(activeKey) > 0 && armedOK && activation == armed &&
			!n.offlineTDilithium3ShareSuperseded(activation) {
			return activeKey
		}
		// The active share is superseded or missing: the armed candidate is
		// the only key this node may anchor once the operator armed the epoch.
		if n.config.DataDir == "" || n.config.ValidatorKeyPassword == "" {
			return nil
		}
		candEpoch, candKey, _, _, candErr := newThresholdShareStore(n.config.DataDir).
			CandidateSharePublicIdentity([]byte(n.config.ValidatorKeyPassword))
		if candErr == nil && armedOK && candEpoch == armed {
			return candKey
		}
		return nil
	}
	// Experimental runtime-DKG posture: the anchor key must belong to the
	// header's epoch.
	if identityErr != nil || len(activeKey) == 0 || activation != epoch {
		return nil
	}
	return activeKey
}

// tdilithium3V1GateHeaderAnchor applies the v1 anchor discipline to a header
// whose QTDGroupKey field is already set (the qfs signer-table anchor written
// by PopulateStardustFields): attach the rotation proof, or strip an anchor
// this node cannot vouch for. Anchors on nodes without the v1 posture armed
// for the header's epoch — the legacy GM-QTD signer table — are untouched,
// byte for byte.
func (n *Node) tdilithium3V1GateHeaderAnchor(header *encoding.BlockHeader, slot uint64) {
	if n == nil || header == nil || len(header.QTDGroupKey) == 0 {
		return
	}
	if !n.tdilithium3V1AnchorArmed(header.Epoch) {
		return
	}
	key := header.QTDGroupKey
	want := n.tdilithium3V1AnchorableKey(header.Epoch)
	if len(want) == 0 || !bytes.Equal(want, key) {
		header.QTDGroupKey = nil
		header.QTDGroupKeyProof = nil
		nodeLog.Info("QTD group key anchor suppressed (v1 discipline: key is not this node's anchorable key for the epoch): slot %d epoch %d",
			slot, header.Epoch)
		return
	}
	proof, keep := n.tdilithium3V1AnchorProofDecision(header.Epoch, key)
	if !keep {
		header.QTDGroupKey = nil
		header.QTDGroupKeyProof = nil
		nodeLog.Info("QTD group key anchor suppressed (v1 discipline: rotation without a usable handoff proof): slot %d epoch %d",
			slot, header.Epoch)
		return
	}
	if len(proof) > 0 {
		header.QTDGroupKeyProof = append([]byte(nil), proof...)
		nodeLog.Info("QTD group key rotation proof attached on epoch boundary anchor: slot %d epoch %d", slot, header.Epoch)
	}
}

// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/quantaureum/qau/wallet/tss"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
	"golang.org/x/crypto/scrypt"
)

var (
	errTDilithium3DKGJournalTransition = errors.New("invalid Dilithium3 DKG journal transition")
	errTDilithium3DKGJournalSession    = errors.New("Dilithium3 DKG journal session mismatch")
)

const (
	tdilithium3DKGJournalMagic   = "QTD3JR01"
	tdilithium3DKGJournalScryptN = 1 << 16
	tdilithium3DKGJournalScryptR = 8
	tdilithium3DKGJournalScryptP = 1
)

type tdilithium3DKGStage uint8

const (
	tdilithium3DKGStagePrepared tdilithium3DKGStage = iota + 1
	tdilithium3DKGStageRandomnessComplete
	tdilithium3DKGStageGroupsInProgress
	tdilithium3DKGStageAllGroupsComplete
	tdilithium3DKGStageShareInstalled
	tdilithium3DKGStageAcknowledgementPersisted
)

type tdilithium3DKGGroupStage uint8

const (
	tdilithium3DKGGroupPending tdilithium3DKGGroupStage = iota
	tdilithium3DKGGroupSeedPersisted
	tdilithium3DKGGroupComponentDerived
	tdilithium3DKGGroupContributionVerified
)

type tdilithium3DKGJournalGroup struct {
	GroupMask          dilithium3v1.RSSGroupMask       `json:"group_mask"`
	Stage              tdilithium3DKGGroupStage        `json:"stage"`
	Attempt            uint8                           `json:"attempt"`
	LeaderPosition     uint8                           `json:"leader_position"`
	Seed               [32]byte                        `json:"seed"`
	SeedDigest         [32]byte                        `json:"seed_digest"`
	Component          dilithium3v1.RSSComponent       `json:"component"`
	ComponentDigest    [32]byte                        `json:"component_digest"`
	Contribution       dilithium3v1.PublicContribution `json:"contribution"`
	ContributionDigest [32]byte                        `json:"contribution_digest"`
}

type tdilithium3DKGJournalRecord struct {
	Version               uint16                       `json:"version"`
	SessionDigest         [32]byte                     `json:"session_digest"`
	CommitteeDigest       [32]byte                     `json:"committee_digest"`
	ParticipantPosition   uint8                        `json:"participant_position"`
	ParticipantCount      uint8                        `json:"participant_count"`
	Sequence              uint64                       `json:"sequence"`
	Stage                 tdilithium3DKGStage          `json:"stage"`
	LocalRandomness       [32]byte                     `json:"local_randomness"`
	RandomnessCommitments [][32]byte                   `json:"randomness_commitments,omitempty"`
	CommitmentsPersisted  bool                         `json:"commitments_persisted"`
	GlobalRandomness      [64]byte                     `json:"global_randomness"`
	Rho                   [32]byte                     `json:"rho"`
	Groups                []tdilithium3DKGJournalGroup `json:"groups"`
	PublicKey             [1952]byte                   `json:"public_key"`
	TranscriptDigest      [32]byte                     `json:"transcript_digest"`
}

type tdilithium3DKGJournal struct {
	path     string
	password []byte
	key      [32]byte
	salt     [32]byte
	keyReady bool
	mu       sync.Mutex
}

func newTDilithium3DKGJournal(path string, password []byte) *tdilithium3DKGJournal {
	return &tdilithium3DKGJournal{path: path, password: append([]byte(nil), password...)}
}

func newTDilithium3DKGJournalRecord(sessionDigest, committeeDigest [32]byte, participantPosition uint8, participantCount int) tdilithium3DKGJournalRecord {
	record := tdilithium3DKGJournalRecord{
		Version:             2,
		SessionDigest:       sessionDigest,
		CommitteeDigest:     committeeDigest,
		ParticipantPosition: participantPosition,
		ParticipantCount:    uint8(participantCount),
		Sequence:            1,
		Stage:               tdilithium3DKGStagePrepared,
	}
	groups, err := dilithium3v1.CanonicalRSSGroupsFor(participantCount)
	if err != nil {
		return record
	}
	record.Groups = make([]tdilithium3DKGJournalGroup, len(groups))
	for index, group := range groups {
		record.Groups[index].GroupMask = group
	}
	return record
}

// Clone returns a deep copy; the R76a record keeps slices, so a plain struct
// copy would alias them and leak mutations across the journal transition.
func (record tdilithium3DKGJournalRecord) Clone() tdilithium3DKGJournalRecord {
	record.RandomnessCommitments = append([][32]byte(nil), record.RandomnessCommitments...)
	record.Groups = append([]tdilithium3DKGJournalGroup(nil), record.Groups...)
	return record
}

func (record *tdilithium3DKGJournalRecord) MarkRandomnessCommitments(commitments [][32]byte) error {
	if record == nil || record.Stage != tdilithium3DKGStagePrepared || record.CommitmentsPersisted || len(commitments) != int(record.ParticipantCount) {
		return errTDilithium3DKGJournalTransition
	}
	for _, commitment := range commitments {
		if commitment == ([32]byte{}) {
			return errTDilithium3DKGJournalTransition
		}
	}
	record.RandomnessCommitments = commitments
	record.CommitmentsPersisted = true
	record.Sequence++
	return nil
}

func (record *tdilithium3DKGJournalRecord) MarkRandomnessComplete(global [64]byte, rho [32]byte) error {
	if record == nil || !record.CommitmentsPersisted || record.Stage != tdilithium3DKGStagePrepared || global == ([64]byte{}) || rho == ([32]byte{}) {
		return errTDilithium3DKGJournalTransition
	}
	record.GlobalRandomness = global
	record.Rho = rho
	record.Stage = tdilithium3DKGStageRandomnessComplete
	record.Sequence++
	return nil
}

func (record *tdilithium3DKGJournalRecord) PersistGroupSeed(group dilithium3v1.RSSGroupMask, attempt, leader uint8, seedDigest [32]byte) error {
	if record == nil || record.Stage < tdilithium3DKGStageRandomnessComplete || record.Stage >= tdilithium3DKGStageAllGroupsComplete || seedDigest == ([32]byte{}) {
		return errTDilithium3DKGJournalTransition
	}
	index, err := tdilithium3DKGGroupIndex(group, int(record.ParticipantCount))
	if err != nil {
		return err
	}
	expectedLeader, err := group.Leader(attempt)
	if err != nil || expectedLeader != leader {
		return errTDilithium3DKGJournalTransition
	}
	state := &record.Groups[index]
	if state.Stage != tdilithium3DKGGroupPending {
		if state.Attempt == attempt && state.LeaderPosition == leader && state.SeedDigest == seedDigest {
			return nil
		}
		return errTDilithium3DKGJournalTransition
	}
	state.Attempt = attempt
	state.LeaderPosition = leader
	state.SeedDigest = seedDigest
	state.Stage = tdilithium3DKGGroupSeedPersisted
	record.Stage = tdilithium3DKGStageGroupsInProgress
	record.Sequence++
	return nil
}

func (record *tdilithium3DKGJournalRecord) MarkComponentDerived(group dilithium3v1.RSSGroupMask, componentDigest [32]byte) error {
	index, err := tdilithium3DKGGroupIndex(group, int(record.ParticipantCount))
	if err != nil || record == nil || record.Groups[index].Stage != tdilithium3DKGGroupSeedPersisted || componentDigest == ([32]byte{}) {
		return errTDilithium3DKGJournalTransition
	}
	record.Groups[index].ComponentDigest = componentDigest
	record.Groups[index].Stage = tdilithium3DKGGroupComponentDerived
	record.Sequence++
	return nil
}

func (record *tdilithium3DKGJournalRecord) MarkContributionVerified(group dilithium3v1.RSSGroupMask, contributionDigest [32]byte) error {
	index, err := tdilithium3DKGGroupIndex(group, int(record.ParticipantCount))
	if err != nil || record == nil || record.Groups[index].Stage != tdilithium3DKGGroupComponentDerived || contributionDigest == ([32]byte{}) {
		return errTDilithium3DKGJournalTransition
	}
	record.Groups[index].ContributionDigest = contributionDigest
	record.Groups[index].Stage = tdilithium3DKGGroupContributionVerified
	record.Sequence++
	return nil
}

func (record *tdilithium3DKGJournalRecord) MarkAllGroupsComplete(publicKey [1952]byte, transcriptDigest [32]byte) error {
	if record == nil || record.Stage != tdilithium3DKGStageGroupsInProgress || publicKey == ([1952]byte{}) || transcriptDigest == ([32]byte{}) {
		return errTDilithium3DKGJournalTransition
	}
	for _, group := range record.Groups {
		if group.Stage != tdilithium3DKGGroupContributionVerified {
			return errTDilithium3DKGJournalTransition
		}
	}
	record.PublicKey = publicKey
	record.TranscriptDigest = transcriptDigest
	record.Stage = tdilithium3DKGStageAllGroupsComplete
	record.Sequence++
	return nil
}

func (record *tdilithium3DKGJournalRecord) MarkShareInstalled() error {
	if record == nil || record.Stage != tdilithium3DKGStageAllGroupsComplete {
		return errTDilithium3DKGJournalTransition
	}
	record.Stage = tdilithium3DKGStageShareInstalled
	record.Sequence++
	return nil
}

func (record *tdilithium3DKGJournalRecord) MarkAcknowledgementPersisted() error {
	if record == nil || record.Stage != tdilithium3DKGStageShareInstalled {
		return errTDilithium3DKGJournalTransition
	}
	record.Stage = tdilithium3DKGStageAcknowledgementPersisted
	record.Sequence++
	return nil
}

func (journal *tdilithium3DKGJournal) Store(record tdilithium3DKGJournalRecord) error {
	if journal == nil || journal.path == "" || len(journal.password) == 0 {
		return errTDilithium3DKGJournalTransition
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := validateTDilithium3DKGJournalRecord(record); err != nil {
		return err
	}
	if previous, exists, err := journal.loadUnlocked(); err != nil {
		return err
	} else if exists {
		if err := validateTDilithium3DKGJournalTransition(previous, record); err != nil {
			return err
		}
	} else if record.Sequence != 1 || record.Stage != tdilithium3DKGStagePrepared {
		return errTDilithium3DKGJournalTransition
	}
	plaintext, err := json.Marshal(record)
	if err != nil {
		return err
	}
	defer tss.SecureZero(plaintext)
	encrypted, err := journal.encryptUnlocked(plaintext)
	if err != nil {
		return err
	}
	return atomicWriteThresholdFile(journal.path, encrypted)
}

func (journal *tdilithium3DKGJournal) Load(expectedSessionDigest [32]byte) (tdilithium3DKGJournalRecord, error) {
	if journal == nil || journal.path == "" || len(journal.password) == 0 {
		return tdilithium3DKGJournalRecord{}, errTDilithium3DKGJournalTransition
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	record, exists, err := journal.loadUnlocked()
	if err != nil {
		return tdilithium3DKGJournalRecord{}, err
	}
	if !exists {
		return tdilithium3DKGJournalRecord{}, os.ErrNotExist
	}
	if record.SessionDigest != expectedSessionDigest {
		return tdilithium3DKGJournalRecord{}, errTDilithium3DKGJournalSession
	}
	return record, nil
}

func (journal *tdilithium3DKGJournal) loadUnlocked() (tdilithium3DKGJournalRecord, bool, error) {
	encrypted, err := os.ReadFile(journal.path)
	if os.IsNotExist(err) {
		return tdilithium3DKGJournalRecord{}, false, nil
	}
	if err != nil {
		return tdilithium3DKGJournalRecord{}, false, err
	}
	plaintext, err := journal.decryptUnlocked(encrypted)
	if err != nil {
		return tdilithium3DKGJournalRecord{}, false, err
	}
	defer tss.SecureZero(plaintext)
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	var record tdilithium3DKGJournalRecord
	if err := decoder.Decode(&record); err != nil {
		return tdilithium3DKGJournalRecord{}, false, err
	}
	if err := ensureTDilithium3DKGJSONEOF(decoder); err != nil {
		return tdilithium3DKGJournalRecord{}, false, err
	}
	if err := validateTDilithium3DKGJournalRecord(record); err != nil {
		return tdilithium3DKGJournalRecord{}, false, err
	}
	return record, true, nil
}

func (journal *tdilithium3DKGJournal) encryptUnlocked(plaintext []byte) ([]byte, error) {
	if !journal.keyReady {
		if _, err := io.ReadFull(rand.Reader, journal.salt[:]); err != nil {
			return nil, err
		}
		if err := journal.deriveKeyUnlocked(journal.salt); err != nil {
			return nil, err
		}
	}
	block, err := aes.NewCipher(journal.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, len(tdilithium3DKGJournalMagic)+len(journal.salt)+len(nonce)+len(plaintext)+gcm.Overhead())
	encoded = append(encoded, tdilithium3DKGJournalMagic...)
	encoded = append(encoded, journal.salt[:]...)
	encoded = append(encoded, nonce...)
	encoded = gcm.Seal(encoded, nonce, plaintext, []byte(tdilithium3DKGJournalMagic))
	return encoded, nil
}

func (journal *tdilithium3DKGJournal) decryptUnlocked(encoded []byte) ([]byte, error) {
	const prefixSize = len(tdilithium3DKGJournalMagic) + 32
	if len(encoded) < prefixSize || !bytes.Equal(encoded[:len(tdilithium3DKGJournalMagic)], []byte(tdilithium3DKGJournalMagic)) {
		return nil, fmt.Errorf("invalid Dilithium3 DKG journal encoding")
	}
	var salt [32]byte
	copy(salt[:], encoded[len(tdilithium3DKGJournalMagic):prefixSize])
	if !journal.keyReady {
		if err := journal.deriveKeyUnlocked(salt); err != nil {
			return nil, err
		}
	} else if journal.salt != salt {
		return nil, fmt.Errorf("Dilithium3 DKG journal salt changed")
	}
	block, err := aes.NewCipher(journal.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(encoded) < prefixSize+gcm.NonceSize()+gcm.Overhead() {
		return nil, fmt.Errorf("truncated Dilithium3 DKG journal")
	}
	nonce := encoded[prefixSize : prefixSize+gcm.NonceSize()]
	ciphertext := encoded[prefixSize+gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, []byte(tdilithium3DKGJournalMagic))
}

func (journal *tdilithium3DKGJournal) deriveKeyUnlocked(salt [32]byte) error {
	key, err := scrypt.Key(journal.password, salt[:], tdilithium3DKGJournalScryptN, tdilithium3DKGJournalScryptR, tdilithium3DKGJournalScryptP, len(journal.key))
	if err != nil {
		return err
	}
	copy(journal.key[:], key)
	tss.SecureZero(key)
	journal.salt = salt
	journal.keyReady = true
	return nil
}

func ensureTDilithium3DKGJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("unexpected trailing journal value")
		}
		return err
	}
	return nil
}

func validateTDilithium3DKGJournalRecord(record tdilithium3DKGJournalRecord) error {
	groups, err := dilithium3v1.CanonicalRSSGroupsFor(int(record.ParticipantCount))
	if err != nil || record.Version != 2 || record.SessionDigest == ([32]byte{}) || record.CommitteeDigest == ([32]byte{}) || record.ParticipantPosition >= record.ParticipantCount || record.Sequence == 0 || record.Stage < tdilithium3DKGStagePrepared || record.Stage > tdilithium3DKGStageAcknowledgementPersisted {
		return errTDilithium3DKGJournalTransition
	}
	if !record.CommitmentsPersisted {
		if len(record.RandomnessCommitments) != 0 || record.Stage != tdilithium3DKGStagePrepared {
			return errTDilithium3DKGJournalTransition
		}
	} else {
		if len(record.RandomnessCommitments) != int(record.ParticipantCount) {
			return errTDilithium3DKGJournalTransition
		}
		for _, commitment := range record.RandomnessCommitments {
			if commitment == ([32]byte{}) {
				return errTDilithium3DKGJournalTransition
			}
		}
	}
	if len(record.Groups) != len(groups) {
		return errTDilithium3DKGJournalTransition
	}
	for index, group := range record.Groups {
		if group.GroupMask != groups[index] || group.Stage > tdilithium3DKGGroupContributionVerified {
			return errTDilithium3DKGJournalTransition
		}
	}
	return nil
}

func validateTDilithium3DKGJournalTransition(previous, next tdilithium3DKGJournalRecord) error {
	if next.SessionDigest != previous.SessionDigest || next.CommitteeDigest != previous.CommitteeDigest || next.ParticipantPosition != previous.ParticipantPosition || next.ParticipantCount != previous.ParticipantCount || next.Version != previous.Version || next.Sequence != previous.Sequence+1 || next.Stage < previous.Stage || next.Stage > previous.Stage+1 {
		return errTDilithium3DKGJournalTransition
	}
	if next.LocalRandomness != previous.LocalRandomness ||
		(previous.Stage >= tdilithium3DKGStageRandomnessComplete && (next.GlobalRandomness != previous.GlobalRandomness || next.Rho != previous.Rho)) ||
		(previous.Stage >= tdilithium3DKGStageAllGroupsComplete && (next.PublicKey != previous.PublicKey || next.TranscriptDigest != previous.TranscriptDigest)) {
		return errTDilithium3DKGJournalTransition
	}
	if previous.CommitmentsPersisted {
		if !next.CommitmentsPersisted || !tdilithium3DKGCommitmentsEqual(next.RandomnessCommitments, previous.RandomnessCommitments) {
			return errTDilithium3DKGJournalTransition
		}
	} else if next.CommitmentsPersisted && (previous.Stage != tdilithium3DKGStagePrepared || next.Stage != tdilithium3DKGStagePrepared) {
		return errTDilithium3DKGJournalTransition
	}
	if len(previous.Groups) != len(next.Groups) {
		return errTDilithium3DKGJournalTransition
	}
	for index := range previous.Groups {
		oldGroup := previous.Groups[index]
		newGroup := next.Groups[index]
		if newGroup.GroupMask != oldGroup.GroupMask || newGroup.Stage < oldGroup.Stage || newGroup.Stage > oldGroup.Stage+1 {
			return errTDilithium3DKGJournalTransition
		}
		if oldGroup.Stage >= tdilithium3DKGGroupSeedPersisted && (newGroup.Attempt != oldGroup.Attempt || newGroup.LeaderPosition != oldGroup.LeaderPosition || newGroup.SeedDigest != oldGroup.SeedDigest || newGroup.Seed != oldGroup.Seed) {
			return errTDilithium3DKGJournalTransition
		}
		if oldGroup.Stage >= tdilithium3DKGGroupComponentDerived && (newGroup.ComponentDigest != oldGroup.ComponentDigest || newGroup.Component != oldGroup.Component) {
			return errTDilithium3DKGJournalTransition
		}
		if oldGroup.Stage >= tdilithium3DKGGroupContributionVerified && (newGroup.ContributionDigest != oldGroup.ContributionDigest || newGroup.Contribution != oldGroup.Contribution) {
			return errTDilithium3DKGJournalTransition
		}
	}
	return nil
}

func tdilithium3DKGGroupIndex(group dilithium3v1.RSSGroupMask, participants int) (int, error) {
	groups, err := dilithium3v1.CanonicalRSSGroupsFor(participants)
	if err != nil {
		return 0, errTDilithium3DKGJournalTransition
	}
	for index, candidate := range groups {
		if candidate == group {
			return index, nil
		}
	}
	return 0, errTDilithium3DKGJournalTransition
}

func tdilithium3DKGCommitmentsEqual(a, b [][32]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

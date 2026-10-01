// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"math"
	"math/bits"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// TestThresholdSigningRejectsThreeShareSubsets requires no three-member subset
// to reconstruct the aggregate secret: the three positions outside every
// subset form a group none of them holds, so three participants can never
// reach a signing round.
func TestThresholdSigningRejectsThreeShareSubsets(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	rejected := 0
	for mask := uint8(0); mask < 1<<6; mask++ {
		if bits.OnesCount8(mask) != 3 {
			continue
		}
		var subset []*LocalShare
		for position, share := range fixture.shares {
			if mask&(1<<position) != 0 {
				subset = append(subset, share)
			}
		}
		if _, _, err := reconstructAggregateSecret(subset); !errors.Is(err, errInvalidSigningAttempt) {
			t.Fatalf("mask %06b: aggregate secret reconstructed from three shares", mask)
		}
		rejected++
	}
	if rejected != 20 {
		t.Fatalf("rejected %d three-member subsets, want 20", rejected)
	}
}

// TestThresholdSigningAttemptRejectsInvalidBindings requires the round-0 validation to
// reject every malformed request, share, and randomness input before anything
// is persisted.
func TestThresholdSigningAttemptRejectsInvalidBindings(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	journal := signingTestJournal(t)
	request := fixture.requestFor([]byte(signingInteropTestMessage))
	active := fixture.activeShares(t, 0b001111)
	if _, err := newSigningAttempt(
		journal, mpcTestRecord(t, 0x71), request.Clone(), active,
		signingTestCoordinator, signingTestRandomnessFor(t, 0x70),
	); err != nil {
		t.Fatalf("baseline attempt: %v", err)
	}

	type arguments struct {
		journal     *SigningJournal
		record      *PreprocessingRecord
		request     protocol.SignRequest
		active      []*LocalShare
		coordinator uint32
		randomness  [4]*signingRandomness
	}
	baseline := func(t *testing.T) arguments {
		t.Helper()
		return arguments{
			journal:     journal,
			record:      mpcTestRecord(t, 0x73),
			request:     request.Clone(),
			active:      fixture.activeShares(t, 0b001111),
			coordinator: signingTestCoordinator,
			randomness:  signingTestRandomnessFor(t, 0x72),
		}
	}
	cases := []struct {
		name   string
		mutate func(t *testing.T, args *arguments)
	}{
		{name: "missing journal", mutate: func(t *testing.T, args *arguments) { args.journal = nil }},
		{name: "missing record", mutate: func(t *testing.T, args *arguments) { args.record = nil }},
		{name: "three signers", mutate: func(t *testing.T, args *arguments) { args.active = args.active[:3] }},
		{name: "five signers", mutate: func(t *testing.T, args *arguments) {
			args.active = append(args.active, fixture.shares[4])
		}},
		{name: "unsorted signers", mutate: func(t *testing.T, args *arguments) {
			args.active[1], args.active[2] = args.active[2], args.active[1]
		}},
		{name: "duplicate signer", mutate: func(t *testing.T, args *arguments) { args.active[1] = args.active[0] }},
		{name: "nil share", mutate: func(t *testing.T, args *arguments) { args.active[2] = nil }},
		{name: "foreign signer", mutate: func(t *testing.T, args *arguments) {
			foreign := fixture.shares[0].Clone()
			foreign.ParticipantID = 9
			args.active[0] = foreign
		}},
		{name: "foreign key generation", mutate: func(t *testing.T, args *arguments) { args.request.Key.Generation++ }},
		{name: "early epoch", mutate: func(t *testing.T, args *arguments) {
			args.request.Epoch = fixture.shares[0].ActivationEpoch - 1
		}},
		{name: "legacy context", mutate: func(t *testing.T, args *arguments) {
			args.request.Context = []byte("mode3 context")
		}},
		{name: "zero coordinator", mutate: func(t *testing.T, args *arguments) { args.coordinator = 0 }},
		{name: "foreign rho", mutate: func(t *testing.T, args *arguments) {
			cloned := fixture.shares[0].Clone()
			cloned.Rho = [32]byte{0xEE}
			args.active[0] = cloned
		}},
		{name: "nil randomness", mutate: func(t *testing.T, args *arguments) { args.randomness[0] = nil }},
		{name: "randomness outside the sampling ball", mutate: func(t *testing.T, args *arguments) {
			cloned := *args.randomness[1]
			cloned.raw[0] = 2 * SigningRandomnessSampleRadius
			args.randomness[1] = &cloned
		}},
		{name: "randomness outside the ball, attacked elsewhere", mutate: func(t *testing.T, args *arguments) {
			cloned := *args.randomness[1]
			cloned.raw[signingRandomnessDimension-1] = SigningRandomnessSampleRadius
			cloned.roundFromRaw()
			args.randomness[1] = &cloned
		}},
		{name: "expansion mismatch", mutate: func(t *testing.T, args *arguments) {
			cloned := *args.randomness[2]
			cloned.first[0][0] = Normalize(cloned.first[0][0] + 1)
			args.randomness[2] = &cloned
		}},
		{name: "non-canonical expansion", mutate: func(t *testing.T, args *arguments) {
			cloned := *args.randomness[3]
			cloned.second[0][0] = Coefficient(-1)
			args.randomness[3] = &cloned
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			args := baseline(t)
			testCase.mutate(t, &args)
			if _, err := newSigningAttempt(
				args.journal, args.record, args.request,
				args.active, args.coordinator, args.randomness,
			); !errors.Is(err, errInvalidSigningAttempt) {
				t.Fatalf("error = %v, want %v", err, errInvalidSigningAttempt)
			}
		})
	}
}

// TestThresholdSigningAttemptOutOfOrderCallsBurn requires a round called out of order to
// burn the attempt, its one-time record, and its journal entry.
func TestThresholdSigningAttemptOutOfOrderCallsBurn(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	journal := signingTestJournal(t)
	request := fixture.requestFor([]byte(signingInteropTestMessage))
	active := fixture.activeShares(t, 0b001111)

	record := mpcTestRecord(t, 0x74)
	attempt, err := newSigningAttempt(
		journal, record, request.Clone(), active, signingTestCoordinator, signingTestRandomnessFor(t, 0x75),
	)
	if err != nil {
		t.Fatalf("newSigningAttempt(): %v", err)
	}
	if _, err := attempt.commit(); !errors.Is(err, errInvalidSigningState) {
		t.Fatalf("commit before prepare error = %v, want %v", err, errInvalidSigningState)
	}
	assertSigningBurned(t, journal, attempt, record)
	if err := attempt.prepare(); !errors.Is(err, errInvalidSigningState) {
		t.Fatalf("prepare after burn error = %v, want %v", err, errInvalidSigningState)
	}

	duplicateRequest := request.Clone()
	duplicateRequest.AttemptNonce = [32]byte{0x99}
	record = mpcTestRecord(t, 0x76)
	attempt, err = newSigningAttempt(
		journal, record, duplicateRequest, active, signingTestCoordinator, signingTestRandomnessFor(t, 0x77),
	)
	if err != nil {
		t.Fatalf("newSigningAttempt(): %v", err)
	}
	if err := attempt.prepare(); err != nil {
		t.Fatalf("prepare(): %v", err)
	}
	if err := attempt.prepare(); !errors.Is(err, errInvalidSigningState) {
		t.Fatalf("duplicate prepare error = %v, want %v", err, errInvalidSigningState)
	}
	assertSigningBurned(t, journal, attempt, record)
}

// assertSigningBurned requires the attempt, its record, and its journal entry
// to be burned for the attempt's session.
func assertSigningBurned(
	t *testing.T,
	journal *SigningJournal,
	attempt *signingAttempt,
	record *PreprocessingRecord,
) {
	t.Helper()
	if attempt.state != signingStateBurned {
		t.Fatalf("attempt state = %s, want burned", attempt.state)
	}
	if record.State() != PreprocessingBurned {
		t.Fatalf("record state = %v, want burned", record.State())
	}
	journalRecord, found, err := journal.Read(attempt.sessionID)
	if err != nil || !found {
		t.Fatalf("journal read: found=%v err=%v", found, err)
	}
	if journalRecord.State != protocol.SingleUseBurned {
		t.Fatalf("journal state = %v, want burned", journalRecord.State)
	}
}

// TestThresholdSigningAttemptChallengeBindsMessageSessionAndCoordinator requires the
// attempt binding to cover the message, the attempt nonce, and the coordinator
// identity, and the challenge to depend on the message through mu.
func TestThresholdSigningAttemptChallengeBindsMessageSessionAndCoordinator(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	active := fixture.activeShares(t, 0b001111)
	randomness := signingTestRandomnessFor(t, 0x7A)
	run := func(label byte, message []byte, coordinator uint32, attemptNonce [32]byte) ([32]byte, [CTildeSize]byte) {
		t.Helper()
		request := fixture.requestFor(message)
		request.AttemptNonce = attemptNonce
		attempt, err := newSigningAttempt(
			signingTestJournal(t), mpcTestRecord(t, label), request, active, coordinator, randomness,
		)
		if err != nil {
			t.Fatalf("newSigningAttempt(): %v", err)
		}
		if err := attempt.prepare(); err != nil {
			t.Fatalf("prepare(): %v", err)
		}
		if _, err := attempt.commit(); err != nil {
			t.Fatalf("commit(): %v", err)
		}
		challenge, err := attempt.challenge()
		if err != nil {
			t.Fatalf("challenge(): %v", err)
		}
		return attempt.bindingDigest, challenge.Challenge
	}
	nonce := [32]byte{1, 2, 3}
	baseBinding, baseChallenge := run(0x80, []byte(signingInteropTestMessage), signingTestCoordinator, nonce)
	againBinding, againChallenge := run(0x81, []byte(signingInteropTestMessage), signingTestCoordinator, nonce)
	if baseBinding != againBinding || baseChallenge != againChallenge {
		t.Fatal("challenge round is not deterministic")
	}
	if otherBinding, otherChallenge := run(
		0x82, []byte(signingRejectionTestMessage), signingTestCoordinator, nonce,
	); otherBinding == baseBinding || otherChallenge == baseChallenge {
		t.Fatal("message is not bound into the attempt and the challenge")
	}
	if otherBinding, _ := run(
		0x83, []byte(signingInteropTestMessage), signingTestCoordinator, [32]byte{9},
	); otherBinding == baseBinding {
		t.Fatal("attempt nonce is not bound into the attempt")
	}
	if otherBinding, _ := run(
		0x84, []byte(signingInteropTestMessage), 4, nonce,
	); otherBinding == baseBinding {
		t.Fatal("coordinator identity is not bound into the attempt")
	}
}

// TestThresholdSigningAttemptRejectionBurnsAndRetrySucceeds requires a local
// rejection and a failed public combine check to burn the attempt without
// releasing a response, and a retry with a fresh journal, record, and slot to
// produce an accepted signature.
func TestThresholdSigningAttemptRejectionBurnsAndRetrySucceeds(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	active := fixture.activeShares(t, 0b001111)
	request := fixture.requestFor([]byte(signingRejectionTestMessage))
	reasons := []string{"local rejection", "hint weight"}
	for index, reason := range reasons {
		t.Run(reason, func(t *testing.T) {
			journal := signingTestJournal(t)
			source := rand.New(rand.NewSource(int64(0x90 + index)))
			for slot := 1; slot <= signingTestAttemptLimit; slot++ {
				slotRequest := request.Clone()
				slotRequest.AttemptNonce[0] = byte(slot)
				slotRequest.AttemptNonce[1] = byte(slot >> 8)
				record := signingTestAttemptRecord(t, slot)
				attempt, err := newSigningAttempt(
					journal, record, slotRequest, active, signingTestCoordinator,
					signingTestAttemptRandomness(t, source),
				)
				if err != nil {
					t.Fatalf("slot %d: newSigningAttempt(): %v", slot, err)
				}
				if err := attempt.prepare(); err != nil {
					t.Fatalf("slot %d: prepare(): %v", slot, err)
				}
				if _, err := attempt.commit(); err != nil {
					t.Fatalf("slot %d: commit(): %v", slot, err)
				}
				if _, err := attempt.challenge(); err != nil {
					t.Fatalf("slot %d: challenge(): %v", slot, err)
				}
				response, err := attempt.respond()
				if err != nil {
					if !errors.Is(err, errSigningRejected) {
						t.Fatalf("slot %d: respond(): %v", slot, err)
					}
					if reason != "local rejection" || !strings.Contains(err.Error(), reason) {
						continue
					}
					if response != (signingResponse{}) {
						t.Fatal("a rejected slot returned a response")
					}
					assertSigningBurned(t, journal, attempt, record)
					if _, err := attempt.finalize(); !errors.Is(err, errInvalidSigningState) {
						t.Fatalf("finalize after rejection error = %v, want %v", err, errInvalidSigningState)
					}
					return
				}
				if _, err := attempt.finalize(); err != nil {
					if !errors.Is(err, errSigningRejected) {
						t.Fatalf("slot %d: finalize(): %v", slot, err)
					}
					if !strings.Contains(err.Error(), reason) {
						continue
					}
					assertSigningBurned(t, journal, attempt, record)
					return
				}
				// This slot produced a signature; probe the next slot instead.
				continue
			}
			t.Fatalf("no %s rejection in %d slots", reason, signingTestAttemptLimit)
		})
	}

	// A retry with a fresh journal, record, and slot signs successfully.
	retryFixture := signingTestFixtureFor(t)
	journal := signingTestJournal(t)
	retryRequest := retryFixture.requestFor([]byte(signingInteropTestMessage))
	slot, attempts, rejections := signingTestSign(
		t, journal, retryRequest, retryFixture.activeShares(t, 0b001111), rand.New(rand.NewSource(0x95)),
	)
	if slot.attempt.state != signingStateFinalized {
		t.Fatalf("retry state = %s, want finalized", slot.attempt.state)
	}
	if attempts != rejections+1 {
		t.Fatalf("retry ran %d attempts with %d rejections", attempts, rejections)
	}
	if err := qcrypto.VerifySignatureForAlgorithm(
		retryFixture.key.Algorithm, retryFixture.key.PublicKey, retryRequest.Message, nil, slot.signature,
	); err != nil {
		t.Fatalf("retry signature verification: %v", err)
	}
}

// TestThresholdSigningRequestCostEnvelope pins the post-R57 cost envelope and
// re-derives the pinned hyperball parameters from their definitions, so the
// numbers in the design note stay reproducible without Monte Carlo. The
// retired pre-R57 envelope (877822 shared multiplications and 1770238 openings
// per accepted attempt) is recorded in the design note as history.
func TestThresholdSigningRequestCostEnvelope(t *testing.T) {
	// The design note's envelope uses the reference packing: 23 bits per w
	// coefficient and 20 bits per response coefficient. The driver's local
	// hashing encodings are PolyEncodedSize and ZEncodedSize; the wire format is
	// fixed by the executor slice.
	slotWireBytes := 32 + K*N*23/8 + L*N*20/8
	if slotWireBytes != 7648 {
		t.Fatalf("per-slot wire bytes = %d, want 7648", slotWireBytes)
	}
	if requestWireBytes := 32 + SigningParallelSlots*(K*N*23/8+L*N*20/8); requestWireBytes != 83808 {
		t.Fatalf("per-request wire bytes = %d, want 83808", requestWireBytes)
	}
	if PolyEncodedSize != 768 || ZEncodedSize != 640 {
		t.Fatalf("local encodings = %d/%d, want 768/640", PolyEncodedSize, ZEncodedSize)
	}
	if SigningParallelSlots != 11 {
		t.Fatalf("parallel slots = %d, want 11", SigningParallelSlots)
	}
	perSlot := math.Pow(2, -SigningRandomnessExponent)
	if math.Abs(perSlot-0.10153) > 5e-5 {
		t.Fatalf("per-slot acceptance = %.5f, want 0.10153", perSlot)
	}
	divergence := SigningRandomnessDivergence()
	if math.Abs(divergence-1.7715) > 5e-4 {
		t.Fatalf("divergence M = %.4f, want 1.7715", divergence)
	}
	sigma := math.Sqrt((math.Pow(2*RSSComponentEta+1, 2) - 1) / 12)
	nu := float64(SigningRandomnessNu)
	body := (float64(K) + float64(L)/(nu*nu)) * float64(N) * 5
	wantShift := 1.3 * math.Sqrt(body) * sigma * math.Sqrt(float64(Tau))
	if math.Abs(wantShift-SigningShiftBound) > 0.02 {
		t.Fatalf("shift bound = %.2f, want %.2f", SigningShiftBound, wantShift)
	}
	phi := float64(SigningRandomnessPhi)
	delta := math.Pow(divergence, 2.0/float64(signingRandomnessDimension)) - 1
	slack := (1/phi + math.Sqrt(1/(phi*phi)+delta)) / delta
	// The derivation yields exact radii that meet the lemma with equality; the
	// pinned constants are those values rounded to 0.1 for the design note, so
	// the closeness check absorbs the rounding and the lemma is checked on the
	// exact values.
	exactRadius := slack * wantShift
	exactSample := math.Pow(divergence, 1.0/float64(signingRandomnessDimension)) * exactRadius
	if math.Abs(exactRadius-SigningRandomnessRadius) > 5 {
		t.Fatalf("test radius r = %.1f, want %.1f", SigningRandomnessRadius, exactRadius)
	}
	if math.Abs(exactSample-SigningRandomnessSampleRadius) > 5 {
		t.Fatalf("sampling radius r' = %.1f, want %.1f", SigningRandomnessSampleRadius, exactSample)
	}
	upper := exactSample * exactSample
	lower := exactRadius*exactRadius + wantShift*wantShift + 2*exactRadius*wantShift/phi
	if upper+1 < lower {
		t.Fatalf("rejection lemma inequality violated: r'^2 = %.1f < %.1f", upper, lower)
	}
}

// TestThresholdSigningSlotAcceptanceBand requires the constructed per-slot
// acceptance rate to stay in the band the parameter derivation predicts. The
// per-party acceptance model is 1/M = 0.5645 and the measured per-party rate
// is 0.5759, so the per-slot rate is about 0.10; the band is deliberately wide
// because this is a regression guard for the sampler and the rejection test,
// not a precise pin.
func TestThresholdSigningSlotAcceptanceBand(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	journal := signingTestJournal(t)
	request := fixture.requestFor([]byte(signingInteropTestMessage))
	active := fixture.activeShares(t, 0b001111)
	source := rand.New(rand.NewSource(0xACCE))
	const slots = 200
	accepted := 0
	for slot := 1; slot <= slots; slot++ {
		slotRequest := request.Clone()
		slotRequest.AttemptNonce[0] = byte(slot)
		slotRequest.AttemptNonce[1] = byte(slot >> 8)
		attempt, err := newSigningAttempt(
			journal, signingTestAttemptRecord(t, slot), slotRequest, active,
			signingTestCoordinator, signingTestAttemptRandomness(t, source),
		)
		if err != nil {
			t.Fatalf("slot %d: newSigningAttempt(): %v", slot, err)
		}
		if err := attempt.prepare(); err != nil {
			t.Fatalf("slot %d: prepare(): %v", slot, err)
		}
		if _, err := attempt.commit(); err != nil {
			t.Fatalf("slot %d: commit(): %v", slot, err)
		}
		if _, err := attempt.challenge(); err != nil {
			t.Fatalf("slot %d: challenge(): %v", slot, err)
		}
		if _, err := attempt.respond(); err == nil {
			accepted++
		} else if !errors.Is(err, errSigningRejected) {
			t.Fatalf("slot %d: respond(): %v", slot, err)
		}
	}
	rate := float64(accepted) / slots
	if rate < 0.025 || rate > 0.22 {
		t.Fatalf("per-slot acceptance %.4f outside the predicted band [0.025, 0.22]", rate)
	}
}

// TestThresholdSigningAttemptLeavesNoSecretArtifacts requires the public artifacts to
// carry no share or randomness type, and the published round values to be
// exactly the public equations the design note fixes: the committed w is the
// sum of the revealed MLWE shares, w1 = HighBits(w), and the aggregate
// response is the sum of the accepted per-signer response parts.
func TestThresholdSigningAttemptLeavesNoSecretArtifacts(t *testing.T) {
	secretTypes := []reflect.Type{
		reflect.TypeOf(LocalShare{}),
		reflect.TypeOf(RSSComponent{}),
		reflect.TypeOf(SecretHandle{}),
		reflect.TypeOf(PreprocessingID{}),
		reflect.TypeOf(VectorL{}),
		reflect.TypeOf(VectorK{}),
		reflect.TypeOf(Poly{}),
		reflect.TypeOf(signingRandomness{}),
		reflect.TypeOf([4]*signingRandomness{}),
		reflect.TypeOf(sharedPoly{}),
		reflect.TypeOf(sharedCoefficient{}),
		reflect.TypeOf(sharedPolyNTT{}),
		reflect.TypeOf(mpcArithmeticEngine{}),
	}
	assertNoSecretFields(t, signingCommitment{}, secretTypes...)
	assertNoSecretFields(t, signingChallenge{}, secretTypes...)
	assertNoSecretFields(t, signingResponse{}, secretTypes...)
	assertNoSecretFields(t, protocol.SingleUseRecord{}, secretTypes...)

	fixture := signingTestFixtureFor(t)
	journal := signingTestJournal(t)
	request := fixture.requestFor([]byte(signingInteropTestMessage))
	active := fixture.activeShares(t, 0b001111)
	slot, _, _ := signingTestSign(t, journal, request, active, rand.New(rand.NewSource(0xA5)))
	for _, point := range slot.randomness {
		if err := validateSigningRandomness(point); err != nil {
			t.Fatalf("accepted randomness is invalid: %v", err)
		}
	}

	var wantW VectorK
	for index := range slot.randomness {
		contribution, err := ComputePublicVector(
			fixture.rho, slot.randomness[index].first, slot.randomness[index].second,
		)
		if err != nil {
			t.Fatalf("ComputePublicVector(): %v", err)
		}
		for row := 0; row < K; row++ {
			wantW[row] = Add(wantW[row], contribution[row])
		}
	}
	if slot.attempt.w != wantW {
		t.Fatal("committed w is not the sum of the revealed commitment shares")
	}
	var wantHigh VectorK
	for row := 0; row < K; row++ {
		wantHigh[row] = HighBits(wantW[row])
	}
	if slot.attempt.highBits != wantHigh {
		t.Fatal("committed w1 is not HighBits(w)")
	}

	var wantZ [L]SignedPoly
	var sumFirst VectorL
	var sumSecond VectorK
	for index := range slot.attempt.partialFirst {
		for row := 0; row < L; row++ {
			product := MultiplyPolynomials(slot.attempt.challengeValue, slot.attempt.partialFirst[index][row])
			rounded := slot.randomness[index].first[row]
			for coefficient := 0; coefficient < N; coefficient++ {
				wantZ[row][coefficient] += CenteredCoefficient(product[coefficient]) +
					CenteredCoefficient(rounded[coefficient])
			}
			sumFirst[row] = Add(sumFirst[row], slot.attempt.partialFirst[index][row])
		}
		for row := 0; row < K; row++ {
			sumSecond[row] = Add(sumSecond[row], slot.attempt.partialSecond[index][row])
		}
	}
	if slot.attempt.z != wantZ {
		t.Fatal("aggregate response is not the sum of the accepted response parts")
	}
	if sumFirst != fixture.s1 || sumSecond != fixture.s2 {
		t.Fatal("partial secrets do not reconstruct the aggregate secret")
	}
}

// signingTestAcceptedRandomness returns four ball points whose slot response is
// accepted. It probes through the reference driver with throwaway journals,
// because the challenge and the rejection test both depend on the sampled
// points.
func signingTestAcceptedRandomness(
	t *testing.T,
	fixture *signingTestFixture,
	active []*LocalShare,
	request protocol.SignRequest,
	source *rand.Rand,
) [4]*signingRandomness {
	t.Helper()
	probeJournal := signingTestJournal(t)
	for probe := 1; probe <= signingTestAttemptLimit; probe++ {
		randomness := signingTestAttemptRandomness(t, source)
		probeRequest := request.Clone()
		probeRequest.AttemptNonce[0] = byte(probe)
		probeRequest.AttemptNonce[1] = byte(probe >> 8)
		attempt, err := newSigningAttempt(
			probeJournal, signingTestAttemptRecord(t, probe), probeRequest, active,
			signingTestCoordinator, randomness,
		)
		if err != nil {
			t.Fatalf("probe %d: newSigningAttempt(): %v", probe, err)
		}
		if err := attempt.prepare(); err != nil {
			t.Fatalf("probe %d: prepare(): %v", probe, err)
		}
		if _, err := attempt.commit(); err != nil {
			t.Fatalf("probe %d: commit(): %v", probe, err)
		}
		if _, err := attempt.challenge(); err != nil {
			t.Fatalf("probe %d: challenge(): %v", probe, err)
		}
		if _, err := attempt.respond(); err != nil {
			if !errors.Is(err, errSigningRejected) {
				t.Fatalf("probe %d: respond(): %v", probe, err)
			}
			continue
		}
		return randomness
	}
	t.Fatalf("no accepted randomness in %d probes", signingTestAttemptLimit)
	return [4]*signingRandomness{}
}

// TestThresholdSigningAttemptRestartBoundariesFailClosed requires every restart boundary
// to burn the session: the wallet journal keeps the stricter fail-closed policy
// that no unfinished session may resume, and a restart may never reuse a slot's
// randomness.
func TestThresholdSigningAttemptRestartBoundariesFailClosed(t *testing.T) {
	fixture := signingTestFixtureFor(t)
	request := fixture.requestFor([]byte(signingInteropTestMessage))
	active := fixture.activeShares(t, 0b001111)
	randomness := signingTestAcceptedRandomness(
		t, fixture, active, request, rand.New(rand.NewSource(0xB0)),
	)
	boundaries := []struct {
		name string
		stop func(t *testing.T, attempt *signingAttempt)
	}{
		{name: "prepared", stop: func(t *testing.T, attempt *signingAttempt) {
			if err := attempt.prepare(); err != nil {
				t.Fatalf("prepare(): %v", err)
			}
		}},
		{name: "committed", stop: func(t *testing.T, attempt *signingAttempt) {
			if err := attempt.prepare(); err != nil {
				t.Fatalf("prepare(): %v", err)
			}
			if _, err := attempt.commit(); err != nil {
				t.Fatalf("commit(): %v", err)
			}
		}},
		{name: "challenged", stop: func(t *testing.T, attempt *signingAttempt) {
			if err := attempt.prepare(); err != nil {
				t.Fatalf("prepare(): %v", err)
			}
			if _, err := attempt.commit(); err != nil {
				t.Fatalf("commit(): %v", err)
			}
			if _, err := attempt.challenge(); err != nil {
				t.Fatalf("challenge(): %v", err)
			}
		}},
		{name: "responded", stop: func(t *testing.T, attempt *signingAttempt) {
			if err := attempt.prepare(); err != nil {
				t.Fatalf("prepare(): %v", err)
			}
			if _, err := attempt.commit(); err != nil {
				t.Fatalf("commit(): %v", err)
			}
			if _, err := attempt.challenge(); err != nil {
				t.Fatalf("challenge(): %v", err)
			}
			if _, err := attempt.respond(); err != nil {
				t.Fatalf("respond(): %v", err)
			}
		}},
	}
	for _, boundary := range boundaries {
		t.Run(boundary.name, func(t *testing.T) {
			directory := t.TempDir()
			label := byte(0xB0 + len(boundary.name))
			journal := signingTestJournalAt(t, directory)
			attempt, err := newSigningAttempt(
				journal, mpcTestRecord(t, label), request.Clone(), active,
				signingTestCoordinator, randomness,
			)
			if err != nil {
				t.Fatalf("newSigningAttempt(): %v", err)
			}
			boundary.stop(t, attempt)
			sessionID := attempt.sessionID
			if err := journal.Close(); err != nil {
				t.Fatalf("journal close: %v", err)
			}
			restarted := signingTestJournalAt(t, directory)
			journalRecord, found, err := restarted.Read(sessionID)
			if err != nil || !found {
				t.Fatalf("journal read after restart: found=%v err=%v", found, err)
			}
			if journalRecord.State != protocol.SingleUseBurned {
				t.Fatalf("journal state after restart = %v, want burned", journalRecord.State)
			}
			fresh, err := newSigningAttempt(
				restarted, mpcTestRecord(t, label+1), request.Clone(), active,
				signingTestCoordinator, randomness,
			)
			if err != nil {
				t.Fatalf("restarted newSigningAttempt(): %v", err)
			}
			if err := fresh.prepare(); err == nil {
				t.Fatal("a restarted attempt reused a burned session")
			}
		})
	}
}

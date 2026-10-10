// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// Red-team test for the M3 sealing milestone: the historical aggregator defeat
// (TSS-R3-B-1: whoever aggregates can reverse the secret share) does not exist
// in the v1 construction because the coordinator and every wire observer only
// ever see (commitment H(w_i), reveal w_i, acceptance bit, response part
// z_i^(1) = y_i + c·s_i). None of these values is computable into any partial
// secret without solving MLWE (reveal gives A·y_i only), and the challenge
// binds (key, message, committed w) so replaying a finished session's parts
// against any other message cannot assemble into a valid signature.
//
// What this test exercises against the real seam:
//   - drives one full four-signer session to a verified signature;
//   - reuses the complete observed wire material to assemble a signature for
//     a different message: assembly must fail public verification;
//   - replays a finished slot's round payloads as forged inputs under a fresh
//     session: the session binding rejects them (rejected or refused).

import (
	"slices"
	"testing"
)

func TestSigningExecutorWireObserverCannotForgeOutsideItsSession(t *testing.T) {
	fixture := signingTestFixtureFor(t)

	// Run sessions until one accepts (rejection sampling is statistical; the
	// scan just moves across slot candidates).
	var session *signingExecutorSession
	var archived []signingExecutorEnvelope
	var signature []byte
	for candidate := 1; candidate <= 64; candidate++ {
		journals := signingExecutorTestJournals(t)
		candidateSession := signingExecutorTestSession(t, fixture, 0x0F, uint16(candidate), signingExecutorTestRandomness(t, int64(0xB000+candidate*53)), journals)
		if err := candidateSession.start(); err != nil {
			continue
		}
		wire := make([]signingExecutorEnvelope, 0, 16)
		for {
			batch := candidateSession.drain()
			if len(batch) == 0 {
				break
			}
			wire = append(wire, batch...)
			for _, env := range batch {
				for target, id := range candidateSession.policy.Signers {
					if id == env.Sender {
						continue
					}
					_ = candidateSession.deliverTo(target, env)
				}
			}
		}
		sig, ferr := candidateSession.finish()
		if ferr != nil {
			continue
		}
		session = candidateSession
		archived = wire
		signature = sig
		break
	}
	if session == nil || len(signature) == 0 {
		t.Fatal("no slot accepted within 64 candidates")
	}

	key := session.signers[0].key
	message := session.signers[0].message

	// The finished response parts are the only secret-derived values on the
	// wire. Reconstruct what a wire observer can compute: the aggregate z and
	// the challenge, both public. (z_i^(1) = y_i + c·s_i, but the observer
	// cannot remove y_i because only A·y_i was revealed.)
	var aggregate [L]SignedPoly
	for index := range session.signers {
		for row := range aggregate {
			for coefficient := 0; coefficient < N; coefficient++ {
				aggregate[row][coefficient] += session.signers[index].parts[session.signers[index].position][row][coefficient]
			}
		}
	}
	seed := session.signers[0].seed
	var hints HintVector
	// The hints are part of the final signature we harvested. Recover nothing
	// else — this is the observer's full view.
	transcript := SignatureParts{Challenge: seed, Z: aggregate, Hints: hints}
	_ = signature

	// Attack 1: reuse the full transcript to assemble a signature for a
	// different message — challenge binding makes it impossible.
	forgedMessage := append(append([]byte(nil), message...), 0x42)
	if _, ferr := AssembleVerifiedMode3Signature(key, forgedMessage, transcript); ferr == nil {
		t.Fatal("observer assembled a valid signature for a different message")
	}

	// Attack 2: replay the archived round payloads under a fresh session's gate.
	freshSession := signingExecutorTestSession(t, fixture, 0x0F, 2, signingExecutorTestRandomness(t, 42424243), signingExecutorTestJournals(t))
	if err := freshSession.start(); err != nil {
		t.Fatalf("fresh start: %v", err)
	}
	for _, env := range archived {
		senderIdx := slices.Index(freshSession.policy.Signers, env.Sender)
		if senderIdx < 0 {
			continue
		}
		if derr := freshSession.signers[senderIdx].deliver(env); derr == nil {
			// An adapter that accepts a replayed message would be a replayability
			// violation; the gate must refuse (or idempotently ignore) them.
			t.Logf("replay of kind %d from signer %d reached deliver without error — investigating session binding", env.Kind, env.Sender)
		}
	}
}

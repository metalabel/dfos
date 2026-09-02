package relay

import (
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ===========================================================================
// DEPENDENCY CLASSIFICATION IS A TYPED FACT, NOT A SPELLING.
//
// The relay keeps a rejected op pending when the rejection is a missing
// dependency and DELETES the raw op otherwise. That branch used to be decided
// by substring-matching the human-readable error, and much of that text quotes
// what the submitter wrote: a kid reaches ValidateDID's "malformed did:dfos
// identifier: %q", a credential's audience reaches "credential audience %s does
// not match operation signer %s". Spelling one of the listed phrases inside one
// of those fields made a permanent rejection classify as retryable, so the op
// was never deleted and was re-verified every cycle — and varying one byte to
// mint a fresh CID grew the raw-op store without bound.
//
// The tests below are the pair that pins the fix: attacker-chosen text must not
// buy retryability, and a genuine dependency miss must still get it. Both twins
// carry the same pair (dfos-web-relay/tests/admission.spec.ts).
// ===========================================================================

// poisonPhrase is one of the six phrases the deleted substring list matched. Any
// of them would do; this one is the phrase a real dependency miss also uses,
// which is exactly what made the text unusable as a discriminator.
const poisonPhrase = "unknown identity: "

// ingestPoisonedCredentialAudience builds the reachable attack: a delegated
// content update whose authorization credential names an audience the submitter
// chose. The credential verifies; it simply does not authorize this signer, so
// the rejection is permanent — but the audience is echoed into the error
// verbatim, which is where the old classifier read it.
func ingestPoisonedCredentialAudience(t *testing.T, r *Relay, aud string) IngestionResult {
	t.Helper()
	creator := createTestIdentity(t)
	delegate := createTestIdentity(t)
	if res := r.Ingest([]string{creator.token, delegate.token}); res[0].Status != "new" || res[1].Status != "new" {
		t.Fatalf("ingest identities: %s / %s", res[0].Status, res[1].Status)
	}

	contentToken, contentID, contentOpCID := createTestContent(t, creator)
	if res := r.Ingest([]string{contentToken})[0]; res.Status != "new" {
		t.Fatalf("ingest content genesis: %s (%s)", res.Status, res.Error)
	}

	cred, err := dfos.CreateCredential(creator.did, aud, creator.did+"#"+creator.auth.keyID,
		"chain:"+contentID, "write", time.Hour, creator.auth.priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	docCID, _, err := dfos.DocumentCID(map[string]any{"type": "post", "title": "delegated"})
	if err != nil {
		t.Fatalf("DocumentCID: %v", err)
	}
	update, _, err := dfos.SignContentUpdateWithOptions(delegate.did, contentOpCID, docCID,
		delegate.did+"#"+delegate.auth.keyID, delegate.auth.priv,
		dfos.ContentUpdateOptions{Authorization: cred})
	if err != nil {
		t.Fatalf("SignContentUpdateWithOptions: %v", err)
	}
	return r.Ingest([]string{update})[0]
}

// poisonedSignerContentGenesis is a content genesis whose signer DID is
// malformed AND spells a dependency phrase. The DID can never become valid, so
// the rejection is permanent no matter how long the relay waits.
func poisonedSignerContentGenesis(t *testing.T) string {
	t.Helper()
	did := "did:dfos:" + poisonPhrase + "notarealidentity"
	docCID, _, err := dfos.DocumentCID(map[string]any{"type": "post", "title": "poison"})
	if err != nil {
		t.Fatalf("DocumentCID: %v", err)
	}
	token, _, _, err := dfos.SignContentCreate(did, docCID, did+"#key_x", newTestKeypair().priv)
	if err != nil {
		t.Fatalf("SignContentCreate: %v", err)
	}
	return token
}

func assertPermanentRejection(t *testing.T, label string, result IngestionResult) {
	t.Helper()
	if result.Status != "rejected" {
		t.Fatalf("%s: expected rejected, got %s", label, result.Status)
	}
	if result.DependencyMissing {
		t.Fatalf("%s: classified as a missing dependency on submitter-chosen text (%q) — "+
			"the op is never deleted and is re-verified forever", label, result.Error)
	}
}

// TestSubmitterChosenTextDoesNotBuyRetryability is the regression test. On the
// substring classifier both cases come back DependencyMissing.
func TestSubmitterChosenTextDoesNotBuyRetryability(t *testing.T) {
	t.Run("credential audience", func(t *testing.T) {
		r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
		if err != nil {
			t.Fatal(err)
		}
		result := ingestPoisonedCredentialAudience(t, r, poisonPhrase+"chosen-by-the-submitter")
		assertPermanentRejection(t, "poisoned credential audience", result)
	})

	t.Run("malformed signer DID", func(t *testing.T) {
		r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
		if err != nil {
			t.Fatal(err)
		}
		assertPermanentRejection(t, "poisoned signer DID", r.Ingest([]string{poisonedSignerContentGenesis(t)})[0])
	})
}

// TestPoisonedRejectionIsDurablyDeleted follows the classification through to
// the consequence that makes it matter: the sequencer must delete the raw op,
// so a second pass finds nothing and the store does not grow.
func TestPoisonedRejectionIsDurablyDeleted(t *testing.T) {
	store := NewMemoryStore()
	token := poisonedSignerContentGenesis(t)
	cid := computeOpCID(token)
	if cid == "" {
		t.Fatal("expected a decodable token")
	}
	if _, err := store.PutRawOp(cid, token); err != nil {
		t.Fatalf("PutRawOp: %v", err)
	}

	r, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if _, result := r.RunSequencer(); result.Rejected != 1 {
		t.Fatalf("expected 1 durable rejection, got rejected=%d pending=%d", result.Rejected, result.Pending)
	}
	if n, _ := store.CountUnsequenced(); n != 0 {
		t.Fatalf("expected the raw op to be deleted, %d still unsequenced", n)
	}
}

// TestGenuineDependencyMissStaysRetryable is the control. Every op kind whose
// verification resolves a key must stay pending when the referenced identity is
// simply not here yet — the case the classification exists to serve.
func TestGenuineDependencyMissStaysRetryable(t *testing.T) {
	assertRetryable := func(t *testing.T, result IngestionResult) {
		t.Helper()
		if result.Status != "rejected" {
			t.Fatalf("expected rejected, got %s", result.Status)
		}
		if !result.DependencyMissing {
			t.Fatalf("an unsynced identity must stay retryable, got a permanent rejection: %q", result.Error)
		}
		// The sentinel rides on the error VALUE, not in its text. The twins'
		// response bodies are compared verbatim by the conformance parity suite,
		// and the TS marker is a property that touches no message.
		if strings.Contains(result.Error, ErrDependencyMissing.Error()) {
			t.Fatalf("the sentinel leaked into the human-readable error: %q", result.Error)
		}
	}

	// The signer of every op below is a well-formed identity the store has
	// never seen — the op verifies once its chain arrives.
	stranger := createTestIdentity(t)
	strangerKid := stranger.did + "#" + stranger.auth.keyID

	t.Run("content genesis", func(t *testing.T) {
		token, _, _ := createTestContent(t, stranger)
		assertRetryable(t, IngestOperations([]string{token}, NewMemoryStore())[0])
	})

	t.Run("countersignature", func(t *testing.T) {
		token, _, err := dfos.SignCountersignWithRelation(stranger.did, stranger.opCID, "witness",
			strangerKid, stranger.auth.priv)
		if err != nil {
			t.Fatal(err)
		}
		assertRetryable(t, IngestOperations([]string{token}, NewMemoryStore())[0])
	})

	t.Run("artifact", func(t *testing.T) {
		token, _, err := dfos.SignArtifact(stranger.did, map[string]any{"$schema": "test/v1", "title": "t"},
			strangerKid, stranger.auth.priv)
		if err != nil {
			t.Fatal(err)
		}
		assertRetryable(t, IngestOperations([]string{token}, NewMemoryStore())[0])
	})

	t.Run("revocation", func(t *testing.T) {
		token, _, err := dfos.SignRevocation(stranger.did, stranger.opCID, strangerKid, stranger.auth.priv)
		if err != nil {
			t.Fatal(err)
		}
		assertRetryable(t, IngestOperations([]string{token}, NewMemoryStore())[0])
	})

	t.Run("public credential", func(t *testing.T) {
		token, err := dfos.CreateCredential(stranger.did, "*", strangerKid, "chain:*", "read",
			time.Hour, stranger.auth.priv)
		if err != nil {
			t.Fatal(err)
		}
		assertRetryable(t, IngestOperations([]string{token}, NewMemoryStore())[0])
	})

	// The credential-authorized content path resolves the credential ISSUER
	// through a second resolver, so a delegation whose intermediate has not
	// synced misses there rather than on the op's own signer.
	t.Run("delegated content op with unsynced credential issuer", func(t *testing.T) {
		r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
		if err != nil {
			t.Fatal(err)
		}
		creator := createTestIdentity(t)
		middle := createTestIdentity(t)
		delegate := createTestIdentity(t)
		// middle is deliberately NOT ingested
		if res := r.Ingest([]string{creator.token, delegate.token}); res[0].Status != "new" || res[1].Status != "new" {
			t.Fatalf("ingest identities: %s / %s", res[0].Status, res[1].Status)
		}
		contentToken, contentID, contentOpCID := createTestContent(t, creator)
		if res := r.Ingest([]string{contentToken})[0]; res.Status != "new" {
			t.Fatalf("ingest content genesis: %s (%s)", res.Status, res.Error)
		}

		parent, err := dfos.CreateCredential(creator.did, middle.did, creator.did+"#"+creator.auth.keyID,
			"chain:"+contentID, "write", time.Hour, creator.auth.priv)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := mintDelegatedCredential(t,
			middle.did, middle.did+"#"+middle.auth.keyID, middle.auth.priv,
			delegate.did, "chain:"+contentID, "write", []string{parent}, time.Hour)

		docCID, _, err := dfos.DocumentCID(map[string]any{"type": "post", "title": "delegated"})
		if err != nil {
			t.Fatal(err)
		}
		update, _, err := dfos.SignContentUpdateWithOptions(delegate.did, contentOpCID, docCID,
			delegate.did+"#"+delegate.auth.keyID, delegate.auth.priv,
			dfos.ContentUpdateOptions{Authorization: leaf})
		if err != nil {
			t.Fatal(err)
		}
		assertRetryable(t, r.Ingest([]string{update})[0])
	})
}

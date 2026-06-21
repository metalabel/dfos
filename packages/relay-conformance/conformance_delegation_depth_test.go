package conformance

import (
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// Delegation-depth boundary. A delegation chain MUST contain at most 16
// credentials (leaf through root inclusive); the 17th is rejected. This boundary
// is validity-determining — a verifier that accepts a 17-credential chain forks
// authorization validity — so it MUST be identical across implementations. The
// TS and Go verifiers historically diverged here (TS rejected 17, Go accepted
// it); this pins the canonical boundary against both relays. (CREDENTIALS.md
// "Depth limit".)
//
// Exercised on the WRITE path, not the read path: a deep chain nests its full
// parent chain inside each credential's `prf`, so the leaf token balloons to
// ~100KB+ at depth 16 — far past any HTTP header limit. The write path carries
// the credential in the `authorization` field of a delegated content operation,
// submitted in the POST /operations body (16 MB cap), so depth is reachable.

// buildWriteChain builds a linear delegation chain of exactly n credentials
// granting write on contentID, rooted at creator, and returns the leaf
// credential plus the writer identity it is addressed to.
func buildWriteChain(t *testing.T, base string, creator identity, contentID string, n int) (leafCred string, writer identity) {
	t.Helper()
	att := []map[string]string{{"resource": "chain:" + contentID, "action": "write"}}
	baseExp := time.Now().Unix() + 600

	// issuers[0] is the creator (root); issuers[1..n-1] are fresh delegates.
	issuers := make([]identity, n)
	issuers[0] = creator
	for k := 1; k < n; k++ {
		issuers[k] = createIdentity(t, base)
	}
	writer = createIdentity(t, base)

	var prev string
	for k := 0; k < n; k++ {
		iss := issuers[k]
		kid := iss.did + "#" + iss.auth.keyID
		prf := []string{} // root carries an empty (non-nil) prf array
		if k > 0 {
			prf = []string{prev}
		}
		aud := writer.did
		if k < n-1 {
			aud = issuers[k+1].did
		}
		exp := baseExp - int64(k) // child (higher k) expires no later than parent
		prev = signCredentialV(t, 1, iss.did, aud, kid, att, prf, exp, iss.auth.priv)
	}
	return prev, writer
}

func TestDelegationDepthBoundary(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)

	// attempt a delegated write authorized by an n-credential delegation chain,
	// on a fresh content chain each time, and return the ingestion status.
	attempt := func(n int) string {
		cc := createContent(t, base, creator)
		leaf, writer := buildWriteChain(t, base, creator, cc.contentID, n)
		doc := map[string]any{"$schema": "https://schemas.dfos.com/post/v1", "format": "short-post", "body": "depth"}
		docCID, _, err := dfos.DocumentCID(doc)
		if err != nil {
			t.Fatalf("DocumentCID: %v", err)
		}
		writerKid := writer.did + "#" + writer.auth.keyID
		token, _, err := dfos.SignContentUpdateWithOptions(
			writer.did, cc.genCID, docCID, writerKid, writer.auth.priv,
			dfos.ContentUpdateOptions{Authorization: leaf},
		)
		if err != nil {
			t.Fatalf("SignContentUpdateWithOptions: %v", err)
		}
		st, _ := postStatus(t, base, token)
		return st
	}

	// 16-credential chain (the maximum) → write authorized.
	if st := attempt(16); st != "new" {
		t.Fatalf("16-credential delegation chain should authorize the write, got status %q", st)
	}

	// 17-credential chain (one too deep) → rejected.
	if st := attempt(17); st != "rejected" {
		t.Fatalf("17-credential delegation chain should be rejected (max 16 credentials), got status %q", st)
	}
}

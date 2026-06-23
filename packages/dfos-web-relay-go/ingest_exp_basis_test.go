package relay

import (
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ===================================================================
// CREDENTIALS.md Expiry Basis (Normative) — ingest-time exp basis
//
// "At ingest (a delegated content operation carrying an inline authorization):
//  exp is compared against the operation's own createdAt. A relay MUST NOT add
//  an ingest-time wall-clock exp check."
//
// The convergence-critical POSITIVE case: a credential whose exp is in the PAST
// relative to the wall clock but in the FUTURE relative to op.createdAt MUST be
// ACCEPTED at ingest. If a relay (wrongly) read its own wall clock here, the
// same content op would be accepted on one relay and rejected on another whose
// clock is a few minutes ahead — divergence, breaking convergence.
//
// Proof site in the implementation:
//   verify.go:839 / :980 verifyContentAuthorization(..., createdAt, ...)
//     → verify.go:644 VerifyCredentialAt(authorization, key, "", "", opTimeUnix)
//       opTimeUnix derived from the op's createdAt (verify.go:634-638)
//     → jwt.go:258  "if claims.Exp <= currentTime { ...expired }"  where
//        currentTime == the op's createdAt, NOT time.Now().
//
// These tests construct the case directly: all timestamps are BACKDATED so the
// credential's exp is already wall-clock-expired, yet the delegated write's
// createdAt sits inside [iat, exp). The op MUST be accepted.
// ===================================================================

const expBasisTimeFormat = "2006-01-02T15:04:05.000Z" // mirrors content.go

// signBackdatedContentCreate hand-builds a genesis content op with a caller-
// chosen createdAt, mirroring SignContentCreate's exact payload shape. The real
// SignContentCreate stamps time.Now(); this lets the test place the whole chain
// in the past so a wall-clock-expired credential can still validate against the
// op's own createdAt.
func signBackdatedContentCreate(t *testing.T, id testIdentity, docCID string, createdAt time.Time) (token, contentID, opCID string) {
	t.Helper()
	payload := map[string]any{
		"version":         1,
		"type":            "create",
		"did":             id.did,
		"documentCID":     docCID,
		"baseDocumentCID": nil,
		"createdAt":       createdAt.UTC().Format(expBasisTimeFormat),
	}
	_, cidBytes, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID(genesis): %v", err)
	}
	header := dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:content-op", Kid: id.did + "#" + id.auth.keyID, CID: cidStr}
	token, err = dfos.CreateJWS(header, payload, id.auth.priv)
	if err != nil {
		t.Fatalf("CreateJWS(genesis): %v", err)
	}
	return token, dfos.DeriveContentID(cidBytes), cidStr
}

// signBackdatedDelegatedUpdate hand-builds a delegated content update op (carrying
// an inline authorization credential) with a caller-chosen createdAt, mirroring
// SignContentUpdateWithOptions' exact payload shape.
func signBackdatedDelegatedUpdate(t *testing.T, delegate testIdentity, previousCID, docCID, authorization string, createdAt time.Time) (token, opCID string) {
	t.Helper()
	payload := map[string]any{
		"version":              1,
		"type":                 "update",
		"did":                  delegate.did,
		"previousOperationCID": previousCID,
		"documentCID":          docCID,
		"baseDocumentCID":      nil,
		"createdAt":            createdAt.UTC().Format(expBasisTimeFormat),
		"authorization":        authorization,
	}
	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID(update): %v", err)
	}
	header := dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:content-op", Kid: delegate.did + "#" + delegate.auth.keyID, CID: cidStr}
	token, err = dfos.CreateJWS(header, payload, delegate.auth.priv)
	if err != nil {
		t.Fatalf("CreateJWS(update): %v", err)
	}
	return token, cidStr
}

// mintCredentialWithExp mints a leaf credential (single att, prf:[]) with a
// caller-chosen iat/exp. mintDelegatedCredential (two_relay_test.go) only takes a
// ttl relative to time.Now(); this variant places exp in the wall-clock past.
func mintCredentialWithExp(t *testing.T, issuerDID, issuerKid string, issuerPriv []byte, aud, resource, action string, iat, exp int64) string {
	t.Helper()
	payload := map[string]any{
		"version": 1,
		"type":    "DFOSCredential",
		"iss":     issuerDID,
		"aud":     aud,
		"att":     []any{map[string]any{"resource": resource, "action": action}},
		"prf":     []any{},
		"exp":     exp,
		"iat":     iat,
	}
	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID(cred): %v", err)
	}
	header := dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:credential", Kid: issuerKid, CID: cidStr}
	token, err := dfos.CreateJWS(header, payload, issuerPriv)
	if err != nil {
		t.Fatalf("CreateJWS(cred): %v", err)
	}
	return token
}

// buildWallClockExpiredDelegatedWrite assembles the convergence-critical fixture:
// a creator's backdated content chain, a credential creator→delegate whose exp is
// already in the wall-clock past, and a backdated delegated write whose createdAt
// falls inside [iat, exp). Returns the seed ops and the delegated write op.
func buildWallClockExpiredDelegatedWrite(t *testing.T) (seed []string, delegatedWrite string, now time.Time) {
	t.Helper()
	now = time.Now()

	creator := createTestIdentity(t)
	delegate := createTestIdentity(t)

	// genesis at T0 = now-3h (well in the past)
	genesisDoc := newDocCID(t, "genesis")
	genesisToken, contentID, genesisOpCID := signBackdatedContentCreate(t, creator, genesisDoc, now.Add(-3*time.Hour))

	// credential creator → delegate: iat = now-3h, exp = now-1h (ALREADY wall-clock
	// expired by an hour). A wall-clock exp check at ingest would reject it.
	creatorKid := creator.did + "#" + creator.auth.keyID
	cred := mintCredentialWithExp(t, creator.did, creatorKid, creator.auth.priv,
		delegate.did, "chain:"+contentID, "write",
		now.Add(-3*time.Hour).Unix(), now.Add(-1*time.Hour).Unix())

	// delegated write at T1 = now-2h: AFTER the genesis (createdAt > lastCreatedAt)
	// and STRICTLY BEFORE the credential's exp (now-1h) — so exp is in the FUTURE
	// relative to the op's own createdAt, the only basis the spec allows at ingest.
	writeDoc := newDocCID(t, "delegated-write")
	delegatedWrite, _ = signBackdatedDelegatedUpdate(t, delegate, genesisOpCID, writeDoc, cred, now.Add(-2*time.Hour))

	seed = []string{creator.token, delegate.token, genesisToken}
	return seed, delegatedWrite, now
}

// TestIngestAcceptsWallClockExpiredCredentialFutureRelativeToOpCreatedAt is the
// CREDENTIALS.md Expiry Basis positive guard: at ingest, a delegated write whose
// inline authorization is wall-clock-expired but still valid relative to the op's
// OWN createdAt MUST be ACCEPTED. If anyone adds an ingest-time wall-clock exp
// check (verify.go verifyContentAuthorization → jwt.go VerifyCredentialAt), this
// flips RED — that is the regression this test exists to catch.
func TestIngestAcceptsWallClockExpiredCredentialFutureRelativeToOpCreatedAt(t *testing.T) {
	seed, delegatedWrite, now := buildWallClockExpiredDelegatedWrite(t)

	store := NewMemoryStore()
	if res := IngestOperations(seed, store); len(res) == 0 {
		t.Fatal("seed ingest returned no results")
	}

	res := IngestOperations([]string{delegatedWrite}, store)
	if res[0].Status != "new" {
		t.Fatalf("expected delegated write accepted at ingest (exp in wall-clock past %s but FUTURE vs op.createdAt %s), got %s (%s)",
			now.Add(-1*time.Hour).UTC().Format(expBasisTimeFormat),
			now.Add(-2*time.Hour).UTC().Format(expBasisTimeFormat),
			res[0].Status, res[0].Error)
	}
}

// TestTwoRelayWallClockExpiredCredentialConverges is the two-relay convergence
// half. The wall-clock exp basis is the whole reason ingest uses op.createdAt:
// two relays reading different wall clocks must reach the SAME verdict on the
// same op. Here both relays ingest the identical wall-clock-expired delegated
// write independently; both MUST accept it and converge on the same chain head.
//
// (Wall clocks are not injectable — time.Now() is process-global — so this models
// the divergence risk structurally: an ingest verdict that depended on time.Now()
// could differ between two relays running at different instants. Because the
// verdict is keyed to the op's createdAt, both relays accept identically.)
func TestTwoRelayWallClockExpiredCredentialConverges(t *testing.T) {
	seed, delegatedWrite, _ := buildWallClockExpiredDelegatedWrite(t)

	writeHeader, _, err := dfos.DecodeJWSUnsafe(delegatedWrite)
	if err != nil {
		t.Fatal(err)
	}
	writeOpCID := writeHeader.CID

	ingestAll := func(label string) *MemoryStore {
		store := NewMemoryStore()
		IngestOperations(seed, store)
		res := IngestOperations([]string{delegatedWrite}, store)
		if res[0].Status != "new" {
			t.Fatalf("[%s] expected wall-clock-expired delegated write accepted, got %s (%s)", label, res[0].Status, res[0].Error)
		}
		return store
	}

	r1 := ingestAll("r1")
	r2 := ingestAll("r2")

	// both relays converge: the write op is durably stored on each, and the
	// content chain head is the SAME op cid on both.
	op1, _ := r1.GetOperation(writeOpCID)
	op2, _ := r2.GetOperation(writeOpCID)
	if op1 == nil || op2 == nil {
		t.Fatalf("expected write op stored on both relays, got r1=%v r2=%v", op1 != nil, op2 != nil)
	}
	if op1.ChainID != op2.ChainID {
		t.Fatalf("relays diverged on chain id: r1=%s r2=%s", op1.ChainID, op2.ChainID)
	}

	chain1, _ := r1.GetContentChain(op1.ChainID)
	chain2, _ := r2.GetContentChain(op2.ChainID)
	if chain1 == nil || chain2 == nil {
		t.Fatal("expected content chain present on both relays")
	}
	if chain1.State.HeadCID != chain2.State.HeadCID {
		t.Fatalf("relays diverged on chain head: r1=%s r2=%s", chain1.State.HeadCID, chain2.State.HeadCID)
	}
	if chain1.State.HeadCID != writeOpCID {
		t.Fatalf("expected chain head to be the delegated write %s, got %s", writeOpCID, chain1.State.HeadCID)
	}
}

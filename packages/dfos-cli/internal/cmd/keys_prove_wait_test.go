package cmd

// The ceremony epilogue's tests: what `dfos keys add` does between the
// presentation and the human's decision, and what it reports for each way that
// decision can land.
//
// The operator is the same loopback stub the presentation tests drive, wearing
// its status route. That matters here more than anywhere: the epilogue's whole
// job is to distinguish six operator answers plus three ways of hearing nothing,
// and a hand-written fake would let a poll that never happened look like a poll
// that answered.
//
// These drive the package globals like every other test in this package, so they
// MUST NOT run with t.Parallel() — including the poll cadence, which is turned
// down to milliseconds so a whole ceremony's worth of polls fits in a test.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// --- helpers ---

// fastCeremonyPolling turns the wait's clock down. The cadence is a product
// decision about how often to bother an operator while a human reads a dialog,
// and nothing in the epilogue's logic depends on its value — so a test drives it
// at a millisecond and asserts on what was asked rather than on when.
//
// The deadline comes down too, and deliberately stays REACHABLE: a bug that
// polls forever should fail this suite in seconds rather than hang it for the
// fifteen minutes the real ceiling allows.
func fastCeremonyPolling(t *testing.T) {
	t.Helper()
	interval, slowAfter, slow, deadline :=
		ceremonyPollInterval, ceremonyPollSlowAfter, ceremonyPollSlowInterval, ceremonyPollDeadline
	ceremonyPollInterval = time.Millisecond
	ceremonyPollSlowAfter = 10 * time.Millisecond
	ceremonyPollSlowInterval = time.Millisecond
	ceremonyPollDeadline = 10 * time.Second
	t.Cleanup(func() {
		ceremonyPollInterval, ceremonyPollSlowAfter, ceremonyPollSlowInterval, ceremonyPollDeadline =
			interval, slowAfter, slow, deadline
	})
}

// waitingCeremony is the arrangement every test here shares: a machine with a
// vault and an oracle, and an operator that serves the poll leg.
func waitingCeremony(t *testing.T, statuses ...map[string]any) *stubCeremony {
	t.Helper()
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	wireOracle(t)
	fastCeremonyPolling(t)
	stub := newStubCeremony(t)
	stub.statusSequence = statuses
	return stub
}

// nextCeremony is a SECOND operator for the machine waitingCeremony already
// arranged: the same keystore, vault, and oracle, a fresh ceremony, a fresh key.
// The terminal-state tests use it to read the receipt a person gets after
// asserting the document a script gets.
func nextCeremony(t *testing.T, statuses ...map[string]any) *stubCeremony {
	t.Helper()
	stub := newStubCeremony(t)
	stub.statusSequence = statuses
	return stub
}

// runProveWaiting is runProve with the wait left ON — the default a person gets.
func runProveWaiting(t *testing.T, input string, out any) (stdout, stderr string, err error) {
	t.Helper()
	return runProve(t, input, map[string]string{"yes": "true", "no-wait": "false"}, out)
}

func runProveWaitingHuman(t *testing.T, input string) (stdout, stderr string, err error) {
	t.Helper()
	return runProveHuman(t, input, map[string]string{"yes": "true", "no-wait": "false"})
}

func adoptedBy(did string) map[string]any {
	return map[string]any{
		"status":    "adopted",
		"onAdopted": map[string]any{"did": did, "keyId": "key_ceremony", "chainOpCID": stubChainOpCID},
	}
}

const stubChainOpCID = "bafyreiadoptadoptadoptadoptadoptadoptadoptadoptadoptadopta"

// --- the status URL ---

// The poll URL is DERIVED from the presentation endpoint's origin and read off
// no answer. The presentation endpoint's authority was already checked against
// the authority the human typed, so nothing an operator says can move the poll
// to a host the human never named.
func TestKeysAdd_TheStatusURLIsDerivedFromThePresentationOrigin(t *testing.T) {
	for _, tc := range []struct{ present, want string }{
		{"https://app.example/keys/present", "https://app.example" + keyProofStatusPath},
		{"https://app.example:8443/a/deep/path", "https://app.example:8443" + keyProofStatusPath},
		{"http://127.0.0.1:9999/keys/present?tenant=t1", "http://127.0.0.1:9999" + keyProofStatusPath},
	} {
		got, err := ceremonyStatusURL(&ceremony{Present: tc.present})
		if err != nil || got != tc.want {
			t.Fatalf("ceremonyStatusURL(%q) = %q, %v — want %q", tc.present, got, err, tc.want)
		}
	}
}

// --- the decisions ---

// The path the whole leg exists for: a human approves, and the command that
// presented the key is the command that reports it and files it.
func TestKeysAdd_AnAdoptionIsWaitedOutAndFiled(t *testing.T) {
	stub := waitingCeremony(t,
		map[string]any{"status": "presented"},
		map[string]any{"status": "presented"},
		adoptedBy(stubDID),
	)

	var result proveResult
	if _, _, err := runProveWaiting(t, stub.shortCode(), &result); err != nil {
		t.Fatalf("keys add: %v", err)
	}

	if result.Status != ceremonyStatusAdopted || result.AdoptedDID != stubDID {
		t.Fatalf("result: %+v", result)
	}
	if result.KeyID != "key_ceremony" || result.ChainOpCID != stubChainOpCID {
		t.Fatalf("the adoption's facts are missing: %+v", result)
	}
	if result.WaitStopped != "" {
		t.Fatalf("a decision arrived and the wait reported a reason for stopping: %q", result.WaitStopped)
	}
	if stub.statusHits < 3 {
		t.Fatalf("polled %d times, want at least the three answers arranged", stub.statusHits)
	}
	if stub.lastStatusFor != stubCode {
		t.Fatalf("the poll asked about %q, want the ceremony's own code", stub.lastStatusFor)
	}
	// The presentation is not re-posted by a poll. Ever.
	if stub.presentHits != 1 {
		t.Fatalf("presented %d times during a wait", stub.presentHits)
	}

	// The key moves out of the candidate namespace into its ordinary address, and
	// the vault records the provenance the DID and key id make possible — the same
	// filing an inline adoption answer performs.
	want := keyAccount(result.PublicKey)
	if result.Account != want || !keys.HasKey(want) {
		t.Fatalf("account: %q, want %q", result.Account, want)
	}
	if keys.HasKey(candidateAccountPrefix + result.PublicKey) {
		t.Fatal("the candidate account was left behind after adoption")
	}
	meta, err := getVaults().Load("personal")
	if err != nil {
		t.Fatalf("load vault: %v", err)
	}
	if len(meta.Minted) != 1 || meta.Minted[0].DID != stubDID || meta.Minted[0].PublicKey != result.PublicKey {
		t.Fatalf("vault records: %+v", meta.Minted)
	}
}

// The receipt of an adoption reports an adoption — the identity, the key id, the
// chain operation that introduced it, and where to look it up in public.
func TestKeysAdd_TheAdoptedReceiptNamesTheChainOperation(t *testing.T) {
	stub := waitingCeremony(t, adoptedBy(stubDID))

	stdout, _, err := runProveWaitingHuman(t, stub.shortCode())
	if err != nil {
		t.Fatalf("keys add: %v", err)
	}
	publicKey := receiptField(t, stdout, "Key:")
	for _, want := range []string{
		"Adopted:", stubDID, "key_ceremony", stubChainOpCID,
		explorerKeyBase + publicKey,
		protocol.KeyWordFingerprint(publicKey),
		"Settings → Signing keys",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("the adopted receipt is missing %q:\n%s", want, stdout)
		}
	}
	// It is an adoption, so it never tells the human to go approve anything.
	if strings.Contains(stdout, "until you approve it there") {
		t.Fatalf("an adopted ceremony was reported as awaiting approval:\n%s", stdout)
	}
}

// A refusal is a decision, and the key is exactly where it was. What the receipt
// owes a person is the way out.
func TestKeysAdd_ARejectionKeepsTheKeyAsACandidate(t *testing.T) {
	stub := waitingCeremony(t, map[string]any{"status": "rejected"})

	var result proveResult
	if _, _, err := runProveWaiting(t, stub.shortCode(), &result); err != nil {
		t.Fatalf("keys add: %v", err)
	}
	if result.Status != ceremonyStatusRejected {
		t.Fatalf("status: %q", result.Status)
	}
	if result.Account != candidateAccountPrefix+result.PublicKey || !keys.HasKey(result.Account) {
		t.Fatalf("a refused key did not stay a held candidate: %q", result.Account)
	}
	if result.AdoptedDID != "" {
		t.Fatalf("a refusal named an adopting identity: %+v", result)
	}

	human, _, err := runProveWaitingHuman(t, nextCeremony(t, map[string]any{"status": "rejected"}).shortCode())
	if err != nil {
		t.Fatalf("keys add: %v", err)
	}
	for _, want := range []string{"Refused:", "No chain declares this key", "dfos keys remove "} {
		if !strings.Contains(human, want) {
			t.Fatalf("the refusal receipt is missing %q:\n%s", want, human)
		}
	}
}

// A ceremony that lapsed before anyone decided. Nothing was refused, so the
// advice is the same paste against a fresh code with the same key.
func TestKeysAdd_AnExpiredCeremonyKeepsTheKeyAndPointsAtAFreshCode(t *testing.T) {
	stub := waitingCeremony(t, map[string]any{"status": "expired"})

	var result proveResult
	if _, _, err := runProveWaiting(t, stub.shortCode(), &result); err != nil {
		t.Fatalf("keys add: %v", err)
	}
	if result.Status != ceremonyStatusExpired {
		t.Fatalf("status: %q", result.Status)
	}
	if result.Account != candidateAccountPrefix+result.PublicKey {
		t.Fatalf("account: %q", result.Account)
	}

	human, _, err := runProveWaitingHuman(t, nextCeremony(t, map[string]any{"status": "expired"}).shortCode())
	if err != nil {
		t.Fatalf("keys add: %v", err)
	}
	for _, want := range []string{"Expired:", "lapsed", "dfos keys add <code> --key "} {
		if !strings.Contains(human, want) {
			t.Fatalf("the expired receipt is missing %q:\n%s", want, human)
		}
	}
}

// A ceremony the operator could not finish is the burned case, and its advice is
// the burned-ceremony advice: a fresh code, this same key.
func TestKeysAdd_AFailedCeremonyReadsAsBurned(t *testing.T) {
	stub := waitingCeremony(t, map[string]any{"status": "failed"})

	var result proveResult
	if _, _, err := runProveWaiting(t, stub.shortCode(), &result); err != nil {
		t.Fatalf("keys add: %v", err)
	}
	if result.Status != ceremonyStatusFailed || result.Account != candidateAccountPrefix+result.PublicKey {
		t.Fatalf("result: %+v", result)
	}

	human, _, err := runProveWaitingHuman(t, nextCeremony(t, map[string]any{"status": "failed"}).shortCode())
	if err != nil {
		t.Fatalf("keys add: %v", err)
	}
	for _, want := range []string{"Unfinished:", "could not finish", "dfos keys add <code> --key ", "dfos identity fetch"} {
		if !strings.Contains(human, want) {
			t.Fatalf("the failed receipt is missing %q:\n%s", want, human)
		}
	}
}

// An adoption naming an identity the human never consented to files NOTHING.
// The provenance it would write is a claim nobody saw, and the same gate that
// refuses an inline answer refuses one learned from a poll.
func TestKeysAdd_AnAdoptionNamingAnotherIdentityFilesNothing(t *testing.T) {
	other := "did:dfos:z6MksomeoneelseentirelyentirelyA"
	stub := waitingCeremony(t, adoptedBy(other))

	var result proveResult
	if _, _, err := runProveWaiting(t, stub.shortCode(), &result); err != nil {
		t.Fatalf("keys add: %v", err)
	}
	if result.Account != candidateAccountPrefix+result.PublicKey {
		t.Fatalf("the key was filed against an identity the human never saw: %q", result.Account)
	}
	if keys.HasKey(keyAccount(result.PublicKey)) {
		t.Fatal("the key moved to its ordinary address on an unconsented adoption")
	}
	meta, err := getVaults().Load("personal")
	if err != nil {
		t.Fatalf("load vault: %v", err)
	}
	if len(meta.Minted) != 0 {
		t.Fatalf("provenance was written for an unconsented identity: %+v", meta.Minted)
	}

	human, _, err := runProveWaitingHuman(t, nextCeremony(t, adoptedBy(other)).shortCode())
	if err != nil {
		t.Fatalf("keys add: %v", err)
	}
	for _, want := range []string{other, stubDID, "nothing was filed", "stays a candidate"} {
		if !strings.Contains(human, want) {
			t.Fatalf("the mismatch receipt is missing %q:\n%s", want, human)
		}
	}
}

// --- the stale head ---

// The chain moved under a live ceremony. The recovery is KEY-PROOF.md's: the
// SAME code re-resolves against the current head, the SAME key signs again, and
// the replacement is presented — which a presented ceremony accepts only from
// the key already on it. It is not a retry: nothing was refused.
func TestKeysAdd_AStaleHeadIsReSignedAgainstTheCurrentHead(t *testing.T) {
	stub := waitingCeremony(t, adoptedBy(stubDID))
	stub.freshPrevCID = "bafyreifreshfreshfreshfreshfreshfreshfreshfreshfreshfreshf"
	stub.staleUntil = 2 // stale until a second presentation arrives

	var result proveResult
	_, stderr, err := runProveWaiting(t, stub.shortCode(), &result)
	if err != nil {
		t.Fatalf("keys add: %v", err)
	}
	if result.Status != ceremonyStatusAdopted {
		t.Fatalf("status: %q", result.Status)
	}
	if result.Resigned != 1 {
		t.Fatalf("re-signed %d times, want exactly 1", result.Resigned)
	}
	if stub.wellKnownHits != 2 {
		t.Fatalf("resolved %d times — a stale head re-resolves the same code exactly once", stub.wellKnownHits)
	}
	if stub.presentHits != 2 || len(stub.lastEnvelopes) != 2 {
		t.Fatalf("presented %d times with %d envelopes", stub.presentHits, len(stub.lastEnvelopes))
	}
	if result.PrevCID != stub.freshPrevCID {
		t.Fatalf("the receipt names head %q, want the one the envelope finally bound %q", result.PrevCID, stub.freshPrevCID)
	}

	// The first envelope named the old head; the replacement names the new one.
	// Both are the same key, the same identity, and the same roles — a re-sign
	// moves the position and nothing else.
	first, err := protocol.VerifyKeyProof(stub.lastEnvelopes[0], protocol.KeyProofExpectations{
		Typ: protocol.KeyAddJWSTyp, Audience: stub.authority(),
		DID: stubDID, RoleSet: stubRoleSet, PrevCID: stubPrevCID,
	}, time.Now())
	if err != nil {
		t.Fatalf("verify the first envelope: %v", err)
	}
	second, err := protocol.VerifyKeyProof(stub.lastEnvelopes[1], protocol.KeyProofExpectations{
		Typ: protocol.KeyAddJWSTyp, Audience: stub.authority(),
		DID: stubDID, RoleSet: stubRoleSet, PrevCID: stub.freshPrevCID,
	}, time.Now())
	if err != nil {
		t.Fatalf("verify the replacement envelope: %v", err)
	}
	if second.Payload.PublicKeyMultibase != first.Payload.PublicKeyMultibase {
		t.Fatal("the replacement was signed by a different key")
	}
	if second.Payload.PublicKeyMultibase != result.PublicKey {
		t.Fatalf("the replacement names %s, the run reported %s", second.Payload.PublicKeyMultibase, result.PublicKey)
	}
	if second.Payload.RoleSet != first.Payload.RoleSet || second.Payload.DID != first.Payload.DID {
		t.Fatal("a re-sign moved the position the human consented to")
	}

	// The human is told it happened. A proof spent at a different head than the
	// one displayed is not something to do silently.
	if !strings.Contains(stderr, "The chain moved under this ceremony") ||
		!strings.Contains(stderr, stub.freshPrevCID) {
		t.Fatalf("the re-sign was not reported:\n%s", stderr)
	}
}

// A head that will not settle is not one to keep spending signatures on. Three
// re-signs, then a loud stop with the key still held and the proof still
// standing.
func TestKeysAdd_TheReSignIsCapped(t *testing.T) {
	stub := waitingCeremony(t, adoptedBy(stubDID))
	stub.freshPrevCID = "bafyreifreshfreshfreshfreshfreshfreshfreshfreshfreshfreshf"
	stub.staleUntil = 99 // the head moves again every time, forever

	var result proveResult
	if _, _, err := runProveWaiting(t, stub.shortCode(), &result); err != nil {
		t.Fatalf("keys add: %v", err)
	}
	if result.Resigned != ceremonyResignCap {
		t.Fatalf("re-signed %d times, want the cap of %d", result.Resigned, ceremonyResignCap)
	}
	if stub.presentHits != 1+ceremonyResignCap {
		t.Fatalf("presented %d times, want the first plus %d replacements", stub.presentHits, ceremonyResignCap)
	}
	if result.Status != ceremonyStatusPresented {
		t.Fatalf("status: %q — a capped wait ends with the proof presented", result.Status)
	}
	if !strings.Contains(result.WaitStopped, "will not settle") {
		t.Fatalf("the stop does not say why it stopped: %q", result.WaitStopped)
	}
	if result.Account != candidateAccountPrefix+result.PublicKey || !keys.HasKey(result.Account) {
		t.Fatalf("the key is not held as a candidate: %q", result.Account)
	}
}

// A re-resolution that answers a different POSITION is not the ceremony that was
// consented to, and no signature is spent following it. The head is the one
// member allowed to move.
func TestKeysAdd_AReSignRefusesAMovedPosition(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(*stubCeremony)
		want    string
	}{
		{"the identity moved", func(s *stubCeremony) {
			s.freshDID = "did:dfos:z6MksomeoneelseentirelyentirelyA"
		}, "the identity that was consented to"},
		{"the roles moved", func(s *stubCeremony) {
			s.freshRoleSet = "auth,assert,controller"
		}, "the role set that was consented to"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := waitingCeremony(t, adoptedBy(stubDID))
			stub.freshPrevCID = "bafyreifreshfreshfreshfreshfreshfreshfreshfreshfreshfreshf"
			stub.staleUntil = 2
			tc.arrange(stub)

			var result proveResult
			if _, _, err := runProveWaiting(t, stub.shortCode(), &result); err != nil {
				t.Fatalf("keys add: %v", err)
			}
			if result.Status != ceremonyStatusPresented || result.Resigned != 0 {
				t.Fatalf("a moved position was signed for: %+v", result)
			}
			if !strings.Contains(result.WaitStopped, "REFUSING to re-sign") ||
				!strings.Contains(result.WaitStopped, tc.want) {
				t.Fatalf("the stop does not name the refusal: %q", result.WaitStopped)
			}
			// The first presentation stands; no second envelope was ever made.
			if stub.presentHits != 1 || len(stub.lastEnvelopes) != 1 {
				t.Fatalf("presented %d times for a position nobody consented to", stub.presentHits)
			}
			if result.Account != candidateAccountPrefix+result.PublicKey {
				t.Fatalf("account: %q", result.Account)
			}
		})
	}
}

// --- hearing nothing ---

// An operator whose status route stops answering does not undo a presentation,
// and the message has to make that impossible to misread. Five consecutive
// unusable answers, then a truthful stop.
func TestKeysAdd_ConsecutiveStatusFailuresStopTruthfully(t *testing.T) {
	stub := waitingCeremony(t)
	// A 5xx rather than a dropped connection, so the count is exactly the budget:
	// Go's transport re-sends an idempotent GET whose connection died before any
	// response arrived, so a hangup is one failure the CLI counts and up to two
	// requests the server sees. The dropped-connection case is the sub-test below,
	// where what is asserted is the stop and not the arithmetic.
	stub.statusStatus = http.StatusServiceUnavailable
	stub.statusBody = `{"error":"the ceremony store is down"}`

	var result proveResult
	if _, _, err := runProveWaiting(t, stub.shortCode(), &result); err != nil {
		t.Fatalf("keys add: %v", err)
	}
	if stub.statusHits != ceremonyPollFailureBudget {
		t.Fatalf("polled %d times, want the budget of %d", stub.statusHits, ceremonyPollFailureBudget)
	}
	if result.Status != ceremonyStatusPresented {
		t.Fatalf("status: %q", result.Status)
	}
	if !strings.Contains(result.WaitStopped, "did not answer its status route") {
		t.Fatalf("the stop does not name what went wrong: %q", result.WaitStopped)
	}
	if result.Account != candidateAccountPrefix+result.PublicKey || !keys.HasKey(result.Account) {
		t.Fatalf("the key is not held as a candidate: %q", result.Account)
	}
	if stub.presentHits != 1 {
		t.Fatalf("presented %d times", stub.presentHits)
	}

	// A host that answers nothing at all — the partition — is the same class of
	// failure and the same truthful stop, and it is what a person actually reads.
	human := nextCeremony(t)
	human.statusHangup = true
	stdout, _, err := runProveWaitingHuman(t, human.shortCode())
	if err != nil {
		t.Fatalf("keys add: %v", err)
	}
	for _, want := range []string{"Presented:", "The wait stopped:", "THE PROOF IS STILL PRESENTED", "held here as a"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("the stopped-wait receipt is missing %q:\n%s", want, stdout)
		}
	}
	if human.presentHits != 1 {
		t.Fatalf("presented %d times while the host was unreachable", human.presentHits)
	}
}

// A transient failure is not an ending. Four in a row, then an answer, and the
// budget is whole again — a hiccup mid-ceremony must not be reported as "no
// decision" when the decision arrives a second later.
func TestKeysAdd_ATransientFailureDoesNotEndTheWait(t *testing.T) {
	stub := waitingCeremony(t, adoptedBy(stubDID))
	// One short of the budget, then the surface comes back and the ceremony
	// completes.
	stub.statusFailFirst = ceremonyPollFailureBudget - 1

	var result proveResult
	if _, _, err := runProveWaiting(t, stub.shortCode(), &result); err != nil {
		t.Fatalf("keys add: %v", err)
	}
	if result.Status != ceremonyStatusAdopted {
		t.Fatalf("status: %q, want the decision that arrived after the hiccup", result.Status)
	}
}

// A status route that says the ceremony is gone says nothing about how it ended,
// and the CLI does not put a decision in the operator's mouth.
func TestKeysAdd_AnUnknownCeremonyIsNotADecision(t *testing.T) {
	stub := waitingCeremony(t)
	stub.statusStatus = http.StatusNotFound
	stub.statusBody = `{"error":"unknown or expired code"}`

	var result proveResult
	if _, _, err := runProveWaiting(t, stub.shortCode(), &result); err != nil {
		t.Fatalf("keys add: %v", err)
	}
	if result.Status != ceremonyStatusPresented {
		t.Fatalf("status: %q — a gone ceremony is not a decision", result.Status)
	}
	if !strings.Contains(result.WaitStopped, "does not say how it ended") {
		t.Fatalf("the stop invented an outcome: %q", result.WaitStopped)
	}
	if stub.statusHits != 1 {
		t.Fatalf("polled %d times — a ceremony the operator does not have is not polled again", stub.statusHits)
	}
}

// --- --no-wait ---

// The scripting shape: present, report, stop. The ceremony is untouched by it —
// the decision is still a human's, and nobody here is looking.
func TestKeysAdd_NoWaitStopsAtPresented(t *testing.T) {
	stub := waitingCeremony(t, adoptedBy(stubDID))

	var result proveResult
	stdout, _, err := runProve(t, stub.shortCode(), map[string]string{"yes": "true", "no-wait": "true"}, &result)
	if err != nil {
		t.Fatalf("keys add --no-wait: %v", err)
	}
	if result.Status != ceremonyStatusPresented {
		t.Fatalf("status: %q", result.Status)
	}
	if stub.statusHits != 0 {
		t.Fatalf("--no-wait polled the status route %d times", stub.statusHits)
	}
	if result.WaitStopped != "" || result.Resigned != 0 {
		t.Fatalf("--no-wait reported a wait it never made: %+v", result)
	}
	// The presented shape is what it always was, plus the fingerprint.
	if result.Fingerprint != protocol.KeyWordFingerprint(result.PublicKey) {
		t.Fatalf("fingerprint: %q", result.Fingerprint)
	}
	if result.Account != candidateAccountPrefix+result.PublicKey {
		t.Fatalf("account: %q", result.Account)
	}
	_ = stdout
}

// --- the fingerprint ---

// The six words a human compares, pinned twice: once against the kit that
// derives them, and once against the literal string, so a drift in either the
// kit or this command fails here.
func TestKeysAdd_TheWordFingerprintIsTheKitsAndIsPinned(t *testing.T) {
	// The protocol's reference genesis key, and the words it renders as.
	const genesisKey = "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
	const genesisWords = "mohawk cumbersome zulu dinosaur goldfish opulent"

	if got := protocol.KeyWordFingerprint(genesisKey); got != genesisWords {
		t.Fatalf("the kit renders %s as %q, and this command's golden says %q", genesisKey, got, genesisWords)
	}
	if got := keyFingerprint(genesisKey); got != genesisWords {
		t.Fatalf("keyFingerprint(%s) = %q, want %q", genesisKey, got, genesisWords)
	}
	if n := len(strings.Fields(genesisWords)); n != 6 {
		t.Fatalf("a fingerprint is six words, not %d", n)
	}
}

// The words are printed where a human compares a key: beside the key in the
// disclosure, before anything is signed, and again on the receipt.
func TestKeysAdd_TheFingerprintIsShownBeforeSigningAndOnTheReceipt(t *testing.T) {
	stub := waitingCeremony(t, adoptedBy(stubDID))

	var result proveResult
	_, stderr, err := runProveWaiting(t, stub.shortCode(), &result)
	if err != nil {
		t.Fatalf("keys add: %v", err)
	}
	words := protocol.KeyWordFingerprint(result.PublicKey)
	if result.Fingerprint != words {
		t.Fatalf("the result's fingerprint is %q, the kit's is %q", result.Fingerprint, words)
	}
	if !strings.Contains(stderr, words) {
		t.Fatalf("the disclosure showed no fingerprint:\n%s", stderr)
	}
	// And it says what the words are FOR. A fingerprint nobody knows to compare
	// defends nobody.
	if !strings.Contains(stderr, "operator's dialog") {
		t.Fatalf("the disclosure does not say where to compare the words:\n%s", stderr)
	}

	human := newStubCeremony(t)
	human.statusSequence = []map[string]any{adoptedBy(stubDID)}
	stdout, _, err := runProveWaitingHuman(t, human.shortCode())
	if err != nil {
		t.Fatalf("keys add: %v", err)
	}
	key := receiptField(t, stdout, "Key:")
	if key == "" || !strings.Contains(stdout, protocol.KeyWordFingerprint(key)) {
		t.Fatalf("the receipt gives no words to compare:\n%s", stdout)
	}
	// The truncated key stays too: it is what a person matches against an
	// operator's list, where a row is a key and not a sentence.
	if !strings.Contains(stdout, truncateKey(key)) {
		t.Fatalf("the receipt dropped the truncated key:\n%s", stdout)
	}
}

// --- the name ---

// `add` is the primary name and `prove` is the alias, and both resolve to one
// command. Nothing else under `keys` answers to either.
func TestKeysAdd_ProveIsAnAliasOfTheSameCommand(t *testing.T) {
	keysCmd := newKeysCmd()
	add, _, err := keysCmd.Find([]string{"add"})
	if err != nil {
		t.Fatalf("keys add does not resolve: %v", err)
	}
	prove, _, err := keysCmd.Find([]string{"prove"})
	if err != nil {
		t.Fatalf("keys prove does not resolve: %v", err)
	}
	if add != prove {
		t.Fatalf("'add' resolves to %q and 'prove' to %q", add.Name(), prove.Name())
	}
	if add.Name() != "add" {
		t.Fatalf("the command's primary name is %q, want 'add'", add.Name())
	}
	// One command answers to both names, and no second subcommand claims either.
	claimants := 0
	for _, sub := range keysCmd.Commands() {
		if sub.Name() == "add" || sub.HasAlias("add") || sub.HasAlias("prove") {
			claimants++
		}
	}
	if claimants != 1 {
		t.Fatalf("%d subcommands under `keys` answer to 'add' or 'prove'", claimants)
	}
}

// `signerKey=` on /index/v0/operations — the key-addressed, actor-axis signer
// filter over every row kind.
//
// The value matched is the multibase public key the row's verified signature
// RESOLVED TO AT INGEST, byte-for-byte as the identity chain declared it — the
// same alphabet `key=` on /index/v0/identities matches, so a key found through
// one filter pastes straight into the other. These tests assert that
// interoperability directly rather than trusting either side alone.
//
// Gating is two-layered. The index family is capability-gated the usual way
// (capabilities.index / a 501 on a probed route). The PARAMETER is gated
// behaviorally: a relay that predates it does not 400 on an unknown query
// param, it IGNORES the param and answers the unfiltered page — so the probe
// asks for a value that can be no key and skips when rows come back.
package conformance

import (
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// requireSignerKeyFilter skips when the target relay does not implement
// `signerKey=`. See the package comment above for why the probe is behavioral
// rather than a 501 check: an unrecognized filter on this route is silently
// dropped, which is indistinguishable from "matched everything" unless the test
// asks a question whose only correct answer is the empty page.
func requireSignerKeyFilter(t *testing.T, base string) {
	t.Helper()
	var unfiltered struct {
		Operations []indexOperationRowBody `json:"operations"`
	}
	resp := getJSON(t, base+"/index/v0/operations?limit=1", &unfiltered)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /index/v0/operations: status %d", resp.StatusCode)
	}
	if len(unfiltered.Operations) == 0 {
		t.Skip("relay's operation index is empty — no corpus to probe signerKey= against")
	}

	var probe struct {
		Operations []indexOperationRowBody `json:"operations"`
	}
	route := base + "/index/v0/operations?limit=1&signerKey=" +
		url.QueryEscape("conformance-probe-that-is-not-a-public-key !")
	resp = getJSON(t, route, &probe)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("signerKey= probe: status %d, want 200 (the value is opaque — there is no format to 400 on)", resp.StatusCode)
	}
	if len(probe.Operations) != 0 {
		t.Skip("relay does not implement signerKey= on /index/v0/operations (an unmatchable value returned rows) — skipping")
	}
}

// signerKeyCorpus is one accepted operation of EVERY indexable kind, with the
// signing key of each named, so a per-kind assertion can say which CID it
// expects the filter to return rather than merely counting rows.
//
// Two keys of ONE identity sign different ops — the author's CONTROLLER key
// signs the genesis, its AUTH key signs everything else. That is the
// discriminating shape for a key-addressed filter: a DID-addressed signer
// filter could not tell those two row sets apart.
type signerKeyCorpus struct {
	author  identity
	witness identity
	content contentChain

	genesisCID     string // identity-op, signed by author.controller — a BARE kid
	contentCreate  string // content-op, signed by author.auth
	artifactCID    string // artifact, signed by author.auth
	credentialCID  string // credential, issued by author.auth
	revocationCID  string // revocation, signed by author.auth
	countersignCID string // countersign, signed by WITNESS.auth over contentCreate
}

func (c signerKeyCorpus) authorAuthKey() string {
	return c.author.auth.mk.PublicKeyMultibase
}

func (c signerKeyCorpus) authorControllerKey() string {
	return c.author.controller.mk.PublicKeyMultibase
}

func (c signerKeyCorpus) witnessAuthKey() string {
	return c.witness.auth.mk.PublicKeyMultibase
}

func buildSignerKeyCorpus(t *testing.T, base string) signerKeyCorpus {
	t.Helper()
	author := createIdentity(t, base)
	witness := createIdentity(t, base)
	content := createContent(t, base, author)

	authorKid := author.did + "#" + author.auth.keyID
	witnessKid := witness.did + "#" + witness.auth.keyID

	artifactToken, artifactCID, err := dfos.SignArtifact(
		author.did,
		map[string]any{"$schema": "conformance/signer-key/v1", "value": 1},
		authorKid, author.auth.priv,
	)
	if err != nil {
		t.Fatalf("SignArtifact: %v", err)
	}

	// aud MUST be "*": a relay ingests PUBLIC credentials as operations and
	// silently declines to hold private ones, so an audience-scoped credential
	// would never reach the operation index to be filtered at all.
	credential, err := dfos.CreateCredential(
		author.did, "*", authorKid,
		"chain:"+content.contentID, "read", 5*time.Minute, author.auth.priv,
	)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	credHeader, _, err := dfos.DecodeJWSUnsafe(credential)
	if err != nil {
		t.Fatalf("DecodeJWSUnsafe(credential): %v", err)
	}
	revocationToken, revocationCID := createRevocation(t, author.did, credHeader.CID, author.auth)

	countersignToken, countersignCID, err := dfos.SignCountersign(
		witness.did, content.genCID, witnessKid, witness.auth.priv,
	)
	if err != nil {
		t.Fatalf("SignCountersign: %v", err)
	}

	// Every op must be ACCEPTED, not merely answered with a 200: a corpus with a
	// silently rejected op would make the per-kind assertions below fail for a
	// reason that has nothing to do with the filter under test.
	postOperationsAccepted(t, base, []string{artifactToken, credential, revocationToken, countersignToken})

	return signerKeyCorpus{
		author:         author,
		witness:        witness,
		content:        content,
		genesisCID:     author.genCID,
		contentCreate:  content.genCID,
		artifactCID:    artifactCID,
		credentialCID:  credHeader.CID,
		revocationCID:  revocationCID,
		countersignCID: countersignCID,
	}
}

// operationsMatching returns the CIDs a /index/v0/operations query pages back in
// one shot, sorted, so multi-row assertions are order-independent.
func operationsMatching(t *testing.T, base, query string) []string {
	t.Helper()
	var body struct {
		Operations []indexOperationRowBody `json:"operations"`
	}
	route := base + "/index/v0/operations?" + query + "&limit=1000"
	resp := getJSON(t, route, &body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: status %d", route, resp.StatusCode)
	}
	cids := make([]string, 0, len(body.Operations))
	for _, row := range body.Operations {
		cids = append(cids, row.CID)
	}
	sort.Strings(cids)
	return cids
}

func signerKeyParam(publicKeyMultibase string) string {
	return "signerKey=" + url.QueryEscape(publicKeyMultibase)
}

func sortedCIDs(cids ...string) []string {
	out := append([]string{}, cids...)
	sort.Strings(out)
	return out
}

// equalSorted compares two ALREADY-SORTED string slices for set equality.
func equalSorted(a, b []string) bool {
	return strings.Join(a, ",") == strings.Join(b, ",")
}

// TestIndexOperationsSignerKeyPerRowKind is the core contract: every row kind is
// reachable through the key that actually signed it, and no row kind is reachable
// through a key that did not.
//
// The GENESIS row carries the load here. An identity genesis signs with a BARE
// key ID rather than a DID URL — the DID does not exist until the op is encoded
// — so a relay whose resolver splits the kid on "#" drops every genesis row from
// this filter silently, returning a plausible-looking answer that is simply
// missing a row kind. Naming the genesis CID is what turns that into a failure.
func TestIndexOperationsSignerKeyPerRowKind(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	c := buildSignerKeyCorpus(t, base)
	requireSignerKeyFilter(t, base)

	// The CONTROLLER key signed exactly one thing: the genesis, with a bare kid.
	byController := operationsMatching(t, base, signerKeyParam(c.authorControllerKey()))
	if !equalSorted(byController, sortedCIDs(c.genesisCID)) {
		t.Fatalf("signerKey=<controller> = %v, want exactly the genesis [%s] (a bare-kid row a #-splitting resolver drops)", byController, c.genesisCID)
	}

	// The AUTH key signed the content-op, the artifact, the credential, and the
	// revocation — four DIFFERENT row kinds under one key.
	byAuth := operationsMatching(t, base, signerKeyParam(c.authorAuthKey()))
	want := sortedCIDs(c.contentCreate, c.artifactCID, c.credentialCID, c.revocationCID)
	if !equalSorted(byAuth, want) {
		t.Fatalf("signerKey=<author auth> = %v, want %v (content-op + artifact + credential + revocation)", byAuth, want)
	}

	// The COUNTERSIGN row indexes the WITNESS's key — never the key that signed
	// the op being countersigned. The witness signed nothing else.
	byWitness := operationsMatching(t, base, signerKeyParam(c.witnessAuthKey()))
	if !equalSorted(byWitness, sortedCIDs(c.countersignCID)) {
		t.Fatalf("signerKey=<witness auth> = %v, want exactly the countersign [%s]", byWitness, c.countersignCID)
	}

	// Two keys of ONE identity partition its rows. A DID-addressed signer filter
	// would return the union for both values; this filter must not.
	for _, cid := range byController {
		if contains(byAuth, cid) {
			t.Fatalf("the author's controller and auth keys returned overlapping rows (%s)", cid)
		}
	}

	// The stored value is AS DECLARED, which is what makes the two key-addressed
	// filters interoperable: the very same string, byte for byte, resolves the
	// signing identity through /index/v0/identities?key=.
	var identities struct {
		Identities []struct {
			DID string `json:"did"`
		} `json:"identities"`
	}
	route := base + "/index/v0/identities?key=" + url.QueryEscape(c.authorAuthKey()) + "&limit=1000"
	resp := getJSON(t, route, &identities)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: status %d", route, resp.StatusCode)
	}
	found := false
	for _, row := range identities.Identities {
		if row.DID == c.author.did {
			found = true
		}
	}
	if !found {
		t.Fatalf("the string signerKey= matched does not resolve through identities?key= — the two filters are not speaking the same alphabet (rows: %+v)", identities.Identities)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestIndexOperationsSignerKeyIsOpaque pins the no-format-validation posture:
// the value is matched as bytes, so anything unmatched is an EMPTY 200 and never
// a 400 — including the two well-formed protocol strings a caller is most likely
// to paste by mistake, a kid and a DID. Neither is a public key.
func TestIndexOperationsSignerKeyIsOpaque(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	c := buildSignerKeyCorpus(t, base)
	requireSignerKeyFilter(t, base)

	for _, garbage := range []string{
		"not-a-multibase-key !",
		c.author.did + "#" + c.author.auth.keyID, // a valid kid
		c.author.did,                             // a valid DID
		"z" + strings.Repeat("0", 44),            // multibase-SHAPED, declared by nothing
		"   ",
	} {
		route := base + "/index/v0/operations?" + signerKeyParam(garbage)
		var body struct {
			Operations []indexOperationRowBody `json:"operations"`
			Error      string                  `json:"error"`
		}
		resp := getJSON(t, route, &body)
		if resp.StatusCode != 200 {
			t.Fatalf("signerKey=%q: status %d (error %q), want 200 — the value is opaque bytes, not a validated format", garbage, resp.StatusCode, body.Error)
		}
		if len(body.Operations) != 0 {
			t.Fatalf("signerKey=%q returned %d rows, want an empty page", garbage, len(body.Operations))
		}
	}

	// THE ROW SHAPE, AS THE SPEC FIXES IT AND NO TIGHTER. WEB-RELAY.md prohibits
	// exactly four row contents — "they contain no JWS, payload, title, or name" —
	// and that is what a third-party relay is gated on here. This suite tests
	// MUSTs, not the reference twins' habits: the same section describes the
	// resolved signer key as "stored metadata" the row RETAINS, so a relay that
	// surfaces it is conformant, and an assertion that signerKey is "never a
	// field" would have failed it for a shape the spec permits. The reference
	// relays pin their own leaner row shape in their own suites
	// (dfos-web-relay/tests, dfos-web-relay-go), which is where a house
	// convention belongs — not in the bar third parties are measured against.
	prohibited := []string{"jws", "jwsToken", "payload", "title", "name"}
	var rows struct {
		Operations []map[string]any `json:"operations"`
	}
	route := base + "/index/v0/operations?" + signerKeyParam(c.authorAuthKey()) + "&limit=1000"
	resp := getJSON(t, route, &rows)
	if resp.StatusCode != 200 || len(rows.Operations) == 0 {
		t.Fatalf("GET %s: status %d, %d rows", route, resp.StatusCode, len(rows.Operations))
	}
	for _, row := range rows.Operations {
		for _, member := range prohibited {
			if _, present := row[member]; present {
				t.Fatalf("operations row carries prohibited content %q — rows are browsing "+
					"metadata, never proof: %+v", member, row)
			}
		}
	}
}

// TestIndexOperationsSignerKeyComposesAndPages covers the two mechanical
// properties the route shares with its siblings: filters AND, and the filtered
// feed drains through the ordered cursor exactly once under BOTH orderings.
func TestIndexOperationsSignerKeyComposesAndPages(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	c := buildSignerKeyCorpus(t, base)
	requireSignerKeyFilter(t, base)

	authKey := signerKeyParam(c.authorAuthKey())

	// ANDs with kind=
	if got := operationsMatching(t, base, authKey+"&kind=artifact"); !equalSorted(got, sortedCIDs(c.artifactCID)) {
		t.Fatalf("signerKey=<auth>&kind=artifact = %v, want [%s]", got, c.artifactCID)
	}
	if got := operationsMatching(t, base, authKey+"&kind=countersign"); len(got) != 0 {
		t.Fatalf("signerKey=<auth>&kind=countersign = %v, want an empty page (the witness signed that row)", got)
	}

	// ANDs with chainId=
	onContent := operationsMatching(t, base, authKey+"&chainId="+url.QueryEscape(c.content.contentID))
	if !equalSorted(onContent, sortedCIDs(c.contentCreate)) {
		t.Fatalf("signerKey=<auth>&chainId=<content> = %v, want [%s]", onContent, c.contentCreate)
	}

	// A contradictory AND is an HONESTLY empty page, not an error.
	contradiction := operationsMatching(t, base,
		signerKeyParam(c.witnessAuthKey())+"&chainId="+url.QueryEscape(c.content.contentID))
	if len(contradiction) != 0 {
		t.Fatalf("signerKey=<witness>&chainId=<content> = %v, want an empty page", contradiction)
	}

	// PAGINATION under both orderings. Same filtered set, drained one row per
	// page, no repeats — the cursor must carry the filter across pages.
	unpaged := operationsMatching(t, base, authKey)
	if len(unpaged) < 2 {
		t.Fatalf("the signerKey-filtered feed has %d rows — too few to page", len(unpaged))
	}
	for _, order := range []string{"createdAt.desc", "ingestedAt.desc"} {
		walked := []string{}
		seen := map[string]bool{}
		after := ""
		for page := 0; page < 50; page++ {
			route := base + "/index/v0/operations?" + authKey + "&order=" + order + "&limit=1"
			if after != "" {
				route += "&after=" + url.QueryEscape(after)
			}
			var body struct {
				Operations []indexOperationRowBody `json:"operations"`
				Next       *string                 `json:"next"`
			}
			resp := getJSON(t, route, &body)
			if resp.StatusCode != 200 {
				t.Fatalf("order=%s page %d: status %d", order, page, resp.StatusCode)
			}
			for _, row := range body.Operations {
				if seen[row.CID] {
					t.Fatalf("order=%s walk revisited %s", order, row.CID)
				}
				seen[row.CID] = true
				walked = append(walked, row.CID)
			}
			if body.Next == nil {
				break
			}
			after = *body.Next
		}
		sort.Strings(walked)
		if !equalSorted(walked, unpaged) {
			t.Fatalf("order=%s walk visited %v, want the unpaged set %v", order, walked, unpaged)
		}
	}
}

// TestIndexOperationsSignerKeySurvivesRotation pins the value as an INGEST-TIME
// FREEZE rather than a live lookup against head state. A key a later update
// rotates out still answers for every row it signed — which is the whole point
// of a key-addressed audit filter, since the rows that matter most to a holder
// recovering from key loss are exactly the ones signed by keys no longer current.
func TestIndexOperationsSignerKeySurvivesRotation(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	c := buildSignerKeyCorpus(t, base)
	requireSignerKeyFilter(t, base)

	before := operationsMatching(t, base, signerKeyParam(c.authorAuthKey()))
	if len(before) == 0 {
		t.Fatal("author auth key matched nothing before the rotation")
	}

	replacement := newKeypair()
	controllerKid := c.author.did + "#" + c.author.controller.keyID
	rotateToken, rotateCID, err := dfos.SignIdentityUpdate(
		c.author.genCID,
		[]dfos.MultikeyPublicKey{c.author.controller.mk},
		[]dfos.MultikeyPublicKey{replacement.mk},
		[]dfos.MultikeyPublicKey{},
		controllerKid, c.author.controller.priv,
	)
	if err != nil {
		t.Fatalf("SignIdentityUpdate: %v", err)
	}
	res := postOperations(t, base, []string{rotateToken})
	if res.StatusCode != 200 {
		t.Fatalf("rotate: status %d, body: %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()

	// The rotated-out key keeps every row it signed, unchanged.
	after := operationsMatching(t, base, signerKeyParam(c.authorAuthKey()))
	if !equalSorted(after, before) {
		t.Fatalf("rotated-out key matched %v after the rotation, want the unchanged set %v", after, before)
	}

	// The controller key picks up the update it signed, alongside the genesis.
	byController := operationsMatching(t, base, signerKeyParam(c.authorControllerKey()))
	if !equalSorted(byController, sortedCIDs(c.genesisCID, rotateCID)) {
		t.Fatalf("signerKey=<controller> = %v, want the genesis + the update it signed %v", byController, sortedCIDs(c.genesisCID, rotateCID))
	}

	// The REPLACEMENT key has signed nothing yet: declared is not signed.
	if got := operationsMatching(t, base, signerKeyParam(replacement.mk.PublicKeyMultibase)); len(got) != 0 {
		t.Fatalf("signerKey=<replacement> = %v, want an empty page — the key is declared, not yet used", got)
	}

	// ...until it signs. Then it matches exactly what it signed, and the
	// rotated-out key's set is still untouched.
	doc := map[string]any{"type": "post", "title": "after the rotation"}
	docCID, _, err := dfos.DocumentCID(doc)
	if err != nil {
		t.Fatalf("DocumentCID: %v", err)
	}
	updateToken, updateCID, err := dfos.SignContentUpdate(
		c.author.did, c.content.genCID, docCID,
		c.author.did+"#"+replacement.keyID, replacement.priv,
	)
	if err != nil {
		t.Fatalf("SignContentUpdate: %v", err)
	}
	res = postOperations(t, base, []string{updateToken})
	if res.StatusCode != 200 {
		t.Fatalf("content update: status %d, body: %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()

	if got := operationsMatching(t, base, signerKeyParam(replacement.mk.PublicKeyMultibase)); !equalSorted(got, sortedCIDs(updateCID)) {
		t.Fatalf("signerKey=<replacement> = %v, want exactly the op it signed [%s]", got, updateCID)
	}
	if got := operationsMatching(t, base, signerKeyParam(c.authorAuthKey())); !equalSorted(got, before) {
		t.Fatalf("rotated-out key's set drifted to %v after the replacement signed, want %v", got, before)
	}
}

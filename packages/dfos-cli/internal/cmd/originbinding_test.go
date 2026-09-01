package cmd

// Origin-binding tests. Every rule in specs/ORIGIN-BINDING.md that the CLI
// enforces is exercised here as a PURE fold — domain validation, claim reading,
// record/body parsing, the bind plan, the verdict matrix — plus the two
// command-level paths that touch nothing but the local relay. No test resolves
// DNS or leaves the machine: the probes are thin wrappers over these folds by
// construction, and the one rule no fold can express — that the client follows
// no redirect — is pinned against a loopback httptest server.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

const (
	testOriginDID      = "did:dfos:cv7n8vkvr64cctf3294h9k4eanhff8z"
	testOriginOtherDID = "did:dfos:2222222222222222222222222222222"
)

// ---------------------------------------------------------------------------
// domain validation
// ---------------------------------------------------------------------------

func TestValidateDomainAccepts(t *testing.T) {
	cases := map[string]string{
		"plain":                  "example.com",
		"subdomain":              "dfos-siwd-demo.vercel.app",
		"trailing dot stripped":  "example.com.",
		"uppercase lowercased":   "Example.COM",
		"surrounding whitespace": "  example.com\n",
		"digits and hyphens":     "a1-b2.example-site.org",
		"punycode a-label":       "xn--80ak6aa92e.com",
		"deep":                   "a.b.c.d.example.com",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := validateDomain(in)
			if err != nil {
				t.Fatalf("validateDomain(%q) = error %v, want accept", in, err)
			}
			if got != strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in), ".")) {
				t.Fatalf("validateDomain(%q) = %q", in, got)
			}
		})
	}
}

func TestValidateDomainRejects(t *testing.T) {
	cases := map[string]string{
		"empty":               "",
		"whitespace only":     "   ",
		"scheme":              "https://example.com",
		"path":                "example.com/.well-known/dfos-did",
		"query":               "example.com?a=1",
		"port":                "example.com:8443",
		"underscore":          "_dfos.example.com",
		"no dot":              "localhost",
		"empty label":         "example..com",
		"leading hyphen":      "-example.com",
		"trailing hyphen":     "example-.com",
		"non-ascii":           "café.com",
		"space inside":        "exa mple.com",
		"double trailing dot": "example.com..",
		"too long label":      strings.Repeat("a", 64) + ".com",
		"too long domain":     strings.Repeat("a.", 130) + "com",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := validateDomain(in); err == nil {
				t.Fatalf("validateDomain(%q) = %q, want rejection", in, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// the chain's half
// ---------------------------------------------------------------------------

func originEntry(id, domain string) protocol.ServiceEntry {
	return protocol.ServiceEntry{"id": id, "type": originServiceType, "domain": domain}
}

func TestReadOriginClaim(t *testing.T) {
	relayEntry := protocol.ServiceEntry{"id": "relay", "type": "DfosRelay", "endpoint": "https://relay.dfos.com"}

	cases := map[string]struct {
		services []protocol.ServiceEntry
		want     string
	}{
		"none":                     {nil, ""},
		"only other types":         {[]protocol.ServiceEntry{relayEntry}, ""},
		"one valid":                {[]protocol.ServiceEntry{relayEntry, originEntry("origin", "example.com")}, "example.com"},
		"two entries claim naught": {[]protocol.ServiceEntry{originEntry("a", "example.com"), originEntry("b", "example.com")}, ""},
		"missing domain":           {[]protocol.ServiceEntry{{"id": "origin", "type": originServiceType}}, ""},
		"empty domain":             {[]protocol.ServiceEntry{originEntry("origin", "")}, ""},
		"non-string domain":        {[]protocol.ServiceEntry{{"id": "origin", "type": originServiceType, "domain": 42}}, ""},
		"non-canonical uppercase":  {[]protocol.ServiceEntry{originEntry("origin", "Example.com")}, ""},
		"non-canonical trailing":   {[]protocol.ServiceEntry{originEntry("origin", "example.com.")}, ""},
		"url not hostname":         {[]protocol.ServiceEntry{originEntry("origin", "https://example.com")}, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := readOriginClaim(tc.services)
			if got.Domain != tc.want {
				t.Fatalf("claim = %q (reason %q), want %q", got.Domain, got.Reason, tc.want)
			}
			if got.Domain == "" && got.Reason == "" {
				t.Fatal("a no-claim result must explain itself")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// the domain's half
// ---------------------------------------------------------------------------

func TestDIDFromWellKnownBody(t *testing.T) {
	cases := map[string]struct {
		body string
		want string
	}{
		"exact":               {testOriginDID, testOriginDID},
		"trailing newline":    {testOriginDID + "\n", testOriginDID},
		"surrounded":          {"  \t" + testOriginDID + " \r\n", testOriginDID},
		"empty":               {"", ""},
		"whitespace only":     {"\n\n", ""},
		"not a did":           {"hello", ""},
		"wrong method":        {"did:web:example.com", ""},
		"truncated id":        {testOriginDID[:len(testOriginDID)-1], ""},
		"extra char":          {testOriginDID + "z", ""},
		"two dids":            {testOriginDID + "\n" + testOriginOtherDID, ""},
		"html error page":     {"<!doctype html><title>404</title>", ""},
		"did with prose":      {"did=" + testOriginDID, ""},
		"internal whitespace": {"did:dfos: " + testOriginDID[9:], ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := didFromWellKnownBody([]byte(tc.body))
			if tc.want == "" {
				if ok {
					t.Fatalf("didFromWellKnownBody(%q) = %q, want rejection", tc.body, got)
				}
				return
			}
			if !ok || got != tc.want {
				t.Fatalf("didFromWellKnownBody(%q) = %q/%v, want %q", tc.body, got, ok, tc.want)
			}
		})
	}
}

func TestDIDFromAppDescription(t *testing.T) {
	full := `{"name":"Demo","redirect_uris":["https://example.com/cb"],"client_did":"` + testOriginDID + `"}`

	cases := map[string]struct {
		body string
		want string
	}{
		"structurally valid":     {full, testOriginDID},
		"extra members ignored":  {`{"name":"Demo","logo":"x","redirect_uris":["https://e/cb"],"client_did":"` + testOriginDID + `"}`, testOriginDID},
		"missing name accepted":  {`{"redirect_uris":["https://e/cb"],"client_did":"` + testOriginDID + `"}`, testOriginDID},
		"empty name":             {`{"name":"","redirect_uris":["https://e/cb"],"client_did":"` + testOriginDID + `"}`, ""},
		"non-string name":        {`{"name":42,"redirect_uris":["https://e/cb"],"client_did":"` + testOriginDID + `"}`, ""},
		"missing redirect_uris":  {`{"name":"Demo","client_did":"` + testOriginDID + `"}`, ""},
		"empty redirect_uris":    {`{"name":"Demo","redirect_uris":[],"client_did":"` + testOriginDID + `"}`, ""},
		"redirect_uris not list": {`{"name":"Demo","redirect_uris":"https://e/cb","client_did":"` + testOriginDID + `"}`, ""},
		"missing client_did":     {`{"name":"Demo","redirect_uris":["https://e/cb"]}`, ""},
		"malformed client_did":   {`{"name":"Demo","redirect_uris":["https://e/cb"],"client_did":"did:web:e"}`, ""},
		"not json":               {"not json", ""},
		"json null":              {"null", ""},
		"json array":             {"[]", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := didFromAppDescription([]byte(tc.body))
			if tc.want == "" {
				if ok {
					t.Fatalf("didFromAppDescription(%q) = %q, want rejection", tc.body, got)
				}
				return
			}
			if !ok || got != tc.want {
				t.Fatalf("didFromAppDescription(%q) = %q/%v, want %q", tc.body, got, ok, tc.want)
			}
		})
	}
}

func TestFoldTXTRecords(t *testing.T) {
	long := "did=" + testOriginDID // a joined multi-chunk record arrives as one string

	cases := map[string]struct {
		records       []string
		wantDID       string
		contradiction bool
	}{
		"no records":              {nil, "", false},
		"no did= record":          {[]string{"v=spf1 -all", "google-site-verification=x"}, "", false},
		"one valid":               {[]string{long}, testOriginDID, false},
		"valid among others":      {[]string{"v=spf1 -all", long}, testOriginDID, false},
		"surrounding whitespace":  {[]string{" " + long + " "}, testOriginDID, false},
		"two did= contradiction":  {[]string{long, "did=" + testOriginOtherDID}, "", true},
		"two identical did=":      {[]string{long, long}, "", true},
		"malformed value":         {[]string{"did=nope"}, "", false},
		"empty value":             {[]string{"did="}, "", false},
		"did= with trailing junk": {[]string{long + " extra"}, "", false},
		"case-sensitive tag":      {[]string{"DID=" + testOriginDID}, "", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := foldTXTRecords("example.com", tc.records)
			if got.DID != tc.wantDID {
				t.Fatalf("did = %q, want %q (detail %q)", got.DID, tc.wantDID, got.Detail)
			}
			if got.Contradiction != tc.contradiction {
				t.Fatalf("contradiction = %v, want %v", got.Contradiction, tc.contradiction)
			}
			if got.Detail == "" {
				t.Fatal("every method result must carry a detail line")
			}
			if got.Source != "_dfos.example.com" {
				t.Fatalf("source = %q", got.Source)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// verdict fold
// ---------------------------------------------------------------------------

func answerResult(name, did string, fallback bool) methodResult {
	return methodResult{Name: name, DID: did, Detail: "attests " + did, Fallback: fallback}
}

func silentResult(name string) methodResult {
	return methodResult{Name: name, Detail: "silent"}
}

func contradictionResult(name string) methodResult {
	return methodResult{Name: name, Detail: "two did= records", Contradiction: true}
}

func TestFoldVerdict(t *testing.T) {
	cases := map[string]struct {
		results []methodResult
		want    bindingVerdict
	}{
		"both agree with chain":       {[]methodResult{answerResult("https", testOriginDID, false), answerResult("dns", testOriginDID, false)}, verdictBound},
		"https only":                  {[]methodResult{answerResult("https", testOriginDID, false), silentResult("dns")}, verdictBound},
		"dns only":                    {[]methodResult{silentResult("https"), answerResult("dns", testOriginDID, false)}, verdictBound},
		"fallback attests":            {[]methodResult{answerResult("https", testOriginDID, true), silentResult("dns")}, verdictBound},
		"all silent":                  {[]methodResult{silentResult("https"), silentResult("dns")}, verdictStale},
		"https attests another":       {[]methodResult{answerResult("https", testOriginOtherDID, false), silentResult("dns")}, verdictBroken},
		"dns attests another":         {[]methodResult{silentResult("https"), answerResult("dns", testOriginOtherDID, false)}, verdictBroken},
		"fallback attests another":    {[]methodResult{answerResult("https", testOriginOtherDID, true), silentResult("dns")}, verdictBroken},
		"methods disagree":            {[]methodResult{answerResult("https", testOriginDID, false), answerResult("dns", testOriginOtherDID, false)}, verdictBroken},
		"dns contradiction":           {[]methodResult{answerResult("https", testOriginDID, false), contradictionResult("dns")}, verdictBroken},
		"contradiction beats silence": {[]methodResult{silentResult("https"), contradictionResult("dns")}, verdictBroken},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := foldVerdict(testOriginDID, tc.results); got != tc.want {
				t.Fatalf("foldVerdict = %q, want %q", got, tc.want)
			}
		})
	}
}

// foldVerdict with no chain DID is the domain-first pre-check: only
// self-contradiction and method-vs-method disagreement can be judged.
func TestFoldVerdictWithoutChainDID(t *testing.T) {
	cases := map[string]struct {
		results []methodResult
		want    bindingVerdict
	}{
		"single answer is not yet broken": {[]methodResult{answerResult("https", testOriginOtherDID, false), silentResult("dns")}, verdictBound},
		"disagreement is broken":          {[]methodResult{answerResult("https", testOriginDID, false), answerResult("dns", testOriginOtherDID, false)}, verdictBroken},
		"contradiction is broken":         {[]methodResult{silentResult("https"), contradictionResult("dns")}, verdictBroken},
		"silence is stale":                {[]methodResult{silentResult("https"), silentResult("dns")}, verdictStale},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := foldVerdict("", tc.results); got != tc.want {
				t.Fatalf("foldVerdict = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestVerdictExitCodes(t *testing.T) {
	want := map[bindingVerdict]int{
		verdictBound:   0,
		verdictBroken:  1,
		verdictStale:   2,
		verdictNoClaim: 0,
	}
	for v, code := range want {
		if got := v.exitCode(); got != code {
			t.Fatalf("%s exit code = %d, want %d", v, got, code)
		}
		if v.meaning() == "" {
			t.Fatalf("%s has no meaning sentence", v)
		}
	}
}

// ---------------------------------------------------------------------------
// redirect policy — ORIGIN-BINDING.md: verifiers "MUST NOT follow redirects",
// and "a redirect is a non-answer, never a contradiction"
// ---------------------------------------------------------------------------

// The one rule no fold can check: the client itself must not follow. A same-host
// hop to a path serving a perfectly good DID is exactly what the CLI used to
// follow and now refuses — what the probe reads is the 3xx, not the body behind
// it, because a followed hop makes the effective serving path unauditable.
func TestAttestationClientFollowsNoRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			_, _ = w.Write([]byte(testOriginDID))
			return
		}
		http.Redirect(w, r, "/moved", http.StatusFound)
	}))
	defer srv.Close()

	got, err := fetchCapped(attestationClient(), srv.URL+wellKnownDIDPath, wellKnownDIDCap)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got.status != http.StatusFound {
		t.Fatalf("status = %d, want %d — the redirect was followed", got.status, http.StatusFound)
	}
	if did, ok := didFromWellKnownBody(got.body); ok {
		t.Fatalf("the hop's body attested %s — the redirect was followed", did)
	}
}

// The non-answer class, and the fallback trigger that rides it. The spec's
// trigger is the WHOLE class — "a 404; a redirect, which is absence in
// everything but status code; or a 200 whose trimmed body is not exactly one
// DFOS DID" — so every one of those MUST reach the app description, and none of
// them may answer.
func TestClassifyWellKnown(t *testing.T) {
	cases := map[string]struct {
		status       int
		body         string
		over         bool
		wantDID      string
		wantFallback bool
	}{
		"attests":            {200, "  " + testOriginDID + "\n", false, testOriginDID, false},
		"absent":             {404, "", false, "", true},
		"gone":               {410, "", false, "", true},
		"moved permanently":  {301, "", false, "", true},
		"found":              {302, "", false, "", true},
		"see other":          {303, "", false, "", true},
		"temporary redirect": {307, "", false, "", true},
		"permanent redirect": {308, "", false, "", true},
		"app shell":          {200, "<!doctype html><html></html>", false, "", true},
		"empty body":         {200, "\n", false, "", true},
		"two dids":           {200, testOriginDID + "\n" + testOriginOtherDID, false, "", true},
		"over the cap":       {200, "", true, "", true},
		"server error":       {500, "", false, "", false},
		"forbidden":          {403, "", false, "", false},
		"unauthorized":       {401, "", false, "", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := classifyWellKnown(tc.status, []byte(tc.body), tc.over)
			if got.DID != tc.wantDID {
				t.Fatalf("DID = %q, want %q", got.DID, tc.wantDID)
			}
			if got.Fallback != tc.wantFallback {
				t.Fatalf("Fallback = %v, want %v", got.Fallback, tc.wantFallback)
			}
			if got.DID == "" && got.Note == "" {
				t.Fatal("a non-answer carries no note for the ladder to print")
			}
			if got.DID != "" && got.Fallback {
				t.Fatal("an answer asked for the fallback")
			}
		})
	}
}

// The well-known's redirect note says all three things the walk owes an
// operator: the origin redirected, the redirect was not followed, and the
// channel therefore said nothing.
func TestClassifyWellKnownRedirectNoteNamesTheRule(t *testing.T) {
	note := classifyWellKnown(http.StatusFound, nil, false).Note
	for _, want := range []string{"302", "redirect", "not followed", wellKnownDIDPath} {
		if !strings.Contains(note, want) {
			t.Fatalf("redirect note %q does not mention %q", note, want)
		}
	}
}

// The fallback leg runs "under the same no-redirects rule", and has nowhere
// further to fall: every non-answer there is plain silence.
func TestClassifyAppDescription(t *testing.T) {
	good := `{"name":"Demo","redirect_uris":["https://example.com/cb"],"client_did":"` + testOriginDID + `"}`
	cases := map[string]struct {
		status  int
		body    string
		over    bool
		wantDID string
	}{
		"attests":      {200, good, false, testOriginDID},
		"redirect":     {302, "", false, ""},
		"absent":       {404, "", false, ""},
		"not an app":   {200, "<!doctype html>", false, ""},
		"over the cap": {200, "", true, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			did, note := classifyAppDescription(tc.status, []byte(tc.body), tc.over)
			if did != tc.wantDID {
				t.Fatalf("did = %q, want %q", did, tc.wantDID)
			}
			if did == "" && note == "" {
				t.Fatal("a silent fallback carries no note")
			}
			if did != "" && note != "" {
				t.Fatalf("an answer carries a silence note: %q", note)
			}
		})
	}
	if _, note := classifyAppDescription(http.StatusFound, nil, false); !strings.Contains(note, "not followed") {
		t.Fatalf("app-description redirect note %q does not say the redirect was not followed", note)
	}
}

// The whole ruling in one assertion: a domain that redirects at the well-known
// path and serves nothing else is STALE — could not check — never broken.
// Nothing contradicted anything.
func TestRedirectIsNeverBroken(t *testing.T) {
	out := classifyWellKnown(http.StatusMovedPermanently, nil, false)
	if out.DID != "" {
		t.Fatalf("a redirect answered %q", out.DID)
	}
	silentHTTPS := methodResult{Name: "https", Source: appDescriptionPath, Fallback: true, Detail: "silent (" + out.Note + "; no app description)"}
	silentDNS := methodResult{Name: "dns", Detail: "silent (no _dfos TXT record)"}
	if got := foldVerdict(testOriginDID, []methodResult{silentHTTPS, silentDNS}); got != verdictStale {
		t.Fatalf("verdict = %s, want %s", got, verdictStale)
	}
}

// ---------------------------------------------------------------------------
// bind plan
// ---------------------------------------------------------------------------

func TestPlanOriginBindingAppends(t *testing.T) {
	existing := []protocol.ServiceEntry{{"id": "relay", "type": "DfosRelay", "endpoint": "https://relay.dfos.com"}}
	plan, err := planOriginBinding(existing, "example.com", "")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Action != bindActionNew || plan.ID != defaultOriginServiceID {
		t.Fatalf("plan = %+v", plan)
	}
	if len(plan.Services) != 2 || plan.Services[0]["id"] != "relay" {
		t.Fatalf("other services were not carried forward: %v", plan.Services)
	}
	if got := readOriginClaim(plan.Services); got.Domain != "example.com" {
		t.Fatalf("planned set claims %q", got.Domain)
	}
	// the input slice must not be mutated
	if len(existing) != 1 {
		t.Fatal("planOriginBinding mutated the chain-state slice")
	}
}

func TestPlanOriginBindingReplacesInPlace(t *testing.T) {
	existing := []protocol.ServiceEntry{
		originEntry("site", "old.example"),
		{"id": "relay", "type": "DfosRelay", "endpoint": "https://relay.dfos.com"},
	}
	plan, err := planOriginBinding(existing, "new.example", "")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Action != bindActionRebind || plan.Previous != "old.example" || plan.ID != "site" {
		t.Fatalf("plan = %+v", plan)
	}
	if len(plan.Services) != 2 || plan.Services[0]["id"] != "site" || plan.Services[1]["id"] != "relay" {
		t.Fatalf("entry was not replaced in place: %v", plan.Services)
	}
	if got := readOriginClaim(plan.Services); got.Domain != "new.example" {
		t.Fatalf("planned set claims %q", got.Domain)
	}
}

func TestPlanOriginBindingUnchanged(t *testing.T) {
	existing := []protocol.ServiceEntry{originEntry("origin", "example.com")}
	plan, err := planOriginBinding(existing, "example.com", "")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Action != bindActionUnchanged {
		t.Fatalf("re-binding the same domain = %q, want unchanged", plan.Action)
	}
}

func TestPlanOriginBindingCollapsesMultiple(t *testing.T) {
	existing := []protocol.ServiceEntry{
		originEntry("a", "one.example"),
		{"id": "relay", "type": "DfosRelay", "endpoint": "https://relay.dfos.com"},
		originEntry("b", "two.example"),
	}
	plan, err := planOriginBinding(existing, "three.example", "")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Collapsed != 1 {
		t.Fatalf("collapsed = %d, want 1", plan.Collapsed)
	}
	if len(plan.Services) != 2 {
		t.Fatalf("services = %v, want the relay plus one DfosOrigin", plan.Services)
	}
	if got := readOriginClaim(plan.Services); got.Domain != "three.example" {
		t.Fatalf("collapsed set claims %q (%s)", got.Domain, got.Reason)
	}
}

func TestPlanOriginBindingRejectsIDCollision(t *testing.T) {
	existing := []protocol.ServiceEntry{{"id": "origin", "type": "DfosRelay", "endpoint": "https://relay.dfos.com"}}
	if _, err := planOriginBinding(existing, "example.com", ""); err == nil {
		t.Fatal("id collision with a non-DfosOrigin entry was accepted")
	} else if !strings.Contains(err.Error(), "--id") {
		t.Fatalf("collision error does not suggest --id: %v", err)
	}
	// --id resolves it
	plan, err := planOriginBinding(existing, "example.com", "site")
	if err != nil {
		t.Fatalf("plan with --id: %v", err)
	}
	if plan.ID != "site" || len(plan.Services) != 2 {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestPlanOriginBindingDropsAdHocMembers(t *testing.T) {
	existing := []protocol.ServiceEntry{{"id": "origin", "type": originServiceType, "domain": "old.example", "note": "stale"}}
	plan, err := planOriginBinding(existing, "new.example", "")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if _, present := plan.Services[0]["note"]; present {
		t.Fatalf("ad-hoc member survived the rebind: %v", plan.Services[0])
	}
	if len(plan.Services[0]) != 3 {
		t.Fatalf("entry = %v, want exactly {id, type, domain}", plan.Services[0])
	}
}

// ---------------------------------------------------------------------------
// command paths (local relay only — no network)
// ---------------------------------------------------------------------------

type bindDomainOutput struct {
	DID              string `json:"did"`
	Domain           string `json:"domain"`
	ServiceID        string `json:"serviceID"`
	OperationCID     string `json:"operationCID"`
	PreviousDomain   string `json:"previousDomain"`
	CollapsedEntries int    `json:"collapsedEntries"`
	Unchanged        bool   `json:"unchanged"`
	WellKnown        struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	} `json:"wellKnown"`
	DNSRecord struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"dnsRecord"`
}

func TestBindDomainWritesClaimAndInstructions(t *testing.T) {
	store, _, lr := setupDevices(t)
	did := createIdentity(t, "alice", store)

	keys = store
	var out bindDomainOutput
	runJSON(t, newIdentityBindDomainCmd(), []string{"Example.COM."}, &out)

	if out.DID != did || out.Domain != "example.com" || out.ServiceID != defaultOriginServiceID {
		t.Fatalf("bind-domain output = %+v", out)
	}
	if out.OperationCID == "" {
		t.Fatal("no operation CID — the claim was not signed")
	}
	if out.WellKnown.Path != wellKnownDIDPath || out.WellKnown.Content != did {
		t.Fatalf("well-known instruction = %+v", out.WellKnown)
	}
	if out.DNSRecord.Name != "_dfos.example.com." || out.DNSRecord.Type != "TXT" || out.DNSRecord.Value != "did="+did {
		t.Fatalf("dns instruction = %+v", out.DNSRecord)
	}

	chain, err := lr.Relay.GetIdentity(did)
	if err != nil || chain == nil {
		t.Fatalf("get identity: %v", err)
	}
	if got := readOriginClaim(chain.State.Services); got.Domain != "example.com" {
		t.Fatalf("chain claims %q (%s)", got.Domain, got.Reason)
	}
	if len(chain.Log) != 2 {
		t.Fatalf("chain has %d operations, want 2", len(chain.Log))
	}
}

func TestBindDomainRejectsMalformedDomain(t *testing.T) {
	store, _, _ := setupDevices(t)
	createIdentity(t, "alice", store)

	keys = store
	cmd := newIdentityBindDomainCmd()
	err := cmd.RunE(cmd, []string{"https://example.com/x"})
	if err == nil {
		t.Fatal("bind-domain accepted a URL")
	}
	if !strings.Contains(err.Error(), "bare hostname") {
		t.Fatalf("error does not steer to the bare hostname: %v", err)
	}
}

func TestBindDomainIsIdempotent(t *testing.T) {
	store, _, lr := setupDevices(t)
	did := createIdentity(t, "alice", store)

	keys = store
	runJSON(t, newIdentityBindDomainCmd(), []string{"example.com"}, nil)
	before, _ := lr.Relay.GetIdentity(did)

	var second bindDomainOutput
	runJSON(t, newIdentityBindDomainCmd(), []string{"example.com"}, &second)
	if !second.Unchanged || second.OperationCID != "" {
		t.Fatalf("re-binding the same domain signed an operation: %+v", second)
	}
	after, _ := lr.Relay.GetIdentity(did)
	if len(after.Log) != len(before.Log) {
		t.Fatalf("chain grew from %d to %d operations", len(before.Log), len(after.Log))
	}
}

func TestBindDomainRebinds(t *testing.T) {
	store, _, lr := setupDevices(t)
	did := createIdentity(t, "alice", store)

	keys = store
	runJSON(t, newIdentityBindDomainCmd(), []string{"old.example"}, nil)

	var out bindDomainOutput
	runJSON(t, newIdentityBindDomainCmd(), []string{"new.example"}, &out)
	if out.PreviousDomain != "old.example" {
		t.Fatalf("previousDomain = %q, want old.example", out.PreviousDomain)
	}

	chain, _ := lr.Relay.GetIdentity(did)
	if got := readOriginClaim(chain.State.Services); got.Domain != "new.example" {
		t.Fatalf("chain claims %q after rebind", got.Domain)
	}
	if len(originEntryIndexes(chain.State.Services)) != 1 {
		t.Fatalf("rebind left %d DfosOrigin entries", len(originEntryIndexes(chain.State.Services)))
	}
}

func TestBindDomainCollapsesAmbiguousClaim(t *testing.T) {
	store, _, lr := setupDevices(t)
	did := createIdentity(t, "alice", store)

	// Two DfosOrigin entries land via the generic --service escape hatch: the
	// core carries them (open namespace), and a set with two claims nothing.
	keys = store
	upd := newIdentityUpdateCmd()
	mustSetFlag(t, upd, "service", "id=a,type=DfosOrigin,domain=one.example")
	mustSetFlag(t, upd, "service", "id=b,type=DfosOrigin,domain=two.example")
	if err := upd.RunE(upd, nil); err != nil {
		t.Fatalf("seed two DfosOrigin entries: %v", err)
	}
	seeded, _ := lr.Relay.GetIdentity(did)
	if got := readOriginClaim(seeded.State.Services); got.Domain != "" {
		t.Fatalf("two entries should claim nothing, got %q", got.Domain)
	}

	var out bindDomainOutput
	runJSON(t, newIdentityBindDomainCmd(), []string{"three.example"}, &out)
	if out.CollapsedEntries != 1 {
		t.Fatalf("collapsedEntries = %d, want 1", out.CollapsedEntries)
	}

	chain, _ := lr.Relay.GetIdentity(did)
	if got := readOriginClaim(chain.State.Services); got.Domain != "three.example" {
		t.Fatalf("chain claims %q (%s) after collapse", got.Domain, got.Reason)
	}
}

func TestVerifyBindingNoClaimExitsZero(t *testing.T) {
	store, _, _ := setupDevices(t)
	createIdentity(t, "alice", store)

	keys = store
	var out struct {
		DID     string `json:"did"`
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
	}
	// runJSON fails the test if RunE returns an error, which is exactly the
	// no-claim contract: nothing is claimed, exit 0, no probing.
	runJSON(t, newIdentityVerifyBindingCmd(), nil, &out)
	if out.Verdict != string(verdictNoClaim) {
		t.Fatalf("verdict = %q, want no-claim", out.Verdict)
	}
	if out.Reason == "" {
		t.Fatal("no-claim verdict must say why")
	}
}

func TestVerifyBindingRejectsUnresolvableTarget(t *testing.T) {
	store, _, _ := setupDevices(t)
	createIdentity(t, "alice", store)

	keys = store
	cmd := newIdentityVerifyBindingCmd()
	err := cmd.RunE(cmd, []string{"not a domain"})
	if err == nil {
		t.Fatal("verify-binding accepted a target that is neither identity nor hostname")
	}
	if !strings.Contains(err.Error(), "bare hostname") {
		t.Fatalf("error does not name the accepted forms: %v", err)
	}
}

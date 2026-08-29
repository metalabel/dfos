package cmd

// Origin binding — the CLI half of specs/ORIGIN-BINDING.md
// (https://protocol.dfos.com/origin-binding).
//
// A DfosOrigin services entry names a domain inside the signed identity chain;
// the domain attests the DID back over HTTPS (/.well-known/dfos-did, with the
// SIWD app-description fallback) or DNS (a did= TXT record at _dfos.<domain>).
// A verifier folds the two halves into one of three verdicts: bound, stale,
// broken.
//
// EVERYTHING in this file is consumer-layer. To a core verifier DfosOrigin is an
// UNRECOGNIZED service type — carried verbatim, never structurally validated —
// and it MUST stay that way: teaching dfos-protocol-go (or the TS reference) to
// recognize it would make a malformed entry reject at chain verification and
// change frozen-core behavior across every language implementation. All
// DfosOrigin structure lives here, in the consumer.
//
// The pure helpers (domain validation, claim reading, record/body parsing, the
// bind plan, the verdict fold) are separated from the two network probes so the
// whole rule set is unit-testable without touching the network.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

const (
	// originServiceType is the service type registered by ORIGIN-BINDING.md.
	// Deliberately NOT in protocol.RecognizedServiceTypes — see the file header.
	originServiceType = "DfosOrigin"
	// defaultOriginServiceID is the entry id `bind-domain` uses when the
	// identity has no DfosOrigin entry yet and --id was not supplied.
	defaultOriginServiceID = "origin"

	wellKnownDIDPath   = "/.well-known/dfos-did"
	appDescriptionPath = "/.well-known/dfos-app.json"
	dnsAttestationName = "_dfos."
	dnsAttestationTag  = "did="

	// attestationTimeout bounds each attestation fetch. Both lookups are single
	// round-trips; a domain that cannot answer in 5s is silent, not broken.
	attestationTimeout = 5 * time.Second
	// wellKnownDIDCap bounds the well-known read. A conforming body is under a
	// hundred bytes, so anything larger is garbage rejected before parsing.
	wellKnownDIDCap = 1024
	// appDescriptionCap bounds the fallback read. App descriptions carry an
	// identity chain (up to 100 operations), so the cap is generous.
	appDescriptionCap = 512 * 1024
	maxRedirectHops   = 5
)

// asciiWhitespace is the trim set for attestation values. ORIGIN-BINDING.md says
// "after trimming ASCII whitespace" — not Unicode space, so this is spelled out
// rather than deferring to strings.TrimSpace.
const asciiWhitespace = " \t\r\n\v\f"

// ---------------------------------------------------------------------------
// domain validation
// ---------------------------------------------------------------------------

const (
	maxDomainLength = 253
	maxLabelLength  = 63
)

// normalizeDomain lowercases, trims surrounding whitespace, and strips ONE
// trailing dot (the DNS root label). It does not validate.
func normalizeDomain(raw string) string {
	return strings.TrimSuffix(strings.ToLower(strings.Trim(raw, asciiWhitespace)), ".")
}

// validateDomain normalizes raw and requires the bare LDH hostname form the
// DfosOrigin `domain` member specifies: no scheme, no port, no path, no
// underscores, at least one dot, RFC-1123 labels, ASCII only. Internationalized
// names must arrive already in A-label (Punycode) form — the CLI does no IDN
// conversion, so the comparison layer never depends on a Unicode choice.
func validateDomain(raw string) (string, error) {
	d := normalizeDomain(raw)
	if d == "" {
		return "", domainError(raw, "it is empty")
	}
	if strings.Contains(d, "://") {
		return "", domainError(raw, "it includes a scheme")
	}
	if strings.ContainsAny(d, "/?#") {
		return "", domainError(raw, "it includes a path, query, or fragment")
	}
	if strings.Contains(d, ":") {
		return "", domainError(raw, "it includes a port")
	}
	if strings.Contains(d, "_") {
		return "", domainError(raw, "hostname labels cannot contain underscores")
	}
	if len(d) > maxDomainLength {
		return "", domainError(raw, fmt.Sprintf("it is %d characters (max %d)", len(d), maxDomainLength))
	}
	for i := 0; i < len(d); i++ {
		if d[i] > 0x7f {
			return "", domainError(raw, "it is not ASCII — supply an internationalized name in its A-label (Punycode, xn--…) form; the CLI does not convert")
		}
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", domainError(raw, "a bare hostname needs at least one dot")
	}
	for _, label := range labels {
		if label == "" {
			return "", domainError(raw, "it has an empty label")
		}
		if len(label) > maxLabelLength {
			return "", domainError(raw, fmt.Sprintf("label %q is %d characters (max %d)", label, len(label), maxLabelLength))
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", domainError(raw, fmt.Sprintf("label %q starts or ends with a hyphen", label))
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return "", domainError(raw, fmt.Sprintf("label %q contains %q", label, string(c)))
			}
		}
	}
	return d, nil
}

func domainError(raw, reason string) error {
	return fmt.Errorf(
		"invalid domain %q: %s. Supply the bare hostname (e.g. example.com) — no scheme, no port, no path",
		raw, reason,
	)
}

// ---------------------------------------------------------------------------
// the chain's half: reading the DfosOrigin claim
// ---------------------------------------------------------------------------

// originEntryIndexes returns the positions of every DfosOrigin-typed entry in a
// services set, valid or not. `bind-domain` needs the malformed ones too — it
// replaces and collapses by TYPE, not by validity.
func originEntryIndexes(services []protocol.ServiceEntry) []int {
	var idx []int
	for i, e := range services {
		if t, _ := e["type"].(string); t == originServiceType {
			idx = append(idx, i)
		}
	}
	return idx
}

// originClaim is what a services set claims, per ORIGIN-BINDING.md "One entry,
// or none": exactly one structurally valid DfosOrigin entry claims its domain;
// zero, several, or one malformed entry claim NOTHING. Domain is "" when
// nothing is claimed, and Reason says which case it was.
type originClaim struct {
	Domain string
	Reason string
}

// readOriginClaim folds a services set into the domain it claims. The stored
// domain must ALREADY be canonical (bare, lowercase, no trailing dot): every
// comparison in the spec is an exact byte comparison of that string, so an
// entry that would only pass after normalization is not a valid claim.
func readOriginClaim(services []protocol.ServiceEntry) originClaim {
	idx := originEntryIndexes(services)
	switch {
	case len(idx) == 0:
		return originClaim{Reason: "no DfosOrigin entry in this identity's services"}
	case len(idx) > 1:
		return originClaim{Reason: fmt.Sprintf("%d DfosOrigin entries — an ambiguous claim is no claim", len(idx))}
	}
	raw, _ := services[idx[0]]["domain"].(string)
	domain, err := validateDomain(raw)
	if err != nil || domain != raw {
		return originClaim{Reason: fmt.Sprintf("DfosOrigin entry's domain %q is not a bare lowercase hostname — it claims nothing", raw)}
	}
	return originClaim{Domain: domain}
}

// ---------------------------------------------------------------------------
// the domain's half: parsing what it serves
// ---------------------------------------------------------------------------

// didFromWellKnownBody reads /.well-known/dfos-did: the trimmed body must be
// exactly one DFOS DID.
func didFromWellKnownBody(body []byte) (string, bool) {
	s := strings.Trim(string(body), asciiWhitespace)
	if !protocol.IsValidDID(s) {
		return "", false
	}
	return s, true
}

// didFromAppDescription applies the SIWD app-description structural bar to the
// fallback document: a JSON object with a non-empty redirect_uris array, a
// client_did in DID form, and an optional name (present-but-empty is
// malformed, not absent). That client_did attests exactly as the well-known
// file would.
func didFromAppDescription(body []byte) (string, bool) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil || doc == nil {
		return "", false
	}
	if rawName, present := doc["name"]; present {
		if name, ok := rawName.(string); !ok || name == "" {
			return "", false
		}
	}
	uris, ok := doc["redirect_uris"].([]any)
	if !ok || len(uris) == 0 {
		return "", false
	}
	did, _ := doc["client_did"].(string)
	if !protocol.IsValidDID(did) {
		return "", false
	}
	return did, true
}

// originTXTName is the DNS name carrying the attestation.
func originTXTName(domain string) string { return dnsAttestationName + domain }

// ---------------------------------------------------------------------------
// method results and the verdict fold
// ---------------------------------------------------------------------------

// methodResult is one attestation method's outcome. DID != "" is an ANSWER;
// DID == "" is SILENCE (and silence is never contradiction). Contradiction
// marks a method that contradicted itself — only DNS can, by carrying more than
// one did= record. Detail is always set: it is the line the ladder prints.
type methodResult struct {
	Name          string
	DID           string
	Source        string
	Detail        string
	Contradiction bool
	Fallback      bool
}

func (m methodResult) answered() bool { return m.DID != "" }

// bindingVerdict is the three-state result, plus the no-claim case that is
// deliberately NOT one of the three (there is nothing to verify).
type bindingVerdict string

const (
	verdictBound   bindingVerdict = "bound"
	verdictStale   bindingVerdict = "stale"
	verdictBroken  bindingVerdict = "broken"
	verdictNoClaim bindingVerdict = "no-claim"
)

// exitCode maps a verdict to the process exit status so scripts can branch on
// it without parsing output: bound 0, broken 1, stale 2, no-claim 0.
func (v bindingVerdict) exitCode() int {
	switch v {
	case verdictBroken:
		return 1
	case verdictStale:
		return 2
	default:
		return 0
	}
}

// meaning is the one-sentence gloss printed under the verdict. The verdicts
// carry different consequences and MUST NOT be conflated, so each says plainly
// what it means.
func (v bindingVerdict) meaning() string {
	switch v {
	case verdictBound:
		return "the domain attests this DID — control of the domain at verification time, nothing more"
	case verdictStale:
		return "domain silent — the last verified claim stands; staleness is legal"
	case verdictBroken:
		return "the domain contradicts the chain's claim"
	default:
		return "nothing is claimed, so there is nothing to verify"
	}
}

// foldVerdict is the whole verification rule, as a pure function:
//
//   - broken — any method answers a DID other than the chain's, the two methods
//     answer differently, or a method contradicted itself (DNS multi-record).
//   - bound  — at least one method answers, and every answer is the chain's DID.
//   - stale  — a claim exists and every method is silent.
//
// chainDID may be "" (the domain-first walk before a chain is resolved), in
// which case only self-contradiction and method-vs-method disagreement can be
// judged.
func foldVerdict(chainDID string, results []methodResult) bindingVerdict {
	answered := false
	firstAnswer := ""
	for _, r := range results {
		if r.Contradiction {
			return verdictBroken
		}
		if !r.answered() {
			continue
		}
		if chainDID != "" && r.DID != chainDID {
			return verdictBroken
		}
		if answered && r.DID != firstAnswer {
			return verdictBroken
		}
		if !answered {
			firstAnswer = r.DID
			answered = true
		}
	}
	if answered {
		return verdictBound
	}
	return verdictStale
}

// ---------------------------------------------------------------------------
// the bind plan (pure)
// ---------------------------------------------------------------------------

type originBindAction string

const (
	bindActionNew       originBindAction = "bound"
	bindActionRebind    originBindAction = "rebound"
	bindActionUnchanged originBindAction = "unchanged"
)

// originBindPlan is the services set `bind-domain` will sign, plus what it did
// to get there. Services is a fresh slice — the chain-state slice is never
// mutated in place.
type originBindPlan struct {
	Services  []protocol.ServiceEntry
	ID        string
	Action    originBindAction
	Previous  string
	Collapsed int
}

// planOriginBinding builds the full-state services replacement that claims
// domain. Services are full-state on every update, so the whole set is carried
// forward with only the DfosOrigin entry touched:
//
//   - no DfosOrigin entry → append one (id from idOverride, else "origin").
//   - one entry → replace it in place, keeping its id unless --id renames it.
//     An entry already identical to the target is left alone (Action unchanged)
//     so re-running the command signs nothing.
//   - several entries → collapse to one at the first entry's position. A set
//     with several claims nothing at all, so collapsing is a repair.
//
// The written entry is exactly {id, type, domain}: the member set is closed by
// the spec, so ad-hoc members on a replaced entry are dropped rather than
// carried into a claim they no longer describe.
func planOriginBinding(services []protocol.ServiceEntry, domain, idOverride string) (originBindPlan, error) {
	idx := originEntryIndexes(services)

	id := idOverride
	previous := ""
	if len(idx) > 0 {
		if existingID, _ := services[idx[0]]["id"].(string); existingID != "" && id == "" {
			id = existingID
		}
		previous, _ = services[idx[0]]["domain"].(string)
	}
	if id == "" {
		id = defaultOriginServiceID
	}

	// Duplicate service ids are rejected by core chain verification, so catch a
	// collision here with an actionable message instead of at ingest.
	isOrigin := make(map[int]bool, len(idx))
	for _, i := range idx {
		isOrigin[i] = true
	}
	for i, e := range services {
		if isOrigin[i] {
			continue
		}
		if eid, _ := e["id"].(string); eid == id {
			t, _ := e["type"].(string)
			return originBindPlan{}, fmt.Errorf(
				"service id %q is already used by a %s entry; pick another id with --id",
				id, t,
			)
		}
	}

	entry := protocol.ServiceEntry{"id": id, "type": originServiceType, "domain": domain}

	out := make([]protocol.ServiceEntry, 0, len(services)+1)
	placed := false
	for i, e := range services {
		if isOrigin[i] {
			if !placed {
				out = append(out, entry)
				placed = true
			}
			continue
		}
		out = append(out, e)
	}
	if !placed {
		out = append(out, entry)
	}

	plan := originBindPlan{Services: out, ID: id, Previous: previous, Collapsed: len(idx) - 1}
	if plan.Collapsed < 0 {
		plan.Collapsed = 0
	}
	switch {
	case len(idx) == 1 && reflect.DeepEqual(services[idx[0]], entry):
		plan.Action = bindActionUnchanged
	case len(idx) > 0:
		plan.Action = bindActionRebind
	default:
		plan.Action = bindActionNew
	}
	return plan, nil
}

// ---------------------------------------------------------------------------
// probes (network)
// ---------------------------------------------------------------------------

// refusedRedirectError marks a redirect the attestation rules REFUSED, as
// distinct from a domain that could not be reached. The two are different facts
// about a deployment — one is "nothing answered", the other is "something
// answered and it was not the named domain" — and reporting the second as the
// first sends an operator to look at DNS and uptime for a redirect they
// configured.
type refusedRedirectError struct{ reason string }

func (e *refusedRedirectError) Error() string { return e.reason }

// refuseForeignRedirect is the HTTPS method's redirect rule: the attestation
// must come from the named domain, so a redirect to a different host — or off
// HTTPS — attests nothing and is refused. Same-host HTTPS redirects are
// followed, up to a bounded hop count.
func refuseForeignRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirectHops {
		return &refusedRedirectError{fmt.Sprintf("stopped after %d redirects", maxRedirectHops)}
	}
	if req.URL.Scheme != "https" {
		return &refusedRedirectError{fmt.Sprintf("refusing redirect off HTTPS to %s://%s", req.URL.Scheme, req.URL.Host)}
	}
	if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		return &refusedRedirectError{fmt.Sprintf("refusing cross-origin redirect to %s", req.URL.Host)}
	}
	return nil
}

func attestationClient() *http.Client {
	return &http.Client{Timeout: attestationTimeout, CheckRedirect: refuseForeignRedirect}
}

// fetchResult is one attestation fetch. `final` is the URL the reply actually
// came from, which is the URL asked for unless a redirect was followed — the
// one fact that separates "this path serves the wrong thing" from "this path
// serves nothing and something else answered for it".
type fetchResult struct {
	status int
	body   []byte
	over   bool // the body exceeded the cap; the read was abandoned, not truncated
	final  string
}

// redirected reports whether the reply came from a URL other than the one asked
// for. A same-host HTTPS redirect is legal and followed, so this is not itself a
// failure — it is the explanation to reach for when what came back is not an
// attestation.
func (f fetchResult) redirected(requested string) bool {
	return f.final != "" && f.final != requested
}

// fetchCapped GETs url and reads at most limit bytes.
func fetchCapped(c *http.Client, url string, limit int64) (fetchResult, error) {
	resp, err := c.Get(url)
	if err != nil {
		return fetchResult{}, err
	}
	defer resp.Body.Close()
	out := fetchResult{status: resp.StatusCode, final: url}
	if resp.Request != nil && resp.Request.URL != nil {
		out.final = resp.Request.URL.String()
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fetchResult{status: resp.StatusCode, final: out.final}, err
	}
	if int64(len(data)) > limit {
		out.over = true
		return out, nil
	}
	out.body = data
	return out, nil
}

// probeHTTPS runs the HTTPS half: the well-known document, with the SIWD
// app-description fallback on ABSENCE ONLY. A dfos-did file that is present but
// malformed is not absence — it blocks the fallback, exactly as a file naming a
// different DID would.
func probeHTTPS(domain string) methodResult {
	res := methodResult{Name: "https", Source: wellKnownDIDPath}
	client := attestationClient()

	requested := "https://" + domain + wellKnownDIDPath
	got, err := fetchCapped(client, requested, wellKnownDIDCap)
	// A redirect is the explanation whenever the reply did not come from the
	// path the attestation must be served at: a site that answers its SPA for
	// every unknown path returns 200 and HTML, and calling that a size-cap
	// overrun reports the symptom and hides the cause.
	redirectNote := ""
	if got.redirected(requested) {
		redirectNote = fmt.Sprintf(" — redirected to %s; the attestation must be served at %s on %s itself", got.final, wellKnownDIDPath, domain)
	}
	switch {
	case err != nil:
		var refused *refusedRedirectError
		if errors.As(err, &refused) {
			res.Detail = fmt.Sprintf("silent (%s redirected off %s: %s — the attestation must come from the named domain)",
				wellKnownDIDPath, domain, refused.reason)
			return res
		}
		res.Detail = fmt.Sprintf("silent (%s unreachable: %s)", wellKnownDIDPath, condenseFetchError(err))
		return res
	case got.status == http.StatusOK && got.over:
		if redirectNote != "" {
			res.Detail = fmt.Sprintf("silent (%s%s)", wellKnownDIDPath, redirectNote)
			return res
		}
		res.Detail = fmt.Sprintf("silent (%s exceeds %d bytes)", wellKnownDIDPath, wellKnownDIDCap)
		return res
	case got.status == http.StatusOK:
		did, ok := didFromWellKnownBody(got.body)
		if !ok {
			if redirectNote != "" {
				res.Detail = fmt.Sprintf("silent (%s%s)", wellKnownDIDPath, redirectNote)
				return res
			}
			res.Detail = fmt.Sprintf("silent (%s present but not a DFOS DID — app fallback blocked)", wellKnownDIDPath)
			return res
		}
		res.DID = did
		res.Detail = fmt.Sprintf("attests %s (%s)", did, wellKnownDIDPath)
		return res
	case got.status == http.StatusNotFound || got.status == http.StatusGone:
		return probeAppDescription(domain, client, got.status)
	default:
		res.Detail = fmt.Sprintf("silent (HTTP %d from %s)", got.status, wellKnownDIDPath)
		return res
	}
}

// probeAppDescription is the HTTPS method's fallback leg. Its answer IS the
// HTTPS method's answer — every existing SIWD application already publishes its
// DID, and this reads it.
func probeAppDescription(domain string, client *http.Client, wellKnownStatus int) methodResult {
	res := methodResult{Name: "https", Source: appDescriptionPath, Fallback: true}

	got, err := fetchCapped(client, "https://"+domain+appDescriptionPath, appDescriptionCap)
	status, body, over := got.status, got.body, got.over
	switch {
	case err != nil:
		var refused *refusedRedirectError
		if errors.As(err, &refused) {
			res.Detail = fmt.Sprintf("silent (%d on %s, %s redirected off %s: %s — the attestation must come from the named domain)",
				wellKnownStatus, wellKnownDIDPath, appDescriptionPath, domain, refused.reason)
			return res
		}
		res.Detail = fmt.Sprintf("silent (%d on %s, %s unreachable: %s)", wellKnownStatus, wellKnownDIDPath, appDescriptionPath, condenseFetchError(err))
		return res
	case status == http.StatusOK && !over:
		if did, ok := didFromAppDescription(body); ok {
			res.DID = did
			res.Detail = fmt.Sprintf("attests %s (%s, app-description fallback)", did, appDescriptionPath)
			return res
		}
		res.Detail = fmt.Sprintf("silent (%d on %s, %s is not a usable app description)", wellKnownStatus, wellKnownDIDPath, appDescriptionPath)
		return res
	default:
		res.Detail = fmt.Sprintf("silent (%d on %s, no app description)", wellKnownStatus, wellKnownDIDPath)
		return res
	}
}

// probeDNS runs the DNS half: TXT records at _dfos.<domain>. A resolver failure
// is silence; two did= records are a contradiction.
func probeDNS(domain string) methodResult {
	name := originTXTName(domain)
	records, err := net.LookupTXT(name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return methodResult{Name: "dns", Source: name, Detail: "silent (no _dfos TXT record)"}
		}
		return methodResult{Name: "dns", Source: name, Detail: fmt.Sprintf("silent (resolver error: %s)", condenseFetchError(err))}
	}
	return foldTXTRecords(domain, records)
}

// foldTXTRecords applies the DNS rules to a record set: records not beginning
// did= are ignored; exactly one well-formed did= record answers; more than one
// is a contradiction the verifier MUST NOT tiebreak; a single malformed value
// is silence.
func foldTXTRecords(domain string, records []string) methodResult {
	name := originTXTName(domain)
	res := methodResult{Name: "dns", Source: name}

	var tagged []string
	for _, r := range records {
		r = strings.Trim(r, asciiWhitespace)
		if strings.HasPrefix(r, dnsAttestationTag) {
			tagged = append(tagged, r)
		}
	}
	switch {
	case len(tagged) == 0:
		res.Detail = "silent (no _dfos TXT record)"
		return res
	case len(tagged) > 1:
		res.Contradiction = true
		res.Detail = fmt.Sprintf("%d did= records at %s — the domain attests more than one DID", len(tagged), name)
		return res
	}
	did := strings.TrimPrefix(tagged[0], dnsAttestationTag)
	if !protocol.IsValidDID(did) {
		res.Detail = fmt.Sprintf("silent (malformed did= value at %s)", name)
		return res
	}
	res.DID = did
	res.Detail = fmt.Sprintf("attests %s (%s TXT)", did, name)
	return res
}

// condenseFetchError strips the URL/host noise Go's net stack wraps around a
// transport failure so the ladder stays one readable line per check.
func condenseFetchError(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 && i+2 < len(msg) {
		msg = msg[i+2:]
	}
	return msg
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

// ladderLine renders one method's outcome. Answers that match the chain get ✓,
// answers that do not (and self-contradictions) get ✗, silence gets –.
func (m methodResult) ladderLine(chainDID string) string {
	switch {
	case m.Contradiction:
		return "✗ " + m.Detail
	case m.answered() && chainDID != "" && m.DID != chainDID:
		return "✗ " + m.Detail
	case m.answered():
		return "✓ " + m.Detail
	default:
		return "– " + m.Detail
	}
}

// methodJSON is one method's machine-readable outcome.
func (m methodResult) methodJSON() map[string]any {
	out := map[string]any{
		"answered": m.answered(),
		"source":   m.Source,
		"detail":   m.Detail,
	}
	if m.answered() {
		out["did"] = m.DID
	}
	if m.Contradiction {
		out["contradiction"] = true
	}
	return out
}

// printBindInstructions prints exactly what the domain must serve for the
// binding to verify. Either method suffices — a static host that cannot touch
// DNS and a DNS operator that cannot serve files are both first-class.
func printBindInstructions(did, domain string) {
	fmt.Printf("\nServe ONE of these from the domain:\n\n")
	fmt.Printf("  A. Well-known document\n")
	fmt.Printf("       url:     https://%s%s\n", domain, wellKnownDIDPath)
	fmt.Printf("       content: %s\n", did)
	fmt.Printf("       (plain text, exactly that one line; serve as text/plain with Access-Control-Allow-Origin: *)\n\n")
	fmt.Printf("  B. DNS TXT record\n")
	fmt.Printf("       %s.  TXT  \"%s%s\"\n\n", originTXTName(domain), dnsAttestationTag, did)
	fmt.Printf("A SIWD app already serving %s with this client_did attests too —\n", appDescriptionPath)
	fmt.Printf("the fallback reads it, so no extra file is needed.\n\n")
	fmt.Printf("Then verify: dfos identity verify-binding %s\n", domain)
}

// probeBinding runs both attestation methods against a domain. Order is fixed
// (HTTPS then DNS) for stable output; neither method wins a disagreement.
func probeBinding(domain string) []methodResult {
	return []methodResult{probeHTTPS(domain), probeDNS(domain)}
}

// bindingReport is everything one verification produced: the two halves, the
// verdict, and — when a half is missing — why. It owns both output branches and
// the exit status, so every path through verify-binding reports identically.
type bindingReport struct {
	DID     string
	Domain  string
	Verdict bindingVerdict
	Claim   string
	Reason  string
	Results []methodResult
}

// emit renders the report and returns the verdict's exit status as an
// ExitCodeError (nil for the zero-status verdicts). The outcome is already on
// stdout, so the error carries a code and no message.
func (r bindingReport) emit() error {
	if jsonFlag {
		r.emitJSON()
	} else {
		r.emitHuman()
	}
	if code := r.Verdict.exitCode(); code != 0 {
		return &ExitCodeError{Code: code}
	}
	return nil
}

func (r bindingReport) emitJSON() {
	out := map[string]any{"verdict": string(r.Verdict)}
	if r.DID != "" {
		out["did"] = r.DID
	}
	if r.Domain != "" {
		out["domain"] = r.Domain
	}
	// chainClaim only earns a field when it DIFFERS from the domain under
	// verification — the domain-first walk landing on a chain that claims
	// something else. In the ordinary case they are the same string.
	if r.Claim != "" && r.Claim != r.Domain {
		out["chainClaim"] = r.Claim
	}
	if r.Reason != "" {
		out["reason"] = r.Reason
	}
	if len(r.Results) > 0 {
		methods := make(map[string]any, len(r.Results))
		fallbackUsed := false
		for _, m := range r.Results {
			methods[m.Name] = m.methodJSON()
			// "used" means the fallback SUPPLIED the HTTPS answer. That the
			// fallback was merely consulted is already visible in its source.
			if m.Fallback && m.answered() {
				fallbackUsed = true
			}
		}
		out["methods"] = methods
		out["fallbackUsed"] = fallbackUsed
	}
	outputJSON(out)
}

func (r bindingReport) emitHuman() {
	const label = "%-13s%s\n"
	if r.DID != "" {
		fmt.Printf(label, "identity:", r.DID)
	}
	reasonShown := false
	switch {
	case r.Claim != "" && r.Claim != r.Domain:
		fmt.Printf(label, "chain claim:", fmt.Sprintf("%s  (not %s)", r.Claim, r.Domain))
		fmt.Printf(label, "domain:", r.Domain)
	case r.Claim != "":
		fmt.Printf(label, "chain claim:", r.Claim)
	case r.DID != "":
		fmt.Printf(label, "chain claim:", "none — "+r.Reason)
		reasonShown = true
		if r.Domain != "" {
			fmt.Printf(label, "domain:", r.Domain)
		}
	default:
		fmt.Printf(label, "domain:", r.Domain)
	}
	for _, m := range r.Results {
		fmt.Printf(label, m.Name+":", m.ladderLine(r.DID))
	}
	fmt.Printf("\nverdict: %s — %s\n", r.Verdict, r.Verdict.meaning())
	if r.Reason != "" && !reasonShown {
		fmt.Printf("%s\n", r.Reason)
	}
}

package cmd

// `dfos keys prove` — the holder's half of a key-add ceremony (specs/KEY-PROOF.md).
//
// A ceremony operator displays a code on one screen; this command is what the
// human runs on the machine that actually holds a key. It resolves the code,
// picks the candidate key, shows the human the identity and the roles they are
// about to consent to, signs the seven-member KEY-PROOF envelope with the
// candidate key ITSELF, and presents it. Adoption — the operator appending the
// key to its chain — happens afterwards on the operator's own authenticated
// surface, outside this command and outside the envelope.
//
// THE CARRIAGE IS TWO VALUES, AND RESOLUTION IS MANDATORY. A carriage conveys an
// authority and a code, and nothing else; the code IS the ceremony identifier.
// Everything the envelope binds — the nonce, the audience, the identity, the
// roles, the chain head — arrives from resolving that code at that authority,
// over one GET. There is no self-contained carriage that skips the resolution,
// and a URL carrying the signing context in its query is refused rather than
// read: a context nobody resolved is a context somebody else chose.
//
// WHAT THE CARRIAGE DISCLOSES, AND WHAT RESOLVING IT DOES. The carriage names no
// identity. A shoulder-surfed code or an intercepted QR is an authority and a
// short-lived token, and neither says whom the ceremony is for. RESOLVING it
// names everything: the DID, the operator's handle and display name for it, the
// roles, the head. That disclosure is deliberate and it is the only shape that
// works — a human who cannot see whom they are joining cannot consent to joining
// them — and what it discloses are public identity facts, reached through a
// single-shot code over TLS. What an interceptor gains is the knowledge that one
// public identity is mid-ceremony, plus the ability to attempt a presentation
// with a key they do not hold.
//
// FOUR RULES CARRY THIS COMMAND, and every branch below serves one of them:
//
//  1. THE AUDIENCE AND THE POSITION ARE SHOWN BEFORE ANYTHING IS SIGNED. Audience
//     binding is what defeats challenge relay — a phished code re-displayed on an
//     attacker's surface still yields a proof naming the authority the victim
//     confirmed. Position binding is what keeps consent to sign as an author from
//     being consent to become a controller. Neither defends anyone who did not SEE
//     it, so the display carries the audience, the adopting identity, and the
//     roles; it is not suppressible by --quiet, and a TTY is asked. --yes is how a
//     script says the human already saw it.
//  2. ONE KEY, ONE DID — REFUSED BY DEFAULT. The relay index's `key=` filter is
//     has-ever-PROVED and its rows survive rotation and deletion, so proving one
//     key into two chains publishes an irreversible public link between them. The
//     check runs against a NAMED oracle before there is a signature to make, and a
//     check that could not run is never silently skipped.
//  3. A PRESENTATION IS NEVER RETRIED. A presentation refused at the signature arm
//     burns its ceremony, and nothing in an HTTP status tells this command which
//     arm refused it. So there is one attempt, ever: a retry would risk spending a
//     live ceremony's rate limit on a nonce that is already dead. The fix is
//     always a fresh code.
//  4. THE PRIVATE KEY NEVER LEAVES. What goes on the wire is a JWS over seven
//     members, one of which is the PUBLIC key. Nothing prints a seed.
//
// The resolution is asked EXACTLY ONCE per invocation. It is IP rate limited at
// the operator, a ceremony lives ten minutes, and a code that did not resolve on
// the first ask is not going to resolve on the second.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/apispec"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/vault"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// deviceCodeAlphabet is the short code's display alphabet: upper-case letters
// and digits with the four confusable glyphs (I, O, 0, 1) removed, because the
// code's whole job is to survive being read off one screen and typed on another.
const deviceCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// deviceCodeLength is how many of those characters a code is.
const deviceCodeLength = 8

// keyProofWellKnownPath is the code-resolution route KEY-PROOF.md names.
const keyProofWellKnownPath = "/.well-known/dfos-key-proof"

// ceremonyHTTPTimeout bounds both ceremony requests. A ceremony lives ten
// minutes; a request that has not answered in twenty seconds is a failure, not
// a slow success worth waiting out.
const ceremonyHTTPTimeout = 20 * time.Second

// keyIDShape is what a presentation answer's `keyId` may look like before it is
// allowed to name a keystore account. An account is `<did>#<keyId>`, so a key id
// carrying '#' or a path separator would be a key filed under a name that means
// something else.
var keyIDShape = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

// --- the carriage ---

// parsedCarriage is the two values a carriage conveys — an authority and a code
// — split out of whichever form the human pasted.
//
// IT IS NOT A SIGNING CONTEXT AND NEVER BECOMES ONE. What it names is where to
// ASK; every value the envelope binds comes back from resolveCode. That is the
// whole reason the authority is the single thing a human has to get right.
type parsedCarriage struct {
	Scheme string
	Host   string
	// Code is the operator's ceremony identifier. It selects the ceremony at
	// resolution and travels beside the envelope at presentation.
	Code string
	// Via says which carriage form produced this, for the disclosure block.
	Via string
}

// Authority is the lowercase authority the code was typed at — bare host on the
// scheme's default port, host:port otherwise. Both the resolution's own audience
// and its presentation endpoint must byte-equal this.
func (c parsedCarriage) Authority() string {
	return apispec.NormalizeAuthority(c.Scheme, c.Host)
}

// ceremony is the RESOLVED signing context: everything the envelope binds, and
// everything render-before-sign shows the human.
//
// EVERY MEMBER CAME FROM ONE RESOLUTION, over TLS, at the authority the human
// named. None of it rode in on the carriage, because a carriage carries none of
// it.
type ceremony struct {
	// Present is the presentation endpoint, absolute, its authority checked equal
	// to the resolving authority.
	Present string
	// Code is the ceremony identifier, echoed back in the presentation body.
	Code string
	// Nonce is the verifier-minted challenge the payload carries.
	Nonce string
	// Audience is the authority the envelope names — byte-equal to the authority
	// the human typed, checked at resolution.
	Audience string
	// DID, Handle and DisplayName are the identity the introduction targets. All
	// three are REQUIRED: they are what render-before-sign displays, and a
	// resolution omitting any of them is one no proof can honestly be signed
	// against.
	DID         string
	Handle      string
	DisplayName string
	// RoleSet is the canonical role set the ceremony introduces the key to.
	RoleSet string
	// PrevCID is the chain head the introduction builds on.
	PrevCID string
	// ExpiresAt is when the operator says the ceremony lapses. It is DISPLAYED
	// and never gated on: the operator's clock is the one that decides, and a
	// holder refusing on its own reading of the member would be refusing a
	// ceremony the operator would still have honored.
	ExpiresAt string
	// Via says which carriage form produced this, for the disclosure block.
	Via string
	// Relay is the oracle the resolution named, when it named one and it was
	// usable. It is a courtesy for a machine that has no relay of its own: it
	// reaches exactly one linkage check and configures nothing.
	Relay string
}

// ceremonyHTTPClient is the client both ceremony requests use.
//
// REDIRECTS ARE REFUSED. Following one would move a ceremony off the authority
// the human typed and confirmed, which is precisely what the short code's
// authority rule exists to prevent; a 3xx here is a failure with a name.
func ceremonyHTTPClient() *http.Client {
	return &http.Client{
		Timeout: ceremonyHTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("refused a redirect to %s — a ceremony never moves off the authority you named", req.URL.Host)
		},
	}
}

// codeSeparators are the marks a code picks up on its way from one screen to
// another. An operator groups eight characters as "ABCD-EFGH" or "ABCD EFGH" to
// make them readable, and a person retypes what they read — neither mark is in
// the alphabet, so neither can be a character of the code, and dropping them is
// unambiguous rather than lenient.
var codeSeparators = strings.NewReplacer("-", "", " ", "", "\u00a0", "")

// normalizeDeviceCode drops those separators, upper-cases what is left, and
// checks it against the code grammar. Case is normalized rather than rejected:
// the alphabet has one case, so a lower-case letter is a typing artifact and not
// an ambiguity.
func normalizeDeviceCode(raw string) (string, bool) {
	code := strings.ToUpper(codeSeparators.Replace(raw))
	if len(code) != deviceCodeLength {
		return "", false
	}
	for _, r := range code {
		if !strings.ContainsRune(deviceCodeAlphabet, r) {
			return "", false
		}
	}
	return code, true
}

func errBadCeremonyInput(raw string) error {
	return fmt.Errorf("'%s' is neither carriage form. Pass what the ceremony operator displayed:\n"+
		"  <authority>/<CODE>       the short code, %d characters of %s\n"+
		"  https://…?code=…         the carriage URI (a QR code's contents verbatim)\n"+
		"Either way it is an authority and a code: everything else comes from resolving the code at that authority.",
		raw, deviceCodeLength, deviceCodeAlphabet)
}

// checkCeremonyScheme enforces HTTPS.
//
// The one exemption is a loopback host, which is how a ceremony operator is
// developed against locally and how this command is tested. Nothing else: a
// ceremony over cleartext to a remote host hands the envelope, the nonce, and
// the ceremony id to the network.
func checkCeremonyScheme(u *url.URL) error {
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("refusing a cleartext ceremony at %s — a carriage is https, except on loopback", u.Host)
	default:
		return fmt.Errorf("refusing scheme '%s' — a carriage is an https URL", u.Scheme)
	}
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return false
}

// uriCarriageCode bounds the code a URI carriage carries.
//
// The DISPLAY alphabet deliberately does not apply here. That one exists so
// eight characters survive being read off one screen and typed on another, and a
// code arriving inside a URL was never retyped — the operator chose it and a
// machine carried it. What is required is only that it is one bounded token that
// rides a query member unambiguously.
var uriCarriageCode = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,64}$`)

// parseCarriage splits the one argument into the authority and the code.
//
// Which form it is, is read off the QUERY, not off the spelling: a URL carrying
// `code` is a URI carriage, and a bare `<authority>/<CODE>` is a short code. A
// scheme is optional on the short form because an operator's UI displays it
// without one and a person pasting it may bring the `https://` back.
func parseCarriage(raw string) (*parsedCarriage, error) {
	// Every space goes, not just the ones at the ends. A URL cannot carry a raw
	// space, and a short code is displayed grouped for reading — so whitespace
	// anywhere in this argument is something a human's eye or a copy put there,
	// in both forms, and removing it decides nothing.
	raw = strings.Join(strings.Fields(raw), "")
	if raw == "" {
		return nil, errBadCeremonyInput(raw)
	}
	target := raw
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return nil, errBadCeremonyInput(raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("refusing a carriage carrying userinfo — a carriage is an authority and a code, and nothing else")
	}
	q := u.Query()

	// The URI form.
	if values := q["code"]; len(values) > 0 {
		if len(values) > 1 {
			return nil, fmt.Errorf("the carriage URI carries 'code' %d times — which one is the ceremony is not a guess this makes",
				len(values))
		}
		code := strings.TrimSpace(values[0])
		if code == "" {
			return nil, fmt.Errorf("the carriage URI's 'code' member is empty")
		}
		if !uriCarriageCode.MatchString(code) {
			return nil, fmt.Errorf("the carriage URI's 'code' member is not a ceremony code")
		}
		if err := checkCeremonyScheme(u); err != nil {
			return nil, err
		}
		return &parsedCarriage{Scheme: u.Scheme, Host: u.Host, Code: code, Via: "carriage URI"}, nil
	}

	// A URL carrying a signing context instead of a code. Naming it is worth its
	// own branch: it is the one wrong input a person is likely to arrive with,
	// and "neither carriage form" would send them hunting for a typo that is not
	// there. What is wrong with it is not its spelling — it is that a context
	// nobody resolved is a context somebody else chose.
	if len(q["ceremony"]) > 0 || len(q["nonce"]) > 0 {
		return nil, fmt.Errorf("that URL carries a ceremony and a nonce rather than a code, so it is not a carriage.\n" +
			"A carriage is an authority and a code; the nonce, the identity, the roles and the chain head all come from\n" +
			"resolving that code at that authority. Ask for the code, or scan the QR the operator displays now")
	}

	// The short form.
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segments) != 1 || segments[0] == "" || u.RawQuery != "" {
		return nil, errBadCeremonyInput(raw)
	}
	code, ok := normalizeDeviceCode(segments[0])
	if !ok {
		return nil, fmt.Errorf("'%s' is not a ceremony code — a code is %d characters of %s "+
			"(no I, O, 0 or 1; spaces and dashes between them are ignored)",
			segments[0], deviceCodeLength, deviceCodeAlphabet)
	}
	if err := checkCeremonyScheme(u); err != nil {
		return nil, err
	}
	return &parsedCarriage{
		Scheme: u.Scheme, Host: u.Host, Code: code,
		Via: "short code at " + apispec.NormalizeAuthority(u.Scheme, u.Host),
	}, nil
}

// resolveCeremony turns the one argument into a resolved ceremony: parse the
// carriage, then ask its authority what the code stands for.
func resolveCeremony(raw string) (*ceremony, error) {
	car, err := parseCarriage(raw)
	if err != nil {
		return nil, err
	}
	return resolveCode(car)
}

// resolveCode asks the authority the human typed what its code stands for — ONE
// request, no retry, no polling.
//
// EVERY BINDING IN THE ENVELOPE COMES OUT OF THIS ANSWER, which is why the rules
// that make the carriage safe all live here:
//
//   - THE AUTHORITY MAY NOT MOVE. The resolved audience MUST byte-equal the
//     resolving authority, and so must the presentation endpoint's. Without both,
//     an operator — or anyone who can answer for it — could resolve a code typed
//     at one host into a ceremony completing at another, and the audience the
//     human confirmed would name a host they never saw.
//   - THE POSITION MUST BE WHOLE. The identity (DID, handle, display name), the
//     roles, and the head are all REQUIRED. They are what render-before-sign
//     displays and what the payload binds, so a resolution missing any of them is
//     refused rather than signed against: a partial position is consent to
//     something nobody was shown.
//   - THE ROLE SET MUST BE CANONICAL. A non-canonical spelling names a set no
//     envelope can carry. Catching it here means the refusal lands before a key is
//     minted, rather than coming back out of the signer.
func resolveCode(car *parsedCarriage) (*ceremony, error) {
	asked := car.Authority()
	endpoint := car.Scheme + "://" + car.Host + keyProofWellKnownPath + "?code=" + url.QueryEscape(car.Code)
	resp, err := ceremonyHTTPClient().Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s to resolve the code %s: %w\n"+
			"Nothing was signed and nothing was sent. Check the host and try again", car.Host, car.Code, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("%s does not know the code %s: %s\n"+
			"A ceremony code is single-shot and lives ten minutes. Mint a fresh one where it was displayed and run this again",
			car.Host, car.Code, ceremonyMessage(body))
	default:
		return nil, fmt.Errorf("HTTP %d from %s%s: %s", resp.StatusCode, car.Host, keyProofWellKnownPath, ceremonyMessage(body))
	}

	var answer struct {
		Present  string `json:"present"`
		Nonce    string `json:"nonce"`
		Audience string `json:"audience"`
		Purpose  string `json:"purpose"`
		Adopts   struct {
			DID         string `json:"did"`
			Handle      string `json:"handle"`
			DisplayName string `json:"displayName"`
		} `json:"adopts"`
		RoleSet   string `json:"roleSet"`
		PrevCID   string `json:"prevCID"`
		ExpiresAt string `json:"expiresAt"`
		// Relay is optional and advisory — see usableCeremonyRelay.
		Relay string `json:"relay"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, fmt.Errorf("%s answered 200 with something that is not a resolution: %s", car.Host, oneLineBody(body, 200))
	}

	// The required members, named all at once. A resolution missing three of them
	// is one broken answer, and reporting them one refusal at a time would make a
	// person re-run a ceremony to discover the next.
	var missing []string
	for _, member := range [][2]string{
		{"present", answer.Present},
		{"nonce", answer.Nonce},
		{"audience", answer.Audience},
		{"adopts.did", answer.Adopts.DID},
		{"adopts.handle", answer.Adopts.Handle},
		{"adopts.displayName", answer.Adopts.DisplayName},
		{"roleSet", answer.RoleSet},
		{"prevCID", answer.PrevCID},
	} {
		if strings.TrimSpace(member[1]) == "" {
			missing = append(missing, member[0])
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%s answered a resolution missing %s — nothing was signed.\n"+
			"A holder signs the identity, the roles and the chain head it was shown, so a resolution that names\n"+
			"less than all of them is one no proof can honestly be signed against. Report this to whoever displayed the code",
			asked, strings.Join(missing, ", "))
	}

	// A purpose this command is not the one to run. Absence is tolerated — it is
	// not a claim about another ceremony — but a purpose naming a DIFFERENT one
	// is, and signing through it would be answering a question nobody asked.
	if purpose := strings.TrimSpace(answer.Purpose); purpose != "" && purpose != protocol.KeyAddJWSTyp {
		return nil, fmt.Errorf("%s is running a '%s' ceremony, and this command completes '%s' ceremonies.\n"+
			"Nothing was signed", asked, purpose, protocol.KeyAddJWSTyp)
	}

	// NOTHING BELOW IS TRIMMED, and that is deliberate. Every member from here on
	// either gets SIGNED or gets byte-compared, and both are byte contracts: a
	// verifier compares the envelope's audience against its own configured
	// authority octet for octet, the role-set grammar forbids whitespace outright,
	// and did and prevCID are matched against values the operator already holds.
	// Trimming would let this command sign bytes the operator did not send and
	// silently repair spellings the grammar exists to refuse. The emptiness test
	// above trims only to decide whether a member is ABSENT, which is a different
	// question from what its value is.
	if answer.Audience != asked {
		return nil, fmt.Errorf("REFUSING: the code you typed at %s resolved to a ceremony audienced to %s.\n"+
			"A code's resolution may never move a ceremony off the host the human typed, so this one is not presented.\n"+
			"Nothing was signed. Report this to whoever displayed the code", asked, answer.Audience)
	}

	present, err := url.Parse(strings.TrimSpace(answer.Present))
	if err != nil || present.Host == "" {
		return nil, fmt.Errorf("%s answered with something that is not a presentation endpoint: %s",
			asked, oneLineBody([]byte(answer.Present), 120))
	}
	if err := checkCeremonyScheme(present); err != nil {
		return nil, err
	}
	if got := apispec.NormalizeAuthority(present.Scheme, present.Host); got != asked {
		return nil, fmt.Errorf("REFUSING: the code you typed at %s resolved to a ceremony presenting at %s.\n"+
			"A code's resolution may never move a ceremony off the host the human typed, so this one is not presented.\n"+
			"Nothing was signed. Report this to whoever displayed the code", asked, got)
	}

	if !protocol.IsCanonicalRoleSet(answer.RoleSet) {
		return nil, fmt.Errorf("%s answered a role set this envelope cannot carry: '%s'.\n"+
			"A role set is a non-empty selection from auth, assert and controller, in that order, comma-joined,\n"+
			"with no spaces and no repeats. Nothing was signed", asked, answer.RoleSet)
	}

	return &ceremony{
		Present:     present.String(),
		Code:        car.Code,
		Nonce:       answer.Nonce,
		Audience:    answer.Audience,
		DID:         answer.Adopts.DID,
		Handle:      answer.Adopts.Handle,
		DisplayName: answer.Adopts.DisplayName,
		RoleSet:     answer.RoleSet,
		PrevCID:     answer.PrevCID,
		ExpiresAt:   answer.ExpiresAt,
		Via:         car.Via,
		Relay:       usableCeremonyRelay(answer.Relay),
	}, nil
}

// usableCeremonyRelay reads the resolution's optional `relay` member: an oracle
// the operator offers to a holder that has none of its own.
//
// IT IS A COURTESY, AND IT NEVER FAILS A CEREMONY. Absent, blank, unparseable,
// cleartext off loopback — every one of those is simply "this operator named no
// relay", because the member configures nothing and a ceremony that refused over
// a malformed courtesy would be refusing over something that does not matter.
// What it is NOT is host-checked: unlike the carriage URI, whose authority must
// byte-equal the one the human typed, an oracle is deliberately allowed to be a
// third party — the operator naming a relay it does not run is the ordinary case,
// and the trust that reaches is bounded by what the check can do (ask one public
// index one question) rather than by whose name is on it.
func usableCeremonyRelay(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	if err := checkCeremonyScheme(u); err != nil {
		return ""
	}
	// Scheme, host, path — the base a relay client is built from. A query or a
	// fragment on an API base is not a relay address, and carrying one through
	// would corrupt every path appended to it.
	base := u.Scheme + "://" + u.Host + u.Path
	return strings.TrimRight(base, "/")
}

// ceremonyRelayLabel names a resolution-supplied oracle for a human. There is no
// peer name to use — it is not a peer — so the host is what a person can
// recognize it by, and the provenance printed beside it says where the name came
// from.
func ceremonyRelayLabel(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return u.Host
	}
	return rawURL
}

// ceremonyMessage renders whatever the operator said about a failure. It reads
// the two conventional members and falls back to the body itself, because an
// operator's sentence is the most useful thing on the screen when a ceremony
// refuses and swallowing it would leave the human with a status code.
func ceremonyMessage(body []byte) string {
	var payload struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		if payload.Error != "" {
			return payload.Error
		}
		if payload.Message != "" {
			return payload.Message
		}
	}
	return oneLineBody(body, 200)
}

// oneLineBody squeezes a response body into something that belongs inside an
// error sentence. A URL that turns out not to be a ceremony operator answers
// with a whole HTML page, and pasting it into a failure message buries the
// sentence the human needs.
func oneLineBody(body []byte, max int) string {
	s := strings.Join(strings.Fields(string(body)), " ")
	if s == "" {
		return "(empty response body)"
	}
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// --- the candidate key ---

// candidateAccountPrefix is where a key that no chain names yet lives in the
// keystore. A candidate is exactly that: proven to a ceremony operator, and not
// declared by anything this machine can read. `keys list` reports it as its own
// status and `prune` never touches it — see classifyKey.
const candidateAccountPrefix = "candidate:"

// candidateKey is the key this ceremony is about, and where it came from.
type candidateKey struct {
	PublicKey string
	Private   ed25519.PrivateKey
	Account   string
	// Origin is the disclosure line: what the human is proving possession of.
	Origin string
	// Minted is true when this run created the key. It gates the vault
	// provenance record, which can only be written once the operator names the
	// identity that adopted the key.
	Minted     bool
	Vault      string
	VaultIndex uint32
}

// errCeremonyNoVault is the no-vault refusal, worded for the machine this
// command is most often run on: a fresh one, where a person has pasted a code
// before they have ever created a seed.
//
// The reassurance is the load-bearing half. Everything else in this command
// tells the operator a failure spent their ceremony, so a bare "no vault" here
// reads as one more burned code — and it is not: resolution asks a question and
// consumes nothing, the nonce is spent only by a completion, and the code they
// are looking at stays live for the rest of its ten minutes. So the fix is the
// same paste, after a seed exists.
//
// No seed is created for them. A vault is the most consequential thing on the
// machine (`dfos vault` — its phrase covers every key it mints), and one minted
// as a side effect of a ceremony is one nobody wrote down.
func errCeremonyNoVault() error {
	return fmt.Errorf("no vault to mint the candidate key from — nothing was signed.\n" +
		"THE CEREMONY IS NOT SPENT: resolving a code asks a question and consumes nothing, so the code on the\n" +
		"other screen is still live for the rest of its lifetime. Create a seed, then paste the same code again:\n" +
		"  dfos vault create <name>                 writes down the phrase that covers every key it mints\n" +
		"  dfos config set default-vault <name>     the standing default, when this machine has more than one\n" +
		"  dfos keys prove <the same code>          the same paste, now that there is a seed\n" +
		"Or pass --no-vault for a standalone key no phrase covers, held only in this keystore.")
}

// mintCandidate creates the key this ceremony enrolls: the phone-story shape,
// where the human is adding a NEW self-held key to an identity someone else
// custodies the chain for.
//
// The key is written to the keystore BEFORE it is used. A ceremony that fails
// after this point leaves a key an operator still holds and can re-present with
// --key; a key that existed only in memory would be gone.
func mintCandidate(vaultFlag string, noVault bool) (*candidateKey, error) {
	name, _, err := resolveVault(vaultFlag, noVault)
	if err != nil {
		return nil, err
	}

	var priv ed25519.PrivateKey
	cand := &candidateKey{Minted: true}
	if name == "" {
		if !noVault {
			return nil, errCeremonyNoVault()
		}
		if _, priv, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return nil, fmt.Errorf("generate a candidate key: %w", err)
		}
		cand.Origin = "generated standalone — no vault phrase covers it"
	} else {
		derived, err := getVaults().Mint(name, 1)
		if err != nil {
			return nil, err
		}
		priv = derived[0].Private
		cand.Vault, cand.VaultIndex = name, derived[0].Index
		cand.Origin = fmt.Sprintf("minted from vault '%s' at %s", name, vault.DerivationPath(derived[0].Index))
	}

	cand.Private = priv
	cand.PublicKey = protocol.EncodeMultikey(priv.Public().(ed25519.PublicKey))
	cand.Account = candidateAccountPrefix + cand.PublicKey
	if _, err := keys.PutKey(cand.Account, priv); err != nil {
		return nil, fmt.Errorf("store the candidate key in %s: %w", keys.Backend(), err)
	}
	return cand, nil
}

// heldCandidate resolves --key against the keys this machine holds.
//
// Signing a key proof is a KEYSTORE-level act: the key need not have been minted
// from a vault, need not be in any chain, and is addressed here the same way
// `keys show` addresses one. What it must be is READABLE — a key whose status
// this machine cannot establish is not a key it will sign a possession proof
// with.
func heldCandidate(selector string) (*candidateKey, error) {
	ledger, err := buildKeyLedger()
	if err != nil {
		return nil, err
	}
	entry, err := findKeyEntry(ledger, selector)
	if err != nil {
		return nil, err
	}
	if entry.Account == "" {
		return nil, fmt.Errorf("%s holds this key and cannot name it, so there is no account to read it from", keys.Backend())
	}
	priv, err := keys.GetPrivateKey(entry.Account)
	if err != nil {
		return nil, fmt.Errorf("read %s from %s: %w", entry.Account, keys.Backend(), err)
	}
	cand := &candidateKey{
		PublicKey: protocol.EncodeMultikey(priv.Public().(ed25519.PublicKey)),
		Private:   priv,
		Account:   entry.Account,
		Origin:    fmt.Sprintf("held here as %s (%s)", entry.Account, entry.Status),
	}
	if entry.Vault != nil {
		cand.Vault, cand.VaultIndex = entry.Vault.Name, entry.Vault.Index
	}
	return cand, entryLinkageLocally(entry)
}

// entryLinkageLocally reports the one-key-one-DID violation this machine can see
// for itself. The oracle is the general answer; a local chain that already PROVED
// the key is a certainty, and certainty deserves the earlier refusal.
//
// A VOID MEMBERSHIP IS NOT A LINK, so it is not this refusal. A chain that
// declared the key without a covering proof never proved it: the membership is
// excluded from effective state, it never enters the index, and it never
// obligates the true holder (specs/KEY-PROOF.md, Holder Obligations). Refusing on
// it would let anyone freeze a key out of its own ceremony by declaring it and
// proving nothing — the hostile-listing move the possession rule exists to
// defang. The ledger reads effective state, so a key held under a void
// declaration arrives here with no DID and passes, which is the right answer.
func entryLinkageLocally(entry *keyLedgerEntry) error {
	if entry.DID == "" || entry.Void {
		return nil
	}
	return fmt.Errorf("%s is already proved into %s in this machine's own local relay.\n%s",
		orDash(entry.KeyID), entry.DID, linkageExplanation())
}

// --- the linkage check ---

// linkageReport is what the oracle said, and how loudly it said it.
type linkageReport struct {
	// Oracle names the relay that answered, always — "used" and "unused" are one
	// relay's answers, and one relay's silence is not the world's.
	Oracle    string `json:"oracle,omitempty"`
	OracleURL string `json:"oracleURL,omitempty"`
	// OracleVia is where that relay came from — this machine's configuration, or
	// the ceremony's own resolution. The two are not the same trust and are never
	// reported as one word.
	OracleVia string `json:"oracleVia,omitempty"`
	// Checked is false when the question could not be asked at all. It is never
	// flattened into "no identity declares this key".
	Checked bool `json:"checked"`
	// Limit is why it could not be asked, when it could not.
	Limit string `json:"limit,omitempty"`
	// Declaring names the identities that have EVER PROVED this key. The member
	// keeps its wire name: it is the shape a script already reads, and renaming
	// it would break those readers to restate what this comment says.
	Declaring []string `json:"declaringIdentities,omitempty"`
	// noOracleAnywhere records the one shape of unanswerability where NEITHER
	// side offered an oracle: this machine named no relay and the resolution
	// carried none. It shapes the refusal's wording and is nobody's business
	// downstream, so it is not part of the receipt.
	noOracleAnywhere bool
}

// oracleProvenance annotates an oracle that came from the ceremony rather than
// from this machine, and says nothing at all about one that came from the
// configuration. A configured peer is a choice the operator already made and
// needs no footnote; a relay this ceremony named is trust the human is extending
// right now, at the moment they are being asked to consent.
func oracleProvenance(r linkageReport) string {
	if r.OracleVia == oracleViaResolution {
		return " (named by the ceremony resolution)"
	}
	return ""
}

// errLinkageUncheckable is the refusal for a check that could not be made — the
// one failure whose whole danger is being read as an answer.
//
// When there was no oracle at ALL it says both halves: this machine named none,
// and neither did the ceremony. Reporting only the first would leave an operator
// hunting for a --relay they may not have, when the other half of the answer is
// that this ceremony offered none — which is the operator's choice and not a
// thing the human can fix from here.
func errLinkageUncheckable(report linkageReport) error {
	nothingToFallBackTo := ""
	if report.noOracleAnywhere {
		nothingToFallBackTo = "Nor did this ceremony name one: a short code's resolution may offer a relay for exactly this\n" +
			"check, and this ceremony offered none.\n"
	}
	return fmt.Errorf("the one-key-one-DID check could not run, so no proof was signed.\n"+
		"  Needed: a relay serving GET /index/v0/identities?key= — the has-ever-proved lookup\n"+
		"  Got:    %s\n"+
		"%sThis is NOT 'no identity declares this key'. Point --relay at a relay that serves the identity\n"+
		"index, or pass --force-linked to sign without the check having run.", report.Limit, nothingToFallBackTo)
}

// linkageExplanation is the one paragraph every linkage refusal ends with.
func linkageExplanation() string {
	return "The relay index's key lookup is HAS-EVER-PROVED: its rows survive rotation and deletion, so a key\n" +
		"proved into two identities publishes an irreversible public link between them. A declaration nobody\n" +
		"proved is not a link — it is void, it never indexes, and it never obligates you. Mint a fresh key\n" +
		"instead — 'dfos keys prove <code>' with no --key does exactly that. Pass --force-linked to publish\n" +
		"the link anyway."
}

// The two provenances an oracle can have. They are words a script branches on,
// so they are constants and not sentences.
const (
	// oracleViaPeer: a relay this machine has registered and pinned.
	oracleViaPeer = "configured peer"
	// oracleViaResolution: the relay this ceremony's own resolution named, used
	// for this one check because the machine had no oracle of its own.
	oracleViaResolution = "ceremony resolution"
)

// checkKeyLinkage asks a named oracle whether any identity has ever PROVED the
// candidate key.
//
// It is the same oracle discipline `dfos recover` uses, for the same reason: a
// relay that does not serve the index (501), one that cannot be reached, and —
// worst — one predating the `key=` filter, which IGNORES the parameter and
// answers an unfiltered page, must each be a loud failure rather than an empty
// result. Here an empty result would read as "nothing declares this key", which
// is exactly the fact the refusal turns on.
//
// THIS MACHINE'S OWN PEER ALWAYS WINS. Only when there is none does the carriage
// resolution's `relay` get to answer, and then for THIS ceremony only: the
// client below is built here, used once, and dropped. Nothing is registered,
// nothing is pinned, and no config is written — a holder that adopted an
// operator's relay as a standing peer would be extending trust the ceremony
// never asked for (KEY-PROOF.md "Security Considerations"). The fallback's
// discipline is identical, so an operator-named relay that cannot answer the
// question is as loud a failure as a configured one.
//
// "NONE" MEANS NONE — errNoPeerConfigured and nothing else. A --relay this
// machine cannot resolve and a peer whose DID pin has moved are both statements
// about a relay the operator DID name, the second of them a compromise signal,
// and each was a hard refusal before there was any fallback to reach for.
// Treating every requirePeer failure as "no oracle here" would let the operator
// who supplies the ceremony also supply the oracle that vets it, exactly when
// this machine had just found something wrong with the one it was told to use.
func checkKeyLinkage(publicKey string, cer *ceremony) linkageReport {
	report := linkageReport{}
	ctx, c, err := requirePeer("")
	switch {
	case err == nil:
		report.Oracle, report.OracleURL, report.OracleVia = ctx.RelayName, ctx.RelayURL, oracleViaPeer
	case errors.Is(err, errNoPeerConfigured) && cer.Relay != "":
		c = client.New(cer.Relay)
		report.Oracle, report.OracleURL, report.OracleVia = ceremonyRelayLabel(cer.Relay), cer.Relay, oracleViaResolution
	default:
		report.Limit = err.Error()
		report.noOracleAnywhere = errors.Is(err, errNoPeerConfigured) && cer.Relay == ""
		return report
	}
	if err := proveOracle(c, report.Oracle, report.OracleURL); err != nil {
		report.Limit = err.Error()
		return report
	}
	rows, err := c.IdentitiesByKey(publicKey, 10)
	if err != nil {
		report.Limit = err.Error()
		return report
	}
	report.Checked = true
	for _, row := range rows {
		report.Declaring = append(report.Declaring, row.DID)
	}
	return report
}

// --- the presentation ---

// presentationAnswer is what the operator says came of the proof.
//
// PRESENTATION IS NOT ADOPTION. A verified proof is stored and the ceremony is
// stamped `presented`; appending the key to the chain happens afterwards, when a
// human approves it on the operator's own authenticated surface. So `keyId` and
// `did` are OPTIONAL here and ordinarily absent — there is no chain row yet to
// name. An operator that answers them anyway lets this command file the key
// under the account that identity's chain will name it by; one that does not is
// not an error, and the key stays a candidate, which is the truthful state.
type presentationAnswer struct {
	Status string `json:"status"`
	KeyID  string `json:"keyId"`
	DID    string `json:"did"`
}

// errCeremonyUnreachable marks the one failure that is NOT a refusal: the
// request never got an answer. The distinction matters to the human, because a
// refusal is something the operator said and a partition is not.
var errCeremonyUnreachable = errors.New("could not reach the ceremony operator")

// presentEnvelope posts the envelope beside its CODE, and beside the description
// when there is one.
//
// The code travels BESIDE the envelope, never inside it. The nonce is the
// binding — minted by the verifier for exactly one ceremony — so envelope→
// ceremony linkage is the verifier's own bookkeeping and the payload stays seven
// members forever. The description rides beside it for the same reason and one
// more: it is a label for the operator's own list of keys, it is UNSIGNED, and
// the payload has no member for it because the payload has no member for
// anything but the proof. An operator is free to ignore it, rename it, or refuse
// an oversized one; nothing here depends on what it does with it.
func presentEnvelope(cer *ceremony, envelope, description string) (*presentationAnswer, error) {
	payload := map[string]string{"code": cer.Code, "envelope": envelope}
	if description != "" {
		payload["description"] = description
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, cer.Present, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errCeremonyUnreachable, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := ceremonyHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %v", errCeremonyUnreachable, cer.Audience, err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%s refused the proof (HTTP %d): %s", cer.Audience, resp.StatusCode, ceremonyMessage(answer))
	}
	var parsed presentationAnswer
	if err := json.Unmarshal(answer, &parsed); err != nil {
		return nil, fmt.Errorf("%s answered HTTP %d with something that is not a presentation: %s",
			cer.Audience, resp.StatusCode, oneLineBody(answer, 200))
	}
	if parsed.Status != "presented" {
		return nil, fmt.Errorf("%s answered HTTP %d without accepting the proof: %s",
			cer.Audience, resp.StatusCode, ceremonyMessage(answer))
	}
	return &parsed, nil
}

// burnedCeremonyAdvice is the tail every presentation failure carries.
//
// A presentation refused at the SIGNATURE arm burns its ceremony; one refused
// before that arm — a stale head, a position that does not match, a label too
// long — does not. Nothing in the answer tells this command which happened, and
// guessing the harmless case would mean retrying against a nonce that may
// already be dead. So the advice is always the one that is safe under both: a
// fresh code, and the same key re-presented rather than a new one minted.
func burnedCeremonyAdvice(cand *candidateKey) string {
	return fmt.Sprintf("\nTreat this ceremony as spent: a refusal at the signature arm burns it, and nothing here can tell\n"+
		"which arm refused, so it is not retried. Mint a fresh code where the last one was displayed, then:\n"+
		"  dfos keys prove <code> --key %s\n"+
		"The key is still held here — that re-presents this same key rather than minting another.", cand.PublicKey)
}

// --- the command ---

type proveResult struct {
	Audience string `json:"audience"`
	Code     string `json:"code"`
	Present  string `json:"present"`
	Carriage string `json:"carriage"`
	Purpose  string `json:"purpose"`

	// The position the envelope binds — the three members that make this proof
	// consent to ONE introduction rather than to a key in general.
	Adopts      string `json:"adopts"`
	Handle      string `json:"handle,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	RoleSet     string `json:"roleSet"`
	PrevCID     string `json:"prevCID"`
	ExpiresAt   string `json:"expiresAt,omitempty"`

	PublicKey string `json:"publicKey"`
	Account   string `json:"account"`
	KeyOrigin string `json:"keyOrigin"`
	Vault     string `json:"vault,omitempty"`
	Backend   string `json:"keystoreBackend"`
	// Description is the label sent to the operator beside the proof. It is not
	// in the envelope and nothing here depends on it.
	Description string `json:"description,omitempty"`

	Linkage linkageReport `json:"linkage"`
	Forced  bool          `json:"forcedLinked,omitempty"`

	Status string `json:"status"`
	KeyID  string `json:"keyId,omitempty"`
	// AdoptedDID is the identity an operator said ADOPTED the key, when it said
	// so. It is distinct from Adopts, which is the identity the ceremony targets:
	// the first is a chain row that exists, the second is the position consented
	// to. Ordinarily only the second is known when this command stops.
	AdoptedDID string `json:"adoptedDID,omitempty"`
	// ExplorerURL is where this key can be looked up in public. It is written
	// only on a presented ceremony, because until then there is nothing to look
	// up.
	ExplorerURL string `json:"explorerURL,omitempty"`
}

// explorerKeyBase is where a public key is looked up in the open explorer. The
// full key goes in the URL and is never truncated: a shortened one addresses
// nothing.
const explorerKeyBase = "https://explore.dfos.com/#/key/"

func explorerKeyURL(publicKeyMultibase string) string {
	return explorerKeyBase + publicKeyMultibase
}

// truncateKey renders a public key the way a person checks one against another
// screen: enough of the head to carry the multibase prefix, and the tail, which
// is what actually distinguishes two keys from the same generator.
//
// It is not truncateMiddle. That one splits a given column width in half for a
// table; this is a fixed convention with no column behind it, and the two would
// disagree about the same key.
func truncateKey(s string) string {
	const head, tail = 10, 6
	runes := []rune(s)
	if len(runes) <= head+tail {
		return s
	}
	return string(runes[:head]) + "…" + string(runes[len(runes)-tail:])
}

// defaultKeyDescription is what this machine calls itself when the human did not
// name the key: user@host, the same shorthand an SSH public key carries as its
// comment, and the thing that makes a list of keys in an operator's settings
// screen readable instead of a column of multibase strings.
//
// Either half may be unavailable — a container with no passwd entry, a host that
// cannot name itself — and neither is worth a failure. What is left is sent; if
// nothing is left, the member is simply absent, which the operator's own default
// then covers.
func defaultKeyDescription() string {
	who := ""
	if u, err := user.Current(); err == nil {
		who = strings.TrimSpace(u.Username)
	}
	host, err := os.Hostname()
	if err != nil {
		host = ""
	}
	host = strings.TrimSpace(host)
	switch {
	case who != "" && host != "":
		return who + "@" + host
	case host != "":
		return host
	default:
		return who
	}
}

func newKeysProveCmd() *cobra.Command {
	var vaultName string
	var noVault bool
	var keySelector string
	var assumeYes bool
	var forceLinked bool
	var description string

	cmd := &cobra.Command{
		Use:   "prove <code-or-uri>",
		Short: "Prove a key to a key-add ceremony (KEY-PROOF)",
		Long: "Present a key to a key-add ceremony an operator started: resolve the code it displayed, sign a " +
			"KEY-PROOF envelope with the candidate key itself, and post it to the ceremony's presentation " +
			"endpoint. The argument is either the short code an operator shows — '<authority>/<CODE>', where " +
			"spaces and dashes between the characters are ignored — or the carriage URI a QR code carries. Both " +
			"are an authority and a code; the identity, the roles, the chain head and the nonce all come from " +
			"resolving that code at that authority.\n\n" +
			"By default it MINTS the key it proves, from the default vault or --vault: the candidate is a new " +
			"self-held key being added to an identity someone else custodies the chain for. --key proves a key " +
			"this machine already holds. --name labels the key in the operator's own list; the label rides " +
			"beside the proof, unsigned, and defaults to <user>@<hostname>.\n\n" +
			"Before signing it shows the audience, the identity being joined and the roles being consented to, " +
			"and asks — that binding only defends a human who saw it — and it refuses a key any identity has " +
			"ever proved, because the relay index's key lookup is has-ever-proved and one key proved into two " +
			"chains is a permanent public link between them. That check runs against this machine's peer; a " +
			"machine with none uses the relay the resolution named, for this ceremony only and never as a " +
			"registered peer. A presentation is never retried.\n\n" +
			"Presenting is not adoption. A verified proof leaves the ceremony awaiting a human's approval on the " +
			"operator's own surface; the key is held here as a candidate until a chain declares it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The default is computed here rather than registered as the flag's
			// default so that --name '' stays distinguishable from an unflagged
			// run: one is a human declining to label the key, the other is a
			// human saying nothing.
			if !cmd.Flags().Changed("name") {
				description = defaultKeyDescription()
			}
			return runKeysProve(cmd, args[0], proveOptions{
				vaultFlag:   vaultName,
				noVault:     noVault,
				keySelector: keySelector,
				assumeYes:   assumeYes,
				forceLinked: forceLinked,
				description: description,
			})
		},
	}
	cmd.Flags().StringVar(&keySelector, "key", "", "Prove a key this machine already holds (key id, public key, or account)")
	cmd.Flags().StringVar(&description, "name", "",
		"Label the operator files this key under (default: <user>@<hostname>; --name '' sends none)")
	cmd.Flags().StringVar(&vaultName, "vault", "", "Vault the new key is minted from (default: config default-vault)")
	cmd.Flags().BoolVar(&noVault, "no-vault", false, "Mint the new key straight into the keystore, from no seed")
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "Skip the confirmation — the audience has already been checked by a human")
	cmd.Flags().BoolVar(&forceLinked, "force-linked", false,
		"Sign even when an identity has already proved this key, or when the check could not run")
	return cmd
}

type proveOptions struct {
	vaultFlag   string
	noVault     bool
	keySelector string
	assumeYes   bool
	forceLinked bool
	description string
}

func runKeysProve(cmd *cobra.Command, input string, opts proveOptions) error {
	if opts.keySelector != "" && (opts.vaultFlag != "" || opts.noVault) {
		return fmt.Errorf("--key names a key this machine already holds; --vault and --no-vault choose where a NEW one is minted from")
	}

	// 1. The carriage and its resolution, first: an unresolvable code costs no key
	//    material, and the position has to be known before there is anything to
	//    show a human or to sign.
	cer, err := resolveCeremony(input)
	if err != nil {
		return err
	}

	// 2. The candidate.
	var cand *candidateKey
	var localLinkage error
	if opts.keySelector != "" {
		cand, localLinkage = heldCandidate(opts.keySelector)
		if cand == nil {
			return localLinkage
		}
		if localLinkage != nil && !opts.forceLinked {
			return localLinkage
		}
	} else {
		if cand, err = mintCandidate(opts.vaultFlag, opts.noVault); err != nil {
			return err
		}
	}

	// 3. One key, one DID. Asked before there is a signature to make, because
	//    the linkage a proof creates is public and permanent.
	linkage := checkKeyLinkage(cand.PublicKey, cer)
	switch {
	case len(linkage.Declaring) > 0 && !opts.forceLinked:
		return fmt.Errorf("REFUSING: %s has already proved %s (%s said so%s, and the key is held here as %s).\n%s",
			strings.Join(linkage.Declaring, ", "), cand.PublicKey, linkage.Oracle, oracleProvenance(linkage),
			cand.Account, linkageExplanation())
	case !linkage.Checked && !opts.forceLinked:
		return errLinkageUncheckable(linkage)
	}

	result := &proveResult{
		Audience: cer.Audience, Code: cer.Code, Present: cer.Present, Carriage: cer.Via,
		Purpose: protocol.KeyAddJWSTyp,
		Adopts:  cer.DID, Handle: cer.Handle, DisplayName: cer.DisplayName,
		RoleSet: cer.RoleSet, PrevCID: cer.PrevCID, ExpiresAt: cer.ExpiresAt,
		PublicKey: cand.PublicKey, Account: cand.Account,
		KeyOrigin: cand.Origin, Vault: cand.Vault, Backend: keys.Backend(),
		Description: opts.description, Linkage: linkage, Forced: opts.forceLinked,
	}

	// 4. Display before signing — a MUST, and not suppressible by --quiet.
	printCeremonyDisclosure(result, localLinkage)
	if !opts.assumeYes {
		if err := confirmCeremony(cmd.InOrStdin(), cand); err != nil {
			return err
		}
	}

	// 5. The envelope, over the position the human just confirmed. The kit derives
	//    publicKeyMultibase from the private key itself — a signer that could name
	//    a key it does not hold is the one construction this artifact exists to
	//    foreclose.
	envelope, _, err := protocol.SignKeyProof(protocol.SignKeyProofInput{
		Typ:        protocol.KeyAddJWSTyp,
		Nonce:      cer.Nonce,
		Audience:   cer.Audience,
		DID:        cer.DID,
		RoleSet:    cer.RoleSet,
		PrevCID:    cer.PrevCID,
		PrivateKey: cand.Private,
	})
	if err != nil {
		return fmt.Errorf("sign the key proof: %w", err)
	}

	// 6. Presentation. One attempt, ever.
	answer, err := presentEnvelope(cer, envelope, opts.description)
	if err != nil {
		if errors.Is(err, errCeremonyUnreachable) {
			return fmt.Errorf("%v.\nIf the request arrived, the proof was presented even though no answer came back.%s",
				err, burnedCeremonyAdvice(cand))
		}
		return fmt.Errorf("%v.%s", err, burnedCeremonyAdvice(cand))
	}
	result.Status, result.KeyID, result.AdoptedDID = answer.Status, answer.KeyID, answer.DID
	result.ExplorerURL = explorerKeyURL(cand.PublicKey)

	// 7. File the key where the identity that adopted it will name it — only if
	//    the operator said the adoption already happened.
	//
	//    Ordinarily it has not: presentation stores the proof and stops, and the
	//    chain row appears when a human approves it elsewhere. So this branch is
	//    the exception, not the path, and the candidate account is the normal
	//    resting place.
	//
	//    Only a CANDIDATE account is renamed. A key already filed under some
	//    other account is filed there because something else named it, and
	//    moving it on an operator's say-so would take that key away from whatever
	//    was using it.
	if ok := adoptionNamesAnIdentity(answer, cer); ok && strings.HasPrefix(cand.Account, candidateAccountPrefix) {
		account := keyAccount(cand.PublicKey)
		if !keys.HasKey(account) {
			if err := keys.RenameKey(cand.Account, account); err == nil {
				result.Account = account
				if cand.Minted && cand.Vault != "" {
					roles := []string{}
					if parsed, ok := protocol.ParseRoleSet(cer.RoleSet); ok {
						for _, role := range parsed {
							roles = append(roles, string(role))
						}
					}
					_ = getVaults().Record(cand.Vault, vault.MintedKey{
						Index: cand.VaultIndex, DID: answer.DID, KeyID: answer.KeyID,
						Roles: roles, PublicKey: cand.PublicKey,
					})
				}
			}
		}
	}

	if jsonFlag {
		outputJSON(result)
		return nil
	}
	printProveResult(result)
	return nil
}

// adoptionNamesAnIdentity reports whether a presentation actually said the key
// was adopted, in a shape this CLI will act on.
//
// The account the key moves to is its own content address and needs neither
// member — but the vault provenance record does, and an answer that names
// nothing readable is one this machine does not file anything against. The key
// id is shape-checked because a '#' in it would make the provenance record read
// as a different key.
//
// AND THE DID MUST BE THE ONE THE HUMAN CONSENTED TO. An answer naming some
// other identity is either a confused operator or one trying to file this key
// against a chain nobody was shown; either way the provenance record it would
// write is a claim the human never saw. Filing nothing is the honest response —
// the key stays a candidate, which is what it is.
func adoptionNamesAnIdentity(answer *presentationAnswer, cer *ceremony) bool {
	return strings.HasPrefix(answer.DID, "did:dfos:") &&
		answer.DID == cer.DID &&
		keyIDShape.MatchString(answer.KeyID)
}

// roleDisclosure spells one role as the power it actually confers.
//
// The canonical token is kept beside the sentence rather than replaced by it: the
// token is what the operator's own screen shows and what the envelope carries, so
// a human comparing the two needs to see it — but a human deciding whether to
// consent needs to know that `controller` is not a synonym for `auth` with a
// longer name. Consenting to sign as an author is not consenting to hand over the
// identity, and only the sentence says so.
func roleDisclosure(role protocol.KeyRole) string {
	switch role {
	case "auth":
		return "auth — sign in and act as this identity"
	case "assert":
		return "assert — publish and attest as this identity"
	case "controller":
		return "controller — CONTROL this identity: add and remove its keys, including yours"
	}
	return string(role)
}

// printCeremonyDisclosure is KEY-PROOF.md's Holder Obligation made visible: the
// audience, the purpose, the identity being joined, and the roles being consented
// to, before anything is signed. It goes to stderr, so --json emits one document
// on stdout and the human still sees what they are consenting to.
func printCeremonyDisclosure(r *proveResult, localLinkage error) {
	out := os.Stderr
	fmt.Fprintf(out, "Ceremony:\n")
	// The identity first. It is the thing being joined, and every other line is a
	// detail about joining it.
	fmt.Fprintf(out, "  Adds to:   %s (@%s)\n", r.DisplayName, r.Handle)
	fmt.Fprintf(out, "             %s\n", r.Adopts)
	// Roles, one per line, each spelled out. A set rendered as one comma-joined
	// token is a token a person's eye skips; a list of sentences is not.
	if roles, ok := protocol.ParseRoleSet(r.RoleSet); ok {
		for i, role := range roles {
			label := "  Roles:     "
			if i > 0 {
				label = "             "
			}
			fmt.Fprintf(out, "%s%s\n", label, roleDisclosure(role))
		}
	} else {
		fmt.Fprintf(out, "  Roles:     %s\n", r.RoleSet)
	}
	fmt.Fprintf(out, "  Audience:  %s\n", r.Audience)
	fmt.Fprintf(out, "  Purpose:   add this key to %s at %s (%s)\n", r.Adopts, r.Audience, r.Purpose)
	fmt.Fprintf(out, "  Carriage:  %s\n", r.Carriage)
	// The head the consent is spent at. A person is not expected to verify it —
	// they hold nothing to check it against — but it is what makes this proof
	// unusable at any other position, and a disclosure that hid it would be
	// hiding the member that does the most work.
	fmt.Fprintf(out, "  Builds on: %s\n", r.PrevCID)
	if r.ExpiresAt != "" {
		fmt.Fprintf(out, "  Expires:   %s\n", r.ExpiresAt)
	}
	fmt.Fprintf(out, "  Key:       %s\n", r.PublicKey)
	fmt.Fprintf(out, "  Origin:    %s\n", r.KeyOrigin)
	if r.Description != "" {
		// It goes to the operator, so the human confirming this ceremony sees it
		// before it does — and sees that it is a label rather than part of what
		// is signed.
		fmt.Fprintf(out, "  Name:      %s (sent beside the proof, unsigned)\n", r.Description)
	}
	fmt.Fprintf(out, "  Keystore:  %s\n", r.Backend)
	switch {
	case len(r.Linkage.Declaring) > 0:
		fmt.Fprintf(out, "  Linkage:   ! %s has already proved this key — %s said so%s\n",
			strings.Join(r.Linkage.Declaring, ", "), r.Linkage.Oracle, oracleProvenance(r.Linkage))
	case r.Linkage.Checked:
		fmt.Fprintf(out, "  Linkage:   no identity has ever proved this key — %s answered%s\n",
			r.Linkage.Oracle, oracleProvenance(r.Linkage))
	default:
		fmt.Fprintf(out, "  Linkage:   ! NOT CHECKED — %s\n", firstLine(r.Linkage.Limit))
	}
	if localLinkage != nil {
		fmt.Fprintf(out, "  Local:     ! %s\n", firstLine(localLinkage.Error()))
	}
	fmt.Fprintf(out, "\nThis signs a proof that you hold this key and consent to joining THIS identity in THESE roles,\n")
	fmt.Fprintf(out, "at THIS host, on THIS chain head. It is spent at that position and is dead bytes at every other.\n")
	fmt.Fprintf(out, "It carries no authority, no content, and no instruction, and the private key stays here.\n")
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// confirmCeremony asks. A pipe, a CI job, and a `< /dev/null` all answer no
// question — they are told to pass --yes, which is a script asserting that a
// human already checked the audience, rather than a prompt nobody read.
func confirmCeremony(in io.Reader, cand *candidateKey) error {
	if !stdinIsInteractive() {
		return fmt.Errorf("nothing was signed: a ceremony is confirmed by a human who has seen the identity, the roles\n"+
			"and the audience above. Re-run with --yes once they are the ones you meant. The candidate key is held as %s",
			cand.Account)
	}
	fmt.Fprintf(os.Stderr, "\nPresent this proof? [y/N]: ")
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("read confirmation: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	}
	return fmt.Errorf("nothing was signed. The candidate key is held as %s — 'dfos keys prove <code> --key %s' presents it to a fresh ceremony",
		cand.Account, cand.PublicKey)
}

// printProveResult is the receipt. It reports what happened — the proof was
// PRESENTED — and never more than that.
//
// THE CEREMONY IS NOT OVER WHEN THIS COMMAND STOPS, and the receipt's job is to
// say so plainly. A presented proof waits for a human to approve it on the
// operator's own surface; until that happens no chain declares the key, the key
// is a candidate here, and telling someone their key was "added" would be telling
// them a step they still have to take is already done.
func printProveResult(r *proveResult) {
	fmt.Printf("\nPresented:\n")
	fmt.Printf("  Adds to:   %s (@%s)\n", r.DisplayName, r.Handle)
	fmt.Printf("             %s\n", r.Adopts)
	fmt.Printf("  Roles:     %s\n", r.RoleSet)
	fmt.Printf("  Audience:  %s\n", r.Audience)
	fmt.Printf("  Key:       %s\n", r.PublicKey)
	if r.KeyID != "" {
		// The operator's name for the key, and beside it the shortened key —
		// which is what a person compares against the row on the other screen,
		// where a key id means nothing.
		fmt.Printf("  Key id:    %s (%s)\n", r.KeyID, truncateKey(r.PublicKey))
	}
	fmt.Printf("  Account:   %s (%s)\n", r.Account, r.Backend)
	if r.ExplorerURL != "" {
		fmt.Printf("  Explorer:  %s\n", r.ExplorerURL)
	}
	fmt.Println()

	// The fingerprint, and what to do with it. This is the human's half of the
	// wrong-ceremony defense: the operator's dialog shows the key it received, and
	// comparing the two is what catches a proof that landed in someone else's
	// ceremony before it is approved.
	fmt.Printf("Approve it at %s — it shows the key it received, and %s\n", r.Audience, truncateKey(r.PublicKey))
	fmt.Printf("is what should be on that screen. Nothing is added to the chain until you approve it there.\n\n")

	if r.AdoptedDID == "" {
		fmt.Printf("Until then the key is held here as a candidate: 'dfos keys list' shows it, 'dfos keys prune'\n")
		fmt.Printf("never removes it, and 'dfos keys remove %s' is how it leaves if the ceremony goes nowhere.\n",
			truncateKey(r.PublicKey))
		if r.Vault != "" {
			fmt.Printf("Once %s declares it, 'dfos recover --vault %s' files it under that identity.\n", r.Adopts, r.Vault)
		} else {
			fmt.Printf("Once %s declares it, 'dfos identity fetch %s' brings that chain here.\n", r.Adopts, r.Adopts)
		}
		return
	}
	fmt.Printf("The key is filed under %s. Signing resolves the identity and uses the key this device holds.\n", r.AdoptedDID)
	// The label is the operator's to keep, so the place to change it is the
	// operator's too — not this command, which has no ceremony left to run.
	fmt.Printf("Rename it any time in Settings → Signing keys.\n")
}

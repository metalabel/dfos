package cmd

// `dfos keys prove` — the holder's half of a key-add ceremony (specs/KEY-PROOF.md).
//
// A ceremony operator displays a code on one screen; this command is what the
// human runs on the machine that actually holds a key. It resolves the carriage,
// picks the candidate key, shows the human what is about to be signed, signs the
// four-member KEY-PROOF envelope with the candidate key ITSELF, and posts it to
// the completion endpoint. What the operator then does with the proven key —
// which identity it lands on, under which role — is the operator's machinery,
// outside this command and outside the envelope.
//
// FOUR RULES CARRY THIS COMMAND, and every branch below serves one of them:
//
//  1. THE AUDIENCE IS SHOWN BEFORE ANYTHING IS SIGNED. Audience binding is what
//     defeats challenge relay — a phished code re-displayed on an attacker's
//     surface still yields a proof naming the authority the victim confirmed —
//     and it only defends a human who SAW the authority. So the display is not
//     suppressible by --quiet, and a TTY is asked; --yes is how a script says
//     the human already saw it.
//  2. ONE KEY, ONE DID — REFUSED BY DEFAULT. The relay index's `key=` filter is
//     has-ever-declared and its rows survive rotation and deletion, so declaring
//     one key in two chains publishes an irreversible public link between them.
//     The check runs against a NAMED oracle before there is a signature to make,
//     and a check that could not run is never silently skipped.
//  3. A COMPLETION IS NEVER RETRIED. A verifier consumes the nonce before it
//     verifies the envelope (check-and-delete, atomically), so a ceremony that
//     fails server-side verification is BURNED. Retrying would present a dead
//     nonce and teach the operator's rate limiter a lesson about this CLI. The
//     fix is always a fresh code.
//  4. THE PRIVATE KEY NEVER LEAVES. What goes on the wire is a JWS over four
//     members, one of which is the PUBLIC key. Nothing prints a seed.
//
// The short-code route is asked EXACTLY ONCE per invocation. It is IP rate
// limited at the operator, a ceremony lives ten minutes, and a code that did not
// resolve on the first ask is not going to resolve on the second.

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
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/apispec"
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

// keyIDShape is what a completion answer's `keyId` may look like before it is
// allowed to name a keystore account. An account is `<did>#<keyId>`, so a key id
// carrying '#' or a path separator would be a key filed under a name that means
// something else.
var keyIDShape = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

// --- the carriage ---

// carriage is the resolved triple KEY-PROOF.md's Carriage section defines —
// completion endpoint, ceremony identifier, nonce — plus the audience derived
// from the endpoint and a note of how it was resolved.
//
// It names no identity, by construction: a shoulder-surfed code or an
// intercepted QR learns where a ceremony completes and nothing about whom it is
// for.
type carriage struct {
	// Endpoint is the completion URL: the carriage URI with the `ceremony` and
	// `nonce` members removed, and nothing else removed. Other query members are
	// the operator's and are carried through.
	Endpoint string
	Ceremony string
	Nonce    string
	// Audience is the completion endpoint's lowercase authority — bare host on
	// the scheme's default port, host:port otherwise. It is the member the
	// verifier byte-compares against its own configured authority.
	Audience string
	// Via says which carriage form produced this, for the disclosure block.
	Via string
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

// normalizeDeviceCode upper-cases an argument and checks it against the code
// grammar. Case is normalized rather than rejected: the alphabet has one case,
// so a lower-case letter is a typing artifact and not an ambiguity.
func normalizeDeviceCode(raw string) (string, bool) {
	code := strings.ToUpper(raw)
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
		"  <authority>/<CODE>   the short code, %d characters of %s\n"+
		"  https://…?ceremony=…&nonce=…   the full carriage URI (a QR code's contents verbatim)",
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

// carriageFromURI validates one carriage URI and splits it into the triple.
func carriageFromURI(u *url.URL, via string) (*carriage, error) {
	if err := checkCeremonyScheme(u); err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, fmt.Errorf("the carriage URI names no host")
	}
	if u.User != nil {
		return nil, fmt.Errorf("refusing a carriage URI carrying userinfo — the triple is an endpoint, a ceremony, and a nonce, and nothing else")
	}
	q := u.Query()
	for _, member := range []string{"ceremony", "nonce"} {
		switch len(q[member]) {
		case 1:
			if strings.TrimSpace(q[member][0]) == "" {
				return nil, fmt.Errorf("the carriage URI's '%s' member is empty", member)
			}
		case 0:
			return nil, fmt.Errorf("the carriage URI carries no '%s' member — a carriage is the completion endpoint plus 'ceremony' and 'nonce'", member)
		default:
			return nil, fmt.Errorf("the carriage URI carries '%s' %d times — which one is the ceremony is not a guess this makes", member, len(q[member]))
		}
	}

	// The completion endpoint is the URL with those two members removed — and
	// only those two. Any other member is the operator's own routing, and
	// dropping it would post to a different endpoint than the one carried.
	endpoint := *u
	endpoint.Fragment = ""
	rest := url.Values{}
	for member, values := range q {
		if member == "ceremony" || member == "nonce" {
			continue
		}
		rest[member] = values
	}
	endpoint.RawQuery = rest.Encode()

	return &carriage{
		Endpoint: endpoint.String(),
		Ceremony: q.Get("ceremony"),
		Nonce:    q.Get("nonce"),
		Audience: apispec.NormalizeAuthority(u.Scheme, u.Host),
		Via:      via,
	}, nil
}

// resolveCeremony turns the one argument into a carriage.
//
// Which form it is, is read off the QUERY, not off the spelling: a URL carrying
// `ceremony` and `nonce` is a carriage URI, and a bare `<authority>/<CODE>` is a
// short code. A scheme is optional on the short form because an operator's UI
// displays it without one and a person pasting it may bring the `https://` back.
func resolveCeremony(raw string) (*carriage, error) {
	raw = strings.TrimSpace(raw)
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
	if q := u.Query(); len(q["ceremony"]) > 0 || len(q["nonce"]) > 0 {
		return carriageFromURI(u, "carriage URI")
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segments) != 1 || segments[0] == "" || u.RawQuery != "" {
		return nil, errBadCeremonyInput(raw)
	}
	code, ok := normalizeDeviceCode(segments[0])
	if !ok {
		return nil, fmt.Errorf("'%s' is not a ceremony code — a code is %d characters of %s (no I, O, 0 or 1)",
			segments[0], deviceCodeLength, deviceCodeAlphabet)
	}
	if err := checkCeremonyScheme(u); err != nil {
		return nil, err
	}
	return resolveShortCode(u.Scheme, u.Host, code)
}

// resolveShortCode asks the authority the human typed what carriage its code
// stands for — ONE request, no retry, no polling.
//
// The resolved URI's authority MUST byte-equal the resolving authority. That
// rule is the whole security of the short form: without it, an operator (or
// anyone who can answer for it) could resolve a code the human typed at one host
// into a ceremony completing at another, and the audience the human confirmed
// would name a host they never saw.
func resolveShortCode(scheme, host, code string) (*carriage, error) {
	endpoint := scheme + "://" + host + keyProofWellKnownPath + "?code=" + url.QueryEscape(code)
	resp, err := ceremonyHTTPClient().Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s to resolve the code %s: %w\n"+
			"Nothing was signed and nothing was sent. Check the host and try again", host, code, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("%s does not know the code %s: %s\n"+
			"A ceremony code is single-shot and lives ten minutes. Mint a fresh one where it was displayed and run this again",
			host, code, ceremonyMessage(body))
	default:
		return nil, fmt.Errorf("HTTP %d from %s%s: %s", resp.StatusCode, host, keyProofWellKnownPath, ceremonyMessage(body))
	}

	var answer struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(body, &answer); err != nil || strings.TrimSpace(answer.URI) == "" {
		return nil, fmt.Errorf("%s answered 200 with no carriage URI: %s", host, ceremonyMessage(body))
	}
	resolved, err := url.Parse(strings.TrimSpace(answer.URI))
	if err != nil || resolved.Host == "" {
		return nil, fmt.Errorf("%s answered with something that is not a carriage URI: %s", host, ceremonyMessage(body))
	}

	asked := apispec.NormalizeAuthority(scheme, host)
	got := apispec.NormalizeAuthority(resolved.Scheme, resolved.Host)
	if !strings.EqualFold(resolved.Scheme, scheme) || got != asked {
		return nil, fmt.Errorf("REFUSING: the code you typed at %s resolved to a ceremony at %s.\n"+
			"A code's resolution may never redirect a ceremony off the host the human typed, so this one is not completed.\n"+
			"Nothing was signed. Report this to whoever displayed the code", asked, resolved.Scheme+"://"+got)
	}
	return carriageFromURI(resolved, "short code at "+asked)
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
			return nil, errNoVault()
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
// for itself. The oracle is the general answer; a local chain that already names
// the key is a certainty, and certainty deserves the earlier refusal.
func entryLinkageLocally(entry *keyLedgerEntry) error {
	if entry.DID == "" {
		return nil
	}
	return fmt.Errorf("%s is already declared by %s in this machine's own local relay.\n%s",
		orDash(entry.KeyID), entry.DID, linkageExplanation())
}

// --- the linkage check ---

// linkageReport is what the oracle said, and how loudly it said it.
type linkageReport struct {
	// Oracle names the relay that answered, always — "used" and "unused" are one
	// relay's answers, and one relay's silence is not the world's.
	Oracle    string `json:"oracle,omitempty"`
	OracleURL string `json:"oracleURL,omitempty"`
	// Checked is false when the question could not be asked at all. It is never
	// flattened into "no identity declares this key".
	Checked bool `json:"checked"`
	// Limit is why it could not be asked, when it could not.
	Limit string `json:"limit,omitempty"`
	// Declaring names the identities that have EVER declared this key.
	Declaring []string `json:"declaringIdentities,omitempty"`
}

// linkageExplanation is the one paragraph every linkage refusal ends with.
func linkageExplanation() string {
	return "The relay index's key lookup is HAS-EVER-DECLARED: its rows survive rotation and deletion, so a key\n" +
		"declared by two identities publishes an irreversible public link between them. Mint a fresh key instead —\n" +
		"'dfos keys prove <code>' with no --key does exactly that. Pass --force-linked to publish the link anyway."
}

// checkKeyLinkage asks a named oracle whether any identity has ever declared the
// candidate key.
//
// It is the same oracle discipline `dfos recover` uses, for the same reason: a
// relay that does not serve the index (501), one that cannot be reached, and —
// worst — one predating the `key=` filter, which IGNORES the parameter and
// answers an unfiltered page, must each be a loud failure rather than an empty
// result. Here an empty result would read as "nothing declares this key", which
// is exactly the fact the refusal turns on.
func checkKeyLinkage(publicKey string) linkageReport {
	report := linkageReport{}
	ctx, c, err := requirePeer("")
	if err != nil {
		report.Limit = err.Error()
		return report
	}
	report.Oracle, report.OracleURL = ctx.RelayName, ctx.RelayURL
	if err := proveOracle(c, ctx.RelayName, ctx.RelayURL); err != nil {
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

// --- the completion ---

// completionAnswer is what the operator says came of the proof.
//
// `did` is OPTIONAL and tolerated rather than required: KEY-PROOF.md leaves
// everything after verification to the ceremony operator, and an operator that
// names the identity its ceremony added the key to lets this command file the
// key under the account that identity's chain will name it by. An operator that
// does not is not an error — the key stays a candidate.
type completionAnswer struct {
	Status string `json:"status"`
	KeyID  string `json:"keyId"`
	DID    string `json:"did"`
}

// errCeremonyUnreachable marks the one failure that is NOT a refusal: the
// request never got an answer. The distinction matters to the human, because a
// refusal is something the operator said and a partition is not.
var errCeremonyUnreachable = errors.New("could not reach the ceremony operator")

// completeCeremony posts the envelope beside its ceremony id.
//
// The ceremony id travels BESIDE the envelope, never inside it: the nonce is the
// binding, minted by the verifier for exactly one ceremony, so envelope→ceremony
// linkage is the verifier's own bookkeeping and the payload stays four members
// forever.
func completeCeremony(c *carriage, envelope string) (*completionAnswer, error) {
	body, err := json.Marshal(map[string]string{"ceremony": c.Ceremony, "envelope": envelope})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errCeremonyUnreachable, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := ceremonyHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %v", errCeremonyUnreachable, c.Audience, err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%s refused the proof (HTTP %d): %s", c.Audience, resp.StatusCode, ceremonyMessage(answer))
	}
	var parsed completionAnswer
	if err := json.Unmarshal(answer, &parsed); err != nil {
		return nil, fmt.Errorf("%s answered HTTP %d with something that is not a completion: %s",
			c.Audience, resp.StatusCode, oneLineBody(answer, 200))
	}
	if parsed.Status != "completed" {
		return nil, fmt.Errorf("%s answered HTTP %d without completing the ceremony: %s",
			c.Audience, resp.StatusCode, ceremonyMessage(answer))
	}
	return &parsed, nil
}

// burnedCeremonyAdvice is the tail every completion failure carries. A verifier
// consumes a nonce before it verifies the envelope, so a failed completion has
// still spent the ceremony — which is why nothing here retries, and why the
// advice is always "a fresh code", never "run it again".
func burnedCeremonyAdvice(cand *candidateKey) string {
	return fmt.Sprintf("\nThis ceremony is spent: a completion consumes its nonce before it verifies the proof, so it is not retried.\n"+
		"Mint a fresh code where the last one was displayed, then:\n"+
		"  dfos keys prove <code> --key %s\n"+
		"The key is still held here — that re-presents this same key rather than minting another.", cand.PublicKey)
}

// --- the command ---

type proveResult struct {
	Audience string `json:"audience"`
	Ceremony string `json:"ceremony"`
	Endpoint string `json:"endpoint"`
	Carriage string `json:"carriage"`
	Purpose  string `json:"purpose"`

	PublicKey string `json:"publicKey"`
	Account   string `json:"account"`
	KeyOrigin string `json:"keyOrigin"`
	Vault     string `json:"vault,omitempty"`
	Backend   string `json:"keystoreBackend"`

	Linkage linkageReport `json:"linkage"`
	Forced  bool          `json:"forcedLinked,omitempty"`

	Status string `json:"status"`
	KeyID  string `json:"keyId,omitempty"`
	DID    string `json:"did,omitempty"`
}

func newKeysProveCmd() *cobra.Command {
	var vaultName string
	var noVault bool
	var keySelector string
	var assumeYes bool
	var forceLinked bool

	cmd := &cobra.Command{
		Use:   "prove <code-or-uri>",
		Short: "Prove a key to a key-add ceremony (KEY-PROOF)",
		Long: "Complete a key-add ceremony an operator started: resolve the carriage it displayed, sign a " +
			"KEY-PROOF envelope with the candidate key itself, and post it to the ceremony's completion " +
			"endpoint. The argument is either the short code an operator shows — '<authority>/<CODE>' — or " +
			"the full carriage URI a QR code carries.\n\n" +
			"By default it MINTS the key it proves, from the default vault or --vault: the candidate is a new " +
			"self-held key being added to an identity someone else custodies the chain for. --key proves a key " +
			"this machine already holds.\n\n" +
			"Before signing it shows the audience and the purpose and asks — audience binding only defends a " +
			"human who saw the authority — and it refuses a key any identity has ever declared, because the " +
			"relay index's key lookup is has-ever-declared and one key in two chains is a permanent public " +
			"link between them. A completion is never retried: a ceremony that fails verification is spent.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeysProve(cmd, args[0], proveOptions{
				vaultFlag:   vaultName,
				noVault:     noVault,
				keySelector: keySelector,
				assumeYes:   assumeYes,
				forceLinked: forceLinked,
			})
		},
	}
	cmd.Flags().StringVar(&keySelector, "key", "", "Prove a key this machine already holds (key id, public key, or account)")
	cmd.Flags().StringVar(&vaultName, "vault", "", "Vault the new key is minted from (default: config default-vault)")
	cmd.Flags().BoolVar(&noVault, "no-vault", false, "Mint the new key straight into the keystore, from no seed")
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "Skip the confirmation — the audience has already been checked by a human")
	cmd.Flags().BoolVar(&forceLinked, "force-linked", false,
		"Sign even when an identity already declares this key, or when the check could not run")
	return cmd
}

type proveOptions struct {
	vaultFlag   string
	noVault     bool
	keySelector string
	assumeYes   bool
	forceLinked bool
}

func runKeysProve(cmd *cobra.Command, input string, opts proveOptions) error {
	if opts.keySelector != "" && (opts.vaultFlag != "" || opts.noVault) {
		return fmt.Errorf("--key names a key this machine already holds; --vault and --no-vault choose where a NEW one is minted from")
	}

	// 1. The carriage, first: an unresolvable code costs no key material.
	car, err := resolveCeremony(input)
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
	linkage := checkKeyLinkage(cand.PublicKey)
	switch {
	case len(linkage.Declaring) > 0 && !opts.forceLinked:
		return fmt.Errorf("REFUSING: %s already declares %s (%s said so, and the key is held here as %s).\n%s",
			strings.Join(linkage.Declaring, ", "), cand.PublicKey, linkage.Oracle, cand.Account, linkageExplanation())
	case !linkage.Checked && !opts.forceLinked:
		return fmt.Errorf("the one-key-one-DID check could not run, so no proof was signed.\n"+
			"  Needed: a relay serving GET /index/v0/identities?key= — the has-ever-declared lookup\n"+
			"  Got:    %s\n"+
			"This is NOT 'no identity declares this key'. Point --relay at a relay that serves the identity\n"+
			"index, or pass --force-linked to sign without the check having run.", linkage.Limit)
	}

	result := &proveResult{
		Audience: car.Audience, Ceremony: car.Ceremony, Endpoint: car.Endpoint, Carriage: car.Via,
		Purpose: protocol.KeyAddJWSTyp, PublicKey: cand.PublicKey, Account: cand.Account,
		KeyOrigin: cand.Origin, Vault: cand.Vault, Backend: keys.Backend(),
		Linkage: linkage, Forced: opts.forceLinked,
	}

	// 4. Display before signing — a MUST, and not suppressible by --quiet.
	printCeremonyDisclosure(result, localLinkage)
	if !opts.assumeYes {
		if err := confirmCeremony(cmd.InOrStdin(), cand); err != nil {
			return err
		}
	}

	// 5. The envelope. The kit derives publicKeyMultibase from the private key
	//    itself — a signer that could name a key it does not hold is the one
	//    construction this artifact exists to foreclose.
	envelope, _, err := protocol.SignKeyProof(protocol.KeyAddJWSTyp, car.Nonce, car.Audience,
		cand.Private, protocol.KeyProofOptions{})
	if err != nil {
		return fmt.Errorf("sign the key proof: %w", err)
	}

	// 6. Completion. One attempt, ever.
	answer, err := completeCeremony(car, envelope)
	if err != nil {
		if errors.Is(err, errCeremonyUnreachable) {
			return fmt.Errorf("%v.\nIf the request arrived, the ceremony is spent even though no answer came back.%s",
				err, burnedCeremonyAdvice(cand))
		}
		return fmt.Errorf("%v.%s", err, burnedCeremonyAdvice(cand))
	}
	result.Status, result.KeyID, result.DID = answer.Status, answer.KeyID, answer.DID

	// 7. File the key where the identity that adopted it will name it, when the
	//    operator said which identity that is.
	//
	//    Only a CANDIDATE account is renamed. A key already filed under some
	//    other account is filed there because something else named it, and
	//    moving it on an operator's say-so would take that key away from whatever
	//    was using it.
	if account, ok := adoptedAccount(answer); ok && strings.HasPrefix(cand.Account, candidateAccountPrefix) &&
		!keys.HasKey(account) {
		if err := keys.RenameKey(cand.Account, account); err == nil {
			result.Account = account
			if cand.Minted && cand.Vault != "" {
				_ = getVaults().Record(cand.Vault, vault.MintedKey{
					Index: cand.VaultIndex, DID: answer.DID, KeyID: answer.KeyID,
					Role: "auth", PublicKey: cand.PublicKey,
				})
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

// adoptedAccount is the keystore account for a completion that named its
// identity. Both members are validated before they name anything local: an
// account is `<did>#<keyId>`, and a key id carrying '#' would file a key under a
// name that means a different key.
func adoptedAccount(answer *completionAnswer) (string, bool) {
	if !strings.HasPrefix(answer.DID, "did:dfos:") || !keyIDShape.MatchString(answer.KeyID) {
		return "", false
	}
	return answer.DID + "#" + answer.KeyID, true
}

// printCeremonyDisclosure is KEY-PROOF.md's Holder Obligation made visible: the
// audience and the purpose, before anything is signed. It goes to stderr, so
// --json emits one document on stdout and the human still sees what they are
// consenting to.
func printCeremonyDisclosure(r *proveResult, localLinkage error) {
	out := os.Stderr
	fmt.Fprintf(out, "Ceremony:\n")
	fmt.Fprintf(out, "  Audience:  %s\n", r.Audience)
	fmt.Fprintf(out, "  Purpose:   add this key to an identity at %s (%s)\n", r.Audience, r.Purpose)
	fmt.Fprintf(out, "  Carriage:  %s\n", r.Carriage)
	fmt.Fprintf(out, "  Key:       %s\n", r.PublicKey)
	fmt.Fprintf(out, "  Origin:    %s\n", r.KeyOrigin)
	fmt.Fprintf(out, "  Keystore:  %s\n", r.Backend)
	switch {
	case len(r.Linkage.Declaring) > 0:
		fmt.Fprintf(out, "  Linkage:   ! %s already declares this key (%s)\n",
			strings.Join(r.Linkage.Declaring, ", "), r.Linkage.Oracle)
	case r.Linkage.Checked:
		fmt.Fprintf(out, "  Linkage:   no identity has ever declared this key — %s answered\n", r.Linkage.Oracle)
	default:
		fmt.Fprintf(out, "  Linkage:   ! NOT CHECKED — %s\n", firstLine(r.Linkage.Limit))
	}
	if localLinkage != nil {
		fmt.Fprintf(out, "  Local:     ! %s\n", firstLine(localLinkage.Error()))
	}
	fmt.Fprintf(out, "\nThis signs a proof that you hold this key and consent to THIS ceremony at THIS host.\n")
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
		return fmt.Errorf("nothing was signed: a ceremony is confirmed by a human who has seen the audience above.\n"+
			"Re-run with --yes once it is the host you meant. The candidate key is held as %s", cand.Account)
	}
	fmt.Fprintf(os.Stderr, "\nComplete this ceremony? [y/N]: ")
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

func printProveResult(r *proveResult) {
	fmt.Printf("\nCompleted:\n")
	fmt.Printf("  Audience:  %s\n", r.Audience)
	fmt.Printf("  Ceremony:  %s\n", r.Ceremony)
	fmt.Printf("  Key:       %s\n", r.PublicKey)
	if r.KeyID != "" {
		fmt.Printf("  Key id:    %s\n", r.KeyID)
	}
	if r.DID != "" {
		fmt.Printf("  Identity:  %s\n", r.DID)
	}
	fmt.Printf("  Account:   %s (%s)\n", r.Account, r.Backend)
	fmt.Println()
	if r.DID == "" {
		fmt.Printf("%s did not name the identity that adopted the key, so it is held here as a candidate.\n", r.Audience)
		fmt.Printf("'dfos keys list' shows it; 'dfos keys prune' never removes it. Once a chain declares it,\n")
		if r.Vault != "" {
			fmt.Printf("'dfos recover --vault %s' files it under that identity.\n", r.Vault)
		} else {
			fmt.Printf("'dfos identity fetch <did>' brings that chain here.\n")
		}
		return
	}
	fmt.Printf("The key is filed under %s. Signing resolves the identity and uses the key this device holds.\n", r.DID)
}

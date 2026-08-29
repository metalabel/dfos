package cmd

// `dfos api call` — resolve one operation out of a cached OpenAPI document,
// sign whatever artifact that operation's security requirements name, send it,
// and print what came back.
//
// The document decides what to ATTEMPT. The host's verdict decides what is
// ACCEPTED, and this command never argues with it: a 401 is printed with the
// challenge and a suggested fix, and NOTHING is retried with escalated auth. An
// automatic retry would turn "the document was wrong" into a second signature
// over the same coordinates, which is exactly the behavior a proof-of-possession
// design exists to make unnecessary.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/apispec"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

// loopbackHosts are the only authorities a proof may be signed for over plain
// http. `api:` surfaces are HTTPS surfaces, and a proof sent in the clear
// replays for its whole freshness window. An EXACT set, never a suffix test.
var loopbackHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "[::1]": true}

type apiCallFlags struct {
	params         []string
	data           string
	dataFile       string
	profile        string
	anon           bool
	includeHeaders bool
	server         string
	trustServers   bool
}

func newAPICallCmd() *cobra.Command {
	f := &apiCallFlags{}

	cmd := &cobra.Command{
		Use:   "call <api> <operationId | METHOD path>",
		Short: "Call one operation of a registered API",
		Long: `Call one operation of a registered API.

Name the operation by its operationId, or by method and path template:

  dfos api call dfos profile.getOwnProfile
  dfos api call dfos GET /spaces/{space} --param space=nce

Path and query parameters ride --param; a JSON body rides --data or --data-file.

The request goes to the ORIGIN THE DOCUMENT CAME FROM. A document's 'servers'
entry contributes a path prefix, never an authority: an entry naming some other
origin is ignored and said out loud, because a document that could redirect the
wire would let whoever serves it aim this client anywhere. --trust-servers sends
the request where the document says; --server <url> names a base outright.

The authentication profile is READ FROM THE DOCUMENT — anonymous, an identity
proof, or a request proof with the credential it binds — from the combination of
security schemes the operation requires. --profile forces one instead. A 401 is
reported with the host's challenge and a suggested fix; nothing is retried under
stronger auth.`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAPICall(f, args)
		},
	}

	cmd.Flags().StringArrayVar(&f.params, "param", nil, "Path or query parameter as name=value (repeatable)")
	cmd.Flags().StringVar(&f.data, "data", "", "Request body (a JSON string)")
	cmd.Flags().StringVar(&f.dataFile, "data-file", "", "Request body from a file (use - for stdin)")
	cmd.Flags().StringVar(&f.profile, "profile", "", "Force an auth profile: anon, identity, or delegated")
	cmd.Flags().BoolVar(&f.anon, "anon", false, "Force the anonymous profile (same as --profile anon)")
	cmd.Flags().BoolVarP(&f.includeHeaders, "include", "i", false, "Print the response status and headers to stderr")
	cmd.Flags().StringVar(&f.server, "server", "", "Base URL to call, overriding both the document's servers and the fetch origin")
	cmd.Flags().BoolVar(&f.trustServers, "trust-servers", false,
		"Let the document's servers entry name the authority, even off the origin it was served from")
	return cmd
}

func runAPICall(f *apiCallFlags, args []string) error {
	name := args[0]
	registration, doc, err := loadAPI(name)
	if err != nil {
		return err
	}

	operation, err := resolveOperation(doc, args[1:])
	if err != nil {
		return err
	}

	params, err := parseKeyValues(f.params, "--param")
	if err != nil {
		return err
	}
	body, err := readCallBody(f)
	if err != nil {
		return err
	}

	// WHERE IT GOES is decided before WHAT IT CARRIES, and the disclosure is
	// printed before the request leaves: a note about an authority the operator
	// did not choose is worth nothing after the bytes are on the wire.
	choice, err := operation.ResolveServer(apispec.ServerPolicy{
		FetchOrigin:  registration.Origin,
		Override:     f.server,
		TrustServers: f.trustServers,
	})
	if err != nil {
		return err
	}
	if choice.Note != "" {
		fmt.Fprintln(os.Stderr, choice.Note)
	}
	request, err := operation.BuildRequest(choice.Base, params, body)
	if err != nil {
		return err
	}

	profile, err := chooseProfile(f, operation, request.Authority)
	if err != nil {
		return err
	}

	headers := map[string]string{}
	if len(body) > 0 {
		mediaType := operation.BodyMediaType()
		if mediaType == "" {
			mediaType = "application/json"
		}
		headers["Content-Type"] = mediaType
	}
	if err := signAPIRequest(profile, request, headers); err != nil {
		return err
	}

	status, respHeaders, respBody, err := sendAPIRequest(request, headers)
	if err != nil {
		return err
	}

	if f.includeHeaders {
		fmt.Fprintf(os.Stderr, "HTTP %d\n", status)
		for _, key := range sortedHeaderNames(respHeaders) {
			for _, value := range respHeaders.Values(key) {
				fmt.Fprintf(os.Stderr, "%s: %s\n", key, value)
			}
		}
		fmt.Fprintln(os.Stderr)
	}

	if status < 200 || status > 299 {
		return apiCallFailure(status, respHeaders, respBody, operation, profile, request)
	}
	announceProfile(operation, profile)
	printResponseBody(respHeaders, respBody)
	return nil
}

// announceProfile echoes which claim actually went out, and whether the document
// or the operator chose it.
//
// A failure already names the profile — every 401 and 403 prints it — so the
// only case where the claim was invisible was the SUCCESS, which is exactly the
// case worth seeing: a route the operator believed anonymous that quietly signed
// an identity proof, or a delegated call that spent a grant they forgot they
// held. It is the same disclosure as the signing-principal line and obeys the
// same --quiet, and it goes to stderr so stdout stays one document.
func announceProfile(operation *apispec.Operation, profile *callProfile) {
	if quietFlag {
		return
	}
	chose := "as the document advertises"
	if profile.forced {
		chose = "forced with --profile"
	}
	detail := ""
	if profile.profile == apispec.ProfileDelegated && profile.actions != nil {
		detail = " (" + apispec.DescribeActions(profile.actions) + ")"
	}
	fmt.Fprintf(os.Stderr, "%s → %s%s, %s\n", operation.Label(), profile.profile, detail, chose)
}

// resolveOperation reads the operation argument in either spelling: one token is
// an operationId, two tokens are a method and a path template.
func resolveOperation(doc *apispec.Doc, args []string) (*apispec.Operation, error) {
	if len(args) == 2 {
		return doc.FindRoute(args[0], args[1])
	}
	operation, err := doc.FindOperation(args[0])
	if err == nil {
		return operation, nil
	}
	// A single argument that looks like a bare method is almost always a
	// forgotten path; say so rather than reporting a missing operationId.
	if isHTTPMethod(args[0]) {
		return nil, fmt.Errorf("%q is an HTTP method, not an operationId — name the path too: 'dfos api call <api> %s /some/path'", args[0], strings.ToUpper(args[0]))
	}
	return nil, err
}

func isHTTPMethod(s string) bool {
	switch strings.ToUpper(s) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	}
	return false
}

func readCallBody(f *apiCallFlags) ([]byte, error) {
	if f.data != "" && f.dataFile != "" {
		return nil, fmt.Errorf("pass --data or --data-file, not both")
	}
	if f.data != "" {
		return []byte(f.data), nil
	}
	if f.dataFile == "" {
		return nil, nil
	}
	if f.dataFile == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read the request body from stdin: %w", err)
		}
		return data, nil
	}
	data, err := os.ReadFile(f.dataFile)
	if err != nil {
		return nil, fmt.Errorf("read the request body: %w", err)
	}
	return data, nil
}

// callProfile is the resolved decision plus the material it needs.
type callProfile struct {
	profile apispec.Profile
	// forced records that the caller overrode the document's advertisement.
	forced bool
	// kid and priv sign the proof. Empty for the anonymous profile.
	kid  string
	priv ed25519.PrivateKey
	// credential is the JWS to carry in X-Credential, and cid the CID its proof
	// binds. Both empty when no credential rides along.
	credential string
	cid        string
	// actions is what the operation requires, kept for the 403 explanation.
	actions [][]string
	// granted is what the selected credential covers on this host.
	granted map[string]bool
}

// chooseProfile decides which claim to make and gathers the material to make it.
//
// An explicit --profile / --anon overrides the document outright. API-AUTH is
// explicit that this is legitimate: "the document ranks as a default, not a
// constraint", and a client override — forcing a profile, or going anonymous —
// is always allowed.
func chooseProfile(f *apiCallFlags, operation *apispec.Operation, authority string) (*callProfile, error) {
	actions, err := operation.RequiredActions()
	if err != nil {
		return nil, err
	}

	if f.anon && f.profile != "" {
		return nil, fmt.Errorf("pass --anon or --profile, not both")
	}
	forced := f.profile
	if f.anon {
		forced = "anon"
	}
	if forced != "" {
		wanted, err := apispec.ParseProfile(forced)
		if err != nil {
			return nil, err
		}
		return gatherProfile(wanted, wanted == apispec.ProfileDelegated, authority, actions, true)
	}

	ranked := apispec.Rank(operation.Alternatives())
	if len(ranked) == 0 {
		return nil, fmt.Errorf("%s advertises no security requirement this client can satisfy:\n  %s\nForce one with --profile <anon|identity|delegated>",
			operation.Label(), strings.Join(unsatisfiableReasons(operation.Alternatives()), "\n  "))
	}

	var firstErr error
	for _, alternative := range ranked {
		chosen, err := gatherProfile(alternative.Profile, alternative.Credential, authority, actions, false)
		if err == nil {
			return chosen, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

func unsatisfiableReasons(alts []apispec.Alternative) []string {
	var reasons []string
	for _, a := range alts {
		if a.Unsatisfiable != "" {
			reasons = append(reasons, a.Unsatisfiable)
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "no requirement object was readable")
	}
	return reasons
}

// gatherProfile collects the key material and credential one profile needs.
func gatherProfile(profile apispec.Profile, withCredential bool, authority string,
	actions [][]string, forced bool) (*callProfile, error) {

	chosen := &callProfile{profile: profile, forced: forced, actions: actions}

	switch profile {
	case apispec.ProfileAnonymous:
		return chosen, nil

	case apispec.ProfileIdentity:
		_, chain, err := requireIdentity()
		if err != nil {
			return nil, err
		}
		kid, err := selectHeldKey(chain.DID, chain.State.AuthKeys, "auth")
		if err != nil {
			return nil, err
		}
		priv, err := keys.GetPrivateKey(kid)
		if err != nil {
			return nil, err
		}
		chosen.kid, chosen.priv = kid, priv
		if withCredential {
			credential, err := selectCredentialForHost(authority)
			if err != nil {
				return nil, err
			}
			chosen.credential, chosen.cid, chosen.granted = credential.token, credential.cid, credential.granted
		}
		return chosen, nil

	case apispec.ProfileDelegated:
		credential, err := selectCredentialForHost(authority)
		if err != nil {
			return nil, err
		}
		priv, err := keys.GetPrivateKey(loginClientAccount(credential.record.ClientKeyID))
		if err != nil {
			return nil, fmt.Errorf("the login client key for %s is not in the %s keystore: %w — 'dfos login' mints a new one (the authorize host will ask you to consent again)",
				credential.record.ClientDID, keys.Backend(), err)
		}
		// The kid's DID portion MUST equal the credential's aud — that equality
		// IS the possession being proven, so it is asserted here rather than
		// discovered as a 401.
		chosen.kid = credential.record.ClientDID + "#" + credential.record.ClientKeyID
		chosen.priv = priv
		chosen.credential, chosen.cid, chosen.granted = credential.token, credential.cid, credential.granted
		announceCredential(credential)
		return chosen, nil
	}
	return nil, fmt.Errorf("unknown profile %q", profile)
}

// spendableCredential is a stored credential read for one host.
type spendableCredential struct {
	record   storedLoginCredential
	token    string
	cid      string
	audience string
	resource string
	granted  map[string]bool
	expiry   int64
}

// selectCredentialForHost picks the stored credential spendable against host.
//
// The host is NOT the credential's audience — the audience is this
// installation's client DID, the party the grant was issued to. The host lives
// in the attenuation, as the `api:<host>` resource string, so that is what is
// matched. When the resolved identity names a subject, its credential wins;
// otherwise exactly one candidate is required, because guessing which grant to
// spend is the one thing a credential client must never do.
func selectCredentialForHost(host string) (*spendableCredential, error) {
	resource := "api:" + host
	items, err := listStoredCredentials(time.Now())
	if err != nil {
		return nil, err
	}

	var candidates []*spendableCredential
	var expired []*spendableCredential
	for _, item := range items {
		// Read back by the file the item CAME FROM. The store holds one file per
		// (subject, host), so re-deriving a path from the subject alone would read
		// one host's credential while scanning another's.
		record, err := readStoredCredential(item.path())
		if err != nil {
			continue
		}
		candidate := readSpendable(record, resource)
		if candidate == nil {
			continue
		}
		if candidate.expiry > 0 && time.Now().Unix() >= candidate.expiry {
			expired = append(expired, candidate)
			continue
		}
		candidates = append(candidates, candidate)
	}

	if len(candidates) == 0 {
		if len(expired) > 0 {
			return nil, fmt.Errorf("the stored credential for %s expired at %s — sign in again with 'dfos login --host %s --as %s'",
				resource, time.Unix(expired[0].expiry, 0).UTC().Format("2006-01-02 15:04:05 UTC"), host, expired[0].record.SubjectDID)
		}
		return nil, fmt.Errorf("no stored credential covers %s — sign in against that host with 'dfos login --host %s --as <name|did>', which offers the actions that host advertises ('dfos creds list' shows what is stored)",
			resource, host)
	}

	ctx, _ := resolveCtx()
	if ctx != nil && ctx.IdentityDID != "" {
		for _, candidate := range candidates {
			if candidate.record.SubjectDID == ctx.IdentityDID {
				return candidate, nil
			}
		}
		return nil, fmt.Errorf("no stored credential for %s covers %s (%d other credential(s) do) — sign in as that identity with 'dfos login --host %s --as %s', or name one that is stored with --as",
			ctx.Principal(), resource, len(candidates), host, ctx.Principal())
	}
	if len(candidates) > 1 {
		subjects := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			subjects = append(subjects, candidate.record.SubjectDID)
		}
		sort.Strings(subjects)
		return nil, fmt.Errorf("%d stored credentials cover %s — name which one with --as <name|did>:\n  %s",
			len(candidates), resource, strings.Join(subjects, "\n  "))
	}
	return candidates[0], nil
}

// readSpendable decodes one stored credential and reports what it grants on
// resource, or nil when it grants nothing there.
//
// Action tokens are copied out VERBATIM. This client never enumerates a
// registry, never validates a token against one, and never interprets what a
// token means — it compares strings the document wrote against strings the
// credential wrote, and prints both back unchanged.
func readSpendable(record storedLoginCredential, resource string) *spendableCredential {
	header, payload, err := protocol.DecodeJWSUnsafe(strings.TrimSpace(record.Credential))
	if err != nil {
		return nil
	}
	audience, _ := payload["aud"].(string)
	if audience != record.ClientDID {
		// Under the delegated profile nothing here could present it: the proof
		// MUST be signed by the audience's key, and this installation holds only
		// its login client's. The store holds only SIWD login credentials, which
		// are always audienced that way, so this filter costs nothing on the
		// authn/authz split — where the credential is not bound to the proof.
		return nil
	}
	granted := map[string]bool{}
	covers := false
	for _, entry := range protocol.ParseAtt(payload) {
		if entry.Resource != resource {
			continue
		}
		covers = true
		for token := range protocol.ParseActions(entry.Action) {
			granted[token] = true
		}
	}
	if !covers {
		return nil
	}
	spendable := &spendableCredential{
		record:   record,
		token:    strings.TrimSpace(record.Credential),
		cid:      header.CID,
		audience: audience,
		resource: resource,
		granted:  granted,
	}
	if exp, ok := payload["exp"].(int64); ok {
		spendable.expiry = exp
	}
	return spendable
}

// announceCredential is the delegated profile's twin of announceSigner. The
// proof is signed by this installation's client key, not by the resolved
// identity, so naming the resolved identity would be a lie about who is acting.
func announceCredential(c *spendableCredential) {
	if quietFlag {
		return
	}
	fmt.Fprintf(os.Stderr, "Presenting the credential issued for %s to %s — signing the request proof with its audience key\n",
		c.record.SubjectDID, c.audience)
}

// signAPIRequest attaches the artifact the chosen profile names.
func signAPIRequest(profile *callProfile, request *apispec.Request, headers map[string]string) error {
	if profile.profile == apispec.ProfileAnonymous {
		return nil
	}
	parsed, err := url.Parse(request.URL)
	if err != nil {
		return fmt.Errorf("parse %s: %w", request.URL, err)
	}
	if parsed.Scheme != "https" && !loopbackHosts[parsed.Hostname()] {
		return fmt.Errorf("refusing to sign a %s:// request to %s: api: surfaces are HTTPS surfaces, and a proof sent in the clear replays for its whole freshness window (plaintext is allowed only to localhost, 127.0.0.1, and [::1])",
			parsed.Scheme, parsed.Host)
	}
	if profile.cid == "" && profile.profile == apispec.ProfileDelegated {
		return fmt.Errorf("the stored credential carries no cid header — a request proof has nothing to bind to")
	}

	opts := protocol.RequestProofOptions{Body: request.Body}
	// A jti rides on every write-shaped request. Read-shaped routes ignore an
	// unknown member, so attaching one is never wrong — and a deployment gating
	// writes MUST have it (API-AUTH.md, Security Considerations).
	if !isSafeMethod(request.Method) {
		id, err := newRequestJTI()
		if err != nil {
			return err
		}
		opts.ExtraMembers = protocol.ProofExtraMembers{"jti": id}
	}

	var proof string
	if profile.profile == apispec.ProfileDelegated {
		proof, err = protocol.BuildRequestProof(request.Method, request.Authority, request.Target,
			profile.cid, profile.kid, profile.priv, opts)
	} else {
		proof, err = protocol.BuildIdentityProof(request.Method, request.Authority, request.Target,
			profile.kid, profile.priv, opts)
	}
	if err != nil {
		return fmt.Errorf("sign the %s proof: %w", profile.profile, err)
	}
	headers["Authorization"] = "DFOS " + proof
	if profile.credential != "" {
		headers["X-Credential"] = profile.credential
	}
	return nil
}

func isSafeMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// newRequestJTI returns a fresh per-request uniqueness member: 128 bits from
// crypto/rand.
func newRequestJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// sendAPIRequest performs the call. Redirects are NOT followed: a redirect
// re-issues the request at coordinates the proof does not cover, and would carry
// X-Credential to whatever authority the Location names.
func sendAPIRequest(request *apispec.Request, headers map[string]string) (int, http.Header, []byte, error) {
	var reader io.Reader
	if len(request.Body) > 0 {
		reader = bytes.NewReader(request.Body)
	}
	req, err := http.NewRequest(request.Method, request.URL, reader)
	if err != nil {
		return 0, nil, nil, err
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	client := &http.Client{
		Timeout:       60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, resp.Header, nil, err
	}
	return resp.StatusCode, resp.Header, body, nil
}

// apiCallFailure renders a non-2xx.
//
// The tiers are kept distinguishable because API-AUTH makes them mean different
// things: 401 is a PROOF-layer refusal (the artifact was wrong, missing, or
// stale), 403 is a CREDENTIAL-layer refusal (the grant did not cover the route),
// and 503 is "could not check", the server's condition and not the caller's.
func apiCallFailure(status int, headers http.Header, body []byte,
	operation *apispec.Operation, profile *callProfile, request *apispec.Request) error {

	detail := strings.TrimSpace(string(body))
	if detail == "" {
		detail = http.StatusText(status)
	}

	switch status {
	case http.StatusUnauthorized:
		var b strings.Builder
		fmt.Fprintf(&b, "HTTP 401 from %s %s — the proof layer refused this request (profile: %s)",
			request.Method, request.URL, profile.profile)
		if challenge := headers.Get("WWW-Authenticate"); challenge != "" {
			fmt.Fprintf(&b, "\n  challenge: %s", challenge)
		}
		fmt.Fprintf(&b, "\n  host says: %s", detail)
		switch {
		case profile.profile == apispec.ProfileAnonymous && profile.forced:
			fmt.Fprintf(&b, "\n  You forced the anonymous profile; the host requires an artifact. Drop --anon to sign what the document advertises, or name a profile with --profile.")
		case profile.profile == apispec.ProfileAnonymous:
			fmt.Fprintf(&b, "\n  The document calls this route anonymous; the host does not. Try --profile identity or --profile delegated.")
		default:
			fmt.Fprintf(&b, "\n  A 401 under a signed profile is a proof the host would not take — a rotated-out key, a clock skew, or the wrong envelope for this route. Nothing was retried under stronger auth.")
		}
		return fmt.Errorf("%s", b.String())

	case http.StatusForbidden:
		var b strings.Builder
		fmt.Fprintf(&b, "HTTP 403 from %s %s — the credential layer refused this request",
			request.Method, request.URL)
		fmt.Fprintf(&b, "\n  host says: %s", detail)
		fmt.Fprintf(&b, "\n  %s requires: %s", operation.Label(), apispec.DescribeActions(profile.actions))
		fmt.Fprintf(&b, "\n  the presented credential grants on api:%s: %s", request.Authority, describeGranted(profile.granted))
		fmt.Fprintf(&b, "\n  Action tokens are the host's vocabulary, not this client's — obtain a grant carrying what the route requires:")
		fmt.Fprintf(&b, "\n  'dfos login --host %s' lists what that host advertises and asks which of it to request.", request.Authority)
		return fmt.Errorf("%s", b.String())

	case http.StatusServiceUnavailable:
		return fmt.Errorf("HTTP 503 from %s %s — the host could not complete the check (an unresolvable presenter or an unreachable revocation source). This is the host's condition, not a verdict on the request.\n  host says: %s",
			request.Method, request.URL, detail)
	}
	return fmt.Errorf("HTTP %d from %s %s\n  %s", status, request.Method, request.URL, detail)
}

func describeGranted(granted map[string]bool) string {
	if len(granted) == 0 {
		return "nothing"
	}
	tokens := make([]string, 0, len(granted))
	for token := range granted {
		tokens = append(tokens, token)
	}
	sort.Strings(tokens)
	return strings.Join(tokens, ", ")
}

// printResponseBody writes the response to stdout — pretty-printed when it is
// JSON, byte-for-byte otherwise. stdout carries the response DOCUMENT and
// nothing else, which is why the staleness line, the signer announcement, and
// --include all go to stderr.
func printResponseBody(headers http.Header, body []byte) {
	if strings.Contains(headers.Get("Content-Type"), "json") {
		var parsed any
		if json.Unmarshal(body, &parsed) == nil {
			pretty, _ := json.MarshalIndent(parsed, "", "  ")
			fmt.Println(string(pretty))
			return
		}
	}
	os.Stdout.Write(body)
	if len(body) > 0 && body[len(body)-1] != '\n' {
		fmt.Println()
	}
}

func sortedHeaderNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

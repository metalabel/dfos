package cmd

// LOGIN — Sign In With DFOS under the loopback credential tier.
//
// The flow is specs/SIWD.md profile A driven from a machine that holds no
// domain: discover the subject's authorize endpoint from the subject's OWN
// chain, ask with a client identity whose key control is proven at ask-time,
// receive the signed challenge on a loopback listener, and verify it here.
//
// Two properties are worth naming because they are what keep this file honest:
//
//   - THE CLI IS ITS OWN VERIFIER. There is no token endpoint to call home to,
//     so the replay expectation lives in this process — SIWD.md §Replay
//     prevention calls it "consumed verification with a store of size one" —
//     and every gate the host would apply to a subject's artifact is applied
//     here too, against a chain re-verified from its operation log rather than
//     against any relay's projection of it.
//   - IT IS PROTOCOL-PURE. No platform hostname appears anywhere below, no
//     scope string is parsed or enumerated, and the success display decodes the
//     returned artifact locally instead of asking anyone what it means.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

const (
	// The bare loopback host is the challenge's domain: SIWD.md pins it to the
	// host without the port, because a local application cannot reserve one, and
	// the authorize host compares that value literally against the redirect's
	// host. 127.0.0.1 rather than "localhost" throughout — the literal is what
	// both halves compare, and a name that resolves is one more thing to disagree
	// about.
	loopbackHost = "127.0.0.1"

	// The DfosAuthorizationServer service type answers "which authorize endpoint
	// speaks for this DID" (SIWD.md §Finding the authorize endpoint). Like
	// DfosOrigin it is an extension the core carries verbatim and never
	// structurally validates, so its rules live in consumers like this one.
	authorizationServerType = "DfosAuthorizationServer"

	// Where the per-install client identity is persisted, relative to ConfigDir().
	loginClientFileName = "login-client.json"

	// The keystore account prefix for the login client's key. Reserved: user
	// identity keys are stored as "<did>#<keyId>" (or transiently "pending:<id>"),
	// so a "login-client__" account can never name a user identity's key, and the
	// login client's DID never appears in the config's identity table.
	loginClientAccountPrefix = "login-client__"

	// Whole-second UTC, the only timestamp spelling the challenge schema admits.
	loginTimestampLayout = "2006-01-02T15:04:05.000Z"
)

// loginClient is the per-install client identity of SIWD.md §Loopback Clients:
// one Ed25519 key and a one-operation genesis chain small enough to carry on the
// authorize request itself. It is deliberately NOT a user identity — it lives
// outside the config's identity table, because what it represents is this
// installation of the CLI, not a person.
//
// It is also deliberately STABLE across logins. A client that re-minted would
// arrive as a different DID every time, so every run would ask the user to
// consent again and every credential an earlier run earned would belong to an
// identity nothing will ever present again.
type loginClient struct {
	DID   string   `json:"did"`
	KeyID string   `json:"keyId"`
	Chain []string `json:"chain"`
}

// storedLoginCredential is what lands in ConfigDir()/credentials/<did>.json. The
// client DID and key id ride along with the artifact because a credential is
// audience-bound and inert without that key: recording which identity it was
// issued to is what lets a later run know whether it can present this at all.
type storedLoginCredential struct {
	SubjectDID  string `json:"subjectDid"`
	ClientDID   string `json:"clientDid"`
	ClientKeyID string `json:"clientKeyId"`
	Credential  string `json:"credential"`
	ObtainedAt  string `json:"obtainedAt"`
}

func newLoginCmd() *cobra.Command {
	var scope string
	var allScopes bool
	var hostFlag string
	var authorizeURLFlag string
	var noBrowser bool
	var timeoutFlag string

	cmd := &cobra.Command{
		Use:     "login [name|did]",
		Short:   "Sign in to an identity's authorize host and store the credential it returns",
		GroupID: "auth",
		Long: "Run the Sign In With DFOS loopback flow for an identity: discover its authorize endpoint from " +
			"its own chain's DfosAuthorizationServer entry, open the consent screen in a browser, and verify the " +
			"signed challenge that comes back on a local listener. This machine asks under the loopback credential " +
			"tier — a per-install client identity whose key control is proven at ask-time — so a scope that returns " +
			"a credential has something to be issued to. Credentials land in the credentials/ directory beside the " +
			"config file — ~/.dfos/credentials/ by default, and beside DFOS_CONFIG wherever that points — and nothing is " +
			"stored unless the signature verifies against a current authentication key of the signer's chain.\n\n" +
			"--host names the API the credential is for, by registered name or by host. Its OpenAPI document's " +
			"action catalog is read and presented, and what you select becomes the scope — asked for verbatim, " +
			"since action tokens are the host's vocabulary and never this client's. An explicit --scope is used as " +
			"typed instead; --all-scopes takes the whole catalog without asking.\n\n" +
			"Key control is all this proves about the asking software: its origin and authorship are unverifiable " +
			"from the host's side, which is why a credential minted here carries a hard expiry ceiling.\n\n" +
			"Normative spec: https://protocol.dfos.com/siwd",
		Args: cobra.MaximumNArgs(1),
		// A human clicks through a consent screen in the middle of this command,
		// so it can legitimately run for minutes. Holding the process-wide state
		// lock for that long would block every other `dfos` invocation on the
		// machine, and login needs none of what the lock protects: it never
		// rewrites config.toml, and the files it does write (the login client and
		// the credential store) are its own.
		Annotations: map[string]string{annNoStateLock: "true"},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Scope is an OPAQUE passthrough. It is not parsed, enumerated, or
			// checked against any registry here: which scopes exist is the
			// authorize host's business, and a CLI that validated them would go
			// stale the moment the host registered one more. --host changes only
			// where the string is CHOSEN — the tokens are still copied verbatim.
			//
			// TYPED, not merely non-default: a flag's default is this client's
			// guess, and only the ask may be overridden by an instruction. Reading
			// Changed rather than the value is what separates the two.
			explicitScope := ""
			if cmd.Flags().Changed("scope") {
				if strings.TrimSpace(scope) == "" {
					return fmt.Errorf("--scope must be non-empty (it is passed through to the authorize host verbatim)")
				}
				explicitScope = scope
			}
			if allScopes && explicitScope != "" {
				return fmt.Errorf("pass --scope or --all-scopes, not both — an explicit scope is not a subset to be widened")
			}
			if allScopes && hostFlag == "" {
				return fmt.Errorf("--all-scopes needs --host <name-or-host>: the catalog it takes is an API document's, and no API is named")
			}
			timeout, err := time.ParseDuration(timeoutFlag)
			if err != nil {
				return fmt.Errorf("invalid --timeout %q: %w (use Go duration units like 90s, 5m)", timeoutFlag, err)
			}
			if timeout <= 0 {
				return fmt.Errorf("--timeout must be positive, got %q", timeoutFlag)
			}

			ctx, peer, err := requirePeer("", false)
			if err != nil {
				return err
			}

			// A positional argument names the subject outright; otherwise the
			// subject is whatever the resolution stack produced, and that gets
			// announced before the flow starts — signing in is signing.
			subjectDID := ctx.IdentityDID
			if len(args) > 0 {
				subjectDID, err = resolveIdentityDID(args[0])
				if err != nil {
					return err
				}
			} else {
				announceSigner(ctx)
			}
			if subjectDID == "" {
				return errNoIdentity()
			}

			authorizeURL, err := resolveAuthorizeURL(peer, subjectDID, authorizeURLFlag)
			if err != nil {
				return err
			}

			// The scope is settled BEFORE the challenge is minted and the browser
			// opens: a person choosing what to grant should be doing it in the
			// terminal, not while a consent screen waits on the other side of a
			// listener with a timeout running.
			var target *loginTarget
			if hostFlag != "" {
				interactive := stdinIsInteractive()
				target, err = resolveLoginTarget(hostFlag, cmd.InOrStdin(), os.Stderr, interactive)
				if err != nil {
					return err
				}
				scope, err = resolveLoginScope(target, explicitScope, allScopes, cmd.InOrStdin(), os.Stderr, interactive)
				if err != nil {
					return err
				}
			}

			lc, clientPriv, err := ensureLoginClient()
			if err != nil {
				return err
			}

			listener, err := startLoginListener()
			if err != nil {
				return err
			}
			defer listener.close()
			redirectURI := fmt.Sprintf("http://%s:%d/callback", loopbackHost, listener.port)

			nonce, err := loginNonce()
			if err != nil {
				return err
			}
			challenge := protocol.SiwdChallenge{
				Domain:    loopbackHost,
				Nonce:     nonce,
				Timestamp: time.Now().UTC().Truncate(time.Second).Format(loginTimestampLayout),
				// Bind the challenge to ONE subject: sign in as this DID or not at
				// all. Binding without verifying the binding would prove nothing,
				// so the signer is checked against it below.
				DID: &subjectDID,
			}
			authRequest, encodedChallenge, err := buildAuthorizeURL(authorizeURL, challenge, redirectURI, scope, lc, clientPriv)
			if err != nil {
				return err
			}
			// The store of size one, minted here alongside the challenge it holds
			// and consumed as the LAST gate below.
			expect := &challengeExpectation{encoded: encodedChallenge}

			// Progress goes to stderr so --json keeps stdout to one document.
			fmt.Fprintf(os.Stderr, "Sign in as %s\n\n  %s\n\n", subjectDID, authRequest)
			if !noBrowser {
				if err := openBrowser(authRequest); err != nil {
					fmt.Fprintf(os.Stderr, "Could not open a browser (%v) — open the URL above yourself.\n", err)
				}
			}
			fmt.Fprintf(os.Stderr, "Waiting for the callback on %s (timeout %s)...\n", redirectURI, timeout)

			callback, err := awaitLoginCallback(listener.urls, timeout, os.Stderr)
			if err != nil {
				return err
			}
			listener.close()

			signerDID, keyID, segment, err := signerFromLoginJWS(callback.JWS, callback.DID)
			if err != nil {
				return err
			}
			if err := assertSignerBinding(signerDID, subjectDID); err != nil {
				return err
			}

			// Re-resolve the signer's chain NOW rather than reusing the copy
			// discovery fetched: authentication resolves against current state, and
			// a key rotated out while the user was at the consent screen must not
			// verify against the state this run started with.
			signer, err := fetchVerifiedIdentity(peer, signerDID)
			if err != nil {
				return err
			}
			if err := verifyLoginSignature(callback.JWS, keyID, signer.State); err != nil {
				return err
			}

			// CONSUMED LAST, per SIWD.md §Replay prevention: everything above has
			// passed, so nothing invalid can spend the expectation, and this is the
			// final gate before a sign-in is granted.
			if err := expect.consume(segment); err != nil {
				return err
			}

			credentialPath := ""
			if callback.Credential != "" {
				if err := assertCredentialForClient(callback.Credential, lc.DID); err != nil {
					return fmt.Errorf("signed in as %s — the sign-in itself verified — but refusing to store what came back: %w",
						signerDID, err)
				}
				targetHost := ""
				if target != nil {
					targetHost = target.Authority
				}
				credentialPath, err = storeLoginCredential(subjectDID, lc, callback.Credential, targetHost)
				if err != nil {
					return fmt.Errorf("signed in as %s — the sign-in itself verified — but %w", signerDID, err)
				}
			}

			// Said once, on the artifact that was actually stored: the credential
			// is found by its `api:<host>` attenuation, so one naming another host
			// is one `api call` will never select for this one.
			if callback.Credential != "" {
				warnCredentialHostMismatch(callback.Credential, target, os.Stderr)
			}

			if jsonFlag {
				out := map[string]any{"did": signerDID, "clientDid": lc.DID, "scope": scope}
				if target != nil {
					out["host"] = target.Authority
					out["resource"] = target.Resource()
				}
				if callback.Credential != "" {
					out["credentialPath"] = credentialPath
					out["credential"] = callback.Credential
				}
				outputJSON(out)
				return nil
			}

			fmt.Printf("Signed in:\n")
			fmt.Printf("  DID:            %s\n", signerDID)
			if name := config.FindIdentityName(cfg, signerDID); name != "" {
				fmt.Printf("  Name:           %s\n", name)
			}
			fmt.Printf("  Signing key:    %s\n", keyID)
			fmt.Printf("  Client DID:     %s\n", lc.DID)
			fmt.Printf("  Authorize host: %s\n", authorizeURL)
			if target != nil {
				fmt.Printf("  For API:        %s\n", target.Resource())
			}
			fmt.Printf("  Scope:          %s\n", scope)
			if callback.Credential == "" {
				fmt.Printf("  Credential:     none returned for this scope — identity verified, nothing stored\n")
				return nil
			}
			fmt.Printf("  Credential:     %s\n", credentialPath)
			summary, err := summarizeCredential(callback.Credential)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: stored the credential but could not decode it for display: %v\n", err)
				return nil
			}
			fmt.Printf("    Issuer:       %s\n", summary.Issuer)
			fmt.Printf("    Audience:     %s\n", summary.Audience)
			for _, entry := range summary.Att {
				fmt.Printf("    Grants:       %s on %s\n", entry.Action, entry.Resource)
			}
			fmt.Printf("    Expires:      %s\n", summary.expiryText())
			return nil
		},
	}

	cmd.Flags().StringVar(&scope, "scope", "identity", "Scope to request, passed to the authorize host verbatim (space-separated for several)")
	cmd.Flags().StringVar(&hostFlag, "host", "", "API the credential is for — a registered name or a host — whose advertised actions are offered")
	cmd.Flags().BoolVar(&allScopes, "all-scopes", false, "With --host, ask for every action the document advertises without prompting")
	cmd.Flags().StringVar(&authorizeURLFlag, "authorize-url", "", "Authorize endpoint to use when the identity's chain names none")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Print the URL and wait without attempting to open a browser")
	cmd.Flags().StringVar(&timeoutFlag, "timeout", "5m", "How long to wait for the callback (e.g. 90s, 5m)")
	return cmd
}

// ---------------------------------------------------------------------------
// discovery
// ---------------------------------------------------------------------------

// parseAuthorizeURL is the shared URL mechanic behind both ways this command
// learns where to send the user. Both paths run through it so they cannot drift
// into two different ideas of what a usable endpoint is — the drift that let a
// string-concatenated "/authorize" land after an endpoint's query string and
// produce a URL nobody named.
func parseAuthorizeURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("%q is not an absolute http(s) URL", raw)
	}
	return parsed, nil
}

// withAuthorizePath appends this profile's /authorize surface to a base URL
// through the PARSED path. Never by concatenation: concatenation appends after
// whatever the string already ends with — a query, a fragment — instead of to
// the path, and the result is a request the far end has no route for.
func withAuthorizePath(base *url.URL) string {
	joined := *base
	joined.Path = strings.TrimRight(joined.Path, "/") + "/authorize"
	joined.RawPath = ""
	return joined.String()
}

// authorizeEndpoint folds a services set into the one authorize endpoint it
// names, or into the reason it names none.
//
// SIWD.md's rule is ONE ENTRY, OR NONE: a set carrying more than one
// DfosAuthorizationServer entry names no discoverable endpoint, and a consumer
// MUST fall back exactly as if the entry were absent — the same ambiguity rule
// DfosOrigin follows, chosen so that ambiguity degrades to the fallback and
// never to a choice.
//
// An endpoint that is missing, empty, not an absolute http(s) URL, or not a
// bare ORIGIN url is ignored the same way. The last of those is the entry's own
// definition doing the work: the spec calls the member the "canonical authorize
// origin URL", so a value carrying a query, a fragment, or userinfo is not one,
// and the choices left are to silently drop the parts that cannot be honored or
// to treat the value as naming nothing. Dropping them would send the user
// somewhere the identity never published, so it names nothing.
func authorizeEndpoint(services []protocol.ServiceEntry) (endpoint string, reason string) {
	var endpoints []string
	for _, entry := range services {
		if typ, _ := entry["type"].(string); typ != authorizationServerType {
			continue
		}
		raw, _ := entry["endpoint"].(string)
		endpoints = append(endpoints, raw)
	}

	switch {
	case len(endpoints) == 0:
		return "", "no " + authorizationServerType + " entry in this identity's services"
	case len(endpoints) > 1:
		return "", fmt.Sprintf("%d %s entries — an ambiguous set names no endpoint", len(endpoints), authorizationServerType)
	}

	parsed, err := parseAuthorizeURL(endpoints[0])
	if err != nil {
		return "", fmt.Sprintf("the %s entry's endpoint %s — it names nothing", authorizationServerType, err)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.EscapedFragment() != "" || parsed.User != nil {
		return "", fmt.Sprintf("the %s entry's endpoint %q carries a query, fragment, or userinfo rather than being a bare origin URL — it names nothing",
			authorizationServerType, endpoints[0])
	}
	// The endpoint is the BASE at which the host serves this profile, so the
	// /authorize surface is appended to it — a base path is kept and extended
	// (https://x.example/base → https://x.example/base/authorize).
	return withAuthorizePath(parsed), ""
}

// resolveAuthorizeURL answers SIWD.md's "which authorize endpoint speaks for
// this DID". The chain's own entry wins; --authorize-url is the out-of-band
// fallback the spec provides for when the chain names none, which is legal and
// is still the common case.
func resolveAuthorizeURL(peer *client.Client, subjectDID, fallback string) (string, error) {
	verified, err := fetchVerifiedIdentity(peer, subjectDID)
	if err != nil {
		return "", err
	}
	endpoint, reason := authorizeEndpoint(verified.State.Services)
	if endpoint != "" {
		if fallback != "" {
			fmt.Fprintf(os.Stderr, "Note: %s names an authorize endpoint in its chain; ignoring --authorize-url.\n", subjectDID)
		}
		return endpoint, nil
	}
	if fallback == "" {
		return "", fmt.Errorf("%s names no authorize endpoint: %s — pass --authorize-url <url> to name one out of band",
			subjectDID, reason)
	}
	return normalizeAuthorizeURL(fallback)
}

// normalizeAuthorizeURL accepts either spelling of --authorize-url: a bare
// origin (the "configured host" the spec's fallback describes), which gets the
// /authorize surface appended, or the endpoint itself, which is left alone
// because a user who typed a path meant it.
//
// The bare-origin rule is the only thing this shares with the discovery path's
// treatment of an endpoint. The rest deliberately differs: a chain entry is
// discovery vocabulary governed by the one-entry-or-none rule, while this flag
// is an instruction typed this run, so a query the user wrote into it is
// carried rather than read as naming nothing.
func normalizeAuthorizeURL(raw string) (string, error) {
	parsed, err := parseAuthorizeURL(raw)
	if err != nil {
		return "", fmt.Errorf("invalid --authorize-url: %w", err)
	}
	if strings.TrimRight(parsed.Path, "/") == "" {
		return withAuthorizePath(parsed), nil
	}
	return parsed.String(), nil
}

// fetchVerifiedIdentity resolves a DID to verified current state through the
// peer's operation LOG, never through /identities/{did}. The difference is the
// whole point: a resolved-state document is the relay's word for what the chain
// says, and this value decides where a sign-in is sent and which key may sign
// it. Replaying the log locally makes the relay a transport again.
func fetchVerifiedIdentity(peer *client.Client, did string) (*protocol.VerifiedIdentityResult, error) {
	log, err := peer.GetIdentityLog(did)
	if err != nil {
		return nil, fmt.Errorf("fetch identity log for %s: %w", did, err)
	}
	if len(log) == 0 {
		return nil, fmt.Errorf("the peer holds no identity chain for %s", did)
	}
	verified, err := protocol.VerifyIdentityChain(log)
	if err != nil {
		return nil, fmt.Errorf("verify identity chain for %s: %w", did, err)
	}
	if verified.State.DID != did {
		return nil, fmt.Errorf("the peer served a chain for %s under %s", verified.State.DID, did)
	}
	return verified, nil
}

// ---------------------------------------------------------------------------
// the per-install client identity
// ---------------------------------------------------------------------------

func loginClientPath() string { return filepath.Join(config.ConfigDir(), loginClientFileName) }

func loginClientAccount(keyID string) string { return loginClientAccountPrefix + keyID }

// ensureLoginClient loads the stored client identity, or mints one on first
// login. A stored identity whose key this machine no longer holds is an ERROR
// with a re-mint hint, never a silent re-mint: a new DID is a new party to the
// authorize host, so re-minting behind the user's back would discard every
// consent and every credential the old DID earned without saying so.
func ensureLoginClient() (*loginClient, ed25519.PrivateKey, error) {
	lc, priv, err := loadLoginClient()
	if err != nil {
		return nil, nil, err
	}
	if lc != nil {
		return lc, priv, nil
	}
	return mintLoginClient()
}

func loadLoginClient() (*loginClient, ed25519.PrivateKey, error) {
	path := loginClientPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}

	var lc loginClient
	if err := json.Unmarshal(data, &lc); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w (delete it to mint a new login client identity)", path, err)
	}

	// The stored chain is verified, not trusted: a truncated or edited log must
	// surface here rather than as a client_did the authorize host refuses after
	// a redirect.
	verified, err := protocol.VerifyIdentityChain(lc.Chain)
	if err != nil {
		return nil, nil, fmt.Errorf("verify the login client chain in %s: %w (delete it to mint a new login client identity)", path, err)
	}
	if verified.State.DID != lc.DID {
		return nil, nil, fmt.Errorf("%s records %s but its chain derives %s", path, lc.DID, verified.State.DID)
	}
	if verified.State.IsDeleted {
		return nil, nil, fmt.Errorf("the login client identity %s is deleted — delete %s to mint a new one", lc.DID, path)
	}

	// CURRENCY, the same rule the authorize host applies to the ask proof: a
	// rotated-out key refuses to restore here, with the reason in hand, rather
	// than signing a proof the far end will reject.
	var authKey *protocol.MultikeyPublicKey
	for i := range verified.State.AuthKeys {
		if verified.State.AuthKeys[i].ID == lc.KeyID {
			authKey = &verified.State.AuthKeys[i]
			break
		}
	}
	if authKey == nil {
		return nil, nil, fmt.Errorf("key %s is not a current authentication key of the login client identity %s — delete %s to mint a new one",
			lc.KeyID, lc.DID, path)
	}

	priv, err := keys.GetPrivateKey(loginClientAccount(lc.KeyID))
	if err != nil {
		return nil, nil, fmt.Errorf("the login client key for %s is not in the %s keystore: %w — delete %s to mint a new login client identity (the authorize host will ask you to consent again)",
			lc.DID, keys.Backend(), err, path)
	}
	published, err := protocol.DecodeMultikey(authKey.PublicKeyMultibase)
	if err != nil {
		return nil, nil, fmt.Errorf("decode the login client's published key: %w", err)
	}
	if !priv.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(published)) {
		return nil, nil, fmt.Errorf("the stored login client key does not match the key %s publishes — delete %s to mint a new login client identity", lc.DID, path)
	}
	return &lc, priv, nil
}

// mintLoginClient generates the one keypair and one genesis operation that make
// up a loopback client identity: a DID it can prove control of, and a
// one-operation chain small enough to carry on the request itself.
func mintLoginClient() (*loginClient, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate login client key: %w", err)
	}
	// Derived from the key, like every other key id this CLI publishes. The
	// account keeps the login-client prefix: this key is infrastructure named by
	// login-client.json, a file this CLI owns, so its address is already
	// reconstructible without a chain to read it out of.
	keyID := protocol.DeriveKeyID(protocol.EncodeMultikey(pub))
	if _, err := keys.PutKey(loginClientAccount(keyID), priv); err != nil {
		return nil, nil, fmt.Errorf("store login client key: %w", err)
	}
	key := protocol.NewMultikeyPublicKey(keyID, pub)

	// One key in all three roles. This identity signs nothing but ask proofs and
	// presents nothing but itself, so a separate controller key would be a second
	// secret to keep with no second thing to authorize.
	jwsToken, did, _, err := protocol.SignIdentityCreate(
		[]protocol.MultikeyPublicKey{key},
		[]protocol.MultikeyPublicKey{key},
		[]protocol.MultikeyPublicKey{key},
		keyID, priv,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("sign login client genesis: %w", err)
	}
	// Verified before it is persisted: a DID this machine will present for the
	// life of the install is worth deriving twice.
	verified, err := protocol.VerifyIdentityChain([]string{jwsToken})
	if err != nil {
		return nil, nil, fmt.Errorf("the minted login client chain does not verify: %w", err)
	}
	if verified.State.DID != did {
		return nil, nil, fmt.Errorf("the minted login client chain derives %s, not %s", verified.State.DID, did)
	}

	lc := &loginClient{DID: did, KeyID: keyID, Chain: []string{jwsToken}}
	data, err := json.MarshalIndent(lc, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(config.ConfigDir(), 0o700); err != nil {
		return nil, nil, fmt.Errorf("create config dir: %w", err)
	}

	// WRITE, THEN CLAIM THE NAME. Login deliberately does not take the
	// process-wide state lock, so two first logins can race here, and the file
	// must never be visible under its real name until it is complete — an O_EXCL
	// create publishes an EMPTY file and fills it afterwards, which is exactly
	// the window where a racing reader finds an unparseable client record.
	//
	// os.Link is the claim: it fails with EEXIST rather than replacing, so it
	// keeps the first-writer-wins semantics the race needs, unlike rename. The
	// loser drops its key and adopts the winner's identity — the outcome a lock
	// would have produced anyway — and the winner's file is complete by
	// construction.
	dir := config.ConfigDir()
	temp, err := os.CreateTemp(dir, "."+loginClientFileName+".*")
	if err != nil {
		return nil, nil, fmt.Errorf("create a temp file in %s: %w", dir, err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return nil, nil, fmt.Errorf("set permissions on %s: %w", tempPath, err)
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		temp.Close()
		return nil, nil, fmt.Errorf("write %s: %w", tempPath, err)
	}
	if err := temp.Close(); err != nil {
		return nil, nil, fmt.Errorf("close %s: %w", tempPath, err)
	}

	path := loginClientPath()
	if err := os.Link(tempPath, path); err != nil {
		if !os.IsExist(err) {
			return nil, nil, fmt.Errorf("write %s: %w", path, err)
		}
		keys.DeleteKey(loginClientAccount(keyID))
		existing, existingPriv, loadErr := loadLoginClient()
		if loadErr != nil {
			return nil, nil, loadErr
		}
		if existing == nil {
			return nil, nil, fmt.Errorf("%s appeared and vanished while minting a login client identity", path)
		}
		return existing, existingPriv, nil
	}
	return lc, priv, nil
}

// ---------------------------------------------------------------------------
// the authorize request
// ---------------------------------------------------------------------------

// loginNonce mints the replay value: 32 bytes of system randomness folded into
// the protocol's own identifier alphabet, so a nonce reads like every other
// DFOS id and carries the same entropy floor.
func loginNonce() (string, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return "", fmt.Errorf("generate challenge nonce: %w", err)
	}
	return protocol.DeriveID(seed), nil
}

// encodeClientChain is the carriage encoding of SIWD.md §Chain residence: the
// full ordered operation log, genesis first, as base64url of its JSON array —
// the same grammar as the challenge param, so one decoder shape serves both. The
// 100-operation cap is spec-normative; a client identity anywhere near it has
// outgrown carriage and belongs on a relay.
func encodeClientChain(log []string) (string, error) {
	if len(log) == 0 {
		return "", fmt.Errorf("the login client chain is empty — carriage needs the full log")
	}
	if len(log) > siwdCarriageCap {
		return "", fmt.Errorf("the login client chain has %d operations; the SIWD carriage cap is %d", len(log), siwdCarriageCap)
	}
	data, err := json.Marshal(log)
	if err != nil {
		return "", err
	}
	return protocol.Base64urlEncode(data), nil
}

// buildAuthorizeURL assembles the loopback authorize request: SIWD.md §1's wire
// params plus the two the loopback credential tier adds. It returns the URL and
// the base64url challenge embedded in it — the value the callback's JWS payload
// segment must equal byte for byte.
//
// The ask proof and the challenge param are derived from the SAME challenge
// value, which is what keeps them from drifting: they must cover identical
// bytes, and deriving them from two inputs is exactly how they would silently
// stop matching.
func buildAuthorizeURL(authorizeURL string, challenge protocol.SiwdChallenge, redirectURI, scope string,
	lc *loginClient, priv ed25519.PrivateKey) (request string, encodedChallenge string, err error) {
	signingInput, err := protocol.SiwdSigningInput(challenge)
	if err != nil {
		return "", "", err
	}
	encodedChallenge = protocol.Base64urlEncode(signingInput)

	proof, err := protocol.SignSiwdAskProof(challenge, lc.DID+"#"+lc.KeyID, priv)
	if err != nil {
		return "", "", err
	}
	carriage, err := encodeClientChain(lc.Chain)
	if err != nil {
		return "", "", err
	}

	parsed, err := url.Parse(authorizeURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid authorize URL %q: %w", authorizeURL, err)
	}
	// Params are set on the endpoint's OWN query so anything it already carries
	// survives instead of being clobbered by concatenation.
	query := parsed.Query()
	query.Set("challenge", encodedChallenge)
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", scope)
	query.Set("client_did", lc.DID)
	query.Set("client_proof", proof)
	query.Set("client_chain", carriage)
	parsed.RawQuery = query.Encode()
	return parsed.String(), encodedChallenge, nil
}

// openBrowser hands the URL to the desktop's own handler. Failure is never
// fatal — the URL has already been printed, so a machine with no browser (a
// container, an SSH session) falls back to the --no-browser behavior on its own.
func openBrowser(rawURL string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", rawURL).Start()
	case "linux":
		return exec.Command("xdg-open", rawURL).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start()
	}
	return fmt.Errorf("no known browser opener for %s", runtime.GOOS)
}

// ---------------------------------------------------------------------------
// the loopback listener — the fragment relay
// ---------------------------------------------------------------------------

// loginRelayPage is what GET /callback answers with, and it exists because a
// browser never sends a URL fragment to a server. The credential rides the
// fragment (SIWD.md §4), so the request line this listener sees carries the
// query and nothing else; the page's script reads location.href in the browser
// and posts the WHOLE url back, which is the only path by which the fragment
// reaches the process that minted the challenge.
//
// No external assets, by construction: this page is served by a CLI on a local
// port, and a network fetch to render it would be one more thing to fail while
// the user waits.
const loginRelayPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dfos login</title>
<style>
  body { font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  main { max-width: 32rem; padding: 2rem; }
  h1 { font-size: 1.25rem; margin: 0 0 .5rem; }
  p { margin: 0; opacity: .7; }
</style>
</head>
<body>
<main>
  <h1 id="status">Finishing sign-in&hellip;</h1>
  <p id="detail">Returning the result to the dfos CLI.</p>
</main>
<script>
  fetch("/collect", { method: "POST", body: location.href })
    .then(function (response) {
      if (!response.ok) { throw new Error("HTTP " + response.status); }
      // Scrub immediately. The signed challenge is in the query and the
      // credential is in the fragment, so until this runs both sit in the
      // address bar and in this browser's history, on a page the user is about
      // to leave open. Wrapped because a failure to tidy the URL must not be
      // reported as a failure to deliver it.
      try { history.replaceState(null, "", "/callback"); } catch (e) {}
      document.getElementById("status").textContent = "Signed in — you can close this tab.";
      document.getElementById("detail").textContent = "";
    })
    .catch(function () {
      document.getElementById("status").textContent = "Could not reach the dfos CLI.";
      document.getElementById("detail").textContent = "It may have stopped waiting. Return to the terminal and try again.";
    });
</script>
</body>
</html>
`

const (
	// maxCollectBody bounds what POST /collect will read. Sized for the artifact
	// rather than the request line: a delegation-chain credential rides the
	// fragment and is legitimately large, and the earlier, tighter cap would have
	// silently truncated one into a corrupt token that stored fine and could
	// never be spent. Over-cap bodies are now refused outright instead.
	maxCollectBody = 1 << 20

	// collectBuffer is the depth of the delivery queue. Non-blocking sends mean a
	// full queue drops rather than wedging a handler goroutine, so the depth is
	// only there to keep a burst of junk POSTs from displacing the real callback
	// in the window before the waiting command reads.
	collectBuffer = 4
)

type loginListener struct {
	server *http.Server
	urls   chan string
	port   int
	closed bool
}

// newLoginMux wires the two routes the relay needs. Split out from the listener
// so the handlers are testable without binding a port.
//
// expectedHost is the literal loopback authority this listener was reached at,
// and every request must carry it. That gate is what closes DNS REBINDING: a
// port on 127.0.0.1 is reachable from any page the user's browser happens to
// load, and an attacker who rebinds a hostname they control to 127.0.0.1 can
// have that page talk to this listener — but its requests carry the attacker's
// hostname in Host, never the literal authority the redirect_uri named. Host is
// attacker-controlled in general; here it is exactly the thing that distinguishes
// the flow this process started from every other origin in the browser.
func newLoginMux(urls chan string, expectedHost string) *http.ServeMux {
	guard := func(w http.ResponseWriter, r *http.Request, method string) bool {
		if r.Method != method {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return false
		}
		if r.Host != expectedHost {
			http.Error(w, "forbidden", http.StatusForbidden)
			return false
		}
		return true
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if !guard(w, r, http.MethodGet) {
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, loginRelayPage)
	})
	mux.HandleFunc("/collect", func(w http.ResponseWriter, r *http.Request) {
		if !guard(w, r, http.MethodPost) {
			return
		}
		// One byte past the cap, so an over-cap body is DETECTED rather than
		// quietly cut to length. A truncated callback URL parses fine and yields a
		// credential that is bytes, not a credential.
		body, err := io.ReadAll(io.LimitReader(r.Body, maxCollectBody+1))
		if err != nil {
			http.Error(w, "could not read the callback URL", http.StatusBadRequest)
			return
		}
		if len(body) > maxCollectBody {
			http.Error(w, "callback URL exceeds the size limit", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		// Delivered AFTER the response is written so the waiting command can shut
		// the listener down the moment it reads, without cutting the page off
		// mid-answer. The send is non-blocking: a burst of POSTs must not wedge
		// handler goroutines.
		select {
		case urls <- string(body):
		default:
		}
	})
	return mux
}

func startLoginListener() (*loginListener, error) {
	// Port 0: the OS picks a free one. A local application cannot reserve a port,
	// which is why the challenge's domain is the bare host and the exact
	// redirect_uri — port included — is what the host redirects to.
	socket, err := net.Listen("tcp", loopbackHost+":0")
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", loopbackHost, err)
	}
	port := socket.Addr().(*net.TCPAddr).Port
	urls := make(chan string, collectBuffer)
	listener := &loginListener{
		server: &http.Server{
			Handler:           newLoginMux(urls, loopbackHost+":"+strconv.Itoa(port)),
			ReadHeaderTimeout: 10 * time.Second,
		},
		urls: urls,
		port: port,
	}
	go listener.server.Serve(socket)
	return listener, nil
}

// close is idempotent: the command shuts the listener down as soon as it has
// collected, and defers a second call for every path that never gets there.
func (l *loginListener) close() {
	if l == nil || l.closed {
		return
	}
	l.closed = true
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	l.server.Shutdown(ctx)
}

// ---------------------------------------------------------------------------
// the callback
// ---------------------------------------------------------------------------

// loginCallback is what came back on the redirect. Nothing in it is trusted:
// DID is unauthenticated courier convenience, and the DID to act on is the one
// the signature resolves to.
type loginCallback struct {
	JWS        string
	DID        string
	Credential string
}

// errNotACallback marks a collected body that is not a SIWD callback at all — a
// probe, a stray fetch from another page, a truncated paste. It is the one parse
// verdict the waiting loop treats as noise rather than as the end of the flow:
// anyone can POST to a loopback port, and letting a stranger's garbage cancel a
// sign-in the user is halfway through would make that a denial-of-service.
//
// A well-formed callback that says no — a denial, a half-callback — is NOT this.
// That is the host's answer, and it ends the flow.
var errNotACallback = errors.New("not a SIWD callback")

// parseLoginCallback splits a collected callback URL into its query verdict and
// its fragment payload.
//
// THE QUERY HALF'S VERDICT WINS. A credential in the fragment is lifted only
// onto a success, never on its own — a fragment arriving with no signed
// challenge is noise, not a sign-in.
//
// A HALF-CALLBACK IS A FAILURE, NOT A NON-EVENT: jws without did (or the
// reverse) is reported, because silence would strand the user with no account
// of why the attempt vanished.
func parseLoginCallback(raw string) (loginCallback, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return loginCallback{}, fmt.Errorf("%w: unparseable URL: %s", errNotACallback, err)
	}
	query := parsed.Query()
	jws, did := query.Get("jws"), query.Get("did")

	if jws != "" && did != "" {
		// EscapedFragment, not Fragment: the host serializes the fragment with
		// URLSearchParams, so it is parsed with the same grammar, from the same
		// bytes the browser sent rather than from a percent-decoded view of them.
		fragment, _ := url.ParseQuery(parsed.EscapedFragment())
		return loginCallback{JWS: jws, DID: did, Credential: fragment.Get("credential")}, nil
	}
	if denial := query.Get("error"); denial != "" {
		return loginCallback{}, fmt.Errorf("sign-in was declined at the authorize host: %s", denial)
	}
	if jws != "" {
		return loginCallback{}, fmt.Errorf("malformed SIWD callback: missing did")
	}
	if did != "" {
		return loginCallback{}, fmt.Errorf("malformed SIWD callback: missing jws")
	}
	return loginCallback{}, fmt.Errorf("%w: no jws, did, or error parameter", errNotACallback)
}

// awaitLoginCallback waits for the host's answer and refuses to let a stranger
// end the flow.
//
// Anyone on this machine — any page in the user's browser, any other process —
// can POST to a loopback port, so junk arriving on /collect is logged and
// skipped rather than treated as the callback. What bounds that tolerance is
// the DEADLINE, computed once here: skipping garbage buys no extra time, so a
// flood delays nothing beyond the timeout the user asked for.
//
// A well-formed callback ends the wait whatever it says. A denial and a
// half-callback are the host's answer, not noise, and retrying past one would
// hang on a flow that is already over.
func awaitLoginCallback(urls <-chan string, timeout time.Duration, warn io.Writer) (loginCallback, error) {
	deadline := time.Now().Add(timeout)
	for {
		var collected string
		select {
		case collected = <-urls:
		case <-time.After(time.Until(deadline)):
			return loginCallback{}, fmt.Errorf("timed out after %s waiting for the sign-in callback", timeout)
		}
		callback, err := parseLoginCallback(collected)
		if err == nil {
			return callback, nil
		}
		if !errors.Is(err, errNotACallback) {
			return loginCallback{}, err
		}
		fmt.Fprintf(warn, "Ignoring a POST to the callback listener that is not a SIWD callback: %v\n", err)
	}
}

// challengeExpectation is this verifier's entire replay store. SIWD.md §Replay
// prevention names the shape for a loopback client: consumed verification with a
// store of size one — the expectation lives in the process that minted it, held
// in memory and discarded after one comparison.
//
// CONSUMED LAST, and the position IS the semantics. The spec makes consumption
// the final verification step, after the signature, key currency, and every
// binding check have passed, so that an invalid presentation can never spend an
// expectation its legitimate holder is still carrying — and so the spend is the
// last thing that happens before a sign-in is granted.
//
// Spent pass or fail. Nothing invalid reaches this by construction, so the only
// wrong answer that can arrive is one that cleared every other gate; a store of
// size one that survived it would admit a second presentation, which is the
// thing being prevented.
type challengeExpectation struct {
	encoded string
	spent   bool
}

func (e *challengeExpectation) consume(segment string) error {
	if e.spent {
		return fmt.Errorf("this run's SIWD challenge was already presented — refusing a second presentation")
	}
	defer func() { e.spent = true }()
	if segment != e.encoded {
		return fmt.Errorf("the callback does not carry this run's challenge")
	}
	return nil
}

// signerFromLoginJWS applies the gates that need nothing but the artifact: the
// typ gate, the kid split, and the courier check. It returns the DID and key id
// the artifact CLAIMS — claims that mean nothing until verifyLoginSignature
// checks them against the signer's own verified chain — along with the payload
// SEGMENT, which is handed back rather than compared here so that the
// expectation is consumed as the last gate rather than the first.
//
// The segment is what the caller compares, not a re-parse of the challenge:
// comparing re-serialized objects would accept a non-canonical spelling of the
// right values, and the bytes are what was signed.
func signerFromLoginJWS(jws, courierDID string) (did, keyID, segment string, err error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid SIWD callback: jws is not a three-part compact JWS")
	}
	header, _, err := protocol.DecodeJWSUnsafe(jws)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid SIWD callback: %w", err)
	}
	// The typ gate is what keeps a client's ask proof — which covers the SAME
	// canonical bytes — from being presented here as a subject's sign-in.
	if header.Typ != protocol.SiwdJWSTyp {
		return "", "", "", fmt.Errorf("invalid SIWD callback: expected typ %s, got %s", protocol.SiwdJWSTyp, header.Typ)
	}
	hashIdx := strings.Index(header.Kid, "#")
	if hashIdx <= 0 || hashIdx == len(header.Kid)-1 {
		return "", "", "", fmt.Errorf("invalid SIWD callback: kid must be a DID URL with both halves non-empty (<did>#<keyId>)")
	}
	did, keyID = header.Kid[:hashIdx], header.Kid[hashIdx+1:]

	if did != courierDID {
		return "", "", "", fmt.Errorf("the callback names %s but %s signed the challenge", courierDID, did)
	}
	return did, keyID, parts[1], nil
}

// assertSignerBinding enforces the challenge's own binding: it named ONE
// subject, so a signature by anyone else is not the sign-in that was asked for.
// Binding a challenge without checking the binding proves nothing — a host that
// ignored the binding would return a signature from whoever happened to be
// logged in, and a client checking only the signature would accept it.
func assertSignerBinding(signerDID, subjectDID string) error {
	if signerDID != subjectDID {
		return fmt.Errorf("the challenge was bound to %s but %s signed it — sign-in refused", subjectDID, signerDID)
	}
	return nil
}

// verifyLoginSignature is the far half: the signature must verify under a
// CURRENT auth key of the signer's verified chain. A rotated-out key and a
// deleted identity both fail here, which is the point — rotation is how a user
// whose key is compromised stops it authenticating in their name, and resolving
// against historical state would remove the only lever there is.
func verifyLoginSignature(jws, keyID string, state protocol.IdentityState) error {
	if state.IsDeleted {
		return fmt.Errorf("identity %s is deleted", state.DID)
	}
	var authKey *protocol.MultikeyPublicKey
	for i := range state.AuthKeys {
		if state.AuthKeys[i].ID == keyID {
			authKey = &state.AuthKeys[i]
			break
		}
	}
	if authKey == nil {
		return fmt.Errorf("key %s is not a current authentication key of %s", keyID, state.DID)
	}
	publicKey, err := protocol.DecodeMultikey(authKey.PublicKeyMultibase)
	if err != nil {
		return fmt.Errorf("decode the signing key published by %s: %w", state.DID, err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%s publishes a %d-byte key for %s, expected %d", state.DID, len(publicKey), keyID, ed25519.PublicKeySize)
	}
	if _, _, err := protocol.VerifyJWS(jws, ed25519.PublicKey(publicKey)); err != nil {
		return fmt.Errorf("SIWD signature verification failed: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// storing and reading back the credential
// ---------------------------------------------------------------------------

// ONE FILE PER (SUBJECT, HOST), NOT PER SUBJECT.
//
// A credential is spent by HOST: `api call` scans the store and selects on the
// `api:<host>` attenuation, which is fully multi-credential aware. The store
// underneath it was not — it was keyed by subject alone, so signing the same
// identity in to a second host overwrote the first host's file, and the calls
// that had worked a minute earlier reported "no stored credential covers
// api:<first>" while the user believed both logins stood.
//
// So the host is part of the name. The filename is a SLOT and nothing reads it
// back: every reader scans the directory and matches on the record's own fields,
// which is what keeps a legacy single-file-per-subject store readable with no
// migration step (it is rewritten into its slot the next time that subject
// stores one — see migrateLegacyCredential).
//
// credentialFileName maps the pair to a filename the way the file keystore maps
// a key account: ':' is legal in a POSIX path but not on Windows, so it is
// replaced rather than relied on.
func credentialFileName(did, host string) string {
	return pathSafeSegment(did) + "__" + pathSafeSegment(credentialSlot(host)) + ".json"
}

// credentialSlot is the slot name for a host: the host itself, or the no-host
// slot when there is none.
func credentialSlot(host string) string {
	if slot := strings.TrimSpace(host); slot != "" {
		return slot
	}
	return noHostCredentialSlot
}

// noHostCredentialSlot files a credential that names no `api:<host>` resource at
// all. Such a credential is not selectable by `api call` under any host, so the
// slot exists only so it cannot displace one that is.
const noHostCredentialSlot = "no-host"

func pathSafeSegment(s string) string { return strings.ReplaceAll(s, ":", "_") }

// assertFilableHost refuses a host that could not honestly be a filename.
//
// THE HOSTS COME FROM THE ISSUER, NOT FROM HERE. A credential's `api:<host>`
// attenuations are written by whoever minted it, and this store turns them into
// path components — so an issuer that returned `api:../../../.ssh/authorized`
// would have named the file this client writes, and `filepath.Join` would have
// carried it out of the credentials directory without complaint. What the
// server says is data; it never gets to be a path.
//
// The rule is the smallest one that says what a slot IS: a bare authority, a
// host with an optional port and nothing else. Anything a path could read as a
// step — a separator, a traversal, whitespace, a userinfo prefix — is not a
// host, and a credential naming one is refused rather than filed somewhere
// unexpected.
func assertFilableHost(host string) error {
	refuse := fmt.Errorf("the credential names the resource %q, whose host is not a bare host[:port] — "+
		"a credential store slot is a filename, and this one is not one", "api:"+host)
	// Nothing but dots is a path step ("." and ".."), never a host, and it is the
	// one authority `url.Parse` hands back unchanged.
	if host == "" || strings.Trim(host, ".") == "" {
		return refuse
	}
	parsed, err := url.Parse("//" + host)
	if err != nil || parsed.Host != host || parsed.User != nil {
		return refuse
	}
	return nil
}

// assertFilableHosts vets every host a credential names, because every one of
// them is a slot this store may file it under. One malformed resource refuses
// the whole credential: a credential that names a path is not one this client
// can account for, and storing the readable half of it would be a partial
// record reported as a whole one.
func assertFilableHosts(hosts []string) error {
	for _, host := range hosts {
		if err := assertFilableHost(host); err != nil {
			return err
		}
	}
	return nil
}

// legacyCredentialFileName is the pre-host spelling — one file per subject. Read
// forever, written never.
func legacyCredentialFileName(did string) string { return pathSafeSegment(did) + ".json" }

func credentialStoreDir() string {
	return filepath.Join(config.ConfigDir(), "credentials")
}

// credentialPath is the one place a (subject, host) pair becomes a path, and it
// is where the pair is proven to be one. The host is vetted as an authority, and
// then the assembled filename is required to be a single local component — a
// second, independent check that catches whatever the first did not, including
// anything a malformed subject DID could contribute. A path that leaves the
// credentials directory is never returned, so nothing downstream has to notice
// that it left.
func credentialPath(did, host string) (string, error) {
	slot := credentialSlot(host)
	if err := assertFilableHost(slot); err != nil {
		return "", err
	}
	name := credentialFileName(did, slot)
	if !filepath.IsLocal(name) {
		return "", fmt.Errorf("the credential store slot for (%s, %s) is not a name inside %s — refusing to write it",
			did, slot, credentialStoreDir())
	}
	return filepath.Join(credentialStoreDir(), name), nil
}

// credentialAPIHosts is every `api:<host>` a credential names, sorted and
// deduplicated. It is the credential's own account of which hosts it can be
// spent against, read the same way `api call` reads it.
func credentialAPIHosts(token string) []string {
	_, payload, err := protocol.DecodeJWSUnsafe(strings.TrimSpace(token))
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var hosts []string
	for _, entry := range protocol.ParseAtt(payload) {
		host, ok := strings.CutPrefix(entry.Resource, "api:")
		if !ok || host == "" || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

// credentialSlotHost picks the slot a credential is filed under: the first host
// its own attenuation names, then the host the login was aimed at, then none.
// hosts is what credentialAPIHosts read from the credential, already vetted as
// filable by the caller.
//
// The credential's word comes first because that is what the spend side matches;
// the login target is the fallback for an artifact whose attenuation says
// nothing this client can read.
func credentialSlotHost(hosts []string, target string) string {
	if len(hosts) > 0 {
		return hosts[0]
	}
	return strings.TrimSpace(target)
}

// credentialFilesForSubject is every stored record whose SubjectDID is this one,
// in filename order. The RECORD decides, not the filename, so a legacy file and
// a slotted one are found the same way.
//
// unreadable is every .json the scan could not open or parse. It is RETURNED
// rather than skipped: a file that will not parse may hold a grant for this
// subject, and nothing here can tell whether it does. A caller that acted on
// records alone would be acting on a partial view of the store, so the partial
// half travels with it and the caller says so.
func credentialFilesForSubject(did string) (paths []string, records []storedLoginCredential, unreadable []string, err error) {
	entries, err := os.ReadDir(credentialStoreDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil, nil
		}
		return nil, nil, nil, fmt.Errorf("read credential store: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(credentialStoreDir(), entry.Name())
		record, err := readStoredCredential(path)
		if err != nil {
			unreadable = append(unreadable, path)
			continue
		}
		if record.SubjectDID != did {
			continue
		}
		paths = append(paths, path)
		records = append(records, record)
	}
	return paths, records, unreadable, nil
}

// credentialJWSTyp is the registered typ of a DFOS credential artifact.
const credentialJWSTyp = "did:dfos:credential"

// assertCredentialForClient refuses a credential this installation could never
// spend. A DFOS credential is audience-bound and inert without the audience's
// key (API-AUTH), so one issued to any DID but this client's is bytes we hold
// and can never present — and storing it under a success line would be a lie
// about what the user now has.
//
// Deliberately NOT gated on `iss`. Who may issue is the resource's business,
// and a space-owned resource legitimately issues from the space's own DID
// rather than from the subject the user signed in as; a check there would
// refuse correct credentials.
func assertCredentialForClient(token, clientDID string) error {
	header, payload, err := protocol.DecodeJWSUnsafe(token)
	if err != nil {
		return fmt.Errorf("the returned credential does not decode: %w", err)
	}
	if header.Typ != credentialJWSTyp {
		return fmt.Errorf("the returned artifact carries typ %q, not %s", header.Typ, credentialJWSTyp)
	}
	audience, _ := payload["aud"].(string)
	if audience != clientDID {
		return fmt.Errorf("the returned credential is issued to %q, not to this installation's client identity %s — nothing here could ever present it",
			audience, clientDID)
	}
	return nil
}

// storeLoginCredential writes one credential into its (subject, host) slot.
// targetHost is the API this login was aimed at, used only when the credential's
// own attenuation names no host.
//
// The hosts are vetted BEFORE anything is written, and the whole credential is
// refused if any of them is not a filable authority — see assertFilableHosts.
func storeLoginCredential(subjectDID string, lc *loginClient, credential, targetHost string) (string, error) {
	hosts := credentialAPIHosts(credential)
	if err := assertFilableHosts(hosts); err != nil {
		return "", fmt.Errorf("refusing to store the credential: %w", err)
	}
	path, err := credentialPath(subjectDID, credentialSlotHost(hosts, targetHost))
	if err != nil {
		return "", fmt.Errorf("refusing to store the credential: %w", err)
	}
	dir := credentialStoreDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	// Before writing, move any pre-host file for this subject into its own slot.
	// Skipping this would leave the old record and the new one both readable and
	// both matching the same host — two candidates naming one subject, which
	// `api call` reports as an ambiguity the user cannot act on.
	if err := migrateLegacyCredential(subjectDID); err != nil {
		return "", err
	}
	if err := rehomeDisplacedCredential(path, hosts); err != nil {
		return "", err
	}
	record := storedLoginCredential{
		SubjectDID:  subjectDID,
		ClientDID:   lc.DID,
		ClientKeyID: lc.KeyID,
		Credential:  credential,
		ObtainedAt:  time.Now().UTC().Truncate(time.Second).Format(loginTimestampLayout),
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", err
	}
	if err := writeFileAtomic(path, append(data, '\n')); err != nil {
		return "", err
	}
	return path, nil
}

// rehomeDisplacedCredential keeps the record already in this slot from taking a
// host down with it.
//
// A slot holds ONE record, and the credential about to take it is filed under
// the FIRST host it names — so an `api:a`+`api:b` credential sits in slot `a`,
// and the next login that returns an `a`-only credential lands on top of it.
// The user is told the login succeeded while the only credential this machine
// held for `b` has just been deleted, and `api call --host b` starts answering
// "no stored credential covers api:b" for a grant they never gave up.
//
// So the incumbent is MOVED rather than overwritten: it is renamed into a slot
// named by one of its own hosts that the incoming credential does not cover.
// Nothing reads a filename back, so the move costs the record nothing — every
// reader still finds it by the hosts it names, all of them, from wherever it
// sits.
//
// A RENAME, NOT A COPY. Same-directory rename is atomic, so the incumbent is in
// exactly one slot at every instant — including the instant after the write that
// follows this one fails, or the process dies between them. Copying first would
// leave the same record in two slots on that path, and every reader that scans
// the store would then report two files naming one host: an ambiguity the user
// cannot act on, produced by a login that did not even succeed.
//
// A host whose slot is already occupied needs no rescue: a file lands in slot X
// because X is one of the hosts ITS record names, so that host still has a
// credential once this write completes. And when every host the incumbent names
// is either covered by the incoming credential or already held elsewhere, there
// is nothing to preserve and the write replaces it.
func rehomeDisplacedCredential(path string, incoming []string) error {
	incumbent, err := readStoredCredential(path)
	if err != nil {
		// An empty slot displaces nothing, and a record that will not parse names
		// no hosts this could preserve.
		return nil
	}
	covered := make(map[string]bool, len(incoming))
	for _, host := range incoming {
		covered[host] = true
	}
	for _, host := range credentialAPIHosts(incumbent.Credential) {
		if covered[host] {
			continue
		}
		// The incumbent's own subject, not the incoming one: they are the same by
		// construction, and a hand-edited store that disagrees is re-filed under
		// the DID its record claims rather than one this call assumed.
		refuge, err := credentialPath(incumbent.SubjectDID, host)
		if err != nil || refuge == path {
			continue
		}
		if _, err := os.Stat(refuge); err == nil {
			continue
		}
		if err := os.Rename(path, refuge); err != nil {
			return fmt.Errorf("move the credential covering %s to %s: %w", host, filepath.Base(refuge), err)
		}
		return nil
	}
	return nil
}

// migrateLegacyCredential rewrites a pre-host `<did>.json` into its slot. Lazy
// by design: a store nobody logs into again is still read correctly, since every
// reader matches records rather than filenames, and the rewrite only has to
// happen before a second file for the same subject could shadow it.
//
// A slot that is already taken is left alone, legacy file and all: the file
// already there was written by this scheme and is the newer record, and
// discarding either of two records the user has is not this function's call.
func migrateLegacyCredential(subjectDID string) error {
	legacy := filepath.Join(credentialStoreDir(), legacyCredentialFileName(subjectDID))
	record, err := readStoredCredential(legacy)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		// Unreadable is not fatal: a login must not be blocked by a record it is
		// about to make redundant.
		return nil
	}
	if record.SubjectDID != subjectDID {
		return nil
	}
	slot, err := credentialPath(subjectDID, credentialSlotHost(credentialAPIHosts(record.Credential), ""))
	if err != nil {
		// A legacy record naming a host that is not filable is left exactly where
		// it is: it is already inside the store under a name this scheme wrote,
		// and a migration is not the place to act on what its issuer said.
		return nil
	}
	if slot == legacy {
		return nil
	}
	if _, err := os.Stat(slot); err == nil {
		return nil
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(slot, append(data, '\n')); err != nil {
		return err
	}
	if err := os.Remove(legacy); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove the superseded credential file %s: %w", legacy, err)
	}
	return nil
}

// writeFileAtomic writes through a temp file in the same directory and renames
// it into place. Two properties, both of which a plain WriteFile lacks: a reader
// (or a crash) never observes a half-written record, since rename is atomic and
// the file is complete before it has the name; and rename REPLACES the target
// rather than opening it, so a symlink someone dropped at the path is discarded
// instead of followed into whatever it points at.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create a temp file in %s: %w", dir, err)
	}
	tempPath := temp.Name()
	// Removed on every failure path; a no-op once the rename has taken the name.
	defer os.Remove(tempPath)

	// Explicit rather than relying on CreateTemp's 0600, because the mode of a
	// file holding a credential is not a detail to inherit from umask.
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("set permissions on %s: %w", tempPath, err)
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write %s: %w", tempPath, err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tempPath, err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// credentialSummary is what the artifact says about itself.
type credentialSummary struct {
	Issuer   string
	Audience string
	Att      []protocol.AttEntry
	Expires  int64
}

func (s credentialSummary) expiryText() string {
	if s.Expires <= 0 {
		return "unknown"
	}
	return time.Unix(s.Expires, 0).UTC().Format("2006-01-02 15:04:05 UTC")
}

// summarizeCredential decodes the artifact LOCALLY. No network call is made to
// display what was just handed to us, and none is needed: the values below are
// the credential's own claims about itself, and what makes them binding is the
// issuer's signature, checked by whoever the credential is spent against.
func summarizeCredential(token string) (credentialSummary, error) {
	_, payload, err := protocol.DecodeJWSUnsafe(token)
	if err != nil {
		return credentialSummary{}, err
	}
	summary := credentialSummary{Att: protocol.ParseAtt(payload)}
	summary.Issuer, _ = payload["iss"].(string)
	summary.Audience, _ = payload["aud"].(string)
	if exp, ok := payload["exp"].(int64); ok {
		summary.Expires = exp
	}
	return summary, nil
}

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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	var authorizeURLFlag string
	var noBrowser bool
	var timeoutFlag string

	cmd := &cobra.Command{
		Use:     "login [identity]",
		Short:   "Sign in to an identity's authorize host and store the credential it returns",
		GroupID: "auth",
		Long: "Run the Sign In With DFOS loopback flow for an identity: discover its authorize endpoint from " +
			"its own chain's DfosAuthorizationServer entry, open the consent screen in a browser, and verify the " +
			"signed challenge that comes back on a local listener. This machine asks under the loopback credential " +
			"tier — a per-install client identity whose key control is proven at ask-time — so a scope that returns " +
			"a credential has something to be issued to. Credentials land in ~/.dfos/credentials/, and nothing is " +
			"stored unless the signature verifies against a current authentication key of the signer's chain.\n\n" +
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
			// stale the moment the host registered one more.
			if scope == "" {
				return fmt.Errorf("--scope must be non-empty (it is passed through to the authorize host verbatim)")
			}
			timeout, err := time.ParseDuration(timeoutFlag)
			if err != nil {
				return fmt.Errorf("invalid --timeout %q: %w (use Go duration units like 90s, 5m)", timeoutFlag, err)
			}
			if timeout <= 0 {
				return fmt.Errorf("--timeout must be positive, got %q", timeoutFlag)
			}

			ctx, peer, err := requirePeer("")
			if err != nil {
				return err
			}

			subjectDID := ctx.IdentityDID
			if len(args) > 0 {
				subjectDID, err = resolveIdentityDID(args[0])
				if err != nil {
					return err
				}
			}
			if subjectDID == "" {
				return fmt.Errorf("no identity to sign in as: pass an identity name or a did:dfos: identifier, " +
					"or set an active context with 'dfos use <identity[@peer]>'")
			}

			authorizeURL, err := resolveAuthorizeURL(peer, subjectDID, authorizeURLFlag)
			if err != nil {
				return err
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

			// Progress goes to stderr so --json keeps stdout to one document.
			fmt.Fprintf(os.Stderr, "Sign in as %s\n\n  %s\n\n", subjectDID, authRequest)
			if !noBrowser {
				if err := openBrowser(authRequest); err != nil {
					fmt.Fprintf(os.Stderr, "Could not open a browser (%v) — open the URL above yourself.\n", err)
				}
			}
			fmt.Fprintf(os.Stderr, "Waiting for the callback on %s (timeout %s)...\n", redirectURI, timeout)

			var collected string
			select {
			case collected = <-listener.urls:
			case <-time.After(timeout):
				return fmt.Errorf("timed out after %s waiting for the sign-in callback", timeout)
			}
			listener.close()

			callback, err := parseLoginCallback(collected)
			if err != nil {
				return err
			}

			// The store of size one. Everything from here to the signature check
			// runs against the expectation this process minted; nothing the
			// callback supplied is allowed to stand in for it.
			expect := &challengeExpectation{encoded: encodedChallenge}
			signerDID, keyID, err := signerFromLoginJWS(callback.JWS, callback.DID, expect)
			if err != nil {
				return err
			}
			if signerDID != subjectDID {
				return fmt.Errorf("the challenge was bound to %s but %s signed it — sign-in refused", subjectDID, signerDID)
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

			credentialPath := ""
			if callback.Credential != "" {
				credentialPath, err = storeLoginCredential(subjectDID, lc, callback.Credential)
				if err != nil {
					return err
				}
			}

			if jsonFlag {
				out := map[string]any{"did": signerDID, "clientDid": lc.DID}
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
	cmd.Flags().StringVar(&authorizeURLFlag, "authorize-url", "", "Authorize endpoint to use when the identity's chain names none")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Print the URL and wait without attempting to open a browser")
	cmd.Flags().StringVar(&timeoutFlag, "timeout", "5m", "How long to wait for the callback (e.g. 90s, 5m)")
	return cmd
}

// ---------------------------------------------------------------------------
// discovery
// ---------------------------------------------------------------------------

// authorizeOrigin folds a services set into the one authorize origin it names,
// or into the reason it names none.
//
// SIWD.md's rule is ONE ENTRY, OR NONE: a set carrying more than one
// DfosAuthorizationServer entry names no discoverable endpoint, and a consumer
// MUST fall back exactly as if the entry were absent — the same ambiguity rule
// DfosOrigin follows, chosen so that ambiguity degrades to the fallback and
// never to a choice. An entry whose endpoint is missing, empty, or not an
// absolute http(s) URL is ignored the same way: it names nothing, and a
// consumer that guessed at it would be inventing the binding.
func authorizeOrigin(services []protocol.ServiceEntry) (origin string, reason string) {
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

	// Trailing slashes are stripped before the path is appended so one endpoint
	// spelling does not become two authorize URLs.
	raw := strings.TrimRight(endpoints[0], "/")
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", fmt.Sprintf("the %s entry's endpoint %q is not an absolute http(s) URL — it names nothing", authorizationServerType, endpoints[0])
	}
	return raw, ""
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
	origin, reason := authorizeOrigin(verified.State.Services)
	if origin != "" {
		if fallback != "" {
			fmt.Fprintf(os.Stderr, "Note: %s names an authorize endpoint in its chain; ignoring --authorize-url.\n", subjectDID)
		}
		return origin + "/authorize", nil
	}
	if fallback == "" {
		return "", fmt.Errorf("%s names no authorize endpoint: %s — pass --authorize-url <url> to name one out of band",
			subjectDID, reason)
	}
	return normalizeAuthorizeURL(fallback)
}

// normalizeAuthorizeURL accepts either spelling of --authorize-url: a bare
// origin (the "configured host" the spec's fallback describes) or the authorize
// endpoint itself. A bare origin gets /authorize appended; anything carrying a
// path is taken as the endpoint and left alone.
func normalizeAuthorizeURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", fmt.Errorf("invalid --authorize-url %q: expected an absolute http(s) URL", raw)
	}
	if parsed.Path == "" {
		parsed.Path = "/authorize"
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
	keyID := protocol.GenerateKeyID()
	priv, pub, err := keys.GenerateKey(loginClientAccount(keyID))
	if err != nil {
		return nil, nil, fmt.Errorf("generate login client key: %w", err)
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

	// O_EXCL, because login deliberately does not take the process-wide state
	// lock: two first logins racing must not leave one of them holding a DID the
	// file no longer names. The loser drops its key and adopts the winner's
	// identity, which is the outcome a lock would have produced anyway.
	path := loginClientPath()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
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
		return nil, nil, fmt.Errorf("write %s: %w", path, err)
	}
	defer file.Close()
	if _, err := file.Write(append(data, '\n')); err != nil {
		return nil, nil, fmt.Errorf("write %s: %w", path, err)
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

// maxCollectBody bounds what POST /collect will read. A callback URL is a few
// kilobytes of JWS; anything past this is not one.
const maxCollectBody = 64 << 10

type loginListener struct {
	server *http.Server
	urls   chan string
	port   int
	closed bool
}

// newLoginMux wires the two routes the relay needs. Split out from the listener
// so the handlers are testable without binding a port.
func newLoginMux(urls chan string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, loginRelayPage)
	})
	mux.HandleFunc("/collect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxCollectBody))
		if err != nil {
			http.Error(w, "could not read the callback URL", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		// Delivered AFTER the response is written so the waiting command can shut
		// the listener down the moment it reads, without cutting the page off
		// mid-answer. The channel is buffered and the send non-blocking: a second
		// POST must not wedge a handler goroutine.
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
	urls := make(chan string, 1)
	listener := &loginListener{
		server: &http.Server{Handler: newLoginMux(urls), ReadHeaderTimeout: 10 * time.Second},
		urls:   urls,
		port:   socket.Addr().(*net.TCPAddr).Port,
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
		return loginCallback{}, fmt.Errorf("malformed SIWD callback URL: %w", err)
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
	return loginCallback{}, fmt.Errorf("malformed SIWD callback: no jws, did, or error parameter")
}

// challengeExpectation is this verifier's entire replay store. SIWD.md §Replay
// prevention names the shape for a loopback client: consumed verification with a
// store of size one — the expectation lives in the process that minted it, held
// in memory and discarded after ONE comparison.
//
// Discarded pass or fail. A store of size one that survived a failed comparison
// would admit a second presentation, which is the thing being prevented.
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

// signerFromLoginJWS applies every gate that can be applied before the network:
// the typ gate, the kid split, the byte-exact challenge comparison, and the
// courier check. It returns the DID and key id the artifact CLAIMS — claims that
// mean nothing until verifyLoginSignature checks them against the signer's own
// verified chain.
func signerFromLoginJWS(jws, courierDID string, expect *challengeExpectation) (did, keyID string, err error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid SIWD callback: jws is not a three-part compact JWS")
	}
	header, _, err := protocol.DecodeJWSUnsafe(jws)
	if err != nil {
		return "", "", fmt.Errorf("invalid SIWD callback: %w", err)
	}
	// The typ gate is what keeps a client's ask proof — which covers the SAME
	// canonical bytes — from being presented here as a subject's sign-in.
	if header.Typ != protocol.SiwdJWSTyp {
		return "", "", fmt.Errorf("invalid SIWD callback: expected typ %s, got %s", protocol.SiwdJWSTyp, header.Typ)
	}
	hashIdx := strings.Index(header.Kid, "#")
	if hashIdx <= 0 || hashIdx == len(header.Kid)-1 {
		return "", "", fmt.Errorf("invalid SIWD callback: kid must be a DID URL with both halves non-empty (<did>#<keyId>)")
	}
	did, keyID = header.Kid[:hashIdx], header.Kid[hashIdx+1:]

	// The payload SEGMENT is compared, not a re-parse of the challenge: comparing
	// re-serialized objects would accept a non-canonical spelling of the right
	// values, and the bytes are what was signed.
	if err := expect.consume(parts[1]); err != nil {
		return "", "", err
	}
	if did != courierDID {
		return "", "", fmt.Errorf("the callback names %s but %s signed the challenge", courierDID, did)
	}
	return did, keyID, nil
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

// credentialFileName maps a DID to a filename the way the file keystore maps a
// key account: ':' is legal in a POSIX path but not on Windows, so it is
// replaced rather than relied on.
func credentialFileName(did string) string {
	return strings.ReplaceAll(did, ":", "_") + ".json"
}

func storeLoginCredential(subjectDID string, lc *loginClient, credential string) (string, error) {
	dir := filepath.Join(config.ConfigDir(), "credentials")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
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
	path := filepath.Join(dir, credentialFileName(subjectDID))
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
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

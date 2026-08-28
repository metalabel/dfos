package cmd

// THE-IDENTITY: the resolution stack, the removal of the mutable pointer, and
// the disclosure that replaces it.
//
// These drive the package globals the root command normally populates, so as
// with the other cmd tests they MUST NOT run with t.Parallel().

import (
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
)

// --- `dfos use` is gone ------------------------------------------------------

func TestUseIsRemovedAndSaysSo(t *testing.T) {
	root := NewRootCmd()
	found, _, err := root.Find([]string{"use"})
	if err != nil {
		t.Fatalf("find use: %v", err)
	}
	if found.Name() != "use" {
		t.Fatalf("use resolved to %q", found.CommandPath())
	}
	if !found.Hidden {
		t.Fatal("the use tombstone must stay hidden — nothing should teach the removed command")
	}

	runErr := found.RunE(found, []string{"alice@prod"})
	if runErr == nil {
		t.Fatal("dfos use must fail")
	}
	msg := runErr.Error()
	for _, want := range []string{"removed", "--as", "DFOS_AS", "dfos config set default-identity"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("use error %q does not mention %q", msg, want)
		}
	}
	if lines := strings.Split(msg, "\n"); len(lines) != 2 {
		t.Fatalf("use error should be two lines, got %d: %q", len(lines), msg)
	}
}

func TestNothingAutoUpdatesTheConfigDefault(t *testing.T) {
	storeA, _, _ := setupDevices(t)

	// Creating the first identity used to select it. It must not: a default
	// that follows "last created" is the mutable pointer under another name.
	createIdentity(t, "alice", storeA)
	if cfg.DefaultIdentity != "" {
		t.Fatalf("identity create set default-identity to %q", cfg.DefaultIdentity)
	}
	if cfg.ActiveContext != "" {
		t.Fatalf("identity create set active_context to %q", cfg.ActiveContext)
	}

	// And a second one does not either.
	createIdentity(t, "bob", storeA)
	if cfg.DefaultIdentity != "" || cfg.ActiveContext != "" {
		t.Fatalf("config default moved on its own: default=%q active=%q", cfg.DefaultIdentity, cfg.ActiveContext)
	}
}

// --- disclosure --------------------------------------------------------------

func TestSigningAnnouncesTheResolvedPrincipal(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createIdentity(t, "alice", storeA)

	identityFlag = ""
	asFlag = "alice"

	signerAnnounced = false
	_, stderr := captureStdio(t, func() {
		if _, _, err := requireIdentity(); err != nil {
			t.Fatalf("requireIdentity: %v", err)
		}
	})
	for _, want := range []string{"Signing as", "alice", did, config.SourceFlagAs} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("announcement %q does not mention %q", stderr, want)
		}
	}
	if lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n"); len(lines) != 1 {
		t.Fatalf("announcement should be one line, got %q", stderr)
	}

	// One line per invocation, however many times the signer is resolved.
	_, stderr = captureStdio(t, func() {
		if _, _, err := requireIdentity(); err != nil {
			t.Fatalf("requireIdentity: %v", err)
		}
	})
	if stderr != "" {
		t.Fatalf("second resolution re-announced: %q", stderr)
	}

	// --quiet silences it.
	signerAnnounced = false
	quietFlag = true
	_, stderr = captureStdio(t, func() {
		if _, _, err := requireIdentity(); err != nil {
			t.Fatalf("requireIdentity: %v", err)
		}
	})
	if stderr != "" {
		t.Fatalf("--quiet still announced: %q", stderr)
	}
}

func TestAnnouncementNamesTheMechanismThatResolved(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	createIdentity(t, "alice", storeA)
	identityFlag = ""

	for _, tc := range []struct {
		name  string
		setup func()
		want  string
	}{
		{"env", func() { t.Setenv(config.SourceEnvAs, "alice") }, config.SourceEnvAs},
		{"config default", func() { cfg.DefaultIdentity = "alice" }, config.SourceDefaultIdentity},
		{"alias flag", func() { identityFlag = "alice" }, config.SourceFlagIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asFlag, identityFlag, cfg.DefaultIdentity = "", "", ""
			t.Setenv(config.SourceEnvAs, "")
			tc.setup()
			signerAnnounced = false
			_, stderr := captureStdio(t, func() {
				if _, _, err := requireIdentity(); err != nil {
					t.Fatalf("requireIdentity: %v", err)
				}
			})
			if !strings.Contains(stderr, tc.want) {
				t.Fatalf("announcement %q does not name %q", stderr, tc.want)
			}
		})
	}
}

func TestAnonymousSigningNamesAllThreeMechanisms(t *testing.T) {
	setupDevices(t)

	_, _, err := requireIdentity()
	if err == nil {
		t.Fatal("signing with nothing resolvable must fail")
	}
	for _, want := range []string{"--as", "DFOS_AS", "dfos config set default-identity"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("anonymous error %q does not mention %q", err, want)
		}
	}

	// --auth on the raw passthrough is a signing site and refuses identically.
	ctx, resolveErr := resolveCtx()
	if resolveErr != nil {
		t.Fatalf("resolveCtx: %v", resolveErr)
	}
	if _, err := resolveIdentityForRelayCall(ctx); err == nil || !strings.Contains(err.Error(), "DFOS_AS") {
		t.Fatalf("relay call --auth anonymous error = %v", err)
	}
}

func TestPublicReadStaysSilentAndAnonymous(t *testing.T) {
	setupRelayCall(t)
	// An identity IS resolvable; an unauthenticated read must still say nothing
	// about it, because nothing about the read is done as that identity.
	cfg.Identities["alice"] = config.IdentityConfig{DID: "did:dfos:alice123"}
	cfg.DefaultIdentity = "alice"
	prevAnnounced := signerAnnounced
	signerAnnounced = false
	defer func() { signerAnnounced = prevAnnounced }()

	_, stderr, err := runThroughRoot(t, newRelayCallCmd(), "call", "GET", "/proof/v1/stats")
	if err != nil {
		t.Fatalf("relay call: %v", err)
	}
	if stderr != "" {
		t.Fatalf("public read chattered about identity: %q", stderr)
	}
}

// --- the config tier ---------------------------------------------------------

func TestConfigSetIsTheOnlyWriterOfTheDefaults(t *testing.T) {
	setupDevices(t)
	cfg.Relays["prod"] = config.RelayConfig{URL: "https://prod.example.com"}

	set := newConfigSetCmd()
	if err := set.RunE(set, []string{"default-identity", "alice"}); err != nil {
		t.Fatalf("set default-identity: %v", err)
	}
	if cfg.DefaultIdentity != "alice" {
		t.Fatalf("default-identity = %q", cfg.DefaultIdentity)
	}

	// The underscore spelling of the TOML key resolves to the same place, so the
	// file and the command never teach two different names.
	if err := set.RunE(set, []string{"default_identity", "bob"}); err != nil {
		t.Fatalf("set default_identity: %v", err)
	}
	if cfg.DefaultIdentity != "bob" {
		t.Fatalf("default_identity = %q", cfg.DefaultIdentity)
	}

	if err := set.RunE(set, []string{"default-peer", "prod"}); err != nil {
		t.Fatalf("set default-peer: %v", err)
	}
	if cfg.DefaultPeer != "prod" {
		t.Fatalf("default-peer = %q", cfg.DefaultPeer)
	}

	// A default naming a peer that does not exist would be a pointer to nothing.
	if err := set.RunE(set, []string{"default-peer", "ghost"}); err == nil ||
		!strings.Contains(err.Error(), "unknown peer") {
		t.Fatalf("unknown default-peer error = %v", err)
	}

	// active_context is no longer writable — it is not part of the stack.
	err := set.RunE(set, []string{"active_context", "alice@prod"})
	if err == nil || !strings.Contains(err.Error(), "unknown config key") {
		t.Fatalf("config set active_context = %v, want an unknown-key error", err)
	}
	if !strings.Contains(err.Error(), "default-identity") {
		t.Fatalf("unknown-key error %q should list the known keys", err)
	}
}

func TestForgetClearsADanglingDefaultIdentity(t *testing.T) {
	cfg := &config.Config{
		DefaultIdentity: "alice",
		Identities:      map[string]config.IdentityConfig{"alice": {DID: testLoginSubject}},
		Contexts:        map[string]config.ContextConfig{},
	}
	result, err := forgetIdentityConfig(cfg, "alice")
	if err != nil {
		t.Fatalf("forget: %v", err)
	}
	if cfg.DefaultIdentity != "" || !result.DefaultIdentityCleared {
		t.Fatalf("default-identity = %q, cleared=%v", cfg.DefaultIdentity, result.DefaultIdentityCleared)
	}
}

// --- whoami ------------------------------------------------------------------

func TestWhoamiReportsEveryStateHonestly(t *testing.T) {
	storeA, storeB, _ := setupDevices(t)
	keys = storeA

	t.Run("nothing selected", func(t *testing.T) {
		var got whoamiResult
		runJSON(t, newWhoamiCmd(), nil, &got)
		if got.Identity != nil || got.Peer != nil {
			t.Fatalf("empty config resolved something: %+v", got)
		}
		if got.SigningKey.Available || got.SigningKey.Backend == "" {
			t.Fatalf("signing key = %+v (backend must be named even with no identity)", got.SigningKey)
		}
		if len(got.Credentials) != 0 {
			t.Fatalf("credentials = %+v", got.Credentials)
		}
	})

	did := createIdentity(t, "alice", storeA)
	identityFlag = ""

	t.Run("key held", func(t *testing.T) {
		asFlag = "alice"
		defer func() { asFlag = "" }()
		var got whoamiResult
		runJSON(t, newWhoamiCmd(), nil, &got)
		if got.Identity == nil || got.Identity.DID != did || got.Identity.Source != config.SourceFlagAs {
			t.Fatalf("identity = %+v", got.Identity)
		}
		if !got.Identity.InChain || got.Identity.Deleted {
			t.Fatalf("chain state = %+v", got.Identity)
		}
		if !got.SigningKey.Available || !strings.HasPrefix(got.SigningKey.KID, did+"#") {
			t.Fatalf("signing key = %+v", got.SigningKey)
		}
		if got.SigningKey.Held != 1 || got.SigningKey.PublishedAll != 1 {
			t.Fatalf("key counts = %+v", got.SigningKey)
		}
	})

	t.Run("key not held on this device", func(t *testing.T) {
		asFlag = "alice"
		keys = storeB
		defer func() { asFlag = ""; keys = storeA }()
		var got whoamiResult
		runJSON(t, newWhoamiCmd(), nil, &got)
		if got.SigningKey.Available || got.SigningKey.Held != 0 {
			t.Fatalf("signing key = %+v, want unavailable", got.SigningKey)
		}
		if !strings.Contains(got.SigningKey.Reason, "holds none") {
			t.Fatalf("reason = %q", got.SigningKey.Reason)
		}
	})

	t.Run("identity named but unregistered", func(t *testing.T) {
		asFlag = "ghost"
		defer func() { asFlag = "" }()
		var got whoamiResult
		runJSON(t, newWhoamiCmd(), nil, &got)
		if got.Identity == nil || got.Identity.DID != "" || got.Identity.Name != "ghost" {
			t.Fatalf("identity = %+v", got.Identity)
		}
		if got.SigningKey.Available || !strings.Contains(got.SigningKey.Reason, "not registered") {
			t.Fatalf("signing key = %+v", got.SigningKey)
		}
	})

	t.Run("peer and legacy pointer", func(t *testing.T) {
		cfg.Relays["prod"] = config.RelayConfig{URL: "https://prod.example.com"}
		cfg.DefaultPeer = "prod"
		cfg.ActiveContext = "alice@prod"
		defer func() { cfg.DefaultPeer, cfg.ActiveContext = "", "" }()

		var got whoamiResult
		runJSON(t, newWhoamiCmd(), nil, &got)
		if got.Peer == nil || got.Peer.Name != "prod" || got.Peer.Source != config.SourceDefaultPeer {
			t.Fatalf("peer = %+v", got.Peer)
		}
		if got.LegacyActiveCtx != "alice@prod" {
			t.Fatalf("legacy active context = %q — whoami must report it as inert, not hide it", got.LegacyActiveCtx)
		}
		// Reported, but never acted on: nothing resolved from it.
		if got.Identity != nil {
			t.Fatalf("the inert active_context resolved an identity: %+v", got.Identity)
		}
	})
}

// --- flag surface ------------------------------------------------------------

func TestGlobalFlagSurface(t *testing.T) {
	root := NewRootCmd()
	for _, name := range []string{"as", "relay", "quiet", "json"} {
		f := root.PersistentFlags().Lookup(name)
		if f == nil {
			t.Fatalf("--%s is not registered", name)
		}
		if f.Hidden {
			t.Fatalf("--%s must be visible in help", name)
		}
	}
	for _, name := range []string{"ctx", "identity", "peer"} {
		f := root.PersistentFlags().Lookup(name)
		if f == nil {
			t.Fatalf("compat alias --%s stopped working", name)
		}
		if !f.Hidden {
			t.Fatalf("compat alias --%s must be hidden — help teaches one spelling", name)
		}
	}
}

func TestOverridesCarriesEverySelector(t *testing.T) {
	prev := [5]string{asFlag, identityFlag, ctxFlag, relayFlag, peerFlag}
	defer func() {
		asFlag, identityFlag, ctxFlag, relayFlag, peerFlag = prev[0], prev[1], prev[2], prev[3], prev[4]
	}()

	asFlag, identityFlag, ctxFlag, relayFlag, peerFlag = "a", "b", "c", "d", "e"
	want := config.Overrides{As: "a", Identity: "b", Ctx: "c", Relay: "d", Peer: "e"}
	if got := overrides(); got != want {
		t.Fatalf("overrides() = %+v, want %+v", got, want)
	}
}

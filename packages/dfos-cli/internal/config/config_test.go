package config

import (
	"strings"
	"testing"
)

func testConfig() *Config {
	return &Config{
		Relays: map[string]RelayConfig{
			"prod":    {URL: "https://prod.example.com"},
			"staging": {URL: "https://staging.example.com"},
		},
		Identities: map[string]IdentityConfig{
			"alice": {DID: "did:dfos:alice123"},
			"bob":   {DID: "did:dfos:bob456"},
		},
		Contexts: map[string]ContextConfig{
			"work": {Identity: "alice", Relay: "prod"},
		},
	}
}

// clearEnv blanks every environment mechanism of the stack so a developer's own
// shell (or a previous test) cannot leak into the case under test.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{SourceEnvAs, SourceEnvIdentity, SourceEnvRelay, SourceEnvContext} {
		t.Setenv(k, "")
	}
}

func resolve(t *testing.T, cfg *Config, ov Overrides) *ResolvedContext {
	t.Helper()
	ctx, err := ResolveContext(cfg, ov)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return ctx
}

// --- the canonical stack -----------------------------------------------------

func TestResolve_AsFlagBeatsEnvBeatsConfigDefault(t *testing.T) {
	clearEnv(t)
	cfg := testConfig()
	cfg.DefaultIdentity = "alice"

	ctx := resolve(t, cfg, Overrides{})
	if ctx.IdentityName != "alice" || ctx.IdentitySource != SourceDefaultIdentity {
		t.Fatalf("config tier = (%q, %q), want (alice, %q)", ctx.IdentityName, ctx.IdentitySource, SourceDefaultIdentity)
	}
	if ctx.IdentityDID != "did:dfos:alice123" {
		t.Fatalf("DID = %q", ctx.IdentityDID)
	}

	t.Setenv(SourceEnvAs, "bob")
	ctx = resolve(t, cfg, Overrides{})
	if ctx.IdentityName != "bob" || ctx.IdentitySource != SourceEnvAs {
		t.Fatalf("env tier = (%q, %q), want (bob, %q)", ctx.IdentityName, ctx.IdentitySource, SourceEnvAs)
	}

	ctx = resolve(t, cfg, Overrides{As: "alice"})
	if ctx.IdentityName != "alice" || ctx.IdentitySource != SourceFlagAs {
		t.Fatalf("flag tier = (%q, %q), want (alice, %q)", ctx.IdentityName, ctx.IdentitySource, SourceFlagAs)
	}
}

func TestResolve_RelayFlagBeatsEnvBeatsConfigDefault(t *testing.T) {
	clearEnv(t)
	cfg := testConfig()
	cfg.DefaultPeer = "prod"

	ctx := resolve(t, cfg, Overrides{})
	if ctx.RelayName != "prod" || ctx.RelaySource != SourceDefaultPeer {
		t.Fatalf("config tier = (%q, %q)", ctx.RelayName, ctx.RelaySource)
	}
	if ctx.RelayURL != "https://prod.example.com" {
		t.Fatalf("URL = %q", ctx.RelayURL)
	}

	t.Setenv(SourceEnvRelay, "staging")
	ctx = resolve(t, cfg, Overrides{})
	if ctx.RelayName != "staging" || ctx.RelaySource != SourceEnvRelay {
		t.Fatalf("env tier = (%q, %q)", ctx.RelayName, ctx.RelaySource)
	}

	ctx = resolve(t, cfg, Overrides{Relay: "prod"})
	if ctx.RelayName != "prod" || ctx.RelaySource != SourceFlagRelay {
		t.Fatalf("flag tier = (%q, %q)", ctx.RelayName, ctx.RelaySource)
	}
}

func TestResolve_AsAcceptsABareDID(t *testing.T) {
	clearEnv(t)
	cfg := testConfig()

	// A DID nobody registered still resolves — that is the point of --as <did>.
	ctx := resolve(t, cfg, Overrides{As: "did:dfos:stranger"})
	if ctx.IdentityDID != "did:dfos:stranger" || ctx.IdentityName != "" {
		t.Fatalf("unregistered DID = (%q, %q)", ctx.IdentityName, ctx.IdentityDID)
	}
	if ctx.Principal() != "did:dfos:stranger" {
		t.Fatalf("principal = %q", ctx.Principal())
	}

	// A registered one picks its name back up, so output can say "alice".
	ctx = resolve(t, cfg, Overrides{As: "did:dfos:alice123"})
	if ctx.IdentityName != "alice" || ctx.IdentityDID != "did:dfos:alice123" {
		t.Fatalf("registered DID = (%q, %q)", ctx.IdentityName, ctx.IdentityDID)
	}
}

func TestResolve_NothingSelectedIsAnonymousNotAnError(t *testing.T) {
	clearEnv(t)
	ctx := resolve(t, testConfig(), Overrides{})
	if ctx.HasIdentity() {
		t.Fatalf("empty config resolved an identity: %+v", ctx)
	}
	if ctx.IdentitySource != "" || ctx.RelaySource != "" {
		t.Fatalf("sources = (%q, %q), want empty", ctx.IdentitySource, ctx.RelaySource)
	}
}

// --- compat aliases ----------------------------------------------------------

func TestResolve_AliasesSitAtTheirOwnTier(t *testing.T) {
	clearEnv(t)
	cfg := testConfig()
	cfg.DefaultIdentity = "alice"

	// --identity is a flag alias: it beats the env canonical.
	t.Setenv(SourceEnvAs, "alice")
	ctx := resolve(t, cfg, Overrides{Identity: "bob"})
	if ctx.IdentityName != "bob" || ctx.IdentitySource != SourceFlagIdentity {
		t.Fatalf("--identity = (%q, %q)", ctx.IdentityName, ctx.IdentitySource)
	}

	// DFOS_IDENTITY is an env alias: it beats the config default, and loses to
	// the canonical env var that sits above it in the same tier.
	t.Setenv(SourceEnvAs, "")
	t.Setenv(SourceEnvIdentity, "bob")
	ctx = resolve(t, cfg, Overrides{})
	if ctx.IdentityName != "bob" || ctx.IdentitySource != SourceEnvIdentity {
		t.Fatalf("DFOS_IDENTITY = (%q, %q)", ctx.IdentityName, ctx.IdentitySource)
	}
	t.Setenv(SourceEnvAs, "alice")
	ctx = resolve(t, cfg, Overrides{})
	if ctx.IdentityName != "alice" || ctx.IdentitySource != SourceEnvAs {
		t.Fatalf("DFOS_AS over DFOS_IDENTITY = (%q, %q)", ctx.IdentityName, ctx.IdentitySource)
	}

	// --peer is the peer-side flag alias.
	clearEnv(t)
	ctx = resolve(t, cfg, Overrides{Peer: "staging"})
	if ctx.RelayName != "staging" || ctx.RelaySource != SourceFlagPeer {
		t.Fatalf("--peer = (%q, %q)", ctx.RelayName, ctx.RelaySource)
	}
}

func TestResolve_CtxAliasFillsBothHalves(t *testing.T) {
	clearEnv(t)
	cfg := testConfig()

	for _, spec := range []string{"alice@prod", "work"} {
		ctx := resolve(t, cfg, Overrides{Ctx: spec})
		if ctx.IdentityName != "alice" || ctx.RelayName != "prod" {
			t.Fatalf("--ctx %q = (%q, %q)", spec, ctx.IdentityName, ctx.RelayName)
		}
		if ctx.IdentitySource != SourceFlagCtx || ctx.RelaySource != SourceFlagCtx {
			t.Fatalf("--ctx %q sources = (%q, %q)", spec, ctx.IdentitySource, ctx.RelaySource)
		}
	}

	// Identity-only spec leaves the peer half open for another mechanism.
	ctx := resolve(t, cfg, Overrides{Ctx: "bob", Relay: "prod"})
	if ctx.IdentityName != "bob" || ctx.RelayName != "prod" || ctx.RelaySource != SourceFlagRelay {
		t.Fatalf("identity-only ctx = %+v", ctx)
	}

	// --as wins the identity half of a --ctx pair; the peer half survives.
	ctx = resolve(t, cfg, Overrides{Ctx: "alice@prod", As: "bob"})
	if ctx.IdentityName != "bob" || ctx.IdentitySource != SourceFlagAs || ctx.RelayName != "prod" {
		t.Fatalf("--as over --ctx = %+v", ctx)
	}
}

func TestResolve_CtxEnvAliasIsEnvTier(t *testing.T) {
	clearEnv(t)
	cfg := testConfig()
	cfg.DefaultIdentity = "bob"
	t.Setenv(SourceEnvContext, "alice@prod")

	ctx := resolve(t, cfg, Overrides{})
	if ctx.IdentityName != "alice" || ctx.IdentitySource != SourceEnvContext {
		t.Fatalf("DFOS_CONTEXT = (%q, %q)", ctx.IdentityName, ctx.IdentitySource)
	}
	if ctx.RelayName != "prod" || ctx.RelaySource != SourceEnvContext {
		t.Fatalf("DFOS_CONTEXT peer = (%q, %q)", ctx.RelayName, ctx.RelaySource)
	}

	// The flag spelling wins outright: a stale DFOS_CONTEXT never contributes a
	// half to an invocation that named its own context.
	ctx = resolve(t, cfg, Overrides{Ctx: "bob"})
	if ctx.IdentityName != "bob" || ctx.RelayName != "" {
		t.Fatalf("--ctx over DFOS_CONTEXT = %+v", ctx)
	}
}

// --- the removed pointer -----------------------------------------------------

func TestResolve_ActiveContextIsInert(t *testing.T) {
	clearEnv(t)
	cfg := testConfig()
	cfg.ActiveContext = "alice@prod"

	ctx := resolve(t, cfg, Overrides{})
	if ctx.HasIdentity() || ctx.RelayName != "" {
		t.Fatalf("the removed active_context still resolves: %+v", ctx)
	}

	// It also loses to nothing, because it is not in the stack at all: a config
	// default set explicitly is what answers.
	cfg.DefaultIdentity = "bob"
	ctx = resolve(t, cfg, Overrides{})
	if ctx.IdentityName != "bob" {
		t.Fatalf("default-identity = %q, want bob", ctx.IdentityName)
	}
}

// --- error surfaces ----------------------------------------------------------

func TestResolve_UnknownContextSpecErrors(t *testing.T) {
	clearEnv(t)
	_, err := ResolveContext(testConfig(), Overrides{Ctx: "nonexistent"})
	if err == nil || !strings.Contains(err.Error(), "unknown context") {
		t.Fatalf("error = %v", err)
	}
}

func TestResolve_UnknownPeerNamesTheMechanism(t *testing.T) {
	clearEnv(t)
	_, err := ResolveContext(testConfig(), Overrides{Relay: "nonexistent"})
	if err == nil || !strings.Contains(err.Error(), "unknown peer") || !strings.Contains(err.Error(), SourceFlagRelay) {
		t.Fatalf("error = %v (must name the peer and the mechanism that supplied it)", err)
	}
}

// DFOS_CONFIG names the config FILE, but everything on disk sits beside it, so
// "point DFOS_CONFIG at a scratch directory" invites naming the directory. The
// bare syscall error there is "is a directory", which reports the symptom and
// not the contract.
func TestConfigPathThatNamesADirectoryStatesTheContract(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DFOS_CONFIG", dir)

	_, err := Load()
	if err == nil {
		t.Fatal("a DFOS_CONFIG naming a directory loaded without complaint")
	}
	for _, want := range []string{"DFOS_CONFIG", "config.toml", dir} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("load error %q does not name %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "is a directory:") && !strings.Contains(err.Error(), "FILE") {
		t.Errorf("load error is still the bare syscall message: %v", err)
	}

	if err := Save(&Config{}); err == nil {
		t.Fatal("Save wrote through a DFOS_CONFIG naming a directory")
	} else if !strings.Contains(err.Error(), "DFOS_CONFIG") {
		t.Errorf("save error does not name the variable: %v", err)
	}

	// The ordinary case still loads: a path whose file does not exist yet is an
	// empty config, not an error.
	t.Setenv("DFOS_CONFIG", dir+"/config.toml")
	if _, err := Load(); err != nil {
		t.Fatalf("a normal DFOS_CONFIG file path: %v", err)
	}
}

func TestResolve_UnknownIdentityNameIsNotAResolutionError(t *testing.T) {
	// A name with no config registration resolves to a name and no DID. The
	// signing site is what rejects it, with a message that can name the source.
	clearEnv(t)
	ctx := resolve(t, testConfig(), Overrides{As: "ghost"})
	if ctx.IdentityName != "ghost" || ctx.IdentityDID != "" {
		t.Fatalf("unknown name = (%q, %q)", ctx.IdentityName, ctx.IdentityDID)
	}
	if !ctx.HasIdentity() {
		t.Fatal("a named-but-unregistered identity must still count as selected")
	}
}

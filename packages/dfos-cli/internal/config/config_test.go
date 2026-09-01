package config

import (
	"os"
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
	}
}

// clearEnv blanks every environment mechanism of the stack so a developer's own
// shell (or a previous test) cannot leak into the case under test.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{SourceEnvAs, SourceEnvRelay} {
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

// --- the command-local peer -------------------------------------------------

// A command's own --peer is not a tier OF the peer stack: it sits in front of
// the whole of it, so `dfos --relay stale recover --peer authoritative` asks
// authoritative. requirePeer is the only thing that writes it.
func TestResolve_CommandLocalPeerOutranksEveryGlobalTier(t *testing.T) {
	clearEnv(t)
	cfg := testConfig()
	cfg.DefaultPeer = "prod"
	t.Setenv(SourceEnvRelay, "prod")

	ctx := resolve(t, cfg, Overrides{Peer: "staging", Relay: "prod"})
	if ctx.RelayName != "staging" || ctx.RelaySource != SourceFlagPeer {
		t.Fatalf("--peer = (%q, %q), want (staging, %q)", ctx.RelayName, ctx.RelaySource, SourceFlagPeer)
	}

	// It selects the peer half and nothing else — the identity half resolves
	// through its own stack, untouched.
	cfg.DefaultIdentity = "alice"
	ctx = resolve(t, cfg, Overrides{Peer: "staging"})
	if ctx.IdentityName != "alice" || ctx.IdentitySource != SourceDefaultIdentity {
		t.Fatalf("identity half = (%q, %q)", ctx.IdentityName, ctx.IdentitySource)
	}
}

// --- error surfaces ----------------------------------------------------------

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

// --- what a config.toml from an earlier layout does --------------------------

// A file carrying keys this package no longer declares must still load. Nothing
// resolves through them, and the keys leave the file the next time Save writes
// it — but a parse error here would lock an operator out of every command at
// once, which is a far worse outcome than an ignored line.
func TestLoad_KeysThisPackageDoesNotDeclareAreIgnored(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DFOS_CONFIG", dir+"/config.toml")
	body := "active_context = \"alice@prod\"\ndefault_identity = \"alice\"\n\n" +
		"[contexts.work]\nidentity = \"alice\"\nrelay = \"prod\"\n"
	if err := os.WriteFile(dir+"/config.toml", []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("a config.toml carrying undeclared keys failed to load: %v", err)
	}
	if cfg.DefaultIdentity != "alice" {
		t.Fatalf("default_identity = %q, want alice — the keys around it must not cost the ones that count", cfg.DefaultIdentity)
	}
}

// The environment names two mechanisms and no more. A DFOS_IDENTITY or
// DFOS_CONTEXT still exported by a developer's shell or a CI job selects
// nothing: it is an unset variable as far as this resolver is concerned.
func TestResolve_TheEnvironmentNamesTwoMechanisms(t *testing.T) {
	clearEnv(t)
	cfg := testConfig()
	cfg.DefaultIdentity = "alice"
	cfg.DefaultPeer = "prod"
	t.Setenv("DFOS_IDENTITY", "bob")
	t.Setenv("DFOS_CONTEXT", "bob@staging")

	ctx := resolve(t, cfg, Overrides{})
	if ctx.IdentityName != "alice" || ctx.IdentitySource != SourceDefaultIdentity {
		t.Fatalf("identity = (%q, %q), want alice via the config tier", ctx.IdentityName, ctx.IdentitySource)
	}
	if ctx.RelayName != "prod" || ctx.RelaySource != SourceDefaultPeer {
		t.Fatalf("peer = (%q, %q), want prod via the config tier", ctx.RelayName, ctx.RelaySource)
	}
}

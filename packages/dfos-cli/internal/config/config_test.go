package config

import (
	"os"
	"testing"
)

func testConfig() *Config {
	return &Config{
		Relays: map[string]RelayConfig{
			"prod": {URL: "https://prod.example.com"},
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

func TestResolveContext_InlineContext(t *testing.T) {
	cfg := testConfig()
	ctx, err := ResolveContext(cfg, "alice@prod", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.IdentityName != "alice" {
		t.Errorf("identity = %q, want alice", ctx.IdentityName)
	}
	if ctx.RelayName != "prod" {
		t.Errorf("relay = %q, want prod", ctx.RelayName)
	}
	if ctx.IdentityDID != "did:dfos:alice123" {
		t.Errorf("DID = %q, want did:dfos:alice123", ctx.IdentityDID)
	}
	if ctx.RelayURL != "https://prod.example.com" {
		t.Errorf("URL = %q, want https://prod.example.com", ctx.RelayURL)
	}
}

func TestResolveContext_NamedContext(t *testing.T) {
	cfg := testConfig()
	ctx, err := ResolveContext(cfg, "work", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.IdentityName != "alice" || ctx.RelayName != "prod" {
		t.Errorf("got (%q, %q), want (alice, prod)", ctx.IdentityName, ctx.RelayName)
	}
}

func TestResolveContext_IdentityOnly_TreatedAsIdentity(t *testing.T) {
	cfg := testConfig()
	// An identity-only string should be treated as the identity name, not error
	ctx, err := ResolveContext(cfg, "alice", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.IdentityName != "alice" {
		t.Errorf("identity = %q, want alice", ctx.IdentityName)
	}
	if ctx.IdentityDID != "did:dfos:alice123" {
		t.Errorf("DID = %q, want did:dfos:alice123", ctx.IdentityDID)
	}
	if ctx.RelayName != "" {
		t.Errorf("relay = %q, want empty", ctx.RelayName)
	}
}

func TestResolveContext_IdentityOnly_FromActiveContext(t *testing.T) {
	cfg := testConfig()
	cfg.ActiveContext = "bob"
	ctx, err := ResolveContext(cfg, "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.IdentityName != "bob" {
		t.Errorf("identity = %q, want bob", ctx.IdentityName)
	}
	if ctx.IdentityDID != "did:dfos:bob456" {
		t.Errorf("DID = %q, want did:dfos:bob456", ctx.IdentityDID)
	}
}

func TestResolveContext_IdentityFlagOverridesContext(t *testing.T) {
	cfg := testConfig()
	cfg.ActiveContext = "alice@prod"
	ctx, err := ResolveContext(cfg, "", "bob", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.IdentityName != "bob" {
		t.Errorf("identity = %q, want bob", ctx.IdentityName)
	}
	// relay should still come from active context
	if ctx.RelayName != "prod" {
		t.Errorf("relay = %q, want prod", ctx.RelayName)
	}
}

func TestResolveContext_EnvVarOverridesActiveContext(t *testing.T) {
	cfg := testConfig()
	cfg.ActiveContext = "alice@prod"
	os.Setenv("DFOS_IDENTITY", "bob")
	defer os.Unsetenv("DFOS_IDENTITY")

	ctx, err := ResolveContext(cfg, "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.IdentityName != "bob" {
		t.Errorf("identity = %q, want bob (env var should override)", ctx.IdentityName)
	}
}

func TestResolveContext_EnvVarOverridesBrokenActiveContext(t *testing.T) {
	cfg := testConfig()
	cfg.ActiveContext = "nonexistent-identity"
	os.Setenv("DFOS_IDENTITY", "alice")
	defer os.Unsetenv("DFOS_IDENTITY")

	ctx, err := ResolveContext(cfg, "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.IdentityName != "alice" {
		t.Errorf("identity = %q, want alice (env var should override broken active_context)", ctx.IdentityName)
	}
}

func TestResolveContext_UnknownRelay(t *testing.T) {
	cfg := testConfig()
	_, err := ResolveContext(cfg, "alice@nonexistent", "", "")
	if err == nil {
		t.Fatal("expected error for unknown relay")
	}
}

func TestResolveContext_Empty(t *testing.T) {
	cfg := testConfig()
	ctx, err := ResolveContext(cfg, "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.IdentityName != "" || ctx.RelayName != "" {
		t.Errorf("expected empty context, got (%q, %q)", ctx.IdentityName, ctx.RelayName)
	}
}

func TestResolveContext_DFOSContextEnvVar(t *testing.T) {
	cfg := testConfig()
	os.Setenv("DFOS_CONTEXT", "bob@prod")
	defer os.Unsetenv("DFOS_CONTEXT")

	ctx, err := ResolveContext(cfg, "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.IdentityName != "bob" || ctx.RelayName != "prod" {
		t.Errorf("got (%q, %q), want (bob, prod)", ctx.IdentityName, ctx.RelayName)
	}
}

func TestResolveContext_FlagTakesPrecedenceOverEnv(t *testing.T) {
	cfg := testConfig()
	os.Setenv("DFOS_CONTEXT", "bob@prod")
	defer os.Unsetenv("DFOS_CONTEXT")

	ctx, err := ResolveContext(cfg, "alice@prod", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.IdentityName != "alice" {
		t.Errorf("identity = %q, want alice (flag should override env)", ctx.IdentityName)
	}
}

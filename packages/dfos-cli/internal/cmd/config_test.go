package cmd

// Config command tests. Like the vault tests these drive RunE directly against
// the package globals setupDevices wires, so they MUST NOT run with
// t.Parallel().

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
)

// `config list` had one rendering under both flags — a JSON document either
// way — which made --json mean nothing on the one command whose whole output is
// configuration. The bare form is the house plain rendering; --json is the
// round-trippable TOML namespace, unchanged.
func TestConfigListRendersPlainAndJSONDifferently(t *testing.T) {
	setupDevices(t)
	cfg.Relays["prod"] = config.RelayConfig{URL: "https://prod.example.com"}
	cfg.Identities["alice"] = config.IdentityConfig{DID: "did:dfos:alice123"}
	cfg.Contexts["work"] = config.ContextConfig{Identity: "alice", Relay: "prod"}
	cfg.DefaultPeer = "prod"
	cfg.Defaults = &config.DefaultsConfig{CredentialTTL: "24h"}

	plain, _, err := runCapturing(t, newConfigListCmd(), nil)
	if err != nil {
		t.Fatalf("config list: %v", err)
	}
	if json.Valid([]byte(strings.TrimSpace(plain))) {
		t.Fatalf("the bare form is still a JSON document:\n%s", plain)
	}
	for _, want := range []string{
		config.ConfigPath(),
		"default-identity", "(unset)", // an unset key is named, not omitted
		"default-peer", "prod",
		"default-vault",
		"defaults.credential_ttl", "24h",
		"Peers: 1", "https://prod.example.com",
		"Identities: 1", "did:dfos:alice123",
		"Contexts: 1", "alice @ prod",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("plain rendering does not report %q:\n%s", want, plain)
		}
	}

	// --json is the config struct's own JSON, key for key with the TOML.
	var doc map[string]any
	if _, _, err := runCapturingJSON(t, newConfigListCmd(), nil, &doc); err != nil {
		t.Fatalf("config list --json: %v", err)
	}
	if doc["default_peer"] != "prod" {
		t.Errorf("--json document is not the TOML namespace: %v", doc)
	}
	if _, ok := doc["default_identity"]; ok {
		t.Errorf("--json document carries an empty default_identity: %v", doc)
	}
}

// `config get` and the plain listing read one key through the same function, so
// the two cannot drift into disagreeing about what a key holds.
func TestConfigValueAndGetAgree(t *testing.T) {
	setupDevices(t)
	cfg.DefaultIdentity = "alice"

	for _, key := range configKeys {
		if _, ok := configValue(key); !ok {
			t.Errorf("configValue does not know the documented key %q", key)
		}
	}
	if _, ok := configValue("nonsense"); ok {
		t.Error("configValue accepted an unknown key")
	}

	get := newConfigGetCmd()
	stdout, _, err := runCapturing(t, get, []string{"default_identity"})
	if err != nil {
		t.Fatalf("config get: %v", err)
	}
	if strings.TrimSpace(stdout) != "alice" {
		t.Errorf("config get default_identity = %q, want alice", strings.TrimSpace(stdout))
	}
	if _, _, err := runCapturing(t, newConfigGetCmd(), []string{"nonsense"}); err == nil {
		t.Error("config get accepted an unknown key")
	}
}

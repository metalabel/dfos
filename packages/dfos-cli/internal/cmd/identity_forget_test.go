package cmd

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
)

func TestForgetIdentityConfig(t *testing.T) {
	tests := []struct {
		name              string
		target            string
		cfg               *config.Config
		wantName          string
		wantDID           string
		wantContexts      []string
		wantActiveCleared bool
		wantActive        string
		wantIdentityCount int
		wantErr           bool
	}{
		{
			name:   "named identity removes referencing contexts and active selection",
			target: "alice",
			cfg: &config.Config{
				ActiveContext: "work",
				Identities: map[string]config.IdentityConfig{
					"alice": {DID: testLoginSubject},
					"bob":   {DID: testLoginOther},
				},
				Contexts: map[string]config.ContextConfig{
					"work":   {Identity: "alice", Relay: "prod"},
					"direct": {Identity: testLoginSubject, Relay: "prod"},
					"other":  {Identity: "bob", Relay: "prod"},
				},
			},
			wantName:          "alice",
			wantDID:           testLoginSubject,
			wantContexts:      []string{"direct", "work"},
			wantActiveCleared: true,
			wantActive:        "",
			wantIdentityCount: 1,
		},
		{
			name:   "bare DID leaves registrations and clears inline active context",
			target: testLoginSubject,
			cfg: &config.Config{
				ActiveContext: testLoginSubject + "@prod",
				Identities: map[string]config.IdentityConfig{
					"bob": {DID: testLoginOther},
				},
				Contexts: map[string]config.ContextConfig{
					"direct": {Identity: testLoginSubject, Relay: "prod"},
					"other":  {Identity: "bob", Relay: "prod"},
				},
			},
			wantDID:           testLoginSubject,
			wantContexts:      []string{"direct"},
			wantActiveCleared: true,
			wantActive:        "",
			wantIdentityCount: 1,
		},
		{
			name:   "unknown name is rejected",
			target: "missing",
			cfg: &config.Config{
				Identities: map[string]config.IdentityConfig{},
				Contexts:   map[string]config.ContextConfig{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := forgetIdentityConfig(tt.cfg, tt.target)
			if (err != nil) != tt.wantErr {
				t.Fatalf("forgetIdentityConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if result.Name != tt.wantName || result.DID != tt.wantDID {
				t.Fatalf("result identity = (%q, %q), want (%q, %q)", result.Name, result.DID, tt.wantName, tt.wantDID)
			}
			if !reflect.DeepEqual(result.RemovedContexts, tt.wantContexts) {
				t.Fatalf("removed contexts = %v, want %v", result.RemovedContexts, tt.wantContexts)
			}
			if result.ActiveContextCleared != tt.wantActiveCleared || tt.cfg.ActiveContext != tt.wantActive {
				t.Fatalf("active = %q, cleared=%v; want %q, %v", tt.cfg.ActiveContext, result.ActiveContextCleared, tt.wantActive, tt.wantActiveCleared)
			}
			if len(tt.cfg.Identities) != tt.wantIdentityCount {
				t.Fatalf("identity count = %d, want %d", len(tt.cfg.Identities), tt.wantIdentityCount)
			}
			for _, removed := range tt.wantContexts {
				if _, ok := tt.cfg.Contexts[removed]; ok {
					t.Fatalf("context %q was not removed", removed)
				}
			}
		})
	}
}

// A credential file that will not parse might be a grant for the identity being
// forgotten, and nothing here can tell whether it is. So forget removes what it
// could read, leaves what it could not, and says which — rather than reporting a
// whole forget on a partial view of the store.
func TestForgetNamesTheCredentialFilesItCouldNotRead(t *testing.T) {
	setupCredsTest(t)
	cfg.Identities["alice"] = config.IdentityConfig{DID: testLoginSubject}
	writeCredentialRecord(t, testLoginSubject, "a.example.test", testCredentialForHost(t, "a.example.test"))

	corrupt := slotPath(t, testLoginSubject, "b.example.test")
	if err := os.WriteFile(corrupt, []byte("{ this is not a record"), 0o600); err != nil {
		t.Fatal(err)
	}

	var result identityForgetResult
	runJSON(t, newIdentityForgetCmd(), []string{"alice"}, &result)

	if !result.CredentialRemoved {
		t.Fatalf("the readable credential was not removed: %+v", result)
	}
	if _, err := os.Stat(slotPath(t, testLoginSubject, "a.example.test")); !os.IsNotExist(err) {
		t.Fatalf("the readable credential survived: %v", err)
	}
	want := []string{"did_dfos_nzkf838efr424433rn2rzkdv8h7t9ae__b.example.test.json"}
	if !reflect.DeepEqual(result.UnreadableCredentialFiles, want) {
		t.Fatalf("unreadable files = %v, want %v", result.UnreadableCredentialFiles, want)
	}
	// Left in place, not quietly deleted: this command cannot read it, so it is
	// not this command's to remove.
	if _, err := os.Stat(corrupt); err != nil {
		t.Fatalf("the unreadable file was removed anyway: %v", err)
	}

	// And the human is told, in the same words the ledger uses for a view it
	// cannot complete.
	setupCredsTest(t)
	cfg.Identities["alice"] = config.IdentityConfig{DID: testLoginSubject}
	if err := os.MkdirAll(credentialStoreDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(slotPath(t, testLoginSubject, "b.example.test"), []byte("{ this is not a record"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		forget := newIdentityForgetCmd()
		if err := forget.RunE(forget, []string{"alice"}); err != nil {
			t.Fatalf("identity forget: %v", err)
		}
	})
	for _, want := range []string{"partial", "b.example.test.json", "may still hold a grant"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the forget did not disclose the partial view (%q missing):\n%s", want, out)
		}
	}
}

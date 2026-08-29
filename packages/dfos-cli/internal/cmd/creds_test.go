package cmd

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

func TestCredsCommands(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "list sorts records and marks expiry",
			run: func(t *testing.T) {
				setupCredsTest(t)
				writeCredentialRecord(t, testLoginOther, "", "not-a-jws")
				writeCredentialRecord(t, testLoginSubject, "", testCredentialToken(t, 1))

				var got []storedCredentialListItem
				runJSON(t, newCredsListCmd(), nil, &got)
				if len(got) != 2 {
					t.Fatalf("list returned %d records, want 2", len(got))
				}
				if got[0].SubjectDID != testLoginOther || got[1].SubjectDID != testLoginSubject {
					t.Fatalf("list order = [%s, %s]", got[0].SubjectDID, got[1].SubjectDID)
				}
				if got[0].Expiry != nil || got[0].Expired {
					t.Fatalf("undecodable expiry = %v, expired=%v", got[0].Expiry, got[0].Expired)
				}
				if got[1].Expiry == nil || *got[1].Expiry != 1 || !got[1].Expired {
					t.Fatalf("expired record = %+v", got[1])
				}
			},
		},
		{
			name: "show resolves configured name and includes claims",
			run: func(t *testing.T) {
				setupCredsTest(t)
				cfg.Identities["alice"] = config.IdentityConfig{DID: testLoginSubject}
				writeCredentialRecord(t, testLoginSubject, "", testCredentialToken(t, 1234))

				var got struct {
					SubjectDID string         `json:"subjectDid"`
					Credential string         `json:"credential"`
					Claims     map[string]any `json:"claims"`
				}
				runJSON(t, newCredsShowCmd(), []string{"alice"}, &got)
				if got.SubjectDID != testLoginSubject || got.Credential == "" {
					t.Fatalf("show record = %+v", got)
				}
				if exp, ok := got.Claims["exp"].(float64); !ok || int64(exp) != 1234 {
					t.Fatalf("show claims exp = %#v", got.Claims["exp"])
				}
			},
		},
		{
			name: "rm accepts bare DID and errors when absent",
			run: func(t *testing.T) {
				setupCredsTest(t)
				writeCredentialRecord(t, testLoginSubject, "", testCredentialToken(t, 1234))
				var got map[string]string
				runJSON(t, newCredsRemoveCmd(), []string{testLoginSubject}, &got)
				if got["removed"] != testLoginSubject {
					t.Fatalf("rm output = %#v", got)
				}
				if _, err := os.Stat(credentialPath(testLoginSubject, "")); !os.IsNotExist(err) {
					t.Fatalf("credential still exists: %v", err)
				}
				cmd := newCredsRemoveCmd()
				if err := cmd.RunE(cmd, []string{testLoginSubject}); err == nil || !strings.Contains(err.Error(), "no stored login credential") {
					t.Fatalf("second rm error = %v", err)
				}
			},
		},
		{
			// One subject, two hosts, two files. A subject stopped being an
			// address the moment a second login could land beside the first, so
			// show and rm name which one rather than picking.
			name: "show and rm refuse to guess between a subject's hosts",
			run: func(t *testing.T) {
				setupCredsTest(t)
				writeCredentialRecord(t, testLoginSubject, "a.example.test", testCredentialForHost(t, "a.example.test"))
				writeCredentialRecord(t, testLoginSubject, "b.example.test", testCredentialForHost(t, "b.example.test"))

				show := newCredsShowCmd()
				err := show.RunE(show, []string{testLoginSubject})
				if err == nil || !strings.Contains(err.Error(), "--host") {
					t.Fatalf("show with two stored credentials must ask which: %v", err)
				}
				for _, host := range []string{"a.example.test", "b.example.test"} {
					if !strings.Contains(err.Error(), host) {
						t.Fatalf("the refusal must name %s:\n%v", host, err)
					}
				}

				var shown struct {
					Credential string `json:"credential"`
				}
				showOne := newCredsShowCmd()
				if err := showOne.Flags().Set("host", "b.example.test"); err != nil {
					t.Fatal(err)
				}
				runJSON(t, showOne, []string{testLoginSubject}, &shown)
				if shown.Credential == "" {
					t.Fatalf("show --host returned no credential: %+v", shown)
				}

				var removed map[string]string
				removeOne := newCredsRemoveCmd()
				if err := removeOne.Flags().Set("host", "a.example.test"); err != nil {
					t.Fatal(err)
				}
				runJSON(t, removeOne, []string{testLoginSubject}, &removed)
				if _, err := os.Stat(credentialPath(testLoginSubject, "a.example.test")); !os.IsNotExist(err) {
					t.Fatalf("the named credential still exists: %v", err)
				}
				if _, err := os.Stat(credentialPath(testLoginSubject, "b.example.test")); err != nil {
					t.Fatalf("removing one host's credential took the other: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

// testCredentialForHost is a credential whose attenuation names api:<host> —
// the string both the store's slot and `api call` read it by.
func testCredentialForHost(t *testing.T, host string) string {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := protocol.CreateCredential(testLoginSubject, testLoginOther, testLoginSubject+"#key_test",
		"api:"+host, "read", time.Hour, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func setupCredsTest(t *testing.T) {
	t.Helper()
	t.Setenv("DFOS_CONFIG", filepath.Join(t.TempDir(), "config.toml"))
	previousCfg := cfg
	cfg = &config.Config{
		Relays:     map[string]config.RelayConfig{},
		Identities: map[string]config.IdentityConfig{},
		Contexts:   map[string]config.ContextConfig{},
	}
	t.Cleanup(func() { cfg = previousCfg })
}

// writeCredentialRecord plants one record in the (subject, host) slot the store
// keys by. host names the slot; what the token itself grants is its own claim.
func writeCredentialRecord(t *testing.T, subjectDID, host, token string) {
	t.Helper()
	if err := os.MkdirAll(credentialStoreDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	record := storedLoginCredential{
		SubjectDID:  subjectDID,
		ClientDID:   testLoginOther,
		ClientKeyID: testLoginOther + "#key_client",
		Credential:  token,
		ObtainedAt:  time.Unix(100, 0).UTC().Format(loginTimestampLayout),
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialPath(subjectDID, host), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testCredentialToken(t *testing.T, expiry int64) string {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := protocol.CreateJWS(protocol.JWSHeader{
		Alg: "EdDSA",
		Typ: credentialJWSTyp,
		Kid: testLoginSubject + "#key_test",
	}, map[string]any{"iss": testLoginSubject, "aud": testLoginOther, "exp": expiry}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

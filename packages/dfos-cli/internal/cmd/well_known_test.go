package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

func TestIdentityWellKnownStdout(t *testing.T) {
	store, _, lr := setupDevices(t)
	did := createIdentity(t, "alice", store)

	chain, err := lr.Relay.GetIdentity(did)
	if err != nil || chain == nil {
		t.Fatalf("get identity: chain=%v err=%v", chain, err)
	}

	keys = store
	var result struct {
		ClientDID     string   `json:"client_did"`
		IdentityChain []string `json:"identity_chain"`
	}
	runJSON(t, newIdentityWellKnownCmd(), nil, &result)

	if result.ClientDID != did {
		t.Fatalf("client_did = %q, want %q", result.ClientDID, did)
	}
	if got, want := len(result.IdentityChain), len(chain.Log); got != want {
		t.Fatalf("identity_chain length = %d, want %d", got, want)
	}
	if len(result.IdentityChain) == 0 {
		t.Fatal("identity_chain is empty")
	}
	_, payload, err := protocol.DecodeJWSUnsafe(result.IdentityChain[0])
	if err != nil {
		t.Fatalf("decode genesis operation: %v", err)
	}
	if got, _ := payload["type"].(string); got != "create" {
		t.Fatalf("first operation type = %q, want create", got)
	}
}

func TestIdentityWellKnownPatch(t *testing.T) {
	store, _, lr := setupDevices(t)
	did := createIdentity(t, "alice", store)
	path := writeTempDoc(t, "{\n  \"name\": \"Example App\",\n  \"redirect_uris\": [\"https://example.com/callback\"]\n}\n")

	keys = store
	cmd := newIdentityWellKnownCmd()
	mustSetFlag(t, cmd, "patch", path)
	var status struct {
		Path       string `json:"path"`
		ClientDID  string `json:"client_did"`
		Operations int    `json:"operations"`
	}
	runJSON(t, cmd, nil, &status)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read patched app description: %v", err)
	}
	var doc struct {
		Name          string   `json:"name"`
		RedirectURIs  []string `json:"redirect_uris"`
		ClientDID     string   `json:"client_did"`
		IdentityChain []string `json:"identity_chain"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal patched app description: %v", err)
	}
	if doc.Name != "Example App" {
		t.Fatalf("name = %q, want Example App", doc.Name)
	}
	if got, want := doc.RedirectURIs, []string{"https://example.com/callback"}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("redirect_uris = %v, want %v", got, want)
	}
	if doc.ClientDID != did {
		t.Fatalf("client_did = %q, want %q", doc.ClientDID, did)
	}
	chain, err := lr.Relay.GetIdentity(did)
	if err != nil || chain == nil {
		t.Fatalf("get identity: chain=%v err=%v", chain, err)
	}
	if status.Path != path || status.ClientDID != did || status.Operations != len(chain.Log) {
		t.Fatalf("unexpected patch status: %+v", status)
	}
	if got, want := len(doc.IdentityChain), len(chain.Log); got != want {
		t.Fatalf("identity_chain length = %d, want %d", got, want)
	}
	for i := range chain.Log {
		if doc.IdentityChain[i] != chain.Log[i] {
			t.Fatalf("identity_chain[%d] differs from stored log", i)
		}
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatal("patched app description lacks trailing newline")
	}
}

func TestIdentityWellKnownPatchRefusesDIDMismatch(t *testing.T) {
	store, _, _ := setupDevices(t)
	createIdentity(t, "alice", store)
	path := writeTempDoc(t, "{\n  \"name\": \"Example App\",\n  \"client_did\": \"did:dfos:different\",\n  \"redirect_uris\": [\"https://example.com/callback\"]\n}\n")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read original app description: %v", err)
	}

	keys = store
	cmd := newIdentityWellKnownCmd()
	mustSetFlag(t, cmd, "patch", path)
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("patch with mismatched client_did succeeded")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read app description after refusal: %v", err)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("app description changed despite client_did mismatch")
	}
}

// The two refusal messages buildWellKnownPatch can produce, as format strings
// over the document path.
const (
	refusalMissingRedirectURIs = "app description at %s is missing its required member (redirect_uris); author that first — see specs/SIWD.md \"The App Description Document\""
	refusalInvalidName         = "app description at %s has an invalid name: present-but-empty is malformed — give it a value or omit it"
)

// name is optional (SIWD.md: the domain leads) — a nameless document patches
// exactly as a named one does.
func TestIdentityWellKnownPatchAcceptsNamelessDocument(t *testing.T) {
	store, _, _ := setupDevices(t)
	did := createIdentity(t, "alice", store)
	path := writeTempDoc(t, "{\n  \"redirect_uris\": [\"https://example.com/callback\"]\n}\n")

	keys = store
	cmd := newIdentityWellKnownCmd()
	mustSetFlag(t, cmd, "patch", path)
	var status struct {
		ClientDID string `json:"client_did"`
	}
	runJSON(t, cmd, nil, &status)
	if status.ClientDID != did {
		t.Fatalf("client_did = %q, want %q", status.ClientDID, did)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read patched app description: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal patched app description: %v", err)
	}
	if _, present := doc["name"]; present {
		t.Fatal("patch invented a name the document never claimed")
	}
	if got, _ := doc["client_did"].(string); got != did {
		t.Fatalf("client_did = %q, want %q", got, did)
	}
}

func TestIdentityWellKnownPatchRefusesIncompleteDocument(t *testing.T) {
	store, _, _ := setupDevices(t)
	createIdentity(t, "alice", store)

	cases := map[string]struct {
		body    string
		wantFmt string
	}{
		"empty object":            {"{}\n", refusalMissingRedirectURIs},
		"null":                    {"null\n", refusalMissingRedirectURIs},
		"missing redirect uris":   {"{\"name\":\"Example App\"}\n", refusalMissingRedirectURIs},
		"empty redirect uris":     {"{\"name\":\"Example App\",\"redirect_uris\":[]}\n", refusalMissingRedirectURIs},
		"non-array redirect uris": {"{\"name\":\"Example App\",\"redirect_uris\":\"https://example.com/callback\"}\n", refusalMissingRedirectURIs},
		"empty name":              {"{\"name\":\"\",\"redirect_uris\":[\"https://example.com/callback\"]}\n", refusalInvalidName},
		"non-string name":         {"{\"name\":42,\"redirect_uris\":[\"https://example.com/callback\"]}\n", refusalInvalidName},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeTempDoc(t, tc.body)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read original app description: %v", err)
			}

			keys = store
			cmd := newIdentityWellKnownCmd()
			mustSetFlag(t, cmd, "patch", path)
			err = cmd.RunE(cmd, nil)
			if err == nil {
				t.Fatal("patch of incomplete app description succeeded")
			}
			want := fmt.Sprintf(tc.wantFmt, path)
			if err.Error() != want {
				t.Fatalf("incomplete document error = %q, want %q", err, want)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read app description after refusal: %v", err)
			}
			if !bytes.Equal(after, original) {
				t.Fatal("incomplete app description changed despite refusal")
			}
		})
	}
}

func TestIdentityWellKnownPatchRefusesNonStringClientDID(t *testing.T) {
	store, _, _ := setupDevices(t)
	createIdentity(t, "alice", store)
	path := writeTempDoc(t, "{\n  \"name\": \"Example App\",\n  \"client_did\": 42,\n  \"redirect_uris\": [\"https://example.com/callback\"]\n}\n")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read original app description: %v", err)
	}

	keys = store
	cmd := newIdentityWellKnownCmd()
	mustSetFlag(t, cmd, "patch", path)
	err = cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("patch with non-string client_did succeeded")
	}
	want := fmt.Sprintf("app description at %s has invalid client_did: must be a string", path)
	if err.Error() != want {
		t.Fatalf("non-string client_did error = %q, want %q", err, want)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read app description after refusal: %v", err)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("app description changed despite non-string client_did")
	}
}

func TestValidateCarriageRefusesChainOverCap(t *testing.T) {
	chain := &relay.StoredIdentityChain{
		DID: "did:dfos:example",
		Log: make([]string, siwdCarriageCap+1),
	}
	err := validateCarriage(chain)
	if err == nil {
		t.Fatal("101-operation identity chain was accepted")
	}
	want := fmt.Sprintf(
		"identity chain has %d operations; the SIWD carriage cap is %d — publish the chain to a relay instead of carrying it",
		len(chain.Log),
		siwdCarriageCap,
	)
	if err.Error() != want {
		t.Fatalf("cap error = %q, want %q", err, want)
	}
}

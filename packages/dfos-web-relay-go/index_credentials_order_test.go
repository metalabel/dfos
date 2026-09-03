package relay

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

func orderedCredentialCID(t *testing.T, token string) string {
	t.Helper()
	header, _, err := dfos.DecodeJWSUnsafe(token)
	if err != nil || header == nil {
		t.Fatalf("decode credential CID: %v", err)
	}
	return header.CID
}

func credentialPageCIDs(t *testing.T, body map[string]any) []string {
	t.Helper()
	rows := body["credentials"].([]any)
	cids := make([]string, 0, len(rows))
	for _, raw := range rows {
		cids = append(cids, raw.(map[string]any)["cid"].(string))
	}
	return cids
}

func walkCredentialPages(t *testing.T, handler http.Handler, route string) []string {
	t.Helper()
	seen := []string{}
	after := ""
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("credential cursor walk exceeded 10 pages")
		}
		path := route
		if after != "" {
			path += "&after=" + url.QueryEscape(after)
		}
		status, body, _ := getIndexJSONBody(t, handler, path)
		if status != http.StatusOK {
			t.Fatalf("credential cursor walk status = %d, body = %v", status, body)
		}
		seen = append(seen, credentialPageCIDs(t, body)...)
		if body["next"] == nil {
			return seen
		}
		after = body["next"].(string)
	}
}

func TestIndexCredentialsOrderedPaginationAndBadInputs(t *testing.T) {
	r, store := indexRelay(t)
	handler := r.Handler()
	issuer := ingestIdentity(t, r)
	kid := issuer.did + "#" + issuer.auth.keyID
	now := time.Now().Unix()
	tokens := []string{
		mintCredentialWithExp(t, issuer.did, kid, issuer.auth.priv, "*", "chain:*", "read", now-10, now+3600),
		mintCredentialWithExp(t, issuer.did, kid, issuer.auth.priv, "*", "chain:*", "write", now-20, now+3600),
	}
	want := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if res := r.Ingest([]string{token}); res[0].Status != "new" {
			t.Fatalf("ingest credential: %+v", res[0])
		}
		want = append(want, orderedCredentialCID(t, token))
		time.Sleep(2 * time.Millisecond)
	}

	lexical := walkCredentialPages(t, handler, "/index/v0/credentials?issuer="+url.QueryEscape(issuer.did)+"&limit=1")
	wantLexical := append([]string(nil), want...)
	sort.Strings(wantLexical)
	if !reflect.DeepEqual(lexical, wantLexical) {
		t.Fatalf("lexical credential walk = %v, want %v", lexical, wantLexical)
	}
	for _, order := range []string{"createdAt.desc", "ingestedAt.desc"} {
		walked := walkCredentialPages(t, handler, "/index/v0/credentials?issuer="+url.QueryEscape(issuer.did)+"&order="+order+"&limit=1")
		wantOrdered := []string{want[0], want[1]}
		if order == "ingestedAt.desc" {
			wantOrdered = []string{want[1], want[0]}
		}
		if !reflect.DeepEqual(walked, wantOrdered) {
			t.Fatalf("%s credential walk = %v, want %v", order, walked, wantOrdered)
		}
	}

	status, ordered, _ := getIndexJSONBody(t, handler, "/index/v0/credentials?order=createdAt.desc&limit=1")
	if status != http.StatusOK {
		t.Fatalf("ordered credential status = %d", status)
	}
	wireRow := ordered["credentials"].([]any)[0].(map[string]any)
	if _, ok := wireRow["createdAt"]; ok {
		t.Fatalf("credential wire row leaked createdAt: %v", wireRow)
	}
	if _, ok := wireRow["ingestedAt"]; ok {
		t.Fatalf("credential wire row leaked ingestedAt: %v", wireRow)
	}
	for _, test := range []struct {
		path string
		err  string
	}{
		{"/index/v0/credentials?order=bogus", "invalid order"},
		{"/index/v0/credentials?order=createdAt.desc&after=not-a-cursor", "invalid cursor"},
	} {
		status, body, _ := getIndexJSONBody(t, handler, test.path)
		if status != http.StatusBadRequest || body["error"] != test.err {
			t.Fatalf("%s = status %d body %v", test.path, status, body)
		}
	}

	for _, cid := range want {
		credential, err := store.GetPublicCredentialByCID(cid)
		if err != nil {
			t.Fatal(err)
		}
		operation, err := store.GetOperation(cid)
		if err != nil {
			t.Fatal(err)
		}
		if credential == nil || operation == nil || credential.IngestedAt != operation.IngestedAt {
			t.Fatalf("credential/operation receipt stamps differ: credential=%+v operation=%+v", credential, operation)
		}
	}
}

func TestIndexCredentialCreatedAtIgnoresPayloadCreatedAt(t *testing.T) {
	r, store := indexRelay(t)
	issuer := ingestIdentity(t, r)
	kid := issuer.did + "#" + issuer.auth.keyID
	now := time.Now().Unix()
	spoofIAT := now - 30
	payload := map[string]any{
		"version":   int64(1),
		"type":      "DFOSCredential",
		"iss":       issuer.did,
		"aud":       "*",
		"att":       []any{map[string]any{"resource": "chain:*", "action": "read"}},
		"prf":       []any{},
		"exp":       now + 3600,
		"iat":       spoofIAT,
		"createdAt": "2099-01-01T00:00:00.000Z",
	}
	_, _, spoofCID, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	spoofToken, err := dfos.CreateJWS(dfos.JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:credential",
		Kid: kid,
		CID: spoofCID,
	}, payload, issuer.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	laterToken := mintCredentialWithExp(t, issuer.did, kid, issuer.auth.priv, "*", "chain:*", "write", now-10, now+3600)
	laterCID := orderedCredentialCID(t, laterToken)
	for _, token := range []string{spoofToken, laterToken} {
		if res := r.Ingest([]string{token}); res[0].Status != "new" {
			t.Fatalf("ingest credential: %+v", res[0])
		}
	}

	stored, err := store.GetPublicCredentialByCID(spoofCID)
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil || stored.CreatedAt != credentialCreatedAt(spoofIAT) {
		t.Fatalf("spoofed credential createdAt = %+v, want %s", stored, credentialCreatedAt(spoofIAT))
	}
	rows, err := store.QueryIndexCredentials(IndexCredentialQuery{Order: "createdAt.desc", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	got := []string{rows[0].CID, rows[1].CID}
	want := []string{laterCID, spoofCID}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("createdAt.desc with spoofed payload claim = %v, want %v", got, want)
	}
}

func TestSQLitePublicCredentialTimestampUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential-timestamps.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE operations (
			cid TEXT PRIMARY KEY,
			jws_token TEXT NOT NULL,
			chain_type TEXT NOT NULL,
			chain_id TEXT NOT NULL,
			ingested_at TEXT NOT NULL
		);
		CREATE TABLE public_credentials (
			cid TEXT PRIMARY KEY,
			issuer_did TEXT NOT NULL,
			att JSON NOT NULL,
			exp INTEGER NOT NULL,
			jws_token TEXT NOT NULL
		);`); err != nil {
		t.Fatal(err)
	}
	issuer := createTestIdentity(t)
	now := time.Now().Unix()
	fixtures := []struct {
		iat    int64
		stamp  string
		action string
	}{
		{iat: now - 120, stamp: "2026-09-03T13:34:56.789Z", action: "read"},
		{iat: now - 60, stamp: "2026-09-03T12:34:56.789Z", action: "write"},
	}
	att, _ := json.Marshal([]AttenuationPair{{Resource: "chain:*", Action: "read"}})
	cids := make([]string, 0, len(fixtures))
	for _, fixture := range fixtures {
		token := mintCredentialWithExp(t, issuer.did, issuer.did+"#"+issuer.auth.keyID, issuer.auth.priv, "*", "chain:*", fixture.action, fixture.iat, now+3600)
		cid := orderedCredentialCID(t, token)
		cids = append(cids, cid)
		if _, err := db.Exec("INSERT INTO operations (cid, jws_token, chain_type, chain_id, ingested_at) VALUES (?, ?, 'credential', ?, ?)", cid, token, issuer.did, fixture.stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("INSERT INTO public_credentials (cid, issuer_did, att, exp, jws_token) VALUES (?, ?, ?, ?, ?)", cid, issuer.did, att, now+3600, token); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore upgrade: %v", err)
	}
	defer store.Close()
	for i, cid := range cids {
		credential, err := store.GetPublicCredentialByCID(cid)
		if err != nil {
			t.Fatal(err)
		}
		wantCreatedAt := credentialCreatedAt(fixtures[i].iat)
		if credential == nil || credential.CreatedAt != wantCreatedAt || credential.IngestedAt != fixtures[i].stamp {
			t.Fatalf("upgraded credential = %+v, want createdAt=%s ingestedAt=%s", credential, wantCreatedAt, fixtures[i].stamp)
		}
	}
	queryCIDs := func(q IndexCredentialQuery) []string {
		t.Helper()
		rows, err := store.QueryIndexCredentials(q)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]string, 0, len(rows))
		for _, row := range rows {
			got = append(got, row.CID)
		}
		return got
	}
	if got, want := queryCIDs(IndexCredentialQuery{Order: "createdAt.desc", Limit: 10}), []string{cids[1], cids[0]}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SQLite createdAt.desc = %v, want %v", got, want)
	}
	if got, want := queryCIDs(IndexCredentialQuery{Order: "ingestedAt.desc", Limit: 10}), []string{cids[0], cids[1]}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SQLite ingestedAt.desc = %v, want %v", got, want)
	}
	wantLexical := append([]string(nil), cids...)
	sort.Strings(wantLexical)
	if got := queryCIDs(IndexCredentialQuery{Limit: 10}); !reflect.DeepEqual(got, wantLexical) {
		t.Fatalf("SQLite lexical order = %v, want %v", got, wantLexical)
	}
	first, err := store.QueryIndexCredentials(IndexCredentialQuery{Order: "createdAt.desc", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	remaining := queryCIDs(IndexCredentialQuery{
		OrderedAfter: &indexOrderedCursor{Timestamp: first[0].CreatedAt, Key: first[0].CID},
		Order:        "createdAt.desc",
		Limit:        1,
	})
	if want := []string{cids[0]}; !reflect.DeepEqual(remaining, want) {
		t.Fatalf("SQLite ordered cursor remainder = %v, want %v", remaining, want)
	}
}

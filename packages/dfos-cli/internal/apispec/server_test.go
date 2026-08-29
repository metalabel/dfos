package apispec

// THE FETCH-ORIGIN DOCTRINE, exhaustively.
//
// One property under test, in every shape a document can write it: the authority
// comes from where the document CAME FROM, and `servers` contributes a path
// prefix and nothing else. The interesting cases are the ones where the document
// disagrees with its own origin, because that disagreement is the attack.

import (
	"strings"
	"testing"
)

// serverDoc is one operation whose server URL is the variable under test.
func serverDoc(t *testing.T, server string) *Operation {
	t.Helper()
	body := `openapi: 3.1.0
info: {title: t, version: "1"}
`
	if server != "" {
		body += "servers: [{url: " + server + "}]\n"
	}
	body += `paths:
  /thing: {get: {operationId: getThing}}
`
	op, err := mustParse(t, body).FindOperation("getThing")
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func TestResolveServerAgainstTheFetchOrigin(t *testing.T) {
	const origin = "https://api.example.test"

	t.Run("a same-origin servers entry contributes its path prefix", func(t *testing.T) {
		choice, err := serverDoc(t, `"https://api.example.test/v1"`).ResolveServer(ServerPolicy{FetchOrigin: origin})
		if err != nil {
			t.Fatal(err)
		}
		if choice.Base != "https://api.example.test/v1" {
			t.Fatalf("base = %q", choice.Base)
		}
		if choice.Note != "" {
			t.Fatalf("a same-origin entry needs no disclosure, got %q", choice.Note)
		}
	})

	t.Run("the default port and the case of the host do not make it off-origin", func(t *testing.T) {
		choice, err := serverDoc(t, `"https://API.Example.test:443/v1"`).ResolveServer(ServerPolicy{FetchOrigin: origin})
		if err != nil {
			t.Fatal(err)
		}
		if choice.Note != "" {
			t.Fatalf("host spelling must not read as a different origin: %q", choice.Note)
		}
		if !strings.HasSuffix(choice.Base, "/v1") {
			t.Fatalf("base = %q", choice.Base)
		}
	})

	t.Run("an off-origin entry keeps its PATH and loses its AUTHORITY", func(t *testing.T) {
		choice, err := serverDoc(t, `"https://evil.example.test/v1"`).ResolveServer(ServerPolicy{FetchOrigin: origin})
		if err != nil {
			t.Fatal(err)
		}
		if choice.Base != "https://api.example.test/v1" {
			t.Fatalf("base = %q — the path prefix is kept, the authority is not", choice.Base)
		}
		for _, want := range []string{"evil.example.test", "api.example.test", "--trust-servers", "--server"} {
			if !strings.Contains(choice.Note, want) {
				t.Fatalf("the disclosure must name %q:\n%s", want, choice.Note)
			}
		}
	})

	// The live case this doctrine un-breaks: a served document whose servers
	// entry points at the operator's own dev machine. Every cached copy of it
	// dials localhost until the doctrine ignores the entry.
	t.Run("a servers entry naming localhost does not redirect a remote call", func(t *testing.T) {
		choice, err := serverDoc(t, `"http://localhost:3000"`).ResolveServer(
			ServerPolicy{FetchOrigin: "https://relay.example.test"})
		if err != nil {
			t.Fatal(err)
		}
		if choice.Base != "https://relay.example.test" {
			t.Fatalf("base = %q — a cached localhost servers entry must not aim the request at localhost", choice.Base)
		}
	})

	// Same host, different scheme, is off-origin — and resolving against the
	// fetch origin can only upgrade it.
	t.Run("http named by an https document is off-origin", func(t *testing.T) {
		choice, err := serverDoc(t, `"http://api.example.test/v1"`).ResolveServer(ServerPolicy{FetchOrigin: origin})
		if err != nil {
			t.Fatal(err)
		}
		if choice.Base != "https://api.example.test/v1" {
			t.Fatalf("base = %q", choice.Base)
		}
		if choice.Note == "" {
			t.Fatalf("the scheme change must be disclosed")
		}
	})

	t.Run("a document declaring no server is the origin itself", func(t *testing.T) {
		choice, err := serverDoc(t, "").ResolveServer(ServerPolicy{FetchOrigin: origin + "/"})
		if err != nil {
			t.Fatal(err)
		}
		if choice.Base != origin || choice.Note != "" {
			t.Fatalf("choice = %+v", choice)
		}
	})
}

func TestResolveServerOverrides(t *testing.T) {
	const origin = "https://api.example.test"

	t.Run("--trust-servers sends it where the document says, and says so", func(t *testing.T) {
		choice, err := serverDoc(t, `"https://evil.example.test/v1"`).ResolveServer(
			ServerPolicy{FetchOrigin: origin, TrustServers: true})
		if err != nil {
			t.Fatal(err)
		}
		if choice.Base != "https://evil.example.test/v1" {
			t.Fatalf("base = %q", choice.Base)
		}
		if !strings.Contains(choice.Note, "--trust-servers") {
			t.Fatalf("note = %q", choice.Note)
		}
	})

	t.Run("--server wins over the document AND the origin, silently", func(t *testing.T) {
		choice, err := serverDoc(t, `"https://evil.example.test/v1"`).ResolveServer(
			ServerPolicy{FetchOrigin: origin, Override: "https://staging.example.test/v2/"})
		if err != nil {
			t.Fatal(err)
		}
		// Nothing to disclose: the operator named the base themselves.
		if choice.Base != "https://staging.example.test/v2" || choice.Note != "" {
			t.Fatalf("choice = %+v", choice)
		}
	})

	t.Run("--server must be an absolute http(s) URL", func(t *testing.T) {
		for _, bad := range []string{"/v1", "ftp://api.example.test", "api.example.test"} {
			if _, err := serverDoc(t, "").ResolveServer(ServerPolicy{FetchOrigin: origin, Override: bad}); err == nil {
				t.Fatalf("--server %q must be refused", bad)
			}
		}
	})
}

// A --file registration has no fetch origin at all, so the document's own
// servers are the only thing left — and they must AGREE.
func TestResolveServerWithoutAnOrigin(t *testing.T) {
	t.Run("one origin across every servers entry is used, and echoed", func(t *testing.T) {
		choice, err := serverDoc(t, `"https://api.example.test/v1"`).ResolveServer(ServerPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		if choice.Base != "https://api.example.test/v1" {
			t.Fatalf("base = %q", choice.Base)
		}
		if !strings.Contains(choice.Note, "https://api.example.test") {
			t.Fatalf("the origin actually used must be echoed, got %q", choice.Note)
		}
	})

	t.Run("two origins is refused, distinguishably", func(t *testing.T) {
		op, err := mustParse(t, `openapi: 3.1.0
info: {title: t, version: "1"}
servers: [{url: "https://api.example.test"}]
paths:
  /a: {get: {operationId: getA}}
  /b: {get: {operationId: getB, servers: [{url: "https://other.example.test"}]}}
`).FindOperation("getA")
		if err != nil {
			t.Fatal(err)
		}
		_, err = op.ResolveServer(ServerPolicy{})
		if err == nil {
			t.Fatal("a document spanning two origins with no fetch origin must be refused")
		}
		for _, want := range []string{"2 origins", "api.example.test", "other.example.test", "--server"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("the refusal must name %q:\n%v", want, err)
			}
		}
	})

	t.Run("no server at all is refused, and named as its own case", func(t *testing.T) {
		_, err := serverDoc(t, "").ResolveServer(ServerPolicy{})
		if err == nil || !strings.Contains(err.Error(), "declares no server") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a relative server URL is refused, and named as its own case", func(t *testing.T) {
		_, err := serverDoc(t, `"/v1"`).ResolveServer(ServerPolicy{})
		if err == nil || !strings.Contains(err.Error(), "relative server URL") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("--server rescues every one of those", func(t *testing.T) {
		for _, server := range []string{"", `"/v1"`, `"https://api.example.test"`} {
			choice, err := serverDoc(t, server).ResolveServer(ServerPolicy{Override: "https://named.example.test"})
			if err != nil {
				t.Fatalf("server %q: %v", server, err)
			}
			if choice.Base != "https://named.example.test" {
				t.Fatalf("base = %q", choice.Base)
			}
		}
	})
}

// The join with the operation path is where a trailing slash used to double up
// (#355). The doctrine's rewriting of the base must not lose that.
func TestResolvedBaseStillJoinsCleanly(t *testing.T) {
	for _, server := range []string{`"https://evil.example.test/v1"`, `"https://evil.example.test/v1/"`} {
		choice, err := serverDoc(t, server).ResolveServer(ServerPolicy{FetchOrigin: "https://api.example.test/"})
		if err != nil {
			t.Fatal(err)
		}
		full, err := JoinServerPath(choice.Base, "/thing")
		if err != nil {
			t.Fatal(err)
		}
		if full != "https://api.example.test/v1/thing" {
			t.Fatalf("server %q produced %q", server, full)
		}
	}
}

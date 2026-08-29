package apispec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimalDoc = `{"openapi":"3.1.1","info":{"title":"t","version":"1"},"paths":{"/x":{"get":{"operationId":"x"}}}}`

// stubFetcher answers exactly the URLs it is given and fails every other.
func stubFetcher(t *testing.T, responses map[string]string) (Fetcher, *[]string) {
	t.Helper()
	var asked []string
	return func(rawURL string) (Fetched, error) {
		asked = append(asked, rawURL)
		if body, ok := responses[rawURL]; ok {
			return Fetched{Data: []byte(body)}, nil
		}
		return Fetched{}, fmt.Errorf("HTTP 404")
	}, &asked
}

func TestResolveSourceForms(t *testing.T) {
	t.Run("a bare host takes the well-known advertisement when there is one", func(t *testing.T) {
		fetch, asked := stubFetcher(t, map[string]string{
			"https://relay.example.test/.well-known/dfos-relay": `{"did":"did:dfos:x","openapi":"/spec/openapi.json"}`,
			"https://relay.example.test/spec/openapi.json":      minimalDoc,
		})
		res, err := Resolve("relay.example.test", "", fetch)
		if err != nil {
			t.Fatalf("Resolve: %v (asked %v)", err, *asked)
		}
		if res.Kind != KindWellKnown {
			t.Fatalf("Kind = %q", res.Kind)
		}
		if res.Document != "https://relay.example.test/spec/openapi.json" {
			t.Fatalf("Document = %q", res.Document)
		}
		if res.Origin != "https://relay.example.test" {
			t.Fatalf("Origin = %q", res.Origin)
		}
	})

	t.Run("an absolute well-known advertisement is honored as written", func(t *testing.T) {
		fetch, _ := stubFetcher(t, map[string]string{
			"https://relay.example.test/.well-known/dfos-relay": `{"openapi":"https://docs.example.test/o.json"}`,
			"https://docs.example.test/o.json":                  minimalDoc,
		})
		res, err := Resolve("relay.example.test", "", fetch)
		if err != nil {
			t.Fatal(err)
		}
		if res.Document != "https://docs.example.test/o.json" {
			t.Fatalf("Document = %q", res.Document)
		}
	})

	t.Run("a host that advertises nothing falls back to the conventional path", func(t *testing.T) {
		fetch, asked := stubFetcher(t, map[string]string{
			"https://api.example.test/openapi.json": minimalDoc,
		})
		res, err := Resolve("api.example.test", "", fetch)
		if err != nil {
			t.Fatal(err)
		}
		if res.Kind != KindConventional {
			t.Fatalf("Kind = %q", res.Kind)
		}
		// The well-known probe runs FIRST and its failure is not an error: a
		// host that serves an API and no relay surface is the common case.
		if len(*asked) != 2 || (*asked)[0] != "https://api.example.test/.well-known/dfos-relay" {
			t.Fatalf("probe order = %v", *asked)
		}
	})

	t.Run("a URL with a path is fetched outright, with no discovery", func(t *testing.T) {
		fetch, asked := stubFetcher(t, map[string]string{
			"https://api.example.test/v2/spec.json": minimalDoc,
		})
		res, err := Resolve("https://api.example.test/v2/spec.json", "", fetch)
		if err != nil {
			t.Fatal(err)
		}
		if res.Kind != KindDirect {
			t.Fatalf("Kind = %q", res.Kind)
		}
		if len(*asked) != 1 {
			t.Fatalf("a direct URL must cost exactly one fetch, asked %v", *asked)
		}
		if res.Origin != "https://api.example.test" {
			t.Fatalf("Origin = %q", res.Origin)
		}
	})

	t.Run("a scheme and host with no path is still discovery", func(t *testing.T) {
		fetch, _ := stubFetcher(t, map[string]string{
			"https://api.example.test/openapi.json": minimalDoc,
		})
		res, err := Resolve("https://api.example.test/", "", fetch)
		if err != nil {
			t.Fatal(err)
		}
		if res.Kind != KindConventional {
			t.Fatalf("Kind = %q", res.Kind)
		}
	})

	t.Run("--file reads from disk and makes no request at all", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "openapi.json")
		if err := os.WriteFile(path, []byte(minimalDoc), 0o600); err != nil {
			t.Fatal(err)
		}
		fetch, asked := stubFetcher(t, nil)
		res, err := Resolve("", path, fetch)
		if err != nil {
			t.Fatal(err)
		}
		if res.Kind != KindFile || len(*asked) != 0 {
			t.Fatalf("Kind = %q, asked %v", res.Kind, *asked)
		}
	})

	t.Run("a source that is not an OpenAPI document fails at registration", func(t *testing.T) {
		fetch, _ := stubFetcher(t, map[string]string{
			"https://api.example.test/openapi.json": `{"hello":"world"}`,
		})
		if _, err := Resolve("api.example.test", "", fetch); err == nil {
			t.Fatalf("registration must refuse a document that is not OpenAPI")
		}
	})

	t.Run("a host serving nothing reports both places it looked", func(t *testing.T) {
		fetch, _ := stubFetcher(t, nil)
		_, err := Resolve("api.example.test", "", fetch)
		if err == nil {
			t.Fatal("expected an error")
		}
		for _, want := range []string{"/.well-known/dfos-relay", "/openapi.json"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want it to name %s", err, want)
			}
		}
	})

	t.Run("a non-http scheme is refused", func(t *testing.T) {
		fetch, _ := stubFetcher(t, nil)
		if _, err := Resolve("ftp://api.example.test/o.json", "", fetch); err == nil {
			t.Fatalf("a non-http source must be refused")
		}
	})
}

// redirectingFetcher answers each URL with a body and the URL it ended up at —
// a 302 the http client already followed by the time the fetcher returns.
func redirectingFetcher(responses map[string]redirected) Fetcher {
	return func(rawURL string) (Fetched, error) {
		answer, ok := responses[rawURL]
		if !ok {
			return Fetched{}, fmt.Errorf("HTTP 404")
		}
		return Fetched{Data: []byte(answer.body), FinalURL: answer.finalURL}, nil
	}
}

type redirected struct {
	body     string
	finalURL string
}

// THE ORIGIN RECORDED IS THE ORIGIN THAT ANSWERED.
//
// Every `servers` entry in a document resolves against the origin the document
// was fetched from, so a redirect that crosses origins would file host B's
// document under host A's name and aim A-bound requests using B's paths. It is
// refused rather than re-attributed; a same-origin redirect changes nothing that
// the doctrine reads and is transparent.
func TestResolveRefusesACrossOriginRedirect(t *testing.T) {
	t.Run("the document fetch", func(t *testing.T) {
		fetch := redirectingFetcher(map[string]redirected{
			"https://a.example.test/openapi.json": {body: minimalDoc, finalURL: "https://b.example.test/openapi.json"},
		})
		_, err := Resolve("https://a.example.test/openapi.json", "", fetch)
		if err == nil {
			t.Fatal("a document served from another origin must not be recorded as this one's")
		}
		for _, want := range []string{"https://a.example.test", "https://b.example.test", "--file"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("the refusal must name %q:\n%v", want, err)
			}
		}
	})

	t.Run("the conventional discovery fetch", func(t *testing.T) {
		fetch := redirectingFetcher(map[string]redirected{
			"https://a.example.test/openapi.json": {body: minimalDoc, finalURL: "https://b.example.test/openapi.json"},
		})
		if _, err := Resolve("a.example.test", "", fetch); err == nil {
			t.Fatal("discovery must refuse a document that crossed origins")
		}
	})

	// A well-known that redirects off-origin is not this host's advertisement, so
	// the probe fails and discovery falls through to the convention — the same
	// path an absent well-known takes.
	t.Run("a redirected well-known probe falls through to the convention", func(t *testing.T) {
		fetch := redirectingFetcher(map[string]redirected{
			"https://a.example.test/.well-known/dfos-relay": {
				body:     `{"openapi":"https://b.example.test/o.json"}`,
				finalURL: "https://b.example.test/.well-known/dfos-relay",
			},
			"https://a.example.test/openapi.json": {body: minimalDoc},
		})
		res, err := Resolve("a.example.test", "", fetch)
		if err != nil {
			t.Fatal(err)
		}
		if res.Kind != KindConventional || res.Document != "https://a.example.test/openapi.json" {
			t.Fatalf("resolution = %q at %q", res.Kind, res.Document)
		}
	})

	t.Run("a same-origin redirect is transparent", func(t *testing.T) {
		fetch := redirectingFetcher(map[string]redirected{
			"https://a.example.test/openapi.json": {body: minimalDoc, finalURL: "https://a.example.test/spec/openapi.json"},
		})
		res, err := Resolve("https://a.example.test/openapi.json", "", fetch)
		if err != nil {
			t.Fatal(err)
		}
		if res.Origin != "https://a.example.test" {
			t.Fatalf("Origin = %q", res.Origin)
		}
	})
}

func TestStoreRoundTripAndStaleness(t *testing.T) {
	store := NewStoreIn(t.TempDir())

	if _, err := store.Get("nope"); err == nil {
		t.Fatalf("an unregistered name must be an error")
	}
	list, err := store.List()
	if err != nil || len(list) != 0 {
		t.Fatalf("empty registry: %v %v", list, err)
	}

	fresh := Registration{Name: "dfos", Source: "api.dfos.com", Document: "https://api.dfos.com/openapi.json",
		Kind: KindConventional, FetchedAt: time.Now()}
	if err := store.Put(fresh, []byte(minimalDoc)); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get("dfos")
	if err != nil {
		t.Fatal(err)
	}
	if got.Document != fresh.Document {
		t.Fatalf("round trip lost the document URL: %+v", got)
	}
	if got.Stale(time.Now()) {
		t.Fatalf("a just-fetched document must not read as stale")
	}
	if !got.Stale(time.Now().Add(StaleAfter + time.Minute)) {
		t.Fatalf("a document past the horizon must read as stale")
	}

	data, err := store.Document("dfos")
	if err != nil || string(data) != minimalDoc {
		t.Fatalf("cached document = %q, %v", data, err)
	}

	if err := store.Remove("dfos"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Document("dfos"); err == nil {
		t.Fatalf("rm must drop the cached document too")
	}
	if err := store.Remove("dfos"); err == nil {
		t.Fatalf("removing twice must be an error")
	}
}

func TestValidateNameRefusesPathTraversal(t *testing.T) {
	for _, bad := range []string{"", "../etc", "a/b", "-leading", ".hidden", strings.Repeat("x", 65)} {
		if err := ValidateName(bad); err == nil {
			t.Fatalf("ValidateName(%q) must fail", bad)
		}
	}
	for _, ok := range []string{"dfos", "api.dfos.com", "my_api-2"} {
		if err := ValidateName(ok); err != nil {
			t.Fatalf("ValidateName(%q) = %v", ok, err)
		}
	}
}

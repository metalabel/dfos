package apispec

// Resolving a source into an OpenAPI document.
//
// Three forms, and the rule that separates them is mechanical rather than
// heuristic:
//
//	--file <path>            the document is on disk
//	<url with a path>        the document is at that exact URL
//	<host> or <scheme://host> DISCOVERY: ask the host, then assume the convention
//
// Discovery asks the host's `/.well-known/dfos-relay` for its `openapi` member
// (WEB-RELAY.md: a relay that serves a document advertises it there, absolute or
// root-relative) and falls back to `/openapi.json`, which is where the canonical
// deployment serves its own.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// wellKnownPath is the relay discovery document; conventionalPath is the
// assumption made when it advertises nothing.
const (
	wellKnownPath    = "/.well-known/dfos-relay"
	conventionalPath = "/openapi.json"
)

// Fetcher retrieves a URL. It is an argument rather than a package-level client
// so tests drive resolution against a loopback server without a global.
type Fetcher func(rawURL string) ([]byte, error)

// HTTPFetcher is the default Fetcher: a plain GET with a bounded timeout and a
// bounded read.
func HTTPFetcher() Fetcher {
	client := &http.Client{Timeout: 30 * time.Second}
	return func(rawURL string) ([]byte, error) {
		resp, err := client.Get(rawURL)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", rawURL, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch %s: HTTP %d", rawURL, resp.StatusCode)
		}
		// One byte PAST the limit, so an over-size body is DETECTED rather than
		// silently truncated to exactly the limit — a truncated document parses
		// as a malformed one, and reports itself as a syntax error that is not
		// there. Parse checks the length and says the honest thing.
		data, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocumentBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", rawURL, err)
		}
		return data, nil
	}
}

// Resolution is where a document came from and what it is.
type Resolution struct {
	Document string
	Kind     SourceKind
	// Origin is the API's base origin — the scheme and authority the document
	// was served from, which is what a relative server URL resolves against.
	Origin string
	Data   []byte
	Doc    *Doc
}

// Resolve turns a source (or a --file path) into a parsed, validated document.
// The document is parsed here, not at call time: a source that is not an
// OpenAPI document is a registration failure, never a surprise on some later call.
func Resolve(source, file string, fetch Fetcher) (*Resolution, error) {
	res, err := locate(source, file, fetch)
	if err != nil {
		return nil, err
	}
	doc, err := Parse(res.Data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", res.Document, err)
	}
	res.Doc = doc
	return res, nil
}

func locate(source, file string, fetch Fetcher) (*Resolution, error) {
	if file != "" {
		if source != "" {
			return nil, fmt.Errorf("pass a source or --file, not both")
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", file, err)
		}
		abs := file
		if resolved, err := filepath.Abs(file); err == nil {
			abs = resolved
		}
		return &Resolution{Document: abs, Kind: KindFile, Data: data}, nil
	}
	if source == "" {
		return nil, fmt.Errorf("name a source: a host (api.dfos.com), an OpenAPI document URL, or --file <path>")
	}

	base, documentURL, err := splitSource(source)
	if err != nil {
		return nil, err
	}
	if documentURL != "" {
		data, err := fetch(documentURL)
		if err != nil {
			return nil, err
		}
		return &Resolution{Document: documentURL, Kind: KindDirect, Origin: base, Data: data}, nil
	}

	// Discovery. The well-known probe is allowed to fail for any reason — a host
	// that serves an API and no relay surface is the common case, not an error —
	// so its failure falls through to the convention rather than aborting.
	if advertised, ok := wellKnownOpenAPI(base, fetch); ok {
		if data, err := fetch(advertised); err == nil {
			return &Resolution{Document: advertised, Kind: KindWellKnown, Origin: base, Data: data}, nil
		} else {
			return nil, fmt.Errorf("%s advertises its OpenAPI document at %s, which did not fetch: %w", base, advertised, err)
		}
	}
	conventional := base + conventionalPath
	data, err := fetch(conventional)
	if err != nil {
		return nil, fmt.Errorf("no OpenAPI document found for %s: nothing advertised at %s, and %s did not fetch: %w",
			base, base+wellKnownPath, conventional, err)
	}
	return &Resolution{Document: conventional, Kind: KindConventional, Origin: base, Data: data}, nil
}

// splitSource reads a source argument as either a host to discover against or a
// document URL to fetch outright. A URL carrying a path beyond "/" names a
// document; a bare host, or a scheme and authority alone, names a host.
func splitSource(source string) (base, documentURL string, err error) {
	raw := strings.TrimSpace(source)
	if raw == "" {
		return "", "", fmt.Errorf("empty source")
	}
	if !strings.Contains(raw, "://") {
		// A bare authority. https, always: `api:` surfaces are HTTPS surfaces.
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("source %q is neither a host nor a URL: %w", source, err)
	}
	switch parsed.Scheme {
	case "http", "https":
	default:
		return "", "", fmt.Errorf("source %q must be an http or https URL, or a bare host", source)
	}
	if parsed.Host == "" {
		return "", "", fmt.Errorf("source %q names no host", source)
	}
	base = parsed.Scheme + "://" + parsed.Host
	if parsed.Path != "" && parsed.Path != "/" {
		return base, parsed.String(), nil
	}
	if parsed.RawQuery != "" {
		return base, parsed.String(), nil
	}
	return base, "", nil
}

// wellKnownOpenAPI reads the `openapi` member of a relay's well-known response.
// The value is absolute, or root-relative against the relay's base URL.
func wellKnownOpenAPI(base string, fetch Fetcher) (string, bool) {
	data, err := fetch(base + wellKnownPath)
	if err != nil {
		return "", false
	}
	var info struct {
		OpenAPI string `json:"openapi"`
	}
	if err := json.Unmarshal(data, &info); err != nil || strings.TrimSpace(info.OpenAPI) == "" {
		return "", false
	}
	value := strings.TrimSpace(info.OpenAPI)
	parsed, err := url.Parse(value)
	if err != nil {
		return "", false
	}
	if parsed.IsAbs() {
		return parsed.String(), true
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	return baseURL.ResolveReference(parsed).String(), true
}

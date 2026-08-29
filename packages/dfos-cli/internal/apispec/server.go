package apispec

// WHERE A REQUEST ACTUALLY GOES.
//
// The document is discovery, never authority (API-AUTH.md) — and the authority a
// document NAMES is exactly the thing it must not be trusted to name. A document
// fetched from host A whose `servers` entry says host B, sent to host B, is a
// document redirecting the wire: whoever can serve A a document can aim this
// client anywhere, and the request that leaves carries whatever artifact the
// profile for B says to attach.
//
// So the FETCH ORIGIN decides the authority, and `servers` contributes a PATH
// PREFIX ONLY: a `servers` url of https://api.example.com/v1 fetched from
// api.example.com contributes `/v1`, and the same entry fetched from anywhere
// else contributes `/v1` and nothing more. An off-origin entry is ignored for
// authority, said out loud on stderr, and honored only when the caller asks for
// it by name (`--trust-servers`) or names the base outright (`--server <url>`).
//
// A `--file` registration has NO fetch origin, so there is nothing to fall back
// to. Its servers must agree on one origin — that origin is echoed when it is
// used — or the caller names one. Two origins is refused rather than resolved:
// picking one of them for a caller is the same trust this doctrine withholds.

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
)

// ServerPolicy is what a caller allows when resolving where a request goes.
type ServerPolicy struct {
	// FetchOrigin is the scheme://authority the document was served from — the
	// authority every request resolves against. Empty for a document read from
	// disk, which has no fetch origin at all.
	FetchOrigin string
	// Override is an explicit base URL (`--server`). It wins over everything,
	// document and origin alike: a caller who names a base is not guessing.
	Override string
	// TrustServers lets an off-origin `servers` entry name the authority
	// (`--trust-servers`). Off by default, deliberately.
	TrustServers bool
}

// ServerChoice is the base URL a request hangs off, plus whatever had to be said
// out loud to arrive at it.
type ServerChoice struct {
	// Base is the absolute base URL, trailing slashes stripped.
	Base string
	// Note is a one-line disclosure for stderr, empty when there is nothing to
	// disclose.
	Note string
}

// ResolveServer computes the base URL for one operation under the fetch-origin
// doctrine above.
func (o *Operation) ResolveServer(p ServerPolicy) (ServerChoice, error) {
	if override := strings.TrimSpace(p.Override); override != "" {
		base, err := absoluteBase(override, "--server")
		if err != nil {
			return ServerChoice{}, err
		}
		return ServerChoice{Base: base}, nil
	}

	declared := o.declaredServer()
	if strings.TrimSpace(p.FetchOrigin) == "" {
		return o.doc.serverWithoutAnOrigin(declared)
	}

	origin, err := absoluteBase(p.FetchOrigin, "the origin this document was fetched from")
	if err != nil {
		return ServerChoice{}, err
	}
	originURL, err := url.Parse(origin)
	if err != nil {
		return ServerChoice{}, fmt.Errorf("origin %q does not parse: %w", origin, err)
	}
	if declared == "" {
		return ServerChoice{Base: origin}, nil
	}

	parsed, err := url.Parse(strings.TrimSpace(declared))
	if err != nil {
		return ServerChoice{}, fmt.Errorf("the document's server URL %q does not parse: %w", declared, err)
	}
	// A relative server URL names no authority, so there is nothing here to
	// distrust: it is already a path prefix, and it already resolves against the
	// origin the document came from.
	if !parsed.IsAbs() {
		return ServerChoice{Base: strings.TrimRight(originURL.ResolveReference(parsed).String(), "/")}, nil
	}
	if sameOrigin(parsed, originURL) {
		return ServerChoice{Base: strings.TrimRight(parsed.String(), "/")}, nil
	}

	if p.TrustServers {
		return ServerChoice{
			Base: strings.TrimRight(parsed.String(), "/"),
			Note: fmt.Sprintf("note: --trust-servers — calling %s, the authority this document names, rather than %s, the origin it came from.",
				originOf(parsed), originOf(originURL)),
		}, nil
	}
	prefix := strings.TrimRight(parsed.EscapedPath(), "/")
	return ServerChoice{
		Base: origin + prefix,
		Note: fmt.Sprintf("note: this document's servers entry names %s, which is not the origin it came from (%s) — the request goes to %s%s. A document is discovery, never authority; --trust-servers sends it where the document says, --server <url> names a base outright.",
			originOf(parsed), originOf(originURL), origin, prefix),
	}, nil
}

// serverWithoutAnOrigin resolves a document that has no fetch origin at all —
// one read from disk. The document's own servers are the only thing left, so
// they must agree on one origin, and the one they agree on is echoed.
func (d *Doc) serverWithoutAnOrigin(declared string) (ServerChoice, error) {
	const noOrigin = "this document was read from a file, so there is no origin to resolve against"
	if declared == "" {
		return ServerChoice{}, fmt.Errorf("%s, and it declares no server — name the base outright with --server <url>", noOrigin)
	}
	origins, relative := d.declaredOrigins()
	if relative {
		return ServerChoice{}, fmt.Errorf("%s, and it declares a relative server URL — name the base outright with --server <url>", noOrigin)
	}
	if len(origins) != 1 {
		return ServerChoice{}, fmt.Errorf("%s, and its servers name %d origins (%s) — name the one you mean with --server <url>",
			noOrigin, len(origins), strings.Join(origins, ", "))
	}
	parsed, err := url.Parse(strings.TrimSpace(declared))
	if err != nil {
		return ServerChoice{}, fmt.Errorf("the document's server URL %q does not parse: %w", declared, err)
	}
	return ServerChoice{
		Base: strings.TrimRight(parsed.String(), "/"),
		Note: fmt.Sprintf("note: no fetch origin (this document was read from a file) — using %s, the one origin its servers name.", origins[0]),
	}, nil
}

// declaredServer is the server URL that governs this operation: its own, then
// the path item's, then the document's. Empty when nothing declares one.
func (o *Operation) declaredServer() string {
	for _, set := range [][]*v3.Server{o.op.Servers, o.pathItem.Servers, o.doc.model.Model.Servers} {
		for _, s := range set {
			if s != nil && s.URL != "" {
				return s.URL
			}
		}
	}
	return ""
}

// declaredOrigins is every distinct origin the document's servers name, anywhere
// — document, path item, or operation — and whether any of them is relative and
// therefore names no origin at all.
func (d *Doc) declaredOrigins() (origins []string, relative bool) {
	seen := map[string]bool{}
	consider := func(raw string) {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || !parsed.IsAbs() || parsed.Host == "" {
			relative = true
			return
		}
		origin := originOf(parsed)
		if !seen[origin] {
			seen[origin] = true
			origins = append(origins, origin)
		}
	}
	for _, op := range d.Operations() {
		for _, set := range [][]*v3.Server{d.model.Model.Servers, op.pathItem.Servers, op.op.Servers} {
			for _, s := range set {
				if s != nil && s.URL != "" {
					consider(s.URL)
				}
			}
		}
	}
	for _, s := range d.model.Model.Servers {
		if s != nil && s.URL != "" {
			consider(s.URL)
		}
	}
	sort.Strings(origins)
	return origins, relative
}

// Authorities returns the distinct authorities the document's operations resolve
// to under a policy — the `<host>` half of the `api:<host>` resource a credential
// for this API names — and the distinct disclosures resolving them produced.
//
// A list rather than a value because nothing says a document describes one host:
// under `--trust-servers`, or from a file, a document can still span two. The
// caller decides what to do with more than one; this only refuses to pick.
func (d *Doc) Authorities(p ServerPolicy) (authorities, notes []string, err error) {
	seenAuthority, seenNote := map[string]bool{}, map[string]bool{}
	for _, op := range d.Operations() {
		choice, err := op.ResolveServer(p)
		if err != nil {
			return nil, nil, err
		}
		parsed, err := url.Parse(choice.Base)
		if err != nil {
			return nil, nil, fmt.Errorf("server URL %q does not parse: %w", choice.Base, err)
		}
		authority := NormalizeAuthority(parsed.Scheme, parsed.Host)
		if authority != "" && !seenAuthority[authority] {
			seenAuthority[authority] = true
			authorities = append(authorities, authority)
		}
		if choice.Note != "" && !seenNote[choice.Note] {
			seenNote[choice.Note] = true
			notes = append(notes, choice.Note)
		}
	}
	return authorities, notes, nil
}

// absoluteBase reads a caller-supplied or registration-supplied base URL. A base
// carries no query and no fragment, and it is always http or https.
func absoluteBase(raw, label string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%s (%q) does not parse: %w", label, raw, err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return "", fmt.Errorf("%s (%q) must be an absolute http or https URL", label, raw)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("%s (%q) names no host", label, raw)
	}
	parsed.RawQuery, parsed.Fragment = "", ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

// sameOrigin compares scheme and authority, with the default port dropped on
// both sides. The scheme is part of it: an https document naming http://itself
// is off-origin, and resolving against the fetch origin upgrades it.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		NormalizeAuthority(a.Scheme, a.Host) == NormalizeAuthority(b.Scheme, b.Host)
}

// originOf is the display spelling of a URL's origin.
func originOf(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + NormalizeAuthority(u.Scheme, u.Host)
}

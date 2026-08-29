package apispec

// Building the exact request an operation names — and the exact string a proof
// binds.
//
// The origin-form target is computed ONCE and used for both: the proof's `path`
// member and the request line come from the same bytes, so no normalization
// anywhere can fork the signed request from the sent one (API-AUTH.md: "`path`
// is the wire string, not a normalization").

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
)

// Request is one fully-resolved call: where it goes, and what a proof binds.
type Request struct {
	Method string
	// URL is the absolute URL to send to.
	URL string
	// Authority is the lowercase host[:port] with a DEFAULT port dropped — the
	// `host` member a proof binds and the `<host>` of the `api:<host>` resource.
	Authority string
	// Target is the origin-form request target — path plus query string, byte
	// for byte — the `path` member a proof binds.
	Target string
	Body   []byte
}

// NormalizeAuthority is the `host` member API-AUTH binds: the lowercase
// authority with the port OMITTED when it is the scheme's default (https:443,
// http:80) and carried otherwise.
//
// The default-port drop is not cosmetic. The TS twin derives its host from
// WHATWG `URL.host`, which already drops :443 and :80, and a verifier compares a
// proof's `host` byte for byte against its own configured authority. A Go signer
// that kept the explicit default port would sign a host no normally configured
// deployment matches — a 401 the two stacks disagree about, from a URL spelling
// the operator is entitled to use.
//
// TWIN: client.normalizeAuthority is the same rule for the relay client. They
// are separate because neither package imports the other, and both implement one
// paragraph of API-AUTH.md — change them together.
func NormalizeAuthority(scheme, hostport string) string {
	host := strings.ToLower(hostport)
	switch strings.ToLower(scheme) {
	case "https":
		return strings.TrimSuffix(host, ":443")
	case "http":
		return strings.TrimSuffix(host, ":80")
	}
	return host
}

// BuildRequest resolves an operation's path template and parameters against the
// values the caller supplied, and returns the request those values name.
//
// params maps parameter NAME to value. Names are matched against the
// operation's declared parameters: a path parameter is substituted into the
// template, a query parameter is appended, and an undeclared name is an error
// rather than a silently-dropped argument.
func (o *Operation) BuildRequest(serverURL string, params map[string]string, body []byte) (*Request, error) {
	declared := o.Parameters()
	byName := map[string]*v3.Parameter{}
	for _, p := range declared {
		byName[p.Name] = p
	}

	pathValues := map[string]string{}
	query := url.Values{}
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("%s declares no parameter %q (it declares %s)",
				o.Label(), name, describeParameters(declared))
		}
		switch strings.ToLower(p.In) {
		case "path":
			pathValues[name] = params[name]
		case "query":
			query.Set(name, params[name])
		default:
			return nil, fmt.Errorf("parameter %q of %s is in %q — this client passes path and query parameters only",
				name, o.Label(), p.In)
		}
	}

	var missing []string
	for _, p := range declared {
		if p.Required == nil || !*p.Required {
			continue
		}
		if _, ok := params[p.Name]; !ok {
			missing = append(missing, p.Name+" ("+p.In+")")
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%s requires %s — pass each as --param <name>=<value>",
			o.Label(), strings.Join(missing, ", "))
	}

	resolvedPath, err := substitutePath(o.Path, pathValues)
	if err != nil {
		return nil, err
	}
	full, err := JoinServerPath(serverURL, resolvedPath)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(full)
	if err != nil {
		return nil, fmt.Errorf("build request URL %q: %w", full, err)
	}
	if len(query) > 0 {
		parsed.RawQuery = query.Encode()
	}

	return &Request{
		Method:    o.Method,
		URL:       parsed.String(),
		Authority: NormalizeAuthority(parsed.Scheme, parsed.Host),
		// RequestURI is the origin-form target the Go client will put on the
		// request line, derived from the same parsed URL the request uses.
		Target: parsed.RequestURI(),
		Body:   body,
	}, nil
}

// substitutePath fills `{name}` placeholders. A placeholder with no value is an
// error: a template segment left literal would call a route that does not exist.
func substitutePath(template string, values map[string]string) (string, error) {
	var out strings.Builder
	rest := template
	for {
		open := strings.Index(rest, "{")
		if open < 0 {
			out.WriteString(rest)
			break
		}
		close := strings.Index(rest[open:], "}")
		if close < 0 {
			return "", fmt.Errorf("path template %q has an unclosed '{'", template)
		}
		close += open
		name := rest[open+1 : close]
		value, ok := values[name]
		if !ok {
			return "", fmt.Errorf("path parameter %q has no value — pass --param %s=<value>", name, name)
		}
		out.WriteString(rest[:open])
		out.WriteString(url.PathEscape(value))
		rest = rest[close+1:]
	}
	return out.String(), nil
}

func describeParameters(params []*v3.Parameter) string {
	if len(params) == 0 {
		return "none"
	}
	described := make([]string, 0, len(params))
	for _, p := range params {
		label := p.Name + " (" + p.In
		if p.Required != nil && *p.Required {
			label += ", required"
		}
		described = append(described, label+")")
	}
	sort.Strings(described)
	return strings.Join(described, ", ")
}

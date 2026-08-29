package relay

/*

  OPENAPI DOCUMENT — the relay's advertised HTTP surface

  WEB-RELAY.md makes serving an OpenAPI document a SHOULD and the well-known's
  `openapi` field the advertisement: a relay that serves one names its URL, and
  absence of the field means none is served. This relay serves one at
  /openapi.json and advertises "/openapi.json" (root-relative, resolved against
  the relay's base URL).

  THE TWO REFERENCE TWINS DIFFER HERE, DELIBERATELY. This relay advertises
  unconditionally; the TS twin advertises only when its caller passes
  createRelay({ openapi: { document } }), and otherwise mounts no route and omits
  the field. Serving is a SHOULD, so both defaults are conformant, and the
  difference is one of packaging rather than protocol: the TS relay is a library
  embedded in someone else's app, where the quiet default is the polite one,
  while this package is what `dfos serve` runs as a deployed relay, where one
  that holds a description of its own surface and declines to say so is just
  less useful. The cost is that relay-conformance/scripts/parity-serve.ts has to opt
  the TS twin in, because the parity gate byte-compares the two well-known
  bodies. Read that opt-in as this note's consequence, not as a workaround for a
  bug.

  THE DOCUMENT IS A COPY, DELIBERATELY. openapi.yaml here is a verbatim copy of
  packages/dfos-web-relay/openapi.yaml, the canonical description of the wire
  surface BOTH reference relays serve. Go's //go:embed cannot reach outside its
  own package directory, so the alternative to a copy is a second, independently
  drifting hand-written document — strictly worse. TestOpenAPIDocumentMatchesCanonical
  is the drift guard: it byte-compares this copy against the canonical file
  (modulo the info.version line, which the release version-sync stamps on the
  canonical only) and names the one-line fix when they diverge.

  THE DOCUMENT DESCRIBES THE FAMILY; THE SERVED COPY DESCRIBES THIS RELAY. The
  canonical file names no `servers`, because there is no host it could name that
  would be true of every relay serving that surface. This relay writes its own
  configured Authority into the served copy's `servers`, so a client reading the
  document resolves operations against THIS relay rather than against whatever
  host the document was authored on. renderOpenAPI carries the full reasoning,
  including why an unconfigured authority correctly yields no `servers` at all.

  YAML in, JSON out: the canonical file is YAML (readable, reviewable, diffable),
  while the served representation is JSON — every OpenAPI consumer reads JSON,
  and the route can then be a plain application/json GET with no content
  negotiation. The conversion runs once, lazily, and is cached.

  The document is DISCOVERY, NEVER AUTHORITY (WEB-RELAY.md): the routes,
  capability gates, and auth rules in the spec govern regardless of what this
  document says. Which is also why the route itself is ungated — a meta surface
  like the well-known, readable before a client knows anything about this relay.

*/

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"
)

// openapiPath is the root-relative URL the document is served at and the value
// the well-known advertises in its `openapi` field. One const so the route and
// the advertisement can never disagree.
const openapiPath = "/openapi.json"

//go:embed openapi.yaml
var openapiYAML []byte

// loopbackHosts are the hosts reached in the clear. `api:` surfaces are HTTPS
// surfaces — the CLI refuses to sign a proof for a plaintext request to
// anything else — so the scheme inferred from a bare authority is https for
// every host but these.
var loopbackHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true, "[::1]": true}

// relayBaseURL is the absolute base URL a request to a relay at authority is
// made against, or "" when there is no authority to describe.
//
// An authority is a bare host or host:port — that is what an identity proof
// binds to — so the scheme has to be inferred. Loopback is served in the clear
// during development; everything else is HTTPS, which is the only scheme a DFOS
// proof may be sent under anyway.
func relayBaseURL(authority string) string {
	if authority == "" {
		return ""
	}
	host := strings.ToLower(authority)
	hostname := host
	if strings.HasPrefix(host, "[") {
		if end := strings.Index(host, "]"); end >= 0 {
			hostname = host[:end+1]
		}
	} else if colon := strings.Index(host, ":"); colon >= 0 {
		hostname = host[:colon]
	}
	if loopbackHosts[hostname] {
		return "http://" + host
	}
	return "https://" + host
}

// renderOpenAPI converts the embedded description to the JSON this relay
// serves. Called once per relay (openapiOnce), never per request.
//
// info.version is overwritten with the running relay's Version rather than the
// canonical file's: the release version-sync stamps the canonical document, not
// this copy, and a served document that reports a version this binary is not is
// worse than no version at all. The well-known's `version` field reports the
// same value, so the two meta surfaces always agree.
//
// SELF-DESCRIPTION. The canonical document carries no `servers` member — it
// describes the surface every DFOS relay serves, not the address of any one of
// them, and a hardcoded host is wrong for every deployment but the one it names.
// The served copy writes `servers` from THIS relay's configured Authority, so a
// client that reads the document reaches this relay. The authority is
// configuration and never the request: Host, X-Forwarded-Host, and the request
// URL are attacker-supplied, and a document that echoed one back would invite a
// client to sign its next proof against a host of the attacker's choosing. With
// no authority configured there is nothing honest to write, so the member stays
// absent — and OpenAPI then resolves operations against the URL the document was
// retrieved from, which for a self-served document is this relay either way.
func renderOpenAPI(authority string) ([]byte, error) {
	var parsed any
	if err := yaml.Unmarshal(openapiYAML, &parsed); err != nil {
		return nil, err
	}
	document := jsonifyYAML(parsed)
	root, ok := document.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("openapi document is not a mapping")
	}
	if info, ok := root["info"].(map[string]any); ok {
		info["version"] = Version
	}
	if base := relayBaseURL(authority); base != "" {
		root["servers"] = []any{map[string]any{"url": base}}
	} else {
		delete(root, "servers")
	}
	return json.Marshal(document)
}

// openapiDocument returns the description this relay serves, converting once.
func (r *Relay) openapiDocument() ([]byte, error) {
	r.openapiOnce.Do(func() {
		r.openapiJSON, r.openapiErr = renderOpenAPI(r.authority)
	})
	return r.openapiJSON, r.openapiErr
}

// jsonifyYAML makes a decoded YAML value JSON-marshalable. yaml.v3 decodes a
// mapping into map[string]any when every key is a string and falls back to
// map[any]any otherwise — and encoding/json cannot marshal the latter. Rewriting
// the fallback keys with fmt.Sprint keeps a non-string key (an unquoted `200:`
// response code, say) from turning the whole document into a 500.
func jsonifyYAML(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			typed[key] = jsonifyYAML(child)
		}
		return typed
	case map[any]any:
		converted := make(map[string]any, len(typed))
		for key, child := range typed {
			converted[fmt.Sprint(key)] = jsonifyYAML(child)
		}
		return converted
	case []any:
		for i, child := range typed {
			typed[i] = jsonifyYAML(child)
		}
		return typed
	default:
		return value
	}
}

// handleOpenAPI serves the relay's OpenAPI document. Ungated: a meta surface,
// like the well-known that advertises it.
func (r *Relay) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	document, err := r.openapiDocument()
	if err != nil {
		writeError(w, 500, "openapi document unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(document)
}

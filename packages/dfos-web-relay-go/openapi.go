package relay

/*

  OPENAPI DOCUMENT — the relay's advertised HTTP surface

  WEB-RELAY.md makes serving an OpenAPI document a SHOULD and the well-known's
  `openapi` field the advertisement: a relay that serves one names its URL, and
  absence of the field means none is served. This relay serves one at
  /openapi.json and advertises "/openapi.json" (root-relative, resolved against
  the relay's base URL).

  THE DOCUMENT IS A COPY, DELIBERATELY. openapi.yaml here is a verbatim copy of
  packages/dfos-web-relay/openapi.yaml, the canonical description of the wire
  surface BOTH reference relays serve. Go's //go:embed cannot reach outside its
  own package directory, so the alternative to a copy is a second, independently
  drifting hand-written document — strictly worse. TestOpenAPIDocumentMatchesCanonical
  is the drift guard: it byte-compares this copy against the canonical file
  (modulo the info.version line, which the release version-sync stamps on the
  canonical only) and names the one-line fix when they diverge.

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
	"sync"

	"gopkg.in/yaml.v3"
)

// openapiPath is the root-relative URL the document is served at and the value
// the well-known advertises in its `openapi` field. One const so the route and
// the advertisement can never disagree.
const openapiPath = "/openapi.json"

//go:embed openapi.yaml
var openapiYAML []byte

var (
	openapiOnce sync.Once
	openapiJSON []byte
	openapiErr  error
)

// openapiDocument returns the embedded description as JSON, converting once.
//
// info.version is overwritten with the running relay's Version rather than the
// canonical file's: the release version-sync stamps the canonical document, not
// this copy, and a served document that reports a version this binary is not is
// worse than no version at all. The well-known's `version` field reports the
// same value, so the two meta surfaces always agree.
func openapiDocument() ([]byte, error) {
	openapiOnce.Do(func() {
		var parsed any
		if err := yaml.Unmarshal(openapiYAML, &parsed); err != nil {
			openapiErr = err
			return
		}
		document := jsonifyYAML(parsed)
		if root, ok := document.(map[string]any); ok {
			if info, ok := root["info"].(map[string]any); ok {
				info["version"] = Version
			}
		}
		openapiJSON, openapiErr = json.Marshal(document)
	})
	return openapiJSON, openapiErr
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
	document, err := openapiDocument()
	if err != nil {
		writeError(w, 500, "openapi document unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(document)
}

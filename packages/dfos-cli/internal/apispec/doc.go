// Package apispec reads an OpenAPI document and answers the two questions a
// generic DFOS client has about it: WHICH request does this operation name, and
// WHICH authentication artifact does it need.
//
// The document is discovery, never authority (API-AUTH.md, "The document is
// discovery, never authority"). Everything here decides what to ATTEMPT; the
// serving host's own verdict — 401, 403, 503 — is the machine signal, and
// nothing in this package retries around one.
package apispec

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/pb33f/libopenapi"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
)

// Doc is a parsed OpenAPI 3.x document.
//
// pb33f/libopenapi is the parser because the canonical deployment publishes
// OpenAPI 3.1.1 and the older Go parsers reject that minor outright.
type Doc struct {
	model *libopenapi.DocumentModel[v3.Document]
}

// Parse reads an OpenAPI document from its bytes (JSON or YAML) and builds the
// v3 model. A Swagger 2.0 document, a 3.x document with structural errors, and
// anything that is not an OpenAPI document at all all fail here — registration
// refuses rather than caching bytes that would only fail at call time.
func Parse(data []byte) (*Doc, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, fmt.Errorf("the document is empty")
	}
	document, err := libopenapi.NewDocument(data)
	if err != nil {
		return nil, fmt.Errorf("not an OpenAPI document: %w", err)
	}
	version := document.GetVersion()
	if !strings.HasPrefix(version, "3.") {
		return nil, fmt.Errorf("OpenAPI %s is not supported — this client reads 3.x documents", version)
	}
	model, errs := document.BuildV3Model()
	if model == nil {
		return nil, fmt.Errorf("build the OpenAPI 3 model: %w", errs)
	}
	return &Doc{model: model}, nil
}

// Version is the document's own `openapi` version string.
func (d *Doc) Version() string { return d.model.Model.Version }

// Title and InfoVersion are the document's self-description, shown by `api list`.
func (d *Doc) Title() string {
	if d.model.Model.Info == nil {
		return ""
	}
	return d.model.Model.Info.Title
}

func (d *Doc) InfoVersion() string {
	if d.model.Model.Info == nil {
		return ""
	}
	return d.model.Model.Info.Version
}

// Operation is one (method, path) the document describes.
type Operation struct {
	ID     string
	Method string
	// Path is the path TEMPLATE, `{param}` placeholders intact.
	Path string

	doc      *Doc
	op       *v3.Operation
	pathItem *v3.PathItem
}

// Operations returns every operation in the document, in path order and then in
// a fixed method order, so `api list`-style output never depends on map walks.
func (d *Doc) Operations() []*Operation {
	var ops []*Operation
	if d.model.Model.Paths == nil {
		return ops
	}
	for path, item := range d.model.Model.Paths.PathItems.FromOldest() {
		for method, op := range item.GetOperations().FromOldest() {
			ops = append(ops, &Operation{
				ID:       op.OperationId,
				Method:   strings.ToUpper(method),
				Path:     path,
				doc:      d,
				op:       op,
				pathItem: item,
			})
		}
	}
	sort.SliceStable(ops, func(i, j int) bool {
		if ops[i].Path != ops[j].Path {
			return ops[i].Path < ops[j].Path
		}
		return ops[i].Method < ops[j].Method
	})
	return ops
}

// FindOperation resolves an operationId. Exact match only: operationIds are the
// document's own identifiers and a fuzzy match would call a different route than
// the one the caller named.
func (d *Doc) FindOperation(operationID string) (*Operation, error) {
	for _, op := range d.Operations() {
		if op.ID == operationID {
			return op, nil
		}
	}
	return nil, fmt.Errorf("no operation with operationId %q in this document", operationID)
}

// FindRoute resolves a METHOD + path pair. The path is matched against the
// document's TEMPLATES literally — `/spaces/{space}` is found by that spelling,
// not by `/spaces/dfos`, because a concrete path cannot be un-templated without
// guessing which segment was the parameter.
func (d *Doc) FindRoute(method, path string) (*Operation, error) {
	method = strings.ToUpper(method)
	for _, op := range d.Operations() {
		if op.Method == method && op.Path == path {
			return op, nil
		}
	}
	return nil, fmt.Errorf("no %s %s in this document", method, path)
}

// Label is the human name of an operation: its operationId when it has one, the
// method and path otherwise.
func (o *Operation) Label() string {
	if o.ID != "" {
		return o.ID
	}
	return o.Method + " " + o.Path
}

// Parameters returns the operation's parameters merged with the path item's,
// operation-level winning on a (name, in) collision — OpenAPI's own override rule.
func (o *Operation) Parameters() []*v3.Parameter {
	var merged []*v3.Parameter
	seen := map[string]bool{}
	for _, p := range o.op.Parameters {
		if p == nil {
			continue
		}
		seen[p.In+"\x00"+p.Name] = true
		merged = append(merged, p)
	}
	for _, p := range o.pathItem.Parameters {
		if p == nil || seen[p.In+"\x00"+p.Name] {
			continue
		}
		merged = append(merged, p)
	}
	return merged
}

// BodyMediaType is the media type a body should be sent as: the operation's
// single declared type, or application/json when it declares several including
// JSON. Empty when the operation declares no body.
func (o *Operation) BodyMediaType() string {
	if o.op.RequestBody == nil || o.op.RequestBody.Content == nil {
		return ""
	}
	var first string
	for mediaType := range o.op.RequestBody.Content.KeysFromOldest() {
		if strings.Contains(mediaType, "json") {
			return mediaType
		}
		if first == "" {
			first = mediaType
		}
	}
	return first
}

// ServerURL is the base URL the operation's path hangs off: the operation's own
// `servers`, then the path item's, then the document's, then fallback (the
// origin the document itself was fetched from). Relative server URLs resolve
// against fallback, which is what a document served with `"url": "/v1"` means.
func (o *Operation) ServerURL(fallback string) (string, error) {
	candidates := [][]*v3.Server{o.op.Servers, o.pathItem.Servers, o.doc.model.Model.Servers}
	for _, set := range candidates {
		for _, s := range set {
			if s != nil && s.URL != "" {
				return resolveServerURL(s.URL, fallback)
			}
		}
	}
	if fallback == "" {
		return "", fmt.Errorf("the document declares no server and no origin is known for it")
	}
	return strings.TrimRight(fallback, "/"), nil
}

// resolveServerURL turns a document's server value into an absolute base URL.
func resolveServerURL(server, fallback string) (string, error) {
	parsed, err := url.Parse(server)
	if err != nil {
		return "", fmt.Errorf("the document's server URL %q does not parse: %w", server, err)
	}
	if !parsed.IsAbs() {
		if fallback == "" {
			return "", fmt.Errorf("the document's server URL %q is relative and no origin is known for it", server)
		}
		base, err := url.Parse(fallback)
		if err != nil {
			return "", fmt.Errorf("origin %q does not parse: %w", fallback, err)
		}
		parsed = base.ResolveReference(parsed)
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

// JoinServerPath joins a server base URL to an operation's path.
//
// The trailing slash is the whole reason this exists. A server URL is entitled
// to end in one, an operation path always begins with one, and literal
// concatenation of the two yields `https://host/v1//spaces` — a 404 nobody
// reading the document would predict. The base's trailing slashes are stripped
// before the join, always.
func JoinServerPath(server, path string) (string, error) {
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("operation path %q does not begin with /", path)
	}
	base := strings.TrimRight(server, "/")
	if base == "" {
		return "", fmt.Errorf("no server URL to join %q to", path)
	}
	if _, err := url.Parse(base + path); err != nil {
		return "", fmt.Errorf("build request URL for %q: %w", path, err)
	}
	return base + path, nil
}

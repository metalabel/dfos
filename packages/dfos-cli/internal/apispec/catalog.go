package apispec

// The ACTION CATALOG — every action token a document advertises, with whatever
// description it gave one.
//
// Two places in a document name action tokens, and the catalog is their union:
//
//   - `x-dfos-actions` on the request-proof security scheme, which API-AUTH.md
//     calls "the host's action catalog": a map of action token → human-readable
//     description, restating the registry the host serves.
//   - `x-dfos-actions` on an Operation Object, which is the OR-of-alternatives a
//     route requires. A token can be required by a route the catalog forgot to
//     list, and a client asking for a grant it will actually spend needs it.
//
// The same extension name carries both, which is unambiguous by POSITION — a
// scheme's is a map, an operation's is an array — and this reader discriminates
// on the node's shape rather than trusting either to be well-formed.
//
// TOKENS ARE OPAQUE. They are read as strings, deduplicated as strings, and
// printed as strings. Descriptions are display text and nothing else: no
// decision anywhere reads one.

import (
	"fmt"
	"sort"
	"strings"

	"go.yaml.in/yaml/v4"
)

// CatalogEntry is one advertised action token.
type CatalogEntry struct {
	Action string `json:"action"`
	// Description is the catalog's own words for the token, empty when the
	// document never described it.
	Description string `json:"description,omitempty"`
	// Advertised reports whether the scheme-level catalog named this token. A
	// token that is false here was found only in an operation's requirements —
	// still real, still askable, just never catalogued.
	Advertised bool `json:"advertised"`
}

// ActionCatalog folds a document's advertised actions into one ordered list:
// the scheme-level catalog first, in the order the document wrote it, then
// every operation-required token the catalog did not name, sorted.
//
// The order is the point of the split. A host that catalogued its actions chose
// a presentation order, and a client asking a person to choose among them should
// not reshuffle it; tokens the catalog omitted have no such order to honor, so
// they get a deterministic one.
func (d *Doc) ActionCatalog() ([]CatalogEntry, error) {
	catalog, err := d.schemeCatalog()
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	for _, entry := range catalog {
		seen[entry.Action] = true
	}

	var extra []string
	for _, op := range d.Operations() {
		alternatives, err := op.RequiredActions()
		if err != nil {
			return nil, err
		}
		for _, alternative := range alternatives {
			for _, token := range alternative {
				if token == "" || seen[token] {
					continue
				}
				seen[token] = true
				extra = append(extra, token)
			}
		}
	}
	sort.Strings(extra)
	for _, token := range extra {
		catalog = append(catalog, CatalogEntry{Action: token})
	}
	return catalog, nil
}

// schemeCatalog reads the `x-dfos-actions` catalogs declared on the document's
// proof schemes.
//
// Scoped to the schemes API-AUTH.md puts a catalog on — the request-proof
// scheme, plus the unmarked `scheme: dfos` case the same section says a consumer
// MAY read under the combination rules. Every other scheme is left alone: an
// unrelated scheme carrying an `x-dfos-actions` member is not this convention's
// catalog, and reading it would put a stranger's vocabulary in front of a person
// choosing what to grant.
func (d *Doc) schemeCatalog() ([]CatalogEntry, error) {
	components := d.model.Model.Components
	if components == nil || components.SecuritySchemes == nil {
		return nil, nil
	}

	var catalog []CatalogEntry
	index := map[string]int{}
	for name, scheme := range components.SecuritySchemes.FromOldest() {
		switch classifyScheme(scheme) {
		case kindRequestProof, kindUnmarkedProof:
		default:
			continue
		}
		if scheme.Extensions == nil {
			continue
		}
		node := scheme.Extensions.GetOrZero("x-dfos-actions")
		if node == nil {
			continue
		}
		entries, err := decodeSchemeCatalog(node)
		if err != nil {
			return nil, fmt.Errorf("x-dfos-actions on security scheme %q: %w", name, err)
		}
		for _, entry := range entries {
			// Two schemes may catalog the same token. First wins on order; a
			// description fills a blank left by an earlier, wordless entry.
			at, ok := index[entry.Action]
			if !ok {
				index[entry.Action] = len(catalog)
				catalog = append(catalog, entry)
				continue
			}
			if catalog[at].Description == "" {
				catalog[at].Description = entry.Description
			}
		}
	}
	return catalog, nil
}

// decodeSchemeCatalog reads one scheme's catalog node.
//
// The map is the spelled convention. A sequence is accepted as the tokens with
// no descriptions, because a host that wrote its catalog as a bare list has
// still named its vocabulary, and refusing it would hide actions a person could
// otherwise ask for.
func decodeSchemeCatalog(node *yaml.Node) ([]CatalogEntry, error) {
	switch node.Kind {
	case yaml.MappingNode:
		entries := make([]CatalogEntry, 0, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			var action string
			if err := node.Content[i].Decode(&action); err != nil || action == "" {
				return nil, fmt.Errorf("entry %d has a key that is not an action token", i/2)
			}
			// A non-string description is DROPPED, not an error: the catalog is
			// documentation, and a malformed line of it must not cost the token.
			var description string
			node.Content[i+1].Decode(&description)
			entries = append(entries, CatalogEntry{Action: action, Description: description, Advertised: true})
		}
		return entries, nil

	case yaml.SequenceNode:
		entries := make([]CatalogEntry, 0, len(node.Content))
		for i, item := range node.Content {
			var action string
			if err := item.Decode(&action); err != nil || action == "" {
				return nil, fmt.Errorf("element %d is neither an action token nor a description of one", i)
			}
			entries = append(entries, CatalogEntry{Action: action, Advertised: true})
		}
		return entries, nil
	}
	return nil, fmt.Errorf("is neither a map of action token to description nor a list of action tokens")
}

// ActionBundle is one AND-alternative a route requires: tokens that mean
// nothing apart, because the route needs all of them or refuses.
type ActionBundle struct {
	Actions []string `json:"actions"`
	// Operations are the routes requiring this exact combination, in document
	// order — the evidence for why the combination is a combination.
	Operations []string `json:"operations"`
}

// Label renders the bundle the way the document wrote it.
func (b ActionBundle) Label() string { return strings.Join(b.Actions, " AND ") }

// ActionBundles is every distinct AND-alternative the document's operations
// require, in first-seen order.
//
// The flat catalog LOSES this, and losing it costs a real grant. A person
// choosing from a list of tokens cannot see that `read:profile` buys nothing on
// a route that requires `read:profile AND read:email`, so they can select a
// strict subset of what a route needs, believe the selection complete, and
// discover otherwise as a 403 after the credential is already minted. A
// single-token alternative has no structure to lose and is not a bundle.
func (d *Doc) ActionBundles() ([]ActionBundle, error) {
	index := map[string]int{}
	var bundles []ActionBundle
	for _, op := range d.Operations() {
		alternatives, err := op.RequiredActions()
		if err != nil {
			return nil, err
		}
		for _, alternative := range alternatives {
			if len(alternative) < 2 {
				continue
			}
			key := strings.Join(alternative, "\x00")
			at, ok := index[key]
			if !ok {
				index[key] = len(bundles)
				bundles = append(bundles, ActionBundle{
					Actions:    append([]string(nil), alternative...),
					Operations: []string{op.Label()},
				})
				continue
			}
			bundles[at].Operations = append(bundles[at].Operations, op.Label())
		}
	}
	return bundles, nil
}

// CatalogActions is the catalog's tokens, in catalog order.
func CatalogActions(catalog []CatalogEntry) []string {
	tokens := make([]string, 0, len(catalog))
	for _, entry := range catalog {
		tokens = append(tokens, entry.Action)
	}
	return tokens
}

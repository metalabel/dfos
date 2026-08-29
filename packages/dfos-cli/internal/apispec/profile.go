package apispec

// Profile inference — which artifact of the API-AUTH envelope family a route
// needs, read out of the document's own security requirements.
//
// THE COMBINATION IS THE DISCRIMINATOR (API-AUTH.md, "Requirement
// combinations"). Not the component names, which are the host's free choice, and
// not the action list, which says nothing about which artifact to sign. Schemes
// are identified STRUCTURALLY — by `type` / `scheme` / header name and the
// `x-dfos-typ` marker — so a host that calls its request-proof scheme `pop` is
// read exactly like one that calls it `dfosRequestProof`.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pb33f/libopenapi/datamodel/high/base"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
	"github.com/pb33f/libopenapi/orderedmap"
	"go.yaml.in/yaml/v4"
)

// Profile is the authentication shape a client attempts for one request.
type Profile string

const (
	// ProfileAnonymous carries no artifact of this family.
	ProfileAnonymous Profile = "anonymous"
	// ProfileIdentity carries an identity proof — authentication only.
	ProfileIdentity Profile = "identity"
	// ProfileDelegated carries a request proof plus the credential it binds.
	ProfileDelegated Profile = "delegated"
)

// ParseProfile reads the `--profile` flag's value, accepting the short spelling
// a person types.
func ParseProfile(s string) (Profile, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "anon", "anonymous":
		return ProfileAnonymous, nil
	case "identity":
		return ProfileIdentity, nil
	case "delegated":
		return ProfileDelegated, nil
	}
	return "", fmt.Errorf("unknown profile %q — use anon, identity, or delegated", s)
}

// The registered `x-dfos-typ` values, and the header the credential rides in.
const (
	TypIdentityProof = "did:dfos:identity-proof"
	TypRequestProof  = "did:dfos:request-proof"
	credentialHeader = "X-Credential"
)

// schemeKind is what one declared security scheme is, structurally.
type schemeKind int

const (
	kindOther schemeKind = iota
	kindIdentityProof
	kindRequestProof
	// kindUnmarkedProof is a `scheme: dfos` scheme with no `x-dfos-typ`. The
	// marker is REQUIRED under the convention, so this is a non-conforming
	// document — but the combination rules disambiguate the two cases that can
	// occur without it, so it is read rather than refused.
	kindUnmarkedProof
	kindCredential
)

// classifyScheme identifies a security scheme by its shape, never by its name.
func classifyScheme(s *v3.SecurityScheme) schemeKind {
	if s == nil {
		return kindOther
	}
	switch {
	case strings.EqualFold(s.Type, "http") && strings.EqualFold(s.Scheme, "dfos"):
		switch extensionString(s.Extensions, "x-dfos-typ") {
		case TypIdentityProof:
			return kindIdentityProof
		case TypRequestProof:
			return kindRequestProof
		case "":
			return kindUnmarkedProof
		}
		// A `scheme: dfos` scheme marked with an envelope this client does not
		// build. Unrecognized, deliberately: guessing would sign the wrong typ.
		return kindOther
	case strings.EqualFold(s.Type, "apiKey") &&
		strings.EqualFold(s.In, "header") &&
		strings.EqualFold(s.Name, credentialHeader):
		return kindCredential
	}
	return kindOther
}

// Alternative is one requirement object read as a claim this client could make.
// Across an operation's `security` array the alternatives are ORed; a client
// satisfies any one of them.
type Alternative struct {
	Profile Profile
	// Credential reports whether a credential rides in `X-Credential`. It is
	// always true for the delegated profile (the proof is meaningless without
	// it) and true for the identity profile only in the authn/authz split, where
	// the route's own specification gives the header a different role.
	Credential bool
	// Schemes are the component names this alternative named, for diagnostics.
	// Nothing decides anything from them.
	Schemes []string
	// Unsatisfiable, when non-empty, says why no conforming client can make this
	// alternative's claim. Such an alternative is never selected.
	Unsatisfiable string
}

// Alternatives reads the operation's effective security requirements — its own
// when it declares any, the document's root default otherwise — into the ordered
// list of claims a client may make.
//
// Two absences are different and both are honored: an operation with NO
// `security` member inherits the root default, while an operation with an empty
// `security: []` is explicitly anonymous and inherits nothing.
func (o *Operation) Alternatives() []Alternative {
	requirements := o.op.Security
	if requirements == nil {
		requirements = o.doc.model.Model.Security
	}
	// Neither the operation nor the root states a requirement: anonymous.
	if len(requirements) == 0 {
		return []Alternative{{Profile: ProfileAnonymous}}
	}

	var alts []Alternative
	for _, requirement := range requirements {
		if requirement == nil {
			continue
		}
		alts = append(alts, o.doc.readRequirement(requirement))
	}
	if len(alts) == 0 {
		return []Alternative{{Profile: ProfileAnonymous}}
	}
	return alts
}

// readRequirement turns ONE requirement object — whose named schemes are ANDed —
// into the claim that combination declares.
func (d *Doc) readRequirement(requirement *base.SecurityRequirement) Alternative {
	var names []string
	counts := map[schemeKind]int{}
	for name := range requirement.Requirements.KeysFromOldest() {
		names = append(names, name)
		counts[classifyScheme(d.securityScheme(name))]++
	}

	alt := Alternative{Schemes: names}
	// An empty requirement object is OpenAPI's own spelling of "this route may
	// also be called with nothing".
	if len(names) == 0 || requirement.ContainsEmptyRequirement {
		alt.Profile = ProfileAnonymous
		return alt
	}

	identity, request, unmarked, credential, other :=
		counts[kindIdentityProof], counts[kindRequestProof], counts[kindUnmarkedProof],
		counts[kindCredential], counts[kindOther]

	switch {
	case other > 0:
		alt.Unsatisfiable = "names a security scheme this client does not implement: " +
			d.describeUnimplemented(names)
	case identity == 1 && request == 0 && unmarked == 0 && credential == 0:
		alt.Profile = ProfileIdentity
	case identity == 1 && request == 0 && unmarked == 0 && credential == 1:
		// The authn/authz split: the proof authenticates, and the credential is
		// evaluated by the route's own machinery in whatever role that route's
		// specification assigns it.
		alt.Profile, alt.Credential = ProfileIdentity, true
	case request == 1 && identity == 0 && unmarked == 0 && credential == 1:
		alt.Profile, alt.Credential = ProfileDelegated, true
	case request == 1 && credential == 0:
		// API-AUTH.md: "a request-proof scheme alone advertises a route no
		// conforming client can call".
		alt.Unsatisfiable = "requires a request proof with no credential scheme beside it — " +
			"a request proof is meaningless without the credential it binds"
	case unmarked == 1 && identity == 0 && request == 0 && credential == 0:
		// The documented fallback for a document missing `x-dfos-typ`: a proof
		// scheme standing alone is the identity proof.
		alt.Profile = ProfileIdentity
	case unmarked == 1 && identity == 0 && request == 0 && credential == 1:
		// ...and a proof scheme ANDed with the credential scheme is the request proof.
		alt.Profile, alt.Credential = ProfileDelegated, true
	default:
		alt.Unsatisfiable = fmt.Sprintf("names a security-scheme combination this client cannot read (%s)",
			strings.Join(names, " AND "))
	}
	return alt
}

// describeUnimplemented says WHY each unreadable scheme in a requirement is
// unreadable.
//
// The distinction is worth the words. A `scheme: dfos` scheme marked with an
// envelope type outside the registered pair is THIS family, mis-marked — a typo
// or a placeholder in the document, fixable in one line — while a scheme that is
// not this family at all is a route this client was never going to call. Naming
// both "a security scheme this client does not implement" and stopping sends a
// reader hunting through their client for a scheme the document got wrong.
func (d *Doc) describeUnimplemented(names []string) string {
	described := make([]string, 0, len(names))
	for _, name := range names {
		scheme := d.securityScheme(name)
		switch {
		case scheme == nil:
			described = append(described, fmt.Sprintf("%s is named by the requirement but declared nowhere in components.securitySchemes", name))
		case classifyScheme(scheme) != kindOther:
			continue
		case strings.EqualFold(scheme.Type, "http") && strings.EqualFold(scheme.Scheme, "dfos"):
			described = append(described, fmt.Sprintf("%s is a `scheme: dfos` scheme marked `x-dfos-typ: %q`, which is neither %s nor %s",
				name, extensionString(scheme.Extensions, "x-dfos-typ"), TypIdentityProof, TypRequestProof))
		default:
			described = append(described, fmt.Sprintf("%s (type: %s, scheme: %s) is not part of the DFOS envelope family",
				name, orNone(scheme.Type), orNone(scheme.Scheme)))
		}
	}
	if len(described) == 0 {
		return strings.Join(names, " AND ")
	}
	return strings.Join(described, "; ")
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func (d *Doc) securityScheme(name string) *v3.SecurityScheme {
	components := d.model.Model.Components
	if components == nil || components.SecuritySchemes == nil {
		return nil
	}
	return components.SecuritySchemes.GetOrZero(name)
}

// Rank orders the alternatives a client should try, cheapest authentication
// first and anonymous LAST.
//
// Anonymous going last is the deliberate part: a route offering both an
// anonymous and an authenticated reading is offering MORE under the
// authenticated one, and silently taking the anonymous alternative would quietly
// hand back the thinner answer. Unsatisfiable alternatives are dropped — they
// are readings no client can act on, not choices.
func Rank(alts []Alternative) []Alternative {
	ranked := make([]Alternative, 0, len(alts))
	for _, a := range alts {
		if a.Unsatisfiable == "" {
			ranked = append(ranked, a)
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool { return cost(ranked[i]) < cost(ranked[j]) })
	return ranked
}

func cost(a Alternative) int {
	switch {
	case a.Profile == ProfileIdentity && !a.Credential:
		return 0
	case a.Profile == ProfileIdentity:
		return 1
	case a.Profile == ProfileDelegated:
		return 2
	default:
		return 3
	}
}

// RequiredActions reads the operation's `x-dfos-actions` as the OR-of-alternatives
// it is: each element is one alternative, either a single action token or an
// array of tokens that must ALL be covered.
//
// A nil result means the member is absent. Under the delegated combination that
// is the presentation-suffices class — a valid credential for the host and no
// particular action token — and it is unambiguous because the requirement
// combination, never the action list, distinguishes the profiles.
//
// Tokens are OPAQUE. They are read as strings, compared as strings, and printed
// as strings; this client never enumerates, validates, or interprets one.
func (o *Operation) RequiredActions() ([][]string, error) {
	node := o.op.Extensions.GetOrZero("x-dfos-actions")
	if node == nil {
		return nil, nil
	}
	var raw []any
	if err := node.Decode(&raw); err != nil {
		// The decoder's own words are a parser's complaint about a document
		// problem. Name the SHAPE instead: a reader can fix a shape.
		return nil, fmt.Errorf("x-dfos-actions on %s %s", o.Label(), describeActionsShape(node))
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("x-dfos-actions on %s is an empty array — it states no alternative any credential could satisfy; omit the member for the presentation-suffices class (a valid credential for the host, and no particular token)", o.Label())
	}
	alternatives := make([][]string, 0, len(raw))
	for i, entry := range raw {
		switch v := entry.(type) {
		case string:
			if v == "" {
				return nil, fmt.Errorf("x-dfos-actions on %s: alternative %d is an empty token", o.Label(), i)
			}
			alternatives = append(alternatives, []string{v})
		case []any:
			if len(v) == 0 {
				// An AND-set with no members is satisfied by anything, which is
				// not a requirement — and reading it as one would widen the
				// route silently.
				return nil, fmt.Errorf("x-dfos-actions on %s: alternative %d is an empty array — an alternative with no tokens states no requirement; omit the member for the presentation-suffices class", o.Label(), i)
			}
			tokens := make([]string, 0, len(v))
			for _, token := range v {
				s, ok := token.(string)
				if !ok {
					return nil, fmt.Errorf("x-dfos-actions on %s: alternative %d holds a non-string token (%T)", o.Label(), i, token)
				}
				if s == "" {
					return nil, fmt.Errorf("x-dfos-actions on %s: alternative %d holds an empty token", o.Label(), i)
				}
				tokens = append(tokens, s)
			}
			alternatives = append(alternatives, tokens)
		default:
			return nil, fmt.Errorf("x-dfos-actions on %s: alternative %d is neither a token nor an array of tokens (%T)", o.Label(), i, entry)
		}
	}
	return alternatives, nil
}

// describeActionsShape names what a non-conforming `x-dfos-actions` node IS.
//
// The two shapes that actually turn up have specific, correctable causes: the
// MAP is the SCHEME-level action catalog written in the wrong place, and the
// BARE TOKEN is an author who wrote the one action a route needs without the
// array around it. Both are worth naming; the raw decoder error names neither.
func describeActionsShape(node *yaml.Node) string {
	switch node.Kind {
	case yaml.MappingNode:
		return "is a map of action token to description — that is the shape of the SCHEME-level action catalog, which belongs on the request-proof security scheme. An operation's member is an array of alternatives: x-dfos-actions: [read:profile, [read:profile, read:email]]"
	case yaml.ScalarNode:
		return fmt.Sprintf("is the bare token %q — an operation's member is an array of alternatives, so write it as [%s]", node.Value, node.Value)
	}
	return "is neither an array of alternatives nor anything this client can read as one"
}

// CoversActions reports whether a granted action set satisfies the operation:
// every token of ANY ONE alternative is present. Absent alternatives (nil)
// always pass — that is the presentation-suffices class.
func CoversActions(alternatives [][]string, granted map[string]bool) bool {
	if alternatives == nil {
		return true
	}
	for _, alternative := range alternatives {
		covered := true
		for _, token := range alternative {
			if !granted[token] {
				covered = false
				break
			}
		}
		if covered {
			return true
		}
	}
	return false
}

// DescribeActions renders the required actions the way the document wrote them,
// verbatim: alternatives joined by " OR ", the tokens of an AND-alternative by
// " AND ". Purely for the error a 403 deserves.
func DescribeActions(alternatives [][]string) string {
	if alternatives == nil {
		return "none (a valid credential for this host suffices)"
	}
	parts := make([]string, 0, len(alternatives))
	for _, alternative := range alternatives {
		parts = append(parts, strings.Join(alternative, " AND "))
	}
	return strings.Join(parts, " OR ")
}

// extensionString reads a string-valued `x-` extension, returning "" when the
// member is absent or is not a string.
func extensionString(extensions *orderedmap.Map[string, *yaml.Node], name string) string {
	if extensions == nil {
		return ""
	}
	node := extensions.GetOrZero(name)
	if node == nil {
		return ""
	}
	var value string
	if err := node.Decode(&value); err != nil {
		return ""
	}
	return value
}

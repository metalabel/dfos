package apispec

// The profile-inference table. The COMBINATION of security schemes in one
// requirement object is what names the artifact, so every combination the
// convention defines gets a row — including the two the fallback rules cover
// when a document omits `x-dfos-typ`, and the one combination that advertises a
// route no conforming client can call.

import (
	"strings"
	"testing"
)

// schemeYAML is the full scheme vocabulary under DELIBERATELY non-recommended
// component names. Nothing may key off a name, so the fixture makes name-keying
// impossible to get away with.
const schemeYAML = `
components:
  securitySchemes:
    whoIsAsking:
      type: http
      scheme: dfos
      x-dfos-typ: did:dfos:identity-proof
    popProof:
      type: http
      scheme: DFOS
      x-dfos-typ: did:dfos:request-proof
      x-dfos-actions:
        read:profile: Read the profile
    theGrant:
      type: apiKey
      in: header
      name: x-credential
    unmarkedProof:
      type: http
      scheme: dfos
    bearerish:
      type: http
      scheme: bearer
`

func docWithOperation(t *testing.T, security string, extras string) *Doc {
	t.Helper()
	body := `openapi: 3.1.0
info:
  title: t
  version: "1"
servers:
  - url: https://api.example.test/v1
paths:
  /thing:
    get:
      operationId: getThing
` + indent(security, "      ") + indent(extras, "      ") + schemeYAML
	doc, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("parse fixture: %v\n%s", err, body)
	}
	return doc
}

func indent(block, prefix string) string {
	if strings.TrimSpace(block) == "" {
		return ""
	}
	var out strings.Builder
	for _, line := range strings.Split(strings.Trim(block, "\n"), "\n") {
		out.WriteString(prefix)
		out.WriteString(line)
		out.WriteString("\n")
	}
	return out.String()
}

func onlyOperation(t *testing.T, doc *Doc) *Operation {
	t.Helper()
	ops := doc.Operations()
	if len(ops) != 1 {
		t.Fatalf("fixture has %d operations, want 1", len(ops))
	}
	return ops[0]
}

func TestProfileInferenceTable(t *testing.T) {
	cases := []struct {
		name       string
		security   string
		want       Profile
		credential bool
		// unsatisfiable is a substring of the reason, when the combination names
		// a claim no conforming client can make.
		unsatisfiable string
	}{
		{
			name:     "no security member at all inherits the root default, which is nothing",
			security: "",
			want:     ProfileAnonymous,
		},
		{
			name:     "an explicit empty security list is anonymous",
			security: "security: []",
			want:     ProfileAnonymous,
		},
		{
			name:     "an empty requirement object is anonymous",
			security: "security:\n  - {}",
			want:     ProfileAnonymous,
		},
		{
			name:     "the identity-proof scheme alone is the identity proof",
			security: "security:\n  - whoIsAsking: []",
			want:     ProfileIdentity,
		},
		{
			name:       "request-proof AND credential is the delegated profile",
			security:   "security:\n  - popProof: []\n    theGrant: []",
			want:       ProfileDelegated,
			credential: true,
		},
		{
			name:       "identity-proof AND credential is the authn/authz split",
			security:   "security:\n  - whoIsAsking: []\n    theGrant: []",
			want:       ProfileIdentity,
			credential: true,
		},
		{
			name:          "a request-proof scheme with no credential beside it is unsatisfiable",
			security:      "security:\n  - popProof: []",
			unsatisfiable: "meaningless without the credential",
		},
		{
			name:     "an unmarked proof scheme standing alone falls back to the identity proof",
			security: "security:\n  - unmarkedProof: []",
			want:     ProfileIdentity,
		},
		{
			name:       "an unmarked proof scheme ANDed with the credential falls back to the request proof",
			security:   "security:\n  - unmarkedProof: []\n    theGrant: []",
			want:       ProfileDelegated,
			credential: true,
		},
		{
			name:          "a scheme this client does not implement is unsatisfiable",
			security:      "security:\n  - bearerish: []",
			unsatisfiable: "does not implement",
		},
		{
			name:          "a scheme the document never declares is unsatisfiable",
			security:      "security:\n  - noSuchScheme: []",
			unsatisfiable: "does not implement",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			op := onlyOperation(t, docWithOperation(t, tc.security, ""))
			alts := op.Alternatives()
			if len(alts) != 1 {
				t.Fatalf("got %d alternatives, want 1: %+v", len(alts), alts)
			}
			got := alts[0]
			if tc.unsatisfiable != "" {
				if !strings.Contains(got.Unsatisfiable, tc.unsatisfiable) {
					t.Fatalf("Unsatisfiable = %q, want it to mention %q", got.Unsatisfiable, tc.unsatisfiable)
				}
				if len(Rank(alts)) != 0 {
					t.Fatalf("an unsatisfiable alternative must never be ranked")
				}
				return
			}
			if got.Unsatisfiable != "" {
				t.Fatalf("unexpectedly unsatisfiable: %s", got.Unsatisfiable)
			}
			if got.Profile != tc.want {
				t.Fatalf("Profile = %q, want %q", got.Profile, tc.want)
			}
			if got.Credential != tc.credential {
				t.Fatalf("Credential = %v, want %v", got.Credential, tc.credential)
			}
		})
	}
}

// The delegated combination WITHOUT x-dfos-actions is the presentation-suffices
// class, and it must stay distinguishable from an identity-proof-alone route.
// The discriminator is the combination, never the action list — so the two are
// tested against each other with the action list absent from both.
func TestPresentationSufficesVersusIdentityProofAlone(t *testing.T) {
	delegated := onlyOperation(t, docWithOperation(t, "security:\n  - popProof: []\n    theGrant: []", ""))
	identity := onlyOperation(t, docWithOperation(t, "security:\n  - whoIsAsking: []", ""))

	delegatedActions, err := delegated.RequiredActions()
	if err != nil {
		t.Fatalf("RequiredActions: %v", err)
	}
	identityActions, err := identity.RequiredActions()
	if err != nil {
		t.Fatalf("RequiredActions: %v", err)
	}
	if delegatedActions != nil || identityActions != nil {
		t.Fatalf("neither fixture declares x-dfos-actions; got %v and %v", delegatedActions, identityActions)
	}

	if got := delegated.Alternatives()[0]; got.Profile != ProfileDelegated || !got.Credential {
		t.Fatalf("absent x-dfos-actions must NOT downgrade the delegated combination: %+v", got)
	}
	if got := identity.Alternatives()[0]; got.Profile != ProfileIdentity || got.Credential {
		t.Fatalf("identity-proof alone must stay credential-less: %+v", got)
	}

	// Presentation-suffices: any granted set passes, including the empty one —
	// a credential may always describe itself.
	if !CoversActions(delegatedActions, map[string]bool{}) {
		t.Fatalf("absent x-dfos-actions must be satisfied by any valid credential")
	}
	if got := DescribeActions(nil); !strings.Contains(got, "valid credential for this host suffices") {
		t.Fatalf("DescribeActions(nil) = %q", got)
	}
}

func TestOrOfRequirementsPicksCheapestAuthAndAnonymousLast(t *testing.T) {
	// Anonymous is listed FIRST in the document and must still rank last; the
	// delegated combination is listed before the identity proof and must still
	// rank after it.
	op := onlyOperation(t, docWithOperation(t, `security:
  - {}
  - popProof: []
    theGrant: []
  - whoIsAsking: []
  - popProof: []`, ""))

	alts := op.Alternatives()
	if len(alts) != 4 {
		t.Fatalf("got %d alternatives, want 4", len(alts))
	}
	ranked := Rank(alts)
	// The request-proof-alone alternative is dropped, never ranked.
	if len(ranked) != 3 {
		t.Fatalf("ranked %d alternatives, want 3 (the unsatisfiable one is dropped): %+v", len(ranked), ranked)
	}
	want := []Profile{ProfileIdentity, ProfileDelegated, ProfileAnonymous}
	for i, p := range want {
		if ranked[i].Profile != p {
			t.Fatalf("ranked[%d] = %q, want %q (full order: %+v)", i, ranked[i].Profile, p, ranked)
		}
	}
}

func TestRequiredActionsOrAndAnd(t *testing.T) {
	t.Run("a flat array is an OR of single tokens", func(t *testing.T) {
		op := onlyOperation(t, docWithOperation(t,
			"security:\n  - popProof: []\n    theGrant: []",
			"x-dfos-actions: [read:profile, read:email]"))
		got, err := op.RequiredActions()
		if err != nil {
			t.Fatalf("RequiredActions: %v", err)
		}
		if len(got) != 2 || got[0][0] != "read:profile" || got[1][0] != "read:email" {
			t.Fatalf("got %v", got)
		}
		if !CoversActions(got, map[string]bool{"read:email": true}) {
			t.Fatalf("either token alone must satisfy an OR")
		}
		if CoversActions(got, map[string]bool{"read:memberships": true}) {
			t.Fatalf("an unrelated token must not satisfy")
		}
	})

	t.Run("a nested array is one AND alternative", func(t *testing.T) {
		op := onlyOperation(t, docWithOperation(t,
			"security:\n  - popProof: []\n    theGrant: []",
			"x-dfos-actions: [[read:profile, read:email]]"))
		got, err := op.RequiredActions()
		if err != nil {
			t.Fatalf("RequiredActions: %v", err)
		}
		if len(got) != 1 || len(got[0]) != 2 {
			t.Fatalf("got %v", got)
		}
		if CoversActions(got, map[string]bool{"read:profile": true}) {
			t.Fatalf("half of an AND alternative must not satisfy it")
		}
		if !CoversActions(got, map[string]bool{"read:profile": true, "read:email": true}) {
			t.Fatalf("both tokens must satisfy the AND alternative")
		}
		if got := DescribeActions(got); got != "read:profile AND read:email" {
			t.Fatalf("DescribeActions = %q", got)
		}
	})

	t.Run("mixed alternatives read as OR of (token | AND-set)", func(t *testing.T) {
		op := onlyOperation(t, docWithOperation(t,
			"security:\n  - popProof: []\n    theGrant: []",
			"x-dfos-actions: [read:memberships, [read:profile, read:email]]"))
		got, err := op.RequiredActions()
		if err != nil {
			t.Fatalf("RequiredActions: %v", err)
		}
		if got := DescribeActions(got); got != "read:memberships OR read:profile AND read:email" {
			t.Fatalf("DescribeActions = %q", got)
		}
		if !CoversActions(got, map[string]bool{"read:memberships": true}) {
			t.Fatalf("the single-token alternative must satisfy")
		}
	})

	t.Run("tokens stay opaque — an unregistered string is carried, never rejected", func(t *testing.T) {
		op := onlyOperation(t, docWithOperation(t,
			"security:\n  - popProof: []\n    theGrant: []",
			"x-dfos-actions: ['write:anything-at-all', 'read:*']"))
		got, err := op.RequiredActions()
		if err != nil {
			t.Fatalf("RequiredActions: %v", err)
		}
		if got[0][0] != "write:anything-at-all" || got[1][0] != "read:*" {
			t.Fatalf("tokens were altered: %v", got)
		}
		// `read:*` is a LITERAL token, never a pattern: a grant of read:profile
		// does not satisfy a route requiring read:*, and vice versa.
		if CoversActions([][]string{{"read:*"}}, map[string]bool{"read:profile": true}) {
			t.Fatalf("read:* must not be expanded into a pattern")
		}
	})

	t.Run("a malformed x-dfos-actions is an error, not a guess", func(t *testing.T) {
		op := onlyOperation(t, docWithOperation(t,
			"security:\n  - popProof: []\n    theGrant: []",
			"x-dfos-actions: {read:profile: yes}"))
		if _, err := op.RequiredActions(); err == nil {
			t.Fatalf("a map-valued x-dfos-actions must be refused")
		}
	})
}

// THE SHAPE MATRIX. Every spelling of `x-dfos-actions` an operation can carry,
// conforming and not, with the exact reading or the exact refusal.
//
// The canonical AND-array — one OR-alternative that is an AND-pair, the
// `[[a, b]]` spelling API-AUTH.md's convention writes verbatim — is the row that
// matters most: it is legal, it is what a real host publishes, and a client that
// mis-walks it refuses a route it can call.
func TestRequiredActionsShapeMatrix(t *testing.T) {
	cases := []struct {
		name string
		// member is the `x-dfos-actions` value, written as a document writes it.
		member string
		want   [][]string
		// refusedNaming is what a refusal must say. Empty when the shape is read.
		refusedNaming []string
	}{
		{
			name:   "bare tokens are an OR of singles",
			member: "[read:profile, read:email]",
			want:   [][]string{{"read:profile"}, {"read:email"}},
		},
		{
			name:   "the canonical AND-array is one alternative of two tokens",
			member: `[["read:profile", "read:email"]]`,
			want:   [][]string{{"read:profile", "read:email"}},
		},
		{
			name:   "a one-token AND-array is one alternative of one token",
			member: `[["read:profile"]]`,
			want:   [][]string{{"read:profile"}},
		},
		{
			name:   "mixed shapes read in document order",
			member: `[read:memberships, ["read:profile", "read:email"], write:posts]`,
			want:   [][]string{{"read:memberships"}, {"read:profile", "read:email"}, {"write:posts"}},
		},
		{
			name:   "a block-sequence AND-array reads the same as the flow one",
			member: "\n  - - read:profile\n    - read:email",
			want:   [][]string{{"read:profile", "read:email"}},
		},
		{
			name:          "an empty array states no satisfiable alternative",
			member:        "[]",
			refusedNaming: []string{"empty array", "presentation-suffices"},
		},
		{
			name:          "a nested-empty alternative is refused, never read as vacuous",
			member:        "[[]]",
			refusedNaming: []string{"alternative 0 is an empty array", "states no requirement"},
		},
		{
			name:          "a nested-empty alternative beside a real one is still refused",
			member:        `[["read:profile"], []]`,
			refusedNaming: []string{"alternative 1 is an empty array"},
		},
		{
			name:          "an empty token is refused",
			member:        `["", read:profile]`,
			refusedNaming: []string{"alternative 0 is an empty token"},
		},
		{
			name:          "an empty token inside an AND-array is refused",
			member:        `[["read:profile", ""]]`,
			refusedNaming: []string{"alternative 0 holds an empty token"},
		},
		{
			name:          "a non-string token is refused and its type named",
			member:        "[[read:profile, 7]]",
			refusedNaming: []string{"alternative 0 holds a non-string token"},
		},
		{
			name:          "a doubly-nested array is refused",
			member:        `[[["read:profile"]]]`,
			refusedNaming: []string{"alternative 0 holds a non-string token"},
		},
		{
			name:          "an alternative that is neither token nor array is refused",
			member:        "[{read:profile: yes}]",
			refusedNaming: []string{"alternative 0 is neither a token nor an array of tokens"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			op := onlyOperation(t, docWithOperation(t,
				"security:\n  - popProof: []\n    theGrant: []",
				"x-dfos-actions: "+tc.member))
			got, err := op.RequiredActions()
			if len(tc.refusedNaming) > 0 {
				if err == nil {
					t.Fatalf("%s must be refused, got %v", tc.member, got)
				}
				for _, want := range tc.refusedNaming {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("the refusal must name %q:\n%v", want, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("RequiredActions: %v", err)
			}
			if DescribeActions(got) != DescribeActions(tc.want) {
				t.Fatalf("read %v, want %v", got, tc.want)
			}
		})
	}
}

// The canonical AND-array must also survive INFERENCE, not just the actions
// walk: the requirement combination is what names the profile, and an action
// list — of any shape — never enters that decision.
func TestCanonicalANDArrayDoesNotDisturbProfileInference(t *testing.T) {
	op := onlyOperation(t, docWithOperation(t,
		"security:\n  - popProof: []\n    theGrant: []",
		`x-dfos-actions: [["read:profile", "read:email"]]`))

	ranked := Rank(op.Alternatives())
	if len(ranked) != 1 || ranked[0].Profile != ProfileDelegated || !ranked[0].Credential {
		t.Fatalf("ranked = %+v, want the delegated combination", ranked)
	}
	actions, err := op.RequiredActions()
	if err != nil {
		t.Fatalf("RequiredActions: %v", err)
	}
	if CoversActions(actions, map[string]bool{"read:profile": true}) {
		t.Fatalf("half of the pair must not cover it")
	}
	if !CoversActions(actions, map[string]bool{"read:profile": true, "read:email": true}) {
		t.Fatalf("the whole pair must cover it")
	}
}

// The errata shapes get a CLI-native message naming the shape. The behavior is
// unchanged — both are still refused — but a raw decoder error reads as a
// parser complaint about a document problem, and sends a reader looking in the
// wrong place.
func TestMalformedActionsNameTheShapeRatherThanLeakingTheDecoder(t *testing.T) {
	t.Run("a map is the scheme-level catalog written in the wrong place", func(t *testing.T) {
		op := onlyOperation(t, docWithOperation(t,
			"security:\n  - popProof: []\n    theGrant: []",
			"x-dfos-actions:\n  read:profile: Read the profile"))
		_, err := op.RequiredActions()
		if err == nil {
			t.Fatal("a map-valued member must be refused")
		}
		for _, want := range []string{"map of action token to description", "security scheme", "array of alternatives"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("message must name %q:\n%v", want, err)
			}
		}
		if strings.Contains(err.Error(), "yaml:") {
			t.Fatalf("the decoder's own words must not leak:\n%v", err)
		}
	})

	t.Run("a bare token names itself and the array it belongs in", func(t *testing.T) {
		op := onlyOperation(t, docWithOperation(t,
			"security:\n  - popProof: []\n    theGrant: []",
			"x-dfos-actions: read:profile"))
		_, err := op.RequiredActions()
		if err == nil {
			t.Fatal("a scalar member must be refused")
		}
		if !strings.Contains(err.Error(), `[read:profile]`) {
			t.Fatalf("the message must show the corrected spelling:\n%v", err)
		}
		if strings.Contains(err.Error(), "yaml:") {
			t.Fatalf("the decoder's own words must not leak:\n%v", err)
		}
	})
}

// A `scheme: dfos` scheme marked with an envelope type outside the registered
// pair is THIS family, mis-marked — a document bug fixable in one line. Reading
// it out as "a scheme this client does not implement" and stopping sends the
// reader hunting through their client instead.
func TestUnimplementedSchemeSaysWhichKindOfUnimplemented(t *testing.T) {
	t.Run("a mis-marked dfos scheme names its own marker", func(t *testing.T) {
		doc, err := Parse([]byte(`openapi: 3.1.0
info: {title: t, version: "1"}
servers: [{url: "https://api.example.test"}]
paths:
  /thing:
    get:
      operationId: getThing
      security: [{dfosAuth: []}]
components:
  securitySchemes:
    dfosAuth: {type: http, scheme: dfos, x-dfos-typ: REQUIRED}
`))
		if err != nil {
			t.Fatal(err)
		}
		op, err := doc.FindOperation("getThing")
		if err != nil {
			t.Fatal(err)
		}
		reason := op.Alternatives()[0].Unsatisfiable
		for _, want := range []string{"dfosAuth", `"REQUIRED"`, TypIdentityProof, TypRequestProof} {
			if !strings.Contains(reason, want) {
				t.Fatalf("the reason must name %q:\n%s", want, reason)
			}
		}
	})

	t.Run("a scheme outside the family says so instead", func(t *testing.T) {
		op := onlyOperation(t, docWithOperation(t, "security:\n  - bearerish: []", ""))
		reason := op.Alternatives()[0].Unsatisfiable
		if !strings.Contains(reason, "not part of the DFOS envelope family") {
			t.Fatalf("reason = %q", reason)
		}
	})

	t.Run("a requirement naming an undeclared scheme says THAT", func(t *testing.T) {
		op := onlyOperation(t, docWithOperation(t, "security:\n  - nowhere: []", ""))
		reason := op.Alternatives()[0].Unsatisfiable
		if !strings.Contains(reason, "declared nowhere in components.securitySchemes") {
			t.Fatalf("reason = %q", reason)
		}
	})
}

// A document past the read limit reports its SIZE, not a truncation artifact.
// The old failure — the reader stopping at exactly the limit and the YAML
// scanner calling that "unexpected end of stream" — read as a syntax error in a
// document that has none.
func TestOverSizeDocumentSaysItIsOverSize(t *testing.T) {
	// Valid YAML, then a comment long enough to put the whole past the limit —
	// so the only thing wrong with the document is its size.
	prefix := "openapi: 3.1.0\ninfo: {title: t, version: \"1\"}\npaths: {}\n# "
	body := make([]byte, 0, MaxDocumentBytes+len(prefix)+1)
	body = append(body, prefix...)
	for len(body) <= MaxDocumentBytes {
		body = append(body, 'x')
	}
	_, err := Parse(body)
	if err == nil {
		t.Fatal("an over-size document must be refused")
	}
	if !strings.Contains(err.Error(), "too large") || !strings.Contains(err.Error(), "16 MiB") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "not an OpenAPI document") {
		t.Fatalf("size must not be reported as a parse failure:\n%v", err)
	}
}

// The root default applies to operations that state no requirement of their own,
// and an operation's own empty list overrides it.
func TestRootSecurityIsInheritedAndOverridable(t *testing.T) {
	body := `openapi: 3.1.0
info: {title: t, version: "1"}
security:
  - whoIsAsking: []
paths:
  /inherits:
    get:
      operationId: inherits
  /opts-out:
    get:
      operationId: optsOut
      security: []
` + schemeYAML
	doc, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	inherits, err := doc.FindOperation("inherits")
	if err != nil {
		t.Fatal(err)
	}
	if got := inherits.Alternatives()[0].Profile; got != ProfileIdentity {
		t.Fatalf("an operation with no security member must inherit the root default, got %q", got)
	}
	optsOut, err := doc.FindOperation("optsOut")
	if err != nil {
		t.Fatal(err)
	}
	if got := optsOut.Alternatives()[0].Profile; got != ProfileAnonymous {
		t.Fatalf("an operation with security: [] must be anonymous, got %q", got)
	}
}

func TestParseProfile(t *testing.T) {
	for spelling, want := range map[string]Profile{
		"anon": ProfileAnonymous, "anonymous": ProfileAnonymous, "ANON": ProfileAnonymous,
		"identity": ProfileIdentity, "delegated": ProfileDelegated,
	} {
		got, err := ParseProfile(spelling)
		if err != nil || got != want {
			t.Fatalf("ParseProfile(%q) = %q, %v", spelling, got, err)
		}
	}
	if _, err := ParseProfile("bearer"); err == nil {
		t.Fatalf("an unknown profile must be refused")
	}
}

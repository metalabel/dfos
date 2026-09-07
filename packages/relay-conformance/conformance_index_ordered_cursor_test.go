package conformance

import (
	"encoding/json"
	"net/url"
	"testing"
)

// ===================================================================
// ORDERED CURSORS TERMINATE
//
// Every /index/v0 route that advertises `order` returns a `next` cursor with the
// page it belongs to. Following that cursor MUST advance: a route that accepts
// `order` but ignores it (or ignores the ordered `after` that goes with it)
// answers the second request with the first page and the same `next`, and a
// client walking it never finishes. That was live on a public relay.
//
// SEED-FREE ON PURPOSE. The contract holds against whatever corpus the relay
// already serves — including an empty one, where `next` is simply absent — so
// this runs under CONFORMANCE_SERVED_CORPUS=1 as well as against a seeded relay.
// ===================================================================

// orderedIndexFamily is one route that advertises ordering: its envelope key,
// the row field identifying a row, and the orders it accepts.
type orderedIndexFamily struct {
	family string
	rowKey string
	orders []string
	// extra supplies required non-order parameters (countersignatures needs a
	// witness). Returning false skips the family.
	extra func(t *testing.T, base string) (url.Values, bool)
}

var orderedIndexFamilies = []orderedIndexFamily{
	{family: "identities", rowKey: "did", orders: []string{"genesisAt.desc", "headAt.desc"}},
	{family: "content", rowKey: "contentId", orders: []string{"genesisAt.desc", "headAt.desc"}},
	{family: "operations", rowKey: "cid", orders: []string{"createdAt.desc", "ingestedAt.desc"}},
	{family: "artifacts", rowKey: "cid", orders: []string{"createdAt.desc", "ingestedAt.desc"}},
	{family: "credentials", rowKey: "cid", orders: []string{"createdAt.desc", "ingestedAt.desc"}},
	{
		family: "countersignatures",
		rowKey: "cid",
		orders: []string{"createdAt.desc", "ingestedAt.desc"},
		extra:  countersignatureWitness,
	},
}

// countersignatureWitness names the relay's own DID: the witness a relay that
// countersigns is the witness OF, and the one witness any served corpus can be
// asked about without seeding one.
func countersignatureWitness(t *testing.T, base string) (url.Values, bool) {
	t.Helper()
	var wellKnown struct {
		DID string `json:"did"`
	}
	resp := getJSON(t, base+"/.well-known/dfos-relay", &wellKnown)
	if resp.StatusCode != 200 || wellKnown.DID == "" {
		return nil, false
	}
	return url.Values{"witness": {wellKnown.DID}}, true
}

// orderedIndexPage reads one page of an ordered family: its rows and its cursor.
func orderedIndexPage(
	t *testing.T,
	base, family, rowKey string,
	query url.Values,
) ([]map[string]any, *string) {
	t.Helper()
	var body map[string]json.RawMessage
	resp := getJSON(t, base+"/index/v0/"+family+"?"+query.Encode(), &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("%s?%s: status %d, want 200", family, query.Encode(), resp.StatusCode)
	}
	var rows []map[string]any
	if err := json.Unmarshal(body[family], &rows); err != nil || rows == nil {
		t.Fatalf("%s: missing or invalid rows: %s", family, body[family])
	}
	var next *string
	if raw, present := body["next"]; present {
		if err := json.Unmarshal(raw, &next); err != nil {
			t.Fatalf("%s: invalid next: %s", family, raw)
		}
	}
	for _, row := range rows {
		if value, ok := row[rowKey].(string); !ok || value == "" {
			t.Fatalf("%s: row missing %s: %+v", family, rowKey, row)
		}
	}
	return rows, next
}

func TestIndexOrderedCursorAdvances(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)

	const limit = "2"
	for _, family := range orderedIndexFamilies {
		for _, order := range family.orders {
			t.Run(family.family+"/order="+order, func(t *testing.T) {
				query := url.Values{"order": {order}, "limit": {limit}}
				if family.extra != nil {
					extra, ok := family.extra(t, base)
					if !ok {
						t.Skipf("%s: no witness available on this relay", family.family)
					}
					for key, values := range extra {
						query[key] = values
					}
				}

				first, next := orderedIndexPage(t, base, family.family, family.rowKey, query)

				// A page short of the limit is the end of the corpus, and the
				// route must say so by omitting the cursor rather than handing
				// out one that walks the same rows again.
				if len(first) < 2 {
					if next != nil {
						t.Fatalf("%s: %d rows under a limit of 2 but next=%q", family.family, len(first), *next)
					}
					return
				}
				if next == nil || *next == "" {
					t.Fatalf("%s: a full page carried no next cursor", family.family)
				}

				following := url.Values{}
				for key, values := range query {
					following[key] = values
				}
				following.Set("after", *next)
				second, secondNext := orderedIndexPage(t, base, family.family, family.rowKey, following)

				if secondNext != nil && *secondNext == *next {
					t.Fatalf("%s: following next returned the SAME cursor %q — pagination never terminates",
						family.family, *next)
				}
				if len(second) > 0 && second[0][family.rowKey] == first[0][family.rowKey] {
					t.Fatalf("%s: following next returned the same first row %v — the ordered cursor was ignored",
						family.family, first[0][family.rowKey])
				}
			})
		}
	}
}

package conformance

import (
	"encoding/json"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

func skipServedCorpusFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("CONFORMANCE_SERVED_CORPUS") == "1" {
		t.Skip("served corpus: this test requires fixtures seeded through POST /proof/v1/operations")
	}
}

// servedIndexPage checks the wire envelope before decoding rows: missing/null
// arrays and a missing next must not masquerade as a valid empty page.
func servedIndexPage(t *testing.T, base, family string, query url.Values, limit int) ([]map[string]any, *string) {
	t.Helper()
	query.Set("limit", strconv.Itoa(limit))
	var body map[string]json.RawMessage
	resp := getJSON(t, base+"/index/v0/"+family+"?"+query.Encode(), &body)
	if resp.StatusCode != 200 {
		t.Fatalf("%s: status %d, want 200", family, resp.StatusCode)
	}
	var rows []map[string]any
	if err := json.Unmarshal(body[family], &rows); err != nil || rows == nil {
		t.Fatalf("%s: missing or invalid rows: %s", family, body[family])
	}
	var next *string
	if err := json.Unmarshal(body["next"], &next); err != nil {
		t.Fatalf("%s: invalid next: %s", family, body["next"])
	}
	if len(rows) > limit || (len(rows) < limit && next != nil) || (len(rows) == limit && (next == nil || *next == "")) {
		t.Fatalf("%s: limit=%d rows=%d next=%v", family, limit, len(rows), next)
	}
	for _, row := range rows {
		fields := []string{"cid", "kind", "chainId", "createdAt", "ingestedAt"}
		timestamps := []string{"createdAt", "ingestedAt"}
		if family == "identities" {
			fields = []string{"did", "headCID", "genesisAt", "headAt"}
			timestamps = []string{"genesisAt", "headAt"}
		}
		for _, field := range fields {
			if value, ok := row[field].(string); !ok || value == "" {
				t.Fatalf("%s: invalid %s: %+v", family, field, row)
			}
		}
		for _, field := range timestamps {
			if _, err := time.Parse(time.RFC3339Nano, row[field].(string)); err != nil {
				t.Fatalf("invalid %s: %v", field, row[field])
			}
		}
		if family == "identities" {
			count, ok := row["opCount"].(float64)
			if !ok || count < 1 || count != float64(int(count)) {
				t.Fatalf("invalid opCount: %+v", row)
			}
			if _, ok := row["isDeleted"].(bool); !ok {
				t.Fatalf("invalid isDeleted: %+v", row)
			}
			profile, present := row["profile"]
			if !present {
				t.Fatal("missing profile")
			}
			if profile != nil {
				p, ok := profile.(map[string]any)
				if !ok {
					t.Fatal("invalid profile")
				}
				if anchor, ok := p["anchor"].(string); !ok || anchor == "" {
					t.Fatal("invalid profile anchor")
				}
				if _, ok := p["publicRead"].(bool); !ok {
					t.Fatal("invalid publicRead")
				}
			}
		}
	}
	return rows, next
}

func TestIndexServedCorpus(t *testing.T) {
	if os.Getenv("CONFORMANCE_SERVED_CORPUS") != "1" {
		t.Skip("served corpus: set CONFORMANCE_SERVED_CORPUS=1 to test existing index rows")
	}
	base := relayURL(t)
	requireIndexCapability(t, base)
	for _, family := range []string{"identities", "operations"} {
		orders := []string{"", "createdAt.desc", "ingestedAt.desc"}
		if family == "identities" {
			orders = []string{"", "genesisAt.desc", "headAt.desc"}
		}
		for _, order := range orders {
			t.Run(family+"/order="+order, func(t *testing.T) {
				query := url.Values{}
				if order != "" {
					query.Set("order", order)
				}
				rows, next := servedIndexPage(t, base, family, query, 2)
				whole, _ := servedIndexPage(t, base, family, query, 4)
				if next != nil {
					query.Set("after", *next)
					following, _ := servedIndexPage(t, base, family, query, 2)
					rows = append(rows, following...)
				}
				if !reflect.DeepEqual(rows, whole) {
					t.Fatalf("cursor round-trip differs from contiguous page: paged=%+v whole=%+v", rows, whole)
				}
				key, stamp := "cid", "ingestedAt"
				if family == "identities" {
					key, stamp = "did", ""
				}
				if order != "" {
					stamp = order[:len(order)-5]
				}
				for i := 1; i < len(rows); i++ {
					prev, cur := rows[i-1], rows[i]
					if prev[key] == cur[key] {
						t.Fatalf("cursor duplicated %v", cur[key])
					}
					if stamp == "" {
						if prev[key].(string) >= cur[key].(string) {
							t.Fatal("identities are not strictly ascending")
						}
					} else {
						a, _ := time.Parse(time.RFC3339Nano, prev[stamp].(string))
						b, _ := time.Parse(time.RFC3339Nano, cur[stamp].(string))
						if a.Before(b) || (a.Equal(b) && prev[key].(string) >= cur[key].(string)) {
							t.Fatalf("invalid composite ordering: %+v then %+v", prev, cur)
						}
					}
				}
				if family == "identities" && order == "" && next != nil && *next != rows[1]["did"] {
					t.Fatal("lexical next must equal last returned DID")
				}
			})
		}
	}
	t.Run("identity filters", func(t *testing.T) {
		rows, _ := servedIndexPage(t, base, "identities", url.Values{}, 1)
		for _, value := range []string{"true", "false"} {
			filtered, _ := servedIndexPage(t, base, "identities", url.Values{"hasPublicProfile": {value}}, 1000)
			for _, row := range filtered {
				p, _ := row["profile"].(map[string]any)
				public := p != nil && p["publicRead"] == true
				if public != (value == "true") {
					t.Fatalf("hasPublicProfile=%s returned %+v", value, row)
				}
			}
		}
		for _, value := range []string{"", "yes"} {
			var body struct {
				Error string `json:"error"`
			}
			resp := getJSON(t, base+"/index/v0/identities?hasPublicProfile="+value, &body)
			if resp.StatusCode != 400 || body.Error == "" {
				t.Fatalf("invalid boolean: status %d body %+v", resp.StatusCode, body)
			}
		}
		if len(rows) == 0 {
			t.Skip("served corpus: no identity available for exact DID and proved-key positive controls")
		}
		did := rows[0]["did"].(string)
		profile, _ := rows[0]["profile"].(map[string]any)
		public := profile != nil && profile["publicRead"] == true
		for _, value := range []bool{false, true} {
			matched, _ := servedIndexPage(t, base, "identities", url.Values{"did": {did}, "hasPublicProfile": {strconv.FormatBool(value)}}, 2)
			want := 0
			if value == public {
				want = 1
			}
			if len(matched) != want || (want == 1 && matched[0]["did"] != did) {
				t.Fatalf("did + hasPublicProfile=%t: %+v", value, matched)
			}
		}

		exact, _ := servedIndexPage(t, base, "identities", url.Values{"did": {did}}, 2)
		if len(exact) != 1 || exact[0]["did"] != did {
			t.Fatalf("did= failed exact match: %+v", exact)
		}
		requireIdentityKeyFilter(t, base)
		var log struct {
			Entries []wdLogEntry `json:"entries"`
		}
		resp := getJSON(t, base+"/proof/v1/identities/"+did+"/log?limit=1", &log)
		if resp.StatusCode != 200 || len(log.Entries) != 1 {
			t.Fatalf("served identity genesis: status %d body %+v", resp.StatusCode, log)
		}
		_, payload, err := dfos.DecodeJWSUnsafe(log.Entries[0].JWSToken)
		if err != nil {
			t.Fatal(err)
		}
		keys, ok := payload["authKeys"].([]any)
		if !ok || len(keys) != 1 {
			t.Fatal("genesis must declare one auth key")
		}
		key, ok := keys[0].(map[string]any)
		if !ok {
			t.Fatal("invalid genesis key")
		}
		multibase, ok := key["publicKeyMultibase"].(string)
		if !ok || multibase == "" {
			t.Fatal("missing genesis public key")
		}
		matched, _ := servedIndexPage(t, base, "identities", url.Values{"did": {did}, "key": {multibase}}, 2)
		if len(matched) != 1 || matched[0]["did"] != did {
			t.Fatalf("proved genesis key did not match: %+v", matched)
		}
		unmatched, _ := servedIndexPage(t, base, "identities", url.Values{"did": {did}, "key": {"conformance impossible key !"}}, 2)
		if len(unmatched) != 0 {
			t.Fatal("did and key filters must intersect")
		}
	})
	t.Run("operation filters", func(t *testing.T) {
		requireSignerKeyFilter(t, base)
		rows, _ := servedIndexPage(t, base, "operations", url.Values{}, 1)
		if len(rows) == 0 {
			t.Skip("served corpus: no operation available for filter positive controls")
		}
		row := rows[0]
		filtered, _ := servedIndexPage(t, base, "operations", url.Values{"kind": {row["kind"].(string)}, "chainId": {row["chainId"].(string)}}, 1000)
		found := false
		for _, r := range filtered {
			if r["kind"] != row["kind"] || r["chainId"] != row["chainId"] {
				t.Fatal("operation filters did not intersect")
			}
			found = found || r["cid"] == row["cid"]
		}
		if !found {
			t.Fatal("operation filter omitted served positive control")
		}
	})
}

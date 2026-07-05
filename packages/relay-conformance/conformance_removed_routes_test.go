// Removed-route regression guard.
//
// The amendment DELETED two routes that earlier relay revisions served:
//
//	GET /proof/v1/operations/{cid}/countersignatures  (replaced by
//	                          GET /proof/v1/countersignatures/{cid})
//	GET /content/{contentId}/documents                (removed outright)
//
// A 404-on-absent-route assertion is inherently low-signal — any unknown path
// 404s, so this cannot distinguish "deleted" from "never existed". Its value is
// narrow but real: it guards against a relay ACCIDENTALLY re-introducing the old
// sub-route alongside the new one (e.g. serving BOTH countersignature shapes).
// To keep the signal, the probes use a genuinely existing op CID / content id, so
// a 404 proves the sub-route is gone rather than the parent resource missing.
package conformance

import (
	"net/http"
	"testing"
)

func TestRemovedRoutes404(t *testing.T) {
	base := relayURL(t)

	// A real identity + content chain, so the parent resources genuinely exist:
	// the op CID resolves and the content id resolves. Any 404 below is therefore
	// attributable to the removed sub-route, not a missing parent.
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	cases := []struct {
		name string
		path string
	}{
		{
			// old countersignatures shape, hung off a known op CID
			name: "GET /proof/v1/operations/{cid}/countersignatures",
			path: "/proof/v1/operations/" + cc.genCID + "/countersignatures",
		},
		{
			// old documents route, hung off a known content id
			name: "GET /content/{contentId}/documents",
			path: "/content/" + cc.contentID + "/documents",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(base + tc.path)
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("GET %s: expected 404 (route removed), got %d", tc.path, resp.StatusCode)
			}
		})
	}
}

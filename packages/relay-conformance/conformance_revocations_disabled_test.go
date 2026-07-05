// Revocations-plane-disabled relay: when the well-known advertises
// capabilities.revocations == false, every /revocations/v1 route MUST return
// 501 Not Implemented ("capability not supported") — NOT 404, and NOT 200 with
// an empty projection. This mirrors the content-plane 501 contract
// (conformance_content_disabled_test.go) and the amendment's item-3 clause: a
// relay that does not serve the revocation-status index advertises the
// capability false and 501s the routes.
//
// This is a gated conformance check: it runs only against a relay deployed with
// the revocations capability OFF. Against the reference relays (which always
// advertise revocations: true) it self-skips, so it is safe to keep in the
// default `go test ./...` run. It exists to hold arbitrary third-party relays
// to the contract — the 501 gate fires before any store lookup or param
// validation, so it holds regardless of whether the credential/issuer exists.
package conformance

import "testing"

// revocationsDisabledBase returns the relay URL only if the relay advertises
// capabilities.revocations == false; otherwise it skips. This scopes the 501
// assertions to the deployment they describe — a revocations-enabled relay (the
// common case) legitimately returns 200/400 on these routes, not 501.
func revocationsDisabledBase(t *testing.T) string {
	t.Helper()
	base := relayURL(t)

	var meta struct {
		Capabilities map[string]any `json:"capabilities"`
	}
	resp := getJSON(t, base+"/.well-known/dfos-relay", &meta)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /.well-known/dfos-relay: status %d", resp.StatusCode)
	}
	if meta.Capabilities["revocations"] != false {
		t.Skip("relay does not advertise capabilities.revocations: false — skipping revocations-disabled conformance")
	}
	return base
}

// TestRevocationsDisabledRoutes501 asserts both /revocations/v1 read routes
// return 501 on a revocations-disabled relay. It reuses assert501 (defined in
// conformance_content_disabled_test.go) so the 404-vs-501 distinction — a
// capability gate, not a missing resource — is enforced identically to the
// content plane.
func TestRevocationsDisabledRoutes501(t *testing.T) {
	base := revocationsDisabledBase(t)

	// Well-formed credential CID and 31-char did:dfos, so a hypothetical 400
	// (malformed param) cannot masquerade as the 501 we are testing for — the
	// capability gate must precede param validation.
	const credentialCID = "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const issuerDID = "did:dfos:2222222222222222222222222222222"

	t.Run("GET /revocations/v1/credential/{cid}", func(t *testing.T) {
		resp := getJSON(t, base+"/revocations/v1/credential/"+credentialCID, nil)
		assert501(t, "GET /revocations/v1/credential/{cid}", resp)
	})

	t.Run("GET /revocations/v1/issuer/{did}", func(t *testing.T) {
		resp := getJSON(t, base+"/revocations/v1/issuer/"+issuerDID, nil)
		assert501(t, "GET /revocations/v1/issuer/{did}", resp)
	})
}

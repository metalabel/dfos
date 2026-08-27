package dfos

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

// The cross-language vector set. Every literal in this block is pinned
// byte-identically in packages/dfos-client/tests/api-auth.spec.ts — if one side
// moves, both test suites go red rather than the two signers silently forking.
const apiAuthVectorCID = "bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne"
const apiAuthVectorKid = "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae#key_api_auth_vector"
const apiAuthVectorIat = 1772841600

const apiAuthVectorCanonical = `{"method":"GET","host":"api.dfos.com","path":"/v0/profile","bodyHash":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","credentialCID":"bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne","iat":1772841600}`
const apiAuthVectorCanonicalQuery = `{"method":"GET","host":"api.dfos.com","path":"/v0/profile?a=1&b=2","bodyHash":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","credentialCID":"bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne","iat":1772841600}`
const apiAuthVectorCanonicalHTML = `{"method":"GET","host":"api.dfos.com","path":"/v0/profile?q=<a>&b=2","bodyHash":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","credentialCID":"bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne","iat":1772841600}`
const apiAuthVectorJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlcXVlc3QtcHJvb2YiLCJraWQiOiJkaWQ6ZGZvczpuemtmODM4ZWZyNDI0NDMzcm4ycnprZHY4aDd0OWFlI2tleV9hcGlfYXV0aF92ZWN0b3IifQ.eyJtZXRob2QiOiJHRVQiLCJob3N0IjoiYXBpLmRmb3MuY29tIiwicGF0aCI6Ii92MC9wcm9maWxlIiwiYm9keUhhc2giOiI0N0RFUXBqOEhCU2EtX1RJbVctNUpDZXVRZVJrbTVOTXBKV1pHM2hTdUZVIiwiY3JlZGVudGlhbENJRCI6ImJhZnlyZWljb2dodmp6bnZsaXVsb3h4bWJmNTR0cHpxd2FobnFwaWxrN25jeGVwamluZWRwa2dhM25lIiwiaWF0IjoxNzcyODQxNjAwfQ.K2TZ7NC4ad9VRF2GM0J3YTNBl3DGdFMmYA6rqgJFGKXjd5WDU5zlqHZzhnWZO1tuplfq8tOeQ75upK_kGxQ2BA"

// The identity proof's half of the SAME fixture: the same seed, kid, iat, host,
// and paths, with credentialCID absent. Five members, canonical order
// method, host, path, bodyHash, iat.
const apiAuthIdentityCanonical = `{"method":"GET","host":"api.dfos.com","path":"/v0/profile","bodyHash":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","iat":1772841600}`
const apiAuthIdentityCanonicalQuery = `{"method":"GET","host":"api.dfos.com","path":"/v0/profile?a=1&b=2","bodyHash":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","iat":1772841600}`
const apiAuthIdentityCanonicalHTML = `{"method":"GET","host":"api.dfos.com","path":"/v0/profile?q=<a>&b=2","bodyHash":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","iat":1772841600}`
const apiAuthIdentityJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LXByb29mIiwia2lkIjoiZGlkOmRmb3M6bnprZjgzOGVmcjQyNDQzM3JuMnJ6a2R2OGg3dDlhZSNrZXlfYXBpX2F1dGhfdmVjdG9yIn0.eyJtZXRob2QiOiJHRVQiLCJob3N0IjoiYXBpLmRmb3MuY29tIiwicGF0aCI6Ii92MC9wcm9maWxlIiwiYm9keUhhc2giOiI0N0RFUXBqOEhCU2EtX1RJbVctNUpDZXVRZVJrbTVOTXBKV1pHM2hTdUZVIiwiaWF0IjoxNzcyODQxNjAwfQ.rfajvn-hrPlzQex_UwiMNzO5D5k0PR_TaGxxpl_t4PBUTeoZKGL9CLUX6TtPKyRm8D_JYP0wpQH8EGZORpMkCw"

// The digest of `{"a":1}` — the body-bearing vector, pinned in both languages.
const apiAuthVectorBodyHash = "AVq9f1zFei3ZS3WQ8ErYCEJzkF7jPsXOvq5iJ2qX-GI"

func apiAuthVectorPayload(path string) RequestProofPayload {
	return RequestProofPayload{
		Method: "GET", Host: "api.dfos.com", Path: path,
		BodyHash: EmptyBodySHA256, CredentialCID: apiAuthVectorCID, Iat: apiAuthVectorIat,
	}
}

func apiAuthIdentityPayload(path string) IdentityProofPayload {
	return IdentityProofPayload{
		Method: "GET", Host: "api.dfos.com", Path: path,
		BodyHash: EmptyBodySHA256, Iat: apiAuthVectorIat,
	}
}

func apiAuthVectorKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func apiAuthVectorResolver(privateKey ed25519.PrivateKey) KeyResolver {
	public := privateKey.Public().(ed25519.PublicKey)
	return func(kid string) (ed25519.PublicKey, error) {
		if kid != apiAuthVectorKid {
			return nil, errors.New("unknown kid")
		}
		return public, nil
	}
}

func TestApiRequestSharedCanonicalAndSignedVectors(t *testing.T) {
	for _, vector := range []struct{ path, want string }{
		{"/v0/profile", apiAuthVectorCanonical},
		{"/v0/profile?a=1&b=2", apiAuthVectorCanonicalQuery},
		{"/v0/profile?q=<a>&b=2", apiAuthVectorCanonicalHTML},
	} {
		got, err := ApiRequestSigningInput(apiAuthVectorPayload(vector.path))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != vector.want {
			t.Fatalf("canonical bytes:\n got %s\nwant %s", got, vector.want)
		}
	}

	token, err := BuildRequestProof("GET", "api.dfos.com", "/v0/profile", apiAuthVectorCID,
		apiAuthVectorKid, apiAuthVectorKey(), RequestProofOptions{Iat: apiAuthVectorIat})
	if err != nil {
		t.Fatal(err)
	}
	if token != apiAuthVectorJWS {
		t.Fatalf("signed request-proof vector:\n got %s\nwant %s", token, apiAuthVectorJWS)
	}

	// The payload SEGMENT is the signing input, by construction — the single
	// reason there is one byte contract and not two.
	segment, err := Base64urlDecode(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	if string(segment) != apiAuthVectorCanonical {
		t.Fatalf("payload segment is not the canonical signing input: %s", segment)
	}
}

// The vector that catches an encoding/json fork: `&`, `<`, and `>` MUST ride the
// signed bytes LITERALLY. A Go implementation that reached for encoding/json
// would emit \u0026 / \u003c / \u003e and produce a proof no TS verifier accepts.
func TestApiRequestSigningInputLeavesHTMLCharactersLiteral(t *testing.T) {
	got, err := ApiRequestSigningInput(apiAuthVectorPayload("/v0/profile?q=<a>&b=2"))
	if err != nil {
		t.Fatal(err)
	}
	canonical := string(got)
	for _, literal := range []string{`"path":"/v0/profile?q=<a>&b=2"`} {
		if !strings.Contains(canonical, literal) {
			t.Fatalf("canonical bytes do not carry %s: %s", literal, canonical)
		}
	}
	for _, escaped := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if strings.Contains(canonical, escaped) {
			t.Fatalf("canonical bytes carry an HTML escape %s: %s", escaped, canonical)
		}
	}
}

func TestSha256BodyHashVectors(t *testing.T) {
	if got := Sha256BodyHash(nil); got != EmptyBodySHA256 {
		t.Fatalf("empty body digest: got %s want %s", got, EmptyBodySHA256)
	}
	if got := Sha256BodyHash([]byte{}); got != EmptyBodySHA256 {
		t.Fatalf("zero-length body digest: got %s want %s", got, EmptyBodySHA256)
	}
	if got := Sha256BodyHash([]byte(`{"a":1}`)); got != apiAuthVectorBodyHash {
		t.Fatalf("body digest: got %s want %s", got, apiAuthVectorBodyHash)
	}
}

func TestApiRequestSigningInputRejectsSchemaViolations(t *testing.T) {
	base := apiAuthVectorPayload("/v0/profile")
	mutate := func(f func(p *RequestProofPayload)) RequestProofPayload {
		p := base
		f(&p)
		return p
	}
	vectors := []struct {
		name    string
		payload RequestProofPayload
	}{
		{"lowercase method", mutate(func(p *RequestProofPayload) { p.Method = "get" })},
		{"mixed-case method", mutate(func(p *RequestProofPayload) { p.Method = "GeT" })},
		{"empty method", mutate(func(p *RequestProofPayload) { p.Method = "" })},
		{"uppercase host", mutate(func(p *RequestProofPayload) { p.Host = "API.dfos.com" })},
		{"host with scheme", mutate(func(p *RequestProofPayload) { p.Host = "https://api.dfos.com" })},
		{"relative path", mutate(func(p *RequestProofPayload) { p.Path = "v0/profile" })},
		{"path with fragment", mutate(func(p *RequestProofPayload) { p.Path = "/v0/profile#top" })},
		{"path with space", mutate(func(p *RequestProofPayload) { p.Path = "/v0/pro file" })},
		{"padded bodyHash", mutate(func(p *RequestProofPayload) { p.BodyHash = EmptyBodySHA256 + "=" })},
		{"short bodyHash", mutate(func(p *RequestProofPayload) { p.BodyHash = EmptyBodySHA256[:42] })},
		{"standard-base64 bodyHash", mutate(func(p *RequestProofPayload) {
			p.BodyHash = strings.ReplaceAll(strings.ReplaceAll(EmptyBodySHA256, "-", "+"), "_", "/")
		})},
		{"empty credentialCID", mutate(func(p *RequestProofPayload) { p.CredentialCID = "" })},
		{"zero iat", mutate(func(p *RequestProofPayload) { p.Iat = 0 })},
		{"negative iat", mutate(func(p *RequestProofPayload) { p.Iat = -1 })},
	}
	for _, vector := range vectors {
		if _, err := ApiRequestSigningInput(vector.payload); err == nil {
			t.Errorf("schema violation accepted: %s", vector.name)
		}
	}
}

// A non-canonical bodyHash SPELLING of the right 32 bytes must reject, not
// normalize: the member is compared as a string against the verifier's own
// re-encoding, so a verifier that decoded and compared bytes would silently
// accept it. `…SuFU` and `…SuFV` decode to the same 32 bytes (the trailing bits
// differ), and only the first re-encodes to itself.
func TestApiRequestNonCanonicalBodyHashSpellingRejects(t *testing.T) {
	nonCanonical := EmptyBodySHA256[:len(EmptyBodySHA256)-1] + "V"
	payload := apiAuthVectorPayload("/v0/profile")
	payload.BodyHash = nonCanonical
	if _, err := ApiRequestSigningInput(payload); err == nil {
		t.Fatalf("non-canonical bodyHash spelling accepted: %s", nonCanonical)
	}
}

func TestVerifyRequestProofAcceptsTheVector(t *testing.T) {
	key := apiAuthVectorKey()
	payload, err := VerifyRequestProof(apiAuthVectorJWS, RequestProofExpectations{
		Method: "GET", Host: "api.dfos.com", Path: "/v0/profile",
	}, apiAuthVectorResolver(key), time.Unix(apiAuthVectorIat+10, 0))
	if err != nil {
		t.Fatal(err)
	}
	if payload.CredentialCID != apiAuthVectorCID || payload.Iat != apiAuthVectorIat {
		t.Fatalf("unexpected verified payload: %+v", payload)
	}
}

func TestVerifyRequestProofAdversarialVectors(t *testing.T) {
	key := apiAuthVectorKey()
	resolve := apiAuthVectorResolver(key)
	fresh := time.Unix(apiAuthVectorIat+10, 0)
	ok := RequestProofExpectations{Method: "GET", Host: "api.dfos.com", Path: "/v0/profile"}

	// A proof signed over a query-bearing path, for the path-mismatch vectors.
	queryProof, err := BuildRequestProof("GET", "api.dfos.com", "/v0/profile?a=1&b=2",
		apiAuthVectorCID, apiAuthVectorKid, key, RequestProofOptions{Iat: apiAuthVectorIat})
	if err != nil {
		t.Fatal(err)
	}
	bodyProof, err := BuildRequestProof("POST", "api.dfos.com", "/v0/profile",
		apiAuthVectorCID, apiAuthVectorKid, key,
		RequestProofOptions{Iat: apiAuthVectorIat, Body: []byte(`{"a":1}`)})
	if err != nil {
		t.Fatal(err)
	}

	vectors := []struct {
		name   string
		token  string
		expect RequestProofExpectations
		now    time.Time
		reason error
	}{
		{"wrong-case method", apiAuthVectorJWS,
			RequestProofExpectations{Method: "get", Host: ok.Host, Path: ok.Path}, fresh, ErrRequestProofInvalid},
		{"method mismatch", apiAuthVectorJWS,
			RequestProofExpectations{Method: "POST", Host: ok.Host, Path: ok.Path}, fresh, ErrRequestProofInvalid},
		{"host mismatch", apiAuthVectorJWS,
			RequestProofExpectations{Method: "GET", Host: "api.example.org", Path: ok.Path}, fresh, ErrRequestProofInvalid},
		{"host port mismatch", apiAuthVectorJWS,
			RequestProofExpectations{Method: "GET", Host: "api.dfos.com:8443", Path: ok.Path}, fresh, ErrRequestProofInvalid},
		{"query-string mismatch", queryProof, ok, fresh, ErrRequestProofInvalid},
		{"trailing-slash mismatch", apiAuthVectorJWS,
			RequestProofExpectations{Method: "GET", Host: ok.Host, Path: "/v0/profile/"}, fresh, ErrRequestProofInvalid},
		{"query-parameter reordering is not equivalence", queryProof,
			RequestProofExpectations{Method: "GET", Host: ok.Host, Path: "/v0/profile?b=2&a=1"}, fresh, ErrRequestProofInvalid},
		{"body-hash mismatch (body arrived, proof says empty)", apiAuthVectorJWS,
			RequestProofExpectations{Method: "GET", Host: ok.Host, Path: ok.Path, Body: []byte(`{"a":1}`)}, fresh, ErrRequestProofInvalid},
		{"body-hash mismatch (body dropped)", bodyProof,
			RequestProofExpectations{Method: "POST", Host: ok.Host, Path: ok.Path}, fresh, ErrRequestProofInvalid},
		{"stale iat", apiAuthVectorJWS, ok, time.Unix(apiAuthVectorIat+61, 0), ErrRequestProofInvalid},
		{"forward-dated iat", apiAuthVectorJWS, ok, time.Unix(apiAuthVectorIat-61, 0), ErrRequestProofInvalid},
		{"W + S over the ceiling", apiAuthVectorJWS,
			RequestProofExpectations{Method: "GET", Host: ok.Host, Path: ok.Path, WindowSeconds: Int64Ptr(240), SkewSeconds: Int64Ptr(61)},
			fresh, ErrRequestProofConfig},
		{"negative window", apiAuthVectorJWS,
			RequestProofExpectations{Method: "GET", Host: ok.Host, Path: ok.Path, WindowSeconds: Int64Ptr(-1)},
			fresh, ErrRequestProofConfig},
		{"single bound over the ceiling (overflow guard)", apiAuthVectorJWS,
			RequestProofExpectations{Method: "GET", Host: ok.Host, Path: ok.Path, WindowSeconds: Int64Ptr(301), SkewSeconds: Int64Ptr(0)},
			fresh, ErrRequestProofConfig},
		{"over-cap body refused before hashing", bodyProof,
			RequestProofExpectations{Method: "POST", Host: ok.Host, Path: ok.Path, Body: []byte(`{"a":1}`), MaxBodyBytes: Int64Ptr(3)},
			fresh, ErrRequestProofInvalid},
		{"negative maxBodyBytes is config", bodyProof,
			RequestProofExpectations{Method: "POST", Host: ok.Host, Path: ok.Path, Body: []byte(`{"a":1}`), MaxBodyBytes: Int64Ptr(-1)},
			fresh, ErrRequestProofConfig},
	}
	for _, vector := range vectors {
		_, err := VerifyRequestProof(vector.token, vector.expect, resolve, vector.now)
		if err == nil || !errors.Is(err, vector.reason) {
			t.Errorf("adversarial vector %q: got %v, want %v", vector.name, err, vector.reason)
		}
	}
}

// Age and forward skew are SEPARATE bounds, and the split is the whole reason
// the W + S ceiling means anything: a symmetric |now - iat| <= W would leave a
// fully forward-dated proof replayable for 2W.
func TestVerifyRequestProofAgeAndSkewAreSeparateBounds(t *testing.T) {
	key := apiAuthVectorKey()
	resolve := apiAuthVectorResolver(key)
	tight := RequestProofExpectations{
		Method: "GET", Host: "api.dfos.com", Path: "/v0/profile",
		WindowSeconds: Int64Ptr(30), SkewSeconds: Int64Ptr(5),
	}
	// An explicit W=0 / S=0 is HONORED, not silently rewritten to the 60s default
	// (the nil-vs-*0 distinction). Under W=0 a proof even 1s old is stale; a nil
	// window would have accepted it.
	zero := RequestProofExpectations{
		Method: "GET", Host: "api.dfos.com", Path: "/v0/profile",
		WindowSeconds: Int64Ptr(0), SkewSeconds: Int64Ptr(0),
	}
	if _, err := VerifyRequestProof(apiAuthVectorJWS, zero, resolve, time.Unix(apiAuthVectorIat, 0)); err != nil {
		t.Fatalf("proof at exactly iat under W=0: %v", err)
	}
	if _, err := VerifyRequestProof(apiAuthVectorJWS, zero, resolve, time.Unix(apiAuthVectorIat+1, 0)); !errors.Is(err, ErrRequestProofInvalid) {
		t.Fatalf("1s-old proof under explicit W=0 should be stale, got: %v", err)
	}
	// 20s old: inside W, and the skew bound is irrelevant.
	if _, err := VerifyRequestProof(apiAuthVectorJWS, tight, resolve, time.Unix(apiAuthVectorIat+20, 0)); err != nil {
		t.Fatalf("20s-old proof under W=30: %v", err)
	}
	// 20s forward-dated: well inside W, but S is only 5 — a symmetric window
	// would have accepted this.
	if _, err := VerifyRequestProof(apiAuthVectorJWS, tight, resolve, time.Unix(apiAuthVectorIat-20, 0)); !errors.Is(err, ErrRequestProofInvalid) {
		t.Fatalf("20s forward-dated proof under S=5: %v", err)
	}
	// Both boundaries are inclusive.
	if _, err := VerifyRequestProof(apiAuthVectorJWS, tight, resolve, time.Unix(apiAuthVectorIat+30, 0)); err != nil {
		t.Fatalf("proof at exactly W: %v", err)
	}
	if _, err := VerifyRequestProof(apiAuthVectorJWS, tight, resolve, time.Unix(apiAuthVectorIat-5, 0)); err != nil {
		t.Fatalf("proof at exactly S: %v", err)
	}
}

func TestVerifyRequestProofEnvelopeGates(t *testing.T) {
	key := apiAuthVectorKey()
	resolve := apiAuthVectorResolver(key)
	fresh := time.Unix(apiAuthVectorIat+10, 0)
	ok := RequestProofExpectations{Method: "GET", Host: "api.dfos.com", Path: "/v0/profile"}

	// Wrong typ — a credential or a SIWD proof must not route here.
	wrongTyp := signRawRequestProof(key, `{"alg":"EdDSA","typ":"did:dfos:siwd","kid":"`+apiAuthVectorKid+`"}`,
		apiAuthVectorCanonical)
	// crit — refused by the Signature Verification Profile.
	crit := signRawRequestProof(key, `{"alg":"EdDSA","typ":"`+RequestProofJWSTyp+`","kid":"`+apiAuthVectorKid+`","crit":["x"]}`,
		apiAuthVectorCanonical)
	// kid without a fragment.
	bareKid := signRawRequestProof(key, `{"alg":"EdDSA","typ":"`+RequestProofJWSTyp+`","kid":"did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae"}`,
		apiAuthVectorCanonical)
	// A padded bodyHash spelling, signed — the schema gate must still refuse it.
	paddedBody := strings.Replace(apiAuthVectorCanonical, EmptyBodySHA256, EmptyBodySHA256[:42]+"U=", 1)
	padded := signRawRequestProof(key, `{"alg":"EdDSA","typ":"`+RequestProofJWSTyp+`","kid":"`+apiAuthVectorKid+`"}`, paddedBody)
	// A missing member.
	missing := signRawRequestProof(key, `{"alg":"EdDSA","typ":"`+RequestProofJWSTyp+`","kid":"`+apiAuthVectorKid+`"}`,
		`{"method":"GET","host":"api.dfos.com","path":"/v0/profile","bodyHash":"`+EmptyBodySHA256+`","iat":1772841600}`)
	// A quoted iat.
	quotedIat := strings.Replace(apiAuthVectorCanonical, `"iat":1772841600`, `"iat":"1772841600"`, 1)
	quoted := signRawRequestProof(key, `{"alg":"EdDSA","typ":"`+RequestProofJWSTyp+`","kid":"`+apiAuthVectorKid+`"}`, quotedIat)
	// A tampered signature.
	tampered := apiAuthVectorJWS[:len(apiAuthVectorJWS)-2] + "AA"

	for _, vector := range []struct {
		name  string
		token string
	}{
		{"wrong typ", wrongTyp},
		{"crit header", crit},
		{"kid without fragment", bareKid},
		{"padded bodyHash", padded},
		{"missing member", missing},
		{"quoted iat", quoted},
		{"tampered signature", tampered},
		{"not a JWS", "not-a-jws"},
		{"oversize proof", strings.Repeat("a", MaxRequestProofSize+1)},
	} {
		if _, err := VerifyRequestProof(vector.token, ok, resolve, fresh); !errors.Is(err, ErrRequestProofInvalid) {
			t.Errorf("envelope gate %q: got %v", vector.name, err)
		}
	}

	// An unresolvable presenter is UNVERIFIABLE, never invalid — a transient
	// resolution failure is the server's condition, not the caller's.
	unresolvable := func(string) (ed25519.PublicKey, error) { return nil, errors.New("relays unreachable") }
	if _, err := VerifyRequestProof(apiAuthVectorJWS, ok, unresolvable, fresh); !errors.Is(err, ErrRequestProofUnverifiable) {
		t.Errorf("unresolvable presenter: got %v", err)
	}
}

// Unknown top-level members are IGNORED, per the protocol's MUST-ignore-unknown
// rule — a future additive member (the `jti` write-path seam) must not make
// today's verifier reject a well-formed proof.
func TestVerifyRequestProofIgnoresUnknownMembers(t *testing.T) {
	key := apiAuthVectorKey()
	withExtra := strings.TrimSuffix(apiAuthVectorCanonical, "}") + `,"jti":"abc"}`
	token := signRawRequestProof(key,
		`{"alg":"EdDSA","typ":"`+RequestProofJWSTyp+`","kid":"`+apiAuthVectorKid+`"}`, withExtra)
	if _, err := VerifyRequestProof(token, RequestProofExpectations{
		Method: "GET", Host: "api.dfos.com", Path: "/v0/profile",
	}, apiAuthVectorResolver(key), time.Unix(apiAuthVectorIat+10, 0)); err != nil {
		t.Fatalf("unknown member rejected: %v", err)
	}
}

// signRawRequestProof assembles a proof of EITHER shape from EXACT header and
// payload strings, so adversarial vectors can carry bytes the builder would
// never emit.
func signRawRequestProof(privateKey ed25519.PrivateKey, header, payload string) string {
	signingInput := Base64urlEncodeString(header) + "." + Base64urlEncodeString(payload)
	return signingInput + "." + Base64urlEncode(ed25519.Sign(privateKey, []byte(signingInput)))
}

// -----------------------------------------------------------------------------
// the identity proof — the same fixture, minus the credential
// -----------------------------------------------------------------------------

func TestApiIdentitySharedCanonicalAndSignedVectors(t *testing.T) {
	for _, vector := range []struct{ path, want string }{
		{"/v0/profile", apiAuthIdentityCanonical},
		{"/v0/profile?a=1&b=2", apiAuthIdentityCanonicalQuery},
		{"/v0/profile?q=<a>&b=2", apiAuthIdentityCanonicalHTML},
	} {
		got, err := ApiIdentitySigningInput(apiAuthIdentityPayload(vector.path))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != vector.want {
			t.Fatalf("identity canonical bytes:\n got %s\nwant %s", got, vector.want)
		}
	}

	// The delta is EXACTLY the credentialCID member — the doctrine claim, pinned.
	if want := strings.Replace(apiAuthVectorCanonical,
		`,"credentialCID":"`+apiAuthVectorCID+`"`, "", 1); want != apiAuthIdentityCanonical {
		t.Fatalf("identity canonical is not the request canonical minus credentialCID:\n got %s\nwant %s",
			apiAuthIdentityCanonical, want)
	}

	token, err := BuildIdentityProof("GET", "api.dfos.com", "/v0/profile", apiAuthVectorKid,
		apiAuthVectorKey(), IdentityProofOptions{Iat: apiAuthVectorIat})
	if err != nil {
		t.Fatal(err)
	}
	if token != apiAuthIdentityJWS {
		t.Fatalf("signed identity-proof vector:\n got %s\nwant %s", token, apiAuthIdentityJWS)
	}

	segment, err := Base64urlDecode(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	if string(segment) != apiAuthIdentityCanonical {
		t.Fatalf("payload segment is not the canonical signing input: %s", segment)
	}
}

// The five-member form takes the SAME escaping rule: `&`, `<`, and `>` ride the
// signed bytes literally, or a Go implementation reaching for encoding/json
// forks away from its TS twin.
func TestApiIdentitySigningInputLeavesHTMLCharactersLiteral(t *testing.T) {
	got, err := ApiIdentitySigningInput(apiAuthIdentityPayload("/v0/profile?q=<a>&b=2"))
	if err != nil {
		t.Fatal(err)
	}
	canonical := string(got)
	if !strings.Contains(canonical, `"path":"/v0/profile?q=<a>&b=2"`) {
		t.Fatalf("canonical bytes do not carry the literal path: %s", canonical)
	}
	for _, escaped := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if strings.Contains(canonical, escaped) {
			t.Fatalf("canonical bytes carry an HTML escape %s: %s", escaped, canonical)
		}
	}
	if strings.Contains(canonical, "credentialCID") {
		t.Fatalf("identity canonical bytes carry a credentialCID member: %s", canonical)
	}
}

// The member rules are the SAME rules — one fewer member, not a relaxation.
func TestApiIdentitySigningInputRejectsSchemaViolations(t *testing.T) {
	base := apiAuthIdentityPayload("/v0/profile")
	mutate := func(f func(p *IdentityProofPayload)) IdentityProofPayload {
		p := base
		f(&p)
		return p
	}
	vectors := []struct {
		name    string
		payload IdentityProofPayload
	}{
		{"lowercase method", mutate(func(p *IdentityProofPayload) { p.Method = "get" })},
		{"empty method", mutate(func(p *IdentityProofPayload) { p.Method = "" })},
		{"uppercase host", mutate(func(p *IdentityProofPayload) { p.Host = "API.dfos.com" })},
		{"host with scheme", mutate(func(p *IdentityProofPayload) { p.Host = "https://api.dfos.com" })},
		{"relative path", mutate(func(p *IdentityProofPayload) { p.Path = "v0/profile" })},
		{"path with fragment", mutate(func(p *IdentityProofPayload) { p.Path = "/v0/profile#top" })},
		{"path with space", mutate(func(p *IdentityProofPayload) { p.Path = "/v0/pro file" })},
		{"padded bodyHash", mutate(func(p *IdentityProofPayload) { p.BodyHash = EmptyBodySHA256 + "=" })},
		{"non-canonical bodyHash spelling", mutate(func(p *IdentityProofPayload) {
			p.BodyHash = EmptyBodySHA256[:len(EmptyBodySHA256)-1] + "V"
		})},
		{"zero iat", mutate(func(p *IdentityProofPayload) { p.Iat = 0 })},
		{"negative iat", mutate(func(p *IdentityProofPayload) { p.Iat = -1 })},
	}
	for _, vector := range vectors {
		if _, err := ApiIdentitySigningInput(vector.payload); err == nil {
			t.Errorf("schema violation accepted: %s", vector.name)
		}
	}
}

func TestVerifyIdentityProofAcceptsTheVector(t *testing.T) {
	key := apiAuthVectorKey()
	payload, err := VerifyIdentityProof(apiAuthIdentityJWS, IdentityProofExpectations{
		Method: "GET", Host: "api.dfos.com", Path: "/v0/profile",
	}, apiAuthVectorResolver(key), time.Unix(apiAuthVectorIat+10, 0))
	if err != nil {
		t.Fatal(err)
	}
	if payload.Iat != apiAuthVectorIat || payload.Path != "/v0/profile" {
		t.Fatalf("unexpected verified payload: %+v", payload)
	}
}

// THE TYP GATE, IN BOTH DIRECTIONS. "Possession of a grant's audience key" and
// "possession of a bare identity's key" are different claims, and neither
// verifier may accept the other's artifact.
func TestVerifyProofTypConfusionRejectsBothDirections(t *testing.T) {
	key := apiAuthVectorKey()
	resolve := apiAuthVectorResolver(key)
	fresh := time.Unix(apiAuthVectorIat+10, 0)
	expect := RequestProofExpectations{Method: "GET", Host: "api.dfos.com", Path: "/v0/profile"}

	if _, err := VerifyIdentityProof(apiAuthVectorJWS, expect, resolve, fresh); !errors.Is(err, ErrIdentityProofInvalid) {
		t.Errorf("a request proof presented to the identity verifier: got %v", err)
	}
	if _, err := VerifyRequestProof(apiAuthIdentityJWS, expect, resolve, fresh); !errors.Is(err, ErrRequestProofInvalid) {
		t.Errorf("an identity proof presented to the request verifier: got %v", err)
	}

	// And the confusion is not rescuable by swapping only the typ: the header is
	// signed, so a re-typed proof dies at the payload schema (no credentialCID)
	// and, were it to get past that, at the signature.
	parts := strings.Split(apiAuthIdentityJWS, ".")
	retyped := Base64urlEncodeString(
		`{"alg":"EdDSA","typ":"`+RequestProofJWSTyp+`","kid":"`+apiAuthVectorKid+`"}`) +
		"." + parts[1] + "." + parts[2]
	if _, err := VerifyRequestProof(retyped, expect, resolve, fresh); !errors.Is(err, ErrRequestProofInvalid) {
		t.Errorf("a re-typed identity proof: got %v", err)
	}
}

func TestVerifyIdentityProofAdversarialVectors(t *testing.T) {
	key := apiAuthVectorKey()
	resolve := apiAuthVectorResolver(key)
	fresh := time.Unix(apiAuthVectorIat+10, 0)
	ok := IdentityProofExpectations{Method: "GET", Host: "api.dfos.com", Path: "/v0/profile"}
	header := `{"alg":"EdDSA","typ":"` + IdentityProofJWSTyp + `","kid":"` + apiAuthVectorKid + `"}`

	queryProof, err := BuildIdentityProof("GET", "api.dfos.com", "/v0/profile?a=1&b=2",
		apiAuthVectorKid, key, IdentityProofOptions{Iat: apiAuthVectorIat})
	if err != nil {
		t.Fatal(err)
	}
	bodyProof, err := BuildIdentityProof("POST", "api.dfos.com", "/v0/profile",
		apiAuthVectorKid, key, IdentityProofOptions{Iat: apiAuthVectorIat, Body: []byte(`{"a":1}`)})
	if err != nil {
		t.Fatal(err)
	}

	// Signed bytes the builder would never emit.
	padded := signRawRequestProof(key, header,
		strings.Replace(apiAuthIdentityCanonical, EmptyBodySHA256, EmptyBodySHA256[:42]+"U=", 1))
	nonCanonical := signRawRequestProof(key, header,
		strings.Replace(apiAuthIdentityCanonical, EmptyBodySHA256, EmptyBodySHA256[:len(EmptyBodySHA256)-1]+"V", 1))
	missing := signRawRequestProof(key, header,
		`{"method":"GET","host":"api.dfos.com","path":"/v0/profile","iat":1772841600}`)
	quoted := signRawRequestProof(key, header,
		strings.Replace(apiAuthIdentityCanonical, `"iat":1772841600`, `"iat":"1772841600"`, 1))
	crit := signRawRequestProof(key,
		`{"alg":"EdDSA","typ":"`+IdentityProofJWSTyp+`","kid":"`+apiAuthVectorKid+`","crit":["x"]}`,
		apiAuthIdentityCanonical)
	bareKid := signRawRequestProof(key,
		`{"alg":"EdDSA","typ":"`+IdentityProofJWSTyp+`","kid":"did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae"}`,
		apiAuthIdentityCanonical)

	vectors := []struct {
		name   string
		token  string
		expect IdentityProofExpectations
		now    time.Time
		reason error
	}{
		{"wrong-case method", apiAuthIdentityJWS,
			IdentityProofExpectations{Method: "get", Host: ok.Host, Path: ok.Path}, fresh, ErrIdentityProofInvalid},
		{"method mismatch", apiAuthIdentityJWS,
			IdentityProofExpectations{Method: "POST", Host: ok.Host, Path: ok.Path}, fresh, ErrIdentityProofInvalid},
		{"host mismatch", apiAuthIdentityJWS,
			IdentityProofExpectations{Method: "GET", Host: "api.example.org", Path: ok.Path}, fresh, ErrIdentityProofInvalid},
		{"host port mismatch", apiAuthIdentityJWS,
			IdentityProofExpectations{Method: "GET", Host: "api.dfos.com:8443", Path: ok.Path}, fresh, ErrIdentityProofInvalid},
		{"query-string mismatch", queryProof, ok, fresh, ErrIdentityProofInvalid},
		{"trailing-slash mismatch", apiAuthIdentityJWS,
			IdentityProofExpectations{Method: "GET", Host: ok.Host, Path: "/v0/profile/"}, fresh, ErrIdentityProofInvalid},
		{"body-hash mismatch (body arrived, proof says empty)", apiAuthIdentityJWS,
			IdentityProofExpectations{Method: "GET", Host: ok.Host, Path: ok.Path, Body: []byte(`{"a":1}`)}, fresh, ErrIdentityProofInvalid},
		{"body-hash mismatch (body dropped)", bodyProof,
			IdentityProofExpectations{Method: "POST", Host: ok.Host, Path: ok.Path}, fresh, ErrIdentityProofInvalid},
		{"stale iat", apiAuthIdentityJWS, ok, time.Unix(apiAuthVectorIat+61, 0), ErrIdentityProofInvalid},
		{"forward-dated iat", apiAuthIdentityJWS, ok, time.Unix(apiAuthVectorIat-61, 0), ErrIdentityProofInvalid},
		{"padded bodyHash", padded, ok, fresh, ErrIdentityProofInvalid},
		{"non-canonical bodyHash spelling", nonCanonical, ok, fresh, ErrIdentityProofInvalid},
		{"missing member", missing, ok, fresh, ErrIdentityProofInvalid},
		{"quoted iat", quoted, ok, fresh, ErrIdentityProofInvalid},
		{"crit header", crit, ok, fresh, ErrIdentityProofInvalid},
		{"kid without fragment", bareKid, ok, fresh, ErrIdentityProofInvalid},
		{"tampered signature", apiAuthIdentityJWS[:len(apiAuthIdentityJWS)-2] + "AA", ok, fresh, ErrIdentityProofInvalid},
		{"not a JWS", "not-a-jws", ok, fresh, ErrIdentityProofInvalid},
		{"oversize proof", strings.Repeat("a", MaxRequestProofSize+1), ok, fresh, ErrIdentityProofInvalid},
		{"W + S over the ceiling", apiAuthIdentityJWS,
			IdentityProofExpectations{Method: "GET", Host: ok.Host, Path: ok.Path,
				WindowSeconds: Int64Ptr(240), SkewSeconds: Int64Ptr(61)}, fresh, ErrIdentityProofConfig},
	}
	for _, vector := range vectors {
		_, err := VerifyIdentityProof(vector.token, vector.expect, resolve, vector.now)
		if err == nil || !errors.Is(err, vector.reason) {
			t.Errorf("adversarial vector %q: got %v, want %v", vector.name, err, vector.reason)
		}
	}

	// An unresolvable presenter is UNVERIFIABLE, never invalid — and there is no
	// 403 tier here to confuse it with.
	unresolvable := func(string) (ed25519.PublicKey, error) { return nil, errors.New("relays unreachable") }
	if _, err := VerifyIdentityProof(apiAuthIdentityJWS, ok, unresolvable, fresh); !errors.Is(err, ErrIdentityProofUnverifiable) {
		t.Errorf("unresolvable presenter: got %v", err)
	}
}

// Unknown top-level members are IGNORED, including a stray credentialCID: the
// typ gate, not member sniffing, is what tells the two artifacts apart.
func TestVerifyIdentityProofIgnoresUnknownMembers(t *testing.T) {
	key := apiAuthVectorKey()
	header := `{"alg":"EdDSA","typ":"` + IdentityProofJWSTyp + `","kid":"` + apiAuthVectorKid + `"}`
	ok := IdentityProofExpectations{Method: "GET", Host: "api.dfos.com", Path: "/v0/profile"}
	fresh := time.Unix(apiAuthVectorIat+10, 0)

	for _, extra := range []string{`"jti":"abc"`, `"credentialCID":"` + apiAuthVectorCID + `"`} {
		token := signRawRequestProof(key, header,
			strings.TrimSuffix(apiAuthIdentityCanonical, "}")+`,`+extra+`}`)
		if _, err := VerifyIdentityProof(token, ok, apiAuthVectorResolver(key), fresh); err != nil {
			t.Errorf("unknown member %s rejected: %v", extra, err)
		}
	}
}

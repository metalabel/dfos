package dfos

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const siwdVectorBare = `{"domain":"3p.com","nonce":"nonce-vector-01","timestamp":"2026-08-10T12:34:56.000Z"}`
const siwdVectorComplete = `{"domain":"3p.com","nonce":"nonce-vector-01","timestamp":"2026-08-10T12:34:56.000Z","statement":"Sign in to 3P App","did":"did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae"}`
const siwdVectorJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnNpd2QiLCJraWQiOiJkaWQ6ZGZvczpuemtmODM4ZWZyNDI0NDMzcm4ycnprZHY4aDd0OWFlI2tleV9zaXdkX3ZlY3RvciJ9.eyJkb21haW4iOiIzcC5jb20iLCJub25jZSI6Im5vbmNlLXZlY3Rvci0wMSIsInRpbWVzdGFtcCI6IjIwMjYtMDgtMTBUMTI6MzQ6NTYuMDAwWiIsInN0YXRlbWVudCI6IlNpZ24gaW4gdG8gM1AgQXBwIiwiZGlkIjoiZGlkOmRmb3M6bnprZjgzOGVmcjQyNDQzM3JuMnJ6a2R2OGg3dDlhZSJ9.52neBNRuHJFbltwI3vx0W5gX2bGkh_zXeHiFaFVRyQr5C0c8fWRtB9_nUf4kp8BahumTZv_J8UuXCQELofHqBQ"

func siwdString(value string) *string { return &value }

func TestSiwdSharedCanonicalAndSignedVectors(t *testing.T) {
	bare := SiwdChallenge{Domain: "3p.com", Nonce: "nonce-vector-01", Timestamp: "2026-08-10T12:34:56.000Z"}
	complete := bare
	complete.Statement = siwdString("Sign in to 3P App")
	complete.DID = siwdString("did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae")
	for _, vector := range []struct {
		challenge SiwdChallenge
		want      string
	}{{bare, siwdVectorBare}, {complete, siwdVectorComplete}} {
		got, err := SiwdSigningInput(vector.challenge)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != vector.want {
			t.Fatalf("canonical bytes:\n got %s\nwant %s", got, vector.want)
		}
		parsed, err := ParseSiwdChallenge(got)
		if err != nil || parsed.Domain != vector.challenge.Domain || parsed.Nonce != vector.challenge.Nonce {
			t.Fatalf("ParseSiwdChallenge: parsed=%+v err=%v", parsed, err)
		}
	}

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	headerJSON, _ := json.Marshal(JWSHeader{
		Alg: "EdDSA", Typ: SiwdJWSTyp,
		Kid: "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae#key_siwd_vector",
	})
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString([]byte(siwdVectorComplete))
	signingInput := header + "." + payload
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(signingInput)))
	if token != siwdVectorJWS {
		t.Fatalf("signed SIWD vector:\n got %s\nwant %s", token, siwdVectorJWS)
	}
}

func TestParseSiwdChallengeAdversarialVectors(t *testing.T) {
	vectors := []string{
		`{"nonce":"nonce-vector-01","domain":"3p.com","timestamp":"2026-08-10T12:34:56.000Z"}`,
		strings.Replace(siwdVectorBare, ".000Z", ".123Z", 1),
		strings.TrimSuffix(siwdVectorBare, "}") + `,"unknown":"value"}`,
		strings.Replace(siwdVectorBare, `:"3p.com"`, `: "3p.com"`, 1),
		strings.Replace(siwdVectorBare, `"domain":"3p.com"`, `"domain":"evil.com","domain":"3p.com"`, 1),
		strings.Replace(siwdVectorBare, `"nonce":"nonce-vector-01"`, `"nonce":""`, 1),
		`[]`,
		siwdVectorBare + "\n",
		strings.Replace(siwdVectorBare, "3p.com", `3p\u002ecom`, 1),
	}
	for _, vector := range vectors {
		if _, err := ParseSiwdChallenge([]byte(vector)); err == nil {
			t.Errorf("adversarial vector accepted: %s", vector)
		}
	}
}

func TestSignSiwdAskProof(t *testing.T) {
	client := makeSignRequestParty("siwd-ask-client")
	challenge := SiwdChallenge{
		Domain: "127.0.0.1", Nonce: "ask-nonce-01", Timestamp: "2026-08-10T12:34:56.000Z",
		DID: siwdString("did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae"),
	}
	token, err := SignSiwdAskProof(challenge, client.kid, client.priv)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("ask proof is not a 3-part compact JWS: %s", token)
	}

	// The payload SEGMENT — not a re-serialization of the decoded challenge — is
	// what the host string-compares against its own re-derivation.
	canonical, err := SiwdSigningInput(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if want := base64.RawURLEncoding.EncodeToString(canonical); parts[1] != want {
		t.Fatalf("payload segment:\n got %s\nwant %s", parts[1], want)
	}

	headerBytes, err := Base64urlDecode(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header JWSHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatal(err)
	}
	if header.Alg != "EdDSA" || header.Typ != SiwdAskJWSTyp || header.Kid != client.kid {
		t.Fatalf("unexpected protected header: %+v", header)
	}
	// Member ORDER is part of the mirror with the TS kit (alg, typ, kid).
	wantHeader := `{"alg":"EdDSA","typ":"did:dfos:siwd-ask","kid":"` + client.kid + `"}`
	if string(headerBytes) != wantHeader {
		t.Fatalf("protected header bytes:\n got %s\nwant %s", headerBytes, wantHeader)
	}

	if _, _, err := VerifyJWS(token, client.pub); err != nil {
		t.Fatalf("ask proof does not verify with the signing key: %v", err)
	}

	// The FUNGIBILITY GATE: the ask proof and a subject's sign-in cover the same
	// canonical bytes, so a verifier gating on SiwdJWSTyp must refuse this one.
	if SiwdAskJWSTyp == SiwdJWSTyp {
		t.Fatal("ask proof and sign-in typ must be distinct")
	}
	if header.Typ == SiwdJWSTyp {
		t.Fatalf("ask proof presents as a sign-in: typ %s", header.Typ)
	}
}

func TestSignSiwdAskProofRejectsMalformedInput(t *testing.T) {
	client := makeSignRequestParty("siwd-ask-malformed")
	challenge := SiwdChallenge{Domain: "127.0.0.1", Nonce: "n", Timestamp: "2026-08-10T12:34:56.000Z"}

	for name, kid := range map[string]string{
		"no separator":   "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae",
		"empty did":      "#key_x",
		"empty key id":   "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae#",
		"bare separator": "#",
		"empty":          "",
	} {
		if _, err := SignSiwdAskProof(challenge, kid, client.priv); err == nil {
			t.Errorf("%s: malformed kid %q accepted", name, kid)
		}
	}

	// A challenge that is not canonical-serializable must fail before any
	// signature exists, not produce bytes no host will re-derive.
	bad := SiwdChallenge{Domain: "127.0.0.1", Nonce: "n", Timestamp: "2026-08-10T12:34:56.123Z"}
	if _, err := SignSiwdAskProof(bad, client.kid, client.priv); err == nil {
		t.Error("non-whole-second challenge timestamp accepted")
	}
}

func TestSiwdSignRequestBuildAndValidate(t *testing.T) {
	requester := makeSignRequestParty("siwd-requester")
	subject := makeSignRequestParty("siwd-subject")
	created := time.Date(2026, 8, 10, 12, 0, 0, 777_000_000, time.UTC)
	expires := created.Add(5*time.Minute + 222*time.Millisecond)
	challenge := SiwdChallenge{
		Domain: "3p.com", Nonce: "mailbox-nonce", Timestamp: "2026-08-10T12:00:00.000Z",
		DID: siwdString(subject.did),
	}
	token, cid, err := BuildSiwdSignRequest(
		requester.did, subject.did, challenge, expires, 5*time.Minute,
		requester.keyID, requester.priv, SignRequestOptions{CreatedAt: created},
	)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := ValidateSiwdSignRequest(
		token, subject.did, 5*time.Minute, signRequestResolver(requester),
		time.Date(2026, 8, 10, 12, 1, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	if validated.RequestCID != cid || validated.PayloadTyp != SiwdJWSTyp || validated.ExpiresAt != "2026-08-10T12:05:00.000Z" {
		t.Fatalf("unexpected validated request: %+v", validated)
	}
	want, _ := SiwdSigningInput(challenge)
	if !bytes.Equal(validated.PayloadBytes, want) || validated.Challenge.DID == nil || *validated.Challenge.DID != subject.did {
		t.Fatalf("unexpected validated challenge: %+v", validated.Challenge)
	}
}

func TestSiwdSignRequestRejectsOneClockViolations(t *testing.T) {
	requester := makeSignRequestParty("siwd-one-clock-requester")
	subject := makeSignRequestParty("siwd-one-clock-subject")
	created := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	challenge := SiwdChallenge{Domain: "3p.com", Nonce: "n", Timestamp: "2026-08-10T12:00:00.000Z"}
	_, _, err := BuildSiwdSignRequest(
		requester.did, subject.did, challenge, created.Add(5*time.Minute+time.Second), 5*time.Minute,
		requester.keyID, requester.priv, SignRequestOptions{CreatedAt: created},
	)
	if err == nil || !strings.Contains(err.Error(), "acceptance window") {
		t.Fatalf("composer one-clock violation: %v", err)
	}

	payload, _ := SiwdSigningInput(challenge)
	token, _, err := BuildSignRequest(
		requester.did, subject.did, SiwdJWSTyp, payload, created.Add(6*time.Minute),
		requester.keyID, requester.priv, SignRequestOptions{CreatedAt: created},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ValidateSiwdSignRequest(
		token, subject.did, 5*time.Minute, signRequestResolver(requester), created.Add(time.Minute),
	)
	if err == nil || !errors.Is(err, ErrSignRequestInvalid) || !strings.Contains(err.Error(), "acceptance window") {
		t.Fatalf("receiver one-clock violation: %v", err)
	}
}

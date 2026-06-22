package dfos

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// canonical anchor fixtures (mirror services.spec.ts)
const (
	testContentIDAnchor = "2346789acdefhknrtvz2346789acdef" // 31 chars, content-chain alphabet
	testArtifactAnchor  = "bafkreieabcdefghijklmnoprstuvwxyz234567"
)

func relayEntry(id string) ServiceEntry {
	return ServiceEntry{"id": id, "type": "DfosRelay", "endpoint": "https://relay.dfos.com"}
}

// ---------------------------------------------------------------------------
// anchor classification (shape-dispatch)
// ---------------------------------------------------------------------------

func TestClassifyAnchor(t *testing.T) {
	cases := map[string]AnchorKind{
		testContentIDAnchor: AnchorChain,
		testArtifactAnchor:  AnchorArtifact,
		// a head CID is base32 baf… → artifact-shaped (rejected later at resolution)
		"bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi": AnchorArtifact,
		"not-an-anchor": AnchorInvalid,
		"short":         AnchorInvalid,
		"":              AnchorInvalid,
	}
	for anchor, want := range cases {
		if got := ClassifyAnchor(anchor); got != want {
			t.Errorf("ClassifyAnchor(%q) = %q, want %q", anchor, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// services projection through the identity chain
// ---------------------------------------------------------------------------

func TestServicesProjection(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	ctrl := []MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}

	profile := ServiceEntry{"id": "profile", "type": "ContentAnchor", "label": "profile", "anchor": testContentIDAnchor}
	card := ServiceEntry{"id": "card", "type": "ContentAnchor", "label": "card", "anchor": testArtifactAnchor}
	svcs := []ServiceEntry{relayEntry("relay-0"), profile, card}

	genesisJWS, did, genCID, err := SignIdentityCreateWithServices(ctrl, ctrl, ctrl, svcs, keyID, priv)
	if err != nil {
		t.Fatalf("sign genesis: %v", err)
	}
	res, err := VerifyIdentityChain([]string{genesisJWS})
	if err != nil {
		t.Fatalf("verify genesis: %v", err)
	}
	if len(res.State.Services) != 3 {
		t.Fatalf("services len = %d, want 3", len(res.State.Services))
	}
	if eps := RelayEndpoints(res.State.Services); len(eps) != 1 || eps[0] != "https://relay.dfos.com" {
		t.Errorf("RelayEndpoints = %v", eps)
	}
	if got := AnchorsByLabel(res.State.Services, "profile"); len(got) != 1 || got[0]["id"] != "profile" {
		t.Errorf("AnchorsByLabel(profile) = %v", got)
	}

	// update REPLACES the full set (drop the card)
	updateJWS, _, err := SignIdentityUpdateWithServices(genCID, ctrl, ctrl, ctrl, []ServiceEntry{relayEntry("relay-0"), profile}, did+"#"+keyID, priv)
	if err != nil {
		t.Fatalf("sign update: %v", err)
	}
	res2, err := VerifyIdentityChain([]string{genesisJWS, updateJWS})
	if err != nil {
		t.Fatalf("verify update: %v", err)
	}
	if len(res2.State.Services) != 2 {
		t.Errorf("after update services len = %d, want 2", len(res2.State.Services))
	}
}

func TestServicesDefaultsEmpty(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	ctrl := []MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}
	genesisJWS, _, _, err := SignIdentityCreate(ctrl, ctrl, ctrl, keyID, priv)
	if err != nil {
		t.Fatal(err)
	}
	res, err := VerifyIdentityChain([]string{genesisJWS})
	if err != nil {
		t.Fatal(err)
	}
	if res.State.Services == nil || len(res.State.Services) != 0 {
		t.Errorf("services = %v, want empty non-nil slice", res.State.Services)
	}
}

// ---------------------------------------------------------------------------
// services validation (rejection parity with the TS reference)
// ---------------------------------------------------------------------------

func TestServicesRejections(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	ctrl := []MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}

	// One entry with a ~33 KB endpoint — individually valid (non-empty, no
	// per-field length cap) but pushing the CBOR array past the 32768-byte cap.
	over := []ServiceEntry{{"id": "r", "type": "DfosRelay", "endpoint": "https://" + strings.Repeat("a", 33000)}}

	cases := map[string][]ServiceEntry{
		"too many entries": func() []ServiceEntry {
			s := make([]ServiceEntry, 0, 257)
			for i := 0; i < 257; i++ {
				id := string(rune('a'+i/26)) + string(rune('a'+i%26))
				s = append(s, relayEntry(id))
			}
			return s
		}(),
		"duplicate ids":          {relayEntry("dup"), relayEntry("dup")},
		"relay without endpoint": {{"id": "r", "type": "DfosRelay"}},
		"anchor with bad target": {{"id": "p", "type": "ContentAnchor", "label": "profile", "anchor": "nope"}},
		"anchor missing label":   {{"id": "p", "type": "ContentAnchor", "anchor": testContentIDAnchor}},
		"over the byte-size cap": over,
	}
	for name, svcs := range cases {
		genesisJWS, _, _, err := SignIdentityCreateWithServices(ctrl, ctrl, ctrl, svcs, keyID, priv)
		if err != nil {
			// some malformed sets fail at encode; treat as rejected
			continue
		}
		if _, err := VerifyIdentityChain([]string{genesisJWS}); err == nil {
			t.Errorf("%s: expected verification to reject", name)
		}
	}

	// Positive control pinning the byte boundary: a single entry whose
	// canonical-CBOR encoding lands just UNDER 32768 bytes verifies cleanly. The
	// single-entry envelope is a fixed 38 bytes, so "https://"+32714×'a' (len
	// 32722) encodes to 32760 < 32768. This proves the over-cap rejection above
	// fires at 32768 specifically, not at some smaller incidental limit.
	underCap := []ServiceEntry{{"id": "r", "type": "DfosRelay", "endpoint": "https://" + strings.Repeat("a", 32714)}}
	underJWS, _, _, err := SignIdentityCreateWithServices(ctrl, ctrl, ctrl, underCap, keyID, priv)
	if err != nil {
		t.Fatalf("just-under-cap services: sign: %v", err)
	}
	if _, err := VerifyIdentityChain([]string{underJWS}); err != nil {
		t.Errorf("just-under-cap services (32760 bytes) should verify, got: %v", err)
	}
}

func TestServicesUnknownTypePreserved(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	ctrl := []MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}
	unknown := ServiceEntry{"id": "x", "type": "MetalabelSpaceTag", "spaceId": "sp_1", "role": "member"}

	genesisJWS, _, _, err := SignIdentityCreateWithServices(ctrl, ctrl, ctrl, []ServiceEntry{unknown}, keyID, priv)
	if err != nil {
		t.Fatal(err)
	}
	res, err := VerifyIdentityChain([]string{genesisJWS})
	if err != nil {
		t.Fatalf("unrecognized type must be accepted (MUST-ignore-unknown): %v", err)
	}
	if len(res.State.Services) != 1 || res.State.Services[0]["spaceId"] != "sp_1" {
		t.Errorf("unknown-type entry not preserved verbatim: %v", res.State.Services)
	}
	if IsRecognizedServiceType("MetalabelSpaceTag") {
		t.Error("MetalabelSpaceTag should not be recognized")
	}
}

// ---------------------------------------------------------------------------
// countersignature relation tag
// ---------------------------------------------------------------------------

func TestCountersignRelation(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	_, did, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)
	kid := did + "#" + keyID
	target := "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenera6h5y"
	resolver := func(k string) (ed25519.PublicKey, error) { return pub, nil }

	// tagged → relation projected; bare → empty; CID differs
	bareJWS, bareCID, err := SignCountersign(did, target, kid, priv)
	if err != nil {
		t.Fatal(err)
	}
	taggedJWS, taggedCID, err := SignCountersignWithRelation(did, target, "endorses", kid, priv)
	if err != nil {
		t.Fatal(err)
	}
	if bareCID == taggedCID {
		t.Error("relation must change the countersign CID")
	}

	tagged, err := VerifyCountersignature(taggedJWS, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if tagged.Relation != "endorses" {
		t.Errorf("relation = %q, want endorses", tagged.Relation)
	}
	bare, err := VerifyCountersignature(bareJWS, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if bare.Relation != "" {
		t.Errorf("bare relation = %q, want empty", bare.Relation)
	}
}

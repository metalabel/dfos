package dfos

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"
)

// ===========================================================================
// A RESOLVER'S ERROR MUST SURVIVE EVERY VERIFY ENTRYPOINT.
//
// The KeyResolver seam is the only place that knows WHY a key did not resolve.
// "the identity chain has not synced to this store yet" (retryable) and "this
// kid is malformed" (permanent) arrive here as the same `error` type, separable
// only by the resolver's own sentinel. A caller that needs the distinction —
// the relay's ingest classifier, which keeps an operation pending on the first
// and deletes it on the second — reads it with errors.Is.
//
// That only works if every entrypoint re-wraps with %w. A single %v or %s
// flattens the chain to text and forces the caller back onto substring-matching
// a message that quotes submitter-controlled input (a kid, a typ, a credential
// audience), which is how a permanent rejection could be spelled to look
// retryable and retried forever. Three sites had already drifted to %v/%s and
// one dropped the error entirely; this table is what stops the class from
// coming back, because it fails the moment any entrypoint stops threading the
// chain rather than the moment someone notices.
// ===========================================================================

// errTestDependencyMiss stands in for a relay resolver's "not in this store"
// sentinel. Its message deliberately shares no substring with any classifier
// heuristic — errors.Is is the whole assertion, so the text must not be able to
// carry the test.
var errTestDependencyMiss = errors.New("test: referenced identity is not held here")

// missingKeyResolver fails every lookup with the sentinel wrapped in a message,
// the shape a real store-backed resolver produces.
func missingKeyResolver() KeyResolver {
	return func(kid string) (ed25519.PublicKey, error) {
		return nil, fmt.Errorf("%w: %s", errTestDependencyMiss, kid)
	}
}

// missingForKid resolves everything the delegate fixture knows EXCEPT one kid,
// which fails with the sentinel — so a single hop of a delegation walk can be
// the failing one.
func missingForKid(base KeyResolver, absent string) KeyResolver {
	return func(kid string) (ed25519.PublicKey, error) {
		if kid == absent {
			return nil, fmt.Errorf("%w: %s", errTestDependencyMiss, kid)
		}
		return base(kid)
	}
}

// delegatedContentFixture is a verified creator genesis plus a delegated update
// signed by a third party under an inline write credential. depth 1 issues that
// credential straight from the creator; depth 2 routes it through an
// intermediate so the delegation walk has a PARENT hop to resolve.
type delegatedContentFixture struct {
	genesisState  ContentState
	genesisLastAt string
	updateJWS     string
	resolveKey    KeyResolver
	creatorKid    string
	middleKid     string
}

func buildDelegatedContentFixture(t *testing.T, depth int) delegatedContentFixture {
	t.Helper()
	now := time.Now().UTC()
	genesisTime := now.Format(protocolTimeFormat)
	updateTime := now.Add(time.Minute).Format(protocolTimeFormat)

	creatorPriv, creatorPub, _, creatorKeyID := testKeys(t)
	_, creatorDID, _ := testSignIdentityGenesis(t, NewMultikeyPublicKey(creatorKeyID, creatorPub), creatorKeyID, creatorPriv, genesisTime)
	middlePriv, middlePub, _, middleKeyID := testKeys(t)
	_, middleDID, _ := testSignIdentityGenesis(t, NewMultikeyPublicKey(middleKeyID, middlePub), middleKeyID, middlePriv, genesisTime)
	delegatePriv, delegatePub, _, delegateKeyID := testKeys(t)
	_, delegateDID, _ := testSignIdentityGenesis(t, NewMultikeyPublicKey(delegateKeyID, delegatePub), delegateKeyID, delegatePriv, genesisTime)

	creatorKid := creatorDID + "#" + creatorKeyID
	middleKid := middleDID + "#" + middleKeyID
	delegateKid := delegateDID + "#" + delegateKeyID
	resolve := func(kid string) (ed25519.PublicKey, error) {
		switch kid {
		case creatorKid:
			return creatorPub, nil
		case middleKid:
			return middlePub, nil
		case delegateKid:
			return delegatePub, nil
		}
		return nil, fmt.Errorf("test fixture holds no key for %s", kid)
	}

	docCID, _, _ := DocumentCID(map[string]any{"hello": "world"})
	contentJWS, _, contentCID := testSignContentGenesis(t, creatorDID, docCID, creatorKid, creatorPriv, genesisTime)
	genesis, err := VerifyContentChain([]string{contentJWS}, resolve, true)
	if err != nil {
		t.Fatalf("verify content genesis: %v", err)
	}

	var leafToken string
	if depth == 2 {
		parentToken, _ := mintAsOfCredential(t, creatorDID, creatorKid, creatorPriv, middleDID, "chain:*", "write", nil)
		leafToken, _ = mintAsOfCredential(t, middleDID, middleKid, middlePriv, delegateDID, "chain:*", "write", []string{parentToken})
	} else {
		leafToken, _ = mintAsOfCredential(t, creatorDID, creatorKid, creatorPriv, delegateDID, "chain:*", "write", nil)
	}

	return delegatedContentFixture{
		genesisState:  genesis.State,
		genesisLastAt: genesis.LastCreatedAt,
		updateJWS:     buildDelegatedUpdate(t, delegateDID, delegateKid, delegatePriv, contentCID, updateTime, leafToken),
		resolveKey:    resolve,
		creatorKid:    creatorKid,
		middleKid:     middleKid,
	}
}

// TestResolverErrorSurvivesEveryVerifyEntrypoint drives every verification
// entrypoint that accepts a KeyResolver and asserts the resolver's sentinel is
// still recoverable with errors.Is from the error the entrypoint returns.
func TestResolverErrorSurvivesEveryVerifyEntrypoint(t *testing.T) {
	now := time.Now().UTC()
	createdAt := now.Format(protocolTimeFormat)

	signerPriv, signerPub, _, signerKeyID := testKeys(t)
	_, signerDID, signerGenesisCID := testSignIdentityGenesis(t, NewMultikeyPublicKey(signerKeyID, signerPub), signerKeyID, signerPriv, createdAt)
	signerKid := signerDID + "#" + signerKeyID

	docCID, _, _ := DocumentCID(map[string]any{"hello": "world"})
	contentGenesis, _, contentGenesisCID := testSignContentGenesis(t, signerDID, docCID, signerKid, signerPriv, createdAt)

	// A trusted prior state for the extension entrypoint. Built from the
	// genesis above by hand rather than by verifying it, because verifying it
	// needs the very resolver this test withholds.
	priorState := ContentState{
		ContentID:          DeriveID([]byte(contentGenesisCID)),
		GenesisCID:         contentGenesisCID,
		HeadCID:            contentGenesisCID,
		CurrentDocumentCID: &docCID,
		Length:             1,
		CreatorDID:         signerDID,
	}
	extensionJWS, _, err := SignContentUpdate(signerDID, contentGenesisCID, docCID, signerKid, signerPriv)
	if err != nil {
		t.Fatalf("SignContentUpdate: %v", err)
	}

	artifactJWS, _, err := SignArtifact(signerDID, map[string]any{"$schema": "test/v1", "title": "t"}, signerKid, signerPriv)
	if err != nil {
		t.Fatalf("SignArtifact: %v", err)
	}
	countersignJWS, _, err := SignCountersign(signerDID, signerGenesisCID, signerKid, signerPriv)
	if err != nil {
		t.Fatalf("SignCountersign: %v", err)
	}
	revocationJWS, _, err := SignRevocation(signerDID, signerGenesisCID, signerKid, signerPriv)
	if err != nil {
		t.Fatalf("SignRevocation: %v", err)
	}
	claimJWS, _, err := SignCreditClaim(signerDID, DeriveID([]byte("credit-claim-content")), "author", signerKeyID, signerPriv)
	if err != nil {
		t.Fatalf("SignCreditClaim: %v", err)
	}

	credentialKeyFixture := buildDelegatedContentFixture(t, 1)
	delegationParentFixture := buildDelegatedContentFixture(t, 2)

	cases := []struct {
		name   string
		verify func() error
	}{
		{
			name: "content chain genesis",
			verify: func() error {
				_, err := VerifyContentChain([]string{contentGenesis}, missingKeyResolver(), true)
				return err
			},
		},
		{
			name: "content extension",
			verify: func() error {
				_, err := VerifyContentExtension(priorState, createdAt, extensionJWS, missingKeyResolver(), true)
				return err
			},
		},
		{
			name: "countersignature",
			verify: func() error {
				_, err := VerifyCountersignature(countersignJWS, missingKeyResolver())
				return err
			},
		},
		{
			name: "artifact",
			verify: func() error {
				_, err := VerifyArtifact(artifactJWS, missingKeyResolver())
				return err
			},
		},
		{
			name: "revocation",
			verify: func() error {
				_, err := VerifyRevocation(revocationJWS, missingKeyResolver())
				return err
			},
		},
		{
			name: "credit claim",
			verify: func() error {
				_, err := VerifyCreditClaim(claimJWS, missingKeyResolver())
				return err
			},
		},
		{
			// The authorization credential is resolved through its OWN
			// resolver, so an op whose signer IS known can still fail on a
			// credential issuer that is not.
			name: "content authorization credential key",
			verify: func() error {
				f := credentialKeyFixture
				_, err := VerifyContentExtension(f.genesisState, f.genesisLastAt, f.updateJWS,
					f.resolveKey, true,
					WithCredentialKeyResolver(missingForKid(f.resolveKey, f.creatorKid)))
				return err
			},
		},
		{
			// One hop further in: the leaf credential verifies and only the
			// PARENT credential's issuer is unresolvable.
			name: "delegation chain parent credential key",
			verify: func() error {
				f := delegationParentFixture
				_, err := VerifyContentExtension(f.genesisState, f.genesisLastAt, f.updateJWS,
					f.resolveKey, true,
					WithCredentialKeyResolver(missingForKid(f.resolveKey, f.creatorKid)))
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.verify()
			if err == nil {
				t.Fatal("expected the withheld key to fail verification, got nil")
			}
			if !errors.Is(err, errTestDependencyMiss) {
				t.Fatalf("resolver error did not survive the entrypoint: %v\n"+
					"the wrap must use %%w — a caller classifies this with errors.Is, and %%v or %%s "+
					"leaves it with nothing but attacker-influenced text", err)
			}
		})
	}
}

// TestCreditClaimUnverifiableKeepsBothChains pins the multi-%w wrap on the
// credit-claim resolver failure: the family verdict (ErrCreditClaimUnverifiable,
// which tells a caller this is "could not check" rather than "invalid") and the
// resolver's own cause must BOTH stay recoverable. Wrapping one and formatting
// the other away makes the caller pick which question it can answer.
func TestCreditClaimUnverifiableKeepsBothChains(t *testing.T) {
	claimant := makeClaimant("credit-claim-resolver-chain")
	jwsToken, _, err := SignCreditClaim(claimant.did, testContentID("chain-resolver"), "author", claimant.keyID, claimant.priv)
	if err != nil {
		t.Fatalf("SignCreditClaim: %v", err)
	}

	_, err = VerifyCreditClaim(jwsToken, missingKeyResolver())
	if err == nil {
		t.Fatal("expected a verification failure")
	}
	if !errors.Is(err, ErrCreditClaimUnverifiable) {
		t.Fatalf("expected ErrCreditClaimUnverifiable, got %v", err)
	}
	if !errors.Is(err, errTestDependencyMiss) {
		t.Fatalf("expected the resolver's cause to survive alongside the verdict, got %v", err)
	}
}

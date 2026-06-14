package relay

import (
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// TestReadPathRejectsMultiParentCredential is the R1 regression guard.
//
// The relay read / per-request-credential path (verifyContentAccess →
// verifyCredentialForAccess → delegation walk) previously ran the relay's OWN
// copy of the delegation walk, which unioned the att of ALL parents and recursed
// only through parents[0]. A self-issued secondary parent could thereby
// contribute scope never rooted at the creator — a multi-parent
// authority-escalation that the protocol library and the TS stack already reject.
// The relay now calls the library's linear walk (dfos.VerifyDelegationChain),
// which rejects any credential whose prf has more than one entry.
//
// This pins both directions: the read path DENIES a multi-parent X-Credential,
// and (control) still GRANTS a valid single-parent delegated read so the fix
// cannot regress into over-rejection of legitimate delegation.
func TestReadPathRejectsMultiParentCredential(t *testing.T) {
	store := NewMemoryStore()
	r, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	creator := createTestIdentity(t)
	delegate := createTestIdentity(t)
	contentToken, contentID, _ := createTestContent(t, creator)
	if res := r.Ingest([]string{creator.token, delegate.token, contentToken}); len(res) == 0 {
		t.Fatal("seed ingest returned no results")
	}

	resource := "chain:" + contentID
	creatorKid := creator.did + "#" + creator.auth.keyID
	delegateKid := delegate.did + "#" + delegate.auth.keyID

	// CONTROL — a valid single-parent (root) delegated read credential, creator →
	// delegate with prf:[], must be GRANTED on the read path.
	rootCred, err := dfos.CreateCredential(creator.did, delegate.did, creatorKid, resource, "read", time.Hour, creator.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if deny := r.verifyContentAccess(delegate.did, creator.did, resource, "read", rootCred); deny != "" {
		t.Fatalf("control: valid single-parent read credential denied: %q", deny)
	}

	// ATTACK — a multi-parent credential (prf has two entries). The multi-parent
	// reject fires before any parent is decoded, so the parent strings are
	// arbitrary non-empty placeholders. Under the old relay copy this slipped
	// through; it must now be DENIED.
	multiParent, _ := mintDelegatedCredential(t, delegate.did, delegateKid, delegate.auth.priv,
		delegate.did, resource, "read", []string{"parentA", "parentB"}, time.Hour)
	deny := r.verifyContentAccess(delegate.did, creator.did, resource, "read", multiParent)
	if deny == "" {
		t.Fatal("SECURITY: multi-parent X-Credential was GRANTED on the read path (R1 regression)")
	}
	if !strings.Contains(deny, "multi-parent") {
		t.Fatalf("expected multi-parent rejection on read path, got %q", deny)
	}
}

package relay

import (
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// TestMatchesResourceActionCanonicalization pins the relay authorization path's
// action-set canonicalization, the same convergence enforced in the protocol
// library (dfos.ParseActions) and the TS stack (dfos-credential.ts parseActions).
//
// matchesResource reads no receiver state — it operates purely on its arguments
// (see auth.go) — so a zero-value &Relay{} exercises it faithfully without any
// relay setup.
func TestMatchesResourceActionCanonicalization(t *testing.T) {
	r := &Relay{}

	tests := []struct {
		name      string
		att       []dfos.AttEntry
		resource  string
		action    string
		wantMatch bool
	}{
		{
			// "write," canonicalizes to {write} — the trailing comma is dropped,
			// so a concrete "write" request is still covered.
			name:      "trailing comma in att action still matches concrete request",
			att:       []dfos.AttEntry{{Resource: "chain:c1", Action: "write,"}},
			resource:  "chain:c1",
			action:    "write",
			wantMatch: true,
		},
		{
			// "," canonicalizes to {} — the empty action set is the lattice
			// bottom: vacuously a subset on attenuation, but it covers no concrete
			// request, so the relay authorizes nothing.
			name:      "all-empty att action set matches nothing",
			att:       []dfos.AttEntry{{Resource: "chain:c1", Action: ","}},
			resource:  "chain:c1",
			action:    "write",
			wantMatch: false,
		},
		{
			name:      "empty-string att action set matches nothing",
			att:       []dfos.AttEntry{{Resource: "chain:c1", Action: ""}},
			resource:  "chain:c1",
			action:    "read",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.matchesResource(tt.att, tt.resource, tt.action)
			if got != tt.wantMatch {
				t.Errorf("matchesResource(%v, %q, %q) = %v, want %v",
					tt.att, tt.resource, tt.action, got, tt.wantMatch)
			}
		})
	}
}

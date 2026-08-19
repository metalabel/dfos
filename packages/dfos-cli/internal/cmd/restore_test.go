package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

func identityRestorableStateJSON(t *testing.T, state protocol.IdentityState) []byte {
	t.Helper()
	projection := struct {
		AuthKeys       []protocol.MultikeyPublicKey `json:"authKeys"`
		AssertKeys     []protocol.MultikeyPublicKey `json:"assertKeys"`
		ControllerKeys []protocol.MultikeyPublicKey `json:"controllerKeys"`
		Services       []protocol.ServiceEntry      `json:"services"`
	}{
		AuthKeys:       state.AuthKeys,
		AssertKeys:     state.AssertKeys,
		ControllerKeys: state.ControllerKeys,
		Services:       state.Services,
	}
	b, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("marshal restorable identity state: %v", err)
	}
	return b
}

func TestIdentityRestore(t *testing.T) {
	store, _, lr := setupDevices(t)
	did := createIdentity(t, "alice", store)

	keys = store
	updateCmd := newIdentityUpdateCmd()
	mustSetFlag(t, updateCmd, "rotate-auth", "true")
	mustSetFlag(t, updateCmd, "rotate-controller", "true")
	mustSetFlag(t, updateCmd, "service", "id=relay,type=DfosRelay,endpoint=https://relay.example")
	runJSON(t, updateCmd, nil, nil)

	chain, err := lr.Relay.GetIdentity(did)
	if err != nil || chain == nil {
		t.Fatalf("get identity before delete: chain=%v err=%v", chain, err)
	}
	if len(chain.State.Services) != 1 {
		t.Fatalf("services before delete = %d, want 1", len(chain.State.Services))
	}
	beforeDelete := identityRestorableStateJSON(t, chain.State)

	keys = store
	deleteCmd := newIdentityDeleteCmd()
	runJSON(t, deleteCmd, nil, nil)

	deleted, err := lr.Relay.GetIdentity(did)
	if err != nil || deleted == nil {
		t.Fatalf("get deleted identity: chain=%v err=%v", deleted, err)
	}
	if !deleted.State.IsDeleted {
		t.Fatal("identity is not marked deleted after delete")
	}
	deletedLogLength := len(deleted.Log)

	keys = store
	restoreCmd := newIdentityRestoreCmd()
	var restoreResult struct {
		DID          string `json:"did"`
		OperationCID string `json:"operationCID"`
		Restored     bool   `json:"restored"`
	}
	runJSON(t, restoreCmd, nil, &restoreResult)
	if restoreResult.DID != did || restoreResult.OperationCID == "" || !restoreResult.Restored {
		t.Fatalf("unexpected restore output: %+v", restoreResult)
	}

	restored, err := lr.Relay.GetIdentity(did)
	if err != nil || restored == nil {
		t.Fatalf("get restored identity: chain=%v err=%v", restored, err)
	}
	if restored.State.IsDeleted {
		t.Fatal("identity remains marked deleted after restore")
	}
	if got, want := len(restored.Log), deletedLogLength+1; got != want {
		t.Fatalf("restored log length = %d, want %d", got, want)
	}
	if got := identityRestorableStateJSON(t, restored.State); !bytes.Equal(got, beforeDelete) {
		t.Fatalf("restored keys/services differ from pre-delete state:\n got: %s\nwant: %s", got, beforeDelete)
	}

	keys = store
	restoreAgain := newIdentityRestoreCmd()
	err = restoreAgain.RunE(restoreAgain, []string{"alice"})
	if err == nil {
		t.Fatal("restoring a non-deleted identity succeeded")
	}
	if got, want := err.Error(), "identity 'alice' is not deleted"; got != want {
		t.Fatalf("restore non-deleted error = %q, want %q", got, want)
	}
}

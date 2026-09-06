package relay

import (
	"encoding/json"
	"fmt"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// verifyBlobBytes returns nil iff bytes canonically (dag-cbor) hash to
// wantDocumentCID. This is the content-addressed integrity check at the heart of
// the content plane: a blob's meaning IS its CID, and the CID is already signed
// in the proof plane, so any source is safe to take bytes from as long as they
// re-hash to the documentCID the chain committed.
func verifyBlobBytes(bytes []byte, wantDocumentCID string) error {
	var parsed any
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		return fmt.Errorf("blob bytes are not valid JSON: %w", err)
	}
	_, _, computedCID, err := dfos.DagCborCID(parsed)
	if err != nil {
		return fmt.Errorf("compute documentCID: %w", err)
	}
	if computedCID != wantDocumentCID {
		return fmt.Errorf("blob bytes hash to %s, want %s", computedCID, wantDocumentCID)
	}
	return nil
}

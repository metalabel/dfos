package relay

// DID DOCUMENT PROJECTION (Go twin)
//
// Pure, read-only projection of a verified identity chain's terminal state into
// a W3C DID Document + DIF resolution result. This is the DID-core view of the
// same self-certified state the proof plane serves at
// /proof/v1/identities/{did}. Byte/semantically identical to the TS reference in
// packages/dfos-web-relay/src/did-document.ts — keep the two in lockstep.
//
// The mapping is NORMATIVELY specified and FROZEN in specs/DID-METHOD.md §4:
//   - §4.1 document structure + @context
//   - §4.2 verification-method mapping (authKeys→authentication,
//     assertKeys→assertionMethod, controllerKeys→capabilityInvocation),
//     dedup by DID-URL id across roles
//   - §4.3 controller is always the DID itself
//   - §4.5 service[] mapping (DfosRelay→serviceEndpoint,
//     ContentAnchor→serviceEndpoint+label, unknown types preserved verbatim)
//   - §5.2.2 resolution metadata (created/updated/deactivated/operationCount)
//   - §5.4 deactivated identity → empty verification-method set
//
// No crypto here: IdentityState already carries publicKeyMultibase on every key
// and a resolved services array. Verification happened at ingest.
//
// RAW-BYTE NOTE: the document, recognized service types, AND the error envelopes
// (invalidDid / notFound) are all emitted in TS field-declaration order (via
// structs), so raw curl output byte-matches the TS twin on every routed path.
// The ONLY remaining raw-byte divergence is UNKNOWN service types, marshaled from
// a map[string]any whose keys Go sorts — so unknown-type entries are semantically +
// canonicalization-identical but not raw-key-order-identical to the TS spread. The
// parity gate canonicalizes (recursive key-sort), so both pass; both TS and Go also
// lose source insertion order at JSON decode anyway.

import dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"

// didContext mirrors DID_CONTEXT in did-document.ts — order is normative.
var didContext = []string{
	"https://www.w3.org/ns/did/v1",
	"https://w3id.org/security/multikey/v1",
}

// isValidDfosDid mirrors did-document.ts DFOS_DID_RE. The regex is byte-identical
// to the protocol validator (derivation.go didRe == did-document.ts:41), so we
// reuse the tested one behind a local name that documents the DID-method contract
// point: a resolver MUST reject any non-canonical did:dfos (DID-METHOD.md §3.1).
func isValidDfosDid(did string) bool { return dfos.IsValidDID(did) }

// didURL builds a DID-URL verification-method / service id: `did#fragment`.
func didURL(did, fragment string) string { return did + "#" + fragment }

// -----------------------------------------------------------------------------
// DID Document + DIF resolution result types (fields in TS insertion order)
// -----------------------------------------------------------------------------

type didVerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"` // always "Multikey"
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// didDocument is the live (non-deactivated) document. Relationship arrays ALWAYS
// render (even empty []); service is OMITTED entirely when the set is empty.
type didDocument struct {
	Context              []string                `json:"@context"`
	ID                   string                  `json:"id"`
	Controller           string                  `json:"controller"`
	VerificationMethod   []didVerificationMethod `json:"verificationMethod"`
	Authentication       []string                `json:"authentication"`
	AssertionMethod      []string                `json:"assertionMethod"`
	CapabilityInvocation []string                `json:"capabilityInvocation"`
	Service              []any                   `json:"service,omitempty"`
}

// deactivatedDidDocument is the §5.4 minimal document: ONLY these four keys, empty
// verification-method set, no relationships and no service.
type deactivatedDidDocument struct {
	Context            []string                `json:"@context"`
	ID                 string                  `json:"id"`
	Controller         string                  `json:"controller"`
	VerificationMethod []didVerificationMethod `json:"verificationMethod"`
}

type dfosRelayService struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint any    `json:"serviceEndpoint"`
}

type contentAnchorService struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint any    `json:"serviceEndpoint"`
	Label           any    `json:"label"`
}

type didResolutionMeta struct {
	ContentType string `json:"contentType"`
}

type didDocumentMeta struct {
	Created        *string `json:"created,omitempty"`
	Updated        string  `json:"updated"`
	Deactivated    bool    `json:"deactivated"`
	OperationCount int     `json:"operationCount"`
}

type didResolutionResult struct {
	Context               string            `json:"@context"`
	DidDocument           any               `json:"didDocument"`
	DidResolutionMetadata didResolutionMeta `json:"didResolutionMetadata"`
	DidDocumentMetadata   didDocumentMeta   `json:"didDocumentMetadata"`
}

// resolverErrorMeta carries the DIF resolution error code (invalidDid / notFound).
type resolverErrorMeta struct {
	Error string `json:"error"`
}

// resolverErrorEnvelope is the DIF error resolution result. Declared as a struct —
// NOT a map[string]any — so encoding/json emits keys in TS insertion order
// (didDocument, didResolutionMetadata, didDocumentMetadata), byte-identical to the
// relay.ts error envelopes rather than merely canonicalization-identical (Go sorts
// map keys). DidDocument is always nil → `null`; DidDocumentMetadata is `{}`.
type resolverErrorEnvelope struct {
	DidDocument           any               `json:"didDocument"`
	DidResolutionMetadata resolverErrorMeta `json:"didResolutionMetadata"`
	DidDocumentMetadata   struct{}          `json:"didDocumentMetadata"`
}

// -----------------------------------------------------------------------------
// projection
// -----------------------------------------------------------------------------

// projectService projects a single service entry into its DID Document form
// (DID-METHOD.md §4.5). Recognized types get an explicit serviceEndpoint mapping;
// unrecognized types are preserved verbatim (envelope + all extra fields, type
// intact) with the id re-anchored to did#entryId, so downstream consumers survive
// a relay that does not recognize them (MUST-ignore-unknown).
func projectService(did string, entry dfos.ServiceEntry) any {
	// entry.id is a validated non-empty string at ingest (services.go parseServices).
	entryID, _ := entry["id"].(string)
	id := didURL(did, entryID)
	typ, _ := entry["type"].(string)

	switch typ {
	case "DfosRelay":
		return dfosRelayService{ID: id, Type: typ, ServiceEndpoint: entry["endpoint"]}
	case "ContentAnchor":
		return contentAnchorService{ID: id, Type: typ, ServiceEndpoint: entry["anchor"], Label: entry["label"]}
	default:
		// unrecognized type: preserve verbatim, re-anchor id. Copy so we never
		// mutate the stored state; the key SET + values match the TS spread.
		m := make(map[string]any, len(entry))
		for k, v := range entry {
			m[k] = v
		}
		m["id"] = id
		return m
	}
}

// identityToDidDocument builds a W3C DID Document from a verified identity's
// terminal state (DID-METHOD.md §4). A deactivated identity resolves to a minimal
// document with an empty verification-method set and no verification relationships
// or services (§5.4).
func identityToDidDocument(state dfos.IdentityState) any {
	did := state.DID

	// deactivated: empty VM set, omit all relationships + services (§5.4)
	if state.IsDeleted {
		return deactivatedDidDocument{
			Context:            didContext,
			ID:                 did,
			Controller:         did,
			VerificationMethod: []didVerificationMethod{},
		}
	}

	// dedup verification methods by DID-URL id across roles (§4.2), preserving
	// deterministic first-seen order: auth → assert → controller.
	seen := make(map[string]bool)
	vms := make([]didVerificationMethod, 0, len(state.AuthKeys)+len(state.AssertKeys)+len(state.ControllerKeys))
	appendVM := func(keys []dfos.MultikeyPublicKey) {
		for _, k := range keys {
			id := didURL(did, k.ID)
			if seen[id] {
				continue
			}
			seen[id] = true
			vms = append(vms, didVerificationMethod{
				ID:                 id,
				Type:               "Multikey",
				Controller:         did,
				PublicKeyMultibase: k.PublicKeyMultibase,
			})
		}
	}
	appendVM(state.AuthKeys)
	appendVM(state.AssertKeys)
	appendVM(state.ControllerKeys)

	// role arrays are FULL per-role lists of did#keyId (non-deduped), non-nil so
	// an empty role renders `[]` rather than being omitted.
	roleIDs := func(keys []dfos.MultikeyPublicKey) []string {
		out := make([]string, 0, len(keys))
		for _, k := range keys {
			out = append(out, didURL(did, k.ID))
		}
		return out
	}

	doc := didDocument{
		Context:              didContext,
		ID:                   did,
		Controller:           did,
		VerificationMethod:   vms,
		Authentication:       roleIDs(state.AuthKeys),
		AssertionMethod:      roleIDs(state.AssertKeys),
		CapabilityInvocation: roleIDs(state.ControllerKeys),
	}

	// service[] is optional in DID-core — omit entirely when empty
	if len(state.Services) > 0 {
		svc := make([]any, 0, len(state.Services))
		for _, entry := range state.Services {
			svc = append(svc, projectService(did, entry))
		}
		doc.Service = svc
	}

	return doc
}

// resolveDidDocument builds a DIF Universal Resolver resolution result from a
// resolved chain (DID-METHOD.md §5.2.2). Pure — the chain is already verified
// terminal state.
func resolveDidDocument(chain *StoredIdentityChain) *didResolutionResult {
	// created = genesis op createdAt, omitted when absent (matches the
	// `typeof created === 'string'` guard in did-document.ts).
	var created *string
	if len(chain.Log) > 0 {
		if _, payload, err := dfos.DecodeJWSUnsafe(chain.Log[0]); err == nil {
			if s, ok := payload["createdAt"].(string); ok {
				created = &s
			}
		}
	}

	return &didResolutionResult{
		Context:               "https://w3id.org/did-resolution/v1",
		DidDocument:           identityToDidDocument(chain.State),
		DidResolutionMetadata: didResolutionMeta{ContentType: "application/did+ld+json"},
		DidDocumentMetadata: didDocumentMeta{
			Created:        created,
			Updated:        chain.LastCreatedAt,
			Deactivated:    chain.State.IsDeleted,
			OperationCount: len(chain.Log),
		},
	}
}

package dfos

import (
	"fmt"
	"regexp"
)

// Services discovery vocabulary limits — mirror the TS reference (schemas.ts).
const (
	maxServiceID           = 64
	maxServiceType         = 64
	maxServiceString       = 512
	maxServicesEntries     = 16
	maxServicesPayloadSize = 8192
)

// Anchor target shapes — a ContentAnchor references a STABLE content identifier,
// dispatched by structural form: a 31-char contentId resolves to a content chain;
// a CIDv1 base32 ("baf…") resolves to an artifact.
var (
	contentIDAnchorRe   = regexp.MustCompile(`^[2346789acdefhknrtvz]{31}$`)
	artifactCIDAnchorRe = regexp.MustCompile(`^baf[a-z2-7]{20,}$`)
)

// ServiceEntry is one discovery-vocabulary entry in identity-chain state. The
// namespace is OPEN: recognized types (DfosRelay, ContentAnchor) are structurally
// validated; unrecognized types are preserved verbatim and ignored. Kept as a raw
// map so unknown fields survive round-trips (MUST-ignore-unknown).
type ServiceEntry = map[string]any

// RecognizedServiceTypes are the core-blessed service types. All other types are
// valid but opaque.
var RecognizedServiceTypes = []string{"DfosRelay", "ContentAnchor"}

// IsRecognizedServiceType reports whether the core assigns structural semantics
// to this service type.
func IsRecognizedServiceType(t string) bool {
	for _, r := range RecognizedServiceTypes {
		if r == t {
			return true
		}
	}
	return false
}

// AnchorKind classifies a ContentAnchor target by structural form.
type AnchorKind string

const (
	AnchorChain    AnchorKind = "chain"
	AnchorArtifact AnchorKind = "artifact"
	AnchorInvalid  AnchorKind = "invalid"
)

// ClassifyAnchor classifies a ContentAnchor target by structural form:
// 'chain' → resolve a content chain by contentId; 'artifact' → fetch by CID and
// require type:"artifact"; 'invalid' → reject. A bare head CID is artifact-shaped
// but fails the resolution-time type check, so it is never anchorable.
func ClassifyAnchor(anchor string) AnchorKind {
	switch {
	case contentIDAnchorRe.MatchString(anchor):
		return AnchorChain
	case artifactCIDAnchorRe.MatchString(anchor):
		return AnchorArtifact
	default:
		return AnchorInvalid
	}
}

// RelayEndpoints selects the DfosRelay transport endpoints from a services set,
// in entry order.
func RelayEndpoints(services []ServiceEntry) []string {
	out := make([]string, 0, len(services))
	for _, e := range services {
		if e["type"] == "DfosRelay" {
			if ep, ok := e["endpoint"].(string); ok {
				out = append(out, ep)
			}
		}
	}
	return out
}

// AnchorsByLabel selects ContentAnchor entries matching a client label.
func AnchorsByLabel(services []ServiceEntry, label string) []ServiceEntry {
	out := make([]ServiceEntry, 0)
	for _, e := range services {
		if e["type"] == "ContentAnchor" && e["label"] == label {
			out = append(out, e)
		}
	}
	return out
}

// parseServices reads and validates the optional services array from an identity
// operation payload, mirroring the TS reference: common envelope (id + type) on
// every entry, structural validation of recognized types, bounded entry count,
// unique ids, and an 8192-byte cap on the canonical-CBOR-encoded array. Returns
// nil when the field is absent (CID-neutral). Unrecognized types pass through
// with envelope + cap only (MUST-ignore-unknown).
func parseServices(payload map[string]any) ([]ServiceEntry, error) {
	raw, ok := payload["services"]
	if !ok {
		return nil, nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("services must be an array")
	}
	if len(arr) > maxServicesEntries {
		return nil, fmt.Errorf("services exceeds max entries: %d > %d", len(arr), maxServicesEntries)
	}

	entries := make([]ServiceEntry, 0, len(arr))
	seen := make(map[string]bool)
	for _, item := range arr {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("service entry must be an object")
		}
		id, ok := entry["id"].(string)
		if !ok || len(id) < 1 || len(id) > maxServiceID {
			return nil, fmt.Errorf("service entry requires an id string (1..%d chars)", maxServiceID)
		}
		if seen[id] {
			return nil, fmt.Errorf("service entry ids must be unique: %s", id)
		}
		seen[id] = true
		typ, ok := entry["type"].(string)
		if !ok || len(typ) < 1 || len(typ) > maxServiceType {
			return nil, fmt.Errorf("service entry requires a type string (1..%d chars)", maxServiceType)
		}

		switch typ {
		case "DfosRelay":
			ep, ok := entry["endpoint"].(string)
			if !ok || len(ep) < 1 || len(ep) > maxServiceString {
				return nil, fmt.Errorf("DfosRelay requires a non-empty endpoint string")
			}
		case "ContentAnchor":
			label, ok := entry["label"].(string)
			if !ok || len(label) < 1 || len(label) > maxServiceString {
				return nil, fmt.Errorf("ContentAnchor requires a non-empty label string")
			}
			anchor, ok := entry["anchor"].(string)
			if !ok || !(contentIDAnchorRe.MatchString(anchor) || artifactCIDAnchorRe.MatchString(anchor)) {
				return nil, fmt.Errorf("ContentAnchor anchor must be a 31-char contentId or a CIDv1 artifact CID")
			}
		}
		// unrecognized types: envelope + byte cap only (MUST-ignore-unknown)
		entries = append(entries, entry)
	}

	// byte cap on the canonical CBOR of the services array — same encoding the
	// wire uses, so the bound is identical across implementations.
	encoded, err := DagCborEncode(arr)
	if err != nil {
		return nil, fmt.Errorf("failed to encode services: %w", err)
	}
	if len(encoded) > maxServicesPayloadSize {
		return nil, fmt.Errorf("services payload exceeds max size: %d > %d", len(encoded), maxServicesPayloadSize)
	}

	return entries, nil
}

// normalizeServices ensures a non-nil slice so verified state always projects an
// array (never JSON null), matching the TS VerifiedIdentity.services invariant.
func normalizeServices(s []ServiceEntry) []ServiceEntry {
	if s == nil {
		return []ServiceEntry{}
	}
	return s
}

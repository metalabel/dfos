package cmd

import (
	"fmt"
	"strings"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// parseServiceFlags turns repeatable --service specs into the protocol's
// services array. Each spec is a comma-separated key=value list with a required
// id and type, e.g.
//
//	--service id=relay,type=DfosRelay,endpoint=https://relay.dfos.com
//	--service id=avatar,type=ContentAnchor,label=avatar,anchor=baf...
//
// The namespace is OPEN: unrecognized types carry their extra key=value pairs
// through verbatim. All values are strings — the recognized-type structural
// rules (and the 256-entry / 32768-byte caps) are enforced by the protocol layer
// at sign time, so this stays a thin transcription with no validation of its
// own beyond requiring id and type.
func parseServiceFlags(specs []string) ([]protocol.ServiceEntry, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	entries := make([]protocol.ServiceEntry, 0, len(specs))
	for _, spec := range specs {
		entry := protocol.ServiceEntry{}
		for _, field := range strings.Split(spec, ",") {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}
			k, v, ok := strings.Cut(field, "=")
			if !ok {
				return nil, fmt.Errorf("invalid service field %q (expected key=value)", field)
			}
			entry[strings.TrimSpace(k)] = v
		}
		if _, ok := entry["id"]; !ok {
			return nil, fmt.Errorf("service %q is missing required id", spec)
		}
		if _, ok := entry["type"]; !ok {
			return nil, fmt.Errorf("service %q is missing required type", spec)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

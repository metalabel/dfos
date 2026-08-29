package client

// The index family (`/index/v0/*`) is a relay's OPTIONAL, non-authoritative
// query surface. It sits on its own `0.x` clock beside the frozen proof plane,
// it is gated by `capabilities.index`, and a relay that does not serve it
// answers 501 on every route.
//
// The CLI reads exactly one route here: the identity index's `key=` filter, the
// "which identities has this key ever been declared by" reverse lookup that
// `dfos recover` asks its oracle. Two properties of that route shape this file:
//
//   - 501 is a real answer with a real meaning — "this relay does not serve the
//     index" — and it must NEVER be flattened into an empty result. It gets its
//     own sentinel error so a caller cannot accidentally read a missing
//     capability as "no identities declared this key".
//   - A relay predating the `key=` parameter IGNORES it and answers with an
//     UNFILTERED page. There is no status code to catch: the spec defines `key=`
//     as an opaque string match with no format validation and therefore no 400
//     to provoke. Detecting that relay is the CALLER's job, with a sentinel
//     query, and this file exists to make that query cheap.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// indexBasePath namespaces the index family. Unlike `/proof/v1` this is NOT
// frozen: the `v0` is the family's `0.x` clock made legible in the path.
const indexBasePath = "/index/v0"

// ErrIndexUnavailable is the relay's "I do not serve this" — a 501 from an
// index route, which WEB-RELAY.md specifies as the answer when
// `capabilities.index` is false or absent. It is a distinct error rather than an
// empty page because the two mean opposite things, and a recovery scan that
// confused them would report an operator's identities as gone.
var ErrIndexUnavailable = errors.New("this relay does not serve the index family (/index/v0) — capabilities.index is off or the relay predates it")

// IndexIdentityRow is one row of GET /index/v0/identities. Rows are browsing
// metadata: they carry no JWS and no proof, and every consumer that needs the
// chain fetches it from the proof plane.
type IndexIdentityRow struct {
	DID       string                `json:"did"`
	HeadCID   string                `json:"headCID"`
	OpCount   int                   `json:"opCount"`
	IsDeleted bool                  `json:"isDeleted"`
	Profile   *IndexIdentityProfile `json:"profile"`
}

// IndexIdentityProfile is the well-known projection carried on an identity row,
// or nil when the identity anchors no profile. Every field is amber: it restates
// what the relay folded, and it is never an access decision or a proof.
type IndexIdentityProfile struct {
	Anchor     string `json:"anchor"`
	PublicRead bool   `json:"publicRead"`
	Name       string `json:"name"`
}

// IdentitiesByKey runs the has-ever-declared reverse lookup: which identities
// have ever declared this public key, in any role, in any accepted operation —
// including operations a later update rotated the key out of. That history is
// the point: a holder rediscovering identities from a restored seed may hold
// exactly the keys that were rotated away, and a current-state match would hide
// the chains that matter most.
//
// key is matched byte-for-byte as an opaque string, so a key no operation ever
// declared simply matches nothing. A 501 returns ErrIndexUnavailable.
//
// One page only. The caller's question is "did anything ever declare this",
// which a first page of up to `limit` rows answers; nothing here needs an
// exhaustive enumeration of a key's history.
func (c *Client) IdentitiesByKey(key string, limit int) ([]IndexIdentityRow, error) {
	q := url.Values{}
	q.Set("key", key)
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	path := indexBasePath + "/identities?" + q.Encode()

	resp, err := c.HTTPClient.Get(c.BaseURL + path)
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotImplemented {
		return nil, ErrIndexUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, path, oneLine(body, 200))
	}

	// The envelope's `identities` member must be an ARRAY for the answer to mean
	// anything. A 200 whose body is not a readable identities page is not an
	// empty result — it is a relay this client cannot interpret, and saying so is
	// the only safe reading.
	var page struct {
		Identities *[]IndexIdentityRow `json:"identities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if page.Identities == nil {
		return nil, fmt.Errorf("%s answered 200 with no 'identities' array — this response is not an index page", path)
	}
	return *page.Identities, nil
}

// oneLine squeezes a response body into something that belongs inside an error
// sentence. A URL that turns out not to be a relay at all answers with a whole
// HTML error page, and pasting forty lines of markup into a failure message
// buries the sentence the operator actually needs to read.
func oneLine(body []byte, max int) string {
	s := strings.Join(strings.Fields(string(body)), " ")
	if s == "" {
		return "(empty response body)"
	}
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

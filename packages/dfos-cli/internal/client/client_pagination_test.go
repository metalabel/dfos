package client

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestGetIdentityLogPrefersNextWithCursorFallback(t *testing.T) {
	client := New("http://relay.test")
	client.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Query().Get("after") {
		case "":
			return jsonResponse(`{"entries":[{"cid":"one","jwsToken":"one.token.sig"}],"cursor":"legacy-resume"}`), nil
		case "legacy-resume":
			return jsonResponse(`{"entries":[{"cid":"two","jwsToken":"two.token.sig"}],"next":"preferred-resume","cursor":"wrong-legacy-resume"}`), nil
		case "preferred-resume":
			return jsonResponse(`{"entries":[],"next":null,"cursor":null}`), nil
		default:
			t.Fatalf("unexpected after value %q", r.URL.Query().Get("after"))
			return nil, nil
		}
	})}

	tokens, err := client.GetIdentityLog("did:dfos:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 || tokens[0] != "one.token.sig" || tokens[1] != "two.token.sig" {
		t.Fatalf("tokens = %v", tokens)
	}
}

func TestGetCountersignaturesPaginatesObjectRows(t *testing.T) {
	client := New("http://relay.test")
	client.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("after") == "cs-one" {
			return jsonResponse(`{"countersignatures":[{"cid":"cs-two","jwsToken":"two.token.sig"}],"next":null}`), nil
		}
		return jsonResponse(`{"countersignatures":[{"cid":"cs-one","jwsToken":"one.token.sig"}],"next":"cs-one"}`), nil
	})}

	result, err := client.GetCountersignatures("target")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result["cid"]; ok {
		t.Fatal("deprecated top-level cid echo must not be synthesized")
	}
	rows, ok := result["countersignatures"].([]any)
	if !ok || len(rows) != 2 {
		t.Fatalf("countersignatures = %#v", result["countersignatures"])
	}
	first, ok := rows[0].(map[string]any)
	if !ok || first["cid"] != "cs-one" || first["jwsToken"] != "one.token.sig" {
		t.Fatalf("first row = %#v", rows[0])
	}
}

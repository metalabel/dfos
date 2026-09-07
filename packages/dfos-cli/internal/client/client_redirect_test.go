package client

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRelayRedirectDoesNotForwardCredential(t *testing.T) {
	var reached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()
	c := New(source.URL)
	req, err := http.NewRequest(http.MethodGet, source.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Credential", "secret")
	_, err = c.HTTPClient.Do(req)
	if err == nil || !strings.Contains(err.Error(), "redirect not followed") {
		t.Fatalf("redirect result: %v", err)
	}
	if reached.Load() {
		t.Fatal("redirect destination received request")
	}
}

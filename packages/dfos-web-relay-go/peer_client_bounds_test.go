package relay

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A peer log page is decoded from a body a hostile peer chooses the size of,
// on a path unauthenticated GETs reach (read-through). The ops budget and the
// deadline only run after the decode returns, so the bound has to live at the
// decode itself.

func TestPeerLogPageIsByteBounded(t *testing.T) {
	// The peer opens a page and then never closes it. Without the
	// io.LimitReader in fetchLog this decode never returns.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"entries":[`)); err != nil {
			return
		}
		entry := `{"cid":"` + strings.Repeat("a", 4096) + `","jwsToken":"x"},`
		for {
			if _, err := w.Write([]byte(entry)); err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))
	defer server.Close()

	client := NewHttpPeerClient()
	page, err := client.GetOperationLog(server.URL, "", 1000)
	if err == nil {
		t.Fatalf("expected an unbounded page to be refused, got %d entries", len(page.Entries))
	}
	if !strings.Contains(err.Error(), "peer log page") {
		t.Fatalf("expected a page-decode error, got %v", err)
	}
}

func TestPeerLogPageEntryCountIsBounded(t *testing.T) {
	// A well-formed page that answers a limit of 10 with 50 entries is
	// answering a question nobody asked; it is refused, not drained.
	var entries []string
	for i := 0; i < 50; i++ {
		entries = append(entries, fmt.Sprintf(`{"cid":"cid-%d","jwsToken":"token-%d"}`, i, i))
	}
	body := `{"entries":[` + strings.Join(entries, ",") + `],"next":"cursor-50"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	client := NewHttpPeerClient()
	if _, err := client.GetOperationLog(server.URL, "", 10); err == nil {
		t.Fatal("expected an over-limit page to be refused")
	} else if !strings.Contains(err.Error(), "50 log entries for a limit of 10") {
		t.Fatalf("expected an entry-count error, got %v", err)
	}

	// The same page is fine when it is what the caller asked for.
	page, err := client.GetOperationLog(server.URL, "", 50)
	if err != nil {
		t.Fatalf("a page within the requested limit must be accepted: %v", err)
	}
	if len(page.Entries) != 50 {
		t.Fatalf("expected 50 entries, got %d", len(page.Entries))
	}
}

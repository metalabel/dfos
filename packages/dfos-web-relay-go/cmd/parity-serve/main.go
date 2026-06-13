// Command parity-serve boots the Go web relay for the dual-relay parity harness
// (WP-7), pinned to the SAME relay identity as the TS twin so neither relay's
// own bootstrap identity leaks into /log or /.well-known. It reads the parity
// fixture (relayDid + relayProfileJws) and starts an HTTP server.
//
// Unlike `dfos serve`, this provides an explicit RelayIdentity, which makes
// NewRelay SKIP the JIT bootstrap (no random identity ingested). The relay's
// own genesis + profile are replayed as ordinary ops by the parity test, so the
// relay DID's log entries are byte-identical across both twins.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

type fixture struct {
	RelayDID        string `json:"relayDid"`
	RelayProfileJWS string `json:"relayProfileJws"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: parity-serve <port> <fixture-path> [sqlite-db-path]")
		os.Exit(1)
	}
	port := os.Args[1]
	fixturePath := os.Args[2]
	dbPath := ""
	if len(os.Args) >= 4 {
		dbPath = os.Args[3]
	}

	data, err := os.ReadFile(fixturePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read fixture: %v\n", err)
		os.Exit(1)
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		fmt.Fprintf(os.Stderr, "parse fixture: %v\n", err)
		os.Exit(1)
	}

	// keep server logs off stdout/stderr from drowning the harness
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	// SQLite store (file-backed — matches the production Go twin). NewRelay
	// auto-derives the WAL read pool for *SQLiteStore.
	var store relay.Store
	if dbPath != "" {
		s, err := relay.NewSQLiteStore(dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open sqlite: %v\n", err)
			os.Exit(1)
		}
		store = s
	} else {
		store = relay.NewMemoryStore()
	}

	r, err := relay.NewRelay(relay.RelayOptions{
		Store: store,
		Identity: &relay.RelayIdentity{
			DID:                f.RelayDID,
			ProfileArtifactJWS: f.RelayProfileJWS,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "new relay: %v\n", err)
		os.Exit(1)
	}

	srv := &http.Server{Addr: ":" + port, Handler: r.Handler()}
	fmt.Printf("parity Go relay on :%s (did=%s)\n", port, f.RelayDID)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

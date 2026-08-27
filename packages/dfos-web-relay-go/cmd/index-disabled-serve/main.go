// Command index-disabled-serve boots the Go reference relay with only the
// optional /index/v0 query family disabled. It is the Go twin of
// packages/relay-conformance/scripts/serve-index-disabled.ts.
package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: index-disabled-serve <port>")
		os.Exit(1)
	}
	port := os.Args[1]

	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	indexDisabled := false
	// The relay's OWN configured authority — the host binding every identity
	// proof is checked against. Configuration, never read from the request.
	r, err := relay.NewRelay(relay.RelayOptions{
		Store:     relay.NewMemoryStore(),
		Authority: "localhost:" + port,
		Index:     &indexDisabled,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "new relay: %v\n", err)
		os.Exit(1)
	}

	srv := &http.Server{Addr: ":" + port, Handler: r.Handler()}
	fmt.Printf("index-disabled Go relay on :%s (did=%s)\n", port, r.DID())
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

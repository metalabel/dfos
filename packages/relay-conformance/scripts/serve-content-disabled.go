//go:build ignore

// Command content-disabled-serve boots the Go reference relay with only the
// optional /content/v1 family disabled. It is the Go twin of
// packages/relay-conformance/scripts/serve-content-disabled.ts.
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
		fmt.Fprintln(os.Stderr, "usage: content-disabled-serve <port>")
		os.Exit(1)
	}
	port := os.Args[1]

	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	contentDisabled := false
	// The relay's OWN configured authority — the host binding every identity
	// proof is checked against. Configuration, never read from the request.
	r, err := relay.NewRelay(relay.RelayOptions{
		Store:     relay.NewMemoryStore(),
		Authority: "localhost:" + port,
		Content:   &contentDisabled,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "new relay: %v\n", err)
		os.Exit(1)
	}

	srv := &http.Server{Addr: ":" + port, Handler: r.Handler()}
	fmt.Printf("content-disabled Go relay on :%s (did=%s)\n", port, r.DID())
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

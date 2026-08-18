// Command signing-serve boots a signing-enabled Go relay for conformance.
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
		fmt.Fprintln(os.Stderr, "usage: signing-serve <port>")
		os.Exit(1)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	enabled := true
	r, err := relay.NewRelay(relay.RelayOptions{
		Store:   relay.NewMemoryStore(),
		Signing: &enabled,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "new relay: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("signing-enabled Go relay on :%s (did=%s)\n", os.Args[1], r.DID())
	if err := http.ListenAndServe(":"+os.Args[1], r.Handler()); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

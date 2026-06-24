// Command write-disabled-serve boots the Go web relay in WRITE-DISABLED (lite /
// pull-only) mode for read-only conformance testing — the Go twin of
// packages/relay-conformance/scripts/serve-write-disabled.ts.
//
// It seeds one user identity chain OUT-OF-BAND — via IngestOperations directly
// against the store, NOT over the POST write path (which is 501 here) — then
// serves with Write:false. It prints `SEEDED_DID=<did>` so the conformance
// runner can point TestWriteDisabledSeededIdentity at a real served chain. The
// relay also JIT-bootstraps its own identity in-process, so even without the
// seed the read plane has a chain to recompute.
//
// Usage: write-disabled-serve <port>
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: write-disabled-serve <port>")
		os.Exit(1)
	}
	port := os.Args[1]

	// keep server logs from drowning the harness output
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	store := relay.NewMemoryStore()

	// --- mint + seed a user identity chain OUT-OF-BAND (not via POST) ---
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate key: %v\n", err)
		os.Exit(1)
	}
	keyID := dfos.GenerateKeyID()
	mk := dfos.NewMultikeyPublicKey(keyID, pub)
	seedJWS, seededDID, _, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{mk}, // controller
		[]dfos.MultikeyPublicKey{mk}, // auth
		[]dfos.MultikeyPublicKey{mk}, // assert
		keyID,
		priv,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign identity genesis: %v\n", err)
		os.Exit(1)
	}
	results := relay.IngestOperations([]string{seedJWS}, store)
	if len(results) == 0 || results[0].Status == "rejected" {
		msg := "unknown"
		if len(results) > 0 && results[0].Error != "" {
			msg = results[0].Error
		}
		fmt.Fprintf(os.Stderr, "seed identity rejected: %s\n", msg)
		os.Exit(1)
	}

	// --- serve write-disabled (POST → 501; reads serve the seeded chain) ---
	writeDisabled := false
	r, err := relay.NewRelay(relay.RelayOptions{
		Store: store,
		Write: &writeDisabled,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "new relay: %v\n", err)
		os.Exit(1)
	}

	srv := &http.Server{Addr: ":" + port, Handler: r.Handler()}
	fmt.Printf("write-disabled Go relay on :%s (did=%s)\n", port, r.DID())
	// printed last so the runner can grep it once the listener is up
	fmt.Printf("SEEDED_DID=%s\n", seededDID)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

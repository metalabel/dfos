package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	store := relay.NewMemoryStore()
	r, err := relay.NewRelay(relay.RelayOptions{
		Store:   store,
		Content: true,
	})
	if err != nil {
		log.Fatalf("failed to create relay: %v", err)
	}

	addr := ":" + port
	fmt.Printf("DFOS Go relay listening on %s (DID: %s)\n", addr, r.DID())
	if err := http.ListenAndServe(addr, r.Handler()); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

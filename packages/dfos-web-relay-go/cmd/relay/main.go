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

	// STORE env var selects the backend: "sqlite" or "memory" (default)
	storeType := os.Getenv("STORE")
	dbPath := os.Getenv("SQLITE_PATH")
	if dbPath == "" {
		dbPath = "relay.db"
	}

	var store relay.Store
	switch storeType {
	case "sqlite":
		s, err := relay.NewSQLiteStore(dbPath)
		if err != nil {
			log.Fatalf("failed to open SQLite store at %s: %v", dbPath, err)
		}
		defer s.Close()
		store = s
		fmt.Printf("Using SQLite store at %s\n", dbPath)
	default:
		store = relay.NewMemoryStore()
		fmt.Println("Using in-memory store")
	}

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

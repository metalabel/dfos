package main

import (
	"fmt"
	"os"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/cmd"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/update"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

var version = "dev"

func main() {
	cmd.Version = version
	relay.SoftwareVersion = version

	// start background version check (non-blocking, 2s timeout, 24h cache)
	updateDone := make(chan struct{})
	go update.CheckAndNotify(version, updateDone)

	root := cmd.NewRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// wait briefly for the update notice to print, but don't block exit
	select {
	case <-updateDone:
	case <-time.After(300 * time.Millisecond):
	}
}

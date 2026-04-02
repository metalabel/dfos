package main

import (
	"fmt"
	"os"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/cmd"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/update"
)

var version = "dev"

func main() {
	cmd.Version = version

	// start background version check (non-blocking, 2s timeout, 24h cache)
	updateDone := make(chan struct{})
	go update.CheckAndNotify(version, updateDone)

	root := cmd.NewRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// wait briefly for the update check to finish printing
	<-updateDone
}

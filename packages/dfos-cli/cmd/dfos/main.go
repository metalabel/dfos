package main

import (
	"encoding/json"
	"errors"
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
	relay.Version = version

	// start background version check (non-blocking, 2s timeout, 24h cache)
	updateDone := make(chan struct{})
	go update.CheckAndNotify(version, updateDone)

	root := cmd.NewRootCmd()
	if err := root.Execute(); err != nil {
		// A verdict-bearing command (identity verify-binding) already printed its
		// result on stdout and carries only an exit status — exit with its code,
		// printing nothing on top.
		var exitErr *cmd.ExitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		// Honor --json on the error path too, so scripted callers always get
		// machine-readable output instead of a bare error line. An error that
		// carries a reason code renders it beside the prose.
		if cmd.JSONFlag() {
			json.NewEncoder(os.Stderr).Encode(cmd.ErrorJSON(err))
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}

	// wait briefly for the update notice to print, but don't block exit
	select {
	case <-updateDone:
	case <-time.After(300 * time.Millisecond):
	}
}

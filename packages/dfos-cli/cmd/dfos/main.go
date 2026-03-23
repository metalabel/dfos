package main

import (
	"fmt"
	"os"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/cmd"
)

var version = "dev"

func main() {
	cmd.Version = version
	root := cmd.NewRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

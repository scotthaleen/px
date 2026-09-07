package main

import (
	"context"
	"fmt"
	"os"

	"github.com/scotthaleen/px/internal/servercli"
)

func main() {
	if err := servercli.NewCommand(context.Background(), servercli.IOStreams{
		In:  os.Stdin,
		Out: os.Stdout,
		Err: os.Stderr,
	}).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "px-server:", err)
		os.Exit(1)
	}
}

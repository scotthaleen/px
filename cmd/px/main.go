package main

import (
	"context"
	"os"

	"github.com/scotthaleen/px/internal/cli"
)

func main() {
	args, err := cli.RewritePXArgs(os.Args[1:])
	if err != nil {
		_ = cli.WritePXError(os.Stderr, err, false)
		os.Exit(1)
	}
	command, err := cli.NewPXCommand(context.Background(), cli.IOStreams{
		In:  os.Stdin,
		Out: os.Stdout,
		Err: os.Stderr,
	})
	if err != nil {
		_ = cli.WritePXError(os.Stderr, err, false)
		os.Exit(1)
	}
	command.SetArgs(args)
	executed, err := command.ExecuteC()
	if err != nil {
		_ = cli.WritePXError(os.Stderr, err, cli.JSONOutputEnabled(executed))
		os.Exit(1)
	}
}

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/pccr10001/wgcfzt/internal/cli"
	"github.com/spf13/cobra"
)

func main() {
	// Windows may broker browser protocol callbacks through Explorer. Cobra's
	// double-click guard would exit before the callback command can deliver JWTs.
	cobra.MousetrapHelpText = ""
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := cli.New().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

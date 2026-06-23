package main

import (
	"os"

	"github.com/l3montree-dev/devguard/cmd/devguard-maint/commands"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "devguard-maint",
		Short: "DevGuard maintenance utilities",
	}

	release := &cobra.Command{
		Use:   "release",
		Short: "Release management commands",
	}
	release.AddCommand(
		commands.ReleaseDevguardCmd,
		commands.ReleaseCICmd,
		commands.ReleaseHelmCmd,
	)

	root.AddCommand(commands.LogsCmd, release)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

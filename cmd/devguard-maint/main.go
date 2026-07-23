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
		commands.ReleaseWebCmd,
		commands.ReleaseCICmd,
		commands.ReleaseHelmCmd,
		commands.ReleaseK8sIntegrationCmd,
		commands.NewLicensesCommand(),
	)

	root.AddCommand(commands.LogsCmd, commands.DocsCmd, release)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

package commands

import (
	"slices"

	"github.com/spf13/cobra"
)

func NewVulndbCommand() *cobra.Command {
	vulndbCmd := cobra.Command{
		Use:   "vulndb",
		Short: "Manage the vulnerability database",
		Long:  "Commands for managing, synchronizing, and maintaining the vulnerability database from multiple upstream sources including NVD, OSV, ExploitDB, and others.",
	}

	vulndbCmd.AddCommand(newImportCommand())
	vulndbCmd.AddCommand(newExportCommand())
	vulndbCmd.AddCommand(newAliasMappingCommand())
	return &vulndbCmd
}

func emptyOrContains(s []string, e string) bool {
	if len(s) == 0 {
		return true
	}
	return slices.Contains(s, e)
}

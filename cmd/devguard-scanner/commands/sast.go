package commands

import (
	"github.com/spf13/cobra"
)

func NewSastCommand() *cobra.Command {
	sastCommand := &cobra.Command{
		Use:   "sast",
		Short: "Launch a static application security test.",
		Long:  "Launch a static application security test. A SAST test runs predefined rules against your source code",

		RunE: func(cmd *cobra.Command, args []string) error {
			return sarifCommandFactory("sast")(cmd, args)
		},
	}

	addScanFlags(sastCommand)
	return sastCommand
}

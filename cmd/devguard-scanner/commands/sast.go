package commands

import (
	"log/slog"

	"github.com/spf13/cobra"
)

func NewSastCommand() *cobra.Command {
	sastCommand := &cobra.Command{
		Use:   "sast",
		Short: "Launch a static application security test.",
		Long:  "Launch a static application security test. A SAST test runs predefined rules against your source code",

		Run: func(cmd *cobra.Command, args []string) {
			err := sarifCommandFactory("sast")(cmd, args)
			if err != nil {
				slog.Error("sast failed", "err", err)
				return
			}
		},
	}

	addScanFlags(sastCommand)
	return sastCommand
}

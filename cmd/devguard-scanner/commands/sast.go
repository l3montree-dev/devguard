package commands

import (
	"log/slog"

	"github.com/spf13/cobra"
)

func NewSastCommand() *cobra.Command {
	sastCommand := &cobra.Command{
		Use:   "sast",
		Short: "Start a static application security testing",
		Long:  "This command will scan an application for vulnerabilities and return a list of vulnerabilities found in the application.",

		Run: func(cmd *cobra.Command, args []string) {
			err := sarifCommandFactory("sast")(cmd, args)
			if err != nil {
				slog.Error("sast failed", "err", err)
				return
			}
		},
	}

	sastCommand.Flags().Bool("riskManagement", true, "Enable risk management (stores the detected vulnerabilities in devguard)")

	addScanFlags(sastCommand)
	return sastCommand
}

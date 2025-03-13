// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package commands

import (
	"bytes"
	"log/slog"
	"os/exec"

	"github.com/spf13/cobra"
)

func NewHealthCheckCommand() *cobra.Command {
	healthCheckCommand := &cobra.Command{
		Use:   "health",
		Short: "Check the health of the scanner. Checks if all dependencies are installed",
		Long:  `Check if all dependencies are installed for the scanner to function`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			// execute cdxgen and git help commands. If they throw an error, print it to the console
			// if they don't, print a success message

			for _, command := range []string{"trivy", "git"} {
				cmd := exec.Command(command, "--help")
				// get the output
				var out bytes.Buffer
				cmd.Stdout = &out

				err := cmd.Run()
				if err != nil {
					slog.Error("could not execute command", "command", command, "err", err)
					panic(err.Error())
				}
				// read the output
				slog.Info("command executed successfully", "command", command)
			}
		},
	}
	return healthCheckCommand
}

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
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func NewContainerScanningCommand() *cobra.Command {
	containerScanningCommand := &cobra.Command{
		Use:   "container-scanning",
		Short: "Software composition analysis of a container image",
		Long:  `Scan a SBOM for vulnerabilities. This command will scan a SBOM for vulnerabilities and return a list of vulnerabilities found in the SBOM. The SBOM must be passed as an argument.`,
		// Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			// check if the path has a .tar ending
			path, err := cmd.Flags().GetString("path")
			if err != nil {
				slog.Error("could not get path", "err", err)
				os.Exit(1)
			}
			if !strings.HasSuffix(path, ".tar") {
				slog.Error("invalid path", "err", fmt.Errorf("path must be a tar file"))
				os.Exit(1)
			}

			err = scaCommandFactory("container-scanning")(cmd, args)

			if err != nil {
				slog.Error("container scanning failed", "err", err)
				os.Exit(1)
			}
		},
	}

	containerScanningCommand.Flags().Bool("riskManagement", true, "Enable risk management (stores the detected vulnerabilities in devguard)")

	addScanFlags(containerScanningCommand)
	return containerScanningCommand
}

// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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
	"strings"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/spf13/cobra"
)

func NewContainerScanningCommand() *cobra.Command {
	containerScanningCommand := &cobra.Command{
		Use:   "container-scanning",
		Short: "Software composition analysis of a container image",
		Long:  `Scan a container image for vulnerabilities. The image must either be a tar file (--path) or available for download via a container registry (--image).`,
		// Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			if config.RuntimeBaseConfig.Image != "" {
				return scaCommand(cmd, args)
			} else {
				hasTarSuffix := strings.HasSuffix(config.RuntimeBaseConfig.Path, ".tar")
				if !hasTarSuffix {
					return fmt.Errorf("path must be a tar file")
				}
				return scaCommand(cmd, args)
			}
		},
	}

	addDependencyVulnsScanFlags(containerScanningCommand)
	containerScanningCommand.Flags().String("image", "", "The oci image to scan.")
	containerScanningCommand.Flags().String("origin", "container-scanning", "The type of the scanner. Can be 'origin' or 'container-scan'. Defaults to 'container-scan'.")

	return containerScanningCommand
}

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
	"strings"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/spf13/cobra"
)

func NewContainerScanningCommand() *cobra.Command {
	containerScanningCommand := &cobra.Command{
		Use:   "container-scanning",
		Short: "Software composition analysis of a container image",
		Long:  `Scan a container image for vulnerabilities. The image must be a tar file.`,
		// Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !strings.HasSuffix(config.RuntimeBaseConfig.Path, ".tar") {
				return fmt.Errorf("path must be a tar file")
			}

			return scaCommandFactory("container-scanning")(cmd, args)
		},
	}

	addScanFlags(containerScanningCommand)
	return containerScanningCommand
}

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
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/spf13/cobra"
)

func NewContainerScanningCommand() *cobra.Command {
	containerScanningCommand := &cobra.Command{
		Use:               "container-scanning",
		Short:             "Software composition analysis of a container image",
		DisableAutoGenTag: true,
		Long: `Scan a container image for vulnerabilities. The image must either be a tar file (--path)
or be available for download via a container registry (--image). The command generates or
uploads an SBOM which is then analyzed by DevGuard. The request is signed using the
configured token before upload.`,
		Example: `  # Scan a container image from registry
  devguard-scanner container-scanning --image ghcr.io/org/image:tag

  # Scan a container image tar file
  devguard-scanner container-scanning --path image.tar

  # Scan and ignore upstream attestations
  devguard-scanner container-scanning --image ghcr.io/org/image:tag --ignoreUpstreamAttestations`,
		RunE: scaCommand,
	}

	scanner.AddDependencyVulnsScanFlags(containerScanningCommand)
	containerScanningCommand.Flags().String("image", "", "OCI image reference to scan (e.g. ghcr.io/org/image:tag). If empty, --path or the first argument may be used to provide a tar or local files.")
	containerScanningCommand.Flags().String("path", "", "Path to a tar file or directory containing the container image to scan. If empty, --image must be provided or an argument.")
	containerScanningCommand.Flags().Bool("ignoreUpstreamAttestations", false, "Ignores attestations from the scanned container image - if they exists")

	return containerScanningCommand
}

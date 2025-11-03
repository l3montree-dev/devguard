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
	"log/slog"
	"os"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/spf13/cobra"
)

func NewVexCommand() *cobra.Command {
	vexCommand := &cobra.Command{
		Use:   "vex <vex-file>",
		Short: "Upload a VEX document to DevGuard",
		Long: `Upload a VEX (Vulnerability Exploitability eXchange) document to DevGuard.
The VEX document must be provided as a file argument. The request is signed using the
configured token before upload.

Example:
  devguard-scanner vex vex.json
`,

		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// check the first argument and read the file
			path := args[0]
			if _, err := os.Stat(path); os.IsNotExist(err) {
				return fmt.Errorf("file does not exist: %s", path)
			}

			file, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("could not read file: %w", err)
			}

			resp, err := scanner.UploadVEX(file)
			if err != nil {
				return fmt.Errorf("could not upload VEX: %w", err)
			}

			defer resp.Body.Close()

			if resp.StatusCode > 399 {
				return fmt.Errorf("could not upload VEX, status code: %d", resp.StatusCode)
			}
			slog.Info("vex document uploaded successfully")
			return nil
		},
	}
	scanner.AddDependencyVulnsScanFlags(vexCommand)
	return vexCommand
}

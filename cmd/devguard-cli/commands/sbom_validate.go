// Copyright (C) 2026 l3montree GmbH
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
	"encoding/json"
	"fmt"
	"io"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/spf13/cobra"
)

func newValidateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [sbom.json|-]",
		Short: "Validate a CycloneDX SBOM by parsing it into a dependency graph",
		Long: `Validate a CycloneDX SBOM by reading it and building an SBOM dependency graph.

Exits with code 0 if the SBOM is valid, non-zero otherwise.
Pass a file path, '-' to read from stdin, or omit the argument to read from stdin.`,
		Example: `  # Validate an SBOM file
  devguard-cli sbom validate sbom.json

  # Validate from stdin
  cat sbom.json | devguard-cli sbom validate`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var src io.Reader
			if len(args) == 0 || args[0] == "-" {
				src = os.Stdin
			} else {
				filePath := args[0]
				file, err := os.Open(filePath)
				if err != nil {
					return fmt.Errorf("failed to open file: %w", err)
				}
				defer file.Close()
				src = file
			}

			data, err := io.ReadAll(src)
			if err != nil {
				return fmt.Errorf("failed to read SBOM: %w", err)
			}

			var bom cdx.BOM
			if err := json.Unmarshal(data, &bom); err != nil {
				return fmt.Errorf("failed to parse CycloneDX SBOM: %w", err)
			}

			if _, err := normalize.SBOMGraphFromCycloneDX(&bom, "stdin", "cli-validate", false); err != nil {
				return fmt.Errorf("failed to build SBOM graph: %w", err)
			}

			fmt.Println("true")
			return nil
		},
	}
}

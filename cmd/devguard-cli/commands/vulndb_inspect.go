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
	"fmt"
	"log/slog"
	"strings"

	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vulndb/scan"
	"github.com/package-url/packageurl-go"
	"github.com/spf13/cobra"
)

// newInspectCommand creates the inspect command for PURL inspection
func newInspectCommand() *cobra.Command {
	inspectCmd := &cobra.Command{
		Use:   "inspect <purl>",
		Short: "Inspect PURL for matching CVEs and vulnerabilities",
		Long: `Inspects a Package URL (PURL) against the vulnerability database and displays
detailed information about matching CVEs, affected components, and relationships.

Examples:
  devguard-cli inspect "pkg:npm/lodash@4.17.20"
  devguard-cli inspect "pkg:deb/debian/libc6@2.31-1"
  devguard-cli inspect -v "pkg:pypi/requests@2.25.0"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			purlString := args[0]

			purl, err := packageurl.FromString(purlString)
			if err != nil {
				slog.Error("invalid PURL", "purl", purlString, "err", err)
				return fmt.Errorf("invalid PURL: %w", err)
			}

			if err := shared.LoadConfig(); err != nil {
				slog.Error("failed to load config", "error", err)
				return fmt.Errorf("failed to load config: %w", err)
			}

			var affectedComponents []models.AffectedComponent
			var matchCtx *normalize.PurlMatchContext
			pool := database.NewPgxConnPool(database.GetPoolConfigFromEnv())
			db := database.NewGormDB(pool)

			matchCtx = normalize.ParsePurlForMatching(purl)
			comparer := scan.NewPurlComparer(db)
			affectedComponents, err = comparer.GetAffectedComponents(purl)
			if err != nil {
				slog.Error("error getting affected components", "error", err, "purl", purlString)
				return fmt.Errorf("error getting affected components: %w", err)
			}
			return outputInspectResult(purlString, purl, matchCtx, affectedComponents)
		},
	}

	return inspectCmd
}

func outputInspectResult(inputPurl string, purl packageurl.PackageURL, matchCtx *normalize.PurlMatchContext, affectedComponents []models.AffectedComponent) error {
	// Collect unique CVEs
	cveMap := make(map[string]models.CVE)
	for _, ac := range affectedComponents {
		for _, cve := range ac.CVE {
			cveMap[cve.CVE] = cve
		}
	}

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("PURL INSPECTION RESULT")
	fmt.Println(strings.Repeat("=", 80))

	fmt.Printf("\n%-20s %s\n", "Input PURL:", inputPurl)
	fmt.Printf("%-20s %s\n", "Search PURL:", matchCtx.SearchPurl)
	fmt.Printf("%-20s %s\n", "Version:", purl.Version)
	fmt.Printf("%-20s %s\n", "Version Type:", matchCtx.HowToInterpretVersionString)
	fmt.Printf("%-20s %s\n", "PURL Type:", purl.Type)
	if purl.Namespace != "" {
		fmt.Printf("%-20s %s\n", "Namespace:", purl.Namespace)
	}
	if matchCtx.Qualifiers.String() != "" {
		fmt.Printf("%-20s %s\n", "Qualifiers:", matchCtx.Qualifiers.String())
	}

	fmt.Printf("\n%-20s %d\n", "Affected Cmps:", len(affectedComponents))
	fmt.Printf("%-20s %d\n", "Total CVEs:", len(cveMap))

	if len(cveMap) > 0 {
		fmt.Println(strings.Repeat("-", 80))
		fmt.Println("MATCHED CVEs")
		fmt.Println(strings.Repeat("-", 80))

		for _, cve := range cveMap {
			fmt.Printf("\n[%s] CVSS: %.1f\n", cve.CVE, cve.CVSS)

			desc := cve.Description
			if len(desc) > 200 {
				desc = desc[:200] + "..."
			}
			fmt.Printf("  Description: %s\n", desc)

			if cve.EPSS != nil {
				fmt.Printf("  EPSS: %.4f", *cve.EPSS)
				if cve.Percentile != nil {
					fmt.Printf(" (Percentile: %.2f%%)", *cve.Percentile*100)
				}
				fmt.Println()
			}

			if len(cve.Weaknesses) > 0 {
				cwes := []string{}
				for _, w := range cve.Weaknesses {
					cwes = append(cwes, w.CWEID)
				}
				fmt.Printf("  CWEs: %s\n", strings.Join(cwes, ", "))
			}

			if len(cve.Exploits) > 0 {
				fmt.Printf("  Exploits: %d known\n", len(cve.Exploits))
				for _, e := range cve.Exploits {
					verified := ""
					if e.Verified {
						verified = " [VERIFIED]"
					}
					fmt.Printf("    - %s%s\n", e.ID, verified)
				}
			}

			if len(cve.Relationships) > 0 {
				fmt.Printf("  Relationships:\n")
				for _, r := range cve.Relationships {
					fmt.Printf("    - %s (%s)\n", r.TargetCVE, r.RelationshipType)
				}
			}
		}
	}

	if len(affectedComponents) > 0 {
		fmt.Println(strings.Repeat("-", 80))
		fmt.Println("AFFECTED COMPONENTS (matching rules)")
		fmt.Println(strings.Repeat("-", 80))

		for i, ac := range affectedComponents {
			fmt.Printf("\n[%d] %s (source: %s)\n", i+1, ac.PurlWithoutVersion, ac.Source)

			if ac.Version != nil {
				fmt.Printf("    Exact version: %s\n", *ac.Version)
			}
			if ac.SemverIntroduced != nil || ac.SemverFixed != nil {
				intro := "<any>"
				if ac.SemverIntroduced != nil {
					intro = *ac.SemverIntroduced
				}
				fixed := "<unfixed>"
				if ac.SemverFixed != nil {
					fixed = *ac.SemverFixed
				}
				fmt.Printf("    Semver range: [%s, %s)\n", intro, fixed)
			}
			if ac.VersionIntroduced != nil || ac.VersionFixed != nil {
				intro := "<any>"
				if ac.VersionIntroduced != nil {
					intro = *ac.VersionIntroduced
				}
				fixed := "<unfixed>"
				if ac.VersionFixed != nil {
					fixed = *ac.VersionFixed
				}
				fmt.Printf("    Version range: [%s, %s)\n", intro, fixed)
			}

			cveIDs := []string{}
			for _, cve := range ac.CVE {
				cveIDs = append(cveIDs, cve.CVE)
			}
			fmt.Printf("    CVEs: %s\n", strings.Join(cveIDs, ", "))
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))

	return nil
}

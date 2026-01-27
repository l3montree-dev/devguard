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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// NewPURLInspectCommand creates the inspect command for PURL inspection
func NewPURLInspectCommand() *cobra.Command {
	inspectCmd := &cobra.Command{
		Use:   "inspect <purl>",
		Short: "Inspect PURL for matching CVEs and vulnerabilities",
		Long: `Inspects a Package URL (PURL) against the vulnerability database and displays
detailed information about matching CVEs, affected components, and relationships.

Shows both raw matches and deduplicated results (after alias resolution).

Examples:
  devguard-cli vulndb inspect "pkg:npm/lodash@4.17.20"
  devguard-cli vulndb inspect "pkg:deb/debian/libc6@2.31-1"
  devguard-cli vulndb inspect "pkg:pypi/requests@2.25.0"`,
		Args: cobra.ExactArgs(1),
		RunE: purlInspectCmd,
	}

	inspectCmd.Flags().Int("timeout", 300, "Set the timeout for scanner operations in seconds")
	inspectCmd.Flags().String("apiUrl", "https://api.devguard.org", "The url of the API to send the request to")
	inspectCmd.Flags().String("outputPath", "", "Path to save the inspection result as JSON file (optional)")

	return inspectCmd
}

func purlInspectCmd(cmd *cobra.Command, args []string) error {
	purlString := args[0]

	timeout := time.Duration(config.RuntimeBaseConfig.Timeout) * time.Second
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	url := fmt.Sprintf("%s/api/v1/vulndb/purl-inspect/%s", config.RuntimeBaseConfig.APIURL, purlString)
	fmt.Println("Inspecting PURL via API:", url)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)

	if err != nil {
		return errors.Wrap(err, "could not create request")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "could not perform request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("API returned status code %d", resp.StatusCode)
	}

	var result struct {
		PURL               packageurl.PackageURL       `json:"purl"`
		MatchContext       *normalize.PurlMatchContext `json:"match_context"`
		AffectedComponents []models.AffectedComponent  `json:"affected_components"`
		Vulns              []models.VulnInPackage      `json:"vulns"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return errors.Wrap(err, "could not decode response")
	}

	r := outputInspectResult(purlString, result.PURL, result.MatchContext, result.AffectedComponents, result.Vulns)
	if config.RuntimeBaseConfig.OutputPath != "" {
		outputData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return errors.Wrap(err, "could not marshal output data")
		}
		err = os.WriteFile(config.RuntimeBaseConfig.OutputPath, outputData, 0644)
		if err != nil {
			return errors.Wrap(err, "could not write output file")
		}
		fmt.Println("Inspection result saved to:", config.RuntimeBaseConfig.OutputPath)
	}
	return r
}

func outputInspectResult(inputPurl string, purl packageurl.PackageURL, matchCtx *normalize.PurlMatchContext, affectedComponents []models.AffectedComponent, vulns []models.VulnInPackage) error {
	// Collect unique CVEs from raw affected components
	rawCVEMap := make(map[string]models.CVE)
	for _, ac := range affectedComponents {
		for _, cve := range ac.CVE {
			rawCVEMap[cve.CVE] = cve
		}
	}

	// Collect deduplicated CVEs
	dedupCVEMap := make(map[string]models.VulnInPackage)
	for _, v := range vulns {
		dedupCVEMap[v.CVEID] = v
	}

	// Find which CVEs were removed by deduplication
	removedByAlias := []string{}
	for cveID := range rawCVEMap {
		if _, exists := dedupCVEMap[cveID]; !exists {
			removedByAlias = append(removedByAlias, cveID)
		}
	}

	// Summary table
	fmt.Println(text.FgHiCyan.Sprint("\nPURL INSPECTION RESULT"))
	fmt.Println(strings.Repeat("─", 60))

	summaryTable := table.NewWriter()
	summaryTable.SetStyle(table.StyleLight)
	summaryTable.AppendRows([]table.Row{
		{"Input PURL", inputPurl},
		{"Search PURL", matchCtx.SearchPurl},
		{"Version", matchCtx.NormalizedVersion},
		{"Version Type", matchCtx.HowToInterpretVersionString},
		{"PURL Type", purl.Type},
	})
	if purl.Namespace != "" {
		summaryTable.AppendRow(table.Row{"Namespace", purl.Namespace})
	}
	if matchCtx.Qualifiers.String() != "" {
		summaryTable.AppendRow(table.Row{"Qualifiers", matchCtx.Qualifiers.String()})
	}
	summaryTable.AppendSeparator()
	summaryTable.AppendRows([]table.Row{
		{"Affected Components", len(affectedComponents)},
		{"Raw CVEs", len(rawCVEMap)},
		{"After Deduplication", text.FgHiGreen.Sprintf("%d", len(dedupCVEMap))},
	})
	fmt.Println(summaryTable.Render())

	// Show deduplication details
	if len(removedByAlias) > 0 {
		fmt.Println(text.FgHiYellow.Sprint("\nALIAS DEDUPLICATION"))
		fmt.Println(strings.Repeat("─", 60))
		fmt.Printf("%d CVE(s) removed as duplicates:\n", len(removedByAlias))

		dedupTable := table.NewWriter()
		dedupTable.SetStyle(table.StyleLight)
		dedupTable.AppendHeader(table.Row{"Removed CVE", "Alias Of"})

		for _, removedCVE := range removedByAlias {
			if cve, exists := rawCVEMap[removedCVE]; exists {
				aliasOf := findAliasOf(cve, dedupCVEMap, removedCVE)
				if aliasOf != "" {
					dedupTable.AppendRow(table.Row{text.FgRed.Sprint(removedCVE), text.FgGreen.Sprint(aliasOf)})
				} else {
					dedupTable.AppendRow(table.Row{text.FgRed.Sprint(removedCVE), "-"})
				}
			}
		}
		fmt.Println(dedupTable.Render())
	}

	// CVE table
	if len(rawCVEMap) > 0 {
		fmt.Println(text.FgHiCyan.Sprint("\nMATCHED CVEs"))
		fmt.Println(strings.Repeat("─", 60))

		cveTable := table.NewWriter()
		cveTable.SetStyle(table.StyleLight)
		cveTable.AppendHeader(table.Row{"CVE", "CVSS", "EPSS", "CWEs", "Exploits", "Status"})

		for _, cve := range rawCVEMap {
			status := text.FgGreen.Sprint("KEPT")
			if _, exists := dedupCVEMap[cve.CVE]; !exists {
				status = text.FgRed.Sprint("REMOVED")
			}

			epssStr := "-"
			if cve.EPSS != nil {
				epssStr = fmt.Sprintf("%.4f", *cve.EPSS)
			}

			cwes := []string{}
			for _, w := range cve.Weaknesses {
				cwes = append(cwes, w.CWEID)
			}
			cweStr := "-"
			if len(cwes) > 0 {
				cweStr = strings.Join(cwes, ", ")
			}

			exploitStr := "-"
			if len(cve.Exploits) > 0 {
				exploitStr = fmt.Sprintf("%d", len(cve.Exploits))
			}

			cvssColor := text.FgGreen
			if cve.CVSS >= 7.0 {
				cvssColor = text.FgRed
			} else if cve.CVSS >= 4.0 {
				cvssColor = text.FgYellow
			}

			cveTable.AppendRow(table.Row{
				cve.CVE,
				cvssColor.Sprintf("%.1f", cve.CVSS),
				epssStr,
				cweStr,
				exploitStr,
				status,
			})
		}
		fmt.Println(cveTable.Render())

		// Detailed CVE info
		fmt.Println(text.FgHiCyan.Sprint("\nCVE DETAILS"))
		fmt.Println(strings.Repeat("─", 60))
		for _, cve := range rawCVEMap {
			statusMark := text.FgGreen.Sprint("●")
			if _, exists := dedupCVEMap[cve.CVE]; !exists {
				statusMark = text.FgRed.Sprint("○")
			}
			fmt.Printf("%s %s (CVSS: %.1f)\n", statusMark, text.Bold.Sprint(cve.CVE), cve.CVSS)

			desc := cve.Description
			if len(desc) > 120 {
				desc = desc[:120] + "..."
			}
			fmt.Printf("   %s\n", text.FgHiBlack.Sprint(desc))

			if len(cve.Relationships) > 0 {
				rels := []string{}
				for _, r := range cve.Relationships {
					rels = append(rels, fmt.Sprintf("%s→%s", r.RelationshipType, r.TargetCVE))
				}
				fmt.Printf("   Relationships: %s\n", strings.Join(rels, ", "))
			}
			fmt.Println()
		}
	}

	// Affected components table
	if len(affectedComponents) > 0 {
		fmt.Println(text.FgHiCyan.Sprint("\nAFFECTED COMPONENTS"))
		fmt.Println(strings.Repeat("─", 60))

		acTable := table.NewWriter()
		acTable.SetStyle(table.StyleLight)
		acTable.AppendHeader(table.Row{"#", "PURL", "Source", "Version Range", "CVEs"})

		for i, ac := range affectedComponents {
			versionRange := "-"
			if ac.Version != nil {
				versionRange = fmt.Sprintf("=%s", *ac.Version)
			} else if ac.SemverIntroduced != nil || ac.SemverFixed != nil {
				intro := "0"
				if ac.SemverIntroduced != nil {
					intro = *ac.SemverIntroduced
				}
				fixed := "∞"
				if ac.SemverFixed != nil {
					fixed = *ac.SemverFixed
				}
				versionRange = fmt.Sprintf("[%s, %s)", intro, fixed)
			} else if ac.VersionIntroduced != nil || ac.VersionFixed != nil {
				intro := "0"
				if ac.VersionIntroduced != nil {
					intro = *ac.VersionIntroduced
				}
				fixed := "∞"
				if ac.VersionFixed != nil {
					fixed = *ac.VersionFixed
				}
				versionRange = fmt.Sprintf("[%s, %s)", intro, fixed)
			}

			cveIDs := []string{}
			for _, cve := range ac.CVE {
				cveIDs = append(cveIDs, cve.CVE)
			}

			acTable.AppendRow(table.Row{
				i + 1,
				ac.PurlWithoutVersion,
				ac.Source,
				versionRange,
				strings.Join(cveIDs, ", "),
			})
		}
		fmt.Println(acTable.Render())
	}

	fmt.Println()
	return nil
}

// findAliasOf finds which kept CVE the removed CVE is an alias of
func findAliasOf(cve models.CVE, dedupCVEMap map[string]models.VulnInPackage, removedCVE string) string {
	// Check if removed CVE points to a kept CVE
	for _, rel := range cve.Relationships {
		if rel.RelationshipType == "alias" {
			if _, kept := dedupCVEMap[rel.TargetCVE]; kept {
				return rel.TargetCVE
			}
		}
	}
	// Check if a kept CVE points to the removed CVE
	for keptCVE, keptVuln := range dedupCVEMap {
		for _, rel := range keptVuln.CVE.Relationships {
			if rel.RelationshipType == "alias" && rel.TargetCVE == removedCVE {
				return keptCVE
			}
		}
	}
	return ""
}

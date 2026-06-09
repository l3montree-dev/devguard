// Copyright (C) 2025 l3montree GmbH
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

package scanner

import (
	"fmt"
	"log/slog"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gosimple/slug"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/package-url/packageurl-go"
)

// Set to gitlab output size limit
var rowLengthLimit = 80

func PrintSarifResults(report sarif.SarifSchema210Json, scannerID, assetName, webUI, assetVersionName string) error {
	tw := table.NewWriter()
	tw.SetAllowedRowLength(rowLengthLimit)

	openCount := 0
	for _, run := range report.Runs {
		for _, result := range run.Results {
			suppressed := len(result.Suppressions) > 0
			if suppressed {
				continue
			}
			openCount++

			ruleID := ""
			if result.RuleID != nil {
				ruleID = *result.RuleID
			}

			uri := ""
			snippet := ""
			if len(result.Locations) > 0 {
				loc := result.Locations[0]
				if loc.PhysicalLocation.ArtifactLocation.URI != nil {
					uri = *loc.PhysicalLocation.ArtifactLocation.URI
				}
				if loc.PhysicalLocation.Region != nil && loc.PhysicalLocation.Region.Snippet != nil && loc.PhysicalLocation.Region.Snippet.Text != nil {
					snippet = *loc.PhysicalLocation.Region.Snippet.Text
				}
			}

			if scannerID == "secret-scanning" {
				tw.AppendRows([]table.Row{
					{"RuleID:", ruleID},
					{"File:", text.FgGreen.Sprint(uri)},
				})
				if snippet != "" {
					tw.AppendRow(table.Row{"Snippet", snippet})
				}
				tw.AppendRow(table.Row{"Message:", text.WrapText(result.Message.Text, rowLengthLimit)})
			} else {
				tw.AppendRow(table.Row{"RuleID", ruleID})
				if snippet != "" {
					tw.AppendRow(table.Row{"Snippet", snippet})
				}
				tw.AppendRow(table.Row{"Message", text.WrapText(result.Message.Text, rowLengthLimit)})
				if uri != "" {
					tw.AppendRow(table.Row{"File", text.FgGreen.Sprint(uri)})
				}
			}
			tw.AppendSeparator()
		}
	}

	if tw.Length() == 0 {
		slog.Info("No open vulnerabilities found")
		return nil
	}

	fmt.Println(tw.Render())

	if assetName != "" {
		link := text.FgBlue.Sprint(fmt.Sprintf("%s/%s/refs/%s/code-risks/", webUI, assetName, slug.Make(assetVersionName)))
		fmt.Printf("See all code risks at:\n%s\n", link)
	}

	if openCount > 0 {
		return fmt.Errorf("found %d unhandled vulnerabilities", openCount)
	}
	return nil
}


// PrintCycloneDXVexResults prints a table from a CycloneDX BOM VEX response.
// Columns match PrintScaResults but without the Path column.
func PrintCycloneDXVexResults(bom cdx.BOM, failOnRisk, failOnCVSS, assetName, webUI string) error {
	vulns := bom.Vulnerabilities
	if vulns == nil || len(*vulns) == 0 {
		slog.Info("No vulnerabilities found")
		return nil
	}

	// build bom-ref -> component index
	compByRef := map[string]cdx.Component{}
	if bom.Components != nil {
		for _, c := range *bom.Components {
			compByRef[c.BOMRef] = c
		}
	}

	tw := table.NewWriter()
	tw.AppendHeader(table.Row{"Library", "Vulnerability", "Risk", "CVSS", "Installed", "Fixed", "Status"})
	tw.SetColumnConfigs([]table.ColumnConfig{{Number: 1, AutoMerge: true}})

	isScanThresholdExceeded := false

	for _, v := range *vulns {
		state := "open"
		if v.Analysis != nil && v.Analysis.State != "" {
			state = string(v.Analysis.State)
		}

		risk := 0.0
		cvss := 0.0
		if v.Ratings != nil {
			for _, r := range *v.Ratings {
				if r.Score != nil {
					if r.Method == cdx.ScoringMethodCVSSv3 || r.Method == cdx.ScoringMethodCVSSv31 {
						cvss = *r.Score
					}
					if *r.Score > risk {
						risk = *r.Score
					}
				}
			}
		}

		if failOnRisk != "" && state == "open" &&
			((failOnRisk == "low" && risk > 0.1) ||
				(failOnRisk == "medium" && risk >= 4) ||
				(failOnRisk == "high" && risk >= 7) ||
				(failOnRisk == "critical" && risk >= 9)) {
			isScanThresholdExceeded = true
		}
		if failOnCVSS != "" && state == "open" &&
			((failOnCVSS == "low" && cvss > 0.1) ||
				(failOnCVSS == "medium" && cvss >= 4) ||
				(failOnCVSS == "high" && cvss >= 7) ||
				(failOnCVSS == "critical" && cvss >= 9)) {
			isScanThresholdExceeded = true
		}

		purl := ""
		installedVersion := ""
		if v.Affects != nil && len(*v.Affects) > 0 {
			ref := (*v.Affects)[0].Ref
			if comp, ok := compByRef[ref]; ok {
				purl = comp.PackageURL
				installedVersion = comp.Version
			}
		}
		libraryName := purl
		if p, err := packageurl.FromString(purl); err == nil {
			libraryName = p.Name
			if installedVersion == "" {
				installedVersion = strings.TrimPrefix(p.Version, "v")
			}
		}

		fixedVersion := ""
		if v.Recommendation != "" {
			fixedVersion = v.Recommendation
		}

		tw.AppendRow(table.Row{libraryName, v.ID, fmt.Sprintf("%.2f", risk), fmt.Sprintf("%.1f", cvss), installedVersion, fixedVersion, state})
	}

	fmt.Println(tw.Render())

	if isScanThresholdExceeded {
		return fmt.Errorf("scan threshold exceeded")
	}
	return nil
}

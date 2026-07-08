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
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gosimple/slug"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/normalize"
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
		assetSlugPath, err := normalize.AssetSlugPath(assetName)
		if err != nil {
			slog.Debug("could not build asset slug path for link", "err", err)
		} else {
			link := text.FgBlue.Sprint(fmt.Sprintf("%s/%s/refs/%s/code-risks/", webUI, assetSlugPath, slug.Make(assetVersionName)))
			fmt.Printf("See all code risks at:\n%s\n", link)
		}
	}

	if openCount > 0 {
		fmt.Printf("Found %d unhandled vulnerabilities\n", openCount)

		return fmt.Errorf("found %d unhandled vulnerabilities", openCount)
	}
	return nil
}

// PrintCycloneDXVexResults prints a table from a CycloneDX BOM VEX response.
// Columns match PrintScaResults but without the Path column.
func PrintCycloneDXVexResults(bom cdx.BOM, failOnRisk, failOnCVSS, assetName, webUI, ref string) error {
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

	sortedVulns := *vulns
	sort.Slice(sortedVulns, func(i, j int) bool {
		refI, refJ := "", ""
		if sortedVulns[i].Affects != nil && len(*sortedVulns[i].Affects) > 0 {
			refI = (*sortedVulns[i].Affects)[0].Ref
		}
		if sortedVulns[j].Affects != nil && len(*sortedVulns[j].Affects) > 0 {
			refJ = (*sortedVulns[j].Affects)[0].Ref
		}
		return refI < refJ
	})

	thresholdViolations := 0
	prevLibrary := ""

	for _, v := range sortedVulns {
		state := "in_triage"
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

		exceedsThreshold := false
		if failOnRisk != "" && state == "in_triage" &&
			((failOnRisk == "low" && risk > 0.1) ||
				(failOnRisk == "medium" && risk >= 4) ||
				(failOnRisk == "high" && risk >= 7) ||
				(failOnRisk == "critical" && risk >= 9)) {
			exceedsThreshold = true
		}
		if failOnCVSS != "" && state == "in_triage" &&
			((failOnCVSS == "low" && cvss > 0.1) ||
				(failOnCVSS == "medium" && cvss >= 4) ||
				(failOnCVSS == "high" && cvss >= 7) ||
				(failOnCVSS == "critical" && cvss >= 9)) {
			exceedsThreshold = true
		}
		if exceedsThreshold {
			thresholdViolations++
		}

		purl := ""
		installedVersion := ""
		fixedVersion := ""
		if v.Affects != nil && len(*v.Affects) > 0 {
			affectedLib := (*v.Affects)[0]
			if comp, ok := compByRef[affectedLib.Ref]; ok {
				purl = comp.PackageURL
				installedVersion = comp.Version
			}
			// check if fixed versions are specified for the library
			if affectedLib.Range != nil {
				for _, r := range *affectedLib.Range {
					if r.Status == cdx.VulnerabilityStatusNotAffected {
						fixedVersion = r.Version
						break
					}
				}
			}
		}
		libraryName := purl
		if p, err := packageurl.FromString(purl); err == nil {
			if p.Namespace != "" {
				libraryName = p.Namespace + "/" + p.Name
			} else {
				libraryName = p.Name
			}
			if installedVersion == "" {
				installedVersion = strings.TrimPrefix(p.Version, "v")
			}
		}

		if libraryName != prevLibrary && prevLibrary != "" {
			tw.AppendSeparator()
		}
		prevLibrary = libraryName

		colorRow := func(s string) string { return s }
		if exceedsThreshold {
			colorRow = func(s string) string { return text.FgRed.Sprint(s) }
		}

		tw.AppendRow(table.Row{
			colorRow(libraryName),
			colorRow(v.ID),
			colorRow(fmt.Sprintf("%.2f", risk)),
			colorRow(fmt.Sprintf("%.1f", cvss)),
			colorRow(installedVersion),
			colorRow(fixedVersion),
			colorRow(state),
		})
	}

	fmt.Println(tw.Render())

	if assetName != "" && ref != "" {
		assetSlugPath, err := normalize.AssetSlugPath(assetName)
		if err != nil {
			slog.Debug("could not build asset slug path for link", "err", err)
		} else {
			link := text.FgBlue.Sprint(fmt.Sprintf("%s/%s/refs/%s/dependency-risks/", webUI, assetSlugPath, slug.Make(ref)))
			fmt.Printf("See all dependency risks at:\n%s\n", link)
		}
	}

	if thresholdViolations > 0 {
		return fmt.Errorf("%d open vulnerabilities exceed the configured risk threshold", thresholdViolations)
	}
	return nil
}

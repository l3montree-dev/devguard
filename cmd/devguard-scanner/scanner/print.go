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
	"slices"
	"strings"

	"github.com/gosimple/slug"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
)

// Set to gitlab output size limit
var rowLengthLimit = 80

func PrintFirstPartyScanResults(scanResponse dtos.FirstPartyScanResponse, assetName string, webUI string, assetVersionName string, scannerID string) error {

	if len(scanResponse.FirstPartyVulns) == 0 {
		return nil
	}

	// get all "open" vulns
	openVulns := utils.Filter(scanResponse.FirstPartyVulns, func(v dtos.FirstPartyVulnDTO) bool {
		return v.State == dtos.VulnStateOpen
	})

	tw := table.NewWriter()
	tw.SetAllowedRowLength(rowLengthLimit)

	switch scannerID {
	case "secret-scanning":
		PrintSecretScanResults(openVulns, webUI, assetName, assetVersionName, tw)
	default:
		PrintSastScanResults(openVulns, webUI, assetName, assetVersionName, tw)
	}

	link := text.FgBlue.Sprint(fmt.Sprintf("%s/%s/refs/%s/code-risks/", webUI, assetName, slug.Make(assetVersionName)))
	wrappedLink := text.WrapText(link, rowLengthLimit)
	tw.AppendRow(table.Row{"Link", wrappedLink})

	fmt.Println(tw.Render())

	if len(openVulns) > 0 {
		return fmt.Errorf("found %d unhandled vulnerabilities", len(openVulns))
	}

	return nil
}

func PrintSecretScanResults(firstPartyVulns []dtos.FirstPartyVulnDTO, webUI string, assetName string, assetVersionName string, tw table.Writer) {
	for _, vuln := range firstPartyVulns {
		raw := []table.Row{
			{"RuleID:", vuln.RuleID},
			{"File:", text.FgGreen.Sprint(vuln.URI)},
		}
		tw.AppendRows(raw)
		for _, snippet := range vuln.SnippetContents {
			tw.AppendRow(table.Row{"Snippet", snippet.Snippet})
		}
		raw = []table.Row{{"Message:", text.WrapText(*vuln.Message, rowLengthLimit)},

			{"Commit:", vuln.Commit},
			{"Author:", vuln.Author},
			{"Email:", vuln.Email},
			{"Date:", vuln.Date}}

		tw.AppendRows(raw)
		tw.AppendSeparator()
	}
}

func PrintSastScanResults(firstPartyVulns []dtos.FirstPartyVulnDTO, webUI, assetName string, assetVersionName string, tw table.Writer) {

	for _, vuln := range firstPartyVulns {
		tw.AppendRow(table.Row{"RuleID", vuln.RuleID})
		for _, snippet := range vuln.SnippetContents {
			tw.AppendRow(table.Row{"Snippet", snippet.Snippet})
		}
		tw.AppendRow(table.Row{"Message", text.WrapText(*vuln.Message, rowLengthLimit)})
		if vuln.URI != "" {
			tw.AppendRow(table.Row{"File", text.FgGreen.Sprint(vuln.URI)})

		}
		tw.AppendSeparator()
	}

}

// can be reused for container scanning as well.
func PrintScaResults(scanResponse dtos.ScanResponse, failOnRisk, failOnCVSS, assetName, webUI string) error {
	slog.Info("Scan completed successfully", "dependencyVulnAmount", len(scanResponse.DependencyVulns), "openedByThisScan", scanResponse.AmountOpened, "closedByThisScan", scanResponse.AmountClosed)

	if len(scanResponse.DependencyVulns) == 0 {
		return nil
	}

	// order the vulns by their risk
	slices.SortFunc(scanResponse.DependencyVulns, func(a, b dtos.DependencyVulnDTO) int {
		return int(utils.OrDefault(a.RawRiskAssessment, 0)*100) - int(utils.OrDefault(b.RawRiskAssessment, 0)*100)
	})

	// get the max risk of open!!! dependencyVulns
	openRisks := utils.Map(utils.Filter(scanResponse.DependencyVulns, func(f dtos.DependencyVulnDTO) bool {
		return f.State == "open"
	}), func(f dtos.DependencyVulnDTO) float64 {
		return utils.OrDefault(f.RawRiskAssessment, 0)
	})

	openCVSS := utils.Map(utils.Filter(scanResponse.DependencyVulns, func(f dtos.DependencyVulnDTO) bool {
		return f.State == "open" && f.CVE != nil
	}), func(f dtos.DependencyVulnDTO) float32 {
		return f.CVE.CVSS
	})

	maxRisk := 0.
	for _, risk := range openRisks {
		if risk > maxRisk {
			maxRisk = risk
		}
	}

	var maxCVSS float32
	for _, v := range openCVSS {
		if v > maxCVSS {
			maxCVSS = v
		}
	}

	tw := table.NewWriter()
	//tw.SetAllowedRowLength(155)
	tw.AppendHeader(table.Row{"Library", "Vulnerability", "Risk", "CVSS", "Installed", "Fixed", "Status"})
	tw.AppendRows(utils.Map(
		scanResponse.DependencyVulns,
		func(v dtos.DependencyVulnDTO) table.Row {
			// extract package name and version from purl
			// purl format: pkg:package-type/namespace/name@version?qualifiers#subpath
			pURL, err := packageurl.FromString(*v.ComponentPurl)
			if err != nil {
				slog.Error("could not parse purl", "err", err)
			}

			return dependencyVulnToTableRow(pURL, v)
		},
	))

	fmt.Println(tw.Render())
	if len(scanResponse.DependencyVulns) > 0 {
		clickableLink := fmt.Sprintf("%s/%s/refs/%s/dependency-risks/", webUI, assetName, slug.Make(scanResponse.DependencyVulns[0].AssetVersionName))
		fmt.Printf("See all dependency risks at:\n%s\n", clickableLink)
	}

	switch failOnRisk {
	case "low":
		if maxRisk > 0.1 {
			return fmt.Errorf("max risk exceeds threshold %.2f", maxRisk)
		}
	case "medium":
		if maxRisk >= 4 {
			return fmt.Errorf("max risk exceeds threshold %.2f", maxRisk)
		}

	case "high":
		if maxRisk >= 7 {
			return fmt.Errorf("max risk exceeds threshold %.2f", maxRisk)
		}

	case "critical":
		if maxRisk >= 9 {
			return fmt.Errorf("max risk exceeds threshold %.2f", maxRisk)
		}
	}

	switch failOnCVSS {
	case "low":
		if maxCVSS > 0.1 {
			return fmt.Errorf("max CVSS exceeds threshold %.2f", maxCVSS)
		}
	case "medium":
		if maxCVSS >= 4 {
			return fmt.Errorf("max CVSS exceeds threshold %.2f", maxCVSS)
		}
	case "high":
		if maxCVSS >= 7 {
			return fmt.Errorf("max CVSS exceeds threshold %.2f", maxCVSS)
		}
	case "critical":
		if maxCVSS >= 9 {
			return fmt.Errorf("max CVSS exceeds threshold %.2f", maxCVSS)
		}
	}

	return nil
}

// Function to dynamically change the format of the table row depending on the input parameters
func dependencyVulnToTableRow(pURL packageurl.PackageURL, v dtos.DependencyVulnDTO) table.Row {
	var cvss float32 = 0.0
	if v.CVE != nil {
		cvss = v.CVE.CVSS
	}

	if pURL.Namespace == "" { //Remove the second slash if the second parameter is empty to avoid double slashes
		return table.Row{fmt.Sprintf("pkg:%s/%s", pURL.Type, pURL.Name), utils.SafeDereference(v.CVEID), utils.OrDefault(v.RawRiskAssessment, 0), cvss, strings.TrimPrefix(pURL.Version, "v"), utils.SafeDereference(v.ComponentFixedVersion), v.State}
	} else {
		return table.Row{fmt.Sprintf("pkg:%s/%s/%s", pURL.Type, pURL.Namespace, pURL.Name), utils.SafeDereference(v.CVEID), utils.OrDefault(v.RawRiskAssessment, 0), cvss, strings.TrimPrefix(pURL.Version, "v"), utils.SafeDereference(v.ComponentFixedVersion), v.State}
	}
}

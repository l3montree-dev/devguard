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
	// group the dependencyVulns by their purl
	dependencyVulnsByPurl := map[string][]dtos.DependencyVulnDTO{}
	for _, v := range scanResponse.DependencyVulns {
		purlKey := strings.TrimSpace(v.ComponentPurl)
		if purlKey == "" {
			slog.Warn("Dependency vulnerability has empty ComponentPurl; skipping grouping", "cveID", v.CVEID, "state", v.State)

		}
		if _, ok := dependencyVulnsByPurl[purlKey]; !ok {
			dependencyVulnsByPurl[purlKey] = []dtos.DependencyVulnDTO{}
		}
		dependencyVulnsByPurl[purlKey] = append(dependencyVulnsByPurl[purlKey], v)
	}

	// delete the duplicates in each group
	for purl, vulns := range dependencyVulnsByPurl {
		uniqueVulns := map[string]dtos.DependencyVulnDTO{}
		for _, v := range vulns {
			uniqueVulns[fmt.Sprintf("%s:%.2f:%s", v.CVEID, v.CVE.CVSS, v.State)] = v
		}
		dependencyVulnsByPurl[purl] = utils.Values(uniqueVulns)
	}

	isScanThresholdExceeded := false

	tw := table.NewWriter()
	//tw.SetAllowedRowLength(155)
	tw.AppendHeader(table.Row{"Library", "Vulnerability", "Risk", "CVSS", "Installed", "Fixed", "Status"})
	for _, v := range dependencyVulnsByPurl {
		//order the vulnerabilities in each group by their risk
		slices.SortFunc(v, func(a, b dtos.DependencyVulnDTO) int {
			return int(utils.OrDefault(a.RawRiskAssessment, 0)*100) - int(utils.OrDefault(b.RawRiskAssessment, 0)*100)
		})

		//First check which vulnerability in this group has failed
		groupHasFailed := false
		vulnFailed := map[string]bool{}

		for _, vuln := range v {
			if vuln.State != dtos.VulnStateOpen {
				continue
			}
			risk := utils.OrDefault(vuln.RawRiskAssessment, 0)
			cvss := vuln.CVE.CVSS
			if (failOnRisk != "" && ((failOnRisk == "low" && risk > 0.1) ||
				(failOnRisk == "medium" && risk >= 4) ||
				(failOnRisk == "high" && risk >= 7) ||
				(failOnRisk == "critical" && risk >= 9))) ||
				(failOnCVSS != "" && ((failOnCVSS == "low" && cvss > 0.1) ||
					(failOnCVSS == "medium" && cvss >= 4) ||
					(failOnCVSS == "high" && cvss >= 7) ||
					(failOnCVSS == "critical" && cvss >= 9))) {
				groupHasFailed = true
				vulnFailed[vuln.CVEID] = true

				isScanThresholdExceeded = true
			}
		}

		for i, vuln := range v {
			// extract package name and version from purl
			// purl format: pkg:package-type/namespace/name@version?qualifiers#subpath
			pURL, err := packageurl.FromString(vuln.ComponentPurl)
			if err != nil {
				slog.Warn("could not parse purl, using fallback representation", "err", err, "purl", vuln.ComponentPurl)
				// Fall back to a minimal PackageURL so the vulnerability is still shown
				pURL = packageurl.PackageURL{
					Name: vuln.ComponentPurl,
				}
			}

			// Show purl only for the first vulnerability in the group
			// Color purl red if any vulnerability in the group has failed
			showPurl := i == 0
			tw.AppendRow(dependencyVulnToTableRow(pURL, vuln, showPurl, vulnFailed[vuln.CVEID], groupHasFailed))
		}
		tw.AppendSeparator()
	}
	fmt.Println(tw.Render())

	if len(scanResponse.DependencyVulns) > 0 {
		clickableLink := fmt.Sprintf("%s/%s/refs/%s/dependency-risks/", webUI, assetName, slug.Make(scanResponse.DependencyVulns[0].AssetVersionName))
		fmt.Printf("Showing deduplicated vulnerabilities grouped by package.\nSee all dependency risks at:\n%s\n", clickableLink)
	}

	riskThreshold := ""
	switch failOnRisk {
	case "low":
		riskThreshold = "> 0.1"
	case "medium":
		riskThreshold = ">= 4"
	case "high":
		riskThreshold = ">= 7"
	case "critical":
		riskThreshold = ">= 9"
	}

	cvssThreshold := ""
	switch failOnCVSS {
	case "low":
		cvssThreshold = "> 0.1"
	case "medium":
		cvssThreshold = ">= 4"
	case "high":
		cvssThreshold = ">= 7"
	case "critical":
		cvssThreshold = ">= 9"
	}

	if isScanThresholdExceeded {
		return fmt.Errorf("one or more dependency vulnerabilities exceeded the defined threshold (risk: %s, cvss: %s)", riskThreshold, cvssThreshold)
	}

	return nil
}

func dependencyVulnToTableRow(pURL packageurl.PackageURL, v dtos.DependencyVulnDTO, showPurl bool, failed bool, groupHasFailed bool) table.Row {
	cvss := v.CVE.CVSS

	var libraryName string
	if showPurl {
		if pURL.Namespace == "" { //Remove the second slash if the second parameter is empty to avoid double slashes
			libraryName = fmt.Sprintf("pkg:%s/%s", pURL.Type, pURL.Name)
		} else {
			libraryName = fmt.Sprintf("pkg:%s/%s/%s", pURL.Type, pURL.Namespace, pURL.Name)
		}
		// Color purl red if any vulnerability in the group has failed
		if groupHasFailed {
			libraryName = text.FgRed.Sprint(libraryName)
		}
	} else {
		libraryName = ""
	}

	if failed {
		return table.Row{
			libraryName,
			text.FgRed.Sprint(v.CVEID),
			text.FgRed.Sprintf("%.2f", utils.OrDefault(v.RawRiskAssessment, 0)),
			text.FgRed.Sprintf("%.1f", cvss),
			text.FgRed.Sprint(strings.TrimPrefix(pURL.Version, "v")),
			text.FgRed.Sprint(utils.SafeDereference(v.ComponentFixedVersion)),
			text.FgRed.Sprint(v.State),
		}
	}

	return table.Row{libraryName, v.CVEID, utils.OrDefault(v.RawRiskAssessment, 0), cvss, strings.TrimPrefix(pURL.Version, "v"), utils.SafeDereference(v.ComponentFixedVersion), v.State}
}

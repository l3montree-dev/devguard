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

package transformer

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
)

// CycloneDXVEXToRules converts the vulnerabilities of a CycloneDX VEX BOM into VEX rules.
//
// CycloneDX is component-level: Affects[].Ref only carries the vulnerable component PURL,
// so unless the BOM carries an explicit devguard:pathPattern property (which DevGuard adds
// for vulns it has already matched to a rule), the reconstructed path pattern is a
// component-level wildcard that matches every path reaching that component.
func CycloneDXVEXToRules(bom *cdx.BOM, assetID uuid.UUID, assetVersionName string, source string) ([]models.VEXRule, error) {
	// we are only interested in the vulnerabilities
	// for creating vex rules we need to find the starting path to the components
	// we ONLY USE METADATA COMPONENT FOR THAT
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		slog.Info("no metadata component found in SBOM, skipping VEX rule creation")
		return nil, fmt.Errorf("no metadata component found in SBOM")
	}

	// try to parse the root component purl if it exists
	var componentPurl packageurl.PackageURL
	if bom.Metadata.Component.PackageURL == "" {
		return nil, fmt.Errorf("no package URL found in metadata component")
	}

	var err error
	componentPurl, err = packageurl.FromString(bom.Metadata.Component.PackageURL)
	if err != nil {
		slog.Info("failed to parse metadata component PURL, continuing anyway", "purl", bom.Metadata.Component.PackageURL, "error", err)
	}

	refToPurl := make(map[string]packageurl.PackageURL)

	if bom.Components == nil || len(*bom.Components) == 0 {
		return nil, fmt.Errorf("no components inside sbom")
	}
	// Build ref-to-purl mapping from components if they exist
	for _, comp := range *bom.Components {
		if comp.PackageURL == "" {
			continue
		}
		purl, err := packageurl.FromString(comp.PackageURL)
		if err != nil {
			slog.Info("failed to parse component PURL, skipping component for VEX rule creation", "purl", comp.PackageURL, "error", err)
			continue
		}
		refToPurl[comp.BOMRef] = purl
	}

	if bom.Vulnerabilities == nil {
		return nil, fmt.Errorf("no vulns inside sbom")
	}

	rules := make([]models.VEXRule, 0, len(*bom.Vulnerabilities))
	for _, vuln := range *bom.Vulnerabilities {
		cveID := extractCVE(vuln.ID)
		if cveID == "" && vuln.Source != nil && vuln.Source.URL != "" {
			cveID = extractCVE(vuln.Source.URL)
		}
		if cveID == "" {
			continue
		}

		eventType, err := mapCDXToEventType(vuln.Analysis)
		if err != nil {
			slog.Info("unable to map CycloneDX vulnerability analysis to event type, skipping VEX rule creation for this vuln", "cveID", cveID, "error", err)
			continue
		}

		justification := ""
		if vuln.Analysis != nil && vuln.Analysis.Detail != "" {
			justification = vuln.Analysis.Detail
		}

		if vuln.Affects == nil || len(*vuln.Affects) == 0 || (*vuln.Affects)[0].Ref == "" {
			continue
		}
		ref := (*vuln.Affects)[0].Ref

		// try to get the purl from the mapping first
		purl := refToPurl[ref]

		// if not found in mapping, try to parse the ref directly as a PURL
		if purl.String() == "" {
			parsedPurl, err := packageurl.FromString(ref)
			if err != nil {
				slog.Info("no component PURL found for vuln affect Ref and unable to parse as PURL, skipping VEX rule creation for this vuln", "ref", ref, "cveID", cveID, "error", err)
				continue
			}
			purl = parsedPurl
		}

		// now create the path pattern
		var pathPattern []dtos.PathPattern
		// first check if we have a concrete properties object with the path pattern (created by devguard itself, see DependencyVulnsToCycloneDXVEX)
		if vuln.Properties != nil {
			patterns := utils.Filter(*vuln.Properties, func(p cdx.Property) bool {
				return p.Name == "devguard:pathPattern"
			})
			if len(patterns) > 0 {
				for _, p := range patterns {
					var pp dtos.PathPattern
					err := json.Unmarshal([]byte(p.Value), &pp)
					if err != nil {
						slog.Info("failed to unmarshal path pattern from vuln properties, skipping this property", "value", p.Value, "error", err)
						continue
					}
					pathPattern = append(pathPattern, pp)
				}
			}
		}

		// if we already found a path pattern in the properties, we can use it directly. If not, we need to create it based on the purl and component purl
		if len(pathPattern) > 0 {
			// we already have a path pattern, so we can skip creating it from the purl
			// but we still want to create a VEX rule for each path pattern found in the properties
			for _, pp := range pathPattern {
				rule := models.VEXRule{
					AssetID:       assetID,
					VexSource:     source,
					Justification: justification,
					EventType:     eventType,
					CELExpression: pp.ToCELExpression(),
					CreatedByID:   "system", // system user
				}
				rule.SetCELExpression(rule.CELExpression)
				rules = append(rules, rule)
			}
			continue
		}

		purlString, err := normalize.PURLToString(purl)
		if err != nil {
			slog.Info("failed to unescape purl for path pattern, continuing anyway", "purl", purl.String(), "error", err)
			purlString = purl.String()
		}

		var pattern dtos.PathPattern

		if componentPurl.String() != "" {
			componentPurlStr, err := normalize.PURLToString(componentPurl)
			if err != nil {
				slog.Info("failed to unescape component purl for path pattern, continuing anyway", "purl", componentPurl.String(), "error", err)
				componentPurlStr = componentPurl.String()
			}
			pattern = dtos.PathPattern{componentPurlStr, dtos.PathPatternWildcard, purlString}
		} else {
			// If no metadata component PURL, use the affected package directly
			pattern = dtos.PathPattern{purlString}
		}

		rule := models.VEXRule{
			AssetID:       assetID,
			VexSource:     source,
			Justification: justification,
			EventType:     eventType,
			CELExpression: pattern.ToCELExpression(),
			CreatedByID:   "system", // system user
		}
		rule.SetCELExpression(rule.CELExpression)
		rules = append(rules, rule)
	}

	return rules, nil
}

// OpenVEXToRules converts an OpenVEX document into VEX rules.
//
// OpenVEX is component-level: it identifies the vulnerable package by the statement's
// subcomponent PURL (or the product PURL when no subcomponent is given). The resulting
// path pattern is therefore a component-level wildcard ["*", componentPurl] that matches
// any path reaching that component - it does not distinguish individual dependency paths.
func OpenVEXToRules(doc *vex.VEX, assetID uuid.UUID, assetVersionName string, source string) ([]models.VEXRule, error) {
	rules := make([]models.VEXRule, 0, len(doc.Statements))
	for _, statement := range doc.Statements {
		cveID := extractCVE(string(statement.Vulnerability.Name))
		if cveID == "" {
			cveID = extractCVE(statement.Vulnerability.ID)
		}
		if cveID == "" {
			continue
		}

		eventType, err := mapOpenVexStatusToEventType(statement.Status)
		if err != nil {
			slog.Info("unable to map OpenVEX status to event type, skipping VEX rule creation for this statement", "cveID", cveID, "status", statement.Status, "error", err)
			continue
		}

		justification := statement.ImpactStatement
		if justification == "" {
			justification = statement.StatusNotes
		}

		// collect the component-level PURLs the statement scopes to
		purlStrings := openVexStatementPurls(statement)
		for _, purlString := range purlStrings {
			rule := models.VEXRule{
				AssetID:       assetID,
				VexSource:     source,
				Justification: justification,
				EventType:     eventType,
				CELExpression: dtos.PathPattern{dtos.PathPatternWildcard, purlString}.ToCELExpression(),
				CreatedByID:   "system", // system user
			}
			rule.SetCELExpression(rule.CELExpression)
			rules = append(rules, rule)
		}
	}

	return rules, nil
}

// openVexStatementPurls returns the vulnerable-component PURLs a statement scopes to:
// the subcomponent PURLs, or the product PURLs when no subcomponent is listed.
func openVexStatementPurls(statement vex.Statement) []string {
	var purls []string
	for _, product := range statement.Products {
		if len(product.Subcomponents) > 0 {
			for _, sub := range product.Subcomponents {
				if p := componentPurl(sub.Component); p != "" {
					purls = append(purls, p)
				}
			}
			continue
		}
		if p := componentPurl(product.Component); p != "" {
			purls = append(purls, p)
		}
	}
	return purls
}

func componentPurl(c vex.Component) string {
	if p, ok := c.Identifiers[vex.PURL]; ok && p != "" {
		return p
	}
	if strings.HasPrefix(c.ID, "pkg:") {
		return c.ID
	}
	return ""
}

func mapOpenVexStatusToEventType(status vex.Status) (dtos.VulnEventType, error) {
	switch status {
	case vex.StatusNotAffected:
		return dtos.EventTypeFalsePositive, nil
	case vex.StatusAffected:
		return dtos.EventTypeAccepted, nil
	default:
		// under_investigation / fixed do not close a vuln through a VEX rule
		return "", fmt.Errorf("no event type mapping for OpenVEX status: %s", status)
	}
}

func mapCDXToEventType(a *cdx.VulnerabilityAnalysis) (dtos.VulnEventType, error) {
	if a == nil {
		return "", fmt.Errorf("vulnerability analysis is nil")
	}
	switch a.State {
	case cdx.IASFalsePositive:
		return dtos.EventTypeFalsePositive, nil
	case cdx.IASExploitable:
		// check if wont fix
		if a.Response != nil {
			if slices.Contains(*a.Response, cdx.IARWillNotFix) {
				return dtos.EventTypeAccepted, nil
			} else if slices.Contains(*a.Response, cdx.IARUpdate) {
				return dtos.EventTypeComment, nil
			}
		}
		return "", fmt.Errorf("vulnerability analysis state is exploitable, no event type mapping")
	case cdx.IASNotAffected:
		return dtos.EventTypeFalsePositive, nil

	default:
		// fallback to response mapping if state is empty
		if a.Response != nil && len(*a.Response) > 0 {
			// take first response
			switch (*a.Response)[0] {
			case cdx.IARWillNotFix:
				return dtos.EventTypeAccepted, nil
			default:
				return "", fmt.Errorf("unknown vulnerability analysis response: %s", (*a.Response)[0])
			}
		}
		return "", fmt.Errorf("unknown vulnerability analysis state: %s", a.State)
	}
}

// extractCVE extracts a cve id from a CycloneDX vulnerability id or source url.
func extractCVE(s string) string {
	if s == "" {
		return ""
	}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "http") {
		parts := strings.Split(s, "/")
		return parts[len(parts)-1]
	}
	return s
}

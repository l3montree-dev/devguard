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
	"fmt"
	"strings"

	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/google/uuid"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
)

// CSAFVEXToRules converts a CSAF advisory into VEX rules.
//
// CSAF is path-granular: DevGuard encodes each dependency path as a chain of nested
// default_component_of relationships (artifact <- p1 <- ... <- vulnerable component). The
// leaf product of each chain is what a ProductStatus bucket references. This function walks
// that chain back to reconstruct the exact component-only path and turns it into a
// (non-wildcard) VEX rule path pattern, so only the path-specific vuln is affected.
func CSAFVEXToRules(advisory *gocsaf.Advisory, assetID uuid.UUID, assetVersionName string, source string) ([]models.VEXRule, error) {
	if advisory == nil || advisory.ProductTree == nil {
		return nil, fmt.Errorf("csaf advisory has no product tree")
	}

	// productID -> purl. Base products use their purl as their product id, but we also read
	// the identification helper so combined (relationship) products resolve too.
	productIDToPurl := map[string]string{}
	if advisory.ProductTree.FullProductNames != nil {
		for _, fpn := range *advisory.ProductTree.FullProductNames {
			if fpn == nil || fpn.ProductID == nil {
				continue
			}
			purl := ""
			if fpn.ProductIdentificationHelper != nil && fpn.ProductIdentificationHelper.PURL != nil {
				purl = string(*fpn.ProductIdentificationHelper.PURL)
			}
			productIDToPurl[string(*fpn.ProductID)] = purl
		}
	}

	// combined (leaf/intermediate) product id -> the relationship that declares it
	relByProductID := map[string]*gocsaf.Relationship{}
	if advisory.ProductTree.RelationShips != nil {
		for _, rel := range *advisory.ProductTree.RelationShips {
			if rel == nil || rel.FullProductName == nil || rel.FullProductName.ProductID == nil {
				continue
			}
			relByProductID[string(*rel.FullProductName.ProductID)] = rel
			if rel.FullProductName.ProductIdentificationHelper != nil && rel.FullProductName.ProductIdentificationHelper.PURL != nil {
				productIDToPurl[string(*rel.FullProductName.ProductID)] = string(*rel.FullProductName.ProductIdentificationHelper.PURL)
			}
		}
	}

	rules := make([]models.VEXRule, 0)
	for _, vuln := range advisory.Vulnerabilities {
		cveID := csafVulnCVE(vuln)
		if cveID == "" || vuln.ProductStatus == nil {
			continue
		}

		// products with a no_fix_planned remediation are treated as accepted; also collect
		// the remediation detail per product for use as the rule justification.
		acceptedProducts := map[string]struct{}{}
		remediationDetail := map[string]string{}
		for _, rem := range vuln.Remediations {
			if rem == nil || rem.ProductIds == nil {
				continue
			}
			for _, pid := range *rem.ProductIds {
				if pid == nil {
					continue
				}
				if rem.Details != nil {
					remediationDetail[string(*pid)] = *rem.Details
				}
				if rem.Category != nil && *rem.Category == gocsaf.CSAFRemediationCategoryNoFixPlanned {
					acceptedProducts[string(*pid)] = struct{}{}
				}
			}
		}

		appendRules := func(products *gocsaf.Products, eventType dtos.VulnEventType) {
			if products == nil {
				return
			}
			for _, pid := range *products {
				if pid == nil {
					continue
				}
				productID := string(*pid)
				et := eventType
				if et == "" {
					// known_affected only closes a vuln when it carries a no_fix_planned
					// remediation (i.e. the risk was explicitly accepted).
					if _, ok := acceptedProducts[productID]; !ok {
						continue
					}
					et = dtos.EventTypeAccepted
				}

				pattern := csafProductToPathPattern(productID, relByProductID, productIDToPurl)
				if len(pattern) == 0 {
					continue
				}

				rule := models.VEXRule{
					AssetID:       assetID,
					VexSource:     source,
					Justification: remediationDetail[productID],
					EventType:     et,
					CELExpression: pattern.ToCELExpression(),
					CreatedByID:   "system",
				}
				rule.SetCELExpression(rule.CELExpression)
				rules = append(rules, rule)
			}
		}

		appendRules(vuln.ProductStatus.KnownNotAffected, dtos.EventTypeFalsePositive)
		// empty event type => decide per product (accepted iff no_fix_planned)
		appendRules(vuln.ProductStatus.KnownAffected, "")
	}

	return rules, nil
}

// csafProductToPathPattern reconstructs the exact component-only path a product id refers to
// by walking the default_component_of relationship chain back to, and including, the
// artifact product referenced by relates_to_product_reference at the root of the chain.
// Falls back to a single-element pattern when the product id has no chain but is
// itself a PURL.
func csafProductToPathPattern(productID string, relByProductID map[string]*gocsaf.Relationship, productIDToPurl map[string]string) dtos.PathPattern {
	var reversed []string
	cur := productID
	seen := map[string]bool{}
	for !seen[cur] {
		seen[cur] = true
		rel, ok := relByProductID[cur]
		if !ok {
			// reached a base product (the artifact) - include it as the root of the path
			if purl := purlForProductID(productIDToPurl, cur); purl != "" {
				reversed = append(reversed, purl)
			}
			break
		}
		if rel.ProductReference != nil {
			if purl := purlForProductID(productIDToPurl, string(*rel.ProductReference)); purl != "" {
				reversed = append(reversed, purl)
			}
		}
		if rel.RelatesToProductReference == nil {
			break
		}
		cur = string(*rel.RelatesToProductReference)
	}

	if len(reversed) == 0 {
		// no chain: use the product's own purl if it is one
		if purl := purlForProductID(productIDToPurl, productID); purl != "" {
			return dtos.PathPattern{purl}
		}
		return nil
	}

	// reversed holds [pn, ..., p1]; flip to path order [p1, ..., pn]
	path := make(dtos.PathPattern, len(reversed))
	for i := range reversed {
		path[len(reversed)-1-i] = reversed[i]
	}
	return path
}

func purlForProductID(productIDToPurl map[string]string, id string) string {
	if p, ok := productIDToPurl[id]; ok && p != "" {
		return p
	}
	// base products use their purl as their product id
	if strings.HasPrefix(id, "pkg:") {
		return id
	}
	return ""
}

func csafVulnCVE(vuln *gocsaf.Vulnerability) string {
	if vuln == nil {
		return ""
	}
	if vuln.CVE != nil && *vuln.CVE != "" {
		return extractCVE(string(*vuln.CVE))
	}
	for _, id := range vuln.IDs {
		if id != nil && id.Text != nil && *id.Text != "" {
			return extractCVE(*id.Text)
		}
	}
	return ""
}

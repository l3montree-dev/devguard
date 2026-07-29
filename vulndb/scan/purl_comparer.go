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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package scan

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/utils"

	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
)

type PurlComparer struct {
	db shared.DB
}

func NewPurlComparer(db shared.DB) *PurlComparer {
	return &PurlComparer{
		db: db,
	}
}

var _ comparer = (*PurlComparer)(nil) // Ensure PurlComparer implements comparer interface

// candidate is a purl we are looking for, together with everything we learned
// about it along the way. Carrying the results on the candidate itself keeps the
// input order intact without any index bookkeeping.
type candidate struct {
	purl       packageurl.PackageURL
	matchCtx   *normalize.PurlMatchContext
	components []models.AffectedComponent
}

func (c *candidate) lookupKey() string {
	return c.matchCtx.SearchPurl + "@" + c.matchCtx.NormalizedVersion
}

// queryShape identifies a set of candidates that can be matched by a single
// query: everything except the package and version itself is constant.
type queryShape struct {
	interpretation   normalize.VersionInterpretationType
	ecosystemPattern string
}

// GetAffectedComponents finds the affected components for a single software
// package.
func (comparer *PurlComparer) GetAffectedComponents(ctx context.Context, purl packageurl.PackageURL) ([]models.AffectedComponent, error) {
	candidates, err := comparer.resolveCandidates(ctx, []packageurl.PackageURL{purl})
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return []models.AffectedComponent{}, nil // no version = no results
	}
	return candidates[0].components, nil
}

// GetVulns resolves the vulnerabilities for a set of purls. Callers looking at a
// single purl pass a one element slice.
func (comparer *PurlComparer) GetVulns(ctx context.Context, purls []packageurl.PackageURL) ([]models.VulnInPackage, error) {
	candidates, err := comparer.resolveCandidates(ctx, purls)
	if err != nil {
		return nil, err
	}

	vulns := make([]models.VulnInPackage, 0, len(candidates))
	for _, c := range candidates {
		vulns = append(vulns, vulnsFromAffectedComponents(c.purl, c.components)...)
	}
	return vulns, nil
}

// resolveCandidates looks up the affected components for every purl that can
// match anything at all, in the order the purls were requested.
//
// Rather than querying per purl, the purls are grouped by "query shape" (how
// their version string has to be interpreted plus the ecosystem pattern their
// distro qualifier implies) and one lookup runs per shape. A container SBOM with
// a thousand packages typically collapses to a handful of queries.
func (comparer *PurlComparer) resolveCandidates(ctx context.Context, purls []packageurl.PackageURL) ([]*candidate, error) {
	candidates := make([]*candidate, 0, len(purls))
	byShape := make(map[queryShape][]*candidate)

	for _, purl := range purls {
		matchCtx := normalize.ParsePurlForMatching(purl)
		if matchCtx.HowToInterpretVersionString == normalize.EmptyVersion {
			continue // No version = no results
		}

		c := &candidate{purl: purl, matchCtx: matchCtx}
		candidates = append(candidates, c)

		shape := queryShape{
			interpretation:   matchCtx.HowToInterpretVersionString,
			ecosystemPattern: repositories.QualifierEcosystemPattern(matchCtx.Qualifiers, matchCtx.Namespace),
		}
		byShape[shape] = append(byShape[shape], c)
	}

	for shape, shapeCandidates := range byShape {
		componentsByKey, err := comparer.matchAffectedComponents(ctx, shape, shapeCandidates)
		if err != nil {
			return nil, err
		}
		for _, c := range shapeCandidates {
			c.components = componentsByKey[c.lookupKey()]

			if shape.interpretation == normalize.EcosystemSpecificVersion {
				// Ecosystem specific rules can only be expressed in Go, so the
				// query returned every row for the package and we narrow it here.
				c.components = filterMatchingComponentsByVersion(c.components, c.matchCtx.NormalizedVersion)
			}
		}
	}

	// the candidates are in request order, whereas byShape is not
	return candidates, nil
}

// matchAffectedComponents runs the lookup for one query shape and returns the
// matching affected components per candidate lookup key, with the same preloads
// GetAffectedComponents uses.
func (comparer *PurlComparer) matchAffectedComponents(ctx context.Context, shape queryShape, candidates []*candidate) (map[string][]models.AffectedComponent, error) {
	// The wanted packages and versions are passed as arrays and joined via
	// unnest, so the statement text stays identical regardless of the batch
	// size and postgres can reuse the plan.
	searchPurls := make([]string, len(candidates))
	versions := make([]string, len(candidates))
	for i, c := range candidates {
		searchPurls[i] = c.matchCtx.SearchPurl
		versions[i] = c.matchCtx.NormalizedVersion
	}

	var conditions []string
	args := []any{searchPurls, versions}

	if predicate := repositories.BatchedVersionPredicate(shape.interpretation); predicate != "" {
		conditions = append(conditions, predicate)
	}
	if shape.ecosystemPattern != "" {
		// numbered placeholder, so that GORM passes the arrays above through
		// verbatim instead of expanding the slices into one placeholder per element
		conditions = append(conditions, fmt.Sprintf("ac.ecosystem LIKE $%d", len(args)+1))
		args = append(args, shape.ecosystemPattern)
	}

	// Selecting only the ids keeps the joined result small - the rows are
	// hydrated by a second query, which is also what lets us preload.
	query := `SELECT q.purl, q.version, ac.id FROM affected_components ac
		JOIN (
			SELECT unnest($1::text[]) AS purl, unnest($2::text[]) AS version
		) q ON ac.purl = q.purl`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	var matches []struct {
		Purl    string
		Version string
		ID      int64
	}
	if err := comparer.db.WithContext(ctx).Raw(query, args...).Scan(&matches).Error; err != nil {
		slog.Error("error executing batched affected components query", "error", err, "interpretation", shape.interpretation)
		return nil, errors.Wrap(err, "could not match affected components")
	}
	if len(matches) == 0 {
		return nil, nil
	}

	ids := make([]int64, 0, len(matches))
	for _, match := range matches {
		ids = append(ids, match.ID)
	}

	var components []models.AffectedComponent
	if err := comparer.db.WithContext(ctx).Model(&models.AffectedComponent{}).
		Where("id IN ?", ids).
		Preload("CVE").Preload("CVE.Exploits").Preload("CVE.Relationships").
		Find(&components).Error; err != nil {
		slog.Error("error loading affected components", "error", err)
		return nil, errors.Wrap(err, "could not load affected components")
	}

	componentsByID := make(map[int64]models.AffectedComponent, len(components))
	for _, component := range components {
		componentsByID[component.ID] = component
	}

	componentsByKey := make(map[string][]models.AffectedComponent, len(candidates))
	for _, match := range matches {
		if component, ok := componentsByID[match.ID]; ok {
			key := match.Purl + "@" + match.Version
			componentsByKey[key] = append(componentsByKey[key], component)
		}
	}
	return componentsByKey, nil
}

func vulnsFromAffectedComponents(purl packageurl.PackageURL, affectedComponents []models.AffectedComponent) []models.VulnInPackage {
	// Pre-allocate with estimated capacity
	vulnerabilities := make([]models.VulnInPackage, 0, len(affectedComponents))

	// transform the affected packages to the vulnInPackage struct
	for _, affectedComponent := range affectedComponents {
		for _, cve := range affectedComponent.CVE {
			fixed := affectedComponent.SemverFixed
			if fixed == nil {
				fixed = affectedComponent.VersionFixed
			}

			// append the cve to the vulnerabilities
			vulnerabilities = append(vulnerabilities, models.VulnInPackage{
				CVEID:        cve.CVE,
				Purl:         purl,
				CVE:          cve,
				FixedVersion: fixed,
			})
		}
	}

	return deduplicateByAlias(vulnerabilities)
}

// deduplicateByAlias removes duplicate vulnerabilities caused by CVE aliasing.
// When the same vulnerability is reported under multiple CVE IDs (aliases),
// this function keeps only the canonical one to avoid double-counting.
//
// Rules:
//   - If A --alias--> B exists, keep A (source) and remove B (target)
//   - If bidirectional (A --alias--> B and B --alias--> A), keep the lexicographically smaller one
func deduplicateByAlias(vulns []models.VulnInPackage) []models.VulnInPackage {
	if len(vulns) <= 1 {
		return vulns
	}

	// Build a map of CVE ID to its vuln for quick lookup
	vulnMap := make(map[string]models.VulnInPackage)
	for _, v := range vulns {
		vulnMap[v.CVEID] = v
	}

	// Build alias graph: source -> set of targets
	// A CVE "points to" its aliases (targets)
	aliasTargets := make(map[string]map[string]bool)
	for _, v := range vulns {
		for _, rel := range v.CVE.Relationships {
			if rel.RelationshipType == "alias" {
				if aliasTargets[rel.SourceCVE] == nil {
					aliasTargets[rel.SourceCVE] = make(map[string]bool)
				}
				aliasTargets[rel.SourceCVE][rel.TargetCVE] = true
			}
		}
	}

	// Determine which CVEs to exclude
	exclude := make(map[string]bool)
	for _, v := range vulns {
		cveID := v.CVEID

		// Skip if already marked for exclusion
		if exclude[cveID] {
			continue
		}

		// Check if any other CVE in our result set aliases to this one
		for otherCVE := range vulnMap {
			if otherCVE == cveID {
				continue
			}

			// Check if otherCVE --alias--> cveID
			if aliasTargets[otherCVE][cveID] {
				// Check for bidirectional alias
				if aliasTargets[cveID][otherCVE] {
					// Bidirectional: keep lexicographically smaller
					if cveID > otherCVE {
						exclude[cveID] = true
					}
				} else {
					// Unidirectional: cveID is a target, exclude it
					exclude[cveID] = true
				}
				break
			}
		}
	}

	// Build result excluding duplicates
	result := make([]models.VulnInPackage, 0, len(vulns)-len(exclude))
	for _, v := range vulns {
		if !exclude[v.CVEID] {
			result = append(result, v)
		}
	}

	return result
}

func filterMatchingComponentsByVersion(components []models.AffectedComponent, lookingForVersion string) []models.AffectedComponent {
	matchingComponents := make([]models.AffectedComponent, 0, len(components))

	for _, component := range components {
		purl, err := packageurl.FromString(component.PurlWithoutVersion)
		if err != nil {
			slog.Warn("invalid purl, skipping affected component")
			continue
		}
		match, err := normalize.CheckVersion(component.Version, component.VersionIntroduced, component.VersionFixed, lookingForVersion, purl.Type)
		if err != nil {
			slog.Warn("could not check version for affected component", "error", err, "lookingForVersion", lookingForVersion, "purl", component.PurlWithoutVersion, "introduced", utils.OrDefault(component.VersionIntroduced, "<nil>"), "fixed", utils.OrDefault(component.VersionFixed, "<nil>"))
			continue
		}
		if match {
			matchingComponents = append(matchingComponents, component)
		}
	}

	return matchingComponents
}

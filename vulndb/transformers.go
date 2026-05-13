package vulndb

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/transformer"
)

// --- Import transformers (gob → model) ---

func gobExploitFilterTransformer(lastImportTime time.Time, elements []GobExploit) []models.Exploit {
	out := make([]models.Exploit, 0, len(elements))
	for _, e := range elements {
		if e.Updated != nil && e.Updated.Before(lastImportTime) {
			continue
		}
		out = append(out, gobExploitToModel(e))
	}
	return out

}

func gobExploitStreamer(ctx context.Context, lastImportTime time.Time, exploitChan chan<- []models.Exploit) func([]GobExploit) error {
	return func(elements []GobExploit) error {
		select {
		case exploitChan <- gobExploitFilterTransformer(lastImportTime, elements):
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	}
}

func osvEntryToMaliciousPackageTransformer(entry *dtos.OSV) (models.MaliciousPackage, []models.MaliciousAffectedComponent) {
	// Create malicious package record
	pkg := models.MaliciousPackage{
		ID:        entry.ID,
		Summary:   entry.Summary,
		Details:   entry.Details,
		Published: entry.Published,
		Modified:  entry.Modified,
	}

	// Create affected components
	components := transformer.MaliciousAffectedComponentFromOSV(entry, entry.ID)
	for i := range components {
		components[i].ID = components[i].CalculateHash()
	}

	return pkg, components
}

func gobOSVToMalFilterTransformer(lastImportTime time.Time) func([]OSVEntry) malRows {
	return func(elements []OSVEntry) malRows {
		malPkgs := make([]models.MaliciousPackage, 0)
		malComps := make([]models.MaliciousAffectedComponent, 0)

		for i := range elements {
			if !lastImportTime.IsZero() && !elements[i].ModifiedTimestamp.After(lastImportTime) {
				continue
			}

			// check if malicious package or vulnerability
			if strings.HasPrefix(elements[i].OSV.ID, "MAL-") {
				pkg, comps := osvEntryToMaliciousPackageTransformer(elements[i].OSV)
				malPkgs = append(malPkgs, pkg)
				malComps = append(malComps, comps...)
				continue
			}
		}
		return malRows{
			pkgs:  malPkgs,
			comps: malComps,
		}
	}
}
func gobOSVToVulnFilterTransformer(lastImportTime time.Time, existingCVEIDs map[int64]struct{}, componentToCVEs map[int64][]int64, cveToComponents map[int64][]int64) func([]OSVEntry) vulndbRows {
	if componentToCVEs == nil {
		componentToCVEs = make(map[int64][]int64)
	}
	if cveToComponents == nil {
		cveToComponents = make(map[int64][]int64)
	}
	return func(elements []OSVEntry) vulndbRows {
		cves := make([]models.CVE, 0, len(elements))
		cveRelationships := make([]models.CVERelationship, 0, len(elements)*2)
		affectedComponents := make([]models.AffectedComponent, 0, len(elements)*12)
		cveAffectedComponents := make([]cveAffectedComponentRow, 0, len(elements)*55)
		deleteCveAffectedComponents := make([]cveAffectedComponentRow, 0)

		for i := range elements {
			if !lastImportTime.IsZero() {
				cveID := models.CalculateHashForCVE(elements[i].OSV.ID)
				_, alreadyInDB := existingCVEIDs[cveID]
				if alreadyInDB && !elements[i].ModifiedTimestamp.After(lastImportTime) {
					continue
				}
				// new entry (not yet in DB): always import regardless of modified timestamp
			}

			// check if malicious package or vulnerability
			if strings.HasPrefix(elements[i].OSV.ID, "MAL-") {
				continue
			}
			relationships := transformer.OSVToCVERelationships(elements[i].OSV)
			affectedComponentsForCVE := transformer.AffectedComponentsFromOSV(elements[i].OSV)
			if len(affectedComponentsForCVE) == 0 && len(relationships) == 0 {
				continue
			}

			cve := transformer.OSVToCVE(elements[i].OSV)
			cve.ID = cve.CalculateHash()
			cves = append(cves, cve)
			cveRelationships = append(cveRelationships, relationships...)

			newComponentHashes := make(map[int64]struct{}, len(affectedComponentsForCVE))

			for _, affectedComponent := range affectedComponentsForCVE {
				hash := affectedComponent.CalculateHashFast()
				affectedComponent.ID = hash

				if _, componentKnown := componentToCVEs[hash]; !componentKnown {
					affectedComponents = append(affectedComponents, affectedComponent)
				}

				if !slices.Contains(componentToCVEs[hash], cve.ID) {
					cveAffectedComponents = append(cveAffectedComponents, cveAffectedComponentRow{CveID: cve.ID, AffectedComponentID: hash})
					componentToCVEs[hash] = append(componentToCVEs[hash], cve.ID)
					cveToComponents[cve.ID] = append(cveToComponents[cve.ID], hash)
				}
				newComponentHashes[hash] = struct{}{}
			}

			// For incremental imports: find affected components this CVE previously owned
			// that are no longer present — use the reverse map for O(k) lookup.
			if !lastImportTime.IsZero() {
				for _, affectedComponentHash := range cveToComponents[cve.ID] {
					if _, stillPresent := newComponentHashes[affectedComponentHash]; !stillPresent {
						deleteCveAffectedComponents = append(deleteCveAffectedComponents, cveAffectedComponentRow{CveID: cve.ID, AffectedComponentID: affectedComponentHash})
					}
				}
			}
		}
		return vulndbRows{
			CVEs:                        cves,
			CVERelationships:            cveRelationships,
			AffectedComponents:          affectedComponents,
			CVEAffectedComponents:       cveAffectedComponents,
			DeleteCVEAffectedComponents: deleteCveAffectedComponents,
		}
	}
}

func gobOSVStreamer(ctx context.Context, lastImportTime time.Time, existingCVEIDs map[int64]struct{}, componentToCVEs map[int64][]int64, cveToComponents map[int64][]int64, vulndbChan chan<- vulndbRows) func([]OSVEntry) error {
	transform := gobOSVToVulnFilterTransformer(lastImportTime, existingCVEIDs, componentToCVEs, cveToComponents)
	return func(elements []OSVEntry) error {
		vulndbRows := transform(elements)
		select {
		case vulndbChan <- vulndbRows:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	}
}

func gobOSVMalPkgStreamer(ctx context.Context, lastImportTime time.Time, malPkgsChan chan<- malRows) func([]OSVEntry) error {
	transform := gobOSVToMalFilterTransformer(lastImportTime)
	return func(elements []OSVEntry) error {
		malRows := transform(elements)
		select {
		case malPkgsChan <- malRows:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	}
}

// --- Export transformers (model → gob) ---

func exploitToGobTransformer(elements []models.Exploit) []GobExploit {
	out := make([]GobExploit, len(elements))
	for i, e := range elements {
		out[i] = exploitToGob(e)
	}
	return out
}

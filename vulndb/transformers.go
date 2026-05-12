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
func gobOSVToVulnFilterTransformer(lastImportTime time.Time, existing map[int64][]int64) func([]OSVEntry) vulndbRows {
	if existing == nil {
		existing = make(map[int64][]int64)
	}
	return func(elements []OSVEntry) vulndbRows {
		cves := make([]models.CVE, 0, len(elements))
		cveRelationships := make([]models.CVERelationship, 0, len(elements)*2)
		affectedComponents := make([]models.AffectedComponent, 0, len(elements)*12)
		cveAffectedComponents := make([]cveAffectedComponentRow, 0, len(elements)*55)
		deleteCveAffectedComponents := make([]cveAffectedComponentRow, 0)

		for i := range elements {
			if !lastImportTime.IsZero() && !elements[i].ModifiedTimestamp.After(lastImportTime) {
				continue
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

			newAffectedComponentHashes := make(map[int64]struct{})

			for _, affectedComponent := range affectedComponentsForCVE {
				hash := affectedComponent.CalculateHashFast()
				affectedComponent.ID = hash

				cveIDs, componentExists := existing[hash]
				if !componentExists {
					affectedComponents = append(affectedComponents, affectedComponent)
				}

				pairExists := slices.Contains(cveIDs, cve.ID)
				if !pairExists {
					cveAffectedComponents = append(cveAffectedComponents, cveAffectedComponentRow{CveID: cve.ID, AffectedComponentID: hash})
					existing[hash] = append(cveIDs, cve.ID)
				}
				newAffectedComponentHashes[hash] = struct{}{}
			}
			// check for all affected components this cve is part of - maybe we need to delete some cve affected component entries
			for affectedComponentHash, cves := range existing {
				if slices.Contains(cves, cve.ID) {
					// check if this affected component is still part of the cve, if not we need to delete the cve affected component entry
					if _, exist := newAffectedComponentHashes[affectedComponentHash]; !exist {
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

func gobOSVStreamer(ctx context.Context, lastImportTime time.Time, existing map[int64][]int64, vulndbChan chan<- vulndbRows) func([]OSVEntry) error {
	transform := gobOSVToVulnFilterTransformer(lastImportTime, existing)
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

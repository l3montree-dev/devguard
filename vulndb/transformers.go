package vulndb

import (
	"context"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/transformer"
)

// --- Import transformers (gob → model) ---

func gobExploitStreamingTransformer(lastImportTime time.Time) func([]GobExploit) []models.Exploit {
	return func(elements []GobExploit) []models.Exploit {
		out := make([]models.Exploit, 0, len(elements))
		for _, e := range elements {
			if e.Updated != nil && e.Updated.Before(lastImportTime) {
				continue
			}
			out = append(out, gobExploitToModel(e))
		}
		return out
	}
}

func gobOSVEntryStreamingTransformer(ctx context.Context, currentCVEAffectedComponents []cveAffectedComponentRow) func([]OSVEntry) vulndbRows {
	isAffectedComponentPresent := make(map[int64]struct{}, len(currentCVEAffectedComponents))
	isCVEAffectedComponentPresent := make(map[cveAffectedComponentRow]struct{}, len(currentCVEAffectedComponents))
	for _, cveAffectedComponent := range currentCVEAffectedComponents {
		isAffectedComponentPresent[cveAffectedComponent.AffectedComponentID] = struct{}{}
		isCVEAffectedComponentPresent[cveAffectedComponent] = struct{}{}
	}
	return func(elements []OSVEntry) vulndbRows {
		cves := make([]models.CVE, 0, len(elements))
		cveRelationships := make([]models.CVERelationship, 0, len(elements)*2)
		affectedComponents := make([]models.AffectedComponent, 0, len(elements)*12)
		cveAffectedComponents := make([]cveAffectedComponentRow, 0, len(elements)*55)

		for i := range elements {
			relationships := transformer.OSVToCVERelationships(elements[i].OSV)
			affectedComponentsForCVE := transformer.AffectedComponentsFromOSV(elements[i].OSV)
			if len(affectedComponentsForCVE) == 0 && len(relationships) == 0 {
				continue
			}

			cve := transformer.OSVToCVE(elements[i].OSV)
			cve.ID = cve.CalculateHash()
			cves = append(cves, cve)
			cveRelationships = append(cveRelationships, relationships...)

			for _, affectedComponent := range affectedComponentsForCVE {
				hash := affectedComponent.CalculateHashFast()
				affectedComponent.ID = hash
				row := cveAffectedComponentRow{CveID: cve.ID, AffectedComponentID: hash}

				if _, ok := isAffectedComponentPresent[hash]; !ok {
					affectedComponents = append(affectedComponents, affectedComponent)
					isAffectedComponentPresent[hash] = struct{}{}
				}
				if _, ok := isCVEAffectedComponentPresent[row]; !ok {
					cveAffectedComponents = append(cveAffectedComponents, row)
					isCVEAffectedComponentPresent[row] = struct{}{}
				}
			}
		}
		return vulndbRows{
			CVEs:                  cves,
			CVERelationships:      cveRelationships,
			AffectedComponents:    affectedComponents,
			CVEAffectedComponents: cveAffectedComponents,
		}
	}
}

func gobMalPackagesStreamingTransformer(lastImportTime time.Time) func([]GobMaliciousPackagesExport) malRow {
	return func(elements []GobMaliciousPackagesExport) malRow {
		pkgs := make([]models.MaliciousPackage, 0, len(elements))
		comps := make([]models.MaliciousAffectedComponent, 0, len(elements)*4)
		for _, element := range elements {
			if !element.Package.Modified.After(lastImportTime) {
				continue
			}
			pkgs = append(pkgs, element.Package)
			for _, c := range element.Components {
				comps = append(comps, gobComponentToModel(c))
			}
		}
		return malRow{pkgs: pkgs, comps: comps}
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

// malPackagesToGobTransformer pairs each package with its components and returns one
// GobMaliciousPackagesExport per package, ready for individual gob encoding.
func malPackagesToGobTransformer(pkgs []models.MaliciousPackage, comps []models.MaliciousAffectedComponent) []GobMaliciousPackagesExport {
	compsByPkg := make(map[string][]GobMaliciousComponent, len(pkgs))
	for _, c := range comps {
		compsByPkg[c.MaliciousPackageID] = append(compsByPkg[c.MaliciousPackageID], maliciousComponentToGob(c))
	}
	out := make([]GobMaliciousPackagesExport, len(pkgs))
	for i, pkg := range pkgs {
		out[i] = GobMaliciousPackagesExport{
			Package:    pkg,
			Components: compsByPkg[pkg.ID],
		}
	}
	return out
}

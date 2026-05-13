package vulndb

import (
	"context"
	"slices"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/transformer"
)

// --- Import transformers (gob → model) ---

func gobExploitFilterTransformer(elements []GobExploit) []models.Exploit {
	out := make([]models.Exploit, 0, len(elements))
	for _, e := range elements {
		out = append(out, gobExploitToModel(e))
	}
	return out
}

func gobExploitStreamer(ctx context.Context, exploitChan chan<- []models.Exploit) func([]GobExploit) error {
	return func(elements []GobExploit) error {
		select {
		case exploitChan <- gobExploitFilterTransformer(elements):
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

func gobOSVToMalTransformer(elements []OSVEntry) malRows {
	malPkgs := make([]models.MaliciousPackage, 0)
	malComps := make([]models.MaliciousAffectedComponent, 0)

	for i := range elements {
		if strings.HasPrefix(elements[i].OSV.ID, "MAL-") {
			pkg, comps := osvEntryToMaliciousPackageTransformer(elements[i].OSV)
			malPkgs = append(malPkgs, pkg)
			malComps = append(malComps, comps...)
		}
	}
	return malRows{
		pkgs:  malPkgs,
		comps: malComps,
	}
}

// gobOSVToVulnTransformer returns a stateful batch transformer that deduplicates
// affected_components and cve_affected_component pivot rows across calls.
func gobOSVToVulnTransformer() func([]OSVEntry) vulndbRows {
	componentToCVEs := make(map[int64][]int64)
	return func(elements []OSVEntry) vulndbRows {
		cves := make([]models.CVE, 0, len(elements))
		cveRelationships := make([]models.CVERelationship, 0, len(elements)*2)
		affectedComponents := make([]models.AffectedComponent, 0, len(elements)*12)
		cveAffectedComponents := make([]cveAffectedComponentRow, 0, len(elements)*55)

		for i := range elements {
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
			cve.ContentHash = cve.CalculateContentHash()
			cves = append(cves, cve)
			cveRelationships = append(cveRelationships, relationships...)

			for _, affectedComponent := range affectedComponentsForCVE {
				hash := affectedComponent.CalculateHashFast()
				affectedComponent.ID = hash

				// Cross-batch dedup: only send each unique component once to staging.
				if _, known := componentToCVEs[hash]; !known {
					affectedComponents = append(affectedComponents, affectedComponent)
				}

				if !slices.Contains(componentToCVEs[hash], cve.ID) {
					cveAffectedComponents = append(cveAffectedComponents, cveAffectedComponentRow{CveID: cve.ID, AffectedComponentID: hash})
					componentToCVEs[hash] = append(componentToCVEs[hash], cve.ID)
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


func gobOSVStreamer(ctx context.Context, vulndbChan chan<- vulndbRows) func([]OSVEntry) error {
	transform := gobOSVToVulnTransformer()
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

func gobOSVMalPkgStreamer(ctx context.Context, malPkgsChan chan<- malRows) func([]OSVEntry) error {
	return func(elements []OSVEntry) error {
		malRows := gobOSVToMalTransformer(elements)
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

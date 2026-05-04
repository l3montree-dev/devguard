package vulndb

import (
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"gorm.io/datatypes"
)

// CISAKEVEntry is the gob-safe representation of a CISA KEV record.
// Dates are stored as *time.Time to avoid the datatypes.Date gob limitation.
type CISAKEVEntry struct {
	CVE               string
	ExploitAddDate    *time.Time
	ActionDueDate     *time.Time
	RequiredAction    string
	VulnerabilityName string
}

// GobExploit is the gob-safe representation of models.Exploit.
// It omits the nested CVE field which contains datatypes.Date.
type GobExploit struct {
	ID          string
	Published   *time.Time
	Updated     *time.Time
	Author      string
	Type        string
	Verified    bool
	SourceURL   string
	Description string
	CVEID       string
	Tags        string
	Forks       int
	Watchers    int
	Subscribers int
	Stars       int
}

// GobMaliciousComponent is the gob-safe representation of models.MaliciousAffectedComponent.
type GobMaliciousComponent struct {
	ID                 string
	MaliciousPackageID string
	PurlWithoutVersion string
	Ecosystem          string
	Version            *string
	SemverIntroduced   *string
	SemverFixed        *string
	VersionIntroduced  *string
	VersionFixed       *string
}

// GobMaliciousPackagesExport bundles the full malicious-packages snapshot.
// models.MaliciousPackage only contains plain types and is gob-safe directly.
type GobMaliciousPackagesExport struct {
	Packages   []models.MaliciousPackage
	Components []GobMaliciousComponent
}

// --- CISA KEV conversions ---

func cisaKEVEntriesToGob(cves []models.CVE) []CISAKEVEntry {
	out := make([]CISAKEVEntry, 0, len(cves))
	for _, c := range cves {
		out = append(out, CISAKEVEntry{
			CVE:               c.CVE,
			ExploitAddDate:    dateToTimePtr(c.CISAExploitAdd),
			ActionDueDate:     dateToTimePtr(c.CISAActionDue),
			RequiredAction:    c.CISARequiredAction,
			VulnerabilityName: c.CISAVulnerabilityName,
		})
	}
	return out
}

func gobCISAKEVEntriesToModels(entries []CISAKEVEntry) []models.CVE {
	out := make([]models.CVE, 0, len(entries))
	for _, e := range entries {
		out = append(out, models.CVE{
			CVE:                   e.CVE,
			CISAExploitAdd:        timePtrToDate(e.ExploitAddDate),
			CISAActionDue:         timePtrToDate(e.ActionDueDate),
			CISARequiredAction:    e.RequiredAction,
			CISAVulnerabilityName: e.VulnerabilityName,
		})
	}
	return out
}

func dateToTimePtr(d *datatypes.Date) *time.Time {
	if d == nil {
		return nil
	}
	t := time.Time(*d)
	return &t
}

func timePtrToDate(t *time.Time) *datatypes.Date {
	if t == nil {
		return nil
	}
	d := datatypes.Date(*t)
	return &d
}

// --- Exploit conversions ---

func exploitToGob(e models.Exploit) GobExploit {
	return GobExploit{
		ID:          e.ID,
		Published:   e.Published,
		Updated:     e.Updated,
		Author:      e.Author,
		Type:        e.Type,
		Verified:    e.Verified,
		SourceURL:   e.SourceURL,
		Description: e.Description,
		CVEID:       e.CVEID,
		Tags:        e.Tags,
		Forks:       e.Forks,
		Watchers:    e.Watchers,
		Subscribers: e.Subscribers,
		Stars:       e.Stars,
	}
}

func gobExploitToModel(g GobExploit) models.Exploit {
	return models.Exploit{
		ID:          g.ID,
		Published:   g.Published,
		Updated:     g.Updated,
		Author:      g.Author,
		Type:        g.Type,
		Verified:    g.Verified,
		SourceURL:   g.SourceURL,
		Description: g.Description,
		CVEID:       g.CVEID,
		Tags:        g.Tags,
		Forks:       g.Forks,
		Watchers:    g.Watchers,
		Subscribers: g.Subscribers,
		Stars:       g.Stars,
	}
}

func exploitsToGob(exploits []models.Exploit) []GobExploit {
	out := make([]GobExploit, len(exploits))
	for i, e := range exploits {
		out[i] = exploitToGob(e)
	}
	return out
}

func gobExploitsToModels(gs []GobExploit) []models.Exploit {
	out := make([]models.Exploit, len(gs))
	for i, g := range gs {
		out[i] = gobExploitToModel(g)
	}
	return out
}

// --- Malicious package conversions ---

func maliciousComponentToGob(c models.MaliciousAffectedComponent) GobMaliciousComponent {
	return GobMaliciousComponent{
		ID:                 c.ID,
		MaliciousPackageID: c.MaliciousPackageID,
		PurlWithoutVersion: c.PurlWithoutVersion,
		Ecosystem:          c.Ecosystem,
		Version:            c.Version,
		SemverIntroduced:   c.SemverIntroduced,
		SemverFixed:        c.SemverFixed,
		VersionIntroduced:  c.VersionIntroduced,
		VersionFixed:       c.VersionFixed,
	}
}

func gobComponentToModel(g GobMaliciousComponent) models.MaliciousAffectedComponent {
	return models.MaliciousAffectedComponent{
		ID:                 g.ID,
		MaliciousPackageID: g.MaliciousPackageID,
		PurlWithoutVersion: g.PurlWithoutVersion,
		Ecosystem:          g.Ecosystem,
		Version:            g.Version,
		SemverIntroduced:   g.SemverIntroduced,
		SemverFixed:        g.SemverFixed,
		VersionIntroduced:  g.VersionIntroduced,
		VersionFixed:       g.VersionFixed,
	}
}

func malPackagesExportToGob(packages []models.MaliciousPackage, components []models.MaliciousAffectedComponent) GobMaliciousPackagesExport {
	gobComps := make([]GobMaliciousComponent, len(components))
	for i, c := range components {
		gobComps[i] = maliciousComponentToGob(c)
	}
	return GobMaliciousPackagesExport{Packages: packages, Components: gobComps}
}

func gobMalPackagesExportToModels(g GobMaliciousPackagesExport, lastImportTime time.Time) ([]models.MaliciousPackage, []models.MaliciousAffectedComponent) {
	// build a map of package ID to last import time for all packages in the export
	pkgImportTimes := make(map[string]struct{})
	filteredPkgs := make([]models.MaliciousPackage, 0, len(g.Packages))
	for _, pkg := range g.Packages {
		if pkg.Modified.After(lastImportTime) {
			pkgImportTimes[pkg.ID] = struct{}{}
			filteredPkgs = append(filteredPkgs, pkg)
		}
	}
	comps := make([]models.MaliciousAffectedComponent, len(g.Components))
	for i, c := range g.Components {
		// only import components whose package was modified after the last import time
		if _, ok := pkgImportTimes[c.MaliciousPackageID]; !ok {
			continue
		}

		comps[i] = gobComponentToModel(c)
	}
	return filteredPkgs, comps
}

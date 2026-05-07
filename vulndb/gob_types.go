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
	Package    models.MaliciousPackage
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

func dateToTimePtr(d *datatypes.Date) *time.Time {
	if d == nil {
		return nil
	}
	t := time.Time(*d)
	return &t
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

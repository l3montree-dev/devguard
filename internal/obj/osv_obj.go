package obj

import (
	"strings"
	"time"
)

type Pkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Purl      string `json:"purl"`
}

type SemverEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type Rng struct {
	Type   string        `json:"type"`
	Events []SemverEvent `json:"events"`
}

type Affected struct {
	Package           Pkg            `json:"package"`
	Ranges            []Rng          `json:"ranges"`
	Versions          []string       `json:"versions"`
	DatabaseSpecific  map[string]any `json:"database_specific"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific"`
}

type OSV struct {
	ID            string     `json:"id"`
	Summary       string     `json:"summary"`
	Modified      time.Time  `json:"modified"`
	Published     time.Time  `json:"published"`
	Related       []string   `json:"related"`
	Aliases       []string   `json:"aliases"`
	Affected      []Affected `json:"affected"`
	SchemaVersion string     `json:"schema_version"`
}

func (osv OSV) GetCVE() []string {
	cves := make([]string, 0)
	for _, alias := range osv.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cves = append(cves, alias)
		}
	}
	// check if the osv itself is a cve
	if strings.HasPrefix(osv.ID, "CVE-") {
		cves = append(cves, osv.ID)
	}

	// check if its related to a cve
	for _, related := range osv.Related {
		if strings.HasPrefix(related, "CVE-") {
			cves = append(cves, related)
		}
	}

	return cves
}
func (osv OSV) IsCVE() bool {
	return len(osv.GetCVE()) > 0
}

package dtos

import (
	"strings"
	"time"
)

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Purl      string `json:"purl"`
}

type SemverEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type Range struct {
	Type   string        `json:"type"`
	Repo   string        `json:"repo"`
	Events []SemverEvent `json:"events"`
}

type Affected struct {
	Package           Package        `json:"package"`
	Ranges            []Range        `json:"ranges"`
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
	Upstream      []string   `json:"upstream"`
	Affected      []Affected `json:"affected"`
	SchemaVersion string     `json:"schema_version"`
	Severity      []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

func (osv OSV) GetAssociatedCVEs() []string {
	cves := make([]string, 0)
	for _, alias := range osv.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cves = append(cves, alias)
		}
	}

	for _, upstream := range osv.Upstream {
		if strings.HasPrefix(upstream, "CVE-") {
			cves = append(cves, upstream)
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
	return len(osv.GetAssociatedCVEs()) > 0
}

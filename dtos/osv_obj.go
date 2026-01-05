package dtos

import (
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

type EcosystemSpecific struct {
	Urgency string `json:"urgency,omitempty"`
	// there are more fields
	// since we are using binary serialization for this struct
	// we need to define all fields we want to use
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
	Details       string     `json:"details"`
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

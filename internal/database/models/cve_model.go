package models

import (
	"encoding/json"
	"time"

	"gorm.io/datatypes"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type cveReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}
type CVE struct {
	CVE string `json:"cve" gorm:"primaryKey;not null;type:text;"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	DatePublished    time.Time `json:"datePublished"`
	DateLastModified time.Time `json:"dateLastModified"`

	Weaknesses  []*Weakness `json:"weaknesses" gorm:"foreignKey:CVEID;constraint:OnDelete:CASCADE;"`
	Description string      `json:"description" gorm:"type:text;"`

	CVSS                float32  `json:"cvss" gorm:"type:decimal(4,2);"`
	Severity            Severity `json:"severity"`
	ExploitabilityScore float32  `json:"exploitabilityScore" gorm:"type:decimal(4,2);"`
	ImpactScore         float32  `json:"impactScore" gorm:"type:decimal(4,2);"`

	AttackVector          string `json:"attackVector"`
	AttackComplexity      string `json:"attackComplexity"`
	PrivilegesRequired    string `json:"privilegesRequired"`
	UserInteraction       string `json:"userInteractionRequired"`
	Scope                 string `json:"scope"`
	ConfidentialityImpact string `json:"confidentialityImpact"`
	IntegrityImpact       string `json:"integrityImpact"`
	AvailabilityImpact    string `json:"availabilityImpact"`

	References string `json:"references" gorm:"type:text;"`

	CISAExploitAdd        *datatypes.Date `json:"cisaExploitAdd" gorm:"type:date;"`
	CISAActionDue         *datatypes.Date `json:"cisaActionDue" gorm:"type:date;"`
	CISARequiredAction    string          `json:"cisaRequiredAction" gorm:"type:text;"`
	CISAVulnerabilityName string          `json:"cisaVulnerabilityName" gorm:"type:text;"`

	Configurations []*CPEMatch `json:"configurations" gorm:"many2many:cve_cpe_match;"`

	EPSS       *float32 `json:"epss" gorm:"type:decimal(6,5);"`
	Percentile *float32 `json:"percentile" gorm:"type:decimal(6,5);"`
}

type Weakness struct {
	Source string `json:"source" gorm:"type:text;"`
	Type   string `json:"type" gorm:"type:text;"`
	CVEID  string `json:"cve" gorm:"primaryKey;not null;type:text;"`
	CVE    CVE
	CWEID  string `json:"cwe" gorm:"primaryKey;not null;type:text;"`
}

func (m Weakness) TableName() string {
	return "weaknesses"
}

func (m CVE) TableName() string {
	return "cves"
}

func (m CVE) GetReferences() ([]cveReference, error) {
	var refs []cveReference
	if err := json.Unmarshal([]byte(m.References), &refs); err != nil {
		return nil, err
	}
	return refs, nil
}

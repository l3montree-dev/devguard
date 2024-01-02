package cwe

import (
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type CVEModel struct {
	CVE string `json:"cve" gorm:"primaryKey;not null;type:varchar(255);"`

	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	FixAvailable *bool     `json:"fixAvailable" gorm:"type:boolean;"`

	DatePublished    time.Time `json:"datePublished"`
	DateLastModified time.Time `json:"dateLastModified"`

	CWEs        []*CWEModel `json:"cwes" gorm:"many2many:cve_cwe;"`
	Description string      `json:"description" gorm:"type:text;"`

	CVSS                float32  `json:"cvss" gorm:"type:decimal(3,2);"`
	Severity            Severity `json:"severity"`
	ExploitabilityScore float32  `json:"exploitabilityScore" gorm:"type:decimal(3,2);"`
	ImpactScore         float32  `json:"impactScore" gorm:"type:decimal(3,2);"`

	AttackVector          string `json:"attackVector"`
	AttackComplexity      string `json:"attackComplexity"`
	PrivilegesRequired    string `json:"privilegesRequired"`
	UserInteraction       string `json:"userInteractionRequired"`
	Scope                 string `json:"scope"`
	ConfidentialityImpact string `json:"confidentialityImpact"`
	IntegrityImpact       string `json:"integrityImpact"`
	AvailabilityImpact    string `json:"availabilityImpact"`
}

func (m CVEModel) TableName() string {
	return "cves"
}

package cve

import (
	"database/sql"
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

	CWE         []*CWEModel `json:"cwe" gorm:"many2many:cve_cwe;"`
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

type CWEModel struct {
	CreatedAt time.Time    `json:"createdAt"`
	UpdatedAt time.Time    `json:"updatedAt"`
	DeletedAt sql.NullTime `gorm:"index" json:"-"`

	CWE string      `json:"cwe" gorm:"primaryKey;not null;"`
	CVE []*CVEModel `json:"cve" gorm:"many2many:cve_cwe;"`
}

func (m CVEModel) TableName() string {
	return "cves"
}

func (m CWEModel) TableName() string {
	return "cwes"
}

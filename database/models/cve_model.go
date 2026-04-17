package models

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"gorm.io/datatypes"
	"gorm.io/gorm"
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
	ID                    int64               `json:"id" gorm:"type:bigint;primaryKey;not null;"`
	CVE                   string              `json:"cve" gorm:"type:text;"`
	CreatedAt             time.Time           `json:"createdAt" cve:"createdAt"`
	UpdatedAt             time.Time           `json:"updatedAt" cve:"updatedAt"`
	DatePublished         time.Time           `json:"datePublished" cve:"datePublished"`
	DateLastModified      time.Time           `json:"dateLastModified" cve:"dateLastModified"`
	Weaknesses            []Weakness          `json:"weaknesses" gorm:"foreignKey:CVEID;constraint:OnDelete:CASCADE;" cve:"weaknesses"`
	Description           string              `json:"description" gorm:"type:text;" cve:"description"`
	CVSS                  float32             `json:"cvss" gorm:"type:decimal(4,2);" cve:"cvss"`
	References            string              `json:"references" gorm:"type:text;" cve:"references"`
	CISAExploitAdd        *datatypes.Date     `json:"cisaExploitAdd" gorm:"type:date;" cve:"cisaExploitAdd" swaggertype:"string" format:"date"`
	CISAActionDue         *datatypes.Date     `json:"cisaActionDue" gorm:"type:date;" cve:"cisaActionDue" swaggertype:"string" format:"date"`
	CISARequiredAction    string              `json:"cisaRequiredAction" gorm:"type:text;" cve:"cisaRequiredAction"`
	CISAVulnerabilityName string              `json:"cisaVulnerabilityName" gorm:"type:text;" cve:"cisaVulnerabilityName"`
	EPSS                  *float64            `json:"epss" gorm:"type:decimal(6,5);" cve:"epss"`
	Percentile            *float32            `json:"percentile" gorm:"type:decimal(6,5);" cve:"percentile"`
	AffectedComponents    []AffectedComponent `json:"affectedComponents" gorm:"many2many:cve_affected_component;constraint:OnDelete:CASCADE"`
	Vector                string              `json:"vector" gorm:"type:text;" cve:"vector"`
	Risk                  dtos.RiskMetrics    `json:"risk" gorm:"-" cve:"risk"`
	Exploits              []Exploit           `json:"exploits" gorm:"foreignKey:CVEID;"`
	Relationships         []CVERelationship   `json:"relationships" gorm:"foreignKey:SourceCVE;constraint:OnDelete:CASCADE;" cve:"relationships"`
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

// calculate the hash for the cve solely based on the cve-id using md5 for compatibility with the postgresql database
func (m CVE) CalculateHash() int64 {
	return CalculateHashForCVE(m.CVE)
}

func CalculateHashForCVE(cveID string) int64 {
	sum := md5.Sum([]byte(cveID))
	u := binary.BigEndian.Uint64(sum[:8])
	return int64(u & 0x7fffffffffffffff)
}

func (m CVE) GetReferences() ([]cveReference, error) {
	var refs []cveReference
	if err := json.Unmarshal([]byte(m.References), &refs); err != nil {
		return nil, err
	}
	return refs, nil
}

func (cve *CVE) BeforeSave(tx *gorm.DB) error {
	if cve.ID == 0 {
		cve.ID = cve.CalculateHash()
	}
	return nil
}

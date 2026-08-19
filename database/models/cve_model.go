package models

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"fmt"
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

type CVEMap map[string]map[string]struct{}

type CVE struct {
	ID                    int64               `json:"id" gorm:"type:bigint;primaryKey;not null;"`
	ContentHash           int64               `json:"contentHash" gorm:"type:bigint;not null;default:0;"`
	CVE                   string              `json:"cve" gorm:"type:text;"`
	DatePublished         time.Time           `json:"datePublished" cve:"datePublished"`
	DateLastModified      time.Time           `json:"dateLastModified" cve:"dateLastModified"`
	Weaknesses            []Weakness          `json:"weaknesses" gorm:"foreignKey:CVEID;references:CVE;constraint:OnDelete:CASCADE;" cve:"weaknesses"`
	Description           string              `json:"description" gorm:"type:text;" cve:"description"`
	CVSS                  float32             `json:"cvss" gorm:"type:decimal(4,2);" cve:"cvss"`
	References            string              `json:"references" gorm:"type:text;" cve:"references"`
	CISAExploitAdd        *datatypes.Date     `json:"cisaExploitAdd" gorm:"type:date;" cve:"cisaExploitAdd" swaggertype:"string" format:"date"`
	CISAActionDue         *datatypes.Date     `json:"cisaActionDue" gorm:"type:date;" cve:"cisaActionDue" swaggertype:"string" format:"date"`
	CISARequiredAction    *string             `json:"cisaRequiredAction" gorm:"type:text;" cve:"cisaRequiredAction"`
	CISAVulnerabilityName *string             `json:"cisaVulnerabilityName" gorm:"type:text;" cve:"cisaVulnerabilityName"`
	EPSS                  *float64            `json:"epss" gorm:"type:decimal(6,5);" cve:"epss"`
	Percentile            *float32            `json:"percentile" gorm:"type:decimal(6,5);" cve:"percentile"`
	AffectedComponents    []AffectedComponent `json:"affectedComponents" gorm:"many2many:cve_affected_component;constraint:OnDelete:CASCADE"`
	Vector                string              `json:"vector" gorm:"type:text;" cve:"vector"`
	Risk                  dtos.RiskMetrics    `json:"risk" gorm:"-" cve:"risk"`
	Exploits              []Exploit           `json:"exploits" gorm:"foreignKey:CVEID;references:CVE;"`
	Relationships         []CVERelationship   `json:"relationships" gorm:"foreignKey:SourceCVE;references:CVE;constraint:OnDelete:CASCADE;" cve:"relationships"`
	EUVDExploitAdd        *datatypes.Date     `json:"euvdExploitAdd" gorm:"type:date"`
	Withdrawn             *datatypes.Date     `json:"withdrawn" gorm:"type:date"`
}

type Weakness struct {
	Source string `json:"source" gorm:"type:text;"`
	Type   string `json:"type" gorm:"type:text;"`
	CVEID  string `json:"cve" gorm:"primaryKey;not null;type:text;"`
	CVE    CVE    `gorm:"foreignKey:CVEID;references:CVE;"`
	CWEID  string `json:"cwe" gorm:"primaryKey;not null;type:text;"`
}

func (w Weakness) TableName() string {
	return "weaknesses"
}

func (w Weakness) ToCELMap() map[string]any {
	return map[string]any{
		"source": w.Source,
		"type":   w.Type,
		"cve":    w.CVEID,
		"cwe":    w.CWEID,
	}
}

func (cve CVE) ToCELMap() map[string]any {
	m := map[string]any{
		"id":               float64(cve.ID),
		"contentHash":      float64(cve.ContentHash),
		"cve":              cve.CVE,
		"datePublished":    timeToCEL(cve.DatePublished),
		"dateLastModified": timeToCEL(cve.DateLastModified),
		"description":      cve.Description,
		"cvss":             float64(cve.CVSS),
		"references":       cve.References,
		"vector":           cve.Vector,
		"risk": map[string]any{
			"baseScore":                            cve.Risk.BaseScore,
			"withEnvironment":                      cve.Risk.WithEnvironment,
			"withThreatIntelligence":               cve.Risk.WithThreatIntelligence,
			"withEnvironmentAndThreatIntelligence": cve.Risk.WithEnvironmentAndThreatIntelligence,
		},
	}

	m["cisaRequiredAction"] = ptrToAny(cve.CISARequiredAction)
	m["cisaVulnerabilityName"] = ptrToAny(cve.CISAVulnerabilityName)
	m["epss"] = ptrToAny(cve.EPSS)
	if cve.Percentile != nil {
		m["percentile"] = float64(*cve.Percentile)
	} else {
		m["percentile"] = nil
	}

	for _, dp := range []struct {
		key string
		val *datatypes.Date
	}{
		{"cisaExploitAdd", cve.CISAExploitAdd},
		{"cisaActionDue", cve.CISAActionDue},
		{"euvdExploitAdd", cve.EUVDExploitAdd},
	} {
		if dp.val != nil {
			m[dp.key] = timeToCEL(time.Time(*dp.val))
		} else {
			m[dp.key] = nil
		}
	}

	weaknesses := make([]any, len(cve.Weaknesses))
	for i, w := range cve.Weaknesses {
		weaknesses[i] = w.ToCELMap()
	}
	m["weaknesses"] = weaknesses

	exploits := make([]any, len(cve.Exploits))
	for i, e := range cve.Exploits {
		exploits[i] = e.ToCELMap()
	}
	m["exploits"] = exploits

	// affectedComponents/relationships are deliberately not converted here -
	// no VEX rule references them today.
	m["affectedComponents"] = []any{}
	m["relationships"] = []any{}

	return m
}

func (cve CVE) TableName() string {
	return "cves"
}

func (cve *CVE) BeforeSave(tx *gorm.DB) error {
	if cve.ID == 0 {
		cve.ID = cve.CalculateHash()
	}
	return nil
}

// calculate the hash for the cve solely based on the cve-id using md5 for compatibility with the postgresql database
func (cve CVE) CalculateHash() int64 {
	return CalculateHashForCVE(cve.CVE)
}

func CalculateHashForCVE(cveID string) int64 {
	sum := md5.Sum([]byte(cveID))
	u := binary.BigEndian.Uint64(sum[:8])
	return int64(u & 0x7fffffffffffffff)
}

// CalculateContentHash hashes the OSV-sourced content fields (description, cvss, vector).
// EPSS and CISA KEV are intentionally excluded — they are applied via separate UPDATE steps
// and their changes should not trigger a delete+reinsert of the CVE or its related rows.
func (cve CVE) CalculateContentHash() int64 {
	h := fmt.Sprintf("%s|%.2f|%s", cve.Description, cve.CVSS, cve.Vector)
	sum := md5.Sum([]byte(h))
	u := binary.BigEndian.Uint64(sum[:8])
	return int64(u & 0x7fffffffffffffff)
}

func (cve CVE) GetReferences() ([]cveReference, error) {
	var refs []cveReference
	if err := json.Unmarshal([]byte(cve.References), &refs); err != nil {
		return nil, err
	}
	return refs, nil
}

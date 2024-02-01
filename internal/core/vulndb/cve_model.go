package vulndb

import (
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/l3montree-dev/flawfix/internal/utils"
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
	CVE string `json:"cve" gorm:"primaryKey;not null;type:varchar(255);"`

	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	FixAvailable *bool     `json:"fixAvailable" gorm:"type:boolean;"`

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
	Source string `json:"source" gorm:"type:varchar(255);"`
	Type   string `json:"type" gorm:"type:varchar(255);"`
	CVEID  string `json:"cve" gorm:"primaryKey;not null;type:varchar(255);"`
	CVE    CVE
	CWEID  string `json:"cwe" gorm:"primaryKey;not null;type:varchar(255);"`
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

type cvssMetric struct {
	Severity              string
	CVSS                  float32
	ExploitabilityScore   float32
	ImpactScore           float32
	AttackVector          string
	AttackComplexity      string
	PrivilegesRequired    string
	UserInteraction       string
	Scope                 string
	ConfidentialityImpact string
	IntegrityImpact       string
	AvailabilityImpact    string
}

func getCVSSMetric(nvdCVE nvdCVE) cvssMetric {
	// check if cvss v3 is available
	if len(nvdCVE.Metrics.CvssMetricV31) > 0 {
		return cvssMetric{
			Severity:              nvdCVE.Metrics.CvssMetricV31[0].CvssData.BaseSeverity,
			CVSS:                  float32(nvdCVE.Metrics.CvssMetricV31[0].CvssData.BaseScore),
			ExploitabilityScore:   float32(nvdCVE.Metrics.CvssMetricV31[0].ExploitabilityScore),
			ImpactScore:           float32(nvdCVE.Metrics.CvssMetricV31[0].ImpactScore),
			AttackVector:          nvdCVE.Metrics.CvssMetricV31[0].CvssData.AttackVector,
			AttackComplexity:      nvdCVE.Metrics.CvssMetricV31[0].CvssData.AttackComplexity,
			PrivilegesRequired:    nvdCVE.Metrics.CvssMetricV31[0].CvssData.PrivilegesRequired,
			UserInteraction:       nvdCVE.Metrics.CvssMetricV31[0].CvssData.UserInteraction,
			Scope:                 nvdCVE.Metrics.CvssMetricV31[0].CvssData.Scope,
			ConfidentialityImpact: nvdCVE.Metrics.CvssMetricV31[0].CvssData.ConfidentialityImpact,
			IntegrityImpact:       nvdCVE.Metrics.CvssMetricV31[0].CvssData.IntegrityImpact,
			AvailabilityImpact:    nvdCVE.Metrics.CvssMetricV31[0].CvssData.AvailabilityImpact,
		}
	}
	if len(nvdCVE.Metrics.CvssMetricV2) == 0 {
		return cvssMetric{}
	}

	return cvssMetric{
		Severity:              nvdCVE.Metrics.CvssMetricV2[0].BaseSeverity,
		CVSS:                  float32(nvdCVE.Metrics.CvssMetricV2[0].CvssData.BaseScore),
		ExploitabilityScore:   float32(nvdCVE.Metrics.CvssMetricV2[0].ExploitabilityScore),
		ImpactScore:           float32(nvdCVE.Metrics.CvssMetricV2[0].ImpactScore),
		AttackVector:          nvdCVE.Metrics.CvssMetricV2[0].CvssData.AccessVector,
		AttackComplexity:      nvdCVE.Metrics.CvssMetricV2[0].CvssData.AccessComplexity,
		PrivilegesRequired:    nvdCVE.Metrics.CvssMetricV2[0].CvssData.Authentication,
		UserInteraction:       "",
		Scope:                 "",
		ConfidentialityImpact: nvdCVE.Metrics.CvssMetricV2[0].CvssData.ConfidentialityImpact,
		IntegrityImpact:       nvdCVE.Metrics.CvssMetricV2[0].CvssData.IntegrityImpact,
		AvailabilityImpact:    nvdCVE.Metrics.CvssMetricV2[0].CvssData.AvailabilityImpact,
	}
}

func toDate(date *utils.Date) *datatypes.Date {
	if date == nil {
		return nil
	}
	t := datatypes.Date(*date)
	return &t
}

func fromNVDCVE(nistCVE nvdCVE) CVE {
	published, err := time.Parse(utils.ISO8601Format, nistCVE.Published)
	if err != nil {
		published = time.Now()
	}

	lastModified, err := time.Parse(utils.ISO8601Format, nistCVE.LastModified)
	if err != nil {
		slog.Error("Error while parsing last modified date", "err", err)
		lastModified = time.Now()
	}

	description := ""

	for _, d := range nistCVE.Descriptions {
		if d.Lang == "en" {
			description = d.Value
			break
		}
	}

	// build the cwe list
	weaknesses := []*Weakness{}
	configurations := []*CPEMatch{}

	for _, w := range nistCVE.Weaknesses {
		for _, d := range w.Description {
			if !strings.HasPrefix(d.Value, "CWE-") {
				// only handle CWES - just continue. The nist might give us other weaknesses
				continue
			}

			if d.Lang == "en" {
				weaknesses = append(weaknesses, &Weakness{
					Source: w.Source,
					Type:   w.Type,
					CWEID:  d.Value,
					CVEID:  nistCVE.ID,
				})
			}
		}
	}

	matchCriteriaIds := make(map[string]struct{})

	for _, c := range nistCVE.Configurations {
		for _, n := range c.Nodes {
			for _, m := range n.CpeMatch {
				// check if we already have that criteria
				if _, ok := matchCriteriaIds[m.MatchCriteriaID]; ok {
					continue
				}
				matchCriteriaIds[m.MatchCriteriaID] = struct{}{}
				cpe := fromNVDCPEMatch(m)
				configurations = append(configurations, &cpe)
			}
		}
	}

	cvssMetric := getCVSSMetric(nistCVE)

	// marshal the references
	refs, err := json.Marshal(nistCVE.References)
	if err != nil {
		slog.Error("Error while marshaling references", "err", err)
	}

	return CVE{
		CVE:              nistCVE.ID,
		DatePublished:    published,
		DateLastModified: lastModified,

		Description: description,

		Weaknesses: weaknesses,

		Severity:              Severity(cvssMetric.Severity),
		CVSS:                  cvssMetric.CVSS,
		ExploitabilityScore:   cvssMetric.ExploitabilityScore,
		ImpactScore:           cvssMetric.ImpactScore,
		AttackVector:          cvssMetric.AttackVector,
		AttackComplexity:      cvssMetric.AttackComplexity,
		PrivilegesRequired:    cvssMetric.PrivilegesRequired,
		UserInteraction:       cvssMetric.UserInteraction,
		Scope:                 cvssMetric.Scope,
		ConfidentialityImpact: cvssMetric.ConfidentialityImpact,
		IntegrityImpact:       cvssMetric.IntegrityImpact,
		AvailabilityImpact:    cvssMetric.AvailabilityImpact,

		CISAExploitAdd:        toDate(nistCVE.CISAExploitAdd),
		CISAActionDue:         toDate(nistCVE.CISAActionDue),
		CISARequiredAction:    nistCVE.CISARequiredAction,
		CISAVulnerabilityName: nistCVE.CISAVulnerabilityName,

		Configurations: configurations,

		References: string(refs),
	}

}

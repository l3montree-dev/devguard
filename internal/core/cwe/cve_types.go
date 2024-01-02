package cwe

import (
	"time"
)

type nistResponse struct {
	ResultsPerPage  int    `json:"resultsPerPage"`
	StartIndex      int    `json:"startIndex"`
	TotalResults    int    `json:"totalResults"`
	Format          string `json:"format"`
	Version         string `json:"version"`
	Timestamp       string `json:"timestamp"`
	Vulnerabilities []struct {
		Cve struct {
			ID               string `json:"id"`
			SourceIdentifier string `json:"sourceIdentifier"`
			Published        string `json:"published"`
			LastModified     string `json:"lastModified"`
			VulnStatus       string `json:"vulnStatus"`
			Descriptions     []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					Source   string `json:"source"`
					Type     string `json:"type"`
					CvssData struct {
						Version               string  `json:"version"`
						VectorString          string  `json:"vectorString"`
						AttackVector          string  `json:"attackVector"`
						AttackComplexity      string  `json:"attackComplexity"`
						PrivilegesRequired    string  `json:"privilegesRequired"`
						UserInteraction       string  `json:"userInteraction"`
						Scope                 string  `json:"scope"`
						ConfidentialityImpact string  `json:"confidentialityImpact"`
						IntegrityImpact       string  `json:"integrityImpact"`
						AvailabilityImpact    string  `json:"availabilityImpact"`
						BaseScore             float64 `json:"baseScore"`
						BaseSeverity          string  `json:"baseSeverity"`
					} `json:"cvssData"`
					ExploitabilityScore float64 `json:"exploitabilityScore"`
					ImpactScore         float64 `json:"impactScore"`
				} `json:"cvssMetricV31"`
				CvssMetricV2 []struct {
					Source   string `json:"source"`
					Type     string `json:"type"`
					CvssData struct {
						Version               string  `json:"version"`
						VectorString          string  `json:"vectorString"`
						AccessVector          string  `json:"accessVector"`
						AccessComplexity      string  `json:"accessComplexity"`
						Authentication        string  `json:"authentication"`
						ConfidentialityImpact string  `json:"confidentialityImpact"`
						IntegrityImpact       string  `json:"integrityImpact"`
						AvailabilityImpact    string  `json:"availabilityImpact"`
						BaseScore             float64 `json:"baseScore"`
					} `json:"cvssData"`
					BaseSeverity            string  `json:"baseSeverity"`
					ExploitabilityScore     float64 `json:"exploitabilityScore"`
					ImpactScore             float64 `json:"impactScore"`
					AcInsufInfo             bool    `json:"acInsufInfo"`
					ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
					ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
					ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
					UserInteractionRequired bool    `json:"userInteractionRequired"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
			Weaknesses []struct {
				Source      string `json:"source"`
				Type        string `json:"type"`
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					Operator string `json:"operator"`
					Negate   bool   `json:"negate"`
					CpeMatch []struct {
						Vulnerable          bool   `json:"vulnerable"`
						Criteria            string `json:"criteria"`
						VersionEndIncluding string `json:"versionEndIncluding"`
						MatchCriteriaID     string `json:"matchCriteriaId"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			References []struct {
				URL    string   `json:"url"`
				Source string   `json:"source"`
				Tags   []string `json:"tags"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func (r nistResponse) ToModel() CVEModel {
	nistCVE := r.Vulnerabilities[0].Cve
	published, err := time.Parse(time.RFC3339, nistCVE.Published)
	if err != nil {
		published = time.Now()
	}

	lastModified, err := time.Parse(time.RFC3339, nistCVE.LastModified)
	if err != nil {
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
	cwes := []*CWEModel{}

	for _, w := range nistCVE.Weaknesses {
		for _, d := range w.Description {
			if d.Lang == "en" {
				cwes = append(cwes, &CWEModel{
					CWE: d.Value,
				})
			}
		}
	}

	return CVEModel{
		CVE:              nistCVE.ID,
		DatePublished:    published,
		DateLastModified: lastModified,

		Description: description,

		CWEs: cwes,

		Severity:              Severity(nistCVE.Metrics.CvssMetricV31[0].CvssData.BaseSeverity),
		CVSS:                  float32(nistCVE.Metrics.CvssMetricV31[0].CvssData.BaseScore),
		ExploitabilityScore:   float32(nistCVE.Metrics.CvssMetricV31[0].ExploitabilityScore),
		ImpactScore:           float32(nistCVE.Metrics.CvssMetricV31[0].ImpactScore),
		AttackVector:          nistCVE.Metrics.CvssMetricV31[0].CvssData.AttackVector,
		AttackComplexity:      nistCVE.Metrics.CvssMetricV31[0].CvssData.AttackComplexity,
		PrivilegesRequired:    nistCVE.Metrics.CvssMetricV31[0].CvssData.PrivilegesRequired,
		UserInteraction:       nistCVE.Metrics.CvssMetricV31[0].CvssData.UserInteraction,
		Scope:                 nistCVE.Metrics.CvssMetricV31[0].CvssData.Scope,
		ConfidentialityImpact: nistCVE.Metrics.CvssMetricV31[0].CvssData.ConfidentialityImpact,
		IntegrityImpact:       nistCVE.Metrics.CvssMetricV31[0].CvssData.IntegrityImpact,
		AvailabilityImpact:    nistCVE.Metrics.CvssMetricV31[0].CvssData.AvailabilityImpact,
	}
}

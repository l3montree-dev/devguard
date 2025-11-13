package vulndb

import "github.com/l3montree-dev/devguard/internal/utils"

type nvdCpeMatch struct {
	Vulnerable bool   `json:"vulnerable"`
	Criteria   string `json:"criteria"`

	VersionEndExcluding   string `json:"versionEndExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
}

type nvdCVE struct {
	ID               string `json:"id"`
	SourceIdentifier string `json:"sourceIdentifier"`
	Published        string `json:"published"`
	LastModified     string `json:"lastModified"`
	VulnStatus       string `json:"vulnStatus"`
	Descriptions     []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	CISAExploitAdd        *utils.Date `json:"cisaExploitAdd"`
	CISAActionDue         *utils.Date `json:"cisaActionDue"`
	CISARequiredAction    string      `json:"cisaRequiredAction"`
	CISAVulnerabilityName string      `json:"cisaVulnerabilityName"`
	Metrics               struct {
		CvssMetricV40 []struct {
			Source   string `json:"source"`
			Type     string `json:"type"`
			CvssData struct {
				Version                           string  `json:"version"`
				VectorString                      string  `json:"vectorString"`
				BaseScore                         float64 `json:"baseScore"`
				BaseSeverity                      string  `json:"baseSeverity"`
				AttackVector                      string  `json:"attackVector"`
				AttackComplexity                  string  `json:"attackComplexity"`
				AttackRequirements                string  `json:"attackRequirements"`
				PrivilegesRequired                string  `json:"privilegesRequired"`
				UserInteraction                   string  `json:"userInteraction"`
				VulnConfidentialityImpact         string  `json:"vulnConfidentialityImpact"`
				VulnIntegrityImpact               string  `json:"vulnIntegrityImpact"`
				VulnAvailabilityImpact            string  `json:"vulnAvailabilityImpact"`
				SubConfidentialityImpact          string  `json:"subConfidentialityImpact"`
				SubIntegrityImpact                string  `json:"subIntegrityImpact"`
				SubAvailabilityImpact             string  `json:"subAvailabilityImpact"`
				ExploitMaturity                   string  `json:"exploitMaturity"`
				ConfidentialityRequirement        string  `json:"confidentialityRequirement"`
				IntegrityRequirement              string  `json:"integrityRequirement"`
				AvailabilityRequirement           string  `json:"availabilityRequirement"`
				ModifiedAttackVector              string  `json:"modifiedAttackVector"`
				ModifiedAttackComplexity          string  `json:"modifiedAttackComplexity"`
				ModifiedAttackRequirements        string  `json:"modifiedAttackRequirements"`
				ModifiedPrivilegesRequired        string  `json:"modifiedPrivilegesRequired"`
				ModifiedUserInteraction           string  `json:"modifiedUserInteraction"`
				ModifiedVulnConfidentialityImpact string  `json:"modifiedVulnConfidentialityImpact"`
				ModifiedVulnIntegrityImpact       string  `json:"modifiedVulnIntegrityImpact"`
				ModifiedVulnAvailabilityImpact    string  `json:"modifiedVulnAvailabilityImpact"`
				ModifiedSubConfidentialityImpact  string  `json:"modifiedSubConfidentialityImpact"`
				ModifiedSubIntegrityImpact        string  `json:"modifiedSubIntegrityImpact"`
				ModifiedSubAvailabilityImpact     string  `json:"modifiedSubAvailabilityImpact"`
				Safety                            string  `json:"Safety"`
				Automatable                       string  `json:"Automatable"`
				Recovery                          string  `json:"Recovery"`
				ValueDensity                      string  `json:"valueDensity"`
				VulnerabilityResponseEffort       string  `json:"vulnerabilityResponseEffort"`
				ProviderUrgency                   string  `json:"providerUrgency"`
			} `json:"cvssData"`
		} `json:"cvssMetricV40"`
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
			Operator string        `json:"operator"`
			Negate   bool          `json:"negate"`
			CpeMatch []nvdCpeMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL    string   `json:"url"`
		Source string   `json:"source"`
		Tags   []string `json:"tags"`
	} `json:"references"`
}

// this is the response from the NIST API
// https://services.nvd.nist.gov/rest/json/cves/2.0
type nistResponse struct {
	ResultsPerPage  int    `json:"resultsPerPage"`
	StartIndex      int    `json:"startIndex"`
	TotalResults    int    `json:"totalResults"`
	Format          string `json:"format"`
	Version         string `json:"version"`
	Timestamp       string `json:"timestamp"`
	Vulnerabilities []struct {
		Cve nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

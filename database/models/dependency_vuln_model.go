package models

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
)

type DependencyVuln struct {
	Vulnerability

	CVE   CVE    `json:"cve"`
	CVEID string `json:"cveId" gorm:"type:text;"`

	ComponentPurl         string   `json:"componentPurl" gorm:"type:text;"`
	ComponentFixedVersion *string  `json:"componentFixedVersion" gorm:"default:null;"`
	VulnerabilityPath     []string `json:"vulnerabilityPath" gorm:"type:jsonb;default:'[]';serializer:json"`

	Effort            *int     `json:"effort" gorm:"default:null;"`
	RiskAssessment    *int     `json:"riskAssessment" gorm:"default:null;"`
	RawRiskAssessment *float64 `json:"rawRiskAssessment" gorm:"default:null;"`

	Priority *int `json:"priority" gorm:"default:null;"`

	LastDetected time.Time `json:"lastDetected" gorm:"default:now();not null;"`

	RiskRecalculatedAt time.Time `json:"riskRecalculatedAt"`

	Artifacts []Artifact `json:"artifacts" gorm:"many2many:artifact_dependency_vulns;constraint:OnDelete:CASCADE"`
}

var _ Vuln = &DependencyVuln{}

func (vuln *DependencyVuln) GetScannerIDsOrArtifactNames() string {
	names := make([]string, 0, len(vuln.Artifacts))
	for _, artifact := range vuln.Artifacts {
		if artifact.ArtifactName != "" {
			names = append(names, artifact.ArtifactName)
		}
	}
	slices.Sort(names)
	return strings.Join(names, " ")
}

func (vuln *DependencyVuln) SetRawRiskAssessment(risk float64) {
	vuln.RawRiskAssessment = &risk
}

func (vuln *DependencyVuln) GetRawRiskAssessment() float64 {
	if vuln.RawRiskAssessment == nil {
		return 0.0
	}

	return *vuln.RawRiskAssessment
}

func (vuln *DependencyVuln) SetRiskRecalculatedAt(t time.Time) {
	vuln.RiskRecalculatedAt = t
}

func (vuln *DependencyVuln) GetType() dtos.VulnType {
	return dtos.VulnTypeDependencyVuln
}

func (vuln *DependencyVuln) GetArtifacts() []Artifact {
	return vuln.Artifacts
}

func (vuln DependencyVuln) AssetVersionIndependentHash() string {
	// Filter the path to only include actual package PURLs for hash calculation
	return utils.HashString(fmt.Sprintf("%s/%s/%s", strings.Join(vuln.VulnerabilityPath, ","), vuln.CVEID, vuln.AssetID))
}

func (vuln DependencyVuln) GetAssetVersionName() string {
	if vuln.AssetVersionName == "" {
		return vuln.AssetVersionName
	}
	return vuln.AssetVersionName
}

func (vuln DependencyVuln) GetEvents() []VulnEvent {
	if vuln.Events == nil {
		return []VulnEvent{}
	}
	return vuln.Events
}

type DependencyVulnRisk struct {
	DependencyVulnID  string
	CreatedAt         time.Time
	ArbitraryJSONData string
	Risk              float64
	Type              dtos.VulnEventType
}

func (vuln DependencyVuln) TableName() string {
	return "dependency_vulns"
}

func (vuln *DependencyVuln) CalculateHash() string {
	return utils.HashString(fmt.Sprintf("%s/%s/%s/%s", vuln.CVEID, vuln.AssetVersionName, vuln.AssetID, strings.Join(vuln.VulnerabilityPath, ",")))
}

// hook to calculate the hash before creating the dependencyVuln
func (vuln *DependencyVuln) BeforeSave(tx *gorm.DB) (err error) {
	hash := vuln.CalculateHash()
	vuln.ID = hash
	return nil
}

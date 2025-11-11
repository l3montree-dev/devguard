package models

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/l3montree-dev/devguard/internal/utils"
)

type VulnState string

const (
	VulnStateOpen              VulnState = "open"
	VulnStateFixed             VulnState = "fixed"         // we did not find the dependencyVuln anymore in the last scan!
	VulnStateAccepted          VulnState = "accepted"      // like ignore
	VulnStateFalsePositive     VulnState = "falsePositive" // we can use that for crowdsource vulnerability management. 27 People marked this as false positive and they have the same dependency tree - propably you are not either
	VulnStateMarkedForTransfer VulnState = "markedForTransfer"
)

type DependencyVuln struct {
	Vulnerability

	CVE   *CVE    `json:"cve"`
	CVEID *string `json:"cveId" gorm:"null;type:text;default:null;"`

	ComponentPurl         *string `json:"componentPurl" gorm:"type:text;default:null;"`
	ComponentDepth        *int    `json:"componentDepth" gorm:"default:null;"`
	ComponentFixedVersion *string `json:"componentFixedVersion" gorm:"default:null;"`

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
	artifactNames := ""
	for _, artifact := range vuln.Artifacts {
		if artifact.ArtifactName != "" {
			artifactNames += artifact.ArtifactName + " "
		}
	}
	return artifactNames
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

func (vuln *DependencyVuln) GetType() VulnType {
	return VulnTypeDependencyVuln
}

func (vuln *DependencyVuln) GetArtifacts() []Artifact {
	return vuln.Artifacts
}

func (vuln DependencyVuln) AssetVersionIndependentHash() string {
	if vuln.CVEID == nil {
		return utils.HashString(fmt.Sprintf("%s/%s/%s", utils.OrDefault(vuln.ComponentPurl, ""), vuln.AssetVersionName, vuln.AssetID))
	}
	return *vuln.CVEID
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
	Type              VulnEventType
}

func (vuln DependencyVuln) TableName() string {
	return "dependency_vulns"
}

func (vuln *DependencyVuln) CalculateHash() string {
	hash := utils.HashString(fmt.Sprintf("%s/%s/%s/%s", utils.OrDefault(vuln.CVEID, ""), utils.OrDefault(vuln.ComponentPurl, ""), vuln.AssetVersionName, vuln.AssetID))
	return hash
}

// hook to calculate the hash before creating the dependencyVuln
func (vuln *DependencyVuln) BeforeSave(tx *gorm.DB) (err error) {
	hash := vuln.CalculateHash()
	vuln.ID = hash
	return nil
}

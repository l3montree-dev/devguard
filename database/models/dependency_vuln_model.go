package models

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
)

func timeToCEL(t time.Time) string {
	return t.Format(time.RFC3339Nano)
}

// ptrToAny returns nil for a nil pointer, or the dereferenced value boxed as
// any otherwise - used by the ToCELMap family to match how json.Unmarshal
// represents an absent-vs-present-but-null field.
func ptrToAny[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

func stringSliceToAny(s []string) []any {
	if s == nil {
		return nil
	}
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

type DependencyVuln struct {
	Vulnerability

	Events []VulnEvent `gorm:"foreignKey:DependencyVulnID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE;" json:"events"`

	CVE                   *CVE    `json:"cve" gorm:"foreignKey:CVEID;references:CVE;"`
	CVEID                 string  `json:"cveId" gorm:"type:text;"`
	ComponentPurl         string  `json:"componentPurl" gorm:"type:text;"`
	ComponentFixedVersion *string `json:"componentFixedVersion" gorm:"default:null;"`

	DirectDependencyFixedVersion *string `json:"directDependencyFixedVersion" gorm:"default:null;"`

	VulnerabilityPath []string `json:"vulnerabilityPath" gorm:"type:jsonb;default:'[]';serializer:json"`

	RiskAssessment *float64 `json:"riskAssessment" gorm:"default:null;"`

	RiskRecalculatedAt time.Time `json:"riskRecalculatedAt"`

	Artifacts []Artifact `json:"artifacts" gorm:"many2many:artifact_dependency_vulns;constraint:OnDelete:CASCADE"`

	// hash of cve_id + vulnerability_path
	Signature int64 `json:"signature" gorm:"type:bigint;not null;index"`

	// hash of cve_id + vulnerability_path + asset_id
	// used by vuln events to deduplicate them.
	AssetSignature int64 `json:"assetSignature" gorm:"type:bigint;not null;index"`
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

// ArtifactPurls returns the purl devguard's own exports (CSAF, CycloneDX
// VEX) use to identify each of this vuln's artifacts as the root of its
// path - see normalize.Purlify. Used to strip that leading path segment
// again during VEX rule matching, since VulnerabilityPath itself never
// includes it.
func (vuln *DependencyVuln) ArtifactPurls() []string {
	identities := make([]string, 0, len(vuln.Artifacts))
	for _, artifact := range vuln.Artifacts {
		identities = append(identities, normalize.Purlify(artifact.ArtifactName, vuln.AssetVersionName))
	}
	return identities
}

// we need this to avoid json.Marshal and json.Unmarshal in the fast path of the vex rule recommendation daemon
func (vuln DependencyVuln) ToCELMap() map[string]any {
	m := map[string]any{
		// promoted from the embedded Vulnerability
		"id":                   vuln.ID.String(),
		"assetVersionName":     vuln.AssetVersionName,
		"vulnAssetId":          vuln.AssetID.String(),
		"state":                string(vuln.State),
		"lastStateChange":      timeToCEL(vuln.LastStateChange),
		"manualTicketCreation": vuln.ManualTicketCreation,
		"createdAt":            timeToCEL(vuln.CreatedAt),
		"updatedAt":            timeToCEL(vuln.UpdatedAt),

		// DependencyVuln's own fields
		"cveId":              vuln.CVEID,
		"componentPurl":      vuln.ComponentPurl,
		"vulnerabilityPath":  stringSliceToAny(vuln.VulnerabilityPath),
		"riskRecalculatedAt": timeToCEL(vuln.RiskRecalculatedAt),
		"signature":          float64(vuln.Signature),
		"assetSignature":     float64(vuln.AssetSignature),
	}

	m["ticketId"] = ptrToAny(vuln.TicketID)
	m["ticketUrl"] = ptrToAny(vuln.TicketURL)
	m["componentFixedVersion"] = ptrToAny(vuln.ComponentFixedVersion)
	m["directDependencyFixedVersion"] = ptrToAny(vuln.DirectDependencyFixedVersion)
	m["riskAssessment"] = ptrToAny(vuln.RiskAssessment)

	if vuln.CVE != nil {
		m["cve"] = vuln.CVE.ToCELMap()
	} else {
		m["cve"] = nil
	}

	return m
}

func (vuln *DependencyVuln) SetRawRiskAssessment(risk float64) {
	vuln.RiskAssessment = &risk
}

func (vuln *DependencyVuln) GetRawRiskAssessment() float64 {
	if vuln.RiskAssessment == nil {
		return 0.0
	}

	return *vuln.RiskAssessment
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

func (vuln DependencyVuln) CalculateAssetVersionIndependentHash() string {
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
	DependencyVulnID  uuid.UUID
	CreatedAt         time.Time
	ArbitraryJSONData string
	Risk              float64
	Type              dtos.VulnEventType
}

func (vuln DependencyVuln) TableName() string {
	return "dependency_vulns"
}

// GetCVE returns the CVE or a zero-value CVE if not loaded, preventing nil dereferences.
func (vuln DependencyVuln) GetCVE() CVE {
	if vuln.CVE == nil {
		return CVE{}
	}
	return *vuln.CVE
}

func (vuln *DependencyVuln) CalculateHash() uuid.UUID {
	return utils.HashToUUID(fmt.Sprintf("%s/%s/%s/%s", vuln.CVEID, vuln.AssetVersionName, vuln.AssetID, strings.Join(vuln.VulnerabilityPath, ",")))
}

func (vuln *DependencyVuln) CalculateSignature() int64 {
	return utils.HashToInt64(fmt.Sprintf("%s/%s", vuln.CVEID, strings.Join(vuln.VulnerabilityPath, ",")))
}

// hook to calculate the hash before creating the dependencyVuln
func (vuln *DependencyVuln) BeforeSave(tx *gorm.DB) (err error) {
	vuln.ID = vuln.CalculateHash()
	vuln.Signature = vuln.CalculateSignature()
	vuln.AssetSignature = utils.HashToInt64(vuln.CalculateAssetVersionIndependentHash())
	return nil
}

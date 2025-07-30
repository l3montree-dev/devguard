package core

import (
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type ManualMitigateEvent struct {
	Ctx           Context
	Justification string
}

type VulnEvent struct {
	Ctx   Context
	Event models.VulnEvent
}

type SBOMCreatedEvent struct {
	SBOM         *cdx.BOM
	Org          OrgObject
	Project      ProjectObject
	Asset        AssetObject
	AssetVersion AssetVersionObject
}

type DependencyVulnsDetectedEvent struct {
	Vulns        any // []vuln.DependencyVulnDTO
	Org          OrgObject
	Project      ProjectObject
	Asset        AssetObject
	AssetVersion AssetVersionObject
}

type FirstPartyVulnsDetectedEvent struct {
	Vulns        any //[]vuln.FirstPartyVulnDTO
	Org          OrgObject
	Project      ProjectObject
	Asset        AssetObject
	AssetVersion AssetVersionObject
}

type OrgObject struct {
	ID                       uuid.UUID `json:"id"`
	Name                     string    `json:"name"`
	ContactPhoneNumber       *string   `json:"contactPhoneNumber"`
	NumberOfEmployees        *int      `json:"numberOfEmployees"`
	Country                  *string   `json:"country"`
	Industry                 *string   `json:"industry"`
	CriticalInfrastructure   bool      `json:"criticalInfrastructure"`
	ISO27001                 bool      `json:"iso27001"`
	NIST                     bool      `json:"nist"`
	Grundschutz              bool      `json:"grundschutz"`
	Slug                     string    `json:"slug"`
	Description              string    `json:"description"`
	IsPublic                 bool      `json:"isPublic"`
	Language                 string    `json:"language"`
	ExternalEntityProviderID *string   `json:"externalEntityProviderId,omitempty"`
}

type ProjectObject struct {
	ID          uuid.UUID      `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Slug        string         `json:"slug"`
	ParentID    *uuid.UUID     `json:"parentId,omitempty"`
	Parent      *ProjectObject `json:"parent,omitempty"` // recursive structure
	IsPublic    bool           `json:"isPublic"`
	Type        string         `json:"type"`

	RepositoryID   *string `json:"repositoryId"`
	RepositoryName *string `json:"repositoryName"`

	ExternalEntityProviderID *string `json:"externalEntityProviderId,omitempty"`
	ExternalEntityID         *string `json:"externalEntityId,omitempty"`
}

type AssetObject struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	ProjectID   uuid.UUID `json:"projectId"`

	AvailabilityRequirement    string `json:"availabilityRequirement"`
	IntegrityRequirement       string `json:"integrityRequirement"`
	ConfidentialityRequirement string `json:"confidentialityRequirement"`
	ReachableFromInternet      bool   `json:"reachableFromInternet"`

	RepositoryID   *string `json:"repositoryId"`
	RepositoryName *string `json:"repositoryName"`

	LastSecretScan    *time.Time `json:"lastSecretScan"`
	LastSastScan      *time.Time `json:"lastSastScan"`
	LastScaScan       *time.Time `json:"lastScaScan"`
	LastIacScan       *time.Time `json:"lastIacScan"`
	LastContainerScan *time.Time `json:"lastContainerScan"`
	LastDastScan      *time.Time `json:"lastDastScan"`
	SigningPubKey     *string    `json:"signingPubKey"`

	EnableTicketRange            bool     `json:"enableTicketRange"`
	CVSSAutomaticTicketThreshold *float64 `json:"cvssAutomaticTicketThreshold"`
	RiskAutomaticTicketThreshold *float64 `json:"riskAutomaticTicketThreshold"`

	ExternalEntityProviderID *string `json:"externalEntityProviderId,omitempty"`
	ExternalEntityID         *string `json:"externalEntityId,omitempty"`
}

type AssetVersionObject struct {
	Name          string         `json:"name"`
	AssetID       uuid.UUID      `json:"assetId"`
	Slug          string         `json:"slug"`
	DefaultBranch bool           `json:"defaultBranch"`
	Type          string         `json:"type"`
	SigningPubKey *string        `json:"signingPubKey"`
	Metadata      map[string]any `json:"metadata"`
}

func ToAssetVersionObject(av models.AssetVersion) AssetVersionObject {
	return AssetVersionObject{
		Name:          av.Name,
		AssetID:       av.AssetID,
		Slug:          av.Slug,
		DefaultBranch: av.DefaultBranch,
		Type:          string(av.Type),
		SigningPubKey: av.SigningPubKey,
		Metadata:      av.Metadata,
	}
}

func ToAssetObject(a models.Asset) AssetObject {
	return AssetObject{
		ID:          a.ID,
		Name:        a.Name,
		Slug:        a.Slug,
		Description: a.Description,
		ProjectID:   a.ProjectID,

		AvailabilityRequirement:    string(a.AvailabilityRequirement),
		IntegrityRequirement:       string(a.IntegrityRequirement),
		ConfidentialityRequirement: string(a.ConfidentialityRequirement),
		ReachableFromInternet:      a.ReachableFromInternet,

		RepositoryID:   a.RepositoryID,
		RepositoryName: a.RepositoryName,

		SigningPubKey:                a.SigningPubKey,
		CVSSAutomaticTicketThreshold: a.CVSSAutomaticTicketThreshold,
		RiskAutomaticTicketThreshold: a.RiskAutomaticTicketThreshold,

		ExternalEntityProviderID: a.ExternalEntityProviderID,
		ExternalEntityID:         a.ExternalEntityID,
	}
}
func ToProjectObject(p models.Project) ProjectObject {
	return ProjectObject{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		Slug:        p.Slug,
		ParentID:    p.ParentID,
		Parent:      nil, // recursive structure not implemented here
		IsPublic:    p.IsPublic,
		Type:        string(p.Type),

		RepositoryID:   p.RepositoryID,
		RepositoryName: p.RepositoryName,

		ExternalEntityProviderID: p.ExternalEntityProviderID,
		ExternalEntityID:         p.ExternalEntityID,
	}
}

func ToOrgObject(o models.Org) OrgObject {

	return OrgObject{
		ID:                     o.ID,
		Name:                   o.Name,
		ContactPhoneNumber:     o.ContactPhoneNumber,
		NumberOfEmployees:      o.NumberOfEmployees,
		Country:                o.Country,
		Industry:               o.Industry,
		CriticalInfrastructure: o.CriticalInfrastructure,
		ISO27001:               o.ISO27001,
		NIST:                   o.NIST,
		Grundschutz:            o.Grundschutz,
		Description:            o.Description,
		IsPublic:               o.IsPublic,
		Slug:                   o.Slug,
		Language:               o.Language,
	}
}

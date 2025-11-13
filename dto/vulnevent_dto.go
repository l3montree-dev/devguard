package dtos

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type VulnEventDTO struct {
	ID       uuid.UUID            `json:"id"`
	Type     models.VulnEventType `json:"type"`
	VulnID   string               `json:"vulnId"`
	VulnType models.VulnType      `json:"vulnType"`
	UserID   string               `json:"userId"`

	Justification           *string                            `json:"justification"`
	MechanicalJustification models.MechanicalJustificationType `json:"mechanicalJustification"`

	ArbitraryJSONData map[string]any `json:"arbitraryJSONData"`

	CreatedAt time.Time `json:"createdAt"`

	AssetVersionName  string               `json:"assetVersionName"`
	AssetVersionSlug  string               `json:"assetVersionSlug"`
	VulnerabilityName string               `json:"vulnerabilityName"`
	PackageName       string               `json:"packageName"`
	URI               string               `json:"uri"`
	Upstream          models.UpstreamState `json:"upstream"`
}

func (dto VulnEventDTO) ToModel() models.VulnEvent {
	vulnID := dto.VulnID
	userID := dto.UserID

	return models.VulnEvent{
		Type:          dto.Type,
		VulnID:        vulnID,
		UserID:        userID,
		Justification: dto.Justification,
		VulnType:      dto.VulnType,
		Upstream:      dto.Upstream,
	}
}

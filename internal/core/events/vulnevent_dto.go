package events

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type VulnEventDTO struct {
	ID     uuid.UUID            `json:"id"`
	Type   models.VulnEventType `json:"type"`
	VulnID string               `json:"vulnId"`
	UserID string               `json:"userId"`

	Justification *string `json:"justification"`

	ArbitraryJsonData map[string]any `json:"arbitraryJsonData"`

	CreatedAt time.Time `json:"createdAt"`

	AssetVersionName string `json:"assetVersionName"`
	AssetVersionSlug string `json:"assetVersionSlug"`
}

func (dto VulnEventDTO) ToModel() models.VulnEvent {
	vulnId := dto.VulnID
	userId := dto.UserID

	return models.VulnEvent{
		Type:          dto.Type,
		VulnID:        vulnId,
		UserID:        userId,
		Justification: dto.Justification,
	}
}

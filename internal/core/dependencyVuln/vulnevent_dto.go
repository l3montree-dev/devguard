package dependencyVuln

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type VulnEventDTO struct {
	ID               uuid.UUID            `json:"id"`
	Type             models.VulnEventType `json:"type"`
	DependencyVulnID string               `json:"dependencyVulnId"`
	UserID           string               `json:"userId"`

	Justification *string `json:"justification"`

	ArbitraryJsonData map[string]any `json:"arbitraryJsonData"`

	CreatedAt time.Time `json:"createdAt"`

	AssetVersion string `json:"assetVersion"`
}

func (dto VulnEventDTO) ToModel() models.VulnEvent {
	dependencyVulnId := dto.DependencyVulnID
	userId := dto.UserID

	return models.VulnEvent{
		Type:             dto.Type,
		DependencyVulnID: dependencyVulnId,
		UserID:           userId,
		Justification:    dto.Justification,
	}
}

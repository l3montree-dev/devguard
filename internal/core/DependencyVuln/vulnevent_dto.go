package DependencyVuln

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type DependencyVulnEventDTO struct {
	ID               uuid.UUID                      `json:"id"`
	Type             models.DependencyVulnEventType `json:"type"`
	DependencyVulnID string                         `json:"dependencyVulnId"`
	UserID           string                         `json:"userId"`

	Justification *string `json:"justification"`

	ArbitraryJsonData map[string]any `json:"arbitraryJsonData"`

	CreatedAt time.Time `json:"createdAt"`
}

func (dto DependencyVulnEventDTO) ToModel() models.DependencyVulnEvent {
	dependencyVulnId := dto.DependencyVulnID
	userId := dto.UserID

	return models.DependencyVulnEvent{
		Type:             dto.Type,
		DependencyVulnID: dependencyVulnId,
		UserID:           userId,
		Justification:    dto.Justification,
	}
}

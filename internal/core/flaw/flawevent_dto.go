package flaw

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type FlawEventDTO struct {
	ID     uuid.UUID            `json:"id"`
	Type   models.FlawEventType `json:"type"`
	FlawID string               `json:"flawId"`
	UserID string               `json:"userId"`

	Justification *string `json:"justification"`

	ArbitraryJsonData map[string]any `json:"arbitraryJsonData"`

	CreatedAt time.Time `json:"createdAt"`

	AssetVersion string `json:"assetVersion"`
}

func (dto FlawEventDTO) ToModel() models.FlawEvent {
	flawId := dto.FlawID
	userId := dto.UserID

	return models.FlawEvent{
		Type:          dto.Type,
		FlawID:        flawId,
		UserID:        userId,
		Justification: dto.Justification,
	}
}

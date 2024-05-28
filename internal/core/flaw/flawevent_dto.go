package flaw

import (
	"github.com/l3montree-dev/flawfix/internal/database/models"
)

type FlawEventDTO struct {
	Type   models.FlawEventType `json:"type"`
	FlawID string               `json:"flawId"`
	UserID string               `json:"userId"`

	Justification *string `json:"justification"`
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

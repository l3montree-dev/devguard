package flaw

import (
	"encoding/json"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"gorm.io/datatypes"
)

type FlawEventDTO struct {
	Type   models.FlawEventType `json:"type"`
	FlawID string               `json:"flawId"`
	UserID string               `json:"userId"`

	Payload interface{} `json:"payload"`
}

func (dto FlawEventDTO) ToModel() models.FlawEvent {
	flawId := uuid.MustParse(dto.FlawID)
	userId := uuid.MustParse(dto.UserID)

	payload, err := json.Marshal(dto.Payload)

	if err != nil {
		panic(err)
	}

	jsonPayload := datatypes.JSON(payload)

	return models.FlawEvent{
		Type:   dto.Type,
		FlawID: flawId,
		UserID: userId,

		Payload: &jsonPayload,
	}
}

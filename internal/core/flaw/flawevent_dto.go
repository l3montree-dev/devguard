package flaw

import (
	"encoding/json"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type FlawEventDTO struct {
	Type   Type   `json:"type"`
	FlawID string `json:"flawId"`
	UserID string `json:"userId"`

	Payload interface{} `json:"payload"`
}

func (dto FlawEventDTO) ToModel() EventModel {
	flawId := uuid.MustParse(dto.FlawID)
	userId := uuid.MustParse(dto.UserID)

	payload, err := json.Marshal(dto.Payload)

	if err != nil {
		panic(err)
	}

	jsonPayload := datatypes.JSON(payload)

	return EventModel{
		Type:   dto.Type,
		FlawID: flawId,
		UserID: userId,

		Payload: &jsonPayload,
	}
}

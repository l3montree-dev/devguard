package flawevent

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
)

type Type string

const (
	EventTypeDetected Type = "detected"
	EventTypeFixed    Type = "fixed"
)

type Model struct {
	core.Model
	Type   Type      `json:"type" gorm:"type:varchar(255)"`
	FlawID uuid.UUID `json:"flawId"`
	UserID uuid.UUID `json:"userId"`
	EnvID  uuid.UUID `json:"envId"`
}

func (m Model) TableName() string {
	return "flaw_events"
}

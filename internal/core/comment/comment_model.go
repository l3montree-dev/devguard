package comment

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
)

type Model struct {
	core.Model
	FlawID  uuid.UUID `json:"flawId"`
	UserID  uuid.UUID `json:"userId"`
	Comment string    `json:"comment"`
	EnvID   uuid.UUID `json:"envId"`
}

func (m Model) TableName() string {
	return "comments"
}

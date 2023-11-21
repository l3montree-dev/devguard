package comment

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
)

type Model struct {
	core.Model
	FlawID  uuid.UUID `json:"resultId"`
	UserID  uuid.UUID `json:"userId"`
	Comment string    `json:"comment"`
}

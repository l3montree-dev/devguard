package env

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/flawevent"
)

type Model struct {
	core.Model
	Name          string            `json:"name" gorm:"type:varchar(255)"`
	Slug          string            `json:"slug" gorm:"type:varchar(255);uniqueIndex:idx_env_app_slug;not null;"`
	ApplicationID uuid.UUID         `json:"applicationId" gorm:"uniqueIndex:idx_env_app_slug;not null;"`
	IsDefault     bool              `json:"isDefault"`
	FlawEvents    []flawevent.Model `json:"flaws" gorm:"foreignKey:EnvID"`
}

func (m Model) TableName() string {
	return "envs"
}

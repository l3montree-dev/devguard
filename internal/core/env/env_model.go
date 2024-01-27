package env

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/flaw"
)

type Model struct {
	core.Model
	Name           string       `json:"name" gorm:"type:varchar(255)"`
	Slug           string       `json:"slug" gorm:"type:varchar(255);uniqueIndex:idx_env_app_slug;not null;"`
	AssetID        uuid.UUID    `json:"assetId" gorm:"uniqueIndex:idx_env_app_slug;not null;"`
	IsDefault      bool         `json:"isDefault"`
	Flaws          []flaw.Model `json:"flaws" gorm:"foreignKey:EnvID;constraint:OnDelete:CASCADE;"`
	LastReportTime time.Time    `json:"lastReportTimestamp"`
}

func (m Model) TableName() string {
	return "envs"
}

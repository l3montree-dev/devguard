package flaw

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/comment"
	"github.com/l3montree-dev/flawfix/internal/core/flawevent"
)

type Model struct {
	core.Model
	RuleID   string            `json:"ruleId" gorm:"uniqueIndex:idx_ruleId_env;not null;"`
	Level    *string           `json:"level"`
	Message  *string           `json:"message"`
	Comments []comment.Model   `gorm:"foreignKey:FlawID;constraint:OnDelete:CASCADE;" json:"comments"`
	Events   []flawevent.Model `gorm:"foreignKey:FlawID;constraint:OnDelete:CASCADE;" json:"events"`
	EnvID    uuid.UUID         `json:"envId" gorm:"uniqueIndex:idx_ruleId_env;not null;"`
}

func (m Model) TableName() string {
	return "flaws"
}

type ModelWithLastEvent struct {
	Model
	LastEvent flawevent.Model `json:"lastEvent"`
}

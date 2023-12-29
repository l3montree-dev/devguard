package flaw

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/comment"
	"github.com/l3montree-dev/flawfix/internal/core/flawevent"
)

type Model struct {
	core.Model
	RuleID   *string           `json:"ruleId"`
	Level    *string           `json:"level"`
	Message  *string           `json:"message"`
	Comments []comment.Model   `gorm:"foreignKey:FlawID"`
	Events   []flawevent.Model `gorm:"foreignKey:FlawID"`
}

func (m Model) TableName() string {
	return "flaws"
}

package flaw

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/comment"
	"github.com/l3montree-dev/flawfix/internal/core/cwe"
)

type State string

const (
	StateOpen                State = "open"
	StateFixed               State = "fixed"
	StateAccepted            State = "accepted"
	StateMarkedForMitigation State = "markedForMitigation"
	StateFalsePositive       State = "falsePositive"
)

type Model struct {
	core.Model
	RuleID   string          `json:"ruleId" gorm:"uniqueIndex:idx_ruleId_env;not null;"`
	Message  *string         `json:"message"`
	Comments []comment.Model `gorm:"foreignKey:FlawID;constraint:OnDelete:CASCADE;" json:"comments"`
	Events   []EventModel    `gorm:"foreignKey:FlawID;constraint:OnDelete:CASCADE;" json:"events"`
	EnvID    uuid.UUID       `json:"envId" gorm:"uniqueIndex:idx_ruleId_env;not null;"`
	State    State           `json:"state" gorm:"default:'open';not null;type:varchar(255);"`

	CVE   *cwe.CVEModel `json:"cve"`
	CVEID string        `json:"cveId" gorm:"null;type:varchar(255);default:null;"`

	Effort            *int `json:"effort" gorm:"default:null;"`
	RiskAssessment    *int `json:"riskAssessment" gorm:"default:null;"`
	RawRiskAssessment *int `json:"rawRiskAssessment" gorm:"default:null;"`

	Priority *int `json:"priority" gorm:"default:null;"`
}

func (m Model) TableName() string {
	return "flaws"
}

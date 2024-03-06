package flaw

import (
	"encoding/json"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/comment"
	"github.com/l3montree-dev/flawfix/internal/core/vulndb"
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
	RuleID   string          `json:"ruleId" gorm:"uniqueIndex:idx_ruleId_asset;not null;"`
	Message  *string         `json:"message"`
	Comments []comment.Model `gorm:"foreignKey:FlawID;constraint:OnDelete:CASCADE;" json:"comments"`
	Events   []EventModel    `gorm:"foreignKey:FlawID;constraint:OnDelete:CASCADE;" json:"events"`
	AssetID  uuid.UUID       `json:"assetId" gorm:"uniqueIndex:idx_ruleId_asset;not null;"`
	State    State           `json:"state" gorm:"default:'open';not null;type:text;"`

	CVE   *vulndb.CVE `json:"cve"`
	CVEID string      `json:"cveId" gorm:"null;type:text;default:null;"`

	Effort            *int `json:"effort" gorm:"default:null;"`
	RiskAssessment    *int `json:"riskAssessment" gorm:"default:null;"`
	RawRiskAssessment *int `json:"rawRiskAssessment" gorm:"default:null;"`

	Priority *int `json:"priority" gorm:"default:null;"`

	AdditionalData string `json:"additionalData" gorm:"type:text;"`

	// this is a map of additional data that is parsed from the AdditionalData field
	// this is not stored in the database - it just caches the parsed data
	additionalData map[string]any
}

func (m Model) TableName() string {
	return "flaws"
}

func (m *Model) GetAdditionalData() map[string]any {
	// parse the additional data
	if m.additionalData == nil {
		m.additionalData = make(map[string]any)
		err := json.Unmarshal([]byte(m.AdditionalData), &m.additionalData)
		if err != nil {
			slog.Error("could not parse additional data", "err", err, "flawId", m.ID)
		}
	}
	return m.additionalData
}

func (m *Model) SetAdditionalData(data map[string]any) {
	m.additionalData = data
	// parse the additional data
	dataBytes, err := json.Marshal(m.additionalData)
	if err != nil {
		slog.Error("could not marshal additional data", "err", err, "flawId", m.ID)
	}
	m.AdditionalData = string(dataBytes)
}

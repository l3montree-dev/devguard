package models

import (
	"encoding/json"
	"log/slog"

	"github.com/google/uuid"
)

type State string

const (
	StateOpen                State = "open"
	StateFixed               State = "fixed"
	StateAccepted            State = "accepted"
	StateMarkedForMitigation State = "markedForMitigation"
	StateFalsePositive       State = "falsePositive"
)

type Flaw struct {
	Model
	// the scanner which was used to detect this flaw
	ScannerID string `json:"scanner" gorm:"uniqueIndex:idx_ruleId_scanner_asset;not null;"`

	Message  *string     `json:"message"`
	Comments []Comment   `gorm:"foreignKey:FlawID;constraint:OnDelete:CASCADE;" json:"comments"`
	Events   []FlawEvent `gorm:"foreignKey:FlawID;constraint:OnDelete:CASCADE;" json:"events"`
	AssetID  uuid.UUID   `json:"assetId" gorm:"uniqueIndex:idx_ruleId_scanner_asset;not null;"`
	State    State       `json:"state" gorm:"default:'open';not null;type:text;"`

	CVE   *CVE   `json:"cve"`
	CVEID string `json:"cveId" gorm:"null;type:text;default:null;"`

	Effort            *int `json:"effort" gorm:"default:null;"`
	RiskAssessment    *int `json:"riskAssessment" gorm:"default:null;"`
	RawRiskAssessment *int `json:"rawRiskAssessment" gorm:"default:null;"`

	Priority *int `json:"priority" gorm:"default:null;"`

	AdditionalData string `json:"additionalData" gorm:"type:text;"`

	// this is a map of additional data that is parsed from the AdditionalData field
	// this is not stored in the database - it just caches the parsed data
	additionalData map[string]any
}

func (m Flaw) TableName() string {
	return "flaws"
}

func (m *Flaw) GetAdditionalData() map[string]any {
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

func (m *Flaw) SetAdditionalData(data map[string]any) {
	m.additionalData = data
	// parse the additional data
	dataBytes, err := json.Marshal(m.additionalData)
	if err != nil {
		slog.Error("could not marshal additional data", "err", err, "flawId", m.ID)
	}
	m.AdditionalData = string(dataBytes)
}

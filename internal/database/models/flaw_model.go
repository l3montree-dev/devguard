package models

import (
	"database/sql"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/l3montree-dev/devguard/internal/utils"
)

type FlawState string

const (
	FlawStateOpen              FlawState = "open"
	FlawStateFixed             FlawState = "fixed"         // we did not find the flaw anymore in the last scan!
	FlawStateAccepted          FlawState = "accepted"      // like ignore
	FlawStateFalsePositive     FlawState = "falsePositive" // we can use that for crowdsource vulnerability management. 27 People marked this as false positive and they have the same dependency tree - propably you are not either
	FlawStateMarkedForTransfer FlawState = "markedForTransfer"
)

type Flaw struct {
	ID string `json:"id" gorm:"primaryKey;not null;"`
	// the scanner which was used to detect this flaw
	ScannerID string `json:"scanner" gorm:"not null;"`

	//TODO: add not null constraint
	AssetID string `json:"flawAssetId" gorm:"not null;"`

	Message          *string     `json:"message"`
	Comments         []Comment   `gorm:"foreignKey:FlawID;constraint:OnDelete:CASCADE;" json:"comments"`
	Events           []FlawEvent `gorm:"foreignKey:FlawID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE;" json:"events"`
	AssetVersionName string      `json:"assetVersionName" gorm:"not null;"`
	State            FlawState   `json:"state" gorm:"default:'open';not null;type:text;"`

	CVE   *CVE    `json:"cve"`
	CVEID *string `json:"cveId" gorm:"null;type:text;default:null;"`

	ComponentPurl         *string `json:"componentPurl" gorm:"type:text;default:null;"`
	ComponentDepth        *int    `json:"componentDepth" gorm:"default:null;"`
	ComponentFixedVersion *string `json:"componentFixedVersion" gorm:"default:null;"`

	Effort            *int     `json:"effort" gorm:"default:null;"`
	RiskAssessment    *int     `json:"riskAssessment" gorm:"default:null;"`
	RawRiskAssessment *float64 `json:"rawRiskAssessment" gorm:"default:null;"`

	Priority *int `json:"priority" gorm:"default:null;"`

	LastDetected time.Time `json:"lastDetected" gorm:"default:now();not null;"`

	TicketID  *string `json:"ticketId" gorm:"default:null;"` // might be set by integrations
	TicketURL *string `json:"ticketUrl" gorm:"default:null;"`

	CreatedAt time.Time    `json:"createdAt"`
	UpdatedAt time.Time    `json:"updatedAt"`
	DeletedAt sql.NullTime `gorm:"index" json:"-"`

	RiskRecalculatedAt time.Time `json:"riskRecalculatedAt" gorm:"default:now();"`
}

type FlawRisk struct {
	FlawID            string
	CreatedAt         time.Time
	ArbitraryJsonData string
	Risk              float64
	Type              FlawEventType
}

func (m Flaw) TableName() string {
	return "flaws"
}

func (m *Flaw) CalculateHash(id string) string {
	hash := utils.HashString(fmt.Sprintf("%s/%s/%s/%s", *m.CVEID, *m.ComponentPurl, m.ScannerID, id))
	return hash
}

// hook to calculate the hash before creating the flaw
func (f *Flaw) BeforeSave(tx *gorm.DB) (err error) {
	hash := f.CalculateHash(string(f.AssetVersionName + f.AssetID))
	f.ID = hash
	return nil
}

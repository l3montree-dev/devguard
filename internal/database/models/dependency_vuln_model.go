package models

import (
	"database/sql"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type DependencyVulnState string

const (
	DependencyVulnStateOpen              DependencyVulnState = "open"
	DependencyVulnStateFixed             DependencyVulnState = "fixed"         // we did not find the dependencyVuln anymore in the last scan!
	DependencyVulnStateAccepted          DependencyVulnState = "accepted"      // like ignore
	DependencyVulnStateFalsePositive     DependencyVulnState = "falsePositive" // we can use that for crowdsource vulnerability management. 27 People marked this as false positive and they have the same dependency tree - propably you are not either
	DependencyVulnStateMarkedForTransfer DependencyVulnState = "markedForTransfer"
)

type DependencyVuln struct {
	ID string `json:"id" gorm:"primaryKey;not null;"`
	// the scanner which was used to detect this dependencyVuln
	ScannerID string `json:"scanner" gorm:"not null;"`

	AssetVersionName string       `json:"assetVersionName" gorm:"not null;"`
	AssetID          uuid.UUID    `json:"dependencyVulnAssetId" gorm:"not null;"`
	AssetVersion     AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`

	Message  *string             `json:"message"`
	Comments []Comment           `gorm:"foreignKey:DependencyVulnID;constraint:OnDelete:CASCADE;" json:"comments"`
	Events   []VulnEvent         `gorm:"foreignKey:DependencyVulnID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE;" json:"events"`
	State    DependencyVulnState `json:"state" gorm:"default:'open';not null;type:text;"`

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
	TicketID     *string   `json:"ticketId" gorm:"default:null;"` // might be set by integrations
	TicketURL    *string   `json:"ticketUrl" gorm:"default:null;"`

	CreatedAt time.Time    `json:"createdAt"`
	UpdatedAt time.Time    `json:"updatedAt"`
	DeletedAt sql.NullTime `gorm:"index" json:"-"`

	RiskRecalculatedAt time.Time `json:"riskRecalculatedAt" gorm:"default:now();"`
}

type DependencyVulnRisk struct {
	DependencyVulnID  string
	CreatedAt         time.Time
	ArbitraryJsonData string
	Risk              float64
	Type              VulnEventType
}

func (m DependencyVuln) TableName() string {
	return "dependencyVulns"
}

func (m *DependencyVuln) CalculateHash() string {
	hash := utils.HashString(fmt.Sprintf("%s/%s/%s/%s/%s", *m.CVEID, *m.ComponentPurl, m.ScannerID, m.AssetVersionName, m.AssetID))
	return hash
}

// hook to calculate the hash before creating the dependencyVuln
func (f *DependencyVuln) BeforeSave(tx *gorm.DB) (err error) {
	hash := f.CalculateHash()
	f.ID = hash
	return nil
}

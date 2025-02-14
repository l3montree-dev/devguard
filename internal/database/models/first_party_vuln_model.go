package models

import (
	"database/sql"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/utils"
	"gorm.io/gorm"
)

type Vulnerability struct {
	ID string `json:"id" gorm:"primaryKey;not null;"`

	Message *string `json:"message"`

	// the scanner which was used to detect this dependencyVuln
	ScannerID string `json:"scanner" gorm:"not null;"`

	Events  []VulnEvent `gorm:"foreignKey:DependencyVulnID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE;" json:"events"`
	AssetID uuid.UUID   `json:"assetId" gorm:"not null;type:uuid;"`
	State   VulnState   `json:"state" gorm:"default:'open';not null;type:text;"`

	LastDetected time.Time `json:"lastDetected" gorm:"default:now();not null;"`

	TicketID  *string `json:"ticketId" gorm:"default:null;"` // might be set by integrations
	TicketURL *string `json:"ticketUrl" gorm:"default:null;"`

	CreatedAt time.Time    `json:"createdAt"`
	UpdatedAt time.Time    `json:"updatedAt"`
	DeletedAt sql.NullTime `gorm:"index" json:"-"`
}

type FirstPartyVulnerability struct {
	Vulnerability
	RuleID      string `json:"ruleId"`
	Uri         string `json:"uri"`
	StartLine   int    `json:"startLine" `
	StartColumn int    `json:"startColumn"`
	EndLine     int    `json:"endLine"`
	EndColumn   int    `json:"endColumn"`
	Snippet     string `json:"snippet"`
}

func (f FirstPartyVulnerability) TableName() string {
	return "first_party_vulnerabilities"
}

func (m *FirstPartyVulnerability) CalculateHash() string {

	startLineStr := strconv.Itoa(m.StartLine)
	startColumnStr := strconv.Itoa(m.StartColumn)

	hash := utils.HashString(startLineStr + startColumnStr + m.RuleID + m.Uri + m.ScannerID + m.AssetID.String())
	m.ID = hash
	return hash
}

func (f *FirstPartyVulnerability) BeforeSave(tx *gorm.DB) (err error) {
	hash := f.CalculateHash()
	f.ID = hash
	return nil
}

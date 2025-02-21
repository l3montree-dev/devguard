package models

import (
	"database/sql"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/utils"
	"gorm.io/gorm"
)

type Vuln interface {
	SetState(state VulnState)
	SetRawRiskAssessment(risk float64)
	SetRiskRecalculatedAt(time.Time)
	GetRawRiskAssessment() float64
	GetAssetVersionName() string
	GetAssetID() uuid.UUID
	GetID() string
}

type Vulnerability struct {
	ID string `json:"id" gorm:"primaryKey;not null;"`

	AssetVersionName string       `json:"assetVersionName" gorm:"not null;"`
	AssetID          uuid.UUID    `json:"flawAssetId" gorm:"not null;"`
	AssetVersion     AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`

	Message *string `json:"message"`

	// the scanner which was used to detect this dependencyVuln
	ScannerID string `json:"scanner" gorm:"not null;"`

	Events []VulnEvent `gorm:"foreignKey:VulnID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE;" json:"events"`

	State VulnState `json:"state" gorm:"default:'open';not null;type:text;"`

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
	Commit      string `json:"commit"`
	Email       string `json:"email"`
	Author      string `json:"author"`
	Date        string `json:"date"`
}

func (d *Vulnerability) SetState(state VulnState) {
	d.State = state
}

func (d *Vulnerability) SetRawRiskAssessment(risk float64) {
	// do nothing
}

func (d *DependencyVuln) SetRawRiskAssessment(risk float64) {
	d.RawRiskAssessment = &risk
}

func (d *Vulnerability) GetRawRiskAssessment() float64 {
	return 0
}

func (d *DependencyVuln) GetRawRiskAssessment() float64 {
	return *d.RawRiskAssessment
}

func (d *Vulnerability) GetAssetVersionName() string {
	return d.AssetVersionName
}

func (d *Vulnerability) GetAssetID() uuid.UUID {
	return d.AssetID
}

func (d *Vulnerability) GetID() string {
	return d.ID
}

func (d *Vulnerability) SetRiskRecalculatedAt(t time.Time) {

}

func (d *DependencyVuln) SetRiskRecalculatedAt(t time.Time) {
	d.RiskRecalculatedAt = t
}

var _ Vuln = &FirstPartyVulnerability{}
var _ Vuln = &DependencyVuln{}

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

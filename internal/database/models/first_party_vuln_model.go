package models

import (
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/utils"
	"gorm.io/gorm"
)

type Vuln interface {
	SetState(state VulnState)
	GetState() VulnState
	SetTicketState(state TicketState)
	SetRawRiskAssessment(risk float64)
	SetRiskRecalculatedAt(time.Time)
	GetRawRiskAssessment() float64
	GetAssetVersionName() string
	GetAssetID() uuid.UUID
	GetID() string
	TableName() string
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

var _ Vuln = &FirstPartyVulnerability{}

func (f FirstPartyVulnerability) TableName() string {
	return "first_party_vulnerabilities"
}

func (m *FirstPartyVulnerability) CalculateHash() string {

	startLineStr := strconv.Itoa(m.StartLine)
	endLineStr := strconv.Itoa(m.EndLine)
	startColumnStr := strconv.Itoa(m.StartColumn)
	endColumnStr := strconv.Itoa(m.EndColumn)

	hash := utils.HashString(startLineStr + endLineStr + startColumnStr + endColumnStr + m.RuleID + m.Uri + m.ScannerID + m.AssetID.String() + m.AssetVersionName)
	m.ID = hash
	return hash
}

func (f *FirstPartyVulnerability) BeforeSave(tx *gorm.DB) (err error) {
	hash := f.CalculateHash()
	f.ID = hash
	return nil
}

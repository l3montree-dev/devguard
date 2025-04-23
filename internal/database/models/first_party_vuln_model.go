package models

import (
	"strconv"

	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/utils"
	"gorm.io/gorm"
)

type FirstPartyVulnerability struct {
	Vulnerability
	RuleID          string         `json:"ruleId"`
	RuleName        string         `json:"ruleName"`
	RuleDescription string         `json:"ruleDescription"`
	RuleHelp        string         `json:"ruleHelp"`
	RuleHelpUri     string         `json:"ruleHelpUri"`
	RuleProperties  database.JSONB `json:"ruleProperties" gorm:"type:jsonb"`

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

	hash := utils.HashString(startLineStr + "/" + endLineStr + "/" + startColumnStr + "/" + endColumnStr + "/" + m.RuleID + "/" + m.Uri + "/" + m.ScannerIDs + "/" + m.AssetID.String() + "/" + m.AssetVersionName)
	m.ID = hash
	return hash
}

func (f *FirstPartyVulnerability) BeforeSave(tx *gorm.DB) (err error) {
	hash := f.CalculateHash()
	f.ID = hash
	return nil
}

package models

import (
	"fmt"

	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type FirstPartyVuln struct {
	Vulnerability
	// the scanner which was used to detect this firstPartyVuln
	ScannerIDs      string         `json:"scannerIds" gorm:"not null;column:scanner_ids"` //List of scanner ids separated by a white space
	Fingerprint     string         `json:"fingerprint" gorm:"type:text;"`
	RuleID          string         `json:"ruleId"`
	RuleName        string         `json:"ruleName"`
	RuleDescription string         `json:"ruleDescription"`
	RuleHelp        string         `json:"ruleHelp"`
	RuleHelpURI     string         `json:"ruleHelpUri"`
	RuleProperties  database.JSONB `json:"ruleProperties" gorm:"type:jsonb"`

	URI string `json:"uri"`

	Commit string `json:"commit"`
	Email  string `json:"email"`
	Author string `json:"author"`
	Date   string `json:"date"`

	SnippetContents database.JSONB `json:"snippetContents" gorm:"type:jsonb;snippet_contents"` // SnippetContents
}

func (firstPartyVuln *FirstPartyVuln) AddScannerID(scannerID string) {
	firstPartyVuln.ScannerIDs = utils.AddToWhitespaceSeparatedStringList(firstPartyVuln.ScannerIDs, scannerID)
}

func (firstPartyVuln *FirstPartyVuln) GetArtifacts() []Artifact {
	return []Artifact{}
}

func (firstPartyVuln *FirstPartyVuln) RemoveScannerID(scannerID string) {
	firstPartyVuln.ScannerIDs = utils.RemoveFromWhitespaceSeparatedStringList(firstPartyVuln.ScannerIDs, scannerID)
}

func (firstPartyVuln *FirstPartyVuln) GetScannerIDsOrArtifactNames() string {
	return firstPartyVuln.ScannerIDs
}

var _ Vuln = &FirstPartyVuln{}

func (firstPartyVuln *FirstPartyVuln) GetType() dtos.VulnType {
	return dtos.VulnTypeFirstPartyVuln
}

func (firstPartyVuln FirstPartyVuln) TableName() string {
	return "first_party_vulnerabilities"
}

func (firstPartyVuln *FirstPartyVuln) CalculateHash() string {

	hash := firstPartyVuln.Fingerprint
	if hash == "" {
		stringToHash := firstPartyVuln.RuleID + "/" + firstPartyVuln.URI + "/" + firstPartyVuln.ScannerIDs + "/" + firstPartyVuln.AssetID.String() + "/" + firstPartyVuln.AssetVersionName
		hash = utils.HashString(stringToHash)
	}
	firstPartyVuln.ID = hash
	return hash
}

func (firstPartyVuln FirstPartyVuln) AssetVersionIndependentHash() string {
	stringToHash := firstPartyVuln.RuleID + "/" + firstPartyVuln.URI
	hash := utils.HashString(stringToHash)
	return hash
}

func (firstPartyVuln FirstPartyVuln) GetAssetVersionName() string {
	return firstPartyVuln.AssetVersionName
}

func (firstPartyVuln FirstPartyVuln) GetEvents() []VulnEvent {
	return firstPartyVuln.Events
}

func (firstPartyVuln *FirstPartyVuln) BeforeSave(tx *gorm.DB) (err error) {
	hash := firstPartyVuln.CalculateHash()
	firstPartyVuln.ID = hash
	return nil
}

func (firstPartyVuln *FirstPartyVuln) Title() string {
	if firstPartyVuln.URI == "" {
		return firstPartyVuln.RuleName
	}

	return fmt.Sprintf("%s found in %s", firstPartyVuln.RuleName, firstPartyVuln.URI)
}

package models

import (
	"fmt"

	"github.com/google/uuid"

	databasetypes "github.com/l3montree-dev/devguard/database/types"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type FirstPartyVuln struct {
	Vulnerability

	Events []VulnEvent `gorm:"foreignKey:FirstPartyVulnID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE;" json:"events"`

	// the scanner which was used to detect this firstPartyVuln
	ScannerIDs      string              `json:"scannerIds" gorm:"not null;column:scanner_ids"` //List of scanner ids separated by a white space
	Fingerprint     string              `json:"fingerprint" gorm:"type:text;"`
	RuleID          string              `json:"ruleId"`
	RuleName        string              `json:"ruleName"`
	RuleDescription string              `json:"ruleDescription"`
	RuleHelp        string              `json:"ruleHelp"`
	RuleHelpURI     string              `json:"ruleHelpUri"`
	RuleProperties  databasetypes.JSONB `json:"ruleProperties" gorm:"type:jsonb"`

	URI string `json:"uri"`

	Commit string `json:"commit"`
	Email  string `json:"email"`
	Author string `json:"author"`
	Date   string `json:"date"`

	SnippetContents databasetypes.JSONB `json:"snippetContents" gorm:"type:jsonb;snippet_contents"` // SnippetContents
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

func (firstPartyVuln *FirstPartyVuln) CalculateHash() uuid.UUID {
	stringToHash := firstPartyVuln.Fingerprint
	if stringToHash == "" {
		stringToHash = firstPartyVuln.RuleID + "/" + firstPartyVuln.URI + "/" + firstPartyVuln.ScannerIDs + "/" + firstPartyVuln.AssetID.String() + "/" + firstPartyVuln.AssetVersionName
	}
	id := utils.HashToUUID(stringToHash)
	firstPartyVuln.ID = id
	return id
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
	firstPartyVuln.ID = firstPartyVuln.CalculateHash()
	return nil
}

func (firstPartyVuln *FirstPartyVuln) Title() string {
	if firstPartyVuln.URI == "" {
		return firstPartyVuln.RuleName
	}

	return fmt.Sprintf("%s found in %s", firstPartyVuln.RuleName, firstPartyVuln.URI)
}

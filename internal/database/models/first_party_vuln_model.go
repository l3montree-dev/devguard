package models

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/utils"
	"gorm.io/gorm"
)

type FirstPartyVuln struct {
	Vulnerability
	RuleID          string         `json:"ruleId"`
	RuleName        string         `json:"ruleName"`
	RuleDescription string         `json:"ruleDescription"`
	RuleHelp        string         `json:"ruleHelp"`
	RuleHelpURI     string         `json:"ruleHelpUri"`
	RuleProperties  database.JSONB `json:"ruleProperties" gorm:"type:jsonb"`

	URI         string `json:"uri"`
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

var _ Vuln = &FirstPartyVuln{}

func (firstPartyVuln *FirstPartyVuln) GetType() VulnType {
	return VulnTypeFirstPartyVuln
}

func (firstPartyVuln FirstPartyVuln) TableName() string {
	return "first_party_vulnerabilities"
}

func (firstPartyVuln *FirstPartyVuln) CalculateHash() string {
	startLineStr := strconv.Itoa(firstPartyVuln.StartLine)
	endLineStr := strconv.Itoa(firstPartyVuln.EndLine)
	startColumnStr := strconv.Itoa(firstPartyVuln.StartColumn)
	endColumnStr := strconv.Itoa(firstPartyVuln.EndColumn)
	stringToHash := startLineStr + "/" + endLineStr + "/" + startColumnStr + "/" + endColumnStr + "/" + firstPartyVuln.RuleID + "/" + firstPartyVuln.URI + "/" + firstPartyVuln.ScannerIDs + "/" + firstPartyVuln.AssetID.String() + "/" + firstPartyVuln.AssetVersionName
	hash := utils.HashString(stringToHash)
	firstPartyVuln.ID = hash
	return hash
}

func (firstPartyVuln *FirstPartyVuln) BeforeSave(tx *gorm.DB) (err error) {
	hash := firstPartyVuln.CalculateHash()
	firstPartyVuln.ID = hash
	return nil
}

func (firstPartyVuln *FirstPartyVuln) RenderMarkdown() string {
	var str strings.Builder
	str.WriteString(*firstPartyVuln.Message)
	// check if there is a filename and snippet - if so, we can render that as well
	if firstPartyVuln.Snippet != "" {
		str.WriteString("\n\n")
		str.WriteString("```")
		str.WriteString("\n")
		str.WriteString(firstPartyVuln.Snippet)
		str.WriteString("\n")
		str.WriteString("```")
	}

	if firstPartyVuln.URI != "" {
		str.WriteString("\n\n")
		str.WriteString("File: ")
		var link string
		if firstPartyVuln.StartLine != 0 {
			link = fmt.Sprintf("[%s](%s%s)", firstPartyVuln.URI, strings.TrimPrefix(firstPartyVuln.URI, "/"), fmt.Sprintf("#L%d", firstPartyVuln.StartLine))
		} else {
			link = fmt.Sprintf("[%s](%s)", firstPartyVuln.URI, strings.TrimPrefix(firstPartyVuln.URI, "/"))
		}

		str.WriteString(link)
		str.WriteString("\n")
	}

	common.AddSlashCommandsToFirstPartyVuln(&str)

	return str.String()
}

func (firstPartyVuln *FirstPartyVuln) Title() string {
	if firstPartyVuln.URI == "" {
		return firstPartyVuln.RuleName
	}

	return fmt.Sprintf("%s found in %s", firstPartyVuln.RuleName, firstPartyVuln.URI)
}

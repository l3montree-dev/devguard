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

var _ Vuln = &FirstPartyVuln{}

func (f *FirstPartyVuln) GetType() VulnType {
	return VulnTypeFirstPartyVuln
}

func (f FirstPartyVuln) TableName() string {
	return "first_party_vulnerabilities"
}

func (m *FirstPartyVuln) CalculateHash() string {
	startLineStr := strconv.Itoa(m.StartLine)
	endLineStr := strconv.Itoa(m.EndLine)
	startColumnStr := strconv.Itoa(m.StartColumn)
	endColumnStr := strconv.Itoa(m.EndColumn)

	hash := utils.HashString(startLineStr + "/" + endLineStr + "/" + startColumnStr + "/" + endColumnStr + "/" + m.RuleID + "/" + m.Uri + "/" + m.ScannerIDs + "/" + m.AssetID.String() + "/" + m.AssetVersionName)
	m.ID = hash
	return hash
}

func (f *FirstPartyVuln) BeforeSave(tx *gorm.DB) (err error) {
	hash := f.CalculateHash()
	f.ID = hash
	return nil
}

func (f *FirstPartyVuln) RenderMarkdown() string {
	var str strings.Builder
	str.WriteString(*f.Message)
	// check if there is a filename and snippet - if so, we can render that as well
	if f.Snippet != "" {
		str.WriteString("\n\n")
		str.WriteString("```")
		str.WriteString("\n")
		str.WriteString(f.Snippet)
		str.WriteString("\n")
		str.WriteString("```")
	}

	if f.Uri != "" {
		str.WriteString("\n\n")
		str.WriteString("File: ")
		var link string
		if f.StartLine != 0 {
			link = fmt.Sprintf("[%s](%s%s)", f.Uri, strings.TrimPrefix(f.Uri, "/"), fmt.Sprintf("#L%d", f.StartLine))
		} else {
			link = fmt.Sprintf("[%s](%s)", f.Uri, strings.TrimPrefix(f.Uri, "/"))
		}

		str.WriteString(link)
		str.WriteString("\n")
	}

	common.AddSlashCommands(&str)

	return str.String()
}

func (f *FirstPartyVuln) Title() string {
	if f.Uri == "" {
		return f.RuleName
	}

	return fmt.Sprintf("%s found in %s", f.RuleName, f.Uri)
}

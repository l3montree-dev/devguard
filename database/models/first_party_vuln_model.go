package models

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/l3montree-dev/devguard/common"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/internal/core/integrations/jira"
	"github.com/l3montree-dev/devguard/transformer"
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

func (firstPartyVuln *FirstPartyVuln) RenderADF(baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug string) jira.ADF {
	snippets, err := transformer.FromJSONSnippetContents(firstPartyVuln)
	if err != nil {
		slog.Error("could not parse snippet contents", "error", err)
		return jira.ADF{}
	}

	adf := jira.ADF{
		Version: 1,
		Type:    "doc",
		Content: []jira.ADFContent{
			{
				Type: "paragraph",
				Content: []jira.ADFContent{
					{
						Type: "text",
						Text: *firstPartyVuln.Message,
					},
				},
			},
		},
	}

	for _, snippet := range snippets.Snippets {
		adf.Content = append(adf.Content, jira.ADFContent{
			Type: "codeBlock",
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: snippet.Snippet,
				},
			},
		})
	}

	if firstPartyVuln.URI != "" {
		link := strings.TrimPrefix(firstPartyVuln.URI, "/")
		adf.Content = append(adf.Content, jira.ADFContent{
			Type: "paragraph",
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: "File: " + link,
				},
			},
		})
	}

	adf.Content = append(adf.Content, jira.ADFContent{
		Type: "paragraph",
		Content: []jira.ADFContent{
			{
				Type: "text",
				Text: fmt.Sprintf("More details can be found in [DevGuard](%s/%s/projects/%s/assets/%s/refs/%s/dependency-risks/%s)", baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, firstPartyVuln.ID),
			},
		},
	})

	//add slash commands
	common.AddSlashCommandsToToFirstPartyVulnADF(&adf)

	return adf
}

func (firstPartyVuln *FirstPartyVuln) RenderMarkdown(baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug string) string {
	var str strings.Builder
	str.WriteString("## Vulnerability Description\n\n")
	str.WriteString(*firstPartyVuln.Message)

	snippet, err := transformer.FromJSONSnippetContents(firstPartyVuln)
	if err != nil {
		slog.Error("could not parse snippet contents", "error", err)
		return str.String()
	}
	extension := getLanguage(firstPartyVuln.URI)

	// dynamically change the headline to the amount of Snippets
	str.WriteString("\n\n")
	if len(snippet.Snippets) == 1 {
		str.WriteString("## Code Snippet\n")
	} else if len(snippet.Snippets) >= 2 {
		str.WriteString("## Code Snippets\n")
	}

	var locationString string
	for _, snippet := range snippet.Snippets {
		// check if there is a filename and snippet - if so, we can render that as well
		sanitizedSnippet := strings.ReplaceAll(snippet.Snippet, "+++\n", "")
		sanitizedSnippet = strings.ReplaceAll(sanitizedSnippet, "\n+++", "") //just to make sure
		str.WriteString("\n\n")
		str.WriteString("```" + extension + "\n")
		str.WriteString(sanitizedSnippet)
		str.WriteString("\n")
		str.WriteString("```\n")

		// build the link to the file and start line of the snippet
		link := fmt.Sprintf("[%s](../%s#L%d)", firstPartyVuln.URI, strings.TrimPrefix(firstPartyVuln.URI, "/"), snippet.StartLine)
		if snippet.StartLine == snippet.EndLine {
			locationString = fmt.Sprintf("**Found at:** %s\n**Line:** %d\n", link, snippet.StartLine)
		} else {
			locationString = fmt.Sprintf("**Found at:** %s\n**Lines:** %d - %d\n", link, snippet.StartLine, snippet.EndLine)
		}
		str.WriteString(locationString)
	}

	str.WriteString("\n\n")

	str.WriteString(fmt.Sprintf("More details can be found in [DevGuard](%s/%s/projects/%s/assets/%s/refs/%s/dependency-risks/%s)", baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, firstPartyVuln.ID))
	fmt.Println("str:", str.String())

	common.AddSlashCommandsToFirstPartyVuln(&str)

	return str.String()
}

func (firstPartyVuln *FirstPartyVuln) Title() string {
	if firstPartyVuln.URI == "" {
		return firstPartyVuln.RuleName
	}

	return fmt.Sprintf("%s found in %s", firstPartyVuln.RuleName, firstPartyVuln.URI)
}

// receives an uri and matches the extension to supported extensions, if not valid or not supported we return txt extension
func getLanguage(URI string) string {

	extension := filepath.Ext(URI)
	switch extension {
	case ".go":
		extension = "go"
	case ".ts":
		extension = "typescript"
	case ".js":
		extension = "js"
	case ".java":
		extension = "java"
	case ".py":
		extension = "python"
	case ".c":
		extension = "c"
	case ".cpp":
		extension = "cpp"
	case ".hpp":
		extension = "cpp"
	case ".css":
		extension = "css"
	case ".cs":
		extension = "csharp"
	case ".json":
		extension = "json"
	case ".yaml":
		extension = "yaml"
	case ".html":
		extension = "html"
	case ".xml":
		extension = "xml"
	case ".sql":
		extension = "sql"
	case ".mak":
		extension = "make"
	default:
		extension = "txt"
	}
	return extension
}

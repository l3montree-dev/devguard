package models

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core/integrations/jira"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/utils"
	"gorm.io/gorm"
)

type FirstPartyVuln struct {
	Vulnerability
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

type SnippetContents struct {
	Snippets []SnippetContent `json:"snippets"`
}

type SnippetContent struct {
	StartLine   int    `json:"startLine"`
	EndLine     int    `json:"endLine"`
	StartColumn int    `json:"startColumn"`
	EndColumn   int    `json:"endColumn"`
	Snippet     string `json:"snippet"`
}

func (s SnippetContents) ToJSON() (database.JSONB, error) {
	if len(s.Snippets) == 0 {
		return database.JSONB{}, fmt.Errorf("no snippets to convert to JSON")
	}
	return database.JSONbFromStruct(s)
}

func (firstPartyVuln *FirstPartyVuln) FromJSONSnippetContents() (SnippetContents, error) {
	res := SnippetContents{
		Snippets: []SnippetContent{},
	}

	snippetsInterface := firstPartyVuln.SnippetContents["snippets"].([]any)
	if snippetsInterface == nil {
		return res, fmt.Errorf("no snippets found in SnippetContents")
	}
	for _, snippetAny := range snippetsInterface {
		snippet, ok := snippetAny.(map[string]any)
		if !ok {
			continue
		}
		sc := SnippetContent{
			StartLine:   int(snippet["startLine"].(float64)),
			EndLine:     int(snippet["endLine"].(float64)),
			StartColumn: int(snippet["startColumn"].(float64)),
			EndColumn:   int(snippet["endColumn"].(float64)),
			Snippet:     snippet["snippet"].(string),
		}
		res.Snippets = append(res.Snippets, sc)
	}

	return res, nil
}

var _ Vuln = &FirstPartyVuln{}

func (firstPartyVuln *FirstPartyVuln) GetType() VulnType {
	return VulnTypeFirstPartyVuln
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

func (firstPartyVuln *FirstPartyVuln) BeforeSave(tx *gorm.DB) (err error) {
	hash := firstPartyVuln.CalculateHash()
	firstPartyVuln.ID = hash
	return nil
}

func (firstPartyVuln *FirstPartyVuln) RenderADF() jira.ADF {
	snippets, err := firstPartyVuln.FromJSONSnippetContents()
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

	//add slash commands
	common.AddSlashCommandsToToFirstPartyVulnADF(&adf)

	return adf
}

func (firstPartyVuln *FirstPartyVuln) RenderMarkdown() string {
	var str strings.Builder
	str.WriteString("## Vulnerability Description\n\n")
	str.WriteString(*firstPartyVuln.Message)

	snippet, err := firstPartyVuln.FromJSONSnippetContents()
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
		str.WriteString("\n\n")
		str.WriteString("```" + extension + "\n")
		str.WriteString(snippet.Snippet)
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

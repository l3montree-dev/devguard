package vuln

import (
	"time"

	"github.com/l3montree-dev/devguard/internal/core/events"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type FirstPartyVulnDTO struct {
	ID                   string                  `json:"id"`
	ScannerIDs           string                  `json:"scannerIds"`
	Message              *string                 `json:"message"`
	AssetVersionName     string                  `json:"assetVersionName"`
	AssetID              string                  `json:"assetId"`
	State                models.VulnState        `json:"state"`
	RuleID               string                  `json:"ruleId"`
	URI                  string                  `json:"uri"`
	SnippetContents      []models.SnippetContent `json:"snippetContents"`
	CreatedAt            time.Time               `json:"createdAt"`
	TicketID             *string                 `json:"ticketId"`
	TicketURL            *string                 `json:"ticketUrl"`
	ManualTicketCreation bool                    `json:"manualTicketCreation"`
	Commit               string                  `json:"commit"`
	Email                string                  `json:"email"`
	Author               string                  `json:"author"`
	Date                 string                  `json:"date"`

	RuleName        string         `json:"ruleName"`
	RuleHelp        string         `json:"ruleHelp"`
	RuleHelpURI     string         `json:"ruleHelpURI"`
	RuleDescription string         `json:"ruleDescription"`
	RuleProperties  map[string]any `json:"ruleProperties"`
}

type detailedFirstPartyVulnDTO struct {
	FirstPartyVulnDTO
	Events []events.VulnEventDTO `json:"events"`
}

func FirstPartyVulnToDto(f models.FirstPartyVuln) FirstPartyVulnDTO {
	snippets, err := f.FromJSONSnippetContents()
	if err != nil {
		snippets = models.SnippetContents{}
	}

	return FirstPartyVulnDTO{
		ID:                   f.ID,
		ScannerIDs:           f.ScannerIDs,
		Message:              f.Message,
		AssetVersionName:     f.AssetVersionName,
		AssetID:              f.AssetID.String(),
		State:                f.State,
		RuleID:               f.RuleID,
		URI:                  f.URI,
		CreatedAt:            f.CreatedAt,
		TicketID:             f.TicketID,
		TicketURL:            f.TicketURL,
		ManualTicketCreation: f.ManualTicketCreation,
		Commit:               f.Commit,
		Email:                f.Email,
		Author:               f.Author,
		Date:                 f.Date,
		SnippetContents:      snippets.Snippets,

		RuleName:        f.RuleName,
		RuleHelp:        f.RuleHelp,
		RuleHelpURI:     f.RuleHelpURI,
		RuleDescription: f.RuleDescription,
		RuleProperties:  f.RuleProperties,
	}
}

package dtos

import (
	"time"

	"github.com/google/uuid"
)

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

type FirstPartyVuln struct {
	ID                   uuid.UUID        `json:"id"`
	ScannerIDs           string           `json:"scannerIds"`
	Message              *string          `json:"message"`
	AssetVersionName     string           `json:"assetVersionName"`
	AssetID              string           `json:"assetId"`
	State                VulnState        `json:"state"`
	RuleID               string           `json:"ruleId"`
	URI                  string           `json:"uri"`
	SnippetContents      []SnippetContent `json:"snippetContents"`
	CreatedAt            time.Time        `json:"createdAt"`
	TicketID             *string          `json:"ticketId"`
	TicketURL            *string          `json:"ticketUrl"`
	ManualTicketCreation bool             `json:"manualTicketCreation"`
	Commit               string           `json:"commit"`
	Email                string           `json:"email"`
	Author               string           `json:"author"`
	Date                 string           `json:"date"`

	RuleName        string         `json:"ruleName"`
	RuleHelp        string         `json:"ruleHelp"`
	RuleHelpURI     string         `json:"ruleHelpURI"`
	RuleDescription string         `json:"ruleDescription"`
	RuleProperties  map[string]any `json:"ruleProperties"`
}

type DetailedFirstPartyVuln struct {
	FirstPartyVuln
	Events []VulnEvent `json:"events"`
}

type FirstPartyVulnStatusRequest struct {
	StatusType              string                      `json:"status" validate:"max=256"`
	Justification           string                      `json:"justification" validate:"max=4000"`
	MechanicalJustification MechanicalJustificationType `json:"mechanicalJustification"`
}

type BatchFirstPartyVulnStatusRequest struct {
	VulnIDs                 []uuid.UUID                 `json:"vulnIds"`
	StatusType              string                      `json:"status" validate:"max=256"`
	Justification           string                      `json:"justification" validate:"max=4000"`
	MechanicalJustification MechanicalJustificationType `json:"mechanicalJustification"`
}

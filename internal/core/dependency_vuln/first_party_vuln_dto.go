package dependency_vuln

import (
	"time"

	"github.com/l3montree-dev/devguard/internal/core/events"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type FirstPartyVulnDTO struct {
	ID                   string             `json:"id"`
	ScannerID            string             `json:"scanner"`
	Message              *string            `json:"message"`
	AssetID              string             `json:"assetId"`
	State                models.VulnState   `json:"state"`
	RuleID               string             `json:"ruleId"`
	Uri                  string             `json:"uri"`
	StartLine            int                `json:"startLine"`
	StartColumn          int                `json:"startColumn"`
	EndLine              int                `json:"endLine"`
	EndColumn            int                `json:"endColumn"`
	Snippet              string             `json:"snippet"`
	CreatedAt            time.Time          `json:"createdAt"`
	TicketID             *string            `json:"ticketId"`
	TicketURL            *string            `json:"ticketUrl"`
	TicketState          models.TicketState `json:"ticketState"`
	ManualTicketCreation bool               `json:"manualTicketCreation"`
	Commit               string             `json:"commit"`
	Email                string             `json:"email"`
	Author               string             `json:"author"`
	Date                 string             `json:"date"`
}

type detailedFirstPartyVulnDTO struct {
	FirstPartyVulnDTO
	Events []events.VulnEventDTO `json:"events"`
}

func FirstPartyVulnToDto(f models.FirstPartyVulnerability) FirstPartyVulnDTO {

	return FirstPartyVulnDTO{
		ID:                   f.ID,
		ScannerID:            f.ScannerID,
		Message:              f.Message,
		AssetID:              f.AssetID.String(),
		State:                f.State,
		RuleID:               f.RuleID,
		Uri:                  f.Uri,
		StartLine:            f.StartLine,
		StartColumn:          f.StartColumn,
		EndLine:              f.EndLine,
		EndColumn:            f.EndColumn,
		Snippet:              f.Snippet,
		CreatedAt:            f.CreatedAt,
		TicketID:             f.TicketID,
		TicketURL:            f.TicketURL,
		TicketState:          f.TicketState,
		ManualTicketCreation: f.ManualTicketCreation,
		Commit:               f.Commit,
		Email:                f.Email,
		Author:               f.Author,
		Date:                 f.Date,
	}
}

// Copyright (C) 2025 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package transformer

import (
	"fmt"

	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
)

func FromJSONSnippetContents(firstPartyVuln models.FirstPartyVuln) (dtos.SnippetContents, error) {
	res := dtos.SnippetContents{
		Snippets: []dtos.SnippetContent{},
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
		sc := dtos.SnippetContent{
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

func FirstPartyVulnToDto(f models.FirstPartyVuln) dtos.FirstPartyVulnDTO {
	snippets, err := FromJSONSnippetContents(f)
	if err != nil {
		snippets = dtos.SnippetContents{}
	}

	return dtos.FirstPartyVulnDTO{
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

func SnippetContentsToJSON(s dtos.SnippetContents) (database.JSONB, error) {
	if len(s.Snippets) == 0 {
		return database.JSONB{}, fmt.Errorf("no snippets to convert to JSON")
	}
	return database.JSONbFromStruct(s)
}

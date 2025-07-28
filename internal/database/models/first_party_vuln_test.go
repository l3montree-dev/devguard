package models_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestRenderMarkdown(t *testing.T) {
	t.Run("Normal Vuln with a valid line", func(t *testing.T) {
		snippetContents := models.SnippetContents{
			Snippets: []models.SnippetContent{
				{
					StartLine:   64,
					EndLine:     64,
					StartColumn: 1,
					EndColumn:   20,
					Snippet:     "TestSnippet",
				},
			},
		}
		snippetJSON, err := snippetContents.ToJSON()
		assert.NoError(t, err)

		firstPartyVuln := models.FirstPartyVuln{
			SnippetContents: snippetJSON,
			Vulnerability:   models.Vulnerability{Message: utils.Ptr("A detailed Message")},
			URI:             "the/uri/of/the/vuln",
		}
		result := firstPartyVuln.RenderMarkdown()
		assert.Contains(t, result, "A detailed Message")
		assert.Contains(t, result, "TestSnippet")
		assert.Contains(t, result, "File: [the/uri/of/the/vuln](the/uri/of/the/vuln)")
	})
	t.Run("vuln without snippet contents", func(t *testing.T) {
		firstPartyVuln := models.FirstPartyVuln{
			SnippetContents: database.JSONB{},
			Vulnerability:   models.Vulnerability{Message: utils.Ptr("A detailed Message")},
			URI:             "the/uri/of/the/vuln",
		}
		result := firstPartyVuln.RenderMarkdown()
		assert.Contains(t, result, "A detailed Message")
		assert.Contains(t, result, "File: [the/uri/of/the/vuln](the/uri/of/the/vuln)")
	})
}
func TestTableName(t *testing.T) {
	t.Run("Normal Vuln with a valid line", func(t *testing.T) {
		firstPartyVuln := models.FirstPartyVuln{}
		assert.Equal(t, "first_party_vulnerabilities", firstPartyVuln.TableName())
	})
}

func TestGetType(t *testing.T) {
	t.Run("Normal Vuln with a valid line", func(t *testing.T) {
		firstPartyVuln := models.FirstPartyVuln{}
		assert.Equal(t, models.VulnType("firstPartyVuln"), firstPartyVuln.GetType())
	})
}

func TestCalculateHash(t *testing.T) {
	t.Run("Normal Vuln with a valid line", func(t *testing.T) {
		firstPartyVuln := models.FirstPartyVuln{
			RuleID:        "no smoking on airplanes",
			URI:           "",
			Vulnerability: models.Vulnerability{AssetID: uuid.New(), AssetVersionName: "bombardini krokodili"},
		}
		expectedHash := utils.HashString(firstPartyVuln.RuleID + "/" + firstPartyVuln.URI + "/" + firstPartyVuln.ScannerIDs + "/" + firstPartyVuln.AssetID.String() + "/" + firstPartyVuln.AssetVersionName)
		assert.Equal(t, expectedHash, firstPartyVuln.CalculateHash())
	})
}

func TestBeforeSave(t *testing.T) {
	t.Run("Normal Vuln with a valid line", func(t *testing.T) {
		firstPartyVuln := models.FirstPartyVuln{}
		err := firstPartyVuln.BeforeSave(nil)
		if err != nil {
			t.Fail()
		}
		assert.Equal(t, firstPartyVuln.CalculateHash(), firstPartyVuln.ID)
	})
}

func TestTitle(t *testing.T) {
	t.Run("URI is empty", func(t *testing.T) {
		firstPartyVuln := models.FirstPartyVuln{RuleName: "tralalero tralala"}
		assert.Equal(t, "tralalero tralala", firstPartyVuln.Title())
	})
	t.Run("URI not empty", func(t *testing.T) {
		firstPartyVuln := models.FirstPartyVuln{URI: "tung/tung/tung/sahur", RuleName: "tralalero tralala"}
		assert.Equal(t, "tralalero tralala found in tung/tung/tung/sahur", firstPartyVuln.Title())
	})
}

package models_test

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/gosimple/slug"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
)

func TestRenderMarkdown(t *testing.T) {

	baseURL := "https://devguard.example.com"
	orgSlug := "my-org"
	projectSlug := "my-project"
	assetSlug := "my-asset"
	assetVersionName := "v1.0.0"

	assertVersionSlug := slug.Make(assetVersionName)
	assert.Equal(t, "v1-0-0", assertVersionSlug)

	t.Run("Normal Vuln with a valid line", func(t *testing.T) {
		snippetContents := dtos.SnippetContents{
			Snippets: []models.dtos.SnippetContent{
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
			Vulnerability: models.Vulnerability{Message: utils.Ptr("A detailed Message"),
				ID: "test-vuln-id",
			},
			URI: "the/uri/of/the/vuln",
		}
		result := firstPartyVuln.RenderMarkdown(baseURL, orgSlug, projectSlug, assetSlug, assertVersionSlug)
		assert.Contains(t, result, "A detailed Message")
		assert.Contains(t, result, "TestSnippet")
		assert.Contains(t, result, "**Found at:** [the/uri/of/the/vuln](../the/uri/of/the/vuln#L64)")
		assert.Contains(t, result, fmt.Sprintf("More details can be found in [DevGuard](%s/%s/projects/%s/assets/%s/refs/%s/dependency-risks/%s)", baseURL, orgSlug, projectSlug, assetSlug, assertVersionSlug, firstPartyVuln.ID))
	})
	t.Run("vuln without snippet contents", func(t *testing.T) {
		snippetContents := dtos.SnippetContents{
			Snippets: []models.dtos.SnippetContent{
				{},
			},
		}
		snippetJSON, err := snippetContents.ToJSON()
		assert.NoError(t, err)
		firstPartyVuln := models.FirstPartyVuln{
			SnippetContents: snippetJSON,
			Vulnerability: models.Vulnerability{Message: utils.Ptr("A detailed Message"),
				ID: "test-vuln-id"},
			URI: "the/uri/of/the/vuln",
		}

		result := firstPartyVuln.RenderMarkdown(baseURL, orgSlug, projectSlug, assetSlug, assertVersionSlug)
		assert.Contains(t, result, "A detailed Message")
		assert.Contains(t, result, "**Found at:** [the/uri/of/the/vuln](../the/uri/of/the/vuln#L0)")
		assert.Contains(t, result, fmt.Sprintf("More details can be found in [DevGuard](%s/%s/projects/%s/assets/%s/refs/%s/dependency-risks/%s)", baseURL, orgSlug, projectSlug, assetSlug, assertVersionSlug, firstPartyVuln.ID))
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
		assert.Equal(t, dtos.VulnType("firstPartyVuln"), firstPartyVuln.GetType())
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

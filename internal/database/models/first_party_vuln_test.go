package models_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestRenderMarkdown(t *testing.T) {
	t.Run("Normal Vuln with a valid line", func(t *testing.T) {
		firstPartyVuln := models.FirstPartyVuln{
			Snippet:       "TestSnippet",
			Vulnerability: models.Vulnerability{Message: utils.Ptr("A detailed Message")},
			URI:           "the/uri/of/the/vuln",
			StartLine:     64,
		}
		result := firstPartyVuln.RenderMarkdown()
		assert.Equal(t, "A detailed Message\n\n```\nTestSnippet\n```\n\nFile: [the/uri/of/the/vuln](the/uri/of/the/vuln#L64)\n\n--- \n### Interact with this vulnerability\nYou can use the following slash commands to interact with this vulnerability:\n\n#### 👍   Reply with this to acknowledge and accept the identified risk.\n```text\n/accept I accept the risk of this vulnerability, because ...\n```\n\n#### ⚠️ Mark the risk as false positive: Use one of these commands if you believe the reported vulnerability is not actually a valid issue.\n```text\n/component-not-present The vulnerable component is not included in the artifact.\n```\n```text\n/vulnerable-code-not-present The component is present, but the vulnerable code is not included or compiled.\n```\n```text\n/vulnerable-code-not-in-execute-path The vulnerable code exists, but is never executed at runtime.\n```\n```text\n/vulnerable-code-cannot-be-controlled-by-adversary Built-in protections prevent exploitation of this vulnerability.\n```\n```text\n/inline-mitigations-already-exist The vulnerable code cannot be controlled or influenced by an attacker.\n```\n\n#### 🔁  Reopen the risk: Use this command to reopen a previously closed or accepted vulnerability.\n```text\n/reopen ... \n```\n", result)
	})
	t.Run("vuln without a valid line", func(t *testing.T) {
		firstPartyVuln := models.FirstPartyVuln{
			Snippet:       "TestSnippet",
			Vulnerability: models.Vulnerability{Message: utils.Ptr("A detailed Message")},
			URI:           "the/uri/of/the/vuln",
			StartLine:     0,
		}
		result := firstPartyVuln.RenderMarkdown()
		assert.Equal(t, "A detailed Message\n\n```\nTestSnippet\n```\n\nFile: [the/uri/of/the/vuln](the/uri/of/the/vuln)\n\n--- \n### Interact with this vulnerability\nYou can use the following slash commands to interact with this vulnerability:\n\n#### 👍   Reply with this to acknowledge and accept the identified risk.\n```text\n/accept I accept the risk of this vulnerability, because ...\n```\n\n#### ⚠️ Mark the risk as false positive: Use one of these commands if you believe the reported vulnerability is not actually a valid issue.\n```text\n/component-not-present The vulnerable component is not included in the artifact.\n```\n```text\n/vulnerable-code-not-present The component is present, but the vulnerable code is not included or compiled.\n```\n```text\n/vulnerable-code-not-in-execute-path The vulnerable code exists, but is never executed at runtime.\n```\n```text\n/vulnerable-code-cannot-be-controlled-by-adversary Built-in protections prevent exploitation of this vulnerability.\n```\n```text\n/inline-mitigations-already-exist The vulnerable code cannot be controlled or influenced by an attacker.\n```\n\n#### 🔁  Reopen the risk: Use this command to reopen a previously closed or accepted vulnerability.\n```text\n/reopen ... \n```\n", result)
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
			StartLine:     0,
			EndLine:       2,
			StartColumn:   2,
			EndColumn:     8,
			RuleID:        "no smoking on airplanes",
			Vulnerability: models.Vulnerability{AssetID: uuid.New(), AssetVersionName: "bombardini krokodili"},
		}
		assert.Equal(t, utils.HashString("0"+"/"+"2"+"/"+"2"+"/"+"8"+"/"+"no smoking on airplanes"+"/"+"/"+"/"+firstPartyVuln.AssetID.String()+"/"+"bombardini krokodili"), firstPartyVuln.CalculateHash())
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

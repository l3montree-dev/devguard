package models_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestRenderMarkdown(t *testing.T) {
	t.Run("Normal Vuln with a valid line", func(t *testing.T) {
		first_party_vul := models.FirstPartyVuln{
			Snippet:       "TestSnippet",
			Vulnerability: models.Vulnerability{Message: utils.Ptr("A detailed Message")},
			Uri:           "the/uri/of/the/vuln",
			StartLine:     64,
		}
		result := first_party_vul.RenderMarkdown()
		assert.Equal(t, "A detailed Message\n\n```\nTestSnippet\n```\n\nFile: [the/uri/of/the/vuln](the/uri/of/the/vuln#L64)\n\n--- \n### Interact with this vulnerability\nYou can use the following slash commands to interact with this vulnerability:\n\n#### 👍   Reply with this to acknowledge and accept the identified risk.\n```text\n/accept I accept the risk of this vulnerability, because ...\n```\n\n#### ⚠️ Mark the risk as false positive: Use one of these commands if you believe the reported vulnerability is not actually a valid issue.\n```text\n/component-not-present The vulnerable component is not included in the artifact.\n```\n```text\n/vulnerable-code-not-present The component is present, but the vulnerable code is not included or compiled.\n```\n```text\n/vulnerable-code-not-in-execute-path The vulnerable code exists, but is never executed at runtime.\n```\n```text\n/vulnerable-code-cannot-be-controlled-by-adversary Built-in protections prevent exploitation of this vulnerability.\n```\n```text\n/inline-mitigations-already-exist The vulnerable code cannot be controlled or influenced by an attacker.\n```\n\n#### 🔁  Reopen the risk: Use this command to reopen a previously closed or accepted vulnerability.\n```text\n/reopen ... \n```\n", result)
	})
	t.Run("vuln without a valid line", func(t *testing.T) {
		first_party_vul := models.FirstPartyVuln{
			Snippet:       "TestSnippet",
			Vulnerability: models.Vulnerability{Message: utils.Ptr("A detailed Message")},
			Uri:           "the/uri/of/the/vuln",
			StartLine:     0,
		}
		result := first_party_vul.RenderMarkdown()
		assert.Equal(t, "A detailed Message\n\n```\nTestSnippet\n```\n\nFile: [the/uri/of/the/vuln](the/uri/of/the/vuln)\n\n--- \n### Interact with this vulnerability\nYou can use the following slash commands to interact with this vulnerability:\n\n#### 👍   Reply with this to acknowledge and accept the identified risk.\n```text\n/accept I accept the risk of this vulnerability, because ...\n```\n\n#### ⚠️ Mark the risk as false positive: Use one of these commands if you believe the reported vulnerability is not actually a valid issue.\n```text\n/component-not-present The vulnerable component is not included in the artifact.\n```\n```text\n/vulnerable-code-not-present The component is present, but the vulnerable code is not included or compiled.\n```\n```text\n/vulnerable-code-not-in-execute-path The vulnerable code exists, but is never executed at runtime.\n```\n```text\n/vulnerable-code-cannot-be-controlled-by-adversary Built-in protections prevent exploitation of this vulnerability.\n```\n```text\n/inline-mitigations-already-exist The vulnerable code cannot be controlled or influenced by an attacker.\n```\n\n#### 🔁  Reopen the risk: Use this command to reopen a previously closed or accepted vulnerability.\n```text\n/reopen ... \n```\n", result)
	})

}

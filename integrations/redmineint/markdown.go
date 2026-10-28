package redmineint

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/integrations/commonint"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/vulndb"
)

const DEVGUARD_COMMENT_TEXT = "This comment was added via DevGuard."

func Markdown(exp vulndb.Explanation, baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug string, mermaidPathToComponent *string) string {
	var str strings.Builder
	fmt.Fprintf(&str, "## %s found in %s \n", exp.CVEID, exp.ShortenedComponentPurl)

	str.WriteString("> [!important] \n")

	severity, err := vulndb.RiskToSeverity(exp.Risk)
	if err != nil {
		fmt.Fprintf(&str, "> **Risk**: `%.2f (%s)`\n", exp.Risk, "Unknown")
	} else {
		fmt.Fprintf(&str, "> **Risk**: `%.2f (%s)`\n", exp.Risk, severity)
	}

	fmt.Fprintf(&str, "> **CVSS**: `%.1f` \n\n", exp.BaseScore)

	str.WriteString("### Description\n")
	str.WriteString(exp.CVEDescription)
	str.WriteString("\n\n")
	str.WriteString("### Affected component \n")
	artifactNames := strings.Fields(exp.ArtifactNames)
	for i, s := range artifactNames {
		artifactNames[i] = fmt.Sprintf("`%s`", s)
	}
	fmt.Fprintf(&str, "The vulnerability is in `%s`, found in artifacts %s.\n\n", exp.ComponentPurl, strings.Join(artifactNames, ", "))
	str.WriteString("### Recommended fix\n")
	if exp.FixedVersion != nil {
		fmt.Fprintf(&str, "Upgrade to version %s or later.\n", *exp.FixedVersion)
		str.WriteString(exp.GenerateCommandsToFixPackage())
	} else {
		str.WriteString("No fix is available.\n")
	}

	str.WriteString("\n\n### Additional guidance for mitigating vulnerabilities\n")
	str.WriteString("Visit our guides on [devguard.org](https://docs.devguard.org/how-to-guides/scanning/scan-your-project)\n")

	if mermaidPathToComponent != nil {
		str.WriteString("\n<details>\n\n<summary>Path to component</summary>\n\n")
		str.WriteString("\n### Path to component\n")
		str.WriteString(*mermaidPathToComponent)
		str.WriteString("\n\n</details>\n\n")
	}

	str.WriteString("| Risk Factor  | Value | Description | \n")
	str.WriteString("| ---- | ----- | ----------- | \n")
	fmt.Fprintf(&str, "| Vulnerability Depth | `%d` | %s | \n", exp.Depth, exp.ComponentDepthMessage)
	fmt.Fprintf(&str, "| EPSS | `%.2f %%` | %s | \n", exp.EPSS*100, exp.EPSSMessage)
	fmt.Fprintf(&str, "| EXPLOIT | `%s` | %s | \n", exp.ExploitMessage.Short, exp.ExploitMessage.Long)
	fmt.Fprintf(&str, "| CVSS-BE | `%.1f` | %s | \n", exp.WithEnvironment, exp.CVSSBEMessage)
	fmt.Fprintf(&str, "| CVSS-B | `%.1f` | %s | \n", exp.BaseScore, exp.CVSSMessage)
	str.WriteString("\n\n")

	fmt.Fprintf(&str, "More details can be found in [DevGuard](%s/%s/projects/%s/assets/%s/refs/%s/dependency-risks/%s)", baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, exp.DependencyVulnID)
	str.WriteString("\n")

	// TODO: Redmine webhooks are currently not implemented. Once they are, we can add the issue commands.
	// utils.AddSlashCommandsToDependencyVuln(&str)
	return str.String()
}

func GenerateFirstPartyIssueDescription(firstPartyVuln models.FirstPartyVuln, baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug string) string {
	var str strings.Builder
	str.WriteString("## Vulnerability Description\n\n")
	str.WriteString(*firstPartyVuln.Message)

	snippet, err := transformer.FromJSONSnippetContents(firstPartyVuln)
	if err != nil {
		slog.Error("could not parse snippet contents", "error", err)
		return str.String()
	}
	extension := commonint.GetLanguage(firstPartyVuln.URI)

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
	fmt.Fprintf(&str, "More details can be found in [DevGuard](%s/%s/projects/%s/assets/%s/refs/%s/code-risks/%s)", baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, firstPartyVuln.ID)

	// TODO: Redmine webhooks are currently not implemented. Once they are, we can add the issue commands.
	// sb.WriteString(fmt.Sprintf("\n\n<details>\n<summary>Issue Commands</summary>\n\n%s\n\n</details>\n", SlashCommandsForFirstPartyVuln()))

	return str.String()
}

func GenerateComment(author string, commentText string, justification string) string {
	var sb strings.Builder

	if author != "" && commentText != "" {
		sb.WriteString(fmt.Sprintf("%s %s:\n\n", author, commentText))
	}

	if justification != "" {
		sb.WriteString(fmt.Sprintf("%s\n\n", justification))
	}

	sb.WriteString(fmt.Sprintf("<sub>%s</sub>", DEVGUARD_COMMENT_TEXT))

	return sb.String()
}

func FormatComponentTree(settings models.RedmineIntegration, dependencyVuln *models.DependencyVuln) *string {
	componentTree := ""
	switch settings.MermaidIntegration {
	case models.CommonMark:
		componentTree = "```" + commonint.MermaidFlowChart([][]string{dependencyVuln.VulnerabilityPath}) + "```\n\n"
	case models.Macro:
		componentTree = "{{" + commonint.MermaidFlowChart([][]string{dependencyVuln.VulnerabilityPath}) + "}}\n\n"
	default:
		return nil
	}
	return &componentTree
}

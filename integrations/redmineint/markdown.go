package redmineint

import (
	"fmt"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/integrations/commonint"
)

const DEVGUARD_COMMENT_TEXT = "This comment was added via DevGuard."

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

func FormatComponentTree(settings models.RedmineIntegration, dependencyVuln *models.DependencyVuln) string {
	componentTree := ""
	switch settings.MermaidIntegration {
	case models.CommonMark:
		componentTree = "```" + commonint.MermaidFlowChart([][]string{dependencyVuln.VulnerabilityPath}) + "```\n\n"
	case models.Macro:
		componentTree = "{{" + commonint.MermaidFlowChart([][]string{dependencyVuln.VulnerabilityPath}) + "}}\n\n"
	}
	return componentTree
}

package redmineint

import (
	"fmt"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/integrations/commonint"
)

const DevguardCommentText = "This comment was added via DevGuard."

func GenerateComment(author string, commentText string, justification string) string {
	var sb strings.Builder

	if author != "" && commentText != "" {
		fmt.Fprintf(&sb, "%s %s:\n\n", author, commentText)
	}

	if justification != "" {
		fmt.Fprintf(&sb, "%s\n\n", justification)
	}

	fmt.Fprintf(&sb, "<sub>%s</sub>", DevguardCommentText)

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

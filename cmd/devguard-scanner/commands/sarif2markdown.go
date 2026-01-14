package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/spf13/cobra"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func newSarifMarkdownCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "sarif2markdown",
		Short:             "Convert a SARIF JSON file into a markdown report",
		DisableAutoGenTag: true,
		Long: `Convert a SARIF JSON file into a human-readable markdown report.

Supports both summary and detailed output formats.`,
		Example: `  # Convert SARIF to markdown summary
  devguard-scanner sarif2markdown -i results.sarif.json

  # Generate detailed markdown report
  devguard-scanner sarif2markdown -i results.sarif.json --detailed

  # Save to file
  devguard-scanner sarif2markdown -i results.sarif.json -o report.md`,
		RunE: func(cmd *cobra.Command, args []string) error {
			inputFile, _ := cmd.Flags().GetString("input")
			outputFile, _ := cmd.Flags().GetString("output")
			detailed, _ := cmd.Flags().GetBool("detailed")

			if inputFile == "" {
				return fmt.Errorf("input file is required")
			}

			data, err := os.ReadFile(inputFile)
			if err != nil {
				return fmt.Errorf("error reading file: %w", err)
			}

			var doc sarif.SarifSchema210Json
			if err := json.Unmarshal(data, &doc); err != nil {
				return fmt.Errorf("error parsing SARIF JSON: %w", err)
			}

			var markdown string
			if detailed {
				markdown = generateDetailedMarkdown(&doc)
			} else {
				markdown = generateSummaryMarkdown(&doc)
			}

			if outputFile != "" {
				if err := os.WriteFile(outputFile, []byte(markdown), 0o644); err != nil {
					return fmt.Errorf("error writing file: %w", err)
				}
				return nil
			}

			fmt.Print(markdown)
			return nil
		},
	}

	cmd.Flags().StringP("input", "i", "", "Input SARIF JSON file")
	cmd.Flags().StringP("output", "o", "", "Output markdown file (default: stdout)")
	cmd.Flags().Bool("detailed", false, "Show detailed results per resource")
	cmd.MarkFlagRequired("input") //nolint:errcheck

	return cmd
}

func generateSummaryMarkdown(doc *sarif.SarifSchema210Json) string {
	var sb strings.Builder
	for _, run := range doc.Runs {
		sb.WriteString(fmt.Sprintf("# %s Security Scan Results\n\n", run.Tool.Driver.Name))
		if run.Tool.Driver.InformationURI != nil {
			sb.WriteString(fmt.Sprintf("Tool: %s\n\n", *run.Tool.Driver.InformationURI))
		}
		summaries := aggregateResults(run.Results)
		sb.WriteString("## Summary by Policy Rule\n\n")
		sb.WriteString("| Policy | Rule | Severity | Status | Resources Affected |\n")
		sb.WriteString("|--------|------|----------|--------|--------------------|\n")
		for _, summary := range summaries {
			status := getStatusIndicator(summary.PassCount, summary.FailCount, summary.SkipCount)
			resourceCount := len(summary.Resources)
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %d |\n",
				escapeMarkdown(summary.Policy),
				escapeMarkdown(summary.Rule),
				getSeverityBadge(summary.Level),
				status,
				resourceCount))
		}
		sb.WriteString("\n")

		totalPass, totalFail, totalSkip := 0, 0, 0
		for _, summary := range summaries {
			totalPass += summary.PassCount
			totalFail += summary.FailCount
			totalSkip += summary.SkipCount
		}
		sb.WriteString("## Overall Statistics\n\n")
		sb.WriteString(fmt.Sprintf("- ✅ Passed: %d\n", totalPass))
		sb.WriteString(fmt.Sprintf("- ❌ Failed: %d\n", totalFail))
		if totalSkip > 0 {
			sb.WriteString(fmt.Sprintf("- ⏭️ Skipped: %d\n", totalSkip))
		}
		sb.WriteString(fmt.Sprintf("- 📊 Total: %d\n\n", totalPass+totalFail+totalSkip))
	}
	return sb.String()
}

func generateDetailedMarkdown(doc *sarif.SarifSchema210Json) string {
	var sb strings.Builder
	titleCaser := cases.Title(language.English)
	for _, run := range doc.Runs {
		sb.WriteString(fmt.Sprintf("# %s Security Scan Results (Detailed)\n\n", run.Tool.Driver.Name))
		if run.Tool.Driver.InformationURI != nil {
			sb.WriteString(fmt.Sprintf("Tool: %s\n\n", *run.Tool.Driver.InformationURI))
		}

		resultsBySeverity := groupBySeverity(run.Results)
		for _, level := range []string{"critical", "high", "medium", "low", "note"} {
			results, exists := resultsBySeverity[level]
			if !exists || len(results) == 0 {
				continue
			}
			sb.WriteString(fmt.Sprintf("## %s Severity Issues\n\n", titleCaser.String(level)))
			sb.WriteString("| Status | Resource | Policy | Rule | Message |\n")
			sb.WriteString("|--------|----------|--------|------|----------|\n")
			for _, result := range results {
				status := getResultStatus(result.Message.Text)
				resource := extractResourceName(result)
				policy := result.Properties.AdditionalProperties["policy"].(string)
				if policy == "" {
					policy = extractPolicyFromRuleID(*result.RuleID)
				}
				rule := extractRuleFromRuleID(*result.RuleID)
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
					status,
					escapeMarkdown(resource),
					escapeMarkdown(policy),
					escapeMarkdown(rule),
					escapeMarkdown(cleanMessage(result.Message.Text))))
			}
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

type summary struct {
	RuleID    string
	Policy    string
	Rule      string
	Level     string
	Resources []string

	PassCount int
	FailCount int
	SkipCount int
}

func aggregateResults(results []sarif.Result) []summary {
	summaryMap := make(map[string]*summary)
	for _, result := range results {
		key := *result.RuleID
		if _, exists := summaryMap[key]; !exists {
			policy := (*result.Properties).AdditionalProperties["policy"].(string)
			if policy == "" {
				policy = extractPolicyFromRuleID(key)
			}
			rule := extractRuleFromRuleID(key)
			summaryMap[key] = &summary{
				RuleID:    *result.RuleID,
				Policy:    policy,
				Rule:      rule,
				Level:     string(result.Level),
				Resources: []string{},
			}
		}
		summary := summaryMap[key]
		resource := extractResourceName(result)
		if resource != "" && !contains(summary.Resources, resource) {
			summary.Resources = append(summary.Resources, resource)
		}

		msg := strings.ToLower(result.Message.Text)
		if strings.Contains(msg, "got fail") {
			summary.FailCount++
		} else if strings.Contains(msg, "got skip") {
			summary.SkipCount++
		} else if strings.Contains(msg, "got pass") || strings.Contains(msg, "passed") {
			summary.PassCount++
		} else {
			summary.FailCount++
		}
	}

	summaries := make([]summary, 0, len(summaryMap))
	for _, summary := range summaryMap {
		summaries = append(summaries, *summary)
	}
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "note": 4}
	sort.Slice(summaries, func(i, j int) bool {
		if severityOrder[summaries[i].Level] != severityOrder[summaries[j].Level] {
			return severityOrder[summaries[i].Level] < severityOrder[summaries[j].Level]
		}
		return summaries[i].Policy < summaries[j].Policy
	})

	return summaries
}

func groupBySeverity(results []sarif.Result) map[string][]sarif.Result {
	grouped := make(map[string][]sarif.Result)
	for _, result := range results {
		level := strings.ToLower(string(result.Level))
		grouped[level] = append(grouped[level], result)
	}
	return grouped
}

func getStatusIndicator(pass, fail, skip int) string {
	if fail > 0 {
		return fmt.Sprintf("❌ %d fail", fail)
	}
	if skip > 0 {
		return fmt.Sprintf("⏭️ %d skip", skip)
	}
	if pass > 0 {
		return fmt.Sprintf("✅ %d pass", pass)
	}
	return "—"
}

func getResultStatus(message string) string {
	msg := strings.ToLower(message)
	if strings.Contains(msg, "got fail") {
		return "❌"
	}
	if strings.Contains(msg, "got skip") {
		return "⏭️"
	}
	if strings.Contains(msg, "got pass") || strings.Contains(msg, "passed") {
		return "✅"
	}
	return "❓"
}

func getSeverityBadge(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "🔴 Critical"
	case "high":
		return "🟠 High"
	case "medium":
		return "🟡 Medium"
	case "low":
		return "🔵 Low"
	case "note":
		return "⚪ Note"
	default:
		return level
	}
}

func extractResourceName(result sarif.Result) string {
	if result.Properties != nil && (*result.Properties).AdditionalProperties["resource"] != "" {
		return (*result.Properties).AdditionalProperties["resource"].(string)
	}
	for _, loc := range result.Locations {
		for _, logLoc := range loc.LogicalLocations {
			if logLoc.Name != nil {
				return *logLoc.Name
			}
		}
	}
	return "unknown"
}

func extractPolicyFromRuleID(ruleID string) string {
	parts := strings.Split(ruleID, "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ruleID
}

func extractRuleFromRuleID(ruleID string) string {
	parts := strings.Split(ruleID, "/")
	if len(parts) > 1 {
		return parts[1]
	}
	return ruleID
}

func cleanMessage(message string) string {
	if idx := strings.Index(message, "(Resource:"); idx != -1 {
		return strings.TrimSpace(message[:idx])
	}
	return message
}

func escapeMarkdown(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

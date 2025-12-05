package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type kyvernoTestResult struct {
	ID       int    `json:"ID"`
	Policy   string `json:"POLICY"`
	Reason   string `json:"REASON"`
	Resource string `json:"RESOURCE"`
	Result   string `json:"RESULT"`
	Rule     string `json:"RULE"`
}

type kyvernoSarifReport struct {
	Version string       `json:"version"`
	Schema  string       `json:"$schema"`
	Runs    []kyvernoRun `json:"runs"`
}

type kyvernoRun struct {
	Tool    kyvernoTool     `json:"tool"`
	Results []kyvernoResult `json:"results"`
}

type kyvernoTool struct {
	Driver kyvernoDriver `json:"driver"`
}

type kyvernoDriver struct {
	Name            string        `json:"name"`
	InformationURI  string        `json:"informationUri,omitempty"`
	Version         string        `json:"version,omitempty"`
	SemanticVersion string        `json:"semanticVersion,omitempty"`
	Rules           []kyvernoRule `json:"rules,omitempty"`
}

type kyvernoRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription kyvernoMessageString   `json:"shortDescription,omitempty"`
	FullDescription  kyvernoMessageString   `json:"fullDescription,omitempty"`
	Help             kyvernoMessageString   `json:"help,omitempty"`
	Properties       *kyvernoRuleProperties `json:"properties,omitempty"`
}

type kyvernoRuleProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type kyvernoMessageString struct {
	Text string `json:"text"`
}

type kyvernoResult struct {
	RuleID     string                   `json:"ruleId"`
	Level      string                   `json:"level"`
	Message    kyvernoMessage           `json:"message"`
	Locations  []kyvernoLocation        `json:"locations,omitempty"`
	Properties *kyvernoResultProperties `json:"properties,omitempty"`
}

type kyvernoResultProperties struct {
	KyvernoID int    `json:"kyvernoId,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Policy    string `json:"policy,omitempty"`
}

type kyvernoMessage struct {
	Text string `json:"text"`
}

type kyvernoLocation struct {
	PhysicalLocation kyvernoPhysicalLocation  `json:"physicalLocation,omitempty"`
	LogicalLocations []kyvernoLogicalLocation `json:"logicalLocations,omitempty"`
}

type kyvernoPhysicalLocation struct {
	ArtifactLocation kyvernoArtifactLocation `json:"artifactLocation"`
}

type kyvernoArtifactLocation struct {
	URI string `json:"uri"`
}

type kyvernoLogicalLocation struct {
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`
}

func newKyvernoSarifCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kyverno-sarif",
		Short: "Convert Kyverno test output to SARIF",
		RunE: func(cmd *cobra.Command, args []string) error {
			inputPath, _ := cmd.Flags().GetString("input")
			outputPath, _ := cmd.Flags().GetString("output")

			if inputPath == "" {
				return fmt.Errorf("input file is required")
			}

			data, err := os.ReadFile(inputPath)
			if err != nil {
				return fmt.Errorf("error reading input file: %w", err)
			}

			jsonData, err := extractKyvernoJSON(string(data))
			if err != nil {
				return fmt.Errorf("error extracting JSON: %w", err)
			}

			var kyvernoResults []kyvernoTestResult
			if err := json.Unmarshal([]byte(jsonData), &kyvernoResults); err != nil {
				return fmt.Errorf("error parsing JSON: %w", err)
			}

			sarif := convertKyvernoToSARIF(kyvernoResults)

			sarifJSON, err := json.MarshalIndent(sarif, "", "  ")
			if err != nil {
				return fmt.Errorf("error generating SARIF JSON: %w", err)
			}

			if outputPath == "" {
				fmt.Println(string(sarifJSON))
				return nil
			}

			if err := os.WriteFile(outputPath, sarifJSON, 0o644); err != nil {
				return fmt.Errorf("error writing output file: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringP("input", "i", "", "Input file containing Kyverno test output")
	cmd.Flags().StringP("output", "o", "", "Output SARIF file (default: stdout)")
	cmd.MarkFlagRequired("input") //nolint:errcheck

	return cmd
}

func extractKyvernoJSON(content string) (string, error) {
	start := strings.Index(content, "[")
	if start == -1 {
		return "", fmt.Errorf("no JSON array found in input")
	}

	end := strings.LastIndex(content, "]")
	if end == -1 || end < start {
		return "", fmt.Errorf("malformed JSON array in input")
	}

	return content[start : end+1], nil
}

func convertKyvernoToSARIF(kyvernoResults []kyvernoTestResult) kyvernoSarifReport {
	rulesMap := make(map[string]kyvernoRule)
	var results []kyvernoResult

	for _, kr := range kyvernoResults {
		ruleID := fmt.Sprintf("%s/%s", kr.Policy, kr.Rule)

		if _, exists := rulesMap[ruleID]; !exists {
			rulesMap[ruleID] = kyvernoRule{
				ID:   ruleID,
				Name: kr.Rule,
				ShortDescription: kyvernoMessageString{
					Text: fmt.Sprintf("%s - %s", kr.Policy, kr.Rule),
				},
				FullDescription: kyvernoMessageString{
					Text: fmt.Sprintf("Kyverno policy '%s' rule '%s'", kr.Policy, kr.Rule),
				},
				Properties: &kyvernoRuleProperties{
					Tags: []string{"kyverno", "security", "kubernetes"},
				},
			}
		}

		level := "medium"
		if strings.Contains(kr.Policy, "privileged") ||
			strings.Contains(kr.Policy, "privilege-escalation") ||
			strings.Contains(kr.Rule, "privileged") {
			level = "high"
		}
		if strings.Contains(kr.Rule, "adding-capabilities") ||
			strings.Contains(kr.Policy, "disallow-capabilities") {
			level = "critical"
		}

		result := kyvernoResult{
			RuleID: ruleID,
			Level:  level,
			Message: kyvernoMessage{
				Text: fmt.Sprintf("%s (Resource: %s)", kr.Reason, kr.Resource),
			},
			Properties: &kyvernoResultProperties{
				KyvernoID: kr.ID,
				Resource:  kr.Resource,
				Policy:    kr.Policy,
			},
		}

		if kr.Resource != "" {
			parts := strings.Split(kr.Resource, "/")
			resourceName := kr.Resource
			if len(parts) > 0 {
				resourceName = parts[len(parts)-1]
			}

			result.Locations = []kyvernoLocation{
				{
					LogicalLocations: []kyvernoLogicalLocation{
						{
							Name: resourceName,
							Kind: "resource",
						},
					},
				},
			}
		}

		results = append(results, result)
	}

	var rules []kyvernoRule
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}

	return kyvernoSarifReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []kyvernoRun{
			{
				Tool: kyvernoTool{
					Driver: kyvernoDriver{
						Name:            "Kyverno",
						InformationURI:  "https://kyverno.io/",
						Version:         "1.0.0",
						SemanticVersion: "1.0.0",
						Rules:           rules,
					},
				},
				Results: results,
			},
		},
	}
}

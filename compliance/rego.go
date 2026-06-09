package compliance

import (
	"context"
	"embed"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/open-policy-agent/opa/v1/rego"
	"gopkg.in/yaml.v2"
)

type yamlPolicy struct {
	Title  string `yaml:"title"`
	Custom customYaml
}

type customYaml struct {
	Description string `yaml:"description"`
	Priority    int    `yaml:"priority"`
	Tags        []string
	// used for mapping from policies to attestations
	PredicateType        string   `yaml:"predicateType"`
	RelatedResources     []string `yaml:"relatedResources"`
	ComplianceFrameworks []string `yaml:"complianceFrameworks"`
}

type PolicyMetadata struct {
	Title                string   `yaml:"title" json:"title"`
	Description          string   `yaml:"description" json:"description"`
	Priority             int      `yaml:"priority" json:"priority"`
	Tags                 []string `yaml:"tags" json:"tags"`
	RelatedResources     []string `yaml:"relatedResources" json:"relatedResources"`
	ComplianceFrameworks []string `yaml:"complianceFrameworks" json:"complianceFrameworks"`
	Filename             string   `json:"filename"`
	Content              string   `json:"content"`
	PredicateType        string   `yaml:"predicateType" json:"predicateType"`
}
type PolicyFS struct {
	PolicyMetadata
	Content string
}

var packageRegexp = regexp.MustCompile(`(?m)^package compliance`)
var metadataRegexp = regexp.MustCompile(`^\s*#\s*METADATA`)

func parseMetadata(fileName string, content string) (PolicyMetadata, error) {
	// split the content by first occurence of a line, that starts with "package compliance"
	parts := packageRegexp.Split(content, 2)

	// do a sanity check. It should start with "METADATA"
	if len(parts) < 2 {
		return PolicyMetadata{}, fmt.Errorf("metadata not found")
	}

	yamlData := parts[0]
	if yamlData == "" {
		return PolicyMetadata{}, nil
	}

	yamlLines := strings.Split(yamlData, "\n")
	// remove everything including metadata line
	collectedLines := []string{}
	collect := false
	for _, line := range yamlLines {
		if metadataRegexp.MatchString(line) {
			collect = true
			continue
		}

		if collect {
			// remove leading comment indicators
			collectedLines = append(collectedLines, strings.TrimPrefix(line, "#"))
		}
	}

	// join the lines and unmarshal the yaml
	yamlData = strings.Join(collectedLines, "\n")
	var metadata yamlPolicy
	if err := yaml.Unmarshal([]byte(yamlData), &metadata); err != nil {
		return PolicyMetadata{}, err
	}

	return PolicyMetadata{
		Title:                metadata.Title,
		Description:          metadata.Custom.Description,
		Priority:             metadata.Custom.Priority,
		Tags:                 metadata.Custom.Tags,
		RelatedResources:     metadata.Custom.RelatedResources,
		ComplianceFrameworks: metadata.Custom.ComplianceFrameworks,
		Filename:             fileName,
		PredicateType:        metadata.Custom.PredicateType,
		Content:              content,
	}, nil
}

type PolicyEvaluation struct {
	PolicyID               string
	PolicyTitle            string
	PolicyDescription      string
	PolicyRelatedResources []string
	PolicyTags             []string
	PolicyPriority         int
	PredicateType          string
	ComplianceFrameworks   []string
	Compliant              *bool
	Violations             []string
	RawEvaluationResult    map[string]any
	AttestationContent     *string
}

func Eval(policy PolicyFS, input any) PolicyEvaluation {
	if input == nil {
		return PolicyEvaluation{Compliant: nil}
	}

	r := rego.New(
		rego.Query("data.compliance"),
		rego.Module(policy.Filename, policy.Content),
	)

	ctx := context.TODO()
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return PolicyEvaluation{Compliant: nil}
	}

	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return PolicyEvaluation{Compliant: nil}
	}

	var violations []string
	var rawEvalResult map[string]any
	var compliant *bool
	if len(rs) > 0 {
		value := rs[0].Expressions[0].Value
		if v, ok := value.(map[string]any); ok {
			rawEvalResult = v
			if v["compliant"] != nil {
				compliant = utils.Ptr(v["compliant"].(bool))
			}
			if v["violations"] != nil {
				for _, violation := range v["violations"].([]any) {
					if s, ok := violation.(string); ok {
						violations = append(violations, s)
					}
				}
			}
		}
	}

	return PolicyEvaluation{
		PolicyID:               policy.Filename,
		PolicyTitle:            policy.Title,
		PolicyDescription:      policy.Description,
		PolicyRelatedResources: policy.RelatedResources,
		PolicyTags:             policy.Tags,
		PolicyPriority:         policy.Priority,
		PredicateType:          policy.PredicateType,
		ComplianceFrameworks:   policy.ComplianceFrameworks,
		Compliant:              compliant,
		Violations:             violations,
		RawEvaluationResult:    rawEvalResult,
		AttestationContent:     nil,
	}
}

// embed the policies in the binary
//
//go:embed attestation-compliance-policies/policies/*.rego
var policiesFs embed.FS

func GetPoliciesFromFS(policyDir string) ([]PolicyFS, error) {
	// fetch all policies
	policyFiles, err := policiesFs.ReadDir(policyDir)
	if err != nil {
		return nil, err
	}

	var policies []PolicyFS
	for _, file := range policyFiles {
		content, err := policiesFs.ReadFile(filepath.Join(policyDir, file.Name()))
		if err != nil {
			continue
		}

		metadata, err := parseMetadata(file.Name(), string(content))
		if err != nil {
			return nil, err
		}

		policy := PolicyFS{
			PolicyMetadata: metadata,
			Content:        string(content),
		}

		policies = append(policies, policy)
	}

	// sort the policies by priority - use a stable sort
	sort.SliceStable(policies, func(i, j int) bool {
		return policies[i].Priority < policies[j].Priority
	})

	return policies, nil
}

func PolicyFSFromContent(fileName, content string) (PolicyFS, error) {
	metadata, err := parseMetadata(fileName, content)
	if err != nil {
		return PolicyFS{}, err
	}
	return PolicyFS{PolicyMetadata: metadata, Content: content}, nil
}

func BuildSarifFromPolicies(srcPath string, evaluations []PolicyEvaluation) sarif.SarifSchema210Json {
	rules := make([]sarif.ReportingDescriptor, 0, len(evaluations))
	results := make([]sarif.Result, 0)
	seenResults := make(map[string]bool)
	addResult := func(r sarif.Result) {
		key := string(r.Kind) + "|" + r.Message.Text
		if !seenResults[key] {
			seenResults[key] = true
			results = append(results, r)
		}
	}
	for _, evaluation := range evaluations {
		ruleID := evaluation.PolicyID
		ruleName := evaluation.PolicyTitle

		var helpURI *string
		if len(evaluation.PolicyRelatedResources) > 0 {
			helpURI = &evaluation.PolicyRelatedResources[0]
		}

		rule := sarif.ReportingDescriptor{
			ID:   ruleID,
			Name: &ruleName,
			ShortDescription: &sarif.MultiformatMessageString{
				Text: evaluation.PolicyTitle,
			},
			FullDescription: &sarif.MultiformatMessageString{
				Text: evaluation.PolicyDescription,
			},
			Help: &sarif.MultiformatMessageString{
				Text: evaluation.PolicyDescription,
			},
			HelpURI: helpURI,
			Properties: &sarif.PropertyBag{
				Tags: evaluation.PolicyTags,
				AdditionalProperties: map[string]any{
					"priority":             evaluation.PolicyPriority,
					"relatedResources":     evaluation.PolicyRelatedResources,
					"complianceFrameworks": evaluation.ComplianceFrameworks,
					"predicateType":        evaluation.PredicateType,
				},
			},
		}

		rules = append(rules, rule)

		artifactLocation := sarif.ArtifactLocation{URI: &srcPath}
		additionalProps := map[string]any{
			"precision": "high",
		}
		if evaluation.AttestationContent != nil {
			additionalProps["attestationContent"] = *evaluation.AttestationContent
		}
		props := &sarif.PropertyBag{
			Tags:                 evaluation.PolicyTags,
			AdditionalProperties: additionalProps,
		}

		if evaluation.Compliant == nil {
			addResult(sarif.Result{
				Kind:   sarif.ResultKindOpen,
				RuleID: &ruleID,
				Message: sarif.Message{
					Text: "No attestation found for policy — compliance could not be determined.",
				},
				Locations: []sarif.Location{
					{PhysicalLocation: sarif.PhysicalLocation{ArtifactLocation: artifactLocation}},
				},
				Properties: props,
			})
			continue
		}

		if *evaluation.Compliant {
			addResult(sarif.Result{
				Kind:   sarif.ResultKindPass,
				RuleID: &ruleID,
				Message: sarif.Message{
					Text: "Policy compliant",
				},
				Locations: []sarif.Location{
					{PhysicalLocation: sarif.PhysicalLocation{ArtifactLocation: artifactLocation}},
				},
				Properties: props,
			})
			continue
		}

		for _, violation := range evaluation.Violations {
			addResult(sarif.Result{
				Kind:   sarif.ResultKindFail,
				RuleID: &ruleID,
				Message: sarif.Message{
					Text: violation,
				},
				Locations: []sarif.Location{
					{PhysicalLocation: sarif.PhysicalLocation{ArtifactLocation: artifactLocation}},
				},
				Properties: props,
			})
		}
	}

	driver := sarif.ToolComponent{
		Name:  "devguard-attestations",
		Rules: rules,
	}

	return sarif.SarifSchema210Json{
		Version: sarif.SarifSchema210JsonVersionA210,
		Schema:  utils.Ptr("https://json.schemastore.org/sarif-2.1.0.json"),
		Runs: []sarif.Run{
			{
				Tool: sarif.Tool{
					Driver: driver,
				},
				Results: results,
			},
		},
	}
}

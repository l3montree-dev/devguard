package compliance

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/open-policy-agent/opa/rego"
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

type PolicyEvaluation struct {
	models.Policy
	Compliant  *bool    `json:"compliant"`
	Violations []string `json:"violations"`
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

func NewPolicy(filename string, content string) (*PolicyFS, error) {
	metadata, err := parseMetadata(filename, content)
	if err != nil {
		return nil, err
	}

	return &PolicyFS{
		PolicyMetadata: metadata,
		Content:        content,
	}, nil
}

func Eval(p models.Policy, input any) PolicyEvaluation {

	if input == nil {
		return PolicyEvaluation{
			Policy:    p,
			Compliant: nil,
		}
	}

	r := rego.New(
		rego.Query("data.compliance"),
		rego.Module("", p.Rego),
	)

	ctx := context.TODO()
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return PolicyEvaluation{
			Policy:    p,
			Compliant: nil,
		}
	}

	rs, err := query.Eval(context.TODO(), rego.EvalInput(input))
	if err != nil {
		return PolicyEvaluation{
			Policy:    p,
			Compliant: nil,
		}
	}

	var violations = []string{}
	var compliant *bool
	if len(rs) > 0 {
		value := rs[0].Expressions[0].Value
		// cast value to map
		if v, ok := value.(map[string]any); ok {
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
		Policy:     p,
		Compliant:  compliant,
		Violations: violations,
	}
}

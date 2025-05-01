package compliance

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/l3montree-dev/devguard/internal/common"
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
	AttestationName      string   `yaml:"attestationName"`
	RelatedResources     []string `yaml:"relatedResources"`
	ComplianceFrameworks []string `yaml:"complianceFrameworks"`
}

type Policy struct {
	common.PolicyMetadata
	Content string
	query   rego.PreparedEvalQuery
}

var packageRegexp = regexp.MustCompile(`(?m)^package compliance`)
var metadataRegexp = regexp.MustCompile(`^\s*#\s*METADATA`)

func parseMetadata(fileName string, content string) (common.PolicyMetadata, error) {
	// split the content by first occurence of a line, that starts with "package compliance"
	parts := packageRegexp.Split(content, 2)

	// do a sanity check. It should start with "METADATA"
	if len(parts) < 2 {
		return common.PolicyMetadata{}, fmt.Errorf("metadata not found")
	}

	yamlData := parts[0]
	if yamlData == "" {
		return common.PolicyMetadata{}, nil
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
		return common.PolicyMetadata{}, err
	}

	return common.PolicyMetadata{
		Title:                metadata.Title,
		Description:          metadata.Custom.Description,
		Priority:             metadata.Custom.Priority,
		Tags:                 metadata.Custom.Tags,
		RelatedResources:     metadata.Custom.RelatedResources,
		ComplianceFrameworks: metadata.Custom.ComplianceFrameworks,
		Filename:             fileName,
		AttestationName:      metadata.Custom.AttestationName,
		Content:              content,
	}, nil
}

func NewPolicy(filename string, content string) (*Policy, error) {
	r := rego.New(
		rego.Query("data.compliance"),
		rego.Module("", content),
	)

	ctx := context.TODO()
	query, err := r.PrepareForEval(ctx)

	if err != nil {
		return nil, err
	}

	metadata, err := parseMetadata(filename, content)
	if err != nil {
		return nil, err
	}

	return &Policy{
		PolicyMetadata: metadata,
		Content:        content,
		query:          query,
	}, nil
}

func (p *Policy) Eval(input any) common.PolicyEvaluation {
	rs, err := p.query.Eval(context.TODO(), rego.EvalInput(input))
	if err != nil {
		return common.PolicyEvaluation{
			PolicyMetadata: p.PolicyMetadata,
			Compliant:      nil,
		}
	}

	var violations []string = []string{}
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

	return common.PolicyEvaluation{
		PolicyMetadata: p.PolicyMetadata,
		Compliant:      compliant,
		Violations:     violations,
	}
}
